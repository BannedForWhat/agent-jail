#include "cgroup.hpp"
#include "fsm.hpp"
#include "pty.hpp"
#include "vfs.hpp"
#include "landlock.hpp"
#include "seccomp_filter.hpp"

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

struct Config {
    char workspace[512]{};
    char socket_path[256]{};
    uint64_t memory_limit{4ULL * 1024ULL * 1024ULL * 1024ULL}; // 4 GiB
    uint32_t pids_limit{128};
    uint32_t timeout_sec{120};
    char** cmd_args{nullptr};
};

static void print_usage(const char* prog) noexcept {
    std::fprintf(stderr,
        "Usage: %s [OPTIONS] -- <command> [args...]\n\n"
        "Options:\n"
        "  --workspace <path>   Workspace directory (default: current working dir)\n"
        "  --socket <path>      Path to prompt-mesh UNIX socket\n"
        "  --timeout <sec>      Execution timeout in seconds (default: 120, 0=disabled)\n"
        "  --mem <bytes>        Memory limit in bytes (default: 4GiB)\n"
        "  --pids <num>         Maximum process count (default: 128)\n"
        "  -h, --help           Show this help message\n", prog);
}

static bool parse_args(int argc, char* argv[], Config& cfg) noexcept {
    if (::getcwd(cfg.workspace, sizeof(cfg.workspace)) == nullptr) {
        return false;
    }

    uid_t uid = ::getuid();
    std::snprintf(cfg.socket_path, sizeof(cfg.socket_path), "/run/user/%u/prompt-mesh.sock", uid);

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--") == 0) {
            if (i + 1 < argc) {
                cfg.cmd_args = &argv[i + 1];
                return true;
            }
            return false;
        } else if (std::strcmp(argv[i], "--workspace") == 0 && i + 1 < argc) {
            std::strncpy(cfg.workspace, argv[++i], sizeof(cfg.workspace) - 1);
        } else if (std::strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            std::strncpy(cfg.socket_path, argv[++i], sizeof(cfg.socket_path) - 1);
        } else if (std::strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            cfg.timeout_sec = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (std::strcmp(argv[i], "--mem") == 0 && i + 1 < argc) {
            cfg.memory_limit = std::strtoull(argv[++i], nullptr, 10);
        } else if (std::strcmp(argv[i], "--pids") == 0 && i + 1 < argc) {
            cfg.pids_limit = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            std::exit(0);
        } else {
            return false;
        }
    }
    return cfg.cmd_args != nullptr;
}

static int worker_stage2_pid1(const Config& cfg, int slave_fd, const char* rootfs_template) noexcept {
    VfsConfig vfs_cfg{};
    vfs_cfg.rootfs_path = rootfs_template;
    vfs_cfg.host_workspace = cfg.workspace;
    vfs_cfg.host_socket = cfg.socket_path;
    vfs_cfg.host_uid = ::getuid();
    vfs_cfg.host_gid = ::getgid();

    if (!deploy_vfs(vfs_cfg)) {
        std::fprintf(stderr, "[agent-jail-worker] VFS deployment failed: %s\n", std::strerror(errno));
        if (slave_fd >= 0) ::close(slave_fd);
        return 101;
    }

    if (::setsid() == -1) {
        std::fprintf(stderr, "[agent-jail-worker] setsid failed: %s\n", std::strerror(errno));
        if (slave_fd >= 0) ::close(slave_fd);
        return 102;
    }

    if (slave_fd >= 0) {
        ::ioctl(slave_fd, TIOCSCTTY, 0);
        ::dup2(slave_fd, STDIN_FILENO);
        ::dup2(slave_fd, STDOUT_FILENO);
        ::dup2(slave_fd, STDERR_FILENO);
        if (slave_fd > STDERR_FILENO) {
            ::close(slave_fd);
        }
    }

    ::close_range(3, ~0U, 0);

    if (::chdir("/workspace") == -1) {
        std::fprintf(stderr, "[agent-jail-worker] chdir(/workspace) failed: %s\n", std::strerror(errno));
        return 104;
    }

    ::clearenv();
    ::setenv("PATH", "/usr/bin:/bin", 1);
    ::setenv("HOME", "/workspace", 1);
    ::setenv("USER", "sickarion", 1);
    ::setenv("LOGNAME", "sickarion", 1);
    ::setenv("TERM", "xterm-256color", 1);
    ::setenv("LANG", "C.UTF-8", 1);
    ::setenv("LC_ALL", "C.UTF-8", 1);
    ::setenv("PROMPT_MESH_SOCKET", "/run/prompt-mesh.sock", 1);

    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        std::fprintf(stderr, "[agent-jail-worker] prctl(NO_NEW_PRIVS) failed: %s\n", std::strerror(errno));
        return 107;
    }

    if (::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &agent_jail_seccomp_prog) == -1) {
        std::fprintf(stderr, "[agent-jail-worker] seccomp filter failed: %s\n", std::strerror(errno));
        return 105;
    }

    LandlockPolicyConfig l_cfg{};
    l_cfg.allow_prompt_mesh_socket = (cfg.socket_path[0] != '\0');
    if (!apply_landlock_policy(l_cfg)) {
        std::fprintf(stderr, "[agent-jail-worker] landlock restrict failed: %s\n", std::strerror(errno));
        return 106;
    }

    ::execvp(cfg.cmd_args[0], cfg.cmd_args);
    std::fprintf(stderr, "[agent-jail-worker] execvp '%s' failed: %s\n", cfg.cmd_args[0], std::strerror(errno));
    return 127;
}

static int worker_stage1_entry(const Config& cfg, int sync_fd, int slave_fd, const char* rootfs_template) noexcept {
    if (!worker_await_handshake(sync_fd)) {
        if (slave_fd >= 0) ::close(slave_fd);
        return 90;
    }
    ::close(sync_fd);

    if (::unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP) == -1) {
        std::fprintf(stderr, "[agent-jail-worker] unshare namespaces failed: %s\n", std::strerror(errno));
        if (slave_fd >= 0) ::close(slave_fd);
        return 91;
    }

    pid_t pid1 = ::fork();
    if (pid1 < 0) {
        if (slave_fd >= 0) ::close(slave_fd);
        return 92;
    }

    if (pid1 == 0) {
        int ret = worker_stage2_pid1(cfg, slave_fd, rootfs_template);
        ::_exit(ret);
    }

    if (slave_fd >= 0) ::close(slave_fd);

    int status = 0;
    ::waitpid(pid1, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : (128 + WTERMSIG(status));
}

int main(int argc, char* argv[]) {
    Config cfg{};
    if (!parse_args(argc, argv, cfg)) {
        print_usage(argv[0]);
        return 1;
    }

    ::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

    char session_id[32];
    std::snprintf(session_id, sizeof(session_id), "%d", ::getpid());

    CgroupScope cgroup;
    if (!cgroup.initialize(::getuid(), session_id, cfg.memory_limit, cfg.pids_limit)) {
        std::fprintf(stderr, "[agent-jail] Warning: cgroups v2 setup failed (is Delegate=yes configured?)\n");
    }

    PtyMasterDevice pty;
    if (!pty.open()) {
        std::fprintf(stderr, "[agent-jail] Error: Failed to allocate PTY: %s\n", std::strerror(errno));
        return 2;
    }
    pty.forward_window_size();

    int slave_fd = pty.open_slave_fd();
    if (slave_fd == -1) {
        std::fprintf(stderr, "[agent-jail] Error: Failed to open slave PTY: %s\n", std::strerror(errno));
        return 2;
    }

    SyncChannel parent_chan;
    SyncChannel child_chan;
    if (!create_sync_pair(parent_chan, child_chan)) {
        std::fprintf(stderr, "[agent-jail] Error: Failed to create sync socketpair: %s\n", std::strerror(errno));
        ::close(slave_fd);
        return 3;
    }

    char rootfs_template[] = "/tmp/agent-jail-root-XXXXXX";
    if (::mkdtemp(rootfs_template) == nullptr) {
        std::fprintf(stderr, "[agent-jail] Error: mkdtemp failed: %s\n", std::strerror(errno));
        ::close(slave_fd);
        return 4;
    }

    pid_t worker_pid = ::fork();
    if (worker_pid < 0) {
        std::fprintf(stderr, "[agent-jail] Error: fork failed: %s\n", std::strerror(errno));
        ::close(slave_fd);
        ::rmdir(rootfs_template);
        return 5;
    }

    if (worker_pid == 0) {
        parent_chan.close();
        int rc = worker_stage1_entry(cfg, child_chan.fd, slave_fd, rootfs_template);
        ::_exit(rc);
    }

    child_chan.close();

    if (!supervisor_handle_handshake(worker_pid, parent_chan.fd, ::getuid(), ::getgid(), cgroup.get_procs_path())) {
        std::fprintf(stderr, "[agent-jail] Error: Supervisor-worker handshake failed\n");
        ::kill(worker_pid, SIGKILL);
        int status = 0;
        ::waitpid(worker_pid, &status, 0);
        cgroup.cleanup();
        ::close(slave_fd);
        ::rmdir(rootfs_template);
        return 6;
    }
    parent_chan.close();

    // Передаем slave_fd в мультиплексор, удерживая PTY живым до завершения чтения
    int exit_code = run_pty_multiplexer(pty.get_fd(), slave_fd, worker_pid, cfg.timeout_sec);

    if (cgroup.check_oom_kill()) {
        std::fprintf(stderr, "\n[agent-jail] Fatal: Process killed by cgroups v2 OOM-killer (Memory limit exceeded)\n");
    }

    cgroup.cleanup();
    ::rmdir(rootfs_template);

    return exit_code;
}
