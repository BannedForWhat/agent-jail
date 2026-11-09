#include "fsm.hpp"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <cerrno>
#include <cstring>
#include <cstdio>

bool SyncChannel::send_token(SyncStage stage) const noexcept {
    if (fd < 0) return false;
    ssize_t ret = ::send(fd, &stage, sizeof(stage), MSG_NOSIGNAL);
    return ret == static_cast<ssize_t>(sizeof(stage));
}

bool SyncChannel::wait_token(SyncStage& out_stage) const noexcept {
    if (fd < 0) return false;
    ssize_t ret = ::recv(fd, &out_stage, sizeof(out_stage), MSG_WAITALL);
    return ret == static_cast<ssize_t>(sizeof(out_stage));
}

void SyncChannel::close() noexcept {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

bool create_sync_pair(SyncChannel& parent_chan, SyncChannel& child_chan) noexcept {
    int fds[2]{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds) == -1) {
        return false;
    }
    parent_chan.fd = fds[0];
    child_chan.fd = fds[1];
    return true;
}

static bool write_exact(const char* path, const char* data, size_t len) noexcept {
    int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) return false;
    ssize_t written = ::write(fd, data, len);
    ::close(fd);
    return written == static_cast<ssize_t>(len);
}

bool supervisor_handle_handshake(pid_t child_pid, int sync_fd, uid_t host_uid, gid_t host_gid, const char* cgroup_procs_path) noexcept {
    int epfd = ::epoll_create1(EPOLL_CLOEXEC);
    if (epfd == -1) return false;

    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
    ev.data.fd = sync_fd;
    if (::epoll_ctl(epfd, EPOLL_CTL_ADD, sync_fd, &ev) == -1) {
        ::close(epfd);
        return false;
    }

    epoll_event event{};
    int nfds = ::epoll_wait(epfd, &event, 1, 5000);
    ::close(epfd);

    if (nfds <= 0) return false;

    if (event.events & (EPOLLHUP | EPOLLRDHUP)) {
        if (!(event.events & EPOLLIN)) return false;
    }

    SyncStage stage{};
    ssize_t ret = ::recv(sync_fd, &stage, sizeof(stage), MSG_WAITALL);
    if (ret != sizeof(stage) || stage != SyncStage::StageUsernsReady) {
        return false;
    }

    char path[128];
    std::snprintf(path, sizeof(path), "/proc/%d/setgroups", child_pid);
    if (!write_exact(path, "deny", 4)) return false;

    std::snprintf(path, sizeof(path), "/proc/%d/uid_map", child_pid);
    char buf[64];
    int len = std::snprintf(buf, sizeof(buf), "0 %u 1\n", host_uid);
    if (len <= 0 || !write_exact(path, buf, static_cast<size_t>(len))) return false;

    std::snprintf(path, sizeof(path), "/proc/%d/gid_map", child_pid);
    len = std::snprintf(buf, sizeof(buf), "0 %u 1\n", host_gid);
    if (len <= 0 || !write_exact(path, buf, static_cast<size_t>(len))) return false;

    // Миграция в cgroup
    if (cgroup_procs_path && cgroup_procs_path[0] != '\0') {
        len = std::snprintf(buf, sizeof(buf), "%d\n", child_pid);
        if (len > 0) {
            if (!write_exact(cgroup_procs_path, buf, static_cast<size_t>(len))) {
                std::fprintf(stderr, "[agent-jail-fsm] Warning: Failed to migrate PID %d to %s: %s\n",
                    child_pid, cgroup_procs_path, std::strerror(errno));
            }
        }
    }

    SyncStage ack = SyncStage::StageSetupDone;
    return ::send(sync_fd, &ack, sizeof(ack), MSG_NOSIGNAL) == sizeof(ack);
}

bool worker_await_handshake(int sync_fd) noexcept {
    if (::unshare(CLONE_NEWUSER) == -1) return false;

    SyncStage stage = SyncStage::StageUsernsReady;
    if (::send(sync_fd, &stage, sizeof(stage), MSG_NOSIGNAL) != sizeof(stage)) {
        return false;
    }

    SyncStage ack{};
    ssize_t ret = ::recv(sync_fd, &ack, sizeof(ack), MSG_WAITALL);
    if (ret != sizeof(ack) || ack != SyncStage::StageSetupDone) {
        return false;
    }

    return true;
}
