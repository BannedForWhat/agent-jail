#include "cgroup.hpp"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cerrno>

CgroupScope::~CgroupScope() noexcept {
    cleanup();
}

CgroupScope::CgroupScope(CgroupScope&& other) noexcept {
    std::memcpy(jail_path_, other.jail_path_, sizeof(jail_path_));
    std::memcpy(procs_path_, other.procs_path_, sizeof(procs_path_));
    std::memcpy(events_path_, other.events_path_, sizeof(events_path_));
    events_fd_ = other.events_fd_;
    active_ = other.active_;

    other.events_fd_ = -1;
    other.active_ = false;
}

CgroupScope& CgroupScope::operator=(CgroupScope&& other) noexcept {
    if (this != &other) {
        cleanup();
        std::memcpy(jail_path_, other.jail_path_, sizeof(jail_path_));
        std::memcpy(procs_path_, other.procs_path_, sizeof(procs_path_));
        std::memcpy(events_path_, other.events_path_, sizeof(events_path_));
        events_fd_ = other.events_fd_;
        active_ = other.active_;

        other.events_fd_ = -1;
        other.active_ = false;
    }
    return *this;
}

bool CgroupScope::write_value(const char* file_path, const char* val, size_t len) noexcept {
    int fd = ::open(file_path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) return false;
    ssize_t written = ::write(fd, val, len);
    ::close(fd);
    return written == static_cast<ssize_t>(len);
}

bool CgroupScope::ensure_subtree_controllers(const char* user_root) noexcept {
    char subtree_path[300];
    std::snprintf(subtree_path, sizeof(subtree_path), "%s/cgroup.subtree_control", user_root);
    const char controllers[] = "+memory +pids";
    return write_value(subtree_path, controllers, sizeof(controllers) - 1);
}

bool CgroupScope::initialize(uid_t uid, const char* session_id, uint64_t max_memory_bytes, uint32_t max_pids) noexcept {
    cleanup();

    char user_root[200];
    std::snprintf(user_root, sizeof(user_root), "/sys/fs/cgroup/user.slice/user-%u.slice/user@%u.service", uid, uid);

    // 1. Активация контроллеров
    ensure_subtree_controllers(user_root);

    // 2. Создание группы
    std::snprintf(jail_path_, sizeof(jail_path_), "%s/agent-jail-%s", user_root, session_id);
    if (::mkdir(jail_path_, 0755) == -1 && errno != EEXIST) {
        return false;
    }

    std::snprintf(procs_path_, sizeof(procs_path_), "%s/cgroup.procs", jail_path_);
    std::snprintf(events_path_, sizeof(events_path_), "%s/memory.events", jail_path_);

    // 3. Установка memory.max
    char buf[64];
    int len = std::snprintf(buf, sizeof(buf), "%lu\n", max_memory_bytes);
    char mem_max_path[280];
    std::snprintf(mem_max_path, sizeof(mem_max_path), "%s/memory.max", jail_path_);
    if (!write_value(mem_max_path, buf, static_cast<size_t>(len))) {
        cleanup();
        return false;
    }

    // 4. БЛОКИРОВКА SWAP (memory.swap.max = 0): исключаем уход в zram при превышении лимита
    char swap_max_path[280];
    std::snprintf(swap_max_path, sizeof(swap_max_path), "%s/memory.swap.max", jail_path_);
    write_value(swap_max_path, "0\n", 2);

    // 5. Установка pids.max
    len = std::snprintf(buf, sizeof(buf), "%u\n", max_pids);
    char pids_max_path[280];
    std::snprintf(pids_max_path, sizeof(pids_max_path), "%s/pids.max", jail_path_);
    if (!write_value(pids_max_path, buf, static_cast<size_t>(len))) {
        cleanup();
        return false;
    }

    // 6. Дескриптор memory.events для итогового чтения
    events_fd_ = ::open(events_path_, O_RDONLY | O_CLOEXEC);
    if (events_fd_ == -1) {
        cleanup();
        return false;
    }

    active_ = true;
    return true;
}

bool CgroupScope::check_oom_kill() const noexcept {
    if (events_fd_ == -1) return false;

    char buffer[256];
    ssize_t bytes = ::pread(events_fd_, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) return false;
    buffer[bytes] = '\0';

    const char* pos = std::strstr(buffer, "oom_kill ");
    if (pos) {
        pos += 9;
        int count = 0;
        if (std::sscanf(pos, "%d", &count) == 1 && count > 0) {
            return true;
        }
    }
    return false;
}

void CgroupScope::cleanup() noexcept {
    if (events_fd_ >= 0) {
        ::close(events_fd_);
        events_fd_ = -1;
    }
    if (active_ && jail_path_[0] != '\0') {
        ::rmdir(jail_path_);
        jail_path_[0] = '\0';
        active_ = false;
    }
}
