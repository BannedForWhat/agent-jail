#pragma once

#include <cstdint>
#include <sys/types.h>

class CgroupScope {
public:
    CgroupScope() noexcept = default;
    ~CgroupScope() noexcept;

    // Запрет копирования, разрешение перемещения
    CgroupScope(const CgroupScope&) = delete;
    CgroupScope& operator=(const CgroupScope&) = delete;
    CgroupScope(CgroupScope&& other) noexcept;
    CgroupScope& operator=(CgroupScope&& other) noexcept;

    // Инициализация подгруппы cgroups v2
    bool initialize(uid_t uid, const char* session_id, uint64_t max_memory_bytes, uint32_t max_pids) noexcept;

    // Путь к cgroup.procs для миграции PID воркера
    [[nodiscard]] const char* get_procs_path() const noexcept { return procs_path_; }

    // Дескриптор memory.events для регистрации в epoll
    [[nodiscard]] int get_events_fd() const noexcept { return events_fd_; }

    // Проверка наступления события OOM
    [[nodiscard]] bool check_oom_kill() const noexcept;

    // Очистка и удаление cgroup
    void cleanup() noexcept;

private:
    char jail_path_[256]{};
    char procs_path_[270]{};
    char events_path_[270]{};
    int events_fd_{-1};
    bool active_{false};

    static bool write_value(const char* file_path, const char* val, size_t len) noexcept;
    static bool ensure_subtree_controllers(const char* user_root) noexcept;
};
