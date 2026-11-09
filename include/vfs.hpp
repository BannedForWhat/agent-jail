#pragma once

#include <sys/types.h>

struct VfsConfig {
    const char* rootfs_path{nullptr};
    const char* host_workspace{nullptr};
    const char* host_socket{nullptr}; // Путь к prompt-mesh сокету (опционально)
    uid_t host_uid{1000};
    gid_t host_gid{1000};
};

// Развертывание VFS песочницы и атомарный pivot_root
// Возвращает true при успехе, false при ошибке системных вызовов
bool deploy_vfs(const VfsConfig& config) noexcept;
