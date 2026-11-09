#include "landlock.hpp"
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#define ACCESS_FS_RO ( \
    LANDLOCK_ACCESS_FS_EXECUTE | \
    LANDLOCK_ACCESS_FS_READ_FILE | \
    LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_RW ( \
    ACCESS_FS_RO | \
    LANDLOCK_ACCESS_FS_WRITE_FILE | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR | \
    LANDLOCK_ACCESS_FS_REMOVE_FILE | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR | \
    LANDLOCK_ACCESS_FS_MAKE_DIR | \
    LANDLOCK_ACCESS_FS_MAKE_REG | \
    LANDLOCK_ACCESS_FS_MAKE_SOCK | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO | \
    LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
    LANDLOCK_ACCESS_FS_MAKE_SYM | \
    LANDLOCK_ACCESS_FS_REFER | \
    LANDLOCK_ACCESS_FS_TRUNCATE | \
    LANDLOCK_ACCESS_FS_IOCTL_DEV)

static int landlock_create_ruleset(const struct landlock_ruleset_attr* attr, size_t size, uint32_t flags) noexcept {
    return static_cast<int>(::syscall(SYS_landlock_create_ruleset, attr, size, flags));
}

static int landlock_add_rule(int ruleset_fd, enum landlock_rule_type type, const void* attr, uint32_t flags) noexcept {
    return static_cast<int>(::syscall(SYS_landlock_add_rule, ruleset_fd, type, attr, flags));
}

static int landlock_restrict_self(int ruleset_fd, uint32_t flags) noexcept {
    return static_cast<int>(::syscall(SYS_landlock_restrict_self, ruleset_fd, flags));
}

static bool add_path_rule(int ruleset_fd, const char* path, uint64_t access_mask) noexcept {
    int fd = ::open(path, O_PATH | O_CLOEXEC);
    if (fd == -1) return false;

    struct landlock_path_beneath_attr path_attr{};
    path_attr.allowed_access = access_mask;
    path_attr.parent_fd = fd;

    int ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
    ::close(fd);
    return ret == 0;
}

bool apply_landlock_policy(const LandlockPolicyConfig& cfg) noexcept {
    int abi = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        return true;
    }

    uint64_t handled_fs = ACCESS_FS_RW;
    if (abi < 5) handled_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
    if (abi < 3) handled_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi < 2) handled_fs &= ~LANDLOCK_ACCESS_FS_REFER;

    struct landlock_ruleset_attr ruleset_attr{};
    ruleset_attr.handled_access_fs = handled_fs;

    int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd == -1) {
        return false;
    }

    uint64_t ro_mask = handled_fs & ACCESS_FS_RO;
    uint64_t rw_mask = handled_fs;

    // 1. Разрешаем чтение и резолв симлинков по всей VFS от корня /
    add_path_rule(ruleset_fd, "/", ro_mask);

    // 2. Явно разрешаем запись только в целевые изолированные директории
    add_path_rule(ruleset_fd, "/workspace", rw_mask);
    add_path_rule(ruleset_fd, "/tmp", rw_mask);
    add_path_rule(ruleset_fd, "/dev", rw_mask);
    add_path_rule(ruleset_fd, "/dev/shm", rw_mask);

    if (cfg.allow_prompt_mesh_socket) {
        add_path_rule(ruleset_fd, "/run", rw_mask);
    }

    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        ::close(ruleset_fd);
        return false;
    }

    if (landlock_restrict_self(ruleset_fd, 0) == -1) {
        ::close(ruleset_fd);
        return false;
    }

    ::close(ruleset_fd);
    return true;
}
