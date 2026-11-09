#include "vfs.hpp"
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cerrno>

static bool checked_mkdir(const char* path, mode_t mode) noexcept {
    if (::mkdir(path, mode) == -1 && errno != EEXIST) {
        return false;
    }
    return true;
}

static bool checked_mount(const char* src, const char* tgt, const char* type, unsigned long flags, const void* data) noexcept {
    return ::mount(src, tgt, type, flags, data) == 0;
}

static bool bind_mount_ro_tree(const char* source, const char* target) noexcept {
    if (!checked_mount(source, target, nullptr, MS_BIND | MS_REC, nullptr)) {
        return false;
    }
    return checked_mount(nullptr, target, nullptr, MS_BIND | MS_REC | MS_REMOUNT | MS_RDONLY | MS_NODEV, nullptr);
}

static bool bind_file_ro(const char* host_file, const char* jail_file) noexcept {
    int fd = ::open(jail_file, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd != -1) ::close(fd);

    if (!checked_mount(host_file, jail_file, nullptr, MS_BIND, nullptr)) {
        return false;
    }
    return checked_mount(nullptr, jail_file, nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
}

static bool bind_device_node(const char* rootfs, const char* device_name) noexcept {
    char target[512];
    std::snprintf(target, sizeof(target), "%s/dev/%s", rootfs, device_name);
    char host_src[64];
    std::snprintf(host_src, sizeof(host_src), "/dev/%s", device_name);

    int fd = ::open(target, O_WRONLY | O_CREAT | O_CLOEXEC, 0666);
    if (fd != -1) ::close(fd);

    return checked_mount(host_src, target, nullptr, MS_BIND, nullptr);
}

bool deploy_vfs(const VfsConfig& cfg) noexcept {
    const char* r = cfg.rootfs_path;

    // 1. Изоляция хостовой VFS от распространения событий монтирования
    if (!checked_mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr)) {
        return false;
    }

    // 2. Монтирование изолированной tmpfs под корень
    if (!checked_mount("none", r, "tmpfs", MS_NODEV | MS_NOSUID, "size=64M,mode=0755")) {
        return false;
    }

    // 3. Создание скелета каталогов
    char buf[512];
    auto make_dir = [r, &buf](const char* sub, mode_t m) noexcept {
        std::snprintf(buf, sizeof(buf), "%s%s", r, sub);
        return checked_mkdir(buf, m);
    };

    if (!make_dir("/usr", 0755) || !make_dir("/etc", 0755) || !make_dir("/run", 0755) ||
        !make_dir("/proc", 0555) || !make_dir("/dev", 0755) || !make_dir("/dev/pts", 0755) ||
        !make_dir("/dev/shm", 01777) || !make_dir("/tmp", 01777) || !make_dir("/workspace", 0700) ||
        !make_dir("/.oldroot", 0700)) {
        return false;
    }

    // 4. Относительные симлинки Merged /usr под Arch Linux
    auto make_symlink = [r, &buf](const char* target, const char* linkpath) noexcept {
        std::snprintf(buf, sizeof(buf), "%s%s", r, linkpath);
        return ::symlink(target, buf) == 0;
    };

    if (!make_symlink("usr/bin", "/bin") ||
        !make_symlink("usr/bin", "/sbin") ||
        !make_symlink("usr/lib", "/lib") ||
        !make_symlink("usr/lib", "/lib64")) {
        return false;
    }

    // 5. Read-only проброс системного /usr
    std::snprintf(buf, sizeof(buf), "%s/usr", r);
    if (!bind_mount_ro_tree("/usr", buf)) {
        return false;
    }

    // 6. Монтирование изолированного /etc (tmpfs) и точечный проброс конфигов
    std::snprintf(buf, sizeof(buf), "%s/etc", r);
    if (!checked_mount("none", buf, "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, "size=8M,mode=0755")) {
        return false;
    }

    char dest[512];
    std::snprintf(dest, sizeof(dest), "%s/etc/ld.so.cache", r);
    bind_file_ro("/etc/ld.so.cache", dest);

    std::snprintf(dest, sizeof(dest), "%s/etc/resolv.conf", r);
    bind_file_ro("/etc/resolv.conf", dest);

    std::snprintf(dest, sizeof(dest), "%s/etc/nsswitch.conf", r);
    bind_file_ro("/etc/nsswitch.conf", dest);

    // Генерация синтетических passwd и group в памяти
    std::snprintf(dest, sizeof(dest), "%s/etc/passwd", r);
    int fd = ::open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd >= 0) {
        char pbuf[256];
        int plen = std::snprintf(pbuf, sizeof(pbuf),
            "root:x:0:0:root:/workspace:/bin/bash\n"
            "sickarion:x:%u:%u:sickarion:/workspace:/bin/bash\n",
            cfg.host_uid, cfg.host_gid);
        if (plen > 0) {
            ssize_t res = ::write(fd, pbuf, static_cast<size_t>(plen));
            (void)res;
        }
        ::close(fd);
    }

    std::snprintf(dest, sizeof(dest), "%s/etc/group", r);
    fd = ::open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd >= 0) {
        char gbuf[256];
        int glen = std::snprintf(gbuf, sizeof(gbuf),
            "root:x:0:\n"
            "sickarion:x:%u:\n",
            cfg.host_gid);
        if (glen > 0) {
            ssize_t res = ::write(fd, gbuf, static_cast<size_t>(glen));
            (void)res;
        }
        ::close(fd);
    }

    // 7. Монтирование proc, devpts, dev/shm
    std::snprintf(buf, sizeof(buf), "%s/proc", r);
    if (!checked_mount("proc", buf, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr)) {
        return false;
    }

    std::snprintf(buf, sizeof(buf), "%s/dev/pts", r);
    if (!checked_mount("devpts", buf, "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620")) {
        return false;
    }

    std::snprintf(buf, sizeof(buf), "%s/dev/ptmx", r);
    if (::symlink("pts/ptmx", buf) == -1) {
        return false;
    }

    std::snprintf(buf, sizeof(buf), "%s/dev/shm", r);
    if (!checked_mount("tmpfs", buf, "tmpfs", MS_NOSUID | MS_NODEV, "size=64M,mode=1777")) {
        return false;
    }

    std::snprintf(buf, sizeof(buf), "%s/tmp", r);
    if (!checked_mount("tmpfs", buf, "tmpfs", MS_NODEV | MS_NOSUID, "size=512M,mode=1777")) {
        return false;
    }

    // Проброс базовых узлов устройств
    if (!bind_device_node(r, "null") ||
        !bind_device_node(r, "zero") ||
        !bind_device_node(r, "full") ||
        !bind_device_node(r, "random") ||
        !bind_device_node(r, "urandom")) {
        return false;
    }

    // 8. Проброс сокета prompt-mesh при наличии
    if (cfg.host_socket && cfg.host_socket[0] != '\0') {
        std::snprintf(dest, sizeof(dest), "%s/run/prompt-mesh.sock", r);
        fd = ::open(dest, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (fd >= 0) {
            ::close(fd);
            checked_mount(cfg.host_socket, dest, nullptr, MS_BIND, nullptr);
        }
    }

    // 9. Монтирование workspace
    std::snprintf(buf, sizeof(buf), "%s/workspace", r);
    if (!checked_mount(cfg.host_workspace, buf, nullptr, MS_BIND | MS_REC, nullptr)) {
        return false;
    }
    if (!checked_mount(nullptr, buf, nullptr, MS_BIND | MS_REMOUNT | MS_NODEV | MS_NOSUID, nullptr)) {
        return false;
    }

    // 10. Атомарный pivot_root
    std::snprintf(buf, sizeof(buf), "%s/.oldroot", r);
    if (::syscall(SYS_pivot_root, r, buf) == -1) {
        return false;
    }

    if (::chdir("/") == -1) {
        return false;
    }

    // 11. Отсоединение и сокрытие хостового корня
    if (::umount2("/.oldroot", MNT_DETACH) == -1) {
        return false;
    }
    ::rmdir("/.oldroot");

    return true;
}
