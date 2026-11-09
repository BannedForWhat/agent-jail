#pragma once

#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdint>

class TerminalStateGuard {
public:
    static bool initialize() noexcept;
    static void enter_raw_mode() noexcept;
    static void restore() noexcept;

private:
    static void restore_atexit() noexcept;
    static void signal_trap(int signo) noexcept;

    inline static bool initialized_{false};
    inline static bool has_terminal_{false};
    inline static bool is_raw_{false};
    inline static termios saved_termios_{};
};

class PtyMasterDevice {
public:
    PtyMasterDevice() noexcept = default;
    ~PtyMasterDevice() noexcept;

    PtyMasterDevice(const PtyMasterDevice&) = delete;
    PtyMasterDevice& operator=(const PtyMasterDevice&) = delete;

    bool open() noexcept;
    void close() noexcept;

    [[nodiscard]] int get_fd() const noexcept { return fd_; }
    [[nodiscard]] const char* get_slave_name() const noexcept { return slave_name_; }
    
    [[nodiscard]] int open_slave_fd() const noexcept {
        return ::open(slave_name_, O_RDWR | O_NOCTTY);
    }

    void forward_window_size() const noexcept;

private:
    int fd_{-1};
    char slave_name_[256]{};
};

int run_pty_multiplexer(int master_fd, int slave_fd, pid_t worker_pid, uint32_t timeout_sec) noexcept;
