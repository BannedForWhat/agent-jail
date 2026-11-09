#include "pty.hpp"
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <csignal>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <array>

bool TerminalStateGuard::initialize() noexcept {
    if (initialized_) return true;

    if (::isatty(STDIN_FILENO)) {
        if (::tcgetattr(STDIN_FILENO, &saved_termios_) == -1) {
            return false;
        }
        has_terminal_ = true;
        std::atexit(TerminalStateGuard::restore_atexit);

        struct sigaction sa{};
        sa.sa_handler = TerminalStateGuard::signal_trap;
        sigemptyset(&sa.sa_mask);
        ::sigaction(SIGINT, &sa, nullptr);
        ::sigaction(SIGTERM, &sa, nullptr);
        ::sigaction(SIGHUP, &sa, nullptr);
        ::sigaction(SIGQUIT, &sa, nullptr);
    }

    initialized_ = true;
    return true;
}

void TerminalStateGuard::enter_raw_mode() noexcept {
    if (!has_terminal_ || is_raw_) return;
    termios raw = saved_termios_;
    ::cfmakeraw(&raw);
    if (::tcsetattr(STDIN_FILENO, TCSADRAIN, &raw) != -1) {
        is_raw_ = true;
    }
}

void TerminalStateGuard::restore() noexcept {
    if (has_terminal_ && is_raw_) {
        ::tcsetattr(STDIN_FILENO, TCSADRAIN, &saved_termios_);
        is_raw_ = false;
    }
}

void TerminalStateGuard::restore_atexit() noexcept {
    restore();
}

void TerminalStateGuard::signal_trap(int signo) noexcept {
    restore();
    ::_exit(128 + signo);
}

PtyMasterDevice::~PtyMasterDevice() noexcept {
    close();
}

bool PtyMasterDevice::open() noexcept {
    close();

    fd_ = ::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (fd_ == -1) return false;

    if (::grantpt(fd_) == -1) {
        close();
        return false;
    }

    if (::unlockpt(fd_) == -1) {
        close();
        return false;
    }

    if (::ptsname_r(fd_, slave_name_, sizeof(slave_name_)) != 0) {
        close();
        return false;
    }

    return true;
}

void PtyMasterDevice::close() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    slave_name_[0] = '\0';
}

void PtyMasterDevice::forward_window_size() const noexcept {
    if (fd_ < 0) return;
    winsize ws{};
    if (::ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0) {
        ::ioctl(fd_, TIOCSWINSZ, &ws);
    }
}

static bool set_nonblocking(int fd) noexcept {
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags == -1) return false;
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

static void drain_master_to_stdout(int master_fd, std::array<char, 8192>& buf) noexcept {
    while (true) {
        ssize_t n = ::read(master_fd, buf.data(), buf.size());
        if (n <= 0) break;
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = ::write(STDOUT_FILENO, buf.data() + written, n - written);
            if (w <= 0) break;
            written += w;
        }
    }
}

int run_pty_multiplexer(int master_fd, int slave_fd, pid_t worker_pid, uint32_t timeout_sec) noexcept {
    TerminalStateGuard::initialize();
    TerminalStateGuard::enter_raw_mode();

    struct GuardScope {
        ~GuardScope() noexcept { TerminalStateGuard::restore(); }
    } scope;

    int epfd = ::epoll_create1(EPOLL_CLOEXEC);
    if (epfd == -1) {
        if (slave_fd >= 0) ::close(slave_fd);
        return -1;
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGWINCH);
    sigaddset(&mask, SIGCHLD);
    ::sigprocmask(SIG_BLOCK, &mask, nullptr);

    int sfd = ::signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd == -1) {
        ::close(epfd);
        if (slave_fd >= 0) ::close(slave_fd);
        return -1;
    }

    int tfd = -1;
    if (timeout_sec > 0) {
        tfd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (tfd >= 0) {
            itimerspec its{};
            its.it_value.tv_sec = timeout_sec;
            ::timerfd_settime(tfd, 0, &its, nullptr);
        }
    }

    set_nonblocking(STDIN_FILENO);
    set_nonblocking(master_fd);

    auto reg_epoll = [epfd](int fd, uint32_t evs) noexcept {
        epoll_event ev{};
        ev.events = evs;
        ev.data.fd = fd;
        return ::epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != -1;
    };

    reg_epoll(STDIN_FILENO, EPOLLIN);
    reg_epoll(master_fd, EPOLLIN);
    reg_epoll(sfd, EPOLLIN);
    if (tfd >= 0) reg_epoll(tfd, EPOLLIN);

    std::array<char, 8192> buffer{};
    bool running = true;

    while (running) {
        std::array<epoll_event, 8> events{};
        int nfds = ::epoll_wait(epfd, events.data(), static_cast<int>(events.size()), -1);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < nfds; ++i) {
            int current_fd = events[i].data.fd;

            if (current_fd == sfd) {
                signalfd_siginfo fdsi{};
                if (::read(sfd, &fdsi, sizeof(fdsi)) == sizeof(fdsi)) {
                    if (fdsi.ssi_signo == SIGWINCH) {
                        winsize ws{};
                        if (::ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0) {
                            ::ioctl(master_fd, TIOCSWINSZ, &ws);
                        }
                    } else if (fdsi.ssi_signo == SIGCHLD) {
                        // Воркер завершился: полностью вычитываем буфер и останавливаем реактор
                        drain_master_to_stdout(master_fd, buffer);
                        if (slave_fd >= 0) {
                            ::close(slave_fd);
                            slave_fd = -1;
                        }
                        drain_master_to_stdout(master_fd, buffer);
                        running = false;
                        break;
                    }
                }
            } else if (tfd >= 0 && current_fd == tfd) {
                ::kill(-worker_pid, SIGKILL);
                running = false;
                break;
            } else if (current_fd == STDIN_FILENO) {
                ssize_t n = ::read(STDIN_FILENO, buffer.data(), buffer.size());
                if (n > 0) {
                    ssize_t written = 0;
                    while (written < n) {
                        ssize_t w = ::write(master_fd, buffer.data() + written, n - written);
                        if (w <= 0) break;
                        written += w;
                    }
                }
            } else if (current_fd == master_fd) {
                ssize_t n = ::read(master_fd, buffer.data(), buffer.size());
                if (n > 0) {
                    ssize_t written = 0;
                    while (written < n) {
                        ssize_t w = ::write(STDOUT_FILENO, buffer.data() + written, n - written);
                        if (w <= 0) break;
                        written += w;
                    }
                } else if (n < 0 && errno == EIO) {
                    running = false;
                    break;
                } else if (n == 0) {
                    running = false;
                    break;
                }
            }
        }
    }

    drain_master_to_stdout(master_fd, buffer);
    if (slave_fd >= 0) {
        ::close(slave_fd);
        slave_fd = -1;
    }
    drain_master_to_stdout(master_fd, buffer);

    if (tfd >= 0) ::close(tfd);
    ::close(sfd);
    ::close(epfd);

    int exit_status = 0;
    ::waitpid(worker_pid, &exit_status, 0);
    return WIFEXITED(exit_status) ? WEXITSTATUS(exit_status) : (128 + WTERMSIG(exit_status));
}
