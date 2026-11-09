#pragma once

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <cstddef>
#include <cerrno>

inline const struct sock_filter agent_jail_bpf_filter[] = {
    // 0: Валидация архитектуры x86_64: A = seccomp_data.arch
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    // 1: if (arch == AUDIT_ARCH_X86_64) goto 3 else goto 2
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    // 2: KILL
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    // 3: Загрузка номера системного вызова: A = seccomp_data.nr
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // 4: Проверка диапазона x32 ABI: nr >= 0x40000000 -> KILL
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
    // 5: KILL
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    // 6: clone3 -> возврат ENOSYS для фоллбэка glibc на clone()
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
    // 7: RET ENOSYS
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),

    // 8..10: Блокировка io_uring -> переход на 11 (RET EPERM)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_register, 0, 1),
    // 11: RET EPERM
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

    // 12..17: Блокировка отладки и небезопасных сисколлов -> переход на 18 (RET EPERM)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 5, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv, 4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_writev, 3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kexec_load, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_userfaultfd, 0, 1),
    // 18: RET EPERM
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

    // 19: socket(2): if (nr == socket) goto 20 else goto 24 (RET ALLOW)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 4),
    // 20: Загрузка args[0] (domain)
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    // 21: if (domain == AF_UNIX) goto 23 else goto 22
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 1, 0),
    // 22: Блокировка внешних сетей -> RET EAFNOSUPPORT
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EAFNOSUPPORT & SECCOMP_RET_DATA)),
    // 23: Восстановление nr в аккумуляторе
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // 24: Разрешить системный вызов
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
};

inline const struct sock_fprog agent_jail_seccomp_prog = {
    .len = static_cast<unsigned short>(sizeof(agent_jail_bpf_filter) / sizeof(agent_jail_bpf_filter[0])),
    .filter = const_cast<struct sock_filter*>(agent_jail_bpf_filter),
};
