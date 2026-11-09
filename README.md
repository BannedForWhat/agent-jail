# agent-jail

**Sub-millisecond (<1ms) Unprivileged Linux Containerless Runtime Sandbox for Autonomous AI Coding Agents.**

`agent-jail` is a lightweight, zero-allocation C++20 process isolator designed specifically for autonomous AI agents (Cline, Roo Code, Aider, OpenHands) running on modern Linux kernels. It eliminates the latency, D-Bus overhead, and root daemon requirements of standard OCI container runtimes (`runc`, `crun`, Docker, Podman) while enforcing strict hardware-level kernel containment.

---

## Architectural Comparison

| Security / Performance Invariant | Docker / Podman (OCI) | `systemd-run --user --scope` | `agent-jail` (Bare-Metal C++20) |
| :--- | :--- | :--- | :--- |
| **Cold Start Latency** | 1,500 – 3,000 ms | 15 – 35 ms (D-Bus serialization) | **< 1 ms (850 – 1,150 µs)** |
| **Privilege Requirement** | Root / Rootless subuid mapping | Unprivileged (`systemd --user`) | **Strictly Unprivileged (`CLONE_NEWUSER`)** |
| **Filesystem Security** | OverlayFS + mount namespaces | Host root accessible | **`pivot_root` + Merged `/usr` + Landlock LSM (ABI v5)** |
| **WAN Network Egress** | Virtual bridge / slirp4netns | Full host network access | **Airgapped (`CLONE_NEWNET` + Seccomp `AF_UNIX` only)** |
| **Local AI Gateway (IPC)** | Complex host-gateway routing | Open localhost port | **Pathname UNIX socket bind-mount (`prompt-mesh`)** |
| **Syscall Filtering** | Static seccomp JSON profile | None by default | **Handcrafted cBPF (`clone3 -> ENOSYS`, ptrace/io_uring block)** |
| **Resource Sandboxing** | cgroups v1/v2 via shim daemon | cgroups v2 via systemd D-Bus | **Direct cgroups v2 (`memory.max`, `memory.swap.max = 0`, `pids.max`)** |
| **Terminal Interactive Mode** | PTY docker attach | Systemd PTY forwarding | **In-kernel PTY pair (`openpty`) with RAII raw-mode safety** |

---

## Defense-in-Depth Architecture

```text
Host (Arch Linux, Kernel 6.x, systemd 256+)
 ├── Supervisor (C++20, PID: host)
 │    ├── Direct cgroups v2 enforcer (user.slice/user-1000.slice/user@1000.service/agent-jail-<PID>)
 │    │    ├── memory.max & memory.swap.max = 0 (OOM enforcement)
 │    │    └── pids.max = 128 (Fork-bomb defense)
 │    ├── socketpair(AF_UNIX, SOCK_SEQPACKET) (Deadlock-free handshake FSM)
 │    ├── prctl(PR_SET_CHILD_SUBREAPER, 1) (Zombie process reaping)
 │    └── epoll_pwait2 reactor + signalfd (PTY master <-> host terminal)
 │
 └── Worker Subtree (PID 1 in isolated namespaces)
      ├── Namespaces: CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS
      ├── VFS Isolation:
      │    ├── tmpfs root + Arch Linux Merged /usr relative symlinks (bin, lib, lib64, sbin)
      │    ├── Read-only bind mounts: /usr, /etc (ld.so.cache, resolv.conf, synthetic passwd/group)
      │    ├── Read-write workspace: /workspace (host home directory strictly stripped)
      │    ├── Local AI IPC: Pathname UNIX domain socket mapped to /run/prompt-mesh.sock
      │    └── Atomic pivot_root(2) + umount2(/.oldroot, MNT_DETACH)
      ├── Landlock LSM (ABI v1-v5):
      │    ├── Read-Only / Execute: / (entire VFS hierarchy)
      │    └── Read-Write: /workspace, /tmp, /dev/shm, /run, /dev
      └── Seccomp-BPF Policy:
           ├── AUDIT_ARCH_X86_64 enforcement (x32 ABI killed)
           ├── clone3 -> SECCOMP_RET_ERRNO(ENOSYS) (glibc graceful fallback to clone)
           ├── io_uring_setup, enter, register -> SECCOMP_RET_ERRNO(EPERM)
           ├── ptrace, process_vm_*, bpf, kexec_load -> SECCOMP_RET_ERRNO(EPERM)
           └── socket(2) domain check: AF_UNIX allowed, AF_INET/AF_INET6 -> EAFNOSUPPORT
```

---

## Building & Installation

### Prerequisites (Arch Linux)
```bash
sudo pacman -S base-devel cmake ninja libutil-linux
```

### System Configuration (One-time cgroups v2 delegation)
```bash
sudo mkdir -p /etc/systemd/system/user@.service.d/
sudo tee /etc/systemd/system/user@.service.d/delegate.conf << 'EOF'
[Service]
Delegate=memory pids cpu io cpuset
