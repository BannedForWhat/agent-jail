#pragma once

#include <cstdint>
#include <sys/types.h>

enum class SyncStage : uint32_t {
    StageUsernsReady = 0x5501,
    StageSetupDone   = 0x5502,
    StageError       = 0xE001
};

struct SyncChannel {
    int fd{-1};

    bool send_token(SyncStage stage) const noexcept;
    bool wait_token(SyncStage& out_stage) const noexcept;
    void close() noexcept;
};

bool create_sync_pair(SyncChannel& parent_chan, SyncChannel& child_chan) noexcept;
bool supervisor_handle_handshake(pid_t child_pid, int sync_fd, uid_t host_uid, gid_t host_gid, const char* cgroup_procs_path) noexcept;
bool worker_await_handshake(int sync_fd) noexcept;
