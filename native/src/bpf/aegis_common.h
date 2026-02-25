/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* aegis_common.h — Shared structures between eBPF and userspace */

#ifndef AEGIS_COMMON_H
#define AEGIS_COMMON_H

#ifdef __cplusplus
#include <cstdint>
#else
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#endif

/* --- Constants --- */
#define AEGIS_MAX_PATH        256
#define AEGIS_MAX_PKG_NAME    128
#define AEGIS_MAX_REASON      128
#define AEGIS_MAX_COMM        16
#define AEGIS_RINGBUF_SIZE    (256 * 1024)  /* 256 KB */

/* --- Event types (kernel → userspace via ring buffer) --- */
enum aegis_event_type {
    AEGIS_EVENT_EXEC_BLOCKED    = 1,  /* execve blocked by blocklist */
    AEGIS_EVENT_EXEC_AUDIT      = 2,  /* execve needs userspace analysis */
    AEGIS_EVENT_FILE_BLOCKED    = 3,  /* file_open blocked (credential) */
    AEGIS_EVENT_UNLINK_BLOCKED  = 4,  /* inode_unlink blocked (self-protect) */
    AEGIS_EVENT_KILL_BLOCKED    = 5,  /* kill blocked (daemon protection) */
    AEGIS_EVENT_AGENT_EXEC      = 6,  /* agent-initiated execution */
};

/* --- Policy flags --- */
enum aegis_policy_flags {
    AEGIS_POL_BLOCKED   = (1 << 0),   /* Hard block */
    AEGIS_POL_AUDIT     = (1 << 1),   /* Send to userspace for analysis */
    AEGIS_POL_ALLOWED   = (1 << 2),   /* Explicitly allowed */
    AEGIS_POL_AGENT     = (1 << 3),   /* Stricter checks for AI agents */
};

/* --- BPF map value structs --- */

/* monitored_binaries map: key = path_hash (u64), value = this struct */
struct monitored_binary {
    uint32_t flags;                        /* aegis_policy_flags */
    uint32_t pattern_id;                   /* ID for destructive pattern matching */
    char     binary_name[AEGIS_MAX_COMM];  /* short name for logging */
};

/* blocked_packages map: key = name_hash (u64), value = this struct */
struct blocked_entry {
    char reason[AEGIS_MAX_REASON];
};

/* agent_pids map: key = pid (u32), value = this struct */
struct agent_info {
    char agent_name[AEGIS_MAX_COMM];   /* "claude", "cursor", "copilot" */
    uint64_t start_time;               /* ktime_ns or epoch */
    uint32_t flags;                    /* future use */
};

/* config_map: array index 0, value = this struct */
struct global_config {
    uint32_t enabled;                  /* master kill switch */
    uint32_t enforce_mode;             /* 0=audit, 1=enforce */
    uint32_t protect_credentials;      /* file_open hook active */
    uint32_t protect_self;             /* inode_unlink + task_kill active */
    uint32_t agent_default_deny;       /* block unknown pkgs from agents */
    uint32_t daemon_pid;               /* aegisd PID for task_kill hook */
};

/* Ring buffer event: kernel → userspace */
struct exec_event {
    uint32_t event_type;               /* aegis_event_type */
    uint32_t pid;
    uint32_t tgid;
    uint32_t uid;
    uint64_t timestamp_ns;
    char     comm[AEGIS_MAX_COMM];
    char     filename[AEGIS_MAX_PATH];
    uint32_t is_agent;                 /* Was caller an AI agent? */
    uint32_t policy_flags;             /* What triggered this event */
};

#endif /* AEGIS_COMMON_H */
