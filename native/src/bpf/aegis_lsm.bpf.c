// SPDX-License-Identifier: GPL-2.0
// aegis_lsm.bpf.c — eBPF LSM programs for AEGIS v1.0 kernel enforcement

#include "aegis_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* ======================== BPF Maps ======================== */

/* Hash: path_hash(u64) → monitored_binary */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct monitored_binary);
} monitored_binaries SEC(".maps");

/* Hash: name_hash(u64) → blocked_entry */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct blocked_entry);
} blocked_packages SEC(".maps");

/* Hash: name_hash(u64) → __u32 (1 = allowed) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u32);
} allowed_packages SEC(".maps");

/* Hash: pid(u32) → agent_info */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct agent_info);
} agent_pids SEC(".maps");

/* Hash: pid(u32) → __u32 (1 = protected) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} protected_pids SEC(".maps");

/* Hash: path_hash(u64) → __u32 (1 = protected) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u32);
} protected_paths SEC(".maps");

/* Array: index 0 → global_config */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_config);
} config_map SEC(".maps");

/* Ring buffer: events → userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, AEGIS_RINGBUF_SIZE);
} events SEC(".maps");

/* ======================== Helpers ======================== */

/* FNV-1a 64-bit hash — eBPF verifier friendly */
static __always_inline __u64 fnv1a_hash(const char *data, int len)
{
    __u64 hash = 14695981039346656037ULL;
    #pragma unroll
    for (int i = 0; i < AEGIS_MAX_PATH && i < len; i++) {
        if (data[i] == 0)
            break;
        hash ^= (__u64)data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static __always_inline struct global_config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline int is_agent(__u32 pid)
{
    return bpf_map_lookup_elem(&agent_pids, &pid) != NULL;
}

static __always_inline void emit_event(__u32 type, __u32 pid, __u32 uid,
                                        const char *filename, int is_agent_flag,
                                        __u32 policy_flags)
{
    struct exec_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return;

    ev->event_type = type;
    ev->pid = pid;
    ev->tgid = pid;
    ev->uid = uid;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->is_agent = is_agent_flag;
    ev->policy_flags = policy_flags;

    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    /* Copy filename safely */
    int i;
    #pragma unroll
    for (i = 0; i < AEGIS_MAX_PATH - 1; i++) {
        if (filename[i] == 0)
            break;
        ev->filename[i] = filename[i];
    }
    ev->filename[i] = 0;

    bpf_ringbuf_submit(ev, 0);
}

/* ======================== LSM Hooks ======================== */

/*
 * Hook: bprm_check_security
 * Intercepts execve() calls. Checks:
 * 1. Is the binary in blocked_packages? → EPERM
 * 2. Is the binary in allowed_packages? → allow
 * 3. Is caller an AI agent? → if agent_default_deny, send audit event
 * 4. Is the binary in monitored_binaries? → send audit event
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_bprm_check, struct linux_binprm *bprm)
{
    struct global_config *cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    /* Read filename from bprm */
    char filename[AEGIS_MAX_PATH] = {};
    bpf_probe_read_str(filename, sizeof(filename),
                        BPF_CORE_READ(bprm, filename));

    __u64 path_hash = fnv1a_hash(filename, AEGIS_MAX_PATH);
    int agent = is_agent(pid);

    /* 1. Check blocked packages (O(1) hash lookup) */
    struct blocked_entry *blocked = bpf_map_lookup_elem(&blocked_packages, &path_hash);
    if (blocked) {
        emit_event(AEGIS_EVENT_EXEC_BLOCKED, pid, uid, filename, agent,
                   AEGIS_POL_BLOCKED);
        if (cfg->enforce_mode)
            return -1;  /* EPERM */
    }

    /* 2. Check allowed packages (O(1) hash lookup) */
    __u32 *allowed = bpf_map_lookup_elem(&allowed_packages, &path_hash);
    if (allowed)
        return 0;  /* explicitly allowed */

    /* 3. Check monitored binaries */
    struct monitored_binary *mon = bpf_map_lookup_elem(&monitored_binaries, &path_hash);
    if (mon) {
        __u32 event_type = (mon->flags & AEGIS_POL_BLOCKED)
                           ? AEGIS_EVENT_EXEC_BLOCKED
                           : AEGIS_EVENT_EXEC_AUDIT;
        emit_event(event_type, pid, uid, filename, agent, mon->flags);

        if ((mon->flags & AEGIS_POL_BLOCKED) && cfg->enforce_mode)
            return -1;
    }

    /* 4. Agent default-deny: unknown binary from AI agent */
    if (agent && cfg->agent_default_deny) {
        emit_event(AEGIS_EVENT_AGENT_EXEC, pid, uid, filename, 1,
                   AEGIS_POL_AUDIT | AEGIS_POL_AGENT);
        /* Don't block yet — let userspace decide. The daemon will
         * add to allowed_packages if safe, or blocked_packages if not.
         * For now, allow but audit. */
    }

    return 0;
}

/*
 * Hook: file_open
 * Protects credential files from being read by package install scripts.
 * Guards: .ssh/, .aws/, .env, .npmrc, .pypirc
 */
SEC("lsm/file_open")
int BPF_PROG(aegis_file_open, struct file *file)
{
    struct global_config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->protect_credentials)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    /* Only protect when called from an agent context */
    if (!is_agent(pid))
        return 0;

    /* Read file path */
    char filename[AEGIS_MAX_PATH] = {};
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    bpf_probe_read_str(filename, sizeof(filename),
                        BPF_CORE_READ(dentry, d_name.name));

    /* Check for sensitive file patterns */
    /* .ssh directory */
    if (filename[0] == '.' && filename[1] == 's' && filename[2] == 's' &&
        filename[3] == 'h') {
        emit_event(AEGIS_EVENT_FILE_BLOCKED, pid, uid, filename, 1,
                   AEGIS_POL_BLOCKED);
        if (cfg->enforce_mode)
            return -1;
    }

    /* .aws directory */
    if (filename[0] == '.' && filename[1] == 'a' && filename[2] == 'w' &&
        filename[3] == 's') {
        emit_event(AEGIS_EVENT_FILE_BLOCKED, pid, uid, filename, 1,
                   AEGIS_POL_BLOCKED);
        if (cfg->enforce_mode)
            return -1;
    }

    /* .env file */
    if (filename[0] == '.' && filename[1] == 'e' && filename[2] == 'n' &&
        filename[3] == 'v' && (filename[4] == 0 || filename[4] == '.')) {
        emit_event(AEGIS_EVENT_FILE_BLOCKED, pid, uid, filename, 1,
                   AEGIS_POL_BLOCKED);
        if (cfg->enforce_mode)
            return -1;
    }

    /* .npmrc */
    if (filename[0] == '.' && filename[1] == 'n' && filename[2] == 'p' &&
        filename[3] == 'm' && filename[4] == 'r' && filename[5] == 'c') {
        emit_event(AEGIS_EVENT_FILE_BLOCKED, pid, uid, filename, 1,
                   AEGIS_POL_BLOCKED);
        if (cfg->enforce_mode)
            return -1;
    }

    /* .pypirc */
    if (filename[0] == '.' && filename[1] == 'p' && filename[2] == 'y' &&
        filename[3] == 'p' && filename[4] == 'i' && filename[5] == 'r' &&
        filename[6] == 'c') {
        emit_event(AEGIS_EVENT_FILE_BLOCKED, pid, uid, filename, 1,
                   AEGIS_POL_BLOCKED);
        if (cfg->enforce_mode)
            return -1;
    }

    return 0;
}

/*
 * Hook: inode_unlink
 * Protects AEGIS files from deletion.
 * Guards: /usr/local/bin/aegisd, /etc/aegis/*, files in protected_paths map
 */
SEC("lsm/inode_unlink")
int BPF_PROG(aegis_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    struct global_config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->protect_self)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    char filename[AEGIS_MAX_PATH] = {};
    bpf_probe_read_str(filename, sizeof(filename),
                        BPF_CORE_READ(dentry, d_name.name));

    __u64 hash = fnv1a_hash(filename, AEGIS_MAX_PATH);

    /* Check protected_paths map */
    __u32 *prot = bpf_map_lookup_elem(&protected_paths, &hash);
    if (prot) {
        emit_event(AEGIS_EVENT_UNLINK_BLOCKED, pid, uid, filename, 0,
                   AEGIS_POL_BLOCKED);
        if (cfg->enforce_mode)
            return -1;
    }

    /* Hardcoded protection for aegisd binary */
    if (filename[0] == 'a' && filename[1] == 'e' && filename[2] == 'g' &&
        filename[3] == 'i' && filename[4] == 's' && filename[5] == 'd' &&
        filename[6] == 0) {
        emit_event(AEGIS_EVENT_UNLINK_BLOCKED, pid, uid, filename, 0,
                   AEGIS_POL_BLOCKED);
        if (cfg->enforce_mode)
            return -1;
    }

    return 0;
}

/*
 * Hook: task_kill
 * Prevents killing the aegisd daemon.
 * Only allows SIGTERM from root (for clean shutdown via systemctl).
 */
SEC("lsm/task_kill")
int BPF_PROG(aegis_task_kill, struct task_struct *target, struct kernel_siginfo *info,
             int sig, const struct cred *cred)
{
    struct global_config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->protect_self)
        return 0;

    __u32 target_pid = BPF_CORE_READ(target, tgid);

    /* Check if target is a protected PID */
    __u32 *prot = bpf_map_lookup_elem(&protected_pids, &target_pid);
    if (!prot)
        return 0;

    /* Also check if target is the daemon PID */
    if (target_pid != cfg->daemon_pid)
        return 0;

    __u32 sender_pid = bpf_get_current_pid_tgid() >> 32;
    __u32 sender_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    /* Allow root to send SIGTERM (systemctl stop) */
    if (sender_uid == 0 && sig == 15 /* SIGTERM */)
        return 0;

    /* Allow the daemon to signal itself */
    if (sender_pid == target_pid)
        return 0;

    /* Block all other kill attempts */
    char filename[AEGIS_MAX_PATH] = "aegisd";
    emit_event(AEGIS_EVENT_KILL_BLOCKED, sender_pid, sender_uid, filename,
               0, AEGIS_POL_BLOCKED);

    if (cfg->enforce_mode)
        return -1;

    return 0;
}
