#ifdef AEGIS_BPF_ENABLED

#include "daemon/bpf_manager.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Generated skeleton header
#include "aegis_lsm.skel.h"

#include <cstring>
#include <stdexcept>
#include <unistd.h>

namespace aegis {

BpfManager::BpfManager() = default;

BpfManager::~BpfManager() {
    detach();
}

uint64_t BpfManager::hash_name(const std::string& name) {
    // FNV-1a 64-bit — must match kernel-side implementation
    uint64_t hash = 14695981039346656037ULL;
    for (char c : name) {
        hash ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
        hash *= 1099511628211ULL;
    }
    return hash;
}

void BpfManager::load_and_attach() {
    // Bump RLIMIT for BPF
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    skel_ = aegis_lsm_bpf__open();
    if (!skel_) {
        throw std::runtime_error("Failed to open BPF skeleton");
    }

    int err = aegis_lsm_bpf__load(skel_);
    if (err) {
        aegis_lsm_bpf__destroy(skel_);
        skel_ = nullptr;
        throw std::runtime_error("Failed to load BPF programs: " + std::to_string(err));
    }

    err = aegis_lsm_bpf__attach(skel_);
    if (err) {
        aegis_lsm_bpf__destroy(skel_);
        skel_ = nullptr;
        throw std::runtime_error("Failed to attach BPF programs: " + std::to_string(err));
    }

    // Setup ring buffer
    rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.events),
                            [](void* ctx, void* data, size_t size) -> int {
                                auto* mgr = static_cast<BpfManager*>(ctx);
                                if (mgr->event_cb_ && size >= sizeof(struct exec_event)) {
                                    mgr->event_cb_(static_cast<const struct exec_event*>(data));
                                }
                                return 0;
                            },
                            this, nullptr);
    if (!rb_) {
        aegis_lsm_bpf__destroy(skel_);
        skel_ = nullptr;
        throw std::runtime_error("Failed to create ring buffer");
    }

    // Initialize config
    struct global_config cfg{};
    cfg.enabled = 1;
    cfg.enforce_mode = 1;
    cfg.protect_credentials = 1;
    cfg.protect_self = 1;
    cfg.agent_default_deny = 1;
    cfg.daemon_pid = getpid();
    update_config(cfg);

    // Protect our own PID
    add_protected_pid(getpid());

    loaded_ = true;
}

void BpfManager::detach() {
    if (rb_) {
        ring_buffer__free(rb_);
        rb_ = nullptr;
    }
    if (skel_) {
        aegis_lsm_bpf__destroy(skel_);
        skel_ = nullptr;
    }
    loaded_ = false;
}

void BpfManager::add_blocked_package(const std::string& name, const std::string& reason) {
    if (!loaded_) return;
    uint64_t key = hash_name(name);
    struct blocked_entry val{};
    strncpy(val.reason, reason.c_str(), sizeof(val.reason) - 1);
    bpf_map__update_elem(skel_->maps.blocked_packages,
                          &key, sizeof(key), &val, sizeof(val), BPF_ANY);
}

void BpfManager::remove_blocked_package(const std::string& name) {
    if (!loaded_) return;
    uint64_t key = hash_name(name);
    bpf_map__delete_elem(skel_->maps.blocked_packages,
                          &key, sizeof(key), 0);
}

void BpfManager::add_allowed_package(const std::string& name) {
    if (!loaded_) return;
    uint64_t key = hash_name(name);
    uint32_t val = 1;
    bpf_map__update_elem(skel_->maps.allowed_packages,
                          &key, sizeof(key), &val, sizeof(val), BPF_ANY);
}

void BpfManager::remove_allowed_package(const std::string& name) {
    if (!loaded_) return;
    uint64_t key = hash_name(name);
    bpf_map__delete_elem(skel_->maps.allowed_packages,
                          &key, sizeof(key), 0);
}

void BpfManager::add_monitored_binary(const std::string& path,
                                        uint32_t flags, uint32_t pattern_id) {
    if (!loaded_) return;
    uint64_t key = hash_name(path);
    struct monitored_binary val{};
    val.flags = flags;
    val.pattern_id = pattern_id;
    strncpy(val.binary_name, path.c_str(), sizeof(val.binary_name) - 1);
    bpf_map__update_elem(skel_->maps.monitored_binaries,
                          &key, sizeof(key), &val, sizeof(val), BPF_ANY);
}

void BpfManager::add_agent_pid(uint32_t pid, const std::string& name) {
    if (!loaded_) return;
    struct agent_info val{};
    strncpy(val.agent_name, name.c_str(), sizeof(val.agent_name) - 1);
    val.start_time = 0;  // filled by kernel if needed
    bpf_map__update_elem(skel_->maps.agent_pids,
                          &pid, sizeof(pid), &val, sizeof(val), BPF_ANY);
}

void BpfManager::remove_agent_pid(uint32_t pid) {
    if (!loaded_) return;
    bpf_map__delete_elem(skel_->maps.agent_pids,
                          &pid, sizeof(pid), 0);
}

void BpfManager::add_protected_pid(uint32_t pid) {
    if (!loaded_) return;
    uint32_t val = 1;
    bpf_map__update_elem(skel_->maps.protected_pids,
                          &pid, sizeof(pid), &val, sizeof(val), BPF_ANY);
}

void BpfManager::add_protected_path(const std::string& path) {
    if (!loaded_) return;
    uint64_t key = hash_name(path);
    uint32_t val = 1;
    bpf_map__update_elem(skel_->maps.protected_paths,
                          &key, sizeof(key), &val, sizeof(val), BPF_ANY);
}

void BpfManager::set_daemon_pid(uint32_t pid) {
    auto cfg = read_config();
    cfg.daemon_pid = pid;
    update_config(cfg);
    add_protected_pid(pid);
}

void BpfManager::set_enforce_mode(bool enforce) {
    auto cfg = read_config();
    cfg.enforce_mode = enforce ? 1 : 0;
    update_config(cfg);
}

void BpfManager::set_enabled(bool enabled) {
    auto cfg = read_config();
    cfg.enabled = enabled ? 1 : 0;
    update_config(cfg);
}

struct global_config BpfManager::read_config() {
    struct global_config cfg{};
    if (!loaded_) return cfg;
    uint32_t key = 0;
    bpf_map__lookup_elem(skel_->maps.config_map,
                          &key, sizeof(key), &cfg, sizeof(cfg), 0);
    return cfg;
}

void BpfManager::update_config(struct global_config& cfg) {
    if (!loaded_ && !skel_) return;
    uint32_t key = 0;
    bpf_map__update_elem(skel_->maps.config_map,
                          &key, sizeof(key), &cfg, sizeof(cfg), BPF_ANY);
}

void BpfManager::poll_events(EventCallback callback) {
    if (!rb_) return;
    event_cb_ = std::move(callback);
    ring_buffer__poll(rb_, 0);  // non-blocking poll
}

int BpfManager::ring_buffer_fd() const {
    if (!rb_) return -1;
    return ring_buffer__epoll_fd(rb_);
}

}  // namespace aegis

#endif  // AEGIS_BPF_ENABLED
