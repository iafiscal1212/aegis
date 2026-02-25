#pragma once

#ifdef AEGIS_BPF_ENABLED

#include "bpf/aegis_common.h"

#include <functional>
#include <string>

// Forward declare skeleton
struct aegis_lsm_bpf;

namespace aegis {

class BpfManager {
public:
    using EventCallback = std::function<void(const struct exec_event*)>;

    BpfManager();
    ~BpfManager();

    BpfManager(const BpfManager&) = delete;
    BpfManager& operator=(const BpfManager&) = delete;

    // Load and attach eBPF programs
    void load_and_attach();

    // Detach and unload
    void detach();

    // Map operations
    void add_blocked_package(const std::string& name, const std::string& reason);
    void remove_blocked_package(const std::string& name);
    void add_allowed_package(const std::string& name);
    void remove_allowed_package(const std::string& name);
    void add_monitored_binary(const std::string& path, uint32_t flags, uint32_t pattern_id);
    void add_agent_pid(uint32_t pid, const std::string& name);
    void remove_agent_pid(uint32_t pid);
    void add_protected_pid(uint32_t pid);
    void add_protected_path(const std::string& path);

    // Set daemon PID in config
    void set_daemon_pid(uint32_t pid);

    // Update global config
    void set_enforce_mode(bool enforce);
    void set_enabled(bool enabled);

    // Poll ring buffer for events
    void poll_events(EventCallback callback);

    // Get ring buffer fd for epoll
    int ring_buffer_fd() const;

    // Check if loaded
    bool is_loaded() const { return loaded_; }

private:
    struct aegis_lsm_bpf* skel_ = nullptr;
    struct ring_buffer* rb_ = nullptr;
    bool loaded_ = false;
    EventCallback event_cb_;

    static uint64_t hash_name(const std::string& name);
    void update_config(struct global_config& cfg);
    struct global_config read_config();
};

}  // namespace aegis

#endif  // AEGIS_BPF_ENABLED
