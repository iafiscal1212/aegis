#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace aegis {

struct DetectedAgent {
    uint32_t pid;
    std::string name;         // "claude", "cursor", "copilot", etc.
    std::string cmdline;
    uint64_t start_time;
};

class AgentMonitor {
public:
    AgentMonitor() = default;

    // Scan /proc for AI agent processes
    // Returns newly detected agents since last scan
    std::vector<DetectedAgent> scan();

    // Get all currently known agents
    const std::unordered_map<uint32_t, DetectedAgent>& agents() const {
        return agents_;
    }

    // Check if a PID belongs to a known agent
    bool is_agent_pid(uint32_t pid) const;

    // Get agent name for PID (empty if not an agent)
    std::string agent_name(uint32_t pid) const;

    // Clean up dead processes
    void cleanup_dead();

private:
    std::unordered_map<uint32_t, DetectedAgent> agents_;

    static bool is_agent_process(const std::string& cmdline,
                                  const std::string& environ,
                                  std::string& agent_name);
    static std::string read_proc_file(uint32_t pid, const char* filename);
    static std::vector<uint32_t> list_pids();
};

}  // namespace aegis
