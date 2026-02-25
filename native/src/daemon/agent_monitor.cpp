#include "daemon/agent_monitor.h"

#include <dirent.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>

namespace aegis {

std::string AgentMonitor::read_proc_file(uint32_t pid, const char* filename) {
    std::string path = "/proc/" + std::to_string(pid) + "/" + filename;
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";

    std::string content;
    content.resize(4096);
    f.read(&content[0], content.size());
    content.resize(f.gcount());

    // Replace null bytes with spaces for easier searching
    std::replace(content.begin(), content.end(), '\0', ' ');
    return content;
}

std::vector<uint32_t> AgentMonitor::list_pids() {
    std::vector<uint32_t> pids;
    DIR* dir = opendir("/proc");
    if (!dir) return pids;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        char* end;
        unsigned long pid = strtoul(entry->d_name, &end, 10);
        if (*end == '\0' && pid > 0) {
            pids.push_back(static_cast<uint32_t>(pid));
        }
    }
    closedir(dir);
    return pids;
}

bool AgentMonitor::is_agent_process(const std::string& cmdline,
                                     const std::string& environ,
                                     std::string& agent_name) {
    // Convert to lowercase for matching
    std::string cmd_lower = cmdline;
    std::string env_lower = environ;
    std::transform(cmd_lower.begin(), cmd_lower.end(), cmd_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::transform(env_lower.begin(), env_lower.end(), env_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Claude Code
    if (cmd_lower.find("claude") != std::string::npos ||
        env_lower.find("claude_code") != std::string::npos ||
        env_lower.find("anthropic_api") != std::string::npos) {
        agent_name = "claude";
        return true;
    }

    // Cursor
    if (cmd_lower.find("cursor") != std::string::npos ||
        env_lower.find("cursor_") != std::string::npos) {
        agent_name = "cursor";
        return true;
    }

    // GitHub Copilot
    if (cmd_lower.find("copilot") != std::string::npos ||
        env_lower.find("github_copilot") != std::string::npos) {
        agent_name = "copilot";
        return true;
    }

    // Aider
    if (cmd_lower.find("aider") != std::string::npos) {
        agent_name = "aider";
        return true;
    }

    // Continue.dev
    if (cmd_lower.find("continue") != std::string::npos &&
        env_lower.find("continue_") != std::string::npos) {
        agent_name = "continue";
        return true;
    }

    // Cody (Sourcegraph)
    if (cmd_lower.find("cody") != std::string::npos ||
        env_lower.find("src_endpoint") != std::string::npos) {
        agent_name = "cody";
        return true;
    }

    // Windsurf
    if (cmd_lower.find("windsurf") != std::string::npos) {
        agent_name = "windsurf";
        return true;
    }

    // Generic: check for common AI-related env vars
    if (env_lower.find("openai_api_key") != std::string::npos ||
        env_lower.find("ai_agent=") != std::string::npos) {
        agent_name = "unknown_agent";
        return true;
    }

    return false;
}

std::vector<DetectedAgent> AgentMonitor::scan() {
    std::vector<DetectedAgent> new_agents;
    auto pids = list_pids();

    auto now = std::chrono::system_clock::now().time_since_epoch();
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(now).count();

    for (uint32_t pid : pids) {
        // Skip already known
        if (agents_.count(pid)) continue;

        std::string cmdline = read_proc_file(pid, "cmdline");
        if (cmdline.empty()) continue;

        std::string environ = read_proc_file(pid, "environ");
        std::string name;

        if (is_agent_process(cmdline, environ, name)) {
            DetectedAgent agent;
            agent.pid = pid;
            agent.name = name;
            agent.cmdline = cmdline.substr(0, 256);  // truncate
            agent.start_time = timestamp;

            agents_[pid] = agent;
            new_agents.push_back(agent);
        }
    }

    return new_agents;
}

bool AgentMonitor::is_agent_pid(uint32_t pid) const {
    return agents_.count(pid) > 0;
}

std::string AgentMonitor::agent_name(uint32_t pid) const {
    auto it = agents_.find(pid);
    return (it != agents_.end()) ? it->second.name : "";
}

void AgentMonitor::cleanup_dead() {
    auto it = agents_.begin();
    while (it != agents_.end()) {
        // Check if process still exists
        if (kill(it->first, 0) != 0) {
            it = agents_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace aegis
