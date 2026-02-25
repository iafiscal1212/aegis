#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace aegis {

class Database;
class TyposquatDetector;
class HttpClient;

struct PolicyConfig {
    std::string mode = "interactive";      // interactive/strict/permissive

    // Ecosystems
    bool python_enabled = true;
    bool node_enabled = true;
    bool rust_enabled = true;

    // Typosquatting
    bool typosquat_enabled = true;
    int typosquat_threshold = 2;

    // Agent
    std::string agent_mode = "strict";     // strict/moderate/permissive
    int agent_typosquat_threshold = 1;

    // Checks
    bool slopsquat_check = true;
    bool osv_check = true;
    int registry_cache_ttl = 3600;

    // Lists
    std::vector<std::string> allowlist;
    std::vector<std::string> blocklist;
    std::vector<std::string> agent_blocklist;
    std::vector<std::string> agent_allowlist;
};

struct CheckResult {
    std::string action;                   // "allow", "warn", "block"
    std::vector<std::string> alerts;
    std::string agent;
};

class PolicyEngine {
public:
    PolicyEngine(Database& db, TyposquatDetector& typo, HttpClient& http);

    // Load config from YAML file
    void load_config(const std::string& path);

    // Reload config (SIGHUP)
    void reload();

    // Get current config
    const PolicyConfig& config() const { return config_; }

    // Check a package install command
    CheckResult check_command(const std::string& command,
                              const std::string& agent = "");

    // Check a single package
    CheckResult check_package(const std::string& name,
                              const std::string& ecosystem,
                              const std::string& agent = "");

    // Get blocklist/allowlist for BPF map sync
    const std::vector<std::string>& blocklist() const { return config_.blocklist; }
    const std::vector<std::string>& allowlist() const { return config_.allowlist; }

private:
    Database& db_;
    TyposquatDetector& typo_;
    HttpClient& http_;
    PolicyConfig config_;
    std::string config_path_;
    mutable std::mutex mutex_;

    struct ParsedCommand {
        std::string ecosystem;
        std::string manager;
        std::vector<std::string> packages;
    };

    ParsedCommand parse_command(const std::string& command) const;
    bool is_in_list(const std::string& name, const std::vector<std::string>& list) const;
    std::string detect_ecosystem(const std::string& manager) const;
};

}  // namespace aegis
