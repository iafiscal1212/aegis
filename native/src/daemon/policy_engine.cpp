#include "daemon/policy_engine.h"
#include "daemon/database.h"
#include "daemon/http_client.h"
#include "daemon/typosquat.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <sstream>

namespace aegis {

PolicyEngine::PolicyEngine(Database& db, TyposquatDetector& typo, HttpClient& http)
    : db_(db), typo_(typo), http_(http) {}

void PolicyEngine::load_config(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_path_ = path;

    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception&) {
        // Use defaults if file doesn't exist or is invalid
        return;
    }

    if (root["mode"]) config_.mode = root["mode"].as<std::string>();

    if (root["ecosystems"]) {
        auto eco = root["ecosystems"];
        if (eco["python"] && eco["python"]["enabled"])
            config_.python_enabled = eco["python"]["enabled"].as<bool>();
        if (eco["node"] && eco["node"]["enabled"])
            config_.node_enabled = eco["node"]["enabled"].as<bool>();
        if (eco["rust"] && eco["rust"]["enabled"])
            config_.rust_enabled = eco["rust"]["enabled"].as<bool>();
    }

    if (root["typosquat_enabled"])
        config_.typosquat_enabled = root["typosquat_enabled"].as<bool>();
    if (root["typosquat_threshold"])
        config_.typosquat_threshold = root["typosquat_threshold"].as<int>();

    if (root["agent_mode"])
        config_.agent_mode = root["agent_mode"].as<std::string>();
    if (root["agent_typosquat_threshold"])
        config_.agent_typosquat_threshold = root["agent_typosquat_threshold"].as<int>();

    if (root["slopsquat_check"])
        config_.slopsquat_check = root["slopsquat_check"].as<bool>();
    if (root["osv_check"])
        config_.osv_check = root["osv_check"].as<bool>();
    if (root["registry_cache_ttl"])
        config_.registry_cache_ttl = root["registry_cache_ttl"].as<int>();

    auto load_list = [](const YAML::Node& node) -> std::vector<std::string> {
        std::vector<std::string> list;
        if (node && node.IsSequence()) {
            for (const auto& item : node) {
                list.push_back(item.as<std::string>());
            }
        }
        return list;
    };

    config_.allowlist = load_list(root["allowlist"]);
    config_.blocklist = load_list(root["blocklist"]);
    config_.agent_blocklist = load_list(root["agent_blocklist"]);
    config_.agent_allowlist = load_list(root["agent_allowlist"]);

    // Apply threshold to detector
    typo_.set_threshold(config_.typosquat_threshold);
}

void PolicyEngine::reload() {
    if (!config_path_.empty()) {
        load_config(config_path_);
    }
}

PolicyEngine::ParsedCommand PolicyEngine::parse_command(const std::string& command) const {
    ParsedCommand result;
    std::istringstream iss(command);
    std::vector<std::string> tokens;
    std::string token;
    while (iss >> token) tokens.push_back(token);

    if (tokens.empty()) return result;

    // Find the package manager
    std::string manager;
    size_t pkg_start = 0;
    for (size_t i = 0; i < tokens.size(); ++i) {
        const auto& t = tokens[i];
        if (t == "pip" || t == "pip3" || t == "python" || t == "python3") {
            manager = "pip";
            // Find "install" subcommand
            for (size_t j = i + 1; j < tokens.size(); ++j) {
                if (tokens[j] == "install") {
                    pkg_start = j + 1;
                    break;
                }
                if (tokens[j] == "-m" && j + 1 < tokens.size() && tokens[j + 1] == "pip") {
                    j++; // skip "pip"
                }
            }
            break;
        } else if (t == "npm" || t == "yarn" || t == "pnpm") {
            manager = t;
            for (size_t j = i + 1; j < tokens.size(); ++j) {
                if (tokens[j] == "install" || tokens[j] == "add" || tokens[j] == "i") {
                    pkg_start = j + 1;
                    break;
                }
            }
            break;
        } else if (t == "cargo") {
            manager = "cargo";
            for (size_t j = i + 1; j < tokens.size(); ++j) {
                if (tokens[j] == "install" || tokens[j] == "add") {
                    pkg_start = j + 1;
                    break;
                }
            }
            break;
        }
    }

    result.manager = manager;
    result.ecosystem = detect_ecosystem(manager);

    // Extract package names (skip flags)
    for (size_t i = pkg_start; i < tokens.size(); ++i) {
        const auto& t = tokens[i];
        if (t.empty() || t[0] == '-') {
            // Skip flags; also skip next token for flags that take values
            if (t == "-r" || t == "--requirement" || t == "-e" || t == "--editable" ||
                t == "-i" || t == "--index-url" || t == "--extra-index-url") {
                i++; // skip value
            }
            continue;
        }
        // Strip version specifiers (name>=1.0, name==1.0, name[extra])
        std::string pkg = t;
        auto bracket = pkg.find('[');
        if (bracket != std::string::npos) pkg = pkg.substr(0, bracket);
        auto ver = pkg.find_first_of(">=<!=~");
        if (ver != std::string::npos) pkg = pkg.substr(0, ver);
        if (!pkg.empty()) {
            result.packages.push_back(pkg);
        }
    }

    return result;
}

std::string PolicyEngine::detect_ecosystem(const std::string& manager) const {
    if (manager == "pip" || manager == "pip3") return "python";
    if (manager == "npm" || manager == "yarn" || manager == "pnpm") return "node";
    if (manager == "cargo") return "rust";
    return "unknown";
}

bool PolicyEngine::is_in_list(const std::string& name,
                               const std::vector<std::string>& list) const {
    return std::find(list.begin(), list.end(), name) != list.end();
}

CheckResult PolicyEngine::check_command(const std::string& command,
                                         const std::string& agent) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto parsed = parse_command(command);
    if (parsed.packages.empty()) {
        return {"allow", {}, agent};
    }

    // Check ecosystem enabled
    if ((parsed.ecosystem == "python" && !config_.python_enabled) ||
        (parsed.ecosystem == "node" && !config_.node_enabled) ||
        (parsed.ecosystem == "rust" && !config_.rust_enabled)) {
        return {"allow", {"ecosystem disabled, skipping"}, agent};
    }

    CheckResult result;
    result.action = "allow";
    result.agent = agent;

    bool is_agent = !agent.empty();

    for (const auto& pkg : parsed.packages) {
        // Blocklist
        if (is_in_list(pkg, config_.blocklist)) {
            result.action = "block";
            result.alerts.push_back("[BLOCK] " + pkg + ": in blocklist");
            db_.log_decision(pkg, parsed.ecosystem, "block", "blocklist", false, agent);
            continue;
        }

        // Agent blocklist
        if (is_agent && is_in_list(pkg, config_.agent_blocklist)) {
            result.action = "block";
            result.alerts.push_back("[BLOCK] " + pkg + ": in agent blocklist");
            db_.log_decision(pkg, parsed.ecosystem, "block", "agent_blocklist", false, agent);
            continue;
        }

        // Allowlist → skip further checks
        if (is_in_list(pkg, config_.allowlist)) {
            db_.log_decision(pkg, parsed.ecosystem, "allow", "allowlist", false, agent);
            continue;
        }

        // Typosquatting
        if (config_.typosquat_enabled) {
            int threshold = is_agent ? config_.agent_typosquat_threshold
                                     : config_.typosquat_threshold;
            TyposquatDetector detector(threshold);
            auto matches = detector.check(pkg, parsed.ecosystem);
            if (!matches.empty()) {
                auto& m = matches[0];
                std::string level = (is_agent || config_.mode == "strict") ? "BLOCK" : "WARN";
                std::string msg = "[" + level + "] " + pkg +
                    ": possible typosquat of '" + m.popular_name + "'" +
                    " (score=" + std::to_string(m.score).substr(0, 4) + ")";
                result.alerts.push_back(msg);

                std::string action = (level == "BLOCK") ? "block" : "warn";
                if (action == "block" || result.action != "block") {
                    result.action = action;
                }
                db_.log_decision(pkg, parsed.ecosystem, action,
                                 "typosquat:" + m.popular_name, false, agent);
                continue;
            }
        }

        // Slopsquatting (registry existence check)
        if (config_.slopsquat_check && is_agent) {
            auto cached = db_.get_registry_cache(pkg, parsed.ecosystem,
                                                  config_.registry_cache_ttl);
            bool exists;
            if (cached) {
                exists = cached->exists;
            } else {
                exists = http_.check_package_exists(pkg, parsed.ecosystem);
                db_.set_registry_cache(pkg, parsed.ecosystem, exists);
            }
            if (!exists) {
                result.action = "block";
                result.alerts.push_back("[BLOCK] " + pkg +
                    ": package does not exist in registry (possible slopsquat/hallucination)");
                db_.log_decision(pkg, parsed.ecosystem, "block", "slopsquat", false, agent);
                continue;
            }
        }

        // OSV vulnerability check
        if (config_.osv_check) {
            auto vulns = http_.check_osv(pkg, parsed.ecosystem);
            if (!vulns.empty()) {
                std::string level = is_agent ? "BLOCK" : "WARN";
                for (const auto& v : vulns) {
                    result.alerts.push_back("[" + level + "] " + pkg + ": " + v);
                }
                std::string action = (level == "BLOCK") ? "block" : "warn";
                if (action == "block" || result.action != "block") {
                    result.action = action;
                }
                db_.log_decision(pkg, parsed.ecosystem, action,
                                 "osv:" + vulns[0], false, agent);
                continue;
            }
        }

        // Passed all checks
        db_.log_decision(pkg, parsed.ecosystem, "allow", "passed", false, agent);
    }

    return result;
}

CheckResult PolicyEngine::check_package(const std::string& name,
                                         const std::string& ecosystem,
                                         const std::string& agent) {
    // Build a synthetic command for reuse
    std::string manager;
    if (ecosystem == "python") manager = "pip";
    else if (ecosystem == "node") manager = "npm";
    else if (ecosystem == "rust") manager = "cargo";
    else manager = "pip";

    return check_command(manager + " install " + name, agent);
}

}  // namespace aegis
