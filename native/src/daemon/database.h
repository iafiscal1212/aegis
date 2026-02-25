#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aegis {

struct Decision {
    int64_t id;
    std::string package_name;
    std::string ecosystem;
    std::string action;     // "allow", "warn", "block"
    std::string reason;
    bool user_override;
    std::string agent_name;
    std::string timestamp;
};

struct PackageRecord {
    int64_t id;
    std::string name;
    std::string version;
    std::string ecosystem;
    double risk_score;
    std::string first_seen;
    std::string last_checked;
    std::string metadata_json;
};

struct RegistryCacheEntry {
    bool exists;
    std::string checked_at;
};

class Database {
public:
    explicit Database(const std::string& path);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    void initialize();

    // Decisions
    void log_decision(const std::string& package_name,
                      const std::string& ecosystem,
                      const std::string& action,
                      const std::string& reason,
                      bool user_override,
                      const std::string& agent_name);
    std::vector<Decision> get_recent_decisions(int limit = 50);
    std::vector<Decision> get_agent_decisions(const std::string& agent, int limit = 50);

    // Packages
    void upsert_package(const std::string& name,
                        const std::string& ecosystem,
                        const std::string& version,
                        double risk_score,
                        const std::string& metadata_json);
    std::optional<PackageRecord> get_package(const std::string& name,
                                             const std::string& ecosystem);

    // Registry cache
    std::optional<RegistryCacheEntry> get_registry_cache(
        const std::string& name, const std::string& ecosystem, int ttl_seconds);
    void set_registry_cache(const std::string& name,
                            const std::string& ecosystem, bool exists);

    // Stats
    struct Stats {
        int64_t total_packages;
        int64_t total_decisions;
        int64_t blocked_count;
        int64_t warned_count;
        int64_t allowed_count;
    };
    Stats get_stats();

private:
    sqlite3* db_ = nullptr;
    void exec(const char* sql);
    sqlite3_stmt* prepare(const char* sql);
};

}  // namespace aegis
