#include "daemon/database.h"

#include <cstring>
#include <stdexcept>

namespace aegis {

Database::Database(const std::string& path) {
    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        throw std::runtime_error("Cannot open database: " + err);
    }
    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA foreign_keys=ON");
}

Database::~Database() {
    if (db_) sqlite3_close(db_);
}

void Database::exec(const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("SQL error: " + msg);
    }
}

sqlite3_stmt* Database::prepare(const char* sql) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(
            std::string("SQL prepare error: ") + sqlite3_errmsg(db_));
    }
    return stmt;
}

void Database::initialize() {
    exec(R"(
        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            version TEXT,
            ecosystem TEXT NOT NULL,
            risk_score REAL DEFAULT 0.0,
            first_seen TEXT DEFAULT (datetime('now')),
            last_checked TEXT DEFAULT (datetime('now')),
            metadata_json TEXT DEFAULT '{}',
            UNIQUE(name, ecosystem)
        )
    )");
    exec(R"(
        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            action TEXT NOT NULL,
            reason TEXT,
            user_override INTEGER DEFAULT 0,
            agent_name TEXT DEFAULT '',
            timestamp TEXT DEFAULT (datetime('now'))
        )
    )");
    exec("CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(timestamp)");
    exec("CREATE INDEX IF NOT EXISTS idx_decisions_pkg ON decisions(package_name)");
    exec("CREATE INDEX IF NOT EXISTS idx_decisions_agent ON decisions(agent_name)");

    exec(R"(
        CREATE TABLE IF NOT EXISTS rules_version (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now'))
        )
    )");
    exec(R"(
        CREATE TABLE IF NOT EXISTS registry_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            exists_in_registry INTEGER DEFAULT 0,
            checked_at TEXT DEFAULT (datetime('now')),
            UNIQUE(package_name, ecosystem)
        )
    )");
}

void Database::log_decision(const std::string& package_name,
                            const std::string& ecosystem,
                            const std::string& action,
                            const std::string& reason,
                            bool user_override,
                            const std::string& agent_name) {
    const char* sql =
        "INSERT INTO decisions (package_name, ecosystem, action, reason, "
        "user_override, agent_name) VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = prepare(sql);
    sqlite3_bind_text(stmt, 1, package_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ecosystem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, user_override ? 1 : 0);
    sqlite3_bind_text(stmt, 6, agent_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<Decision> Database::get_recent_decisions(int limit) {
    const char* sql =
        "SELECT id, package_name, ecosystem, action, reason, user_override, "
        "agent_name, timestamp FROM decisions ORDER BY timestamp DESC LIMIT ?";
    sqlite3_stmt* stmt = prepare(sql);
    sqlite3_bind_int(stmt, 1, limit);

    std::vector<Decision> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Decision d;
        d.id = sqlite3_column_int64(stmt, 0);
        d.package_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        d.ecosystem = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        d.action = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        d.reason = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 4) ? sqlite3_column_text(stmt, 4) : reinterpret_cast<const unsigned char*>(""));
        d.user_override = sqlite3_column_int(stmt, 5) != 0;
        d.agent_name = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 6) ? sqlite3_column_text(stmt, 6) : reinterpret_cast<const unsigned char*>(""));
        d.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        results.push_back(std::move(d));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<Decision> Database::get_agent_decisions(const std::string& agent,
                                                     int limit) {
    const char* sql =
        "SELECT id, package_name, ecosystem, action, reason, user_override, "
        "agent_name, timestamp FROM decisions WHERE agent_name = ? "
        "ORDER BY timestamp DESC LIMIT ?";
    sqlite3_stmt* stmt = prepare(sql);
    sqlite3_bind_text(stmt, 1, agent.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, limit);

    std::vector<Decision> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Decision d;
        d.id = sqlite3_column_int64(stmt, 0);
        d.package_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        d.ecosystem = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        d.action = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        d.reason = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 4) ? sqlite3_column_text(stmt, 4) : reinterpret_cast<const unsigned char*>(""));
        d.user_override = sqlite3_column_int(stmt, 5) != 0;
        d.agent_name = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 6) ? sqlite3_column_text(stmt, 6) : reinterpret_cast<const unsigned char*>(""));
        d.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        results.push_back(std::move(d));
    }
    sqlite3_finalize(stmt);
    return results;
}

void Database::upsert_package(const std::string& name,
                              const std::string& ecosystem,
                              const std::string& version,
                              double risk_score,
                              const std::string& metadata_json) {
    const char* sql =
        "INSERT INTO packages (name, ecosystem, version, risk_score, metadata_json) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(name, ecosystem) DO UPDATE SET "
        "version=excluded.version, risk_score=excluded.risk_score, "
        "last_checked=datetime('now'), metadata_json=excluded.metadata_json";
    sqlite3_stmt* stmt = prepare(sql);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ecosystem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 4, risk_score);
    sqlite3_bind_text(stmt, 5, metadata_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::optional<PackageRecord> Database::get_package(const std::string& name,
                                                    const std::string& ecosystem) {
    const char* sql =
        "SELECT id, name, version, ecosystem, risk_score, first_seen, "
        "last_checked, metadata_json FROM packages WHERE name=? AND ecosystem=?";
    sqlite3_stmt* stmt = prepare(sql);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ecosystem.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<PackageRecord> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        PackageRecord p;
        p.id = sqlite3_column_int64(stmt, 0);
        p.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        p.version = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 2) ? sqlite3_column_text(stmt, 2) : reinterpret_cast<const unsigned char*>(""));
        p.ecosystem = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        p.risk_score = sqlite3_column_double(stmt, 4);
        p.first_seen = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        p.last_checked = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        p.metadata_json = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 7) ? sqlite3_column_text(stmt, 7) : reinterpret_cast<const unsigned char*>("{}"));
        result = std::move(p);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::optional<RegistryCacheEntry> Database::get_registry_cache(
    const std::string& name, const std::string& ecosystem, int ttl_seconds) {
    const char* sql =
        "SELECT exists_in_registry, checked_at FROM registry_cache "
        "WHERE package_name=? AND ecosystem=? "
        "AND checked_at > datetime('now', '-' || ? || ' seconds')";
    sqlite3_stmt* stmt = prepare(sql);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ecosystem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, ttl_seconds);

    std::optional<RegistryCacheEntry> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        RegistryCacheEntry e;
        e.exists = sqlite3_column_int(stmt, 0) != 0;
        e.checked_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        result = std::move(e);
    }
    sqlite3_finalize(stmt);
    return result;
}

void Database::set_registry_cache(const std::string& name,
                                  const std::string& ecosystem, bool exists) {
    const char* sql =
        "INSERT INTO registry_cache (package_name, ecosystem, exists_in_registry) "
        "VALUES (?, ?, ?) "
        "ON CONFLICT(package_name, ecosystem) DO UPDATE SET "
        "exists_in_registry=excluded.exists_in_registry, "
        "checked_at=datetime('now')";
    sqlite3_stmt* stmt = prepare(sql);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ecosystem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, exists ? 1 : 0);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

Database::Stats Database::get_stats() {
    Stats s{};
    sqlite3_stmt* stmt;

    stmt = prepare("SELECT COUNT(*) FROM packages");
    if (sqlite3_step(stmt) == SQLITE_ROW)
        s.total_packages = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    stmt = prepare("SELECT COUNT(*) FROM decisions");
    if (sqlite3_step(stmt) == SQLITE_ROW)
        s.total_decisions = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    stmt = prepare("SELECT COUNT(*) FROM decisions WHERE action='block'");
    if (sqlite3_step(stmt) == SQLITE_ROW)
        s.blocked_count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    stmt = prepare("SELECT COUNT(*) FROM decisions WHERE action='warn'");
    if (sqlite3_step(stmt) == SQLITE_ROW)
        s.warned_count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    stmt = prepare("SELECT COUNT(*) FROM decisions WHERE action='allow'");
    if (sqlite3_step(stmt) == SQLITE_ROW)
        s.allowed_count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    return s;
}

}  // namespace aegis
