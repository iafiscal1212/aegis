#include "daemon/agent_monitor.h"
#include "daemon/database.h"
#include "daemon/http_client.h"
#include "daemon/ipc_server.h"
#include "daemon/policy_engine.h"
#include "daemon/signal_handler.h"
#include "daemon/typosquat.h"

#ifdef AEGIS_BPF_ENABLED
#include "daemon/bpf_manager.h"
#endif

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

// Minimal JSON builder for IPC responses
namespace {

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    auto start = json.find('"', pos + 1);
    if (start == std::string::npos) return "";
    start++;
    auto end = start;
    while (end < json.size() && json[end] != '"') {
        if (json[end] == '\\') end++;
        end++;
    }
    return json.substr(start, end - start);
}

// sd_notify for systemd readiness (manual implementation to avoid libsystemd dep)
void sd_notify_ready() {
    const char* sock = getenv("NOTIFY_SOCKET");
    if (!sock) return;

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (sock[0] == '@') {
        addr.sun_path[0] = '\0';
        strncpy(addr.sun_path + 1, sock + 1, sizeof(addr.sun_path) - 2);
    } else {
        strncpy(addr.sun_path, sock, sizeof(addr.sun_path) - 1);
    }

    const char* msg = "READY=1\nSTATUS=aegisd running";
    size_t path_len = (sock[0] == '@')
        ? 1 + strlen(sock + 1)
        : strlen(sock);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + path_len;

    sendto(fd, msg, strlen(msg), 0,
           reinterpret_cast<struct sockaddr*>(&addr), addr_len);
    close(fd);
}

}  // namespace

static constexpr int MAX_EPOLL_EVENTS = 64;
static constexpr int AGENT_SCAN_INTERVAL_SEC = 30;

static std::string find_config_path() {
    // 1. /etc/aegis/config.yml (system)
    if (access("/etc/aegis/config.yml", R_OK) == 0)
        return "/etc/aegis/config.yml";

    // 2. ~/.aegis/config.yml (user)
    const char* home = getenv("HOME");
    if (home) {
        std::string path = std::string(home) + "/.aegis/config.yml";
        if (access(path.c_str(), R_OK) == 0)
            return path;
    }

    // 3. Bundled default
    return "/etc/aegis/config.yml";
}

static std::string find_db_path() {
    if (geteuid() == 0) {
        mkdir("/var/lib/aegis", 0755);
        return "/var/lib/aegis/aegis.db";
    }
    const char* home = getenv("HOME");
    if (home) {
        std::string dir = std::string(home) + "/.aegis";
        mkdir(dir.c_str(), 0700);
        return dir + "/aegis.db";
    }
    return "/tmp/aegis.db";
}

int main(int argc, char* argv[]) {
    // Parse basic options
    std::string config_path;
    std::string socket_path;
    bool foreground = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-f" || arg == "--foreground") {
            foreground = true;
        } else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_path = argv[++i];
        } else if ((arg == "-s" || arg == "--socket") && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "aegisd 1.0.0" << std::endl;
            return 0;
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: aegisd [OPTIONS]\n"
                      << "  -f, --foreground    Run in foreground\n"
                      << "  -c, --config PATH   Config file path\n"
                      << "  -s, --socket PATH   IPC socket path\n"
                      << "  -v, --version       Show version\n"
                      << "  -h, --help          Show help\n";
            return 0;
        }
    }

    if (config_path.empty()) config_path = find_config_path();
    std::string db_path = find_db_path();

    std::cerr << "[aegisd] Starting v1.0.0" << std::endl;
    std::cerr << "[aegisd] Config: " << config_path << std::endl;
    std::cerr << "[aegisd] Database: " << db_path << std::endl;

    // Initialize components
    aegis::Database db(db_path);
    db.initialize();

    aegis::TyposquatDetector typo;
    aegis::HttpClient http;
    aegis::PolicyEngine policy(db, typo, http);
    policy.load_config(config_path);

    aegis::AgentMonitor agent_monitor;
    aegis::IpcServer ipc(socket_path);

#ifdef AEGIS_BPF_ENABLED
    aegis::BpfManager bpf;
    bool bpf_loaded = false;
    try {
        bpf.load_and_attach();
        bpf_loaded = true;
        // Sync policy to BPF maps
        for (const auto& pkg : policy.blocklist()) {
            bpf.add_blocked_package(pkg, "config blocklist");
        }
        for (const auto& pkg : policy.allowlist()) {
            bpf.add_allowed_package(pkg);
        }
        bpf.set_daemon_pid(getpid());
        std::cerr << "[aegisd] eBPF programs loaded and attached" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[aegisd] WARNING: eBPF not available: " << e.what() << std::endl;
        std::cerr << "[aegisd] Falling back to userspace-only mode" << std::endl;
    }
#endif

    // Register IPC handlers
    ipc.register_handler("check", [&](const std::string& json) -> std::string {
        std::string command = json_get_string(json, "command");
        std::string agent = json_get_string(json, "agent");
        auto result = policy.check_command(command, agent);

        std::string alerts_json = "[";
        for (size_t i = 0; i < result.alerts.size(); ++i) {
            if (i > 0) alerts_json += ",";
            alerts_json += "\"" + json_escape(result.alerts[i]) + "\"";
        }
        alerts_json += "]";

        return R"({"status":"ok","action":")" + result.action +
               R"(","alerts":)" + alerts_json +
               R"(,"agent":")" + json_escape(result.agent) + R"("})";
    });

    ipc.register_handler("check_package", [&](const std::string& json) -> std::string {
        std::string name = json_get_string(json, "name");
        std::string ecosystem = json_get_string(json, "ecosystem");
        std::string agent = json_get_string(json, "agent");
        auto result = policy.check_package(name, ecosystem, agent);

        std::string alerts_json = "[";
        for (size_t i = 0; i < result.alerts.size(); ++i) {
            if (i > 0) alerts_json += ",";
            alerts_json += "\"" + json_escape(result.alerts[i]) + "\"";
        }
        alerts_json += "]";

        return R"({"status":"ok","action":")" + result.action +
               R"(","alerts":)" + alerts_json + R"(})";
    });

    ipc.register_handler("check_hook", [&](const std::string& json) -> std::string {
        // Claude Code PreToolUse hook protocol
        std::string command = json_get_string(json, "command");
        std::string agent = json_get_string(json, "agent");
        if (agent.empty()) agent = "claude";
        auto result = policy.check_command(command, agent);

        std::string alerts_json = "[";
        for (size_t i = 0; i < result.alerts.size(); ++i) {
            if (i > 0) alerts_json += ",";
            alerts_json += "\"" + json_escape(result.alerts[i]) + "\"";
        }
        alerts_json += "]";

        return R"({"status":"ok","action":")" + result.action +
               R"(","alerts":)" + alerts_json +
               R"(,"agent":")" + json_escape(result.agent) + R"("})";
    });

    ipc.register_handler("status", [&](const std::string&) -> std::string {
        auto stats = db.get_stats();
        auto agents = agent_monitor.agents();

        std::string bpf_status = "unavailable";
#ifdef AEGIS_BPF_ENABLED
        bpf_status = bpf_loaded ? "active" : "failed";
#endif

        std::string agents_json = "[";
        size_t i = 0;
        for (const auto& [pid, agent] : agents) {
            if (i++ > 0) agents_json += ",";
            agents_json += R"({"pid":)" + std::to_string(pid) +
                           R"(,"name":")" + json_escape(agent.name) + R"("})";
        }
        agents_json += "]";

        return R"({"status":"ok","version":"1.0.0","mode":")" +
               policy.config().mode +
               R"(","bpf":")" + bpf_status +
               R"(","packages":)" + std::to_string(stats.total_packages) +
               R"(,"decisions":)" + std::to_string(stats.total_decisions) +
               R"(,"blocked":)" + std::to_string(stats.blocked_count) +
               R"(,"agents":)" + agents_json + R"(})";
    });

    ipc.register_handler("reload_config", [&](const std::string&) -> std::string {
        policy.reload();
#ifdef AEGIS_BPF_ENABLED
        if (bpf_loaded) {
            for (const auto& pkg : policy.blocklist())
                bpf.add_blocked_package(pkg, "config blocklist");
            for (const auto& pkg : policy.allowlist())
                bpf.add_allowed_package(pkg);
        }
#endif
        return R"({"status":"ok","message":"config reloaded"})";
    });

    ipc.register_handler("ping", [](const std::string&) -> std::string {
        return R"({"status":"ok","message":"pong"})";
    });

    // Setup signal handling
    aegis::SignalHandler::block_signals();
    int signal_fd = aegis::SignalHandler::create_signal_fd();

    bool running = true;
    aegis::SignalHandler::set_shutdown_callback([&](int) {
        std::cerr << "[aegisd] Shutting down..." << std::endl;
        running = false;
    });
    aegis::SignalHandler::set_reload_callback([&](int) {
        std::cerr << "[aegisd] Reloading config..." << std::endl;
        policy.reload();
    });

    // Start IPC server
    int ipc_fd = ipc.start();
    std::cerr << "[aegisd] IPC socket: " << ipc.socket_path() << std::endl;

    // Create timer for periodic agent scanning
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd >= 0) {
        struct itimerspec ts{};
        ts.it_value.tv_sec = 5;  // first scan after 5s
        ts.it_interval.tv_sec = AGENT_SCAN_INTERVAL_SEC;
        timerfd_settime(timer_fd, 0, &ts, nullptr);
    }

    // Setup epoll
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        std::cerr << "[aegisd] epoll_create1 failed" << std::endl;
        return 1;
    }

    auto epoll_add = [&](int fd, uint32_t events) {
        struct epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    };

    epoll_add(signal_fd, EPOLLIN);
    epoll_add(ipc_fd, EPOLLIN);
    if (timer_fd >= 0) epoll_add(timer_fd, EPOLLIN);

#ifdef AEGIS_BPF_ENABLED
    int ring_buf_fd = -1;
    if (bpf_loaded) {
        ring_buf_fd = bpf.ring_buffer_fd();
        if (ring_buf_fd >= 0) {
            epoll_add(ring_buf_fd, EPOLLIN);
        }
    }
#endif

    // Notify systemd we're ready
    sd_notify_ready();
    std::cerr << "[aegisd] Ready." << std::endl;

    // Main event loop
    struct epoll_event events[MAX_EPOLL_EVENTS];

    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, 1000);

        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;

            if (fd == signal_fd) {
                int sig = aegis::SignalHandler::read_signal(signal_fd);
                if (sig > 0) aegis::SignalHandler::dispatch(sig);

            } else if (fd == ipc_fd) {
                // New client connection
                int client_fd = ipc.accept_client();
                if (client_fd >= 0) {
                    epoll_add(client_fd, EPOLLIN | EPOLLHUP);
                }

            } else if (fd == timer_fd) {
                // Timer: scan for agents
                uint64_t expirations;
                read(timer_fd, &expirations, sizeof(expirations));

                agent_monitor.cleanup_dead();
                auto new_agents = agent_monitor.scan();
                for (const auto& a : new_agents) {
                    std::cerr << "[aegisd] Agent detected: " << a.name
                              << " (PID " << a.pid << ")" << std::endl;
#ifdef AEGIS_BPF_ENABLED
                    if (bpf_loaded) {
                        bpf.add_agent_pid(a.pid, a.name);
                    }
#endif
                }

#ifdef AEGIS_BPF_ENABLED
            } else if (fd == ring_buf_fd && bpf_loaded) {
                bpf.poll_events([&](const struct exec_event* ev) {
                    std::cerr << "[aegisd] BPF event: type=" << ev->event_type
                              << " pid=" << ev->pid
                              << " file=" << ev->filename << std::endl;

                    if (ev->event_type == AEGIS_EVENT_EXEC_AUDIT) {
                        // Userspace analysis needed
                        auto result = policy.check_command(ev->filename,
                            ev->is_agent ? agent_monitor.agent_name(ev->pid) : "");
                        if (result.action == "allow") {
                            // Add to allowed list for next attempt
                            bpf.add_allowed_package(ev->filename);
                        }
                    }
                });
#endif
            } else {
                // Client data or disconnect
                if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
                    ipc.close_client(fd);
                } else if (events[i].events & EPOLLIN) {
                    if (!ipc.process_client(fd)) {
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
                        ipc.close_client(fd);
                    }
                }
            }
        }
    }

    // Cleanup
    if (timer_fd >= 0) close(timer_fd);
    close(signal_fd);
    close(epoll_fd);
    ipc.shutdown();

#ifdef AEGIS_BPF_ENABLED
    if (bpf_loaded) bpf.detach();
#endif

    std::cerr << "[aegisd] Stopped." << std::endl;
    return 0;
}
