#include "daemon/ipc_server.h"

#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

// Minimal JSON helpers (avoid external dependency for IPC layer)
namespace {

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
        if (json[end] == '\\') end++;  // skip escaped chars
        end++;
    }
    return json.substr(start, end - start);
}

std::string json_error(const std::string& msg) {
    return R"({"status":"error","message":")" + msg + R"("})";
}

}  // namespace

namespace aegis {

IpcServer::IpcServer(const std::string& socket_path)
    : socket_path_(socket_path.empty() ? resolve_socket_path() : socket_path) {}

IpcServer::~IpcServer() {
    shutdown();
}

std::string IpcServer::resolve_socket_path() {
    // If running as root, use /run/aegis/
    if (geteuid() == 0) {
        return DEFAULT_SOCKET_PATH;
    }
    // Otherwise use ~/.aegis/aegisd.sock
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    return std::string(home) + "/" + USER_SOCKET_DIR + "/aegisd.sock";
}

void IpcServer::register_handler(const std::string& type, MessageHandler handler) {
    handlers_[type] = std::move(handler);
}

int IpcServer::start() {
    // Create parent directory
    auto last_slash = socket_path_.rfind('/');
    if (last_slash != std::string::npos) {
        std::string dir = socket_path_.substr(0, last_slash);
        mkdir(dir.c_str(), 0755);
    }

    // Remove stale socket
    unlink(socket_path_.c_str());

    listen_fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listen_fd_ < 0) {
        throw std::runtime_error("socket() failed: " + std::string(strerror(errno)));
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(addr.sun_path)) {
        throw std::runtime_error("Socket path too long");
    }
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw std::runtime_error("bind() failed: " + std::string(strerror(errno)));
    }

    // Set socket permissions (owner only for user socket, group for root)
    if (geteuid() == 0) {
        chmod(socket_path_.c_str(), 0660);
    } else {
        chmod(socket_path_.c_str(), 0600);
    }

    if (listen(listen_fd_, MAX_CLIENTS) < 0) {
        throw std::runtime_error("listen() failed: " + std::string(strerror(errno)));
    }

    return listen_fd_;
}

int IpcServer::accept_client() {
    int fd = accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd >= 0) {
        clients_[fd] = ClientBuffer{};
    }
    return fd;
}

bool IpcServer::process_client(int client_fd) {
    auto it = clients_.find(client_fd);
    if (it == clients_.end()) {
        clients_[client_fd] = ClientBuffer{};
        it = clients_.find(client_fd);
    }

    auto& buf = it->second;

    // Read available data
    uint8_t tmp[4096];
    ssize_t n = recv(client_fd, tmp, sizeof(tmp), 0);
    if (n <= 0) {
        return false;  // disconnected or error
    }

    buf.recv_buf.insert(buf.recv_buf.end(), tmp, tmp + n);

    // Process complete messages (length-prefix protocol)
    while (true) {
        if (!buf.have_header && buf.recv_buf.size() >= 4) {
            // Read 4-byte LE length
            uint32_t len = 0;
            len |= static_cast<uint32_t>(buf.recv_buf[0]);
            len |= static_cast<uint32_t>(buf.recv_buf[1]) << 8;
            len |= static_cast<uint32_t>(buf.recv_buf[2]) << 16;
            len |= static_cast<uint32_t>(buf.recv_buf[3]) << 24;

            if (len > MAX_MESSAGE_SIZE) {
                return false;  // message too large, disconnect
            }

            buf.expected_len = len;
            buf.have_header = true;
            buf.recv_buf.erase(buf.recv_buf.begin(), buf.recv_buf.begin() + 4);
        }

        if (buf.have_header && buf.recv_buf.size() >= buf.expected_len) {
            std::string json(buf.recv_buf.begin(),
                             buf.recv_buf.begin() + buf.expected_len);
            buf.recv_buf.erase(buf.recv_buf.begin(),
                               buf.recv_buf.begin() + buf.expected_len);
            buf.have_header = false;
            buf.expected_len = 0;

            std::string response = dispatch(json);
            if (!send_message(client_fd, response)) {
                return false;
            }
        } else {
            break;  // need more data
        }
    }

    return true;
}

void IpcServer::close_client(int client_fd) {
    clients_.erase(client_fd);
    close(client_fd);
}

void IpcServer::shutdown() {
    for (auto& [fd, _] : clients_) {
        close(fd);
    }
    clients_.clear();
    if (listen_fd_ >= 0) {
        close(listen_fd_);
        listen_fd_ = -1;
    }
    unlink(socket_path_.c_str());
}

bool IpcServer::send_message(int fd, const std::string& json) {
    uint32_t len = static_cast<uint32_t>(json.size());
    uint8_t header[4];
    header[0] = len & 0xFF;
    header[1] = (len >> 8) & 0xFF;
    header[2] = (len >> 16) & 0xFF;
    header[3] = (len >> 24) & 0xFF;

    // Send header + body (small messages, should succeed in one write)
    struct iovec iov[2];
    iov[0].iov_base = header;
    iov[0].iov_len = 4;
    iov[1].iov_base = const_cast<char*>(json.data());
    iov[1].iov_len = json.size();

    struct msghdr msg{};
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    ssize_t sent = sendmsg(fd, &msg, MSG_NOSIGNAL);
    return sent == static_cast<ssize_t>(4 + json.size());
}

std::string IpcServer::dispatch(const std::string& json) {
    std::string type = json_get_string(json, "type");
    if (type.empty()) {
        return json_error("missing 'type' field");
    }

    auto it = handlers_.find(type);
    if (it == handlers_.end()) {
        return json_error("unknown message type: " + type);
    }

    try {
        return it->second(json);
    } catch (const std::exception& e) {
        return json_error(e.what());
    }
}

}  // namespace aegis
