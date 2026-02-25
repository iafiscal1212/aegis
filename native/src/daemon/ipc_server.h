#pragma once

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace aegis {

// JSON message handler: receives request JSON, returns response JSON
using MessageHandler = std::function<std::string(const std::string&)>;

class IpcServer {
public:
    static constexpr const char* DEFAULT_SOCKET_PATH = "/run/aegis/aegisd.sock";
    static constexpr const char* USER_SOCKET_DIR = ".aegis";
    static constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024;  // 1MB
    static constexpr int MAX_CLIENTS = 32;

    explicit IpcServer(const std::string& socket_path = "");
    ~IpcServer();

    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    // Register handler for a message type
    void register_handler(const std::string& type, MessageHandler handler);

    // Start listening, returns fd for epoll
    int start();

    // Accept new client, returns client fd
    int accept_client();

    // Read and process message from client fd
    // Returns false if client disconnected
    bool process_client(int client_fd);

    // Close a client
    void close_client(int client_fd);

    // Shutdown server
    void shutdown();

    // Get the listen fd for epoll
    int listen_fd() const { return listen_fd_; }

    // Get socket path
    const std::string& socket_path() const { return socket_path_; }

private:
    std::string socket_path_;
    int listen_fd_ = -1;
    std::unordered_map<std::string, MessageHandler> handlers_;

    struct ClientBuffer {
        std::vector<uint8_t> recv_buf;
        size_t expected_len = 0;
        bool have_header = false;
    };
    std::unordered_map<int, ClientBuffer> clients_;

    bool send_message(int fd, const std::string& json);
    std::string dispatch(const std::string& json);
    static std::string resolve_socket_path();
};

}  // namespace aegis
