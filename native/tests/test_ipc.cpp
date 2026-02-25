#include "daemon/ipc_server.h"
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <chrono>

class IpcTest : public ::testing::Test {
protected:
    void SetUp() override {
        socket_path_ = "/tmp/aegis_test_ipc.sock";
        unlink(socket_path_.c_str());
    }

    void TearDown() override {
        unlink(socket_path_.c_str());
    }

    std::string socket_path_;

    // Helper: send length-prefixed JSON
    static bool send_msg(int fd, const std::string& json) {
        uint32_t len = json.size();
        uint8_t header[4];
        header[0] = len & 0xFF;
        header[1] = (len >> 8) & 0xFF;
        header[2] = (len >> 16) & 0xFF;
        header[3] = (len >> 24) & 0xFF;
        if (write(fd, header, 4) != 4) return false;
        if (write(fd, json.data(), json.size()) != (ssize_t)json.size()) return false;
        return true;
    }

    // Helper: recv length-prefixed JSON
    static std::string recv_msg(int fd) {
        uint8_t header[4];
        if (read(fd, header, 4) != 4) return "";
        uint32_t len = header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24);
        std::string buf(len, '\0');
        if (read(fd, &buf[0], len) != (ssize_t)len) return "";
        return buf;
    }
};

TEST_F(IpcTest, PingPong) {
    aegis::IpcServer server(socket_path_);
    server.register_handler("ping", [](const std::string&) -> std::string {
        return R"({"status":"ok","message":"pong"})";
    });
    server.start();

    // Connect client
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(client, 0);

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    ASSERT_EQ(connect(client, (struct sockaddr*)&addr, sizeof(addr)), 0);

    // Accept on server side
    int srv_client = server.accept_client();
    ASSERT_GE(srv_client, 0);

    // Send ping
    ASSERT_TRUE(send_msg(client, R"({"type":"ping"})"));

    // Process on server
    ASSERT_TRUE(server.process_client(srv_client));

    // Read response
    std::string resp = recv_msg(client);
    EXPECT_NE(resp.find("pong"), std::string::npos);

    close(client);
    server.close_client(srv_client);
    server.shutdown();
}

TEST_F(IpcTest, UnknownType) {
    aegis::IpcServer server(socket_path_);
    server.start();

    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
    connect(client, (struct sockaddr*)&addr, sizeof(addr));

    int srv_client = server.accept_client();

    send_msg(client, R"({"type":"nonexistent"})");
    server.process_client(srv_client);

    std::string resp = recv_msg(client);
    EXPECT_NE(resp.find("error"), std::string::npos);

    close(client);
    server.close_client(srv_client);
    server.shutdown();
}
