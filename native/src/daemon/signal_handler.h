#pragma once

#include <functional>

namespace aegis {

class SignalHandler {
public:
    using Callback = std::function<void(int)>;

    // Create signalfd for SIGTERM, SIGHUP, SIGINT
    // Returns fd for epoll integration
    static int create_signal_fd();

    // Read and dispatch pending signals from signalfd
    // Returns signal number, or 0 if no signal
    static int read_signal(int signal_fd);

    // Block signals in current thread (call before epoll loop)
    static void block_signals();

    // Set callbacks
    static void set_shutdown_callback(Callback cb);
    static void set_reload_callback(Callback cb);

    // Dispatch signal to appropriate callback
    static void dispatch(int signum);

private:
    static Callback shutdown_cb_;
    static Callback reload_cb_;
};

}  // namespace aegis
