#include "daemon/signal_handler.h"

#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>

namespace aegis {

SignalHandler::Callback SignalHandler::shutdown_cb_;
SignalHandler::Callback SignalHandler::reload_cb_;

void SignalHandler::block_signals() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGPIPE);

    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
        throw std::runtime_error("sigprocmask failed");
    }
}

int SignalHandler::create_signal_fd() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);

    int fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd < 0) {
        throw std::runtime_error("signalfd failed");
    }
    return fd;
}

int SignalHandler::read_signal(int signal_fd) {
    struct signalfd_siginfo info;
    ssize_t n = read(signal_fd, &info, sizeof(info));
    if (n != sizeof(info)) {
        return 0;
    }
    return static_cast<int>(info.ssi_signo);
}

void SignalHandler::set_shutdown_callback(Callback cb) {
    shutdown_cb_ = std::move(cb);
}

void SignalHandler::set_reload_callback(Callback cb) {
    reload_cb_ = std::move(cb);
}

void SignalHandler::dispatch(int signum) {
    switch (signum) {
        case SIGTERM:
        case SIGINT:
            if (shutdown_cb_) shutdown_cb_(signum);
            break;
        case SIGHUP:
            if (reload_cb_) reload_cb_(signum);
            break;
    }
}

}  // namespace aegis
