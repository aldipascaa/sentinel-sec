#pragma once
#include <functional>
#include <stop_token>
#include <string>

#include "sentinel/logscan.hpp"

namespace sentinel {

struct ServerOptions {
    int port = 8787;  // 0 = pick a free port (see `on_ready`)
    std::string report_dir = "reports";
    int max_seconds = 0;  // >0: stop automatically (useful for smoke tests)
    RulesConfig rules;    // detection rules used by /api/logscan
    // Called once the socket is bound, with the actual port, just before serving starts.
    std::function<void(int port)> on_ready;
    bool quiet = false;
};

// Serves the dashboard + JSON API on 127.0.0.1 only. Blocks until `stop` is requested,
// max_seconds elapse, or the listener fails. Returns a process exit code.
int run_server(const ServerOptions& opt, std::stop_token stop = {});

}  // namespace sentinel
