#pragma once
#include <string>

namespace sentinel {

struct ServerOptions {
    int port = 8787;
    std::string report_dir = "reports";
    int max_seconds = 0;  // >0: stop automatically (useful for smoke tests)
};

// Serves the dashboard + JSON API on 127.0.0.1 only. Returns a process exit code.
int run_server(const ServerOptions& opt);

}  // namespace sentinel
