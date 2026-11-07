#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace sentinel {

struct ScanOptions {
    std::string host = "127.0.0.1";
    std::vector<std::uint16_t> ports;
    int timeout_ms = 500;     // per-connection timeout
    int threads = 200;        // worker threads
    int rate_per_sec = 1000;  // max new connections per second (0 = unlimited)
    bool grab_banner = true;
};

struct PortResult {
    std::uint16_t port = 0;
    std::string service;
    std::string banner;
    double rtt_ms = 0;
};

struct ScanSummary {
    std::string host;
    std::string address;
    std::size_t scanned = 0;
    std::vector<PortResult> open;  // sorted by port
    double elapsed_ms = 0;
};

// Non-blocking TCP connect scan. Throws std::runtime_error if the host cannot be resolved.
// The optional progress callback is invoked (serialized) with (done, total).
ScanSummary run_scan(const ScanOptions& opt,
                     const std::function<void(std::size_t, std::size_t)>& progress = {});

bool is_loopback_host(const std::string& host);

}  // namespace sentinel
