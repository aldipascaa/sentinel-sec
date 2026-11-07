#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <stop_token>
#include <string>
#include <vector>

#include "sentinel/net.hpp"
#include "sentinel/result.hpp"

namespace sentinel {

struct ScanOptions {
    std::string host = "127.0.0.1";
    std::vector<std::uint16_t> ports;
    net::Family family = net::Family::Auto;
    int timeout_ms = 500;     // per-connection timeout; the banner wait is min(timeout, 300 ms)
    int threads = 4;          // worker threads; each multiplexes many non-blocking sockets
    int concurrency = 512;    // max connection attempts in flight across all workers
    int rate_per_sec = 1000;  // max new connections per second (0 = unlimited)
    bool grab_banner = true;
    // Defense in depth: the library itself refuses non-loopback targets unless this is set.
    bool authorized = false;
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
    bool cancelled = false;
};

// Non-blocking TCP connect scan: a few worker threads each drive many sockets with
// select()/poll(). Expected failures are returned, not thrown: Errc::Failed for resolve
// errors and Errc::Unauthorized for non-loopback targets without `authorized`.
// A requested stop yields a partial summary with cancelled == true.
// The optional progress callback is invoked (serialized) with (done, total).
Result<ScanSummary> run_scan(const ScanOptions& opt,
                             const std::function<void(std::size_t, std::size_t)>& progress = {},
                             std::stop_token cancel = {});

// True for "localhost" and loopback IP literals (127.0.0.0/8, ::1). Names are NOT resolved,
// so "127.evil.example" is correctly rejected. run_scan() re-checks the resolved address.
bool is_loopback_host(const std::string& host);

}  // namespace sentinel
