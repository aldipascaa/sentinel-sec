#include "sentinel/scanner.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>

#include "sentinel/portrange.hpp"
#include "sentinel/threadpool.hpp"

namespace sentinel {
namespace {

using Clock = std::chrono::steady_clock;

struct WsaGuard {
    WsaGuard() {
        WSADATA d;
        ok = WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }
    ~WsaGuard() {
        if (ok) WSACleanup();
    }
    bool ok = false;
};

void ensure_wsa() {
    static WsaGuard g;
    if (!g.ok) throw std::runtime_error("WSAStartup failed");
}

// Spaces out connection attempts: each caller reserves the next time slot.
class RateLimiter {
public:
    explicit RateLimiter(int per_sec)
        : interval_(per_sec > 0 ? std::chrono::nanoseconds(1'000'000'000LL / per_sec)
                                : std::chrono::nanoseconds(0)) {}
    void acquire() {
        if (interval_.count() == 0) return;
        Clock::time_point slot;
        {
            std::lock_guard lk(m_);
            auto now = Clock::now();
            slot = std::max(next_, now);
            next_ = slot + interval_;
        }
        std::this_thread::sleep_until(slot);
    }

private:
    std::chrono::nanoseconds interval_;
    std::mutex m_;
    Clock::time_point next_{};
};

std::string sanitize_banner(const char* data, int n) {
    std::string s;
    for (int i = 0; i < n && s.size() < 160; ++i) {
        unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\r' || c == '\n' || c == '\t') {
            if (!s.empty() && s.back() != ' ') s.push_back(' ');
        } else if (c >= 32 && c < 127) {
            s.push_back(static_cast<char>(c));
        }
    }
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

bool http_like(std::uint16_t p) {
    return p == 80 || p == 3000 || p == 5000 || p == 8000 || p == 8008 || p == 8080 || p == 8081 ||
           p == 8787 || p == 8888;
}

bool wait_socket(SOCKET s, short events, int timeout_ms, short* revents) {
    WSAPOLLFD fd{};
    fd.fd = s;
    fd.events = events;
    int r = WSAPoll(&fd, 1, timeout_ms);
    if (r <= 0) return false;
    *revents = fd.revents;
    return true;
}

struct Probe {
    bool open = false;
    double rtt_ms = 0;
    std::string banner;
};

Probe probe_port(sockaddr_in addr, std::uint16_t port, int timeout_ms, bool banner) {
    Probe out;
    addr.sin_port = htons(port);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return out;
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    const auto t0 = Clock::now();
    int r = connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    bool connected = (r == 0);
    if (!connected && WSAGetLastError() == WSAEWOULDBLOCK) {
        short rev = 0;
        if (wait_socket(s, POLLWRNORM, timeout_ms, &rev) && (rev & POLLWRNORM) && !(rev & (POLLERR | POLLHUP))) {
            int err = 0;
            int len = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
            connected = (err == 0);
        }
    }
    if (connected) {
        out.open = true;
        out.rtt_ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        if (banner) {
            char buf[256];
            short rev = 0;
            const int wait = std::min(timeout_ms, 300);
            bool ready = wait_socket(s, POLLRDNORM, wait, &rev);
            if (!ready && http_like(port)) {
                static const char req[] = "HEAD / HTTP/1.0\r\nUser-Agent: sentinel\r\n\r\n";
                send(s, req, static_cast<int>(sizeof(req) - 1), 0);
                ready = wait_socket(s, POLLRDNORM, wait, &rev);
            }
            if (ready) {
                int n = recv(s, buf, static_cast<int>(sizeof(buf)), 0);
                if (n > 0) out.banner = sanitize_banner(buf, n);
            }
        }
    }
    closesocket(s);
    return out;
}

std::string guess_service(std::uint16_t port, const std::string& banner) {
    std::string name = service_name(port);
    if (!name.empty()) return name;
    if (banner.rfind("SSH-", 0) == 0) return "ssh";
    if (banner.rfind("HTTP/", 0) == 0) return "http";
    if (banner.rfind("220", 0) == 0) return "smtp/ftp";
    return "unknown";
}

}  // namespace

bool is_loopback_host(const std::string& host) {
    return host == "localhost" || host == "::1" || host.rfind("127.", 0) == 0;
}

ScanSummary run_scan(const ScanOptions& opt, const std::function<void(std::size_t, std::size_t)>& progress) {
    ensure_wsa();

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(opt.host.c_str(), nullptr, &hints, &res) != 0 || !res)
        throw std::runtime_error("cannot resolve host '" + opt.host + "'");
    sockaddr_in addr{};
    std::memcpy(&addr, res->ai_addr, sizeof(addr));
    freeaddrinfo(res);

    char ip[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));

    ScanSummary summary;
    summary.host = opt.host;
    summary.address = ip;
    summary.scanned = opt.ports.size();

    std::mutex m;
    std::size_t done = 0;
    const std::size_t total = opt.ports.size();
    RateLimiter limiter(opt.rate_per_sec);
    const auto t0 = Clock::now();
    {
        ThreadPool pool(static_cast<std::size_t>(std::clamp(opt.threads, 1, 512)));
        for (std::uint16_t port : opt.ports) {
            pool.submit([&, port] {
                limiter.acquire();
                Probe p = probe_port(addr, port, std::max(opt.timeout_ms, 1), opt.grab_banner);
                std::lock_guard lk(m);
                if (p.open) {
                    PortResult pr;
                    pr.port = port;
                    pr.banner = std::move(p.banner);
                    pr.service = guess_service(port, pr.banner);
                    pr.rtt_ms = p.rtt_ms;
                    summary.open.push_back(std::move(pr));
                }
                ++done;
                if (progress) progress(done, total);
            });
        }
        pool.wait_idle();
    }
    summary.elapsed_ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    std::sort(summary.open.begin(), summary.open.end(),
              [](const PortResult& a, const PortResult& b) { return a.port < b.port; });
    return summary;
}

}  // namespace sentinel
