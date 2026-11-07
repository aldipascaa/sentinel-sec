#include "sentinel/scanner.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <list>
#include <mutex>
#include <thread>

#include "sentinel/portrange.hpp"

namespace sentinel {
namespace {

using Clock = std::chrono::steady_clock;
constexpr int kBannerWaitMs = 300;

// Token-bucket style limiter. A short burst allowance (50 ms worth of slots) keeps the average
// rate correct even when the OS sleeps with coarse timer granularity (about 15 ms on Windows).
class RateLimiter {
public:
    explicit RateLimiter(int per_sec)
        : interval_(per_sec > 0 ? std::chrono::nanoseconds(1'000'000'000LL / per_sec) : std::chrono::nanoseconds(0)) {}

    // Grants up to `want` connection slots right now. Returns how many were granted; when it is
    // zero, `wait` is set to the time until the next slot becomes available.
    std::size_t take(std::size_t want, std::chrono::nanoseconds& wait) {
        wait = std::chrono::nanoseconds(0);
        if (interval_.count() == 0) return want;
        std::lock_guard lk(m_);
        const auto now = Clock::now();
        const auto lower = now - std::max(std::chrono::nanoseconds(kBurst), interval_);
        if (next_ < lower) next_ = lower;
        std::size_t n = 0;
        while (n < want && next_ <= now) {
            next_ += interval_;
            ++n;
        }
        if (n == 0) wait = std::chrono::duration_cast<std::chrono::nanoseconds>(next_ - now);
        return n;
    }

private:
    static constexpr std::chrono::nanoseconds kBurst{std::chrono::milliseconds(50)};
    std::chrono::nanoseconds interval_;
    std::mutex m_;
    Clock::time_point next_{};
};

std::string sanitize_banner(const char* data, std::size_t n) {
    std::string s;
    for (std::size_t i = 0; i < n && s.size() < 160; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
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
    return p == 80 || p == 3000 || p == 5000 || p == 8000 || p == 8008 || p == 8080 || p == 8081 || p == 8787 ||
           p == 8888;
}

std::string guess_service(std::uint16_t port, const std::string& banner) {
    std::string name = service_name(port);
    if (!name.empty()) return name;
    if (banner.rfind("SSH-", 0) == 0) return "ssh";
    if (banner.rfind("HTTP/", 0) == 0) return "http";
    if (banner.rfind("220", 0) == 0) return "smtp/ftp";
    return "unknown";
}

// One in-flight probe. Phases: Connecting -> (Banner) -> done.
struct Probe {
    enum class Phase { Connecting, Banner };
    net::Socket sock;
    std::uint16_t port = 0;
    Phase phase = Phase::Connecting;
    bool probe_sent = false;
    Clock::time_point started, deadline;
    PortResult result;
    bool open = false;
};

struct Shared {
    const ScanOptions& opt;
    const net::Address& target;
    RateLimiter limiter;
    std::atomic<std::size_t> next{0};
    std::mutex m;  // guards everything below
    std::size_t done = 0;
    std::vector<PortResult> open;
    const std::function<void(std::size_t, std::size_t)>& progress;
};

int ms_until(Clock::time_point t, Clock::time_point now) {
    if (t <= now) return 0;
    return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(t - now).count()) + 1;
}

void finish(Shared& sh, Probe& p) {
    std::lock_guard lk(sh.m);
    if (p.open) {
        p.result.service = guess_service(p.port, p.result.banner);
        sh.open.push_back(std::move(p.result));
    }
    ++sh.done;
    if (sh.progress) sh.progress(sh.done, sh.opt.ports.size());
}

// A single worker multiplexes up to `slots` sockets.
void worker(Shared& sh, std::size_t slots, const std::stop_token& cancel) {
    const ScanOptions& opt = sh.opt;
    const int timeout_ms = std::max(opt.timeout_ms, 1);
    const auto banner_wait = std::chrono::milliseconds(std::min(timeout_ms, kBannerWaitMs));
    std::list<Probe> live;
    std::vector<net::PollEntry> entries;
    std::vector<Probe*> order;
    bool exhausted = false;

    while (!cancel.stop_requested()) {
        std::chrono::nanoseconds rate_wait{0};
        // ---- start new connections
        std::size_t grant = 0;
        while (!exhausted && live.size() < slots) {
            if (grant == 0) {
                grant = sh.limiter.take(slots - live.size(), rate_wait);
                if (grant == 0) break;
            }
            --grant;
            const std::size_t idx = sh.next.fetch_add(1);
            if (idx >= opt.ports.size()) {
                exhausted = true;
                break;
            }
            Probe p;
            p.port = opt.ports[idx];
            p.started = Clock::now();
            p.deadline = p.started + std::chrono::milliseconds(timeout_ms);
            bool alive = false;
            auto sock = net::Socket::create(sh.target);
            if (sock && sock.value().set_nonblocking()) {
                p.sock = std::move(sock).value();
                switch (p.sock.connect(sh.target.with_port(p.port))) {
                    case net::Socket::Connect::Connected:
                        p.open = true;
                        p.result.port = p.port;
                        p.result.rtt_ms = std::chrono::duration<double, std::milli>(Clock::now() - p.started).count();
                        if (opt.grab_banner) {
                            p.phase = Probe::Phase::Banner;
                            p.deadline = Clock::now() + banner_wait;
                            alive = true;
                        }
                        break;
                    case net::Socket::Connect::InProgress: alive = true; break;
                    case net::Socket::Connect::Failed: break;
                }
            }
            if (alive) live.push_back(std::move(p));
            else finish(sh, p);
        }
        if (live.empty()) {
            if (exhausted) break;
            // Nothing in flight, only waiting for the rate limiter: sleep (empty poll) until the next slot.
            const auto now = Clock::now();
            net::poll({}, std::clamp(ms_until(now + rate_wait, now), 1, 50));
            continue;
        }

        // ---- wait for socket events or the nearest deadline
        entries.clear();
        order.clear();
        auto now = Clock::now();
        int wait_ms = 50;  // wake periodically so cancellation is observed
        for (auto& p : live) {
            net::PollEntry e;
            e.socket = &p.sock;
            e.want_write = p.phase == Probe::Phase::Connecting;
            e.want_read = p.phase == Probe::Phase::Banner;
            entries.push_back(e);
            order.push_back(&p);
            wait_ms = std::min(wait_ms, ms_until(p.deadline, now));
        }
        if (!exhausted && live.size() < slots && rate_wait.count() > 0)
            wait_ms = std::min(wait_ms, std::max(1, ms_until(now + rate_wait, now)));
        net::poll(entries, wait_ms);

        // ---- advance probes
        now = Clock::now();
        std::vector<Probe*> finished;
        for (std::size_t i = 0; i < entries.size(); ++i) {
            Probe& p = *order[i];
            const net::PollEntry& e = entries[i];
            const bool expired = now >= p.deadline;
            if (p.phase == Probe::Phase::Connecting) {
                if (e.writable || e.failed) {
                    if (p.sock.finish_connect()) {
                        p.open = true;
                        p.result.port = p.port;
                        p.result.rtt_ms = std::chrono::duration<double, std::milli>(now - p.started).count();
                        if (opt.grab_banner) {
                            p.phase = Probe::Phase::Banner;
                            p.deadline = now + banner_wait;
                            continue;
                        }
                    }
                    finished.push_back(&p);
                } else if (expired) {
                    finished.push_back(&p);  // timed out: filtered
                }
            } else {  // Banner
                bool done_p = false;
                if (e.readable || e.failed) {
                    char buf[256];
                    const auto r = p.sock.recv(buf, sizeof buf);
                    if (r.kind == net::IoResult::Kind::Data) p.result.banner = sanitize_banner(buf, r.bytes);
                    done_p = r.kind != net::IoResult::Kind::WouldBlock;
                }
                if (!done_p && expired) {
                    if (!p.probe_sent && http_like(p.port)) {
                        static const char req[] = "HEAD / HTTP/1.0\r\nUser-Agent: sentinel\r\n\r\n";
                        p.sock.send(req, sizeof(req) - 1);
                        p.probe_sent = true;
                        p.deadline = now + banner_wait;
                    } else {
                        done_p = true;
                    }
                }
                if (done_p) finished.push_back(&p);
            }
        }
        for (Probe* fp : finished) {
            finish(sh, *fp);
            live.remove_if([fp](const Probe& x) { return &x == fp; });
        }
    }
    // Cancelled: remaining sockets close via RAII; their ports are not counted as done.
}

}  // namespace

bool is_loopback_host(const std::string& host) {
    if (host == "localhost") return true;
    auto a = net::Address::parse_literal(host);
    return a && a.value().is_loopback();
}

Result<ScanSummary> run_scan(const ScanOptions& opt, const std::function<void(std::size_t, std::size_t)>& progress,
                             std::stop_token cancel) {
    auto target = net::Address::resolve(opt.host, 0, opt.family);
    if (!target) return target.error();
    if (!opt.authorized && !target.value().is_loopback())
        return make_error("'" + opt.host + "' resolves to " + target.value().ip_string() +
                              ", which is not a loopback address; authorization is required",
                          Errc::Unauthorized);

    ScanSummary summary;
    summary.host = opt.host;
    summary.address = target.value().ip_string();
    summary.scanned = opt.ports.size();

    Shared sh{opt, target.value(), RateLimiter(opt.rate_per_sec), {}, {}, 0, {}, progress};
    const std::size_t workers = static_cast<std::size_t>(std::clamp(opt.threads, 1, 64));
    const std::size_t total_slots = static_cast<std::size_t>(std::clamp(opt.concurrency, 1, 1024));
    const std::size_t slots = std::clamp<std::size_t>((total_slots + workers - 1) / workers, 1, net::kMaxPollEntries);

    std::mutex err_m;
    std::string first_error;
    const auto t0 = Clock::now();
    {
        std::vector<std::jthread> pool;
        for (std::size_t i = 0; i < workers; ++i) {
            pool.emplace_back([&] {
                try {
                    worker(sh, slots, cancel);
                } catch (const std::exception& e) {  // never let an exception escape a thread
                    std::lock_guard lk(err_m);
                    if (first_error.empty()) first_error = e.what();
                } catch (...) {
                    std::lock_guard lk(err_m);
                    if (first_error.empty()) first_error = "unknown error in scan worker";
                }
            });
        }
    }  // jthreads join here
    if (!first_error.empty()) return make_error("scan failed: " + first_error);

    summary.elapsed_ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    summary.open = std::move(sh.open);
    summary.cancelled = cancel.stop_requested() && sh.done < opt.ports.size();
    std::sort(summary.open.begin(), summary.open.end(),
              [](const PortResult& a, const PortResult& b) { return a.port < b.port; });
    return summary;
}

}  // namespace sentinel
