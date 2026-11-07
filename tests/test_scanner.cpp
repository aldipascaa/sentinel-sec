#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <stop_token>
#include <thread>

#include "sentinel/net.hpp"
#include "sentinel/scanner.hpp"

using namespace sentinel;

namespace {
// A loopback listener on an ephemeral port that sends a banner to each client.
struct Listener {
    net::Socket s;
    std::uint16_t port = 0;
    bool ok = false;
    std::atomic<bool> stop{false};
    std::thread th;
    const char* banner;

    explicit Listener(net::Family f = net::Family::IPv4, const char* msg = "SSH-2.0-TestServer\r\n") : banner(msg) {
        auto sock = net::Socket::create(net::Address::loopback(f));
        if (!sock) return;
        s = std::move(sock).value();
        if (!s.bind(net::Address::loopback(f, 0)) || !s.listen(32) || !s.set_nonblocking()) return;
        port = s.local_port().value();
        ok = true;
        th = std::thread([this] {
            while (!stop) {
                net::PollEntry e;
                e.socket = &s;
                e.want_read = true;
                net::poll({&e, 1}, 20);
                if (!e.readable) continue;
                auto c = s.accept();
                if (c && c.value().valid() && *banner) {
                    net::Socket client = std::move(c).value();
                    client.send(banner, std::char_traits<char>::length(banner));
                }
            }
        });
    }
    ~Listener() {
        stop = true;
        if (th.joinable()) th.join();
    }
};

std::uint16_t closed_port() {
    std::uint16_t p;
    {
        Listener l;
        p = l.port;
    }  // listener closed -> port refuses connections
    return p;
}
}  // namespace

TEST(Scanner, FindsOpenPortAndBanner) {
    Listener l;
    ASSERT_TRUE(l.ok);
    ScanOptions o;
    o.ports = {l.port};
    o.timeout_ms = 1000;
    auto r = run_scan(o);
    ASSERT_TRUE(r) << r.error().message;
    ASSERT_EQ(r.value().open.size(), 1u);
    EXPECT_EQ(r.value().open[0].port, l.port);
    EXPECT_EQ(r.value().open[0].banner, "SSH-2.0-TestServer");
    EXPECT_EQ(r.value().open[0].service, "ssh");  // guessed from banner
    EXPECT_EQ(r.value().address, "127.0.0.1");
}

TEST(Scanner, ClosedPortIsNotReported) {
    ScanOptions o;
    o.ports = {closed_port()};
    o.timeout_ms = 1500;
    auto r = run_scan(o);
    ASSERT_TRUE(r);
    EXPECT_TRUE(r.value().open.empty());
    EXPECT_EQ(r.value().scanned, 1u);
}

TEST(Scanner, ScansManyPortsConcurrently) {
    Listener l;
    ASSERT_TRUE(l.ok);
    ScanOptions o;
    for (unsigned p = l.port > 40 ? l.port - 20u : 1u; p < l.port + 20u && p < 65535u; ++p)
        o.ports.push_back(static_cast<std::uint16_t>(p));
    o.rate_per_sec = 0;
    o.grab_banner = false;
    o.timeout_ms = 1500;
    std::size_t last = 0;
    auto r = run_scan(o, [&](std::size_t done, std::size_t) { last = done; });
    ASSERT_TRUE(r);
    EXPECT_EQ(last, o.ports.size());
    bool found = false;
    for (auto& p : r.value().open) found |= (p.port == l.port);
    EXPECT_TRUE(found);
}

TEST(Scanner, ManyClosedPortsFinishFasterThanSerialTimeouts) {
    // 200 closed ports with a 1 s timeout would take minutes if probed one at a time.
    ScanOptions o;
    for (unsigned p = 20000; p < 20200; ++p) o.ports.push_back(static_cast<std::uint16_t>(p));
    o.rate_per_sec = 0;
    o.timeout_ms = 1000;
    auto t0 = std::chrono::steady_clock::now();
    auto r = run_scan(o);
    auto dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    ASSERT_TRUE(r);
    EXPECT_EQ(r.value().scanned, 200u);
    EXPECT_LT(dt, 15.0);
}

TEST(Scanner, SilentServerYieldsEmptyBanner) {
    Listener silent(net::Family::IPv4, "");
    ASSERT_TRUE(silent.ok);
    ScanOptions o;
    o.ports = {silent.port};
    o.timeout_ms = 600;
    auto r = run_scan(o);
    ASSERT_TRUE(r);
    ASSERT_EQ(r.value().open.size(), 1u);
    EXPECT_TRUE(r.value().open[0].banner.empty());  // not http-like port -> no probe, no banner
}

TEST(Scanner, UnresolvableHostIsAnError) {
    ScanOptions o;
    o.host = "no-such-host.invalid";
    o.ports = {80};
    auto r = run_scan(o);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.error().code, Errc::Failed);
}

TEST(Scanner, NonLoopbackRequiresAuthorizationInTheLibrary) {
    ScanOptions o;
    o.host = "192.0.2.1";  // TEST-NET-1, never contacted: the guard fires before any socket is created
    o.ports = {80};
    auto r = run_scan(o);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.error().code, Errc::Unauthorized);
}

TEST(Scanner, PreCancelledScanReturnsPartialResult) {
    std::stop_source src;
    src.request_stop();
    ScanOptions o;
    for (unsigned p = 30000; p < 30100; ++p) o.ports.push_back(static_cast<std::uint16_t>(p));
    auto r = run_scan(o, {}, src.get_token());
    ASSERT_TRUE(r);
    EXPECT_TRUE(r.value().cancelled);
}

TEST(Scanner, CancellationInterruptsRateLimitedScan) {
    std::stop_source src;
    ScanOptions o;
    for (unsigned p = 30000; p < 30400; ++p) o.ports.push_back(static_cast<std::uint16_t>(p));
    o.rate_per_sec = 20;  // would take 20 s uncancelled
    std::thread t([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        src.request_stop();
    });
    auto t0 = std::chrono::steady_clock::now();
    auto r = run_scan(o, {}, src.get_token());
    auto dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    t.join();
    ASSERT_TRUE(r);
    EXPECT_TRUE(r.value().cancelled);
    EXPECT_LT(dt, 5.0);
}

TEST(Scanner, RateLimitSpacesConnections) {
    ScanOptions o;
    for (unsigned p = 31000; p < 31010; ++p) o.ports.push_back(static_cast<std::uint16_t>(p));
    o.rate_per_sec = 20;  // 10 ports at 20/s >= ~0.45 s
    o.timeout_ms = 1000;
    auto r = run_scan(o);
    ASSERT_TRUE(r);
    EXPECT_GE(r.value().elapsed_ms, 400.0);
}

TEST(Scanner, Ipv6LoopbackWhenAvailable) {
    Listener l(net::Family::IPv6);
    if (!l.ok) GTEST_SKIP() << "IPv6 loopback not available";
    ScanOptions o;
    o.host = "::1";
    o.ports = {l.port};
    o.timeout_ms = 1000;
    auto r = run_scan(o);
    ASSERT_TRUE(r) << r.error().message;
    ASSERT_EQ(r.value().open.size(), 1u);
    EXPECT_EQ(r.value().address, "::1");
}

TEST(Scanner, LoopbackDetection) {
    EXPECT_TRUE(is_loopback_host("127.0.0.1"));
    EXPECT_TRUE(is_loopback_host("127.5.5.5"));
    EXPECT_TRUE(is_loopback_host("localhost"));
    EXPECT_TRUE(is_loopback_host("::1"));
    EXPECT_FALSE(is_loopback_host("192.168.1.10"));
    EXPECT_FALSE(is_loopback_host("example.com"));
    EXPECT_FALSE(is_loopback_host("127.evil.example.com"));  // prefix trick must not pass
    EXPECT_FALSE(is_loopback_host("127.0.0.1.evil.example.com"));
}
