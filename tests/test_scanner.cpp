#include <gtest/gtest.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <thread>

#include "sentinel/scanner.hpp"

using namespace sentinel;

namespace {
// A loopback listener on an ephemeral port that sends a banner to each client.
struct Listener {
    SOCKET s = INVALID_SOCKET;
    std::uint16_t port = 0;
    std::atomic<bool> stop{false};
    std::thread th;

    Listener() {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        a.sin_port = 0;
        bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        listen(s, 16);
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        int len = sizeof(a);
        getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
        th = std::thread([this] {
            while (!stop) {
                WSAPOLLFD p{s, POLLRDNORM, 0};
                if (WSAPoll(&p, 1, 50) > 0) {
                    SOCKET c = accept(s, nullptr, nullptr);
                    if (c != INVALID_SOCKET) {
                        const char msg[] = "SSH-2.0-TestServer\r\n";
                        send(c, msg, static_cast<int>(sizeof(msg) - 1), 0);
                        closesocket(c);
                    }
                }
            }
        });
    }
    ~Listener() {
        stop = true;
        th.join();
        closesocket(s);
    }
};
}  // namespace

TEST(Scanner, FindsOpenPortAndBanner) {
    Listener l;
    ScanOptions o;
    o.ports = {l.port};
    o.timeout_ms = 1000;
    auto r = run_scan(o);
    ASSERT_EQ(r.open.size(), 1u);
    EXPECT_EQ(r.open[0].port, l.port);
    EXPECT_EQ(r.open[0].banner, "SSH-2.0-TestServer");
    EXPECT_EQ(r.open[0].service, "ssh");  // guessed from banner
    EXPECT_EQ(r.address, "127.0.0.1");
}

TEST(Scanner, ClosedPortIsNotReported) {
    std::uint16_t closed;
    {
        Listener l;
        closed = l.port;
    }  // listener closed -> port refuses connections
    ScanOptions o;
    o.ports = {closed};
    o.timeout_ms = 500;
    auto r = run_scan(o);
    EXPECT_TRUE(r.open.empty());
    EXPECT_EQ(r.scanned, 1u);
}

TEST(Scanner, ScansManyPortsConcurrently) {
    Listener l;
    ScanOptions o;
    for (unsigned p = l.port > 40 ? l.port - 20u : 1u; p < l.port + 20u && p < 65535u; ++p)
        o.ports.push_back(static_cast<std::uint16_t>(p));
    o.rate_per_sec = 0;
    o.grab_banner = false;
    std::size_t last = 0;
    auto r = run_scan(o, [&](std::size_t done, std::size_t) { last = done; });
    EXPECT_EQ(last, o.ports.size());
    bool found = false;
    for (auto& p : r.open) found |= (p.port == l.port);
    EXPECT_TRUE(found);
}

TEST(Scanner, UnresolvableHostThrows) {
    ScanOptions o;
    o.host = "no-such-host.invalid";
    o.ports = {80};
    EXPECT_THROW(run_scan(o), std::runtime_error);
}

TEST(Scanner, LoopbackDetection) {
    EXPECT_TRUE(is_loopback_host("127.0.0.1"));
    EXPECT_TRUE(is_loopback_host("localhost"));
    EXPECT_FALSE(is_loopback_host("192.168.1.10"));
    EXPECT_FALSE(is_loopback_host("example.com"));
}
