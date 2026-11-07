#include <gtest/gtest.h>

#include <chrono>

#include "sentinel/net.hpp"

using namespace sentinel;

TEST(NetAddress, ParsesLiterals) {
    auto a = net::Address::parse_literal("127.0.0.1", 80);
    ASSERT_TRUE(a);
    EXPECT_FALSE(a.value().is_ipv6());
    EXPECT_EQ(a.value().port(), 80);
    EXPECT_EQ(a.value().ip_string(), "127.0.0.1");

    auto b = net::Address::parse_literal("::1");
    ASSERT_TRUE(b);
    EXPECT_TRUE(b.value().is_ipv6());
    EXPECT_EQ(b.value().ip_string(), "::1");

    EXPECT_FALSE(net::Address::parse_literal("not-an-ip"));
    EXPECT_FALSE(net::Address::parse_literal("300.1.1.1"));
}

TEST(NetAddress, LoopbackClassification) {
    EXPECT_TRUE(net::Address::parse_literal("127.0.0.1").value().is_loopback());
    EXPECT_TRUE(net::Address::parse_literal("127.200.1.1").value().is_loopback());
    EXPECT_TRUE(net::Address::parse_literal("::1").value().is_loopback());
    EXPECT_TRUE(net::Address::parse_literal("::ffff:127.0.0.1").value().is_loopback());
    EXPECT_FALSE(net::Address::parse_literal("10.0.0.1").value().is_loopback());
    EXPECT_FALSE(net::Address::parse_literal("8.8.8.8").value().is_loopback());
    EXPECT_FALSE(net::Address::parse_literal("2001:db8::1").value().is_loopback());
    EXPECT_FALSE(net::Address().is_loopback());
}

TEST(NetAddress, ResolveHonorsFamily) {
    EXPECT_TRUE(net::Address::resolve("127.0.0.1", 1, net::Family::IPv4));
    EXPECT_FALSE(net::Address::resolve("127.0.0.1", 1, net::Family::IPv6));
    EXPECT_FALSE(net::Address::resolve("::1", 1, net::Family::IPv4));
    EXPECT_FALSE(net::Address::resolve("no-such-host.invalid"));
}

TEST(NetAddress, WithPortKeepsHost) {
    auto a = net::Address::loopback(net::Family::IPv4, 1).with_port(4242);
    EXPECT_EQ(a.port(), 4242);
    EXPECT_EQ(a.ip_string(), "127.0.0.1");
}

TEST(NetSocket, MoveTransfersOwnership) {
    auto s = net::Socket::create(net::Address::loopback(net::Family::IPv4));
    ASSERT_TRUE(s);
    net::Socket a = std::move(s).value();
    ASSERT_TRUE(a.valid());
    net::Socket b = std::move(a);
    EXPECT_FALSE(a.valid());  // NOLINT: moved-from state is specified
    EXPECT_TRUE(b.valid());
    b.close();
    EXPECT_FALSE(b.valid());
    b.close();  // idempotent
}

TEST(NetSocket, NonBlockingConnectToClosedPortFailsWithinTimeout) {
    std::uint16_t port;
    {
        auto l = net::Socket::create(net::Address::loopback(net::Family::IPv4)).value();
        ASSERT_TRUE(l.bind(net::Address::loopback(net::Family::IPv4, 0)));
        port = l.local_port().value();
    }  // closed again
    auto addr = net::Address::loopback(net::Family::IPv4, port);
    auto s = net::Socket::create(addr).value();
    ASSERT_TRUE(s.set_nonblocking());
    auto c = s.connect(addr);
    if (c == net::Socket::Connect::Failed) SUCCEED();  // some stacks refuse immediately
    ASSERT_NE(c, net::Socket::Connect::Connected);

    net::PollEntry e;
    e.socket = &s;
    e.want_write = true;
    const auto t0 = std::chrono::steady_clock::now();
    int ready = 0;
    while (ready == 0 && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(3))
        ready = net::poll({&e, 1}, 100);
    ASSERT_GT(ready, 0);  // the failure must be signalled, not left to time out
    EXPECT_FALSE(s.finish_connect());
}

TEST(NetSocket, ConnectAndExchangeData) {
    auto lis = net::Socket::create(net::Address::loopback(net::Family::IPv4)).value();
    ASSERT_TRUE(lis.bind(net::Address::loopback(net::Family::IPv4, 0)));
    ASSERT_TRUE(lis.listen());
    ASSERT_TRUE(lis.set_nonblocking());
    const auto addr = net::Address::loopback(net::Family::IPv4, lis.local_port().value());

    auto cli = net::Socket::create(addr).value();
    ASSERT_TRUE(cli.set_nonblocking());
    auto c = cli.connect(addr);
    ASSERT_NE(c, net::Socket::Connect::Failed);

    net::PollEntry le;
    le.socket = &lis;
    le.want_read = true;
    ASSERT_GT(net::poll({&le, 1}, 2000), 0);
    net::Socket srv = lis.accept().value();
    ASSERT_TRUE(srv.valid());

    net::PollEntry ce;
    ce.socket = &cli;
    ce.want_write = true;
    ASSERT_GT(net::poll({&ce, 1}, 2000), 0);
    EXPECT_TRUE(cli.finish_connect());

    EXPECT_EQ(srv.send("hi", 2).kind, net::IoResult::Kind::Data);
    net::PollEntry re;
    re.socket = &cli;
    re.want_read = true;
    ASSERT_GT(net::poll({&re, 1}, 2000), 0);
    char buf[8];
    auto r = cli.recv(buf, sizeof buf);
    ASSERT_EQ(r.kind, net::IoResult::Kind::Data);
    EXPECT_EQ(r.bytes, 2u);
    EXPECT_EQ(std::string(buf, 2), "hi");

    // Nothing pending now: non-blocking recv reports WouldBlock, not an error.
    EXPECT_EQ(cli.recv(buf, sizeof buf).kind, net::IoResult::Kind::WouldBlock);
    srv.close();
    net::PollEntry re2;
    re2.socket = &cli;
    re2.want_read = true;
    ASSERT_GT(net::poll({&re2, 1}, 2000), 0);
    EXPECT_EQ(cli.recv(buf, sizeof buf).kind, net::IoResult::Kind::Closed);
}

TEST(NetSocket, PollTimesOutWhenNothingReady) {
    auto lis = net::Socket::create(net::Address::loopback(net::Family::IPv4)).value();
    ASSERT_TRUE(lis.bind(net::Address::loopback(net::Family::IPv4, 0)));
    ASSERT_TRUE(lis.listen());
    net::PollEntry e;
    e.socket = &lis;
    e.want_read = true;
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_EQ(net::poll({&e, 1}, 150), 0);
    EXPECT_GE(std::chrono::steady_clock::now() - t0, std::chrono::milliseconds(100));
    EXPECT_FALSE(e.readable);
}

TEST(NetSocket, AcceptWithNothingPendingIsNotAnError) {
    auto lis = net::Socket::create(net::Address::loopback(net::Family::IPv4)).value();
    ASSERT_TRUE(lis.bind(net::Address::loopback(net::Family::IPv4, 0)));
    ASSERT_TRUE(lis.listen());
    ASSERT_TRUE(lis.set_nonblocking());
    auto c = lis.accept();
    ASSERT_TRUE(c);
    EXPECT_FALSE(c.value().valid());
}

TEST(NetSocket, EmptyPollSleeps) {
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_EQ(net::poll({}, 60), 0);
    EXPECT_GE(std::chrono::steady_clock::now() - t0, std::chrono::milliseconds(40));
}
