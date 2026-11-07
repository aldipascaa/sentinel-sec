// Portable socket layer: Winsock and POSIX (BSD sockets) implementations behind #ifdef.
#ifdef _WIN32
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024  // fd_set is an array on Windows, so a larger set costs nothing
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <chrono>
#include <cstring>
#include <thread>

#include "sentinel/net.hpp"

namespace sentinel::net {
namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kBadSocket = INVALID_SOCKET;
using SockLen = int;
int last_error() { return WSAGetLastError(); }
bool is_would_block(int e) { return e == WSAEWOULDBLOCK; }
bool is_in_progress(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
void close_native(NativeSocket s) { closesocket(s); }
std::string error_text(int e) { return "socket error " + std::to_string(e); }
constexpr int kSendFlags = 0;

struct Runtime {
    Runtime() {
        WSADATA d;
        rc = WSAStartup(MAKEWORD(2, 2), &d);
    }
    ~Runtime() {
        if (rc == 0) WSACleanup();
    }
    int rc = -1;
};
#else
using NativeSocket = int;
constexpr NativeSocket kBadSocket = -1;
using SockLen = socklen_t;
int last_error() { return errno; }
bool is_would_block(int e) { return e == EAGAIN || e == EWOULDBLOCK; }
bool is_in_progress(int e) { return e == EINPROGRESS || e == EINTR; }
void close_native(NativeSocket s) { ::close(s); }
std::string error_text(int e) { return std::string(std::strerror(e)) + " (" + std::to_string(e) + ")"; }
#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif
#endif

NativeSocket to_native(std::intptr_t fd) { return static_cast<NativeSocket>(fd); }

const sockaddr* sa(const Address& a) { return static_cast<const sockaddr*>(a.data()); }

}  // namespace

Status ensure_initialized() {
#ifdef _WIN32
    static const Runtime rt;  // WSAStartup once; WSACleanup at process exit (RAII)
    if (rt.rc != 0) return make_error("WSAStartup failed (" + std::to_string(rt.rc) + ")");
#endif
    return ok_status();
}

// ---------------------------------------------------------------- Address

Result<Address> Address::parse_literal(const std::string& text, std::uint16_t port) {
    if (auto s = ensure_initialized(); !s) return s.error();
    Address a;
    auto* v4 = static_cast<sockaddr_in*>(a.mutable_data());
    if (inet_pton(AF_INET, text.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        a.set_size(static_cast<int>(sizeof(sockaddr_in)));
        return a;
    }
    Address b;
    auto* v6 = static_cast<sockaddr_in6*>(b.mutable_data());
    if (inet_pton(AF_INET6, text.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        b.set_size(static_cast<int>(sizeof(sockaddr_in6)));
        return b;
    }
    return make_error("'" + text + "' is not an IP address", Errc::InvalidArgument);
}

Result<Address> Address::resolve(const std::string& host, std::uint16_t port, Family f) {
    if (auto s = ensure_initialized(); !s) return s.error();
    if (auto lit = parse_literal(host, port); lit) {
        const bool v6 = lit.value().is_ipv6();
        if ((f == Family::IPv4 && v6) || (f == Family::IPv6 && !v6))
            return make_error("'" + host + "' is not an address of the requested family", Errc::InvalidArgument);
        return lit;
    }
    addrinfo hints{};
    hints.ai_family = f == Family::IPv4 ? AF_INET : f == Family::IPv6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
        return make_error("cannot resolve host '" + host + "'");
    const addrinfo* pick = nullptr;
    for (const addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET && p->ai_family != AF_INET6) continue;
        if (!pick || (p->ai_family == AF_INET && pick->ai_family != AF_INET)) pick = p;  // prefer IPv4
    }
    Address a;
    if (!pick || static_cast<std::size_t>(pick->ai_addrlen) > sizeof(sockaddr_in6)) {
        freeaddrinfo(res);
        return make_error("cannot resolve host '" + host + "'");
    }
    std::memcpy(a.mutable_data(), pick->ai_addr, pick->ai_addrlen);
    a.set_size(static_cast<int>(pick->ai_addrlen));
    freeaddrinfo(res);
    return a.with_port(port);
}

Address Address::loopback(Family f, std::uint16_t port) {
    Address a;
    if (f == Family::IPv6) {
        auto* v6 = static_cast<sockaddr_in6*>(a.mutable_data());
        v6->sin6_family = AF_INET6;
        v6->sin6_addr = in6addr_loopback;
        v6->sin6_port = htons(port);
        a.set_size(static_cast<int>(sizeof(sockaddr_in6)));
    } else {
        auto* v4 = static_cast<sockaddr_in*>(a.mutable_data());
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        v4->sin_port = htons(port);
        a.set_size(static_cast<int>(sizeof(sockaddr_in)));
    }
    return a;
}

Address Address::with_port(std::uint16_t port) const {
    Address a = *this;
    if (is_ipv6()) static_cast<sockaddr_in6*>(a.mutable_data())->sin6_port = htons(port);
    else if (len_ > 0) static_cast<sockaddr_in*>(a.mutable_data())->sin_port = htons(port);
    return a;
}

bool Address::is_ipv6() const { return len_ > 0 && sa(*this)->sa_family == AF_INET6; }

std::uint16_t Address::port() const {
    if (len_ == 0) return 0;
    return ntohs(is_ipv6() ? static_cast<const sockaddr_in6*>(data())->sin6_port
                           : static_cast<const sockaddr_in*>(data())->sin_port);
}

bool Address::is_loopback() const {
    if (len_ == 0) return false;
    if (!is_ipv6()) {
        const auto ip = ntohl(static_cast<const sockaddr_in*>(data())->sin_addr.s_addr);
        return (ip >> 24) == 127;
    }
    const auto* b = reinterpret_cast<const unsigned char*>(&static_cast<const sockaddr_in6*>(data())->sin6_addr);
    bool zero_prefix = true;
    for (int i = 0; i < 15; ++i) zero_prefix = zero_prefix && b[i] == 0;
    if (zero_prefix && b[15] == 1) return true;  // ::1
    bool mapped = true;                          // ::ffff:127.x.x.x
    for (int i = 0; i < 10; ++i) mapped = mapped && b[i] == 0;
    return mapped && b[10] == 0xff && b[11] == 0xff && b[12] == 127;
}

std::string Address::ip_string() const {
    if (len_ == 0) return {};
    char buf[INET6_ADDRSTRLEN] = {};
    if (is_ipv6()) inet_ntop(AF_INET6, &static_cast<const sockaddr_in6*>(data())->sin6_addr, buf, sizeof buf);
    else inet_ntop(AF_INET, &static_cast<const sockaddr_in*>(data())->sin_addr, buf, sizeof buf);
    return buf;
}

// ----------------------------------------------------------------- Socket

Result<Socket> Socket::create(const Address& like) {
    if (auto s = ensure_initialized(); !s) return s.error();
    NativeSocket fd = ::socket(like.is_ipv6() ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == kBadSocket) return make_error("socket() failed: " + error_text(last_error()));
    return Socket(static_cast<std::intptr_t>(fd));
}

void Socket::close() noexcept {
    if (fd_ != kInvalid) close_native(to_native(fd_));
    fd_ = kInvalid;
}

Status Socket::set_nonblocking(bool on) {
#ifdef _WIN32
    u_long v = on ? 1 : 0;
    if (ioctlsocket(to_native(fd_), FIONBIO, &v) != 0)
        return make_error("ioctlsocket failed: " + error_text(last_error()));
#else
    int fl = fcntl(static_cast<int>(fd_), F_GETFL, 0);
    if (fl < 0 || fcntl(static_cast<int>(fd_), F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK)) < 0)
        return make_error("fcntl failed: " + error_text(last_error()));
#endif
    return ok_status();
}

Socket::Connect Socket::connect(const Address& to) {
    if (::connect(to_native(fd_), sa(to), static_cast<SockLen>(to.size())) == 0) return Connect::Connected;
    return is_in_progress(last_error()) ? Connect::InProgress : Connect::Failed;
}

Status Socket::finish_connect() {
    int err = 0;
    SockLen len = sizeof(err);
    if (getsockopt(to_native(fd_), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) != 0)
        return make_error("getsockopt failed: " + error_text(last_error()));
    if (err != 0) return make_error("connect failed: " + error_text(err));
    return ok_status();
}

Status Socket::bind(const Address& a) {
    if (::bind(to_native(fd_), sa(a), static_cast<SockLen>(a.size())) != 0)
        return make_error("bind failed: " + error_text(last_error()));
    return ok_status();
}

Status Socket::listen(int backlog) {
    if (::listen(to_native(fd_), backlog) != 0) return make_error("listen failed: " + error_text(last_error()));
    return ok_status();
}

Result<std::uint16_t> Socket::local_port() const {
    Address a;
    SockLen len = static_cast<SockLen>(sizeof(sockaddr_in6));
    if (getsockname(to_native(fd_), static_cast<sockaddr*>(a.mutable_data()), &len) != 0)
        return make_error("getsockname failed: " + error_text(last_error()));
    a.set_size(static_cast<int>(len));
    return a.port();
}

Result<Socket> Socket::accept() {
    NativeSocket c = ::accept(to_native(fd_), nullptr, nullptr);
    if (c == kBadSocket) {
        if (is_would_block(last_error())) return Socket();
        return make_error("accept failed: " + error_text(last_error()));
    }
    return Socket(static_cast<std::intptr_t>(c));
}

IoResult Socket::send(const void* data, std::size_t n) {
#ifdef _WIN32
    const int r = ::send(to_native(fd_), static_cast<const char*>(data), static_cast<int>(n), kSendFlags);
#else
    const auto r = ::send(static_cast<int>(fd_), data, n, kSendFlags);
#endif
    if (r >= 0) return {IoResult::Kind::Data, static_cast<std::size_t>(r)};
    return {is_would_block(last_error()) ? IoResult::Kind::WouldBlock : IoResult::Kind::Error, 0};
}

IoResult Socket::recv(void* buf, std::size_t n) {
#ifdef _WIN32
    const int r = ::recv(to_native(fd_), static_cast<char*>(buf), static_cast<int>(n), 0);
#else
    const auto r = ::recv(static_cast<int>(fd_), buf, n, 0);
#endif
    if (r > 0) return {IoResult::Kind::Data, static_cast<std::size_t>(r)};
    if (r == 0) return {IoResult::Kind::Closed, 0};
    return {is_would_block(last_error()) ? IoResult::Kind::WouldBlock : IoResult::Kind::Error, 0};
}

// ------------------------------------------------------------------- poll

int poll(std::span<PollEntry> entries, int timeout_ms) {
    if (timeout_ms < 0) timeout_ms = 0;
    if (entries.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
        return 0;
    }
    if (entries.size() > kMaxPollEntries) return -1;
    for (auto& e : entries) e.readable = e.writable = e.failed = false;
#ifdef _WIN32
    // select(): WSAPoll historically did not report failed non-blocking connects.
    fd_set rd, wr, ex;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&ex);
    for (auto& e : entries) {
        const SOCKET s = to_native(e.socket->native());
        if (e.want_read) FD_SET(s, &rd);
        if (e.want_write) {
            FD_SET(s, &wr);
            FD_SET(s, &ex);  // a failed connect is reported as an exceptional condition
        }
    }
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(0, &rd, &wr, &ex, &tv) < 0) return -1;
    int ready = 0;
    for (auto& e : entries) {
        const SOCKET s = to_native(e.socket->native());
        e.readable = FD_ISSET(s, &rd) != 0;
        e.writable = FD_ISSET(s, &wr) != 0;
        e.failed = FD_ISSET(s, &ex) != 0;
        if (e.readable || e.writable || e.failed) ++ready;
    }
    return ready;
#else
    std::array<pollfd, kMaxPollEntries> fds{};
    for (std::size_t i = 0; i < entries.size(); ++i) {
        fds[i].fd = static_cast<int>(entries[i].socket->native());
        fds[i].events = static_cast<short>((entries[i].want_read ? POLLIN : 0) | (entries[i].want_write ? POLLOUT : 0));
    }
    int r;
    do {
        r = ::poll(fds.data(), static_cast<nfds_t>(entries.size()), timeout_ms);
    } while (r < 0 && errno == EINTR);
    if (r < 0) return -1;
    int ready = 0;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        entries[i].readable = (fds[i].revents & (POLLIN | POLLHUP)) != 0;
        entries[i].writable = (fds[i].revents & POLLOUT) != 0;
        entries[i].failed = (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
        if (fds[i].revents) ++ready;
    }
    return ready;
#endif
}

}  // namespace sentinel::net
