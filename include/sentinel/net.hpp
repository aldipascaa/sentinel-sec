#pragma once
// Portable TCP socket layer. Platform headers (winsock2 / sys/socket) never leak out of
// this interface; implementations live in src/net/socket_win.cpp and src/net/socket_posix.cpp.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "sentinel/result.hpp"

namespace sentinel::net {

// Initializes the platform socket runtime (WSAStartup on Windows, no-op elsewhere).
// Safe to call repeatedly; cleanup is RAII at process exit. Socket/Address functions call it for you.
Status ensure_initialized();

enum class Family { Auto, IPv4, IPv6 };  // Auto prefers IPv4 when a name has both

class Address {
public:
    Address() = default;
    // Resolves a host name or numeric IPv4/IPv6 literal.
    static Result<Address> resolve(const std::string& host, std::uint16_t port = 0, Family f = Family::Auto);
    // Parses a numeric literal only (no DNS); returns an error if `text` is not an IP address.
    static Result<Address> parse_literal(const std::string& text, std::uint16_t port = 0);
    static Address loopback(Family f, std::uint16_t port = 0);  // 127.0.0.1 or ::1

    Address with_port(std::uint16_t port) const;
    std::uint16_t port() const;
    bool is_ipv6() const;
    bool is_loopback() const;  // 127.0.0.0/8, ::1, ::ffff:127.0.0.0/104
    std::string ip_string() const;

    const void* data() const { return storage_.data(); }
    int size() const { return len_; }
    void* mutable_data() { return storage_.data(); }
    void set_size(int n) { len_ = n; }

private:
    alignas(8) std::array<unsigned char, 128> storage_{};
    int len_ = 0;
};

struct IoResult {
    enum class Kind { Data, WouldBlock, Closed, Error };
    Kind kind = Kind::Error;
    std::size_t bytes = 0;
};

// RAII owner of a TCP socket. Move-only; closes on destruction.
class Socket {
public:
    Socket() noexcept = default;
    ~Socket() { close(); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& o) noexcept : fd_(o.release()) {}
    Socket& operator=(Socket&& o) noexcept {
        if (this != &o) {
            close();
            fd_ = o.release();
        }
        return *this;
    }

    static Result<Socket> create(const Address& like);  // TCP stream socket of the address family
    bool valid() const noexcept { return fd_ != kInvalid; }
    std::intptr_t native() const noexcept { return fd_; }
    void close() noexcept;

    Status set_nonblocking(bool on = true);

    enum class Connect { Connected, InProgress, Failed };
    Connect connect(const Address& to);  // for a non-blocking socket: InProgress is the normal result
    Status finish_connect();             // after the socket became writable: checks SO_ERROR

    Status bind(const Address& a);
    Status listen(int backlog = 16);
    Result<std::uint16_t> local_port() const;
    // Non-blocking accept. Returns an invalid Socket (ok result) when nothing is pending.
    Result<Socket> accept();

    IoResult send(const void* data, std::size_t n);
    IoResult recv(void* buf, std::size_t n);

private:
    static constexpr std::intptr_t kInvalid = -1;
    std::intptr_t release() noexcept {
        auto f = fd_;
        fd_ = kInvalid;
        return f;
    }
    explicit Socket(std::intptr_t fd) noexcept : fd_(fd) {}
    std::intptr_t fd_ = kInvalid;
};

struct PollEntry {
    const Socket* socket = nullptr;
    bool want_read = false;
    bool want_write = false;  // also reports connect completion/failure
    // results
    bool readable = false;
    bool writable = false;
    bool failed = false;  // error/hangup/exception condition: inspect with finish_connect() or recv()
};

// Waits up to timeout_ms for readiness of any entry (with an empty span: just sleeps).
// Returns the number of ready entries, or -1 on error. Limit: 1000 entries per call.
int poll(std::span<PollEntry> entries, int timeout_ms);

constexpr std::size_t kMaxPollEntries = 1000;

}  // namespace sentinel::net
