#pragma once
// Minimal expected-like result type (std::expected is C++23; the project targets C++20).
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace sentinel {

enum class Errc { Failed, Unauthorized, Cancelled, InvalidArgument };

struct Error {
    std::string message;
    Errc code = Errc::Failed;
};

struct Unit {};

template <class T>
class Result {
public:
    Result(T value) : v_(std::move(value)) {}  // NOLINT: implicit by design
    Result(Error err) : v_(std::move(err)) {}  // NOLINT: implicit by design

    bool ok() const noexcept { return v_.index() == 0; }
    explicit operator bool() const noexcept { return ok(); }

    // value() throws std::runtime_error if the result holds an error; use it only at
    // program boundaries (CLI, tests) where an exception is the right way to bail out.
    T& value() & {
        check();
        return std::get<0>(v_);
    }
    const T& value() const& {
        check();
        return std::get<0>(v_);
    }
    T&& value() && {
        check();
        return std::get<0>(std::move(v_));
    }
    const Error& error() const { return std::get<1>(v_); }

private:
    void check() const {
        if (!ok()) throw std::runtime_error(std::get<1>(v_).message);
    }
    std::variant<T, Error> v_;
};

using Status = Result<Unit>;
inline Status ok_status() { return Unit{}; }
inline Error make_error(std::string msg, Errc code = Errc::Failed) { return Error{std::move(msg), code}; }

}  // namespace sentinel
