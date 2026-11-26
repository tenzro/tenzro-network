// tenzro/client.hpp - header-only C++17 RAII wrapper over the C ABI (tenzro.h).
//
// Error handling: a small Result<T> (value or Error) is used instead of
// std::expected so the header builds under C++17. No exceptions are thrown by
// the wrapper (except possibly std::bad_alloc from std::string).
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <variant>

#include "tenzro/tenzro.h"

namespace tenzro {

struct Error {
    TenzroStatus code = TENZRO_OK;
    std::string message;
};

template <typename T>
class Result {
public:
    Result(T v) : v_(std::move(v)) {}
    Result(Error e) : v_(std::move(e)) {}
    bool ok() const { return std::holds_alternative<T>(v_); }
    explicit operator bool() const { return ok(); }
    const T& value() const { return std::get<T>(v_); }
    T& value() { return std::get<T>(v_); }
    const Error& error() const { return std::get<Error>(v_); }
private:
    std::variant<T, Error> v_;
};

using NodeStatus = TenzroNodeStatus;

class Client {
public:
    // Check ok() after construction: an invalid endpoint leaves the client invalid.
    explicit Client(const std::string& endpoint, std::uint64_t expected_chain_id = 0)
        : h_(tenzro_client_new(endpoint.c_str(), expected_chain_id)) {}
    ~Client() { tenzro_client_free(h_); }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&& o) noexcept : h_(std::exchange(o.h_, nullptr)) {}
    Client& operator=(Client&& o) noexcept {
        if (this != &o) { tenzro_client_free(h_); h_ = std::exchange(o.h_, nullptr); }
        return *this;
    }

    bool valid() const { return h_ != nullptr; }

    Result<std::uint64_t> chain_id() { return u64(tenzro_get_chain_id); }
    Result<std::uint64_t> block_number() { return u64(tenzro_get_block_number); }

    Result<NodeStatus> status() {
        if (!h_) return invalid();
        NodeStatus s{};
        TenzroStatus st = tenzro_get_status(h_, &s);
        if (st != TENZRO_OK) return fail(st);
        return s;
    }

    // Balance as a 0x-prefixed hex string (may exceed 64 bits).
    Result<std::string> balance_hex(const std::string& address) {
        if (!h_) return invalid();
        std::string buf(80, '\0');
        size_t needed = 0;
        TenzroStatus st = tenzro_get_balance(h_, address.c_str(), &buf[0], buf.size(), &needed);
        if (st == TENZRO_ERR_BUFFER_TOO_SMALL) {
            buf.assign(needed, '\0');
            st = tenzro_get_balance(h_, address.c_str(), &buf[0], buf.size(), &needed);
        }
        if (st != TENZRO_OK) return fail(st);
        buf.resize(std::char_traits<char>::length(buf.c_str()));
        return buf;
    }

private:
    template <typename F>
    Result<std::uint64_t> u64(F f) {
        if (!h_) return invalid();
        std::uint64_t v = 0;
        TenzroStatus st = f(h_, &v);
        if (st != TENZRO_OK) return fail(st);
        return v;
    }
    Error invalid() const { return Error{TENZRO_ERR_INVALID_ARG, "invalid client (bad endpoint?)"}; }
    Error fail(TenzroStatus st) const {
        std::string m = tenzro_last_error(h_);
        if (m.empty()) m = tenzro_status_str(st);
        return Error{st, std::move(m)};
    }
    TenzroClient* h_;
};

}  // namespace tenzro
