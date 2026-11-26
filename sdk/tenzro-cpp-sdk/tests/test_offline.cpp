// Offline tests: no node needed. Spins up a tiny fake JSON-RPC server on loopback.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <tenzro/client.hpp>

static int serve(int lfd, const char* body, int n_requests) {
    for (int i = 0; i < n_requests; i++) {
        int fd = accept(lfd, nullptr, nullptr);
        char buf[4096]; (void)!read(fd, buf, sizeof buf);
        std::string r = std::string("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ") +
                        std::to_string(strlen(body)) + "\r\n\r\n" + body;
        (void)!write(fd, r.data(), r.size());
        close(fd);
    }
    return 0;
}

static int listen_any(int* port) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(l, (sockaddr*)&a, sizeof a); listen(l, 4);
    socklen_t len = sizeof a; getsockname(l, (sockaddr*)&a, &len); *port = ntohs(a.sin_port);
    return l;
}

int main() {
    int port;
    { // bad endpoints
        tenzro::Client d("ftp://x"); assert(!d.valid());
        tenzro::Client e("http://127.0.0.1:"); assert(!e.valid());
        tenzro::Client f("https://"); assert(!f.valid());
        assert(tenzro::Client("https://rpc.tenzro.com").valid());
    }
    { // an https endpoint is reached over TLS: a plain-HTTP server cannot answer it
        int l = listen_any(&port);
        std::thread t(serve, l, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x3444\"}", 1);
        tenzro::Client c("https://127.0.0.1:" + std::to_string(port), 13380);
        auto r = c.chain_id(); assert(!r.ok() && r.error().code == TENZRO_ERR_CONNECT);
        t.join(); close(l);
    }
    { // chain id ok
        int l = listen_any(&port);
        std::thread t(serve, l, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x3444\"}", 1);
        tenzro::Client c("http://127.0.0.1:" + std::to_string(port), 13380);
        auto r = c.chain_id(); assert(r.ok() && r.value() == 13380);
        t.join(); close(l);
    }
    { // chain mismatch
        int l = listen_any(&port);
        std::thread t(serve, l, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}", 1);
        tenzro::Client c("http://127.0.0.1:" + std::to_string(port), 13380);
        auto r = c.chain_id(); assert(!r.ok() && r.error().code == TENZRO_ERR_CHAIN_MISMATCH);
        t.join(); close(l);
    }
    { // rpc error, message containing "result" must not confuse parser
        int l = listen_any(&port);
        std::thread t(serve, l, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"bad \\\"result\\\": x\"}}", 1);
        tenzro::Client c("http://127.0.0.1:" + std::to_string(port));
        auto r = c.balance_hex("0x01"); assert(!r.ok() && r.error().code == TENZRO_ERR_RPC);
        t.join(); close(l);
    }
    { // long balance triggers retry path (needs 2 requests)
        int l = listen_any(&port);
        std::string big = "0x" + std::string(100, 'f');
        std::string body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"" + big + "\"}";
        std::thread t(serve, l, body.c_str(), 2);
        tenzro::Client c("http://127.0.0.1:" + std::to_string(port));
        auto r = c.balance_hex("0x01"); assert(r.ok() && r.value() == big);
        t.join(); close(l);
    }
    { // invalid address rejected before network
        tenzro::Client c("http://127.0.0.1:1");
        auto r = c.balance_hex("not-an-address"); assert(!r.ok() && r.error().code == TENZRO_ERR_INVALID_ARG);
    }
    { // connection refused
        tenzro::Client c("http://127.0.0.1:1");
        auto r = c.chain_id(); assert(!r.ok() && r.error().code == TENZRO_ERR_CONNECT);
    }
    std::puts("all offline tests passed");
}
