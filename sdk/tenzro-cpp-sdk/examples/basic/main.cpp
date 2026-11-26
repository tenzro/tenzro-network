#include <cstdio>
#include <cstdlib>
#include <tenzro/client.hpp>

int main(int argc, char** argv) {
    const char* env = std::getenv("TENZRO_RPC_URL");
    std::string endpoint = argc > 1 ? argv[1] : (env ? env : "http://127.0.0.1:28545");
    std::string addr = argc > 2 ? argv[2] : "0x0000000000000000000000000000000000000001";

    tenzro::Client c(endpoint, 13380);
    if (!c.valid()) { std::fprintf(stderr, "bad endpoint (http:// only): %s\n", endpoint.c_str()); return 2; }

    auto id = c.chain_id();
    if (!id) { std::fprintf(stderr, "chain_id: %s\n", id.error().message.c_str()); return 1; }
    std::printf("endpoint:     %s\nchain id:     %llu\n", endpoint.c_str(), (unsigned long long)id.value());

    auto st = c.status();
    if (!st) { std::fprintf(stderr, "status: %s\n", st.error().message.c_str()); return 1; }
    std::printf("block number: %llu\npeers:        %llu\nsyncing:      %d\nhealthy:      %d\n",
                (unsigned long long)st.value().block_number, (unsigned long long)st.value().peer_count,
                st.value().syncing, st.value().healthy);

    auto bal = c.balance_hex(addr);
    if (!bal) { std::fprintf(stderr, "balance: %s\n", bal.error().message.c_str()); return 1; }
    std::printf("balance(%s) = %s\n", addr.c_str(), bal.value().c_str());
    return 0;
}
