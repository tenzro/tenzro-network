/*
 * tenzro.h - minimal C ABI for talking to a Tenzro node over JSON-RPC.
 *
 * Hand-written (no cbindgen; the core is C, see README).
 *
 * Scope: read-only calls on methods the node classifies as OPEN
 * (eth_chainId, eth_blockNumber, net_peerCount, eth_syncing, getHealth,
 * tenzro_getBalance). Transport is libcurl: "http://" and "https://"
 * endpoints, TLS with the peer's certificate and host name verified against
 * the system's trust store.
 *
 * OWNERSHIP RULES
 *  - tenzro_client_new() returns a handle owned by the caller; release it
 *    with tenzro_client_free() exactly once. tenzro_client_free(NULL) is a no-op.
 *  - Every other function writes results into memory supplied by the caller
 *    (output pointers / buffers). The library never returns heap memory that
 *    the caller must free.
 *  - tenzro_last_error() returns a pointer owned by the handle. It stays
 *    valid until the next call on the same handle or tenzro_client_free().
 *    Do not free it.
 *  - A handle is not thread-safe: use one handle per thread, or lock.
 */
#ifndef TENZRO_H
#define TENZRO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TENZRO_ABI_VERSION 1

typedef struct TenzroClient TenzroClient; /* opaque */

typedef enum TenzroStatus {
    TENZRO_OK = 0,
    TENZRO_ERR_INVALID_ARG = 1,         /* NULL pointer, bad address string, ... */
    TENZRO_ERR_UNSUPPORTED_SCHEME = 2,  /* endpoint is not http:// or https:// */
    TENZRO_ERR_CONNECT = 3,             /* resolve/connect/send/recv failed or timed out */
    TENZRO_ERR_HTTP = 4,                /* non-200 HTTP status or malformed response */
    TENZRO_ERR_RPC = 5,                 /* node returned a JSON-RPC error object */
    TENZRO_ERR_PARSE = 6,               /* response JSON not in the expected shape */
    TENZRO_ERR_BUFFER_TOO_SMALL = 7,    /* caller buffer too small (see *needed) */
    TENZRO_ERR_CHAIN_MISMATCH = 8       /* node chain id != expected chain id */
} TenzroStatus;

typedef struct TenzroNodeStatus {
    uint64_t block_number;  /* eth_blockNumber */
    uint64_t peer_count;    /* net_peerCount */
    int32_t  syncing;       /* eth_syncing: 1 if syncing, else 0 */
    int32_t  healthy;       /* getHealth == "ok": 1, else 0 */
} TenzroNodeStatus;

/* Returns the ABI version the library was built with (TENZRO_ABI_VERSION). */
int tenzro_abi_version(void);

/* Human-readable name for a status code. Static string; never freed. */
const char *tenzro_status_str(TenzroStatus s);

/*
 * Create a client. `endpoint` is "http://" or "https://" followed by
 * "host[:port][/path]" (copied).
 * `expected_chain_id`: 0 = do not check; otherwise tenzro_get_chain_id()
 * returns TENZRO_ERR_CHAIN_MISMATCH if the node reports another chain.
 * Does not touch the network. Returns NULL on bad endpoint or OOM.
 * Caller owns the result; free with tenzro_client_free().
 */
TenzroClient *tenzro_client_new(const char *endpoint, uint64_t expected_chain_id);

/* Free a client. Safe on NULL. Invalidates pointers from tenzro_last_error(). */
void tenzro_client_free(TenzroClient *c);

/* Message for the last failed call on this handle ("" if none). Handle-owned. */
const char *tenzro_last_error(const TenzroClient *c);

/* eth_chainId -> *out. */
TenzroStatus tenzro_get_chain_id(TenzroClient *c, uint64_t *out);

/* eth_blockNumber -> *out. */
TenzroStatus tenzro_get_block_number(TenzroClient *c, uint64_t *out);

/* eth_blockNumber + net_peerCount + eth_syncing + getHealth -> *out. */
TenzroStatus tenzro_get_status(TenzroClient *c, TenzroNodeStatus *out);

/*
 * tenzro_getBalance. `address` is a hex address string (0x-prefixed, 20 bytes,
 * passed to the node as-is). The balance is a 0x-prefixed hex string written
 * NUL-terminated into caller buffer `out` (capacity `cap`), because balances
 * can exceed 64 bits. On TENZRO_ERR_BUFFER_TOO_SMALL, *needed (if non-NULL)
 * is the required capacity including the NUL.
 */
TenzroStatus tenzro_get_balance(TenzroClient *c, const char *address,
                                char *out, size_t cap, size_t *needed);

#ifdef __cplusplus
}
#endif
#endif /* TENZRO_H */
