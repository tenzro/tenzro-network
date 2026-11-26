/* Minimal Tenzro JSON-RPC client core over libcurl: HTTP and HTTPS. */
#include "tenzro/tenzro.h"

#include <ctype.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERRLEN 256
#define TIMEOUT_MS 10000
#define MAX_RESPONSE (1u << 20) /* 1 MiB cap */

struct TenzroClient {
    char *url;
    uint64_t expected_chain_id;
    unsigned long next_id;
    char err[ERRLEN];
};

int tenzro_abi_version(void) { return TENZRO_ABI_VERSION; }

const char *tenzro_status_str(TenzroStatus s) {
    switch (s) {
    case TENZRO_OK: return "ok";
    case TENZRO_ERR_INVALID_ARG: return "invalid argument";
    case TENZRO_ERR_UNSUPPORTED_SCHEME: return "unsupported URL scheme (http:// or https:// only)";
    case TENZRO_ERR_CONNECT: return "connection error";
    case TENZRO_ERR_HTTP: return "http error";
    case TENZRO_ERR_RPC: return "json-rpc error";
    case TENZRO_ERR_PARSE: return "response parse error";
    case TENZRO_ERR_BUFFER_TOO_SMALL: return "buffer too small";
    case TENZRO_ERR_CHAIN_MISMATCH: return "chain id mismatch";
    }
    return "unknown";
}

static void set_err(TenzroClient *c, const char *fmt, const char *a) {
    snprintf(c->err, ERRLEN, fmt, a ? a : "");
}

static char *dup_n(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

TenzroClient *tenzro_client_new(const char *endpoint, uint64_t expected_chain_id) {
    if (!endpoint) return NULL;
    size_t scheme = strncmp(endpoint, "https://", 8) == 0 ? 8
                  : strncmp(endpoint, "http://", 7) == 0  ? 7
                                                          : 0;
    const char *authority = endpoint + scheme;
    size_t alen = strcspn(authority, "/");
    if (scheme == 0 || alen == 0 || authority[0] == ':' || authority[alen - 1] == ':') return NULL;
    TenzroClient *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->url = dup_n(endpoint, strlen(endpoint));
    c->expected_chain_id = expected_chain_id;
    c->next_id = 1;
    if (!c->url) {
        tenzro_client_free(c);
        return NULL;
    }
    return c;
}

void tenzro_client_free(TenzroClient *c) {
    if (!c) return;
    free(c->url);
    free(c);
}

const char *tenzro_last_error(const TenzroClient *c) { return c ? c->err : ""; }

/* The response body as it arrives, bounded by MAX_RESPONSE. */
struct body {
    char *buf;
    size_t len;
    int too_large;
};

static size_t on_body(char *data, size_t size, size_t n, void *user) {
    struct body *b = user;
    size_t add = size * n;
    if (b->len + add > MAX_RESPONSE) {
        b->too_large = 1;
        return 0;
    }
    char *nb = realloc(b->buf, b->len + add + 1);
    if (!nb) return 0;
    memcpy(nb + b->len, data, add);
    b->buf = nb;
    b->len += add;
    b->buf[b->len] = 0;
    return add;
}

/* Perform one HTTP POST; *resp is malloc'd internally and freed by the caller
 * of this static helper (never crosses the C ABI). Body is NUL-terminated.
 * An https:// endpoint is reached over TLS with the peer's certificate and
 * host name verified against the system's trust store. */
static TenzroStatus http_post(TenzroClient *c, const char *body, char **resp) {
    CURL *h = curl_easy_init();
    if (!h) { set_err(c, "out of memory%s", ""); return TENZRO_ERR_CONNECT; }
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    struct body got = {NULL, 0, 0};
    curl_easy_setopt(h, CURLOPT_URL, c->url);
    curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, (long)TIMEOUT_MS);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &got);
    CURLcode rc = curl_easy_perform(h);
    long status = 0;
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(h);
    if (got.too_large) {
        free(got.buf);
        set_err(c, "response too large%s", "");
        return TENZRO_ERR_HTTP;
    }
    if (rc != CURLE_OK) {
        free(got.buf);
        set_err(c, "request failed: %s", curl_easy_strerror(rc));
        return TENZRO_ERR_CONNECT;
    }
    if (status != 200) {
        char line[24];
        snprintf(line, sizeof line, "%ld", status);
        free(got.buf);
        set_err(c, "HTTP status %s", line);
        return TENZRO_ERR_HTTP;
    }
    *resp = got.buf ? got.buf : dup_n("", 0);
    if (!*resp) { set_err(c, "out of memory%s", ""); return TENZRO_ERR_CONNECT; }
    return TENZRO_OK;
}

static const char *skip_ws(const char *p) { while (*p && isspace((unsigned char)*p)) p++; return p; }

/* Skip one JSON value starting at p; returns pointer past it, or NULL. */
static const char *skip_value(const char *p) {
    p = skip_ws(p);
    if (*p == '"') {
        for (p++; *p; p++) { if (*p == '\\' && p[1]) p++; else if (*p == '"') return p + 1; }
        return NULL;
    }
    if (*p == '{' || *p == '[') {
        int depth = 0;
        for (; *p; p++) {
            if (*p == '"') { p = skip_value(p); if (!p) return NULL; p--; }
            else if (*p == '{' || *p == '[') depth++;
            else if (*p == '}' || *p == ']') { if (--depth == 0) return p + 1; }
        }
        return NULL;
    }
    while (*p && *p != ',' && *p != '}' && *p != ']' && !isspace((unsigned char)*p)) p++;
    return p;
}

static int find_key(const char *json, const char *key, const char **vs, const char **ve) {
    const char *p = skip_ws(json);
    if (*p != '{') return 0;
    p = skip_ws(p + 1);
    size_t kl = strlen(key);
    while (*p == '"') {
        const char *ke = skip_value(p);
        if (!ke) return 0;
        int match = (size_t)(ke - p - 2) == kl && strncmp(p + 1, key, kl) == 0;
        p = skip_ws(ke);
        if (*p != ':') return 0;
        const char *v = skip_ws(p + 1);
        const char *e = skip_value(v);
        if (!e) return 0;
        if (match) { *vs = v; *ve = e; return 1; }
        p = skip_ws(e);
        if (*p == ',') p = skip_ws(p + 1); else break;
    }
    return 0;
}

/* Issue a JSON-RPC call; on success *val points to a malloc'd copy of the
 * result's raw JSON text (internal; freed by callers below). */
static TenzroStatus rpc_call(TenzroClient *c, const char *method, const char *params, char **val) {
    char body[512];
    int n = snprintf(body, sizeof body, "{\"jsonrpc\":\"2.0\",\"id\":%lu,\"method\":\"%s\",\"params\":%s}",
                     c->next_id++, method, params);
    if (n < 0 || (size_t)n >= sizeof body) { set_err(c, "request too large%s", ""); return TENZRO_ERR_INVALID_ARG; }
    c->err[0] = 0;
    char *resp = NULL;
    TenzroStatus st = http_post(c, body, &resp);
    if (st != TENZRO_OK) return st;
    const char *vs, *ve;
    if (find_key(resp, "error", &vs, &ve)) {
        const char *ms, *me;
        char *errobj = dup_n(vs, (size_t)(ve - vs));
        if (errobj && find_key(errobj, "message", &ms, &me) && me - ms >= 2)
            snprintf(c->err, ERRLEN, "rpc error: %.*s", (int)(me - ms - 2), ms + 1);
        else set_err(c, "rpc error%s", "");
        free(errobj); free(resp);
        return TENZRO_ERR_RPC;
    }
    if (!find_key(resp, "result", &vs, &ve)) { free(resp); set_err(c, "response has no result%s", ""); return TENZRO_ERR_PARSE; }
    *val = dup_n(vs, (size_t)(ve - vs));
    free(resp);
    if (!*val) { set_err(c, "out of memory%s", ""); return TENZRO_ERR_PARSE; }
    return TENZRO_OK;
}

/* Parse a JSON string value holding 0x-hex into u64. */
static int parse_hex_u64(const char *v, uint64_t *out) {
    if (v[0] != '"' || v[1] != '0' || (v[2] != 'x' && v[2] != 'X')) return 0;
    const char *p = v + 3;
    uint64_t r = 0; int digits = 0;
    for (; *p && *p != '"'; p++, digits++) {
        int d = isdigit((unsigned char)*p) ? *p - '0' : (tolower((unsigned char)*p) >= 'a' && tolower((unsigned char)*p) <= 'f') ? tolower((unsigned char)*p) - 'a' + 10 : -1;
        if (d < 0 || digits >= 16) return 0;
        r = (r << 4) | (uint64_t)d;
    }
    if (*p != '"' || digits == 0) return 0;
    *out = r;
    return 1;
}

static TenzroStatus call_u64(TenzroClient *c, const char *method, uint64_t *out) {
    if (!c || !out) return TENZRO_ERR_INVALID_ARG;
    char *v = NULL;
    TenzroStatus st = rpc_call(c, method, "[]", &v);
    if (st != TENZRO_OK) return st;
    int ok = parse_hex_u64(v, out);
    free(v);
    if (!ok) { set_err(c, "%s: result is not a hex quantity", method); return TENZRO_ERR_PARSE; }
    return TENZRO_OK;
}

TenzroStatus tenzro_get_chain_id(TenzroClient *c, uint64_t *out) {
    TenzroStatus st = call_u64(c, "eth_chainId", out);
    if (st == TENZRO_OK && c->expected_chain_id && *out != c->expected_chain_id) {
        snprintf(c->err, ERRLEN, "chain id mismatch: node %llu, expected %llu",
                 (unsigned long long)*out, (unsigned long long)c->expected_chain_id);
        return TENZRO_ERR_CHAIN_MISMATCH;
    }
    return st;
}

TenzroStatus tenzro_get_block_number(TenzroClient *c, uint64_t *out) { return call_u64(c, "eth_blockNumber", out); }

TenzroStatus tenzro_get_status(TenzroClient *c, TenzroNodeStatus *out) {
    if (!c || !out) return TENZRO_ERR_INVALID_ARG;
    TenzroNodeStatus s = {0};
    TenzroStatus st = call_u64(c, "eth_blockNumber", &s.block_number);
    if (st != TENZRO_OK) return st;
    if ((st = call_u64(c, "net_peerCount", &s.peer_count)) != TENZRO_OK) return st;
    char *v = NULL;
    if ((st = rpc_call(c, "eth_syncing", "[]", &v)) != TENZRO_OK) return st;
    s.syncing = strcmp(v, "false") != 0; /* object with progress => syncing */
    free(v); v = NULL;
    if ((st = rpc_call(c, "getHealth", "[]", &v)) != TENZRO_OK) return st;
    s.healthy = strcmp(v, "\"ok\"") == 0;
    free(v);
    *out = s;
    return TENZRO_OK;
}

TenzroStatus tenzro_get_balance(TenzroClient *c, const char *address, char *out, size_t cap, size_t *needed) {
    if (!c || !address || !out) return TENZRO_ERR_INVALID_ARG;
    size_t al = strlen(address);
    if (al < 3 || al > 130 || address[0] != '0' || (address[1] != 'x' && address[1] != 'X')) {
        set_err(c, "address must be 0x-prefixed hex%s", ""); return TENZRO_ERR_INVALID_ARG;
    }
    for (size_t i = 2; i < al; i++) if (!isxdigit((unsigned char)address[i])) { set_err(c, "address must be 0x-prefixed hex%s", ""); return TENZRO_ERR_INVALID_ARG; }
    char params[200];
    snprintf(params, sizeof params, "[\"%s\"]", address);
    char *v = NULL;
    TenzroStatus st = rpc_call(c, "tenzro_getBalance", params, &v);
    if (st != TENZRO_OK) return st;
    size_t vl = strlen(v);
    if (vl < 5 || v[0] != '"' || v[1] != '0' || v[2] != 'x' || v[vl - 1] != '"') { free(v); set_err(c, "balance is not a hex string%s", ""); return TENZRO_ERR_PARSE; }
    size_t need = vl - 2 + 1;
    if (needed) *needed = need;
    if (cap < need) { free(v); set_err(c, "buffer too small%s", ""); return TENZRO_ERR_BUFFER_TOO_SMALL; }
    memcpy(out, v + 1, vl - 2);
    out[vl - 2] = 0;
    free(v);
    return TENZRO_OK;
}
