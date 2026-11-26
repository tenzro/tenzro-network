#include "tenzro/sign.h"

#include <string.h>

#include "tz_hash.h"
#include "tz_json.h"

static const char PREFIX[] = "CompositeAlgorithmSignatures2025";
static const char VOUCHER_DOMAIN[] = "tenzro/escrow-voucher";
static const char READING_DOMAIN[] = "tenzro/sensor-reading";

tz_status tz_message_representative(const char *context,
                                    const uint8_t *message, size_t message_len,
                                    uint8_t *out, size_t out_capacity,
                                    size_t *out_len)
{
    static const uint8_t empty = 0;
    const size_t prefix_len = sizeof(PREFIX) - 1;
    const size_t label_len = sizeof(TZ_LABEL_MLDSA65_P256) - 1;
    size_t context_len;
    size_t total;
    uint8_t *p = out;

    if (context == NULL || out == NULL || out_len == NULL ||
        (message == NULL && message_len != 0)) {
        return TZ_ERR_ARGUMENT;
    }
    context_len = strlen(context);
    if (context_len == 0 || context_len > 255) {
        return TZ_ERR_ARGUMENT;
    }
    total = prefix_len + label_len + 1 + context_len + 64;
    if (out_capacity < total) {
        return TZ_ERR_SPACE;
    }
    memcpy(p, PREFIX, prefix_len);
    p += prefix_len;
    memcpy(p, TZ_LABEL_MLDSA65_P256, label_len);
    p += label_len;
    *p++ = (uint8_t)context_len;
    memcpy(p, context, context_len);
    p += context_len;
    if (tz_sha512(message_len != 0 ? message : &empty, message_len, p) != 0) {
        return TZ_ERR_HASH;
    }
    *out_len = total;
    return TZ_OK;
}

tz_status tz_signing_digest(const char *context,
                            const uint8_t *message, size_t message_len,
                            uint8_t digest[32])
{
    uint8_t representative[TZ_REPRESENTATIVE_MAX];
    size_t len = 0;
    tz_status status;

    if (digest == NULL) {
        return TZ_ERR_ARGUMENT;
    }
    status = tz_message_representative(context, message, message_len,
                                       representative, sizeof(representative),
                                       &len);
    if (status != TZ_OK) {
        return status;
    }
    return tz_sha256(representative, len, digest) == 0 ? TZ_OK : TZ_ERR_HASH;
}

void tz_escrow_voucher_bytes(uint64_t chain_id, const uint8_t escrow_id[32],
                             const uint8_t cumulative_le[16],
                             const uint8_t binding[32],
                             uint8_t out[TZ_ESCROW_VOUCHER_LEN])
{
    const size_t domain_len = sizeof(VOUCHER_DOMAIN) - 1;
    uint8_t *p = out;
    int i;

    memcpy(p, VOUCHER_DOMAIN, domain_len);
    p += domain_len;
    for (i = 0; i < 8; i++) {
        *p++ = (uint8_t)(chain_id >> (8 * i));
    }
    memcpy(p, escrow_id, 32);
    p += 32;
    memcpy(p, cumulative_le, 16);
    p += 16;
    memcpy(p, binding, 32);
}

tz_status tz_sensor_reading_digest(const char *device_did,
                                   const uint8_t payload_digest[32],
                                   uint64_t measured_at_ms,
                                   uint8_t digest[32])
{
    const size_t domain_len = sizeof(READING_DOMAIN) - 1;
    uint8_t preimage[sizeof(READING_DOMAIN) - 1 + 4 + TZ_DEVICE_DID_MAX + 32 + 8];
    uint8_t *p = preimage;
    size_t did_len;
    int i;

    if (device_did == NULL || payload_digest == NULL || digest == NULL) {
        return TZ_ERR_ARGUMENT;
    }
    did_len = strlen(device_did);
    if (did_len == 0 || did_len > TZ_DEVICE_DID_MAX) {
        return TZ_ERR_ARGUMENT;
    }
    memcpy(p, READING_DOMAIN, domain_len);
    p += domain_len;
    for (i = 0; i < 4; i++) {
        *p++ = (uint8_t)(did_len >> (8 * i));
    }
    memcpy(p, device_did, did_len);
    p += did_len;
    memcpy(p, payload_digest, 32);
    p += 32;
    for (i = 0; i < 8; i++) {
        *p++ = (uint8_t)(measured_at_ms >> (8 * i));
    }
    return tz_sha256(preimage, (size_t)(p - preimage), digest) == 0 ? TZ_OK : TZ_ERR_HASH;
}

/* A bounded writer: once it runs out of room it writes nothing more. */
struct tz_writer {
    char *out;
    size_t capacity;
    size_t len;
    int full;
};

static void put(struct tz_writer *w, const char *text, size_t len)
{
    if (w->full || w->capacity - w->len <= len) {
        w->full = 1;
        return;
    }
    memcpy(w->out + w->len, text, len);
    w->len += len;
}

static void put_text(struct tz_writer *w, const char *text)
{
    put(w, text, strlen(text));
}

static void put_hex(struct tz_writer *w, const uint8_t *bytes, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        char pair[2];
        pair[0] = digits[bytes[i] >> 4];
        pair[1] = digits[bytes[i] & 0x0f];
        put(w, pair, 2);
    }
}

static void put_u64(struct tz_writer *w, uint64_t value)
{
    char digits[20];
    size_t n = 0;

    do {
        digits[sizeof(digits) - ++n] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    put(w, digits + sizeof(digits) - n, n);
}

tz_status tz_sensor_reading_evidence(const char *device_did,
                                     const uint8_t payload_digest[32],
                                     uint64_t measured_at_ms,
                                     const uint8_t p256_signature[64],
                                     const uint8_t *ml_dsa_signature,
                                     size_t ml_dsa_len,
                                     char *out, size_t out_capacity,
                                     size_t *out_len)
{
    struct tz_writer w;
    size_t did_len;
    size_t i;

    if (device_did == NULL || payload_digest == NULL || p256_signature == NULL ||
        out == NULL || out_len == NULL || out_capacity == 0 ||
        (ml_dsa_signature == NULL) != (ml_dsa_len == 0)) {
        return TZ_ERR_ARGUMENT;
    }
    did_len = strlen(device_did);
    if (did_len == 0 || did_len > TZ_DEVICE_DID_MAX) {
        return TZ_ERR_ARGUMENT;
    }
    for (i = 0; i < did_len; i++) {
        unsigned char c = (unsigned char)device_did[i];
        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') {
            return TZ_ERR_ARGUMENT;
        }
    }
    w.out = out;
    w.capacity = out_capacity;
    w.len = 0;
    w.full = 0;
    put_text(&w, "{\"sensor_data\":{\"device_did\":\"");
    put(&w, device_did, did_len);
    put_text(&w, "\",\"payload_digest\":\"");
    put_hex(&w, payload_digest, 32);
    put_text(&w, "\",\"measured_at_ms\":");
    put_u64(&w, measured_at_ms);
    put_text(&w, ",\"signature\":{\"classical\":{\"form\":\"raw\",\"signature\":\"");
    put_hex(&w, p256_signature, 64);
    put_text(&w, "\"}");
    if (ml_dsa_len != 0) {
        put_text(&w, ",\"pq\":\"");
        put_hex(&w, ml_dsa_signature, ml_dsa_len);
        put_text(&w, "\"");
    }
    put_text(&w, "}}}");
    if (w.full) {
        return TZ_ERR_SPACE;
    }
    out[w.len] = '\0';
    *out_len = w.len;
    return TZ_OK;
}

/* Writes `value` (128-bit little-endian) in decimal into `digits`, returns the count. */
static size_t u128_decimal(const uint8_t value_le[16], char digits[40])
{
    uint8_t v[16];
    char reversed[40];
    size_t n = 0;
    int zero;

    memcpy(v, value_le, 16);
    do {
        unsigned int rem = 0;
        int i;
        zero = 1;
        for (i = 15; i >= 0; i--) {
            unsigned int cur = (rem << 8) | v[i];
            v[i] = (uint8_t)(cur / 10);
            rem = cur % 10;
            if (v[i] != 0) {
                zero = 0;
            }
        }
        reversed[n++] = (char)('0' + rem);
    } while (!zero);
    {
        size_t i;
        for (i = 0; i < n; i++) {
            digits[i] = reversed[n - 1 - i];
        }
    }
    return n;
}

tz_status tz_transfer_type(const uint8_t amount_le[16], char *out,
                           size_t out_capacity, size_t *out_len)
{
    struct tz_writer w;
    char digits[40];
    size_t n;
    int fits_u64 = 1;
    int i;

    if (amount_le == NULL || out == NULL || out_len == NULL || out_capacity == 0) {
        return TZ_ERR_ARGUMENT;
    }
    for (i = 8; i < 16; i++) {
        if (amount_le[i] != 0) {
            fits_u64 = 0;
        }
    }
    n = u128_decimal(amount_le, digits);
    w.out = out;
    w.capacity = out_capacity;
    w.len = 0;
    w.full = 0;
    /* An amount above 2^64 - 1 is written as a string, as the ledger writes it. */
    put_text(&w, "{\"Transfer\":{\"amount\":");
    if (!fits_u64) {
        put_text(&w, "\"");
    }
    put(&w, digits, n);
    if (!fits_u64) {
        put_text(&w, "\"");
    }
    put_text(&w, "}}");
    if (w.full) {
        return TZ_ERR_SPACE;
    }
    out[w.len] = '\0';
    *out_len = w.len;
    return TZ_OK;
}

static void le64(uint8_t out[8], uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) {
        out[i] = (uint8_t)(v >> (8 * i));
    }
}

tz_status tz_transaction_hash(const tz_tx_header *header,
                              const char *tx_type, size_t tx_type_len,
                              const char *memo, uint8_t hash[32])
{
    enum { FIXED = 8 + 32 + 32 + 8 + 8 + 8 + 8 + 8 };
    static uint8_t preimage[FIXED + TZ_TX_TYPE_MAX + TZ_MEMO_MAX];
    size_t memo_len = memo != NULL ? strlen(memo) : 0;
    uint8_t *p = preimage;

    if (header == NULL || tx_type == NULL || tx_type_len == 0 ||
        tx_type_len > TZ_TX_TYPE_MAX || memo_len > TZ_MEMO_MAX || hash == NULL) {
        return TZ_ERR_ARGUMENT;
    }
    le64(p, header->chain_id);
    memcpy(p + 8, header->from, 32);
    memcpy(p + 40, header->to, 32);
    le64(p + 72, header->nonce);
    le64(p + 80, header->gas_limit);
    le64(p + 88, header->gas_price);
    le64(p + 96, (uint64_t)header->timestamp_ms);
    le64(p + 104, (uint64_t)header->valid_until_ms);
    p += FIXED;
    memcpy(p, tx_type, tx_type_len);
    p += tx_type_len;
    if (memo_len != 0) {
        memcpy(p, memo, memo_len);
        p += memo_len;
    }
    /* Every validity time has the SHA-256 scheme today. */
    return tz_sha256(preimage, (size_t)(p - preimage), hash) == 0 ? TZ_OK : TZ_ERR_HASH;
}

tz_status tz_transfer_request(uint64_t id, const tz_tx_header *header,
                              const uint8_t amount_le[16],
                              const uint8_t public_key[64],
                              const uint8_t p256_signature[64],
                              const uint8_t *ml_dsa_signature,
                              size_t ml_dsa_len, char *out,
                              size_t out_capacity, size_t *out_len)
{
    struct tz_writer w;
    char type[TZ_TRANSFER_TYPE_MAX];
    char digits[40];
    size_t type_len = 0;
    size_t n;
    tz_status status;

    if (header == NULL || amount_le == NULL || public_key == NULL ||
        p256_signature == NULL || out == NULL || out_len == NULL ||
        out_capacity == 0 || (ml_dsa_signature == NULL) != (ml_dsa_len == 0) ||
        header->timestamp_ms < 0 || header->valid_until_ms < 0) {
        return TZ_ERR_ARGUMENT;
    }
    status = tz_transfer_type(amount_le, type, sizeof(type), &type_len);
    if (status != TZ_OK) {
        return status;
    }
    n = u128_decimal(amount_le, digits);
    w.out = out;
    w.capacity = out_capacity;
    w.len = 0;
    w.full = 0;
    put_text(&w, "{\"jsonrpc\":\"2.0\",\"id\":");
    put_u64(&w, id);
    put_text(&w, ",\"method\":\"tenzro_sendRawTransaction\",\"params\":{\"from\":\"0x");
    put_hex(&w, header->from, 32);
    put_text(&w, "\",\"to\":\"0x");
    put_hex(&w, header->to, 32);
    put_text(&w, "\",\"value\":\"");
    put(&w, digits, n);
    put_text(&w, "\",\"gas_limit\":");
    put_u64(&w, header->gas_limit);
    put_text(&w, ",\"gas_price\":");
    put_u64(&w, header->gas_price);
    put_text(&w, ",\"nonce\":");
    put_u64(&w, header->nonce);
    put_text(&w, ",\"chain_id\":");
    put_u64(&w, header->chain_id);
    put_text(&w, ",\"timestamp\":");
    put_u64(&w, (uint64_t)header->timestamp_ms);
    put_text(&w, ",\"valid_until\":");
    put_u64(&w, (uint64_t)header->valid_until_ms);
    put_text(&w, ",\"tx_type\":");
    put(&w, type, type_len);
    put_text(&w, ",\"public_key\":\"");
    put_hex(&w, public_key, 64);
    put_text(&w, "\",\"signature\":{\"classical\":{\"form\":\"raw\",\"signature\":\"");
    put_hex(&w, p256_signature, 64);
    put_text(&w, "\"}");
    if (ml_dsa_len != 0) {
        put_text(&w, ",\"pq\":\"");
        put_hex(&w, ml_dsa_signature, ml_dsa_len);
        put_text(&w, "\"");
    }
    put_text(&w, "}}}");
    if (w.full) {
        return TZ_ERR_SPACE;
    }
    out[w.len] = '\0';
    *out_len = w.len;
    return TZ_OK;
}

static const char ACCOUNT_DOMAIN[] = "tenzro/account";

tz_status tz_account_slot(const uint8_t public_key[64], uint8_t slot[32])
{
    uint8_t preimage[sizeof(ACCOUNT_DOMAIN) - 1 + 2 + 64];
    uint8_t digest[32];
    size_t n = sizeof(ACCOUNT_DOMAIN) - 1;

    if (public_key == NULL || slot == NULL) {
        return TZ_ERR_ARGUMENT;
    }
    memcpy(preimage, ACCOUNT_DOMAIN, n);
    preimage[n++] = 0x02; /* the P-256 account key */
    preimage[n++] = 64;
    memcpy(preimage + n, public_key, 64);
    if (tz_sha256(preimage, sizeof(preimage), digest) != 0) {
        return TZ_ERR_HASH;
    }
    memcpy(slot, digest, 20);
    memset(slot + 20, 0, 12);
    return TZ_OK;
}

/* 1 to TZ_ENROLMENT_FIELD_MAX bytes a shell takes as one word unquoted. */
static int plain_word(const char *text, int comma)
{
    size_t i, n;

    if (text == NULL) {
        return 0;
    }
    n = strlen(text);
    if (n == 0 || n > TZ_ENROLMENT_FIELD_MAX) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        char c = text[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == ':' || c == '.' || c == '_' ||
              c == '-' || (comma && c == ','))) {
            return 0;
        }
    }
    return 1;
}

tz_status tz_enrolment_command(const char *name, const char *controller_did,
                               const char *capabilities,
                               const uint8_t public_key[64], char *out,
                               size_t out_capacity, size_t *out_len)
{
    struct tz_writer w;

    if (!plain_word(name, 0) || !plain_word(controller_did, 0) ||
        !plain_word(capabilities, 1) || public_key == NULL || out == NULL ||
        out_len == NULL || out_capacity == 0) {
        return TZ_ERR_ARGUMENT;
    }
    w.out = out;
    w.capacity = out_capacity;
    w.len = 0;
    w.full = 0;
    put_text(&w, "tenzro identity register --identity-type machine --name ");
    put_text(&w, name);
    put_text(&w, " --controller ");
    put_text(&w, controller_did);
    put_text(&w, " --public-key ");
    put_hex(&w, public_key, 64);
    put_text(&w, " --capabilities ");
    put_text(&w, capabilities);
    if (w.full) {
        return TZ_ERR_SPACE;
    }
    out[w.len] = '\0';
    *out_len = w.len;
    return TZ_OK;
}

tz_status tz_read_request(uint64_t id, tz_read read, const uint8_t slot[32],
                          char *out, size_t out_capacity, size_t *out_len)
{
    struct tz_writer w;
    const char *method;

    switch (read) {
    case TZ_READ_BALANCE:
        method = "tenzro_getBalance";
        break;
    case TZ_READ_NONCE:
        method = "tenzro_getNonce";
        break;
    case TZ_READ_FINALITY:
        method = "tenzro_getFinality";
        break;
    default:
        return TZ_ERR_ARGUMENT;
    }
    if ((read == TZ_READ_FINALITY) != (slot == NULL) || out == NULL ||
        out_len == NULL || out_capacity == 0) {
        return TZ_ERR_ARGUMENT;
    }
    w.out = out;
    w.capacity = out_capacity;
    w.len = 0;
    w.full = 0;
    put_text(&w, "{\"jsonrpc\":\"2.0\",\"id\":");
    put_u64(&w, id);
    put_text(&w, ",\"method\":\"");
    put_text(&w, method);
    if (slot != NULL) {
        put_text(&w, "\",\"params\":[\"0x");
        put_hex(&w, slot, 20);
        put_text(&w, "\"]}");
    } else {
        put_text(&w, "\",\"params\":[]}");
    }
    if (w.full) {
        return TZ_ERR_SPACE;
    }
    out[w.len] = '\0';
    *out_len = w.len;
    return TZ_OK;
}

struct tz_answer {
    const char *id, *result, *error;
    size_t id_len, result_len, error_len;
};

static int answer_member(void *ctx, const char *key, size_t key_len,
                         const char *value, size_t value_len)
{
    struct tz_answer *a = ctx;
    const char **slot = NULL;
    size_t *len = NULL;

    if (tz_json_key_is(key, key_len, "id")) {
        slot = &a->id;
        len = &a->id_len;
    } else if (tz_json_key_is(key, key_len, "result")) {
        slot = &a->result;
        len = &a->result_len;
    } else if (tz_json_key_is(key, key_len, "error")) {
        slot = &a->error;
        len = &a->error_len;
    } else {
        return 1;
    }
    if (*slot != NULL) {
        return 0; /* a member twice */
    }
    *slot = value;
    *len = value_len;
    return 1;
}

/* The `result` of the answer to request `id`, or why there is none. */
static tz_status answer_result(const char *response, size_t response_len, uint64_t id,
                               struct tz_json *result)
{
    struct tz_answer a;
    struct tz_json r;
    uint64_t got;

    if (response == NULL) {
        return TZ_ERR_ARGUMENT;
    }
    memset(&a, 0, sizeof(a));
    r.p = response;
    r.end = response + response_len;
    if (!tz_json_object(&r, answer_member, &a)) {
        return TZ_ERR_RESPONSE;
    }
    tz_json_space(&r);
    if (r.p != r.end || a.id == NULL || !tz_json_u64(a.id, a.id_len, &got) || got != id) {
        return TZ_ERR_RESPONSE;
    }
    if (a.error != NULL) {
        return TZ_ERR_REFUSED;
    }
    if (a.result == NULL) {
        return TZ_ERR_RESPONSE;
    }
    result->p = a.result;
    result->end = a.result + a.result_len;
    return TZ_OK;
}

tz_status tz_read_quantity(const char *response, size_t response_len,
                           uint64_t id, uint8_t value_le[16])
{
    struct tz_json r;
    const char *digits;
    size_t n, i;
    tz_status status;

    if (value_le == NULL) {
        return TZ_ERR_ARGUMENT;
    }
    status = answer_result(response, response_len, id, &r);
    if (status != TZ_OK) {
        return status;
    }
    if (!tz_json_string(&r, &digits, &n) || r.p != r.end || n < 3 || n > 2 + 32 ||
        digits[0] != '0' || digits[1] != 'x') {
        return TZ_ERR_RESPONSE;
    }
    memset(value_le, 0, 16);
    digits += 2;
    n -= 2;
    for (i = 0; i < n; i++) {
        char c = digits[n - 1 - i];
        unsigned v;
        if (c >= '0' && c <= '9') {
            v = (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v = (unsigned)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v = (unsigned)(c - 'A' + 10);
        } else {
            return TZ_ERR_RESPONSE;
        }
        value_le[i / 2] |= (uint8_t)(v << (4 * (i % 2)));
    }
    return TZ_OK;
}

struct tz_heights {
    uint64_t ordered, certified;
    int has_ordered, has_certified;
};

static int heights_member(void *ctx, const char *key, size_t key_len,
                          const char *value, size_t value_len)
{
    struct tz_heights *h = ctx;

    if (tz_json_key_is(key, key_len, "ordered")) {
        if (h->has_ordered || !tz_json_u64(value, value_len, &h->ordered)) {
            return 0;
        }
        h->has_ordered = 1;
    } else if (tz_json_key_is(key, key_len, "certified")) {
        if (h->has_certified || !tz_json_u64(value, value_len, &h->certified)) {
            return 0;
        }
        h->has_certified = 1;
    }
    return 1;
}

tz_status tz_read_finality(const char *response, size_t response_len,
                           uint64_t id, uint64_t *ordered,
                           uint64_t *certified)
{
    struct tz_json r;
    struct tz_heights h;
    tz_status status;

    if (ordered == NULL || certified == NULL) {
        return TZ_ERR_ARGUMENT;
    }
    status = answer_result(response, response_len, id, &r);
    if (status != TZ_OK) {
        return status;
    }
    memset(&h, 0, sizeof(h));
    if (!tz_json_object(&r, heights_member, &h) || r.p != r.end || !h.has_ordered ||
        !h.has_certified) {
        return TZ_ERR_RESPONSE;
    }
    *ordered = h.ordered;
    *certified = h.certified;
    return TZ_OK;
}
