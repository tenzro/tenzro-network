/*
 * Checks the library against the shared signing vectors: every line of
 * sdk/fixtures/signing/composite.txt must come out byte for byte.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "tenzro/sign.h"
#include "tenzro/update.h"

#define MAX_FIELDS 15
#define MAX_LINE 32768

static size_t unhex(const char *hex, uint8_t *out, size_t capacity)
{
    size_t n = strlen(hex) / 2;
    size_t i;
    if (strlen(hex) % 2 != 0 || n > capacity) {
        fprintf(stderr, "bad hex field\n");
        exit(2);
    }
    for (i = 0; i < n; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            fprintf(stderr, "bad hex field\n");
            exit(2);
        }
        out[i] = (uint8_t)byte;
    }
    return n;
}

/* Splits on '|', keeping empty fields. */
static int split(char *line, char *fields[MAX_FIELDS])
{
    int n = 0;
    char *p = line;
    fields[n++] = p;
    while ((p = strchr(p, '|')) != NULL && n < MAX_FIELDS) {
        *p++ = '\0';
        fields[n++] = p;
    }
    return n;
}

static int check_voucher(char *f[MAX_FIELDS])
{
    uint8_t escrow[32], cumulative[16], binding[32];
    uint8_t want[TZ_ESCROW_VOUCHER_LEN], got[TZ_ESCROW_VOUCHER_LEN];
    uint64_t chain_id = strtoull(f[1], NULL, 10);

    if (unhex(f[2], escrow, sizeof(escrow)) != 32 ||
        unhex(f[3], cumulative, sizeof(cumulative)) != 16 ||
        unhex(f[4], binding, sizeof(binding)) != 32 ||
        unhex(f[5], want, sizeof(want)) != sizeof(want)) {
        return 1;
    }
    tz_escrow_voucher_bytes(chain_id, escrow, cumulative, binding, got);
    return memcmp(want, got, sizeof(want)) != 0;
}

static int check_representative(char *f[MAX_FIELDS])
{
    static uint8_t message[MAX_LINE / 2];
    uint8_t want[TZ_REPRESENTATIVE_MAX], got[TZ_REPRESENTATIVE_MAX];
    uint8_t want_digest[32], got_digest[32];
    size_t message_len = unhex(f[2], message, sizeof(message));
    size_t want_len = unhex(f[3], want, sizeof(want));
    size_t got_len = 0;

    if (unhex(f[4], want_digest, sizeof(want_digest)) != 32) {
        return 1;
    }
    if (tz_message_representative(f[1], message, message_len, got, sizeof(got),
                                  &got_len) != TZ_OK ||
        got_len != want_len || memcmp(want, got, want_len) != 0) {
        return 1;
    }
    if (tz_signing_digest(f[1], message, message_len, got_digest) != TZ_OK) {
        return 1;
    }
    return memcmp(want_digest, got_digest, 32) != 0;
}

static int check_reading(char *f[MAX_FIELDS])
{
    uint8_t payload[32], want[32], got[32];
    uint64_t measured_at_ms = strtoull(f[3], NULL, 10);

    if (unhex(f[2], payload, sizeof(payload)) != 32 ||
        unhex(f[4], want, sizeof(want)) != 32) {
        return 1;
    }
    if (tz_sensor_reading_digest(f[1], payload, measured_at_ms, got) != TZ_OK) {
        return 1;
    }
    return memcmp(want, got, 32) != 0;
}

static int check_evidence(char *f[MAX_FIELDS])
{
    static uint8_t ml_dsa[TZ_MLDSA65_SIGNATURE_LEN];
    static char got[TZ_READING_EVIDENCE_MAX_HYBRID];
    uint8_t payload[32], p256[64];
    uint64_t measured_at_ms = strtoull(f[3], NULL, 10);
    size_t ml_dsa_len = unhex(f[5], ml_dsa, sizeof(ml_dsa));
    size_t got_len = 0;
    size_t capacity = ml_dsa_len != 0 ? TZ_READING_EVIDENCE_MAX_HYBRID : TZ_READING_EVIDENCE_MAX;

    if (unhex(f[2], payload, sizeof(payload)) != 32 ||
        unhex(f[4], p256, sizeof(p256)) != 64) {
        return 1;
    }
    if (tz_sensor_reading_evidence(f[1], payload, measured_at_ms, p256,
                                   ml_dsa_len != 0 ? ml_dsa : NULL, ml_dsa_len,
                                   got, capacity, &got_len) != TZ_OK) {
        return 1;
    }
    if (got_len != strlen(f[6]) || strcmp(got, f[6]) != 0) {
        return 1;
    }
    /* One byte short of the text and its NUL is refused, and nothing longer is written. */
    return tz_sensor_reading_evidence(f[1], payload, measured_at_ms, p256,
                                      ml_dsa_len != 0 ? ml_dsa : NULL, ml_dsa_len,
                                      got, got_len, &got_len) != TZ_ERR_SPACE;
}

static int check_transaction(char *f[MAX_FIELDS])
{
    tz_tx_header h;
    uint8_t amount[16], want[32], got[32];
    char type[TZ_TRANSFER_TYPE_MAX];
    size_t type_len = 0;

    h.chain_id = strtoull(f[1], NULL, 10);
    h.nonce = strtoull(f[4], NULL, 10);
    h.gas_limit = strtoull(f[5], NULL, 10);
    h.gas_price = strtoull(f[6], NULL, 10);
    h.timestamp_ms = strtoll(f[7], NULL, 10);
    h.valid_until_ms = strtoll(f[8], NULL, 10);
    if (unhex(f[2], h.from, 32) != 32 || unhex(f[3], h.to, 32) != 32 ||
        unhex(f[9], amount, 16) != 16 || unhex(f[12], want, 32) != 32) {
        return 1;
    }
    /* The type the library writes is the ledger's, byte for byte. */
    if (tz_transfer_type(amount, type, sizeof(type), &type_len) != TZ_OK ||
        type_len != strlen(f[11]) || strcmp(type, f[11]) != 0) {
        return 1;
    }
    if (tz_transaction_hash(&h, type, type_len, f[10][0] != '\0' ? f[10] : NULL, got) != TZ_OK) {
        return 1;
    }
    return memcmp(want, got, 32) != 0;
}

static int check_request(char *f[MAX_FIELDS])
{
    static uint8_t ml_dsa[TZ_MLDSA65_SIGNATURE_LEN];
    static char got[TZ_TRANSFER_REQUEST_MAX_HYBRID];
    tz_tx_header h;
    uint8_t amount[16], public_key[64], p256[64];
    uint64_t id = strtoull(f[1], NULL, 10);
    size_t ml_dsa_len = unhex(f[13], ml_dsa, sizeof(ml_dsa));
    size_t got_len = 0;
    size_t capacity = ml_dsa_len != 0 ? TZ_TRANSFER_REQUEST_MAX_HYBRID : TZ_TRANSFER_REQUEST_MAX;

    h.chain_id = strtoull(f[2], NULL, 10);
    h.nonce = strtoull(f[5], NULL, 10);
    h.gas_limit = strtoull(f[6], NULL, 10);
    h.gas_price = strtoull(f[7], NULL, 10);
    h.timestamp_ms = strtoll(f[8], NULL, 10);
    h.valid_until_ms = strtoll(f[9], NULL, 10);
    if (unhex(f[3], h.from, 32) != 32 || unhex(f[4], h.to, 32) != 32 ||
        unhex(f[10], amount, 16) != 16 || unhex(f[11], public_key, 64) != 64 ||
        unhex(f[12], p256, 64) != 64) {
        return 1;
    }
    if (tz_transfer_request(id, &h, amount, public_key, p256,
                            ml_dsa_len != 0 ? ml_dsa : NULL, ml_dsa_len,
                            got, capacity, &got_len) != TZ_OK ||
        got_len != strlen(f[14]) || strcmp(got, f[14]) != 0) {
        return 1;
    }
    /* A buffer without room for the NUL is refused. */
    if (tz_transfer_request(id, &h, amount, public_key, p256,
                            ml_dsa_len != 0 ? ml_dsa : NULL, ml_dsa_len,
                            got, got_len, &got_len) != TZ_ERR_SPACE) {
        return 1;
    }
    /* A time before 1970 cannot be submitted. */
    h.timestamp_ms = -1;
    return tz_transfer_request(id, &h, amount, public_key, p256, NULL, 0, got,
                               capacity, &got_len) != TZ_ERR_ARGUMENT;
}

static int check_account(char *f[MAX_FIELDS])
{
    uint8_t public_key[64], want[32], got[32];

    if (unhex(f[1], public_key, 64) != 64 || unhex(f[2], want, 32) != 32) {
        return 1;
    }
    return tz_account_slot(public_key, got) != TZ_OK || memcmp(got, want, 32) != 0;
}

static int check_enrolment(char *f[MAX_FIELDS])
{
    char got[TZ_ENROLMENT_COMMAND_MAX];
    uint8_t public_key[64];
    size_t len = 0;

    if (unhex(f[4], public_key, 64) != 64 ||
        tz_enrolment_command(f[1], f[2], f[3], public_key, got, sizeof(got), &len) != TZ_OK ||
        len != strlen(f[5]) || strcmp(got, f[5]) != 0) {
        return 1;
    }
    /* A field a shell would split or expand is refused. */
    return tz_enrolment_command("a b", f[2], f[3], public_key, got, sizeof(got), &len) != TZ_ERR_ARGUMENT ||
           tz_enrolment_command(f[1], "did:$(x)", f[3], public_key, got, sizeof(got), &len) != TZ_ERR_ARGUMENT ||
           tz_enrolment_command(f[1], f[2], "a;b", public_key, got, sizeof(got), &len) != TZ_ERR_ARGUMENT ||
           tz_enrolment_command(f[1], f[2], "", public_key, got, sizeof(got), &len) != TZ_ERR_ARGUMENT ||
           tz_enrolment_command(f[1], f[2], f[3], public_key, got, len, &len) != TZ_ERR_SPACE;
}

/* The requests a device reads its account and finality with, and the node's answers as the node writes them. */
static int check_reads(void)
{
    static const uint8_t slot[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                     0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0xff};
    char out[TZ_READ_REQUEST_MAX];
    uint8_t value[16], want[16];
    uint64_t ordered = 0, certified = 0;
    size_t len = 0;
    static const char *bad[] = {
        "{\"jsonrpc\":\"2.0\",\"id\":8,\"result\":\"0x1\"}",              /* another request's answer */
        "{\"jsonrpc\":\"2.0\",\"id\":7}",                                  /* no result */
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x\"}",                /* no digits */
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"12\"}",                /* not hex */
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x1g\"}",              /* not hex */
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x100000000000000000000000000000000\"}", /* 129 bits */
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x1\",\"result\":\"0x2\"}", /* a member twice */
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x1\"} x",            /* trailing bytes */
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x1\"",               /* cut short */
        "{\"jsonrpc\":\"2.0\",\"id\":\"7\",\"result\":\"0x1\"}",            /* the id as a string */
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":7}",                      /* a number */
    };
    const char *ok;
    size_t i;

    if (tz_read_request(7, TZ_READ_BALANCE, slot, out, sizeof(out), &len) != TZ_OK ||
        strcmp(out, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tenzro_getBalance\","
                    "\"params\":[\"0x0102030405060708090a0b0c0d0e0f10111213ff\"]}") != 0 ||
        len != strlen(out)) {
        return 1;
    }
    if (tz_read_request(8, TZ_READ_NONCE, slot, out, sizeof(out), &len) != TZ_OK ||
        strstr(out, "\"method\":\"tenzro_getNonce\"") == NULL ||
        tz_read_request(9, TZ_READ_FINALITY, NULL, out, sizeof(out), &len) != TZ_OK ||
        strcmp(out, "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tenzro_getFinality\",\"params\":[]}") != 0 ||
        tz_read_request(9, TZ_READ_FINALITY, slot, out, sizeof(out), &len) != TZ_ERR_ARGUMENT ||
        tz_read_request(9, TZ_READ_BALANCE, NULL, out, sizeof(out), &len) != TZ_ERR_ARGUMENT ||
        tz_read_request(7, TZ_READ_BALANCE, slot, out, 20, &len) != TZ_ERR_SPACE) {
        return 1;
    }
    /* A balance as the node writes it (format!("0x{:x}", u128)): u128::MAX. */
    ok = " { \"jsonrpc\" : \"2.0\", \"result\" : \"0xffffffffffffffffffffffffffffffff\", \"id\" : 7 }\n";
    memset(want, 0xff, 16);
    if (tz_read_quantity(ok, strlen(ok), 7, value) != TZ_OK || memcmp(value, want, 16) != 0) {
        return 1;
    }
    ok = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x1A2\"}";
    memset(want, 0, 16);
    want[0] = 0xa2;
    want[1] = 0x01;
    if (tz_read_quantity(ok, strlen(ok), 7, value) != TZ_OK || memcmp(value, want, 16) != 0) {
        return 1;
    }
    ok = "{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32602,\"message\":\"Invalid address: \\\"x\\\"\"}}";
    if (tz_read_quantity(ok, strlen(ok), 7, value) != TZ_ERR_REFUSED) {
        return 1;
    }
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (tz_read_quantity(bad[i], strlen(bad[i]), 7, value) != TZ_ERR_RESPONSE) {
            fprintf(stderr, "reply %u was read\n", (unsigned)i);
            return 1;
        }
    }
    /* Finality as the node writes it: the heights, then the certificate. */
    ok = "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ordered\":18446744073709551615,\"certified\":120,"
         "\"certificate\":{\"epoch\":3,\"index\":40,\"first_height\":100,\"last_height\":120,"
         "\"state_height\":120,\"state_root\":\"0xab\",\"signers\":4}}}";
    if (tz_read_finality(ok, strlen(ok), 9, &ordered, &certified) != TZ_OK ||
        ordered != UINT64_MAX || certified != 120) {
        return 1;
    }
    ok = "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ordered\":5,\"certified\":0,\"certificate\":null}}";
    if (tz_read_finality(ok, strlen(ok), 9, &ordered, &certified) != TZ_OK || ordered != 5 || certified != 0) {
        return 1;
    }
    {
        static const char *bad_finality[] = {
            "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ordered\":5}}",
            "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ordered\":5,\"certified\":-1}}",
            "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ordered\":5,\"certified\":18446744073709551616}}",
            "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ordered\":05,\"certified\":1}}",
            "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ordered\":5,\"certified\":1,\"x\":[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]}}",
        };
        for (i = 0; i < sizeof(bad_finality) / sizeof(bad_finality[0]); i++) {
            if (tz_read_finality(bad_finality[i], strlen(bad_finality[i]), 9, &ordered, &certified) != TZ_ERR_RESPONSE) {
                fprintf(stderr, "finality reply %u was read\n", (unsigned)i);
                return 1;
            }
        }
    }
    return 0;
}

static tz_status status_named(const char *name)
{
    if (strcmp(name, "ok") == 0) {
        return TZ_OK;
    }
    if (strcmp(name, "rollback") == 0) {
        return TZ_ERR_ROLLBACK;
    }
    if (strcmp(name, "no_target") == 0) {
        return TZ_ERR_NO_TARGET;
    }
    if (strcmp(name, "signature") == 0) {
        return TZ_ERR_SIGNATURE;
    }
    return TZ_ERR_RESPONSE;
}

/*
 * Whether byte `at` of an envelope lies in the signature of an entry the release key did not
 * make: the verifier skips such an entry, so changing it must not change the answer.
 */
static int in_other_signature(const char *env, size_t at, const char *release_keyid)
{
    const char *sig = NULL, *p;

    for (p = env; (p = strstr(p, "\"sig\":\"")) != NULL && (size_t)(p - env) < at; p += 7) {
        sig = p + 7;
    }
    if (sig == NULL || at < (size_t)(sig - env) || strchr(sig, '"') == NULL ||
        at >= (size_t)(strchr(sig, '"') - env)) {
        return 0;
    }
    /* The entry's keyid sits before its sig. */
    for (p = sig; p > env && strncmp(p, "\"keyid\":\"", 9) != 0; p--) {
    }
    return strncmp(p + 9, release_keyid, 64) != 0;
}

static int check_update(char *f[MAX_FIELDS])
{
    static uint8_t scratch[TZ_UPDATE_SCRATCH_MAX];
    tz_update_target t;
    uint8_t release_key[65], sha[32];
    uint64_t installed = strtoull(f[3], NULL, 10);
    tz_status want = status_named(f[5]), got;
    size_t len = strlen(f[4]);

    if (unhex(f[1], release_key, 65) != 65) {
        return 1;
    }
    got = tz_update_target_of(f[4], len, release_key, f[2], installed, scratch, sizeof(scratch), &t);
    if (got != want) {
        fprintf(stderr, "update: %d, wanted %d\n", (int)got, (int)want);
        return 1;
    }
    if (want != TZ_OK) {
        return 0;
    }
    if (unhex(f[10], sha, 32) != 32 || t.version != strtoull(f[6], NULL, 10) ||
        strcmp(t.release, f[7]) != 0 || strcmp(t.path, f[8]) != 0 ||
        t.length != strtoull(f[9], NULL, 10) || memcmp(t.sha256, sha, 32) != 0) {
        return 1;
    }
    /* Any byte of the envelope changed, the release key's signature fails or the envelope no longer reads. */
    {
        size_t i;
        uint8_t digest[32];
        char keyid[65];
        for (i = 0; i < 32; i++) {
            snprintf(keyid + 2 * i, 3, "%02x", SHA256(release_key, 65, digest)[i]);
        }
        for (i = 0; i < len; i += 7) {
            char saved = f[4][i];
            if (in_other_signature(f[4], i, keyid)) {
                continue;
            }
            f[4][i] = (char)(saved == 'A' ? 'B' : 'A');
            got = tz_update_target_of(f[4], len, release_key, f[2], installed, scratch, sizeof(scratch), &t);
            f[4][i] = saved;
            if (got == TZ_OK) {
                fprintf(stderr, "update: a changed byte %u was taken\n", (unsigned)i);
                return 1;
            }
        }
    }
    /* Too little scratch for the document is refused, not overrun. */
    return tz_update_target_of(f[4], len, release_key, f[2], installed, scratch, 64, &t) != TZ_ERR_RESPONSE;
}

static int check_refusals(void)
{
    uint8_t out[TZ_REPRESENTATIVE_MAX];
    uint8_t digest[32] = {0};
    size_t len = 0;
    char long_context[257];
    char long_did[TZ_DEVICE_DID_MAX + 2];

    memset(long_context, 'a', 256);
    long_context[256] = '\0';
    memset(long_did, 'd', TZ_DEVICE_DID_MAX + 1);
    long_did[TZ_DEVICE_DID_MAX + 1] = '\0';
    if (tz_sensor_reading_digest("", digest, 0, digest) != TZ_ERR_ARGUMENT ||
        tz_sensor_reading_digest(long_did, digest, 0, digest) != TZ_ERR_ARGUMENT ||
        tz_sensor_reading_digest(NULL, digest, 0, digest) != TZ_ERR_ARGUMENT) {
        return 1;
    }
    {
        char text[TZ_READING_EVIDENCE_MAX];
        uint8_t signature[64] = {0};
        if (tz_sensor_reading_evidence("did:\"x", digest, 0, signature, NULL, 0, text, sizeof(text), &len) != TZ_ERR_ARGUMENT ||
            tz_sensor_reading_evidence("did:\\x", digest, 0, signature, NULL, 0, text, sizeof(text), &len) != TZ_ERR_ARGUMENT ||
            tz_sensor_reading_evidence("did:\nx", digest, 0, signature, NULL, 0, text, sizeof(text), &len) != TZ_ERR_ARGUMENT ||
            tz_sensor_reading_evidence("did:x", digest, 0, signature, digest, 0, text, sizeof(text), &len) != TZ_ERR_ARGUMENT ||
            tz_sensor_reading_evidence(long_did, digest, 0, signature, NULL, 0, text, sizeof(text), &len) != TZ_ERR_ARGUMENT) {
            return 1;
        }
    }
    return tz_message_representative("", NULL, 0, out, sizeof(out), &len) != TZ_ERR_ARGUMENT ||
           tz_message_representative(long_context, NULL, 0, out, sizeof(out), &len) != TZ_ERR_ARGUMENT ||
           tz_message_representative(TZ_CONTEXT_TRANSACTION, NULL, 1, out, sizeof(out), &len) != TZ_ERR_ARGUMENT ||
           tz_message_representative(TZ_CONTEXT_TRANSACTION, NULL, 0, out, 16, &len) != TZ_ERR_SPACE;
}

int main(int argc, char **argv)
{
    char line[MAX_LINE];
    int checked = 0, failed = 0;
    FILE *in;

    if (argc != 2 || (in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "usage: vectors <composite.txt>\n");
        return 2;
    }
    while (fgets(line, sizeof(line), in) != NULL) {
        char *fields[MAX_FIELDS];
        int n, bad;

        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        n = split(line, fields);
        if (n == 6 && strcmp(fields[0], "voucher") == 0) {
            bad = check_voucher(fields);
        } else if (n == 5 && strcmp(fields[0], "reading") == 0) {
            bad = check_reading(fields);
        } else if (n == 15 && strcmp(fields[0], "request") == 0) {
            bad = check_request(fields);
        } else if (n == 13 && strcmp(fields[0], "transaction") == 0) {
            bad = check_transaction(fields);
        } else if (n == 7 && strcmp(fields[0], "evidence") == 0) {
            bad = check_evidence(fields);
        } else if (n == 5 && strcmp(fields[0], "representative") == 0) {
            bad = check_representative(fields);
        } else if (n == 3 && strcmp(fields[0], "account") == 0) {
            bad = check_account(fields);
        } else if (n == 6 && strcmp(fields[0], "enrolment") == 0) {
            bad = check_enrolment(fields);
        } else if (n == 11 && strcmp(fields[0], "update") == 0) {
            bad = check_update(fields);
        } else {
            fprintf(stderr, "unknown vector line: %s\n", fields[0]);
            fclose(in);
            return 2;
        }
        checked++;
        if (bad) {
            failed++;
            fprintf(stderr, "vector %d (%s) differs\n", checked, fields[0]);
        }
    }
    fclose(in);
    if (check_reads()) {
        failed++;
        fprintf(stderr, "a read request or a node's answer came out wrong\n");
    }
    if (check_refusals()) {
        failed++;
        fprintf(stderr, "a malformed call was not refused\n");
    }
    printf("%d vectors checked, %d failed\n", checked, failed);
    return checked == 0 || failed != 0;
}
