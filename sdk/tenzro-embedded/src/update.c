#include "tenzro/update.h"

#include <string.h>

#include "tz_hash.h"
#include "tz_json.h"

/* What the release key signs a targets document under (the channel's domain). */
static const char TARGETS_DOMAIN[] = "tenzro-update/1\ntargets\n";
static const char SPEC[] = "tenzro-update/1";

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

/* Lower-case hex of exactly `n` bytes. */
static int lower_hex(const char *s, size_t len, uint8_t *out, size_t n)
{
    size_t i;

    if (len != 2 * n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        int hi = hex_value(s[2 * i]), lo = hex_value(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 1;
}

static int base64_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

/* Standard base64 with padding, canonical; the decoded length in `out_len`. */
static int base64_decode(const char *s, size_t len, uint8_t *out, size_t capacity, size_t *out_len)
{
    size_t i, n = 0;

    if (len == 0 || len % 4 != 0) {
        return 0;
    }
    for (i = 0; i < len; i += 4) {
        int v[4], k, pad = 0;
        uint32_t word = 0;
        for (k = 0; k < 4; k++) {
            if (s[i + k] == '=' && i + 4 == len && k >= 2) {
                v[k] = 0;
                pad++;
            } else if (pad != 0 || (v[k] = base64_value(s[i + k])) < 0) {
                return 0;
            }
            word = word << 6 | (uint32_t)v[k];
        }
        /* Bits the padding drops must be zero: one encoding per document. */
        if ((pad == 1 && (word & 0xff) != 0) || (pad == 2 && (word & 0xffff) != 0)) {
            return 0;
        }
        if (capacity - n < (size_t)(3 - pad)) {
            return 0;
        }
        out[n++] = (uint8_t)(word >> 16);
        if (pad < 2) {
            out[n++] = (uint8_t)(word >> 8);
        }
        if (pad < 1) {
            out[n++] = (uint8_t)word;
        }
    }
    *out_len = n;
    return 1;
}

/* r || s of a DER `SEQUENCE { INTEGER r, INTEGER s }` for P-256. */
static int der_to_raw(const uint8_t *der, size_t len, uint8_t raw[64])
{
    size_t at = 2, part;

    if (len < 8 || der[0] != 0x30 || (size_t)der[1] != len - 2) {
        return 0;
    }
    for (part = 0; part < 2; part++) {
        size_t n;
        const uint8_t *v;
        if (at + 2 > len || der[at] != 0x02) {
            return 0;
        }
        n = der[at + 1];
        v = der + at + 2;
        if (n == 0 || at + 2 + n > len) {
            return 0;
        }
        /* Minimal encoding, positive: a leading zero only before a high bit. */
        if ((v[0] & 0x80) != 0 || (n > 1 && v[0] == 0 && (v[1] & 0x80) == 0)) {
            return 0;
        }
        if (v[0] == 0 && n > 1) {
            v++;
            n--;
        }
        if (n > 32) {
            return 0;
        }
        memset(raw + 32 * part, 0, 32 - n);
        memcpy(raw + 32 * part + 32 - n, v, n);
        at += 2 + der[at + 1];
    }
    return at == len;
}

/* ---- The envelope: {"payload": base64, "signatures": [{"keyid", "sig"}]} ---- */

struct envelope {
    const char *payload;
    size_t payload_len;
    const char *signatures;
    size_t signatures_len;
    int bad;
};

static int envelope_member(void *ctx, const char *key, size_t key_len, const char *value,
                           size_t value_len)
{
    struct envelope *e = ctx;
    const char **slot;
    size_t *len;

    if (tz_json_key_is(key, key_len, "payload")) {
        slot = &e->payload;
        len = &e->payload_len;
    } else if (tz_json_key_is(key, key_len, "signatures")) {
        slot = &e->signatures;
        len = &e->signatures_len;
    } else {
        return 0; /* the channel's envelope has no other member */
    }
    if (*slot != NULL) {
        return 0;
    }
    *slot = value;
    *len = value_len;
    return 1;
}

struct signature {
    const char *keyid, *sig;
    size_t keyid_len, sig_len;
};

static int signature_member(void *ctx, const char *key, size_t key_len, const char *value,
                            size_t value_len)
{
    struct signature *s = ctx;
    struct tz_json r;
    const char **slot;
    size_t *len;

    if (tz_json_key_is(key, key_len, "keyid")) {
        slot = &s->keyid;
        len = &s->keyid_len;
    } else if (tz_json_key_is(key, key_len, "sig")) {
        slot = &s->sig;
        len = &s->sig_len;
    } else {
        return 0;
    }
    r.p = value;
    r.end = value + value_len;
    return *slot == NULL && tz_json_string(&r, slot, len) && r.p == r.end;
}

/*
 * Whether one of `signatures` is the release key's over `digest`: an entry
 * naming the key's id with a signature that verifies. Entries for other keys
 * are passed over; a malformed entry fails the envelope.
 */
static tz_status release_signed(const char *signatures, size_t len, const uint8_t release_key[65],
                                const uint8_t digest[32])
{
    struct tz_json r;
    uint8_t keyid[32], named[32];
    int signed_by_release = 0;

    if (tz_sha256(release_key, 65, keyid) != 0) {
        return TZ_ERR_HASH;
    }
    r.p = signatures;
    r.end = signatures + len;
    if (!tz_json_take(&r, '[')) {
        return TZ_ERR_RESPONSE;
    }
    if (tz_json_take(&r, ']')) {
        return TZ_ERR_SIGNATURE;
    }
    do {
        struct signature s;
        uint8_t sig[72], raw[64];
        size_t sig_len = 0;

        memset(&s, 0, sizeof(s));
        if (!tz_json_object(&r, signature_member, &s) || s.keyid == NULL || s.sig == NULL ||
            !lower_hex(s.keyid, s.keyid_len, named, 32)) {
            return TZ_ERR_RESPONSE;
        }
        if (memcmp(named, keyid, 32) != 0) {
            continue;
        }
        if (s.sig_len == 128) {
            if (!lower_hex(s.sig, s.sig_len, raw, 64)) {
                return TZ_ERR_RESPONSE;
            }
        } else {
            sig_len = s.sig_len / 2;
            if (s.sig_len % 2 != 0 || sig_len > sizeof(sig) ||
                !lower_hex(s.sig, s.sig_len, sig, sig_len) || !der_to_raw(sig, sig_len, raw)) {
                return TZ_ERR_RESPONSE;
            }
        }
        if (tz_p256_verify(release_key, digest, raw) == 0) {
            signed_by_release = 1;
        }
    } while (tz_json_take(&r, ','));
    if (!tz_json_take(&r, ']') || (tz_json_space(&r), r.p != r.end)) {
        return TZ_ERR_RESPONSE;
    }
    return signed_by_release ? TZ_OK : TZ_ERR_SIGNATURE;
}

/* ---- The targets document ---- */

struct entry {
    const char *platform, *name, *path, *sha256;
    size_t platform_len, name_len, path_len, sha256_len;
    uint64_t length;
    int has_length;
};

/* A string member's bytes: plain text, no escapes. */
static int plain_string(const char *value, size_t value_len, const char **out, size_t *out_len)
{
    struct tz_json r;
    size_t i;

    r.p = value;
    r.end = value + value_len;
    if (!tz_json_string(&r, out, out_len) || r.p != r.end) {
        return 0;
    }
    for (i = 0; i < *out_len; i++) {
        if ((*out)[i] == '\\') {
            return 0;
        }
    }
    return 1;
}

static int entry_member(void *ctx, const char *key, size_t key_len, const char *value,
                        size_t value_len)
{
    struct entry *e = ctx;

    if (tz_json_key_is(key, key_len, "platform")) {
        return e->platform == NULL && plain_string(value, value_len, &e->platform, &e->platform_len);
    }
    if (tz_json_key_is(key, key_len, "name")) {
        return e->name == NULL && plain_string(value, value_len, &e->name, &e->name_len);
    }
    if (tz_json_key_is(key, key_len, "path")) {
        return e->path == NULL && plain_string(value, value_len, &e->path, &e->path_len);
    }
    if (tz_json_key_is(key, key_len, "sha256")) {
        return e->sha256 == NULL && plain_string(value, value_len, &e->sha256, &e->sha256_len);
    }
    if (tz_json_key_is(key, key_len, "length")) {
        if (e->has_length || !tz_json_u64(value, value_len, &e->length)) {
            return 0;
        }
        e->has_length = 1;
        return 1;
    }
    return 0; /* a file entry has no other member */
}

/* A path under the channel: relative, `/`-separated, no climbing. */
static int path_ok(const char *p, size_t n)
{
    size_t i, seg = 0;

    if (n == 0 || n > TZ_UPDATE_PATH_MAX || p[0] == '/') {
        return 0;
    }
    for (i = 0; i <= n; i++) {
        if (i == n || p[i] == '/') {
            if (seg == 0 || (seg == 1 && p[i - 1] == '.') ||
                (seg == 2 && p[i - 1] == '.' && p[i - 2] == '.')) {
                return 0;
            }
            seg = 0;
            continue;
        }
        if (!((p[i] >= 'a' && p[i] <= 'z') || (p[i] >= 'A' && p[i] <= 'Z') ||
              (p[i] >= '0' && p[i] <= '9') || p[i] == '.' || p[i] == '_' || p[i] == '-')) {
            return 0;
        }
        seg++;
    }
    return 1;
}

struct targets {
    const char *platform;
    tz_update_target *target;
    int has_type, has_spec, has_version, has_release, has_class, has_description, has_files;
    int found, bad_entry;
};

static int files_value(struct targets *t, const char *value, size_t value_len)
{
    struct tz_json r;

    r.p = value;
    r.end = value + value_len;
    if (!tz_json_take(&r, '[')) {
        return 0;
    }
    if (tz_json_take(&r, ']')) {
        return r.p == r.end;
    }
    do {
        struct entry e;
        uint8_t digest[32];

        memset(&e, 0, sizeof(e));
        if (!tz_json_object(&r, entry_member, &e) || e.platform == NULL || e.name == NULL ||
            e.path == NULL || e.sha256 == NULL || !e.has_length ||
            !lower_hex(e.sha256, e.sha256_len, digest, 32) || !path_ok(e.path, e.path_len)) {
            return 0;
        }
        if (e.platform_len == strlen(t->platform) &&
            memcmp(e.platform, t->platform, e.platform_len) == 0 &&
            e.name_len == strlen(TZ_FIRMWARE_NAME) &&
            memcmp(e.name, TZ_FIRMWARE_NAME, e.name_len) == 0) {
            if (t->found) {
                return 0; /* two images for one platform */
            }
            t->found = 1;
            memcpy(t->target->path, e.path, e.path_len);
            t->target->path[e.path_len] = '\0';
            memcpy(t->target->sha256, digest, 32);
            t->target->length = e.length;
        }
    } while (tz_json_take(&r, ','));
    return tz_json_take(&r, ']') && r.p == r.end;
}

static int targets_member(void *ctx, const char *key, size_t key_len, const char *value,
                          size_t value_len)
{
    struct targets *t = ctx;
    const char *s;
    size_t n;

    if (tz_json_key_is(key, key_len, "_type")) {
        if (t->has_type || !plain_string(value, value_len, &s, &n) || n != 7 ||
            memcmp(s, "targets", 7) != 0) {
            return 0;
        }
        t->has_type = 1;
    } else if (tz_json_key_is(key, key_len, "spec")) {
        if (t->has_spec || !plain_string(value, value_len, &s, &n) || n != strlen(SPEC) ||
            memcmp(s, SPEC, n) != 0) {
            return 0;
        }
        t->has_spec = 1;
    } else if (tz_json_key_is(key, key_len, "version")) {
        if (t->has_version || !tz_json_u64(value, value_len, &t->target->version)) {
            return 0;
        }
        t->has_version = 1;
    } else if (tz_json_key_is(key, key_len, "release")) {
        if (t->has_release || !plain_string(value, value_len, &s, &n) || n == 0 ||
            n > TZ_UPDATE_RELEASE_MAX) {
            return 0;
        }
        memcpy(t->target->release, s, n);
        t->target->release[n] = '\0';
        t->has_release = 1;
    } else if (tz_json_key_is(key, key_len, "class")) {
        if (t->has_class || !plain_string(value, value_len, &s, &n)) {
            return 0;
        }
        t->has_class = 1;
    } else if (tz_json_key_is(key, key_len, "description")) {
        struct tz_json r;
        r.p = value;
        r.end = value + value_len;
        if (t->has_description || !tz_json_string(&r, &s, &n) || r.p != r.end) {
            return 0;
        }
        t->has_description = 1;
    } else if (tz_json_key_is(key, key_len, "files")) {
        if (t->has_files || !files_value(t, value, value_len)) {
            return 0;
        }
        t->has_files = 1;
    } else {
        return 0; /* a targets document has no other member */
    }
    return 1;
}

tz_status tz_update_target_of(const char *envelope, size_t envelope_len,
                              const uint8_t release_key[65],
                              const char *platform, uint64_t installed_version,
                              uint8_t *scratch, size_t scratch_len,
                              tz_update_target *target)
{
    const size_t domain_len = sizeof(TARGETS_DOMAIN) - 1;
    struct envelope e;
    struct targets t;
    struct tz_json r;
    const char *payload;
    size_t payload_b64_len, payload_len = 0, platform_len;
    uint8_t digest[32];
    tz_status status;

    if (envelope == NULL || release_key == NULL || release_key[0] != 0x04 || platform == NULL ||
        scratch == NULL || target == NULL || scratch_len <= domain_len) {
        return TZ_ERR_ARGUMENT;
    }
    platform_len = strlen(platform);
    if (platform_len == 0 || platform_len > TZ_UPDATE_PLATFORM_MAX) {
        return TZ_ERR_ARGUMENT;
    }
    memset(&e, 0, sizeof(e));
    r.p = envelope;
    r.end = envelope + envelope_len;
    if (!tz_json_object(&r, envelope_member, &e) || (tz_json_space(&r), r.p != r.end) ||
        e.payload == NULL || e.signatures == NULL) {
        return TZ_ERR_RESPONSE;
    }
    r.p = e.payload;
    r.end = e.payload + e.payload_len;
    if (!tz_json_string(&r, &payload, &payload_b64_len) || r.p != r.end) {
        return TZ_ERR_RESPONSE;
    }
    /* The signed bytes are the domain, then the payload: decoded in place after it. */
    memcpy(scratch, TARGETS_DOMAIN, domain_len);
    if (!base64_decode(payload, payload_b64_len, scratch + domain_len, scratch_len - domain_len,
                       &payload_len)) {
        return TZ_ERR_RESPONSE;
    }
    if (tz_sha256(scratch, domain_len + payload_len, digest) != 0) {
        return TZ_ERR_HASH;
    }
    status = release_signed(e.signatures, e.signatures_len, release_key, digest);
    if (status != TZ_OK) {
        return status;
    }
    /* Signed by the release key: now what it says. */
    memset(target, 0, sizeof(*target));
    memset(&t, 0, sizeof(t));
    t.platform = platform;
    t.target = target;
    r.p = (const char *)scratch + domain_len;
    r.end = r.p + payload_len;
    if (!tz_json_object(&r, targets_member, &t) || (tz_json_space(&r), r.p != r.end) ||
        !t.has_type || !t.has_spec || !t.has_version || !t.has_release || !t.has_class ||
        !t.has_description || !t.has_files) {
        memset(target, 0, sizeof(*target));
        return TZ_ERR_RESPONSE;
    }
    if (target->version <= installed_version) {
        memset(target, 0, sizeof(*target));
        return TZ_ERR_ROLLBACK;
    }
    if (!t.found) {
        memset(target, 0, sizeof(*target));
        return TZ_ERR_NO_TARGET;
    }
    return TZ_OK;
}
