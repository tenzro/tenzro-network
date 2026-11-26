/*
 * A small JSON scanner over bytes received: it checks structure and finds
 * members, decodes nothing it is not asked for, and refuses nesting deeper
 * than TZ_JSON_DEPTH_MAX.
 */
#include "tz_json.h"

#include <string.h>

void tz_json_space(struct tz_json *r)
{
    while (r->p < r->end &&
           (*r->p == ' ' || *r->p == '\t' || *r->p == '\n' || *r->p == '\r')) {
        r->p++;
    }
}

int tz_json_take(struct tz_json *r, char c)
{
    tz_json_space(r);
    if (r->p < r->end && *r->p == c) {
        r->p++;
        return 1;
    }
    return 0;
}

/* A string: its bytes between the quotes, escapes left as they are. */
int tz_json_string(struct tz_json *r, const char **start, size_t *len)
{
    tz_json_space(r);
    if (r->p >= r->end || *r->p != '"') {
        return 0;
    }
    *start = ++r->p;
    while (r->p < r->end && *r->p != '"') {
        if ((unsigned char)*r->p < 0x20) {
            return 0;
        }
        if (*r->p == '\\' && ++r->p >= r->end) {
            return 0;
        }
        r->p++;
    }
    if (r->p >= r->end) {
        return 0;
    }
    *len = (size_t)(r->p - *start);
    r->p++;
    return 1;
}

int tz_json_value(struct tz_json *r, int depth)
{
    const char *s;
    size_t n;

    tz_json_space(r);
    if (r->p >= r->end || depth > TZ_JSON_DEPTH_MAX) {
        return 0;
    }
    switch (*r->p) {
    case '"':
        return tz_json_string(r, &s, &n);
    case '{':
        r->p++;
        if (tz_json_take(r, '}')) {
            return 1;
        }
        do {
            if (!tz_json_string(r, &s, &n) || !tz_json_take(r, ':') || !tz_json_value(r, depth + 1)) {
                return 0;
            }
        } while (tz_json_take(r, ','));
        return tz_json_take(r, '}');
    case '[':
        r->p++;
        if (tz_json_take(r, ']')) {
            return 1;
        }
        do {
            if (!tz_json_value(r, depth + 1)) {
                return 0;
            }
        } while (tz_json_take(r, ','));
        return tz_json_take(r, ']');
    default:
        s = r->p;
        while (r->p < r->end &&
               ((*r->p >= '0' && *r->p <= '9') || (*r->p >= 'a' && *r->p <= 'z') ||
                *r->p == '-' || *r->p == '+' || *r->p == '.' || *r->p == 'E')) {
            r->p++;
        }
        return r->p > s;
    }
}

/* A non-negative decimal of at most 64 bits, exactly the bytes [s, s + n). */
int tz_json_u64(const char *s, size_t n, uint64_t *value)
{
    uint64_t v = 0;
    size_t i;

    if (n == 0 || n > 20 || (n > 1 && s[0] == '0')) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        unsigned d;
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
        d = (unsigned)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10) {
            return 0;
        }
        v = v * 10 + d;
    }
    *value = v;
    return 1;
}

/* Calls `member` for each member of the object at `r`, with its key and value span. */
int tz_json_object(struct tz_json *r,
                   int (*member)(void *ctx, const char *key, size_t key_len,
                                 const char *value, size_t value_len),
                   void *ctx)
{
    if (!tz_json_take(r, '{')) {
        return 0;
    }
    if (tz_json_take(r, '}')) {
        return 1;
    }
    do {
        const char *key, *value;
        size_t key_len;

        if (!tz_json_string(r, &key, &key_len) || !tz_json_take(r, ':')) {
            return 0;
        }
        tz_json_space(r);
        value = r->p;
        if (!tz_json_value(r, 1) || !member(ctx, key, key_len, value, (size_t)(r->p - value))) {
            return 0;
        }
    } while (tz_json_take(r, ','));
    return tz_json_take(r, '}');
}

int tz_json_key_is(const char *key, size_t key_len, const char *name)
{
    return key_len == strlen(name) && memcmp(key, name, key_len) == 0;
}
