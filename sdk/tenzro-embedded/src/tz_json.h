/* The library's JSON scanner (internal). */
#ifndef TENZRO_JSON_H
#define TENZRO_JSON_H

#include <stddef.h>
#include <stdint.h>

/* Bytes still to read: [p, end). */
struct tz_json {
    const char *p;
    const char *end;
};

/* Deepest nesting a scanned value may have. */
#define TZ_JSON_DEPTH_MAX 16

void tz_json_space(struct tz_json *r);
/* Takes `c` after any white space; 1 when it was there. */
int tz_json_take(struct tz_json *r, char c);
/* A string: its bytes between the quotes, escapes left as they are. */
int tz_json_string(struct tz_json *r, const char **start, size_t *len);
/* Skips one value of nesting at most TZ_JSON_DEPTH_MAX - depth. */
int tz_json_value(struct tz_json *r, int depth);
/* A non-negative decimal of at most 64 bits, exactly the bytes [s, s + n). */
int tz_json_u64(const char *s, size_t n, uint64_t *value);
/* Calls `member` for each member of the object at `r`, with its key and value span. */
int tz_json_object(struct tz_json *r,
                   int (*member)(void *ctx, const char *key, size_t key_len,
                                 const char *value, size_t value_len),
                   void *ctx);
int tz_json_key_is(const char *key, size_t key_len, const char *name);

#endif
