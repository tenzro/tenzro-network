/* The hashes and the signature check the library needs, supplied by the platform. 0 on success. */
#ifndef TENZRO_PORT_HASH_H
#define TENZRO_PORT_HASH_H

#include <stddef.h>
#include <stdint.h>

int tz_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
int tz_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

/* 0 when `signature` (raw r || s) is ECDSA P-256 by `public_key` (0x04 || x || y) over `digest`. */
int tz_p256_verify(const uint8_t public_key[65], const uint8_t digest[32],
                   const uint8_t signature[64]);

#endif
