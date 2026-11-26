/* Hashes and the P-256 check through the PSA Crypto API (Mbed TLS, as shipped with ESP-IDF). */
#include "tz_hash.h"

#include "psa/crypto.h"

static int hash(psa_algorithm_t alg, const uint8_t *data, size_t len,
                uint8_t *out, size_t out_len)
{
    size_t written = 0;
    if (psa_crypto_init() != PSA_SUCCESS) {
        return -1;
    }
    if (psa_hash_compute(alg, data, len, out, out_len, &written) != PSA_SUCCESS) {
        return -1;
    }
    return written == out_len ? 0 : -1;
}

int tz_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    return hash(PSA_ALG_SHA_256, data, len, out, 32);
}

int tz_sha512(const uint8_t *data, size_t len, uint8_t out[64])
{
    return hash(PSA_ALG_SHA_512, data, len, out, 64);
}

int tz_p256_verify(const uint8_t public_key[65], const uint8_t digest[32],
                   const uint8_t signature[64])
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    psa_status_t status;

    if (psa_crypto_init() != PSA_SUCCESS) {
        return -1;
    }
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (psa_import_key(&attributes, public_key, 65, &key) != PSA_SUCCESS) {
        return -1;
    }
    status = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest, 32, signature, 64);
    psa_destroy_key(key);
    return status == PSA_SUCCESS ? 0 : -1;
}
