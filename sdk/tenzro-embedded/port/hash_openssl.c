/* Hashes and the P-256 check through OpenSSL, for the host tests. */
#include "tz_hash.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/sha.h>

int tz_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    return SHA256(data, len, out) != NULL ? 0 : -1;
}

int tz_sha512(const uint8_t *data, size_t len, uint8_t out[64])
{
    return SHA512(data, len, out) != NULL ? 0 : -1;
}

int tz_p256_verify(const uint8_t public_key[65], const uint8_t digest[32],
                   const uint8_t signature[64])
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    ECDSA_SIG *sig = NULL;
    unsigned char *der = NULL;
    int der_len, ok = 0;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL ||
        !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) ||
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, public_key, 65) ||
        (params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
        (ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL ||
        EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        goto done;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    sig = ECDSA_SIG_new();
    if (sig == NULL ||
        !ECDSA_SIG_set0(sig, BN_bin2bn(signature, 32, NULL), BN_bin2bn(signature + 32, 32, NULL)) ||
        (der_len = i2d_ECDSA_SIG(sig, &der)) <= 0 ||
        (ctx = EVP_PKEY_CTX_new(key, NULL)) == NULL || EVP_PKEY_verify_init(ctx) <= 0) {
        goto done;
    }
    ok = EVP_PKEY_verify(ctx, der, (size_t)der_len, digest, 32) == 1;
done:
    OPENSSL_free(der);
    ECDSA_SIG_free(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ok ? 0 : -1;
}
