# ESP-IDF component: the library with hashes and the P-256 check from the PSA Crypto API.
idf_component_register(
    SRCS "src/sign.c" "src/update.c" "src/tz_json.c" "port/hash_psa.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "port" "src"
    PRIV_REQUIRES mbedtls
)
