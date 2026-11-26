/*
 * The bytes a Tenzro signature covers, for clients on small machines.
 *
 * A signature has a P-256 leg and, where the signer holds one, an ML-DSA-65
 * leg. Both sign the message representative
 *
 *   M' = prefix || label || len(context) || context || SHA-512(message)
 *
 * The P-256 leg is ECDSA over SHA-256(M'), produced as r || s. The ML-DSA-65
 * leg signs M' with the label as its FIPS 204 context. The context names the
 * protocol, so a signature made for one never verifies under another.
 */
#ifndef TENZRO_SIGN_H
#define TENZRO_SIGN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TZ_OK = 0,
    TZ_ERR_ARGUMENT = -1,
    TZ_ERR_SPACE = -2,
    TZ_ERR_HASH = -3,
    /* A node's reply that is not the JSON-RPC answer to the request sent. */
    TZ_ERR_RESPONSE = -4,
    /* The node answered with a JSON-RPC error. */
    TZ_ERR_REFUSED = -5,
    /* An update's signature is not the release key's over its document. */
    TZ_ERR_SIGNATURE = -6,
    /* An update document not above the version installed: a roll back. */
    TZ_ERR_ROLLBACK = -7,
    /* An update document names no image for this platform. */
    TZ_ERR_NO_TARGET = -8,
} tz_status;

/* Signature contexts a small client signs under. */
#define TZ_CONTEXT_TRANSACTION "tenzro/tx"
#define TZ_CONTEXT_ESCROW_VOUCHER "tenzro/escrow/voucher"
#define TZ_CONTEXT_SENSOR_READING "tenzro/dispute/sensor-reading"

/* The label of the ML-DSA-65 with P-256 scheme; also the ML-DSA context. */
#define TZ_LABEL_MLDSA65_P256 "COMPSIG-MLDSA65-ECDSA-P256-SHA512"

/* Room for the representative of the longest context (255 bytes). */
#define TZ_REPRESENTATIVE_MAX (32 + 33 + 1 + 255 + 64)

/* Length of an escrow voucher's signed bytes. */
#define TZ_ESCROW_VOUCHER_LEN (21 + 8 + 32 + 16 + 32)

/*
 * Writes M' for `message` under `context` (a NUL-terminated string of 1 to
 * 255 bytes) into `out` and its length into `out_len`.
 */
tz_status tz_message_representative(const char *context,
                                    const uint8_t *message, size_t message_len,
                                    uint8_t *out, size_t out_capacity,
                                    size_t *out_len);

/* The 32 bytes the P-256 leg signs: SHA-256(M'). */
tz_status tz_signing_digest(const char *context,
                            const uint8_t *message, size_t message_len,
                            uint8_t digest[32]);

/*
 * The bytes a payer signs for an escrow voucher, under
 * TZ_CONTEXT_ESCROW_VOUCHER. `cumulative_le` is the cumulative amount as a
 * 128-bit little-endian integer.
 */
void tz_escrow_voucher_bytes(uint64_t chain_id, const uint8_t escrow_id[32],
                             const uint8_t cumulative_le[16],
                             const uint8_t binding[32],
                             uint8_t out[TZ_ESCROW_VOUCHER_LEN]);

/* Longest device DID a reading names, in bytes. */
#define TZ_DEVICE_DID_MAX 256

/*
 * The 32 bytes a device signs, under TZ_CONTEXT_SENSOR_READING, to attest one
 * reading: who measured it (`device_did`, a NUL-terminated string of 1 to
 * TZ_DEVICE_DID_MAX bytes), the SHA-256 of the reading's payload, whatever
 * produced it, and when it was measured in milliseconds since the Unix epoch.
 */
tz_status tz_sensor_reading_digest(const char *device_did,
                                   const uint8_t payload_digest[32],
                                   uint64_t measured_at_ms,
                                   uint8_t digest[32]);

/* Length of the ML-DSA-65 leg of a signature. */
#define TZ_MLDSA65_SIGNATURE_LEN 3309

/*
 * Room for the evidence item of a reading: with the P-256 leg alone, and
 * with the ML-DSA-65 leg beside it. Both count the closing NUL.
 */
#define TZ_READING_EVIDENCE_MAX (384 + TZ_DEVICE_DID_MAX)
#define TZ_READING_EVIDENCE_MAX_HYBRID \
    (TZ_READING_EVIDENCE_MAX + 8 + 2 * TZ_MLDSA65_SIGNATURE_LEN)

/*
 * Writes the evidence item a device hands over with a reading it signed: the
 * JSON object the ledger accepts as `sensor_data` evidence, NUL-terminated,
 * with its length (the NUL not counted) in `out_len`. `p256_signature` is
 * r || s over tz_signing_digest(TZ_CONTEXT_SENSOR_READING, <reading digest>).
 * `ml_dsa_signature` is the ML-DSA-65 leg of `ml_dsa_len` bytes, or NULL with
 * a length of 0 for a device that holds no ML-DSA-65 key. A DID with a quote,
 * a backslash or a byte outside printable ASCII is refused.
 */
tz_status tz_sensor_reading_evidence(const char *device_did,
                                     const uint8_t payload_digest[32],
                                     uint64_t measured_at_ms,
                                     const uint8_t p256_signature[64],
                                     const uint8_t *ml_dsa_signature,
                                     size_t ml_dsa_len,
                                     char *out, size_t out_capacity,
                                     size_t *out_len);

/* The fields of a native transaction other than its type and memo. */
typedef struct {
    uint64_t chain_id;
    uint8_t from[32];
    uint8_t to[32];
    uint64_t nonce;
    uint64_t gas_limit;
    uint64_t gas_price;
    /* Milliseconds since the Unix epoch. */
    int64_t timestamp_ms;
    /* The last millisecond the transaction may be included at. */
    int64_t valid_until_ms;
} tz_tx_header;

/* Longest transaction type and memo tz_transaction_hash takes. */
#define TZ_TX_TYPE_MAX 1024
#define TZ_MEMO_MAX 256

/* Room for the type of a transfer, with the closing NUL: 66 bytes for the largest amount. */
#define TZ_TRANSFER_TYPE_MAX 72

/*
 * Writes the type of a transfer of `amount_le` (128-bit little-endian, the
 * smallest unit) as the ledger encodes it, NUL-terminated, its length in
 * `out_len`.
 */
tz_status tz_transfer_type(const uint8_t amount_le[16], char *out,
                           size_t out_capacity, size_t *out_len);

/*
 * The hash of a native transaction: what its signature covers, under
 * TZ_CONTEXT_TRANSACTION (sign tz_signing_digest of these 32 bytes).
 * `tx_type` is the encoding of its type (tz_transfer_type for a transfer),
 * `memo` the memo or NULL. Not reentrant: it builds the preimage in one
 * static buffer of about 1.4 KB rather than on a small device's stack.
 * Privileged actions (governance, guardian, issuer,
 * agent terms) are signed over a typed preimage instead and are not built here.
 */
tz_status tz_transaction_hash(const tz_tx_header *header,
                              const char *tx_type, size_t tx_type_len,
                              const char *memo, uint8_t hash[32]);

/*
 * Room for a signed transfer's JSON-RPC request, with the closing NUL: with
 * the P-256 leg alone, and with the ML-DSA-65 leg beside it.
 */
#define TZ_TRANSFER_REQUEST_MAX 896
#define TZ_TRANSFER_REQUEST_MAX_HYBRID \
    (TZ_TRANSFER_REQUEST_MAX + 8 + 2 * TZ_MLDSA65_SIGNATURE_LEN)

/*
 * Writes the JSON-RPC request that submits a signed transfer
 * (`tenzro_sendRawTransaction`), NUL-terminated, its length in `out_len`.
 * `header` and `amount_le` are what tz_transaction_hash hashed, with no memo
 * (the node submits none), and both times are 0 or later. `public_key` is the
 * device's P-256 key as x || y, `p256_signature` r || s over
 * tz_signing_digest(TZ_CONTEXT_TRANSACTION, <hash>), and `ml_dsa_signature`
 * the ML-DSA-65 leg of `ml_dsa_len` bytes, or NULL with 0.
 */
tz_status tz_transfer_request(uint64_t id, const tz_tx_header *header,
                              const uint8_t amount_le[16],
                              const uint8_t public_key[64],
                              const uint8_t p256_signature[64],
                              const uint8_t *ml_dsa_signature,
                              size_t ml_dsa_len, char *out,
                              size_t out_capacity, size_t *out_len);

/*
 * The 32-byte account slot of the device's P-256 key (`public_key` x || y):
 * its ledger address SHA-256("tenzro/account" || 0x02 || 0x40 || x || y),
 * first 20 bytes, then 12 zero bytes. A transfer's `from`, and the account
 * tz_read_request asks about.
 */
tz_status tz_account_slot(const uint8_t public_key[64], uint8_t slot[32]);

/* Longest name, controller DID and capability list tz_enrolment_command takes. */
#define TZ_ENROLMENT_FIELD_MAX 128
/* Room for the enrolment command, with the closing NUL. */
#define TZ_ENROLMENT_COMMAND_MAX (128 + 3 * TZ_ENROLMENT_FIELD_MAX + 128)

/*
 * Writes the command the device's operator runs to register it as a machine
 * they control, NUL-terminated, its length in `out_len`:
 *   tenzro identity register --identity-type machine --name <name>
 *     --controller <controller_did> --public-key <x || y hex>
 *     --capabilities <capabilities>
 * (one line). The device prints it (on its console, or as a QR code); the
 * operator's own key signs the registration. `name`, `controller_did` and
 * `capabilities` (comma-separated) are 1 to TZ_ENROLMENT_FIELD_MAX bytes of
 * A-Z a-z 0-9 : . _ - (and , in the capabilities), so the line needs no
 * shell quoting.
 */
tz_status tz_enrolment_command(const char *name, const char *controller_did,
                               const char *capabilities,
                               const uint8_t public_key[64], char *out,
                               size_t out_capacity, size_t *out_len);

/* What tz_read_request asks a node. */
typedef enum {
    /* The account's balance in the smallest unit (tenzro_getBalance). */
    TZ_READ_BALANCE,
    /* The account's next nonce (tenzro_getNonce). */
    TZ_READ_NONCE,
    /* The ordered and certified heights (tenzro_getFinality); no account. */
    TZ_READ_FINALITY,
} tz_read;

/* Room for a read request, with the closing NUL. */
#define TZ_READ_REQUEST_MAX 160

/*
 * Writes the JSON-RPC request for `read`, NUL-terminated, its length in
 * `out_len`. `slot` is the account (tz_account_slot), named by its 20-byte
 * address; NULL for TZ_READ_FINALITY.
 */
tz_status tz_read_request(uint64_t id, tz_read read, const uint8_t slot[32],
                          char *out, size_t out_capacity, size_t *out_len);

/*
 * Reads a node's answer to a TZ_READ_BALANCE or TZ_READ_NONCE request `id`:
 * the quantity in `value_le` (128-bit little-endian). TZ_ERR_REFUSED when
 * the node answered with an error, TZ_ERR_RESPONSE when `response` is not
 * the answer to `id` or its result is not a quantity of at most 128 bits.
 */
tz_status tz_read_quantity(const char *response, size_t response_len,
                           uint64_t id, uint8_t value_le[16]);

/*
 * Reads a node's answer to a TZ_READ_FINALITY request `id`: the height the
 * node has ordered and the height a certificate covers. The certificate
 * itself is not checked here: on the device, that is a quorum of ML-DSA-65
 * and P-256 signatures, measured first on the boards (#238 step 0).
 */
tz_status tz_read_finality(const char *response, size_t response_len,
                           uint64_t id, uint64_t *ordered,
                           uint64_t *certified);

#ifdef __cplusplus
}
#endif

#endif
