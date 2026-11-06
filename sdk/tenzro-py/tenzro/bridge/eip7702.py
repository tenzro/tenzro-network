"""Standard EIP-7702 set-code transactions (type 0x04) for an external
secp256k1 signer.

No signing key is held here. The helpers produce the two digests a wallet or
hardware signer signs (the authorization digest and the transaction digest)
and assemble the signed bytes from the signatures they are handed. The raw
bytes go to ``eth_sendRawTransaction``; the node recovers the sender and every
authority from their signatures and installs the delegation designator in the
authority's code.

    authorization digest = keccak256(0x05 || rlp([chain_id, address, nonce]))
    transaction digest   = keccak256(0x04 || rlp([chain_id, nonce, max_priority_fee_per_gas,
                             max_fee_per_gas, gas_limit, to, value, data, access_list,
                             authorization_list]))
    raw transaction      = 0x04 || rlp([...same fields..., y_parity, r, s])

Addresses, keys, data and signature scalars are 0x-hex strings; amounts are
ints. A signature is ``{"y_parity": 0|1, "r": hex, "s": hex}``.
"""

from __future__ import annotations

from ..hashes import keccak256

SET_CODE_TX_TYPE = 0x04
AUTHORIZATION_MAGIC = 0x05


def _hex(s: str, length: int | None = None) -> bytes:
    b = bytes.fromhex(s[2:] if s.startswith("0x") else s)
    if length is not None and len(b) != length:
        raise ValueError(f"expected {length} bytes: {s}")
    return b


def _prefix(length: int, short: int, long: int) -> bytes:
    if length < 56:
        return bytes([short + length])
    be = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([long + len(be)]) + be


def _rlp_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _prefix(len(b), 0x80, 0xB7) + b


def _rlp_uint(v: int) -> bytes:
    if v < 0:
        raise ValueError("negative integer")
    return _rlp_bytes(v.to_bytes((v.bit_length() + 7) // 8, "big"))


def _rlp_word(s: str) -> bytes:
    return _rlp_uint(int.from_bytes(_hex(s, 32), "big"))


def _rlp_list(items: list[bytes]) -> bytes:
    body = b"".join(items)
    return _prefix(len(body), 0xC0, 0xF7) + body


def authorization_signing_hash(chain_id: int, address: str, nonce: int) -> str:
    """The digest the authority signs."""
    body = _rlp_list([_rlp_uint(chain_id), _rlp_bytes(_hex(address, 20)), _rlp_uint(nonce)])
    return "0x" + keccak256(bytes([AUTHORIZATION_MAGIC]) + body).hex()


def _authorization_rlp(a: dict) -> bytes:
    sig = a["signature"]
    return _rlp_list([
        _rlp_uint(a["chain_id"]),
        _rlp_bytes(_hex(a["address"], 20)),
        _rlp_uint(a["nonce"]),
        _rlp_uint(sig["y_parity"]),
        _rlp_word(sig["r"]),
        _rlp_word(sig["s"]),
    ])


def _fields(tx: dict) -> list[bytes]:
    auths = tx.get("authorization_list") or []
    if not auths:
        raise ValueError("a set-code transaction needs at least one authorization")
    access = [
        _rlp_list([
            _rlp_bytes(_hex(i["address"], 20)),
            _rlp_list([_rlp_bytes(_hex(k, 32)) for k in i.get("storage_keys", [])]),
        ])
        for i in tx.get("access_list", [])
    ]
    return [
        _rlp_uint(tx["chain_id"]),
        _rlp_uint(tx["nonce"]),
        _rlp_uint(tx["max_priority_fee_per_gas"]),
        _rlp_uint(tx["max_fee_per_gas"]),
        _rlp_uint(tx["gas_limit"]),
        _rlp_bytes(_hex(tx["to"], 20)),
        _rlp_uint(tx.get("value", 0)),
        _rlp_bytes(_hex(tx.get("data", "0x"))),
        _rlp_list(access),
        _rlp_list([_authorization_rlp(a) for a in auths]),
    ]


def set_code_transaction_signing_hash(tx: dict) -> str:
    """The digest the sender signs.

    ``tx`` has chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
    gas_limit, to, value, data, access_list and authorization_list (each
    authorization: chain_id, address, nonce, signature).
    """
    return "0x" + keccak256(bytes([SET_CODE_TX_TYPE]) + _rlp_list(_fields(tx))).hex()


def encode_signed_set_code_transaction(tx: dict, signature: dict) -> str:
    """The raw signed transaction (0x-hex) for ``eth_sendRawTransaction``."""
    fields = _fields(tx) + [
        _rlp_uint(signature["y_parity"]),
        _rlp_word(signature["r"]),
        _rlp_word(signature["s"]),
    ]
    return "0x" + (bytes([SET_CODE_TX_TYPE]) + _rlp_list(fields)).hex()


def raw_transaction_hash(raw: str) -> str:
    """The hash a wallet and the node record a raw transaction under."""
    return "0x" + keccak256(_hex(raw)).hex()


def delegation_designator(address: str) -> str:
    """The code an authority carries once its delegation is installed."""
    return "0xef0100" + _hex(address, 20).hex()
