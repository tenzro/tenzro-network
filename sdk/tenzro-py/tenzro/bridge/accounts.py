"""Agents' accounts on other chains, and the grants that bound them.

:func:`omni_address` derives an agent's account on a chain from its DID and
the chain's deployment of the agent account code, as every Tenzro node does
(checked against ``sdk/fixtures/remote_grant``). The reads and serving-node
requests are RPC methods on :class:`tenzro.RpcClient` (``agent_accounts``,
``request_remote_grant``, ``get_agent_grant_proof``, ``build_remote_action``,
``sign_remote_action``, ``sign_remote_channel_voucher``,
``agent_wallet_consent``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..hashes import blake2b256, keccak256, sha256


@dataclass(frozen=True)
class OmniAddress:
    """An agent's account on one chain."""

    caip2: str
    address: str
    raw: bytes


AccountDeployment = dict[str, Any]

_P = (1 << 255) - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _on_ed25519(b: bytes) -> bool:
    """Whether 32 bytes decompress to a point of the Ed25519 curve."""
    y = int.from_bytes(b[:31] + bytes([b[31] & 0x7F]), "little")
    if y >= _P:
        return False
    y2 = y * y % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    v3 = v * v * v % _P
    x = u * v3 % _P * pow(u * v3 * v3 * v % _P, (_P - 5) // 8, _P) % _P
    vx2 = v * x * x % _P
    return vx2 == u or vx2 == (-u) % _P


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    for x in b:
        if x != 0:
            break
        out = "1" + out
    return out


def _unbase58(s: str) -> bytes:
    n = 0
    for c in s:
        i = _B58.find(c)
        if i < 0:
            raise ValueError("not base58")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    lead = len(s) - len(s.lstrip("1"))
    return bytes(lead) + body


def _bech32(hrp: str, data: bytes) -> str:
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    words: list[int] = []
    acc = bits = 0
    for x in data:
        acc = (acc << 8) | x
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((acc >> bits) & 31)
    if bits:
        words.append((acc << (5 - bits)) & 31)

    def polymod(values: list[int]) -> int:
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in values:
            top = chk >> 25
            chk = ((chk & 0x1FFFFFF) << 5) ^ v
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= gen[i]
        return chk

    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    mod = polymod(expand + words + [0] * 6) ^ 1
    check = [(mod >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(charset[w] for w in words + check)


def stellar_strkey(version: int, payload: bytes) -> str:
    """A Stellar StrKey: base32 of the version byte, the payload and its CRC16-XModem (little-endian)."""
    b = bytes([version]) + payload
    crc = 0
    for x in b:
        crc ^= x << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    data = b + bytes([crc & 0xFF, crc >> 8])
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    out = ""
    acc = bits = 0
    for x in data:
        acc = (acc << 8) | x
        bits += 8
        while bits >= 5:
            bits -= 5
            out += alphabet[(acc >> bits) & 31]
        acc &= (1 << bits) - 1
    if bits:
        out += alphabet[(acc << (5 - bits)) & 31]
    return out


def _eip55(raw: bytes) -> str:
    lower = raw.hex()
    h = keccak256(lower.encode())
    out = "0x"
    for i, c in enumerate(lower):
        nibble = (h[i >> 1] >> (4 if i % 2 == 0 else 0)) & 0xF
        out += c.upper() if c in "abcdef" and nibble >= 8 else c
    return out


def _be(v: int, n: int) -> bytes:
    return v.to_bytes(n, "big")


def _le(v: int, n: int) -> bytes:
    return v.to_bytes(n, "little")


def omni_salt(did: str) -> bytes:
    """The per-DID salt."""
    return sha256(b"tenzro/omni-account/v1", did.encode())


def grant_tree_key(did: str, caip2: str) -> bytes:
    """The state tree key of the grant of ``did`` on ``caip2``."""
    key = "storage:" + "f" * 40 + ":" + f"agent_grant:{did}:{caip2}".encode().hex()
    return sha256(b"tenzro.state-trie.key", _le(5, 2), b"state", key.encode())


def omni_address(did: str, caip2: str, d: AccountDeployment) -> OmniAddress:
    """The account of ``did`` on ``caip2`` under ``deployment``."""
    family = d["family"]
    if caip2.split(":")[0] != family:
        raise ValueError(f"the deployment is for {family}, the chain is {caip2}")
    s = omni_salt(did)
    if family == "eip155":
        raw = keccak256(b"\xff" + bytes(d["factory"]) + s + bytes(d["init_code_hash"]))[12:]
        return OmniAddress(caip2, _eip55(raw), raw)
    if family == "solana":
        seed = sha256(did.encode())
        for bump in range(255, -1, -1):
            c = sha256(b"agent", seed, bytes([bump]), bytes(d["program_id"]), b"ProgramDerivedAddress")
            if not _on_ed25519(c):
                return OmniAddress(caip2, _base58(c), c)
        raise ValueError("no program address")
    if family == "sui":
        key_bcs = bytes([32]) + s
        tag = (
            bytes([7]) + _be(2, 32) + bytes([14]) + b"derived_object" + bytes([16]) + b"DerivedObjectKey" + bytes([1, 6, 1])
        )
        raw = blake2b256(b"\xf0" + bytes(d["registry"]) + _le(len(key_bcs), 8) + key_bcs + tag)
        return OmniAddress(caip2, "0x" + raw.hex(), raw)
    if family == "aptos":
        raw = hashlib.sha3_256(bytes(d["creator"]) + s + b"\xfe").digest()
        return OmniAddress(caip2, "0x" + raw.hex(), raw)
    if family == "stellar":
        raw = sha256(_be(8, 4), sha256(d["network_passphrase"].encode()), _be(0, 4), _be(1, 4), bytes(d["factory"]), s)
        return OmniAddress(caip2, stellar_strkey(0x10, raw), raw)
    if family == "cosmos":

        def part(p: bytes) -> bytes:
            return _be(len(p), 8) + p

        key = b"wasm\x00" + part(bytes(d["code_checksum"])) + part(bytes(d["factory"])) + part(s) + part(b"")
        raw = sha256(sha256(b"module"), key)
        return OmniAddress(caip2, _bech32(d["hrp"], raw), raw)
    if family == "tvm":
        data_hash = sha256(bytes([0, 128]), sha256(did.encode()), grant_tree_key(did, caip2))
        raw = sha256(bytes([2, 1, 0x34]), _be(d["code_depth"], 2), _be(0, 2), bytes(d["code_hash"]), data_hash)
        return OmniAddress(caip2, f"{d['workchain']}:{raw.hex()}", raw)
    raise ValueError(f"unknown deployment family {family}")


def to_caip10(a: OmniAddress) -> str:
    """CAIP-10 of an account."""
    return f"{a.caip2}:{a.address}"


def to_erc7930(a: OmniAddress) -> bytes | None:
    """The ERC-7930 interoperable address of an EVM or Solana account; ``None`` for other families."""
    ns, ref = a.caip2.split(":", 1)
    if ns == "eip155":
        chain_type = bytes([0, 0])
        n = int(ref)
        chain_ref = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"\x00"
    elif ns == "solana":
        chain_type = bytes([0, 2])
        chain_ref = _unbase58(ref)
    else:
        return None
    return bytes([0, 1]) + chain_type + bytes([len(chain_ref)]) + chain_ref + bytes([len(a.raw)]) + a.raw


def encode_action(a: dict[str, Any]) -> bytes:
    """The encoded action: target and selector (u16-prefixed), amount and refund (u128), data (u32-prefixed), big-endian."""
    t = bytes.fromhex(a["target"].removeprefix("0x"))
    sel = bytes.fromhex(a["selector"].removeprefix("0x"))
    data = bytes.fromhex(a["data"].removeprefix("0x"))
    return (
        _be(len(t), 2) + t + _be(len(sel), 2) + sel
        + _be(int(a["amount"]), 16) + _be(int(a["relay_refund"]), 16)
        + _be(len(data), 4) + data
    )


def act_digest(caip2: str, account: bytes, seq: int, nonce: int, action: bytes) -> bytes:
    """The digest serving nodes sign for action ``nonce`` under grant ``seq`` of ``account`` (32 bytes) on ``caip2``."""
    return sha256(b"tenzro/agent-act/v1", sha256(caip2.encode()), account, _be(seq, 8), _be(nonce, 8), action)


def channel_voucher_digest(caip2: str, account: bytes, channel_id: int, cumulative: int) -> bytes:
    """The digest a serving node signs for a voucher paying ``cumulative`` on channel ``channel_id``."""
    return sha256(b"tenzro/agent-channel/v1", sha256(caip2.encode()), account, _be(channel_id, 8), _be(cumulative, 16))


def pay_data(payee: bytes, request_digest: bytes, quote_digest: bytes, usd_e6: int) -> bytes:
    """The 104 bytes a paying action carries: payee, request and quote digests, and the USD price (micro-units)."""
    for name, b in (("payee", payee), ("request_digest", request_digest), ("quote_digest", quote_digest)):
        if len(b) != 32:
            raise ValueError(f"{name} must be 32 bytes")
    return bytes(payee) + bytes(request_digest) + bytes(quote_digest) + _be(usd_e6, 8)


def proven_payment_tx(agent_did: str, chain: str, delivery: bytes) -> dict[str, Any]:
    """The ``Payment`` transaction type recording one payment the agent's account on ``chain`` reported."""
    return {"Payment": {"op": {"proven": {"agent_did": agent_did, "chain": chain, "delivery": bytes(delivery).hex()}}}}


def remote_grant_settle_tx(agent_did: str, chain: str, delivery: bytes) -> dict[str, Any]:
    """The ``RemoteGrantSettle`` transaction type that settles one report of the agent's account on ``chain``."""
    return {"RemoteGrantSettle": {"agent_did": agent_did, "chain": chain, "delivery": bytes(delivery).hex()}}
