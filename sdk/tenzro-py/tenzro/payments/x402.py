"""The x402 payer side.

A payer answers ``402 Payment Required`` by paying one of the offered
requirements and retrying, and keeps paying a path it has paid before without
another 402 round trip. :class:`HybridPayer` pays ``tenzro-hybrid``
requirements with the payer's hardware key; :class:`AgentChannelPayer` pays
``batch-settlement`` requirements as a delegated agent from a channel its
wallet funded, its serving node signing each voucher with its hardware key for
the agent, which the ledger honours only within the agent's Terms. Plan
payments are in :mod:`tenzro.settlement`.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import struct
import uuid
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from ..rpc import RpcClient
from ..wallet import HybridSigner, account_address, composite_message_representative, composite_signature_json

PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"
X402_VERSION = 2

#: Context of the composite signature over a payment authorization.
PAYMENT_AUTHORIZATION_CONTEXT = b"tenzro/payment/authorization"

PaymentRequirement = dict[str, Any]
ResourceInfo = dict[str, Any]
PaymentRequired = dict[str, Any]

_TENZRO_NETWORK = re.compile(r"^tenzro:(\d+)$")


def encode_header_text(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def decode_header_text(value: str) -> str:
    return base64.b64decode(value.strip()).decode()


def stringify_exact(value: Any) -> str:
    """JSON with integers written exactly (amounts above 2^53 stay numbers), compact, key order kept."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def challenge_id_of(r: PaymentRequirement) -> str | None:
    cid = (r.get("extra") or {}).get("challengeId")
    return cid if isinstance(cid, str) else None


def tenzro_network(chain_id: int) -> str:
    return f"tenzro:{chain_id}"


class Payer(Protocol):
    """Pays requirements it supports, returning the payload's ``payload`` field."""

    def supports(self, r: PaymentRequirement) -> bool: ...

    def pay(self, r: PaymentRequirement, resource: ResourceInfo) -> Any: ...


def payment_header(payer: Payer, required: PaymentRequired, requirement: PaymentRequirement) -> str:
    """The ``PAYMENT-SIGNATURE`` value for ``requirement``, paid by ``payer``."""
    payload = payer.pay(requirement, required["resource"])
    body = {"x402Version": X402_VERSION, "resource": required["resource"], "accepted": requirement, "payload": payload}
    return encode_header_text(stringify_exact(body))


def _tenzro_address(value: str) -> bytes:
    """A Tenzro address from 20 or 32 bytes of hex; 20 bytes fill the leading bytes."""
    b = bytes.fromhex(value.strip().removeprefix("0x"))
    if len(b) == 32:
        return b
    if len(b) == 20:
        return b + bytes(12)
    raise ValueError(f"address {value} is {len(b)} bytes; a Tenzro address is 20 or 32 bytes")


def hybrid_authorization_message(r: PaymentRequirement, resource_url: str, payer: bytes, max_amount: int) -> bytes:
    """The message a payer signs to authorize ``max_amount`` against a ``tenzro-hybrid`` requirement.

    Exactly as the facilitator rebuilds it: the chain, the challenge id, payer
    and payee, the ceiling, the asset, and the request digest of the resource.
    """
    chain = _TENZRO_NETWORK.match(r["network"])
    if not chain:
        raise ValueError(f"{r['network']} is not a Tenzro network")
    challenge_id = challenge_id_of(r)
    if challenge_id is None:
        raise ValueError("the requirement names no challengeId")
    if not 0 <= max_amount < 1 << 128:
        raise ValueError("amount out of range")
    cid = challenge_id.encode()
    asset = r["asset"].encode()
    request_digest = hashlib.sha256(b"tenzro/request" + resource_url.encode()).digest()
    return b"".join(
        [
            b"tenzro/payment-authorization",
            struct.pack("<Q", int(chain.group(1))),
            struct.pack("<I", len(cid)),
            cid,
            bytes(payer),
            _tenzro_address(r["payTo"]),
            max_amount.to_bytes(16, "little"),
            struct.pack("<I", len(asset)),
            asset,
            request_digest,
            bytes(32),
            struct.pack("<Q", 0),
            _app_margin_bytes(None),
        ]
    )


def _challenge_app_margin(extra: dict[str, Any]) -> tuple[bytes, int] | None:
    """The developer margin a challenge asks the payer to sign: ``app_wallet``
    and a non-zero ``margin_bps`` together, or neither."""
    bps = extra.get("margin_bps", 0)
    wallet = extra.get("app_wallet")
    if not isinstance(bps, int) or isinstance(bps, bool) or not 0 <= bps < 1 << 32:
        raise ValueError("margin_bps must be a u32")
    if wallet is not None and not isinstance(wallet, str):
        raise ValueError("app_wallet must be a hex string")
    if wallet is None and bps == 0:
        return None
    if wallet is None or bps == 0:
        raise ValueError("a developer margin names both a non-zero margin_bps and an app_wallet")
    return _tenzro_address(wallet), bps


def _app_margin_bytes(margin: tuple[bytes, int] | None) -> bytes:
    """``0x00`` for no margin, or ``0x01 || app_wallet(32) || margin_bps(u32 LE)``."""
    if margin is None:
        return b"\x00"
    return b"\x01" + margin[0] + struct.pack("<I", margin[1])


def challenge_authorization_message(challenge: dict[str, Any], payer: bytes, max_amount: int) -> bytes:
    """The message a payer signs to authorize ``max_amount`` against a challenge the node issued.

    Exactly as the node rebuilds it (``tenzro_createPaymentChallenge``): the
    chain, the challenge id, payer and payee, the ceiling, the asset, and what
    is paid for (the request digest of the resource, the quote digest and the
    USD price a quoted challenge carries, zero when unquoted, and the
    developer margin it asks the payer to sign, if any).
    """
    extra = challenge.get("extra") or {}
    chain_id = extra.get("chain_id")
    if not isinstance(chain_id, int):
        raise ValueError(f"challenge {challenge.get('challenge_id')} carries no chain_id; it was not issued by a node")
    if not 0 <= max_amount < 1 << 128:
        raise ValueError("amount out of range")
    quote = extra.get("quote_digest")
    quote_digest = bytes(32) if quote is None else bytes.fromhex(str(quote).removeprefix("0x"))
    if len(quote_digest) != 32:
        raise ValueError("quote_digest is 32 bytes of hex")
    usd_e6 = int(extra.get("usd_e6", 0))
    margin = _challenge_app_margin(extra)
    cid = challenge["challenge_id"].encode()
    asset = challenge["asset"].encode()
    request_digest = hashlib.sha256(b"tenzro/request" + challenge["resource"].encode()).digest()
    return b"".join(
        [
            b"tenzro/payment-authorization",
            struct.pack("<Q", chain_id),
            struct.pack("<I", len(cid)),
            cid,
            bytes(payer),
            _tenzro_address(challenge["recipient"]),
            max_amount.to_bytes(16, "little"),
            struct.pack("<I", len(asset)),
            asset,
            request_digest,
            quote_digest,
            struct.pack("<Q", usd_e6),
            _app_margin_bytes(margin),
        ]
    )


def _paying_account(signer: HybridSigner, account: str | None) -> bytes:
    """The account paid from: ``account`` (20 or 32 bytes of hex), such as the
    shared account a wallet's linked passkeys act for, or by default the
    account the signer's P-256 key names."""
    if account is None:
        return account_address(signer.p256_public_key())
    b = bytes.fromhex(account.removeprefix("0x"))
    if len(b) == 20:
        return b + bytes(12)
    if len(b) == 32:
        return b
    raise ValueError(f"account {account} is {len(b)} bytes; a Tenzro address is 20 or 32 bytes")


def sign_challenge_credential(
    challenge: dict[str, Any],
    signer: HybridSigner,
    payer_did: str = "",
    max_amount: int | None = None,
    account: str | None = None,
) -> dict[str, Any]:
    """Sign a credential for a node-issued challenge with the payer's hardware key.

    The charge is the challenge amount; ``max_amount`` is the ceiling signed
    (defaults to the charge), recorded as ``upto_max`` when above it (a
    metered credential). ``account`` names the account paid from when it is
    not the one the signer's key names: a passkey account whose keystore on
    chain links the signer's passkey.
    """
    amount = int(challenge["amount"])
    ceiling = amount if max_amount is None else int(max_amount)
    if ceiling < amount:
        raise ValueError(f"max_amount {ceiling} is below the challenge amount {amount}")
    public_key = signer.p256_public_key()
    payer = _paying_account(signer, account)
    message = challenge_authorization_message(challenge, payer, ceiling)
    m_prime = composite_message_representative(PAYMENT_AUTHORIZATION_CONTEXT, message)
    classical, pq = signer.sign_composite(m_prime)
    extra = {"public_key": bytes(public_key).hex()}
    if ceiling != amount:
        extra["upto_max"] = str(ceiling)
    return {
        "credential_id": str(uuid.uuid4()),
        "challenge_id": challenge["challenge_id"],
        "protocol": challenge["protocol"].lower(),
        "payer_did": payer_did,
        "payer_address": payer.hex(),
        "amount": amount,
        "asset": challenge["asset"],
        "signature": composite_signature_json(classical, pq),
        "extra": extra,
    }


class HybridPayer:
    """A payer paying ``tenzro-hybrid`` requirements with its hardware key."""

    def __init__(self, signer: HybridSigner, payer_did: str = "", account: str | None = None):
        """``account`` names the account paid from when it is not the one the
        signer's key names: a passkey account whose keystore links it."""
        self._signer = signer
        self._payer_did = payer_did
        self._account = account

    def supports(self, r: PaymentRequirement) -> bool:
        return r.get("scheme") == "tenzro-hybrid" and bool(_TENZRO_NETWORK.match(r.get("network", "")))

    def pay(self, r: PaymentRequirement, resource: ResourceInfo) -> dict[str, Any]:
        public_key = self._signer.p256_public_key()
        payer = _paying_account(self._signer, self._account)
        amount = int(r["amount"])
        message = hybrid_authorization_message(r, resource["url"], payer, amount)
        m_prime = composite_message_representative(PAYMENT_AUTHORIZATION_CONTEXT, message)
        classical, pq = self._signer.sign_composite(m_prime)
        return {
            "credential_id": str(uuid.uuid4()),
            "challenge_id": challenge_id_of(r) or "",
            "protocol": "x402",
            "payer_did": self._payer_did,
            "payer_address": payer.hex(),
            "amount": amount,
            "asset": r["asset"],
            "signature": composite_signature_json(classical, pq),
            "extra": {"public_key": bytes(public_key).hex()},
        }


def agent_voucher_credential(
    r: PaymentRequirement,
    channel_id: str,
    cumulative: int,
    charge: int,
    voucher: dict[str, Any],
    credential_id: str,
) -> dict[str, Any]:
    """The credential a facilitator takes for an agent's voucher, as the node's ``PaymentCredential`` serializes."""
    agent = voucher["agent"]
    return {
        "credential_id": credential_id,
        "challenge_id": challenge_id_of(r) or "",
        "protocol": "x402",
        "payer_did": agent["agent_did"],
        "payer_address": "",
        "amount": charge,
        "asset": r["asset"],
        "signature": voucher["signature"],
        "extra": {
            "escrow_id": channel_id.removeprefix("0x"),
            "cumulative_amount": str(cumulative),
            "agent_did": agent["agent_did"],
            "machine_did": agent["machine_did"],
            "as_of_ms": str(agent["as_of_ms"]),
        },
    }


class AgentChannelPayer:
    """A delegated agent paying from its channel (an escrow its wallet funded) to one payee.

    ``rpc`` is a client on one of the agent's serving nodes carrying the
    agent's credential; ``spent`` is what earlier vouchers on the channel
    already cover.
    """

    def __init__(self, rpc: RpcClient, chain_id: int, channel_id: str, pay_to: str, spent: int = 0):
        self._rpc = rpc
        self._chain_id = chain_id
        self._channel_id = channel_id
        self._pay_to = pay_to
        self._cumulative = spent

    def supports(self, r: PaymentRequirement) -> bool:
        return (
            r.get("scheme") == "batch-settlement"
            and r.get("network") == tenzro_network(self._chain_id)
            and r.get("payTo", "").removeprefix("0x").lower() == self._pay_to.removeprefix("0x").lower()
        )

    def pay(self, r: PaymentRequirement, resource: ResourceInfo | None = None) -> dict[str, Any]:
        charge = int(r["amount"])
        nxt = self._cumulative + charge
        signed = self._rpc.call(
            "tenzro_agentVoucher", {"channel_id": self._channel_id, "cumulative_amount": str(nxt)}
        )
        self._cumulative = nxt
        return agent_voucher_credential(r, self._channel_id, nxt, charge, signed["voucher"], str(uuid.uuid4()))


class PayingClient:
    """An HTTP client that pays: a 402 is answered by paying one offered requirement within ``max_amount``.

    Returns the paid response, or the 402 when nothing offered is payable.
    """

    def __init__(self, payer: Payer, max_amount: int, http: httpx.Client | None = None):
        self._payer = payer
        self._max = max_amount
        self._http = http or httpx.Client()
        self._known: dict[str, tuple[PaymentRequired, PaymentRequirement]] = {}

    @staticmethod
    def _key(url: str) -> str:
        u = urlsplit(url)
        return f"{u.scheme}://{u.netloc}{u.path}"

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        key = self._key(url)
        prior = self._known.get(key)
        if prior:
            # A path paid before is paid up front under a fresh challenge id; a
            # voucher only ever moves forward, so a replay pays nothing twice.
            required, requirement = prior
            fresh = copy.deepcopy(requirement)
            fresh["extra"] = {**(fresh.get("extra") or {}), "challengeId": str(uuid.uuid4())}
            res = self._send(method, url, payment_header(self._payer, required, fresh), **kwargs)
            if res.status_code != 402:
                return res
            del self._known[key]
        first = self._http.request(method, url, **kwargs)
        if first.status_code != 402:
            return first
        header = first.headers.get(PAYMENT_REQUIRED_HEADER)
        if not header:
            return first
        required = json.loads(decode_header_text(header))
        requirement = next(
            (r for r in required.get("accepts", []) if self._payer.supports(r) and int(r["amount"]) <= self._max), None
        )
        if requirement is None:
            return first
        paid = self._send(method, url, payment_header(self._payer, required, requirement), **kwargs)
        if paid.status_code != 402:
            self._known[key] = (required, requirement)
        return paid

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def _send(self, method: str, url: str, header: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", None) or {})
        headers[PAYMENT_SIGNATURE_HEADER] = header
        return self._http.request(method, url, headers=headers, **kwargs)
