"""Paying on the Tenzro ledger in whatever asset the payer holds.

A price in the unit of account, a quote per accepted asset with its fee in
kind, an idempotent payment, and a receipt checked against the chain on two
endpoints::

    pay = LedgerPayments([rpc_a, rpc_b])
    q = pay.quote(payee, "0.25", request, ["0x..usdc", "TNZO"])
    paid = pay.pay(q, signer, idempotency_key="order-1")
    pay.verify_receipt(paid.expected)

Nothing is rerouted silently: an asset that cannot settle now is reported
with its code, a quote none of whose accepted assets can settle is refused,
and a receipt the two endpoints disagree on is refused. The signer is a
hardware or passkey signer; no raw key is accepted.
"""

from __future__ import annotations

import hashlib
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from ..wallet import account_address, composite_message_representative, composite_signature_json
from .x402 import PAYMENT_AUTHORIZATION_CONTEXT

__all__ = [
    "AssetQuote",
    "ExpectedPayment",
    "LedgerPayments",
    "LedgerQuote",
    "MemoryChargeStore",
    "PaidPayment",
    "PaymentError",
    "check_receipt",
    "choose_asset",
    "ledger_authorization_message",
    "parse_price_e6",
    "payment_id",
    "read_quote_assets",
    "request_digest",
]


class PaymentError(Exception):
    """A payment step refused, with a stable code (``asset_suspended``, ``asset_inflow_full``, ``asset_off_peg``, ``receipt_mismatch``, ...)."""

    def __init__(self, code: str, reason: str):
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


_PRICE = re.compile(r"^(\d+)(?:\.(\d{1,6}))?$")


def parse_price_e6(amount: str) -> int:
    """Micro-units of a decimal price: ``"0.25"`` is 250000. Refuses more than six places, signs and exponents."""
    m = _PRICE.match(amount)
    if not m:
        raise PaymentError("invalid_price", f"price {amount!r} is not a decimal with at most six places")
    e6 = int(m.group(1)) * 1_000_000 + int((m.group(2) or "").ljust(6, "0"))
    if e6 == 0:
        raise PaymentError("invalid_price", "a price is greater than zero")
    if e6 >= 1 << 64:
        raise PaymentError("invalid_price", f"price {amount} is too large")
    return e6


def request_digest(request: str) -> bytes:
    """The digest of what a payment buys: SHA-256 of ``tenzro/request`` and the request."""
    return hashlib.sha256(b"tenzro/request" + request.encode()).digest()


def payment_id(idempotency_key: str, payer: bytes, payee: bytes, digest: bytes) -> str:
    """The payment id every retry of one payment settles under, as hex. The chain settles an id once."""
    key = idempotency_key.encode()
    return hashlib.sha256(
        b"tenzro/payment-id" + struct.pack("<I", len(key)) + key + payer + payee + digest
    ).hexdigest()


def ledger_authorization_message(
    *,
    chain_id: int,
    payment_id: str,
    payer: bytes,
    payee: bytes,
    max_amount: int,
    asset: str,
    request_digest: bytes,
    usd_e6: int,
    quote_digest: bytes = bytes(32),
    resellers: Sequence[tuple[bytes, int]] = (),
) -> bytes:
    """The authorization preimage a ``PayerSettle`` checks, exactly as the chain builds it (no developer
    margin). With ``resellers`` (account, commission bps), a ``0x02`` tag, their count and each reseller and
    commission follow, so none can change after signing."""
    pid = payment_id.encode()
    a = asset.encode()
    legs = b""
    if resellers:
        legs = b"\x02" + struct.pack("<I", len(resellers)) + b"".join(r + struct.pack("<I", bps) for r, bps in resellers)
    return (
        b"tenzro/payment-authorization"
        + struct.pack("<Q", chain_id)
        + struct.pack("<I", len(pid))
        + pid
        + payer
        + payee
        + max_amount.to_bytes(16, "little")
        + struct.pack("<I", len(a))
        + a
        + request_digest
        + quote_digest
        + struct.pack("<Q", usd_e6)
        + b"\x00"
        + legs
    )


@dataclass(frozen=True)
class AssetQuote:
    """One accepted asset's price now, with the fee it pays in kind."""

    asset: str
    amount: int
    fee: int
    fee_asset: str
    rate_epoch: int | None
    #: The operator's price inside ``amount``.
    operator_amount: int = 0
    #: Each commission inside ``amount`` (``reseller``, ``commission_bps``, ``amount``, ``fee``).
    legs: tuple = ()


@dataclass(frozen=True)
class AssetRefusal:
    """An accepted asset the payment cannot settle in now."""

    asset: str
    error: PaymentError


def read_quote_assets(response: dict) -> list[AssetQuote | AssetRefusal]:
    """Reads a ``tenzro_quotePayment`` answer."""
    out: list[AssetQuote | AssetRefusal] = []
    for a in response["assets"]:
        if a.get("error"):
            out.append(AssetRefusal(a["asset"], PaymentError(a["error"]["code"], a["error"].get("reason", ""))))
        else:
            out.append(
                AssetQuote(
                    a["asset"],
                    int(a["amount"]),
                    int(a["fee"]),
                    a["fee_asset"],
                    a.get("rate_epoch"),
                    int(a.get("operator_amount", a["amount"])),
                    tuple(a.get("legs") or ()),
                )
            )
    return out


def choose_asset(assets: Sequence[AssetQuote | AssetRefusal], accept: Sequence[str]) -> AssetQuote:
    """The first asset in ``accept`` order the payment can settle in; refused with every reason when none can."""
    reasons: list[str] = []
    only: str | None = None
    for want in accept:
        a = next((x for x in assets if x.asset.lower() == want.lower()), None)
        if a is None:
            reasons.append(f"{want}: not quoted")
            continue
        if isinstance(a, AssetQuote):
            return a
        reasons.append(f"{want}: {a.error.code} ({a.error.reason})")
        only = a.error.code if only in (None, a.error.code) else "no_accepted_asset"
    raise PaymentError(only or "no_accepted_asset", "no accepted asset can settle now: " + "; ".join(reasons))


@dataclass(frozen=True)
class ExpectedPayment:
    """What a payment was made for, to check its record against."""

    payment_id: str
    payee: str
    asset: str
    amount: int
    #: The one request the payment pays for.
    request: str
    #: The commissions the payment carries (account, bps); their legs must all be on the record.
    resellers: Sequence[tuple[bytes, int]] = ()


def _payee_hex(v: Any) -> str:
    if isinstance(v, list):
        return bytes(v).hex()
    return str(v).removeprefix("0x").lower()


def check_receipt(expected: ExpectedPayment, a: Any, b: Any) -> dict:
    """Checks the record two endpoints returned: both present and identical, a native record under the
    payment id, to the payee, in the asset and amount paid, for exactly ``expected.request``, with every
    receipt field filled. A receipt for one request never verifies for another."""
    if a is None or b is None:
        raise PaymentError("receipt_missing", f"no record settled under {expected.payment_id}")
    if a != b:
        raise PaymentError("receipt_mismatch", "the two endpoints return different records")

    def fail(what: str) -> PaymentError:
        return PaymentError("receipt_mismatch", f"the record's {what} is not what was paid")

    if a.get("class") != "native":
        raise fail("class")
    if a.get("nonce") != expected.payment_id:
        raise fail("payment id")
    if _payee_hex(a.get("payee")) != expected.payee.removeprefix("0x").lower():
        raise fail("payee")
    if str(a.get("asset", "")).lower() != expected.asset.lower():
        raise fail("asset")
    if int(a.get("amount", "-1")) != expected.amount:
        raise fail("amount")
    for f in ("fee_asset", "payout_asset", "value_units"):
        if not isinstance(a.get(f), str) or a.get(f) == "":
            raise fail(f)
    if not (a.get("unit") or {}).get("basket"):
        raise fail("unit")
    if (a.get("binding") or {}).get("request_digest") != request_digest(expected.request).hex():
        raise fail("request")
    legs = a.get("legs") or []
    if not legs or legs[0].get("role") != "operator" or _payee_hex(legs[0].get("account")) != expected.payee.removeprefix("0x").lower():
        raise fail("operator leg")
    resold = [x for x in legs if x.get("role") == "reseller"]
    want = list(expected.resellers)
    if len(resold) != len(want) or not all(
        any(_payee_hex(x.get("account")) == r.hex() and x.get("commission_bps") == bps for x in resold) for r, bps in want
    ):
        raise fail("reseller legs")
    return a


class MemoryChargeStore:
    """Where a seller records the payments it has served, in this process's memory, so each unlocks one
    request once. Any object with the same ``claim`` shared by every server of a seller makes that hold
    across them."""

    def __init__(self) -> None:
        self._used: dict[str, str] = {}

    def claim(self, payment_id: str, request: str) -> bool:
        """``True`` the first time ``payment_id`` is claimed, ``False`` ever after."""
        if payment_id in self._used:
            return False
        self._used[payment_id] = request
        return True


@dataclass
class LedgerQuote:
    """A quote with the asset chosen."""

    payee: bytes
    request: str
    request_digest: bytes
    usd_e6: int
    assets: list
    chosen: AssetQuote
    #: The commissions the payment carries (account, bps), signed with it.
    resellers: tuple = ()


@dataclass
class PaidPayment:
    """A settled payment and the record the chain holds for it."""

    expected: ExpectedPayment
    record: dict = field(default_factory=dict)


def _reseller_json(resellers: Sequence[tuple[bytes, int]]) -> list:
    return [{"reseller": list(r), "commission_bps": bps} for r, bps in resellers]


def _b32(value: str, what: str) -> bytes:
    b = bytes.fromhex(value.removeprefix("0x"))
    if len(b) != 32:
        raise PaymentError("invalid_asset", f"{what} is 32 bytes of hex")
    return b


class LedgerPayments:
    """Quote, pay and verify ledger payments over one or more node endpoints (receipts on the first two)."""

    def __init__(self, rpcs: Sequence[Any], backoff_s: float = 0.25, charges: Any = None):
        if not rpcs:
            raise ValueError("at least one endpoint")
        self.rpcs = list(rpcs)
        self.backoff_s = backoff_s
        #: Where :meth:`charge` records the payments it has served.
        self.charges = charges if charges is not None else MemoryChargeStore()

    def _lookup(self, i: int, pid: str) -> Any:
        return self.rpcs[i % len(self.rpcs)].call("tenzro_getPayment", {"payment_id": pid, "exact": True})

    def quote(self, payee: str, price: str, request: str, accept: Sequence[str],
              resellers: Sequence[tuple[bytes, int]] = ()) -> LedgerQuote:
        """What ``price`` (a decimal in USD) costs in each of ``accept`` now, the operator price and each
        reseller commission disclosed apart; chooses the first that can settle."""
        usd_e6 = parse_price_e6(price)
        params: dict = {"usd_e6": usd_e6, "accept": list(accept)}
        if resellers:
            params["resellers"] = _reseller_json(resellers)
        response = self.rpcs[0].call("tenzro_quotePayment", params)
        assets = read_quote_assets(response)
        return LedgerQuote(_b32(payee, "payee"), request, request_digest(request), usd_e6, assets,
                           choose_asset(assets, accept), tuple(resellers))

    def pay(self, q: LedgerQuote, signer: Any, idempotency_key: str, account: str | None = None) -> PaidPayment:
        """Pays a quote: signs the chosen asset and amount, has a node relay it, and waits for the record.
        A retry with the same idempotency key looks the payment up first and never pays twice."""
        public_key = signer.p256_public_key()
        payer = _b32(account, "account") if account else account_address(public_key)
        pid = payment_id(idempotency_key, payer, q.payee, q.request_digest)
        expected = ExpectedPayment(pid, q.payee.hex(), q.chosen.asset, q.chosen.amount, q.request, q.resellers)
        existing = self._lookup(0, pid)
        if existing:
            return PaidPayment(expected, existing)
        chain_id = int(self.rpcs[0].call("eth_chainId", []), 16)
        message = ledger_authorization_message(
            chain_id=chain_id,
            payment_id=pid,
            payer=payer,
            payee=q.payee,
            max_amount=q.chosen.amount,
            asset=q.chosen.asset,
            request_digest=q.request_digest,
            usd_e6=q.usd_e6,
            resellers=q.resellers,
        )
        classical, ml_dsa = signer.sign_composite(
            composite_message_representative(PAYMENT_AUTHORIZATION_CONTEXT, message)
        )
        params = {
            "payee": q.payee.hex(),
            "amount": str(q.chosen.amount),
            "payment": {
                "payer": payer.hex(),
                "payment_id": pid,
                "authorization": {
                    "public_key": bytes(public_key).hex(),
                    "signature": composite_signature_json(classical, ml_dsa),
                    "max_amount": str(q.chosen.amount),
                    "asset": q.chosen.asset,
                    "binding": {
                        "request_digest": q.request_digest.hex(),
                        "quote_digest": bytes(32).hex(),
                        "usd_e6": q.usd_e6,
                        "app_margin": None,
                    },
                    "resellers": _reseller_json(q.resellers),
                },
            },
        }
        wait = self.backoff_s
        last: Exception | None = None
        for i in range(4):
            try:
                self.rpcs[i % len(self.rpcs)].call("tenzro_settle", params)
                last = None
                break
            except Exception as e:  # transport or node refusal: look first, then retry
                last = e
                try:
                    settled = self._lookup(i, pid)
                except Exception:
                    settled = None
                if settled:
                    return PaidPayment(expected, settled)
                time.sleep(wait)
                wait *= 2
        if last is not None:
            raise PaymentError("settlement_failed", f"the payment was not settled: {last}")
        for i in range(30):
            record = self._lookup(i, pid)
            if record:
                return PaidPayment(expected, record)
            time.sleep(self.backoff_s)
        raise PaymentError("receipt_missing", f"payment {pid} was submitted and is not yet recorded")

    def verify_receipt(self, expected: ExpectedPayment) -> dict:
        """Checks a payment's record on two endpoints."""
        if len(self.rpcs) < 2:
            raise PaymentError("receipt_unverified", "a receipt is checked on two endpoints")
        return check_receipt(expected, self._lookup(0, expected.payment_id), self._lookup(1, expected.payment_id))

    def pay_for(self, request: str, payee: str, price: str, accept: Sequence[str], signer: Any,
                idempotency_key: str, account: str | None = None,
                resellers: Sequence[tuple[bytes, int]] = ()) -> PaidPayment:
        """Quote, pay and verify in one call, through ``resellers`` when given."""
        paid = self.pay(self.quote(payee, price, request, accept, resellers), signer, idempotency_key, account)
        if len(self.rpcs) >= 2:
            paid.record = self.verify_receipt(paid.expected)
        return paid

    def charge(self, request: str, payment_id_: str | None, payee: str, price: str,
               reseller: tuple[bytes, int] | None = None) -> dict | None:
        """Seller side: the record when the payment ``payment_id_`` on chain, checked on two endpoints,
        pays ``payee`` at least ``price`` for ``request`` and is presented for the first time
        (:attr:`charges`); ``None`` to answer 402."""
        owed = parse_price_e6(price)
        if not payment_id_:
            return None
        if len(self.rpcs) < 2:
            raise PaymentError("receipt_unverified", "a charge checks payments on two endpoints")
        a, b = self._lookup(0, payment_id_), self._lookup(1, payment_id_)
        if a is None or b is None:
            return None
        if a != b:
            raise PaymentError("receipt_mismatch", "the two endpoints return different records")
        paid_for = request_digest(request).hex()
        if (
            _payee_hex(a.get("payee")) == payee.removeprefix("0x").lower()
            and (a.get("binding") or {}).get("request_digest") == paid_for
            and int(a.get("value_units") or 0) >= owed
            and (
                reseller is None
                or any(
                    x.get("role") == "reseller"
                    and _payee_hex(x.get("account")) == reseller[0].hex()
                    and x.get("commission_bps") == reseller[1]
                    for x in a.get("legs") or []
                )
            )
            and self.charges.claim(payment_id_, request)
        ):
            return a
        return None
