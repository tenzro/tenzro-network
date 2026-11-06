"""Requests to an account's opt-in outflow policy (a cap per window, a hold and
an optional guardian), and a plain-language preview of each to show before
signing. The same wire form and wording as the node's
``tenzro_types::account_outflow_ui`` and the Rust and TypeScript SDKs; the
rules are the chain's, in its ``account_outflow`` module.

Send a request with ``TypedTxClient.send(signer, outflow_transaction(...))``; a
guardian sends from its own account, naming the guarded account.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .typed_tx import TypedTransaction

ONE_TNZO = 10**18


@dataclass(frozen=True)
class OutflowPolicy:
    window_ms: int
    cap: int
    hold_ms: int
    guardian: str | None = None
    pending: dict[str, Any] | None = None

    @staticmethod
    def from_rpc(v: dict[str, Any] | None) -> "OutflowPolicy | None":
        """Read the ``policy`` of a ``tenzro_getAccountOutflow`` answer."""
        if not v:
            return None
        return OutflowPolicy(v["window_ms"], int(v["cap"]), v["hold_ms"], v.get("guardian"), v.get("pending"))


def _op(name: str, account: bytes, **fields: Any) -> dict[str, Any]:
    return {"op": name, "account": list(account), **fields}


def set_policy(account: bytes, window_ms: int, cap: int, hold_ms: int, guardian: str | None = None) -> dict[str, Any]:
    """``guardian`` is a person's identity (DID) whose passkey approves a cancel or an early payment."""
    return _op("set", account, window_ms=window_ms, cap=str(cap), hold_ms=hold_ms, guardian=guardian)


def remove_policy(account: bytes) -> dict[str, Any]:
    return _op("remove", account)


def cancel_pending(account: bytes, approval: dict[str, Any] | None = None) -> dict[str, Any]:
    """``approval`` is the guardian's passkey approval when the guardian cancels."""
    return _op("cancel_pending", account, approval=approval)


def request_release(account: bytes, to: bytes, amount: int) -> dict[str, Any]:
    return _op("request_release", account, to=list(to), amount=str(amount))


def cancel_release(account: bytes, release_id: int, approval: dict[str, Any] | None = None) -> dict[str, Any]:
    return _op("cancel_release", account, id=release_id, approval=approval)


def claim_release(account: bytes, release_id: int, approval: dict[str, Any] | None = None) -> dict[str, Any]:
    """The guardian passes ``approval`` to pay before the hold ends."""
    return _op("claim_release", account, id=release_id, approval=approval)


def approval_target(account: bytes, action: str, release_id: int, step: int) -> bytes:
    """The bytes a guardian's passkey signs; ``step`` is ``approval_step`` from the node's answer."""
    a = action.encode()
    return (len(account).to_bytes(4, "big") + account + len(a).to_bytes(4, "big") + a
            + release_id.to_bytes(8, "big") + step.to_bytes(8, "big"))


def outflow_transaction(op: dict[str, Any]) -> TypedTransaction:
    """The transaction carrying ``op``, for ``TypedTxClient.send``."""
    # The chain's operation is externally tagged: {"set": {...fields}}.
    body = {k: v for k, v in op.items() if k != "op"}
    raw = json.dumps({op["op"]: body}, separators=(",", ":")).encode()
    return TypedTransaction(kind="AccountOutflow", fields={"op": list(raw)})


def _tnzo(wei: int) -> str:
    whole, frac = divmod(wei, ONE_TNZO)
    if frac == 0:
        return f"{whole} TNZO"
    return f"{whole}.{str(frac).rjust(18, '0').rstrip('0')} TNZO"


def _span(ms: int) -> str:
    m = ms // 60000
    if m >= 2 * 24 * 60:
        return f"{m // 1440} days"
    if m >= 120:
        return f"{m // 60} hours"
    if m >= 1:
        return f"{m} minutes"
    return "under a minute"


def _at(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def loosens(cur: OutflowPolicy, window_ms: int, cap: int, hold_ms: int, guardian: str | None) -> bool:
    """Whether the new values loosen ``cur`` (the chain queues those for the hold)."""
    return (
        cap * cur.window_ms > cur.cap * window_ms
        or hold_ms < cur.hold_ms
        or (cur.guardian is not None and guardian != cur.guardian)
    )


def describe(op: dict[str, Any], current: OutflowPolicy | None, now_ms: int) -> list[str]:
    """Plain-language lines to show before signing ``op``."""
    who = " or your guardian" if current and current.guardian else ""
    kind = op["op"]
    if kind == "set":
        g = op.get("guardian") or None
        cap, win, hold = int(op["cap"]), op["window_ms"], op["hold_ms"]
        out = [
            f"Cap: this account can send at most {_tnzo(cap)} per {_span(win)}.",
            f"Hold: a larger payment is queued and waits {_span(hold)} before it can be paid. "
            f"You{' or your guardian' if g else ''} can cancel it meanwhile.",
            (f"Guardian: {g} can cancel a queued payment and can approve one at once, each with their own passkey. "
             "Choose a person whose passkey is on different hardware from this account's.") if g else
            ("No guardian: only this account can cancel or approve. A thief holding its key could also "
             "approve a queued payment once the hold ends, so the hold is your only protection."),
        ]
        if current is None:
            out.append("A first policy takes effect at once.")
        elif loosens(current, win, cap, hold, g):
            out.append(f"This loosens the policy, so it is queued for the current hold ({_span(current.hold_ms)}) "
                       f"and takes effect at {_at(now_ms + current.hold_ms)}. You{who} can cancel it until then.")
        else:
            out.append("This tightens the policy, so it takes effect at once.")
        return out
    if kind == "remove":
        hold = current.hold_ms if current else 0
        return [f"Remove the outflow policy. This is queued for the current hold ({_span(hold)}) and takes "
                f"effect at {_at(now_ms + hold)}; until then the cap still applies. You{who} can cancel it."]
    if kind == "cancel_pending":
        return ["Cancel the queued change to this account's outflow policy. The policy stays as it is now."]
    if kind == "request_release":
        return [
            f"Queue a payment of {_tnzo(int(op['amount']))} to 0x{bytes(op['to']).hex()}.",
            (f"It can be paid at {_at(now_ms + current.hold_ms)} (after the {_span(current.hold_ms)} hold). "
             f"You{who} can cancel it until it is paid.") if current else
            "This account has no outflow policy, so a queued payment is refused.",
        ]
    if kind == "cancel_release":
        return [f"Cancel queued payment #{op['id']}. Nothing is sent; it leaves the queue."]
    if kind == "claim_release":
        return [f"Pay queued payment #{op['id']}. The account pays it once its hold has ended; "
                "its guardian may pay it at once, with their passkey approval."]
    raise ValueError(f"unknown outflow operation {kind}")


def creation_offer() -> list[str]:
    """What a wallet offers when it creates an account. Nothing is set unless the holder chooses to."""
    return [
        "Optional: protect this account with an outflow limit.",
        "You choose a cap per window and a hold. A payment above the cap is queued and waits the hold, and you can cancel it meanwhile.",
        "For the strongest protection name a guardian: a person whose passkey is on different hardware from this account's. The guardian can cancel, and can approve a payment at once.",
        "Nothing is set unless you set it: tenzro wallet outflow set --cap <TNZO> --guardian <did>",
    ]
