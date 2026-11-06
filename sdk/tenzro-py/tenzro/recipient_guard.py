"""Recipient checks before a transfer is signed: first-time recipient friction
and look-alike (address poisoning) detection. The same rules as
``tenzro_types::recipient_guard``. The byte counts are the governed parameters
``wallet.recipient_lookalike_prefix_bytes`` and
``wallet.recipient_lookalike_suffix_bytes``, read from ``tenzro_getNetworkParams``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

PREFIX_BYTES_PARAM = "wallet.recipient_lookalike_prefix_bytes"
SUFFIX_BYTES_PARAM = "wallet.recipient_lookalike_suffix_bytes"
DEFAULT_PREFIX_BYTES = 3
DEFAULT_SUFFIX_BYTES = 3

FIRST_TIME_RECIPIENT = "first_time_recipient"
LOOKS_LIKE = "looks_like"
SEEN_ONLY_AS_INBOUND_SENDER = "seen_only_as_inbound_sender"


@dataclass(frozen=True)
class LookalikeParams:
    prefix_bytes: int = DEFAULT_PREFIX_BYTES
    suffix_bytes: int = DEFAULT_SUFFIX_BYTES


@dataclass(frozen=True)
class RecipientAssessment:
    full_address: str
    flags: tuple[tuple[str, str | None], ...] = field(default_factory=tuple)
    describe: tuple[str, ...] = field(default_factory=tuple)

    @property
    def requires_full_address_confirmation(self) -> bool:
        return bool(self.flags)

    @property
    def is_lookalike(self) -> bool:
        return any(kind == LOOKS_LIKE for kind, _ in self.flags)


def _norm(a: str) -> str:
    a = a.strip().lower()
    return a[2:] if a.startswith("0x") else a


def _alike(a: str, b: str, p: LookalikeParams) -> bool:
    if a == b or len(a) != len(b):
        return False
    pre, suf = min(p.prefix_bytes * 2, len(a)), min(p.suffix_bytes * 2, len(a))
    if pre + suf == 0:
        return False
    return a[:pre] == b[:pre] and a[len(a) - suf :] == b[len(b) - suf :]


def assess_recipient(
    recipient: str,
    trusted: Iterable[str],
    inbound_only: Iterable[str] = (),
    params: LookalikeParams = LookalikeParams(),
) -> RecipientAssessment:
    to = _norm(recipient)
    tr = [_norm(t) for t in trusted]
    flags: list[tuple[str, str | None]] = []
    if to not in tr:
        flags.append((FIRST_TIME_RECIPIENT, None))
        near = next((t for t in tr if _alike(to, t, params)), None)
        if near is not None:
            flags.append((LOOKS_LIKE, near))
        if to in [_norm(s) for s in inbound_only]:
            flags.append((SEEN_ONLY_AS_INBOUND_SENDER, None))
    lines = [f"Recipient: 0x{to}"]
    for kind, other in flags:
        if kind == FIRST_TIME_RECIPIENT:
            lines.append("First payment to this address from this account: compare every character.")
        elif kind == LOOKS_LIKE:
            lines.append(
                f"This address looks like a trusted one (0x{other}) but is a different address. "
                "This is how address poisoning works: do not send unless you meant this one."
            )
        else:
            lines.append(
                "This address has only ever sent to you. Copying an address from your history "
                "is how address poisoning works."
            )
    return RecipientAssessment(to, tuple(flags), tuple(lines))


def confirmation_matches(assessment: RecipientAssessment, typed: str) -> bool:
    """Whether ``typed`` is the full address; a shortened form never matches."""
    return _norm(typed) == assessment.full_address


def assess_recipient_from_node(rpc: Any, from_hex: str, to: str) -> RecipientAssessment:
    """Assess ``to`` for ``from_hex`` from the node's history and the governed
    thresholds. ``rpc`` has ``call(method, params)``."""

    def governed(key: str) -> int | None:
        try:
            return int(rpc.call("tenzro_getNetworkParams", {"key": key})["value"])
        except Exception:
            return None

    params = LookalikeParams(
        governed(PREFIX_BYTES_PARAM) or DEFAULT_PREFIX_BYTES,
        governed(SUFFIX_BYTES_PARAM) or DEFAULT_SUFFIX_BYTES,
    )
    history = rpc.call("tenzro_getTransactionHistory", {"address": from_hex, "limit": 500})
    me = _norm(from_hex)
    trusted: list[str] = []
    senders: list[str] = []
    for tx in history.get("transactions", []):
        f, t = tx.get("from"), tx.get("to")
        if not f or not t:
            continue
        if _norm(f) == me:
            trusted.append(t)
        elif _norm(t) == me:
            senders.append(f)
    tset = {_norm(x) for x in trusted}
    return assess_recipient(to, trusted, [s for s in senders if _norm(s) not in tset], params)
