"""A publisher's policy: which paths are paid, at what USD price, in which
assets and schemes, and under which licence and content-usage terms. The same
policy renders the machine-readable licence (RSL), the robots.txt ``License:``
line and each response's ``Content-Usage`` (AIPREF) header.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: The default scheme order: a voucher on a channel, then a signed one-off payment.
DEFAULT_SCHEMES: tuple[str, ...] = ("batch-settlement", "tenzro-hybrid")


@dataclass(frozen=True)
class PaidRoute:
    """One paid path."""

    #: An exact path, or a prefix ending in ``*`` (``/articles/*``).
    path: str
    #: Price per request in USD micro-units (1 USD = 1_000_000).
    usd_e6: int
    #: Accepted schemes, most preferred first; empty means :data:`DEFAULT_SCHEMES`.
    schemes: tuple[str, ...] = ()
    #: The asset paid; ``TNZO`` when absent, priced at the consensus rate.
    asset: str | None = None
    #: A fixed amount in the asset's smallest unit, instead of quoting ``usd_e6``.
    amount: str | None = None
    #: Uses the licence permits for this path (RSL usage tokens, e.g. ``ai-input``).
    permits: tuple[str, ...] = ()
    #: Uses it prohibits (e.g. ``ai-train``).
    prohibits: tuple[str, ...] = ()
    #: What a payment licenses (RSL payment type): ``use``, ``crawl``, ``training`` or ``purchase``.
    licence_type: str | None = None
    #: The ``Content-Usage`` header value served with the path.
    content_usage: str | None = None
    #: Shown to payers with the requirement.
    description: str | None = None

    def accepted_schemes(self) -> tuple[str, ...]:
        return self.schemes or DEFAULT_SCHEMES

    def paid_asset(self) -> str:
        return self.asset or "TNZO"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PaidRoute:
        """A route from its JSON shape (the TypeScript and Rust SDKs' camelCase)."""
        return cls(
            path=d["path"],
            usd_e6=int(d["usdE6"]),
            schemes=tuple(d.get("schemes") or ()),
            asset=d.get("asset"),
            amount=d.get("amount"),
            permits=tuple(d.get("permits") or ()),
            prohibits=tuple(d.get("prohibits") or ()),
            licence_type=d.get("licenceType"),
            content_usage=d.get("contentUsage"),
            description=d.get("description"),
        )


@dataclass(frozen=True)
class PublisherPolicy:
    """A publisher's whole policy."""

    #: The Tenzro chain payments settle on.
    chain_id: int
    #: The Tenzro account paid (hex). Payouts reach whatever the account's passkey controls.
    pay_to: str
    #: Base URL of the x402 facilitator that verifies and settles, such as one
    #: a harness runs beside the publisher.
    facilitator: str
    #: Paid paths. Unlisted paths are free.
    routes: tuple[PaidRoute, ...] = field(default_factory=tuple)
    #: Charge requests that carry no agent signature too. Default: people browse free.
    charge_unsigned: bool = False
    #: Seconds a payer has to answer a requirement; 300 when absent.
    max_timeout_seconds: int | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PublisherPolicy:
        """A policy from its JSON shape (the TypeScript and Rust SDKs' camelCase)."""
        return cls(
            chain_id=int(d["chainId"]),
            pay_to=d["payTo"],
            facilitator=d["facilitator"],
            routes=tuple(PaidRoute.from_dict(r) for r in d.get("routes", ())),
            charge_unsigned=bool(d.get("chargeUnsigned", False)),
            max_timeout_seconds=d.get("maxTimeoutSeconds"),
        )


def match_route(routes: tuple[PaidRoute, ...] | list[PaidRoute], pathname: str) -> PaidRoute | None:
    """The route ``pathname`` falls under: an exact path wins, then the longest prefix."""
    for r in routes:
        if not r.path.endswith("*") and r.path == pathname:
            return r
    best: PaidRoute | None = None
    for r in routes:
        if r.path.endswith("*") and pathname.startswith(r.path[:-1]) and (best is None or len(r.path) > len(best.path)):
            best = r
    return best


def _xml(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _usd(usd_e6: int) -> str:
    frac = f"{usd_e6 % 1_000_000:06d}".rstrip("0")
    whole = str(usd_e6 // 1_000_000)
    return f"{whole}.{frac}" if frac else whole


def rsl_xml(policy: PublisherPolicy, origin: str) -> str:
    """The policy as an RSL licence document, its content URLs on ``origin``."""
    base = origin.rstrip("/")
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<rsl xmlns="https://rslstandard.org/rsl">']
    for r in policy.routes:
        lines += [f'  <content url="{_xml(base + r.path)}">', "    <license>"]
        if r.permits:
            lines.append(f'      <permits type="usage">{_xml(" ".join(r.permits))}</permits>')
        if r.prohibits:
            lines.append(f'      <prohibits type="usage">{_xml(" ".join(r.prohibits))}</prohibits>')
        lines += [
            f'      <payment type="{r.licence_type or "use"}">',
            f'        <amount currency="USD">{_usd(r.usd_e6)}</amount>',
            "      </payment>",
            "    </license>",
            "  </content>",
        ]
    lines.append("</rsl>")
    return "\n".join(lines) + "\n"


def robots_license_line(origin: str, licence_path: str = "/license.xml") -> str:
    """The robots.txt line pointing crawlers at the licence."""
    return f"License: {origin.rstrip('/')}{licence_path}"


__all__ = [
    "DEFAULT_SCHEMES",
    "PaidRoute",
    "PublisherPolicy",
    "match_route",
    "robots_license_line",
    "rsl_xml",
]
