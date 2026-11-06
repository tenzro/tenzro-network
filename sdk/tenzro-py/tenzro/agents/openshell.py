"""OpenShell sandboxes on Tenzro: the Terms a sandbox's agent is delegated under, the
provider credential the gateway attaches, and the signed records of what the Tenzro
extensions decided, verified offline.

Terms are held by Tenzro and approved by the controller's passkey. The policy's ``tenzro``
network middleware takes no config: it only routes the sandbox's traffic through the
extensions, which read the agent's Terms from Tenzro on every decision.

Every decision is a tenzro-types agent audit entry, signed by a session key that the serving
node's hardware identity certified. An entry is ``{"body": <hex of the entry JSON>,
"signature": <hex of the SessionSignature JSON>}``; entries of one session are numbered from
0, each chained to the leaf hash of the one before, and the session's root is the MMR root of
their leaf hashes. A session is named by SHA-256("tenzro/openshell/session/v1" || 0x00 ||
gateway || 0x00 || name), the name being a sandbox, or the agent's DID for its model calls.

Verifying signatures needs the ``cryptography`` package, 50 or later for ML-DSA-65
(``pip install tenzro[verify]``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import time
from typing import Any

from ..rpc import RpcClient
from ..wallet import COMPOSITE_LABEL_MLDSA65_P256, composite_message_representative
from .terms import AgentTerms, Authorize, delegate_agent

SESSION_DOMAIN = b"tenzro/openshell/session/v1\x00"
_CERTIFICATE_CONTEXT = b"tenzro/session/certificate"
_HYBRID_SESSION_CONTEXT = b"tenzro/session/ml-dsa-65"
_ML_DSA_65_VK_LEN = 1952
_ML_DSA_65_SIG_LEN = 3309
_KEY_TYPE_TAGS = {"Ed25519": 0, "Secp256k1": 1, "Ed25519MlDsa65": 2}

#: The middleware name the Tenzro supervisor middleware registers under.
OPENSHELL_TENZRO_MIDDLEWARE = "tenzro"

#: The payment rails a sandbox may use, as Terms name them.
OPENSHELL_PAYMENT_PROTOCOLS = ("x402", "mpp", "ap2")

#: The sandbox annotation that names the agent a sandbox runs.
OPENSHELL_AGENT_ANNOTATION = "tenzro.agent"

#: The response header that carries the signed record of a model call.
OPENSHELL_RECEIPT_HEADER = "x-tenzro-receipt"

_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def openshell_terms(policy: dict[str, Any], grant: dict[str, Any], options: dict[str, Any]) -> AgentTerms:
    """The Terms to ask Tenzro for, from an explicit ``grant``, checked against the sandbox
    ``policy``: the policy routes through exactly one ``tenzro`` middleware, which carries no
    config and does not fail open, and every payment service is an endpoint of its network
    policy. Refuses open limits or payees, rails Terms do not know and wildcard models. Every
    sandbox may be created and reach its endpoints; policy changes, tool calls, inference and
    payments are granted only when asked for."""
    mws = [m for m in (policy.get("network_middlewares") or {}).values() if (m or {}).get("middleware") == OPENSHELL_TENZRO_MIDDLEWARE]
    if not mws:
        raise ValueError("the policy has no tenzro middleware")
    if len(mws) > 1:
        raise ValueError("the policy names the tenzro middleware twice")
    if "config" in mws[0]:
        raise ValueError("the tenzro middleware takes no config: Terms stay on Tenzro")
    if "on_error" in mws[0] and mws[0]["on_error"] != "fail_closed":
        raise ValueError("the tenzro middleware must fail closed")
    models = list(grant.get("models") or [])
    if any(not m or "*" in m for m in models):
        raise ValueError("models must be named")
    pay = grant.get("payments") or {}
    protocols = [p.lower() for p in pay.get("protocols") or []]
    for p in protocols:
        if p not in OPENSHELL_PAYMENT_PROTOCOLS:
            raise ValueError(f"payment protocol {p} is not one of {', '.join(OPENSHELL_PAYMENT_PROTOCOLS)}")
    payees: list[str] = []
    if protocols and pay.get("any_payee") is not True:
        payees = list(pay.get("payees") or [])
        if not payees:
            raise ValueError("name the payees or set any_payee")
        for a in payees:
            if not isinstance(a, str) or not _ADDRESS.match(a):
                raise ValueError(f"payee {a} is not a 20-byte hex address")
        payees = [a.lower() for a in payees]
    services = list(pay.get("services") or [])
    if services and not protocols:
        raise ValueError("payment services need a payment rail")
    hosts = {
        ep["host"].lower()
        for np in (policy.get("network_policies") or {}).values()
        for ep in (np.get("endpoints") or [])
    }
    for s in services:
        if s.lower() not in hosts:
            raise ValueError(f"payment service {s} is not an endpoint of the network policy")
    for k in ("max_transaction_value", "max_daily_spend"):
        v = grant.get(k)
        if not isinstance(v, str) or not _DECIMAL.match(v):
            raise ValueError(f"{k} is not a canonical decimal")
    if int(grant["max_transaction_value"]) > int(grant["max_daily_spend"]):
        raise ValueError("max_transaction_value is above max_daily_spend")
    secs = grant.get("expires_in_secs")
    if not isinstance(secs, int) or isinstance(secs, bool) or secs <= 0:
        raise ValueError("expires_in_secs must be a positive whole number")
    operations = ["sandbox", "fetch"]
    if grant.get("policy_changes") is True:
        operations.append("sandbox.policy")
    if grant.get("tools") is True:
        operations.append("tool")
    if models:
        operations.append("inference")
    if protocols:
        operations.append("pay")
    now_ms = options.get("now_ms")
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    terms: dict[str, Any] = {
        "controller_did": options["controller_did"],
        "agent_name": options["agent_name"],
        "delegation_scope": {
            "max_transaction_value": grant["max_transaction_value"],
            "max_daily_spend": grant["max_daily_spend"],
            "allowed_operations": operations,
            "allowed_payment_protocols": protocols,
            "allowed_chains": list(grant.get("chains") or ["tenzro"]),
            "allowed_models": models,
            "allowed_counterparties": payees,
        },
        "capabilities": list(options.get("capabilities") or []),
        "serving_nodes": list(options["serving_nodes"]),
        "expires_at_ms": now_ms + secs * 1000,
    }
    if options.get("min_distinct_operators") is not None:
        terms["min_distinct_operators"] = options["min_distinct_operators"]
    return terms  # type: ignore[return-value]


def openshell_session_id(gateway: str, name: str) -> str:
    """The session id of ``name`` (a sandbox, or an agent DID) on ``gateway``, hex."""
    return hashlib.sha256(SESSION_DOMAIN + gateway.encode() + b"\x00" + name.encode()).hexdigest()


def mint_openshell_credential(
    rpc: RpcClient,
    account_address: str,
    policy: dict[str, Any],
    grant: dict[str, Any],
    options: dict[str, Any],
    authorize: Authorize,
) -> dict[str, Any]:
    """Delegate the sandbox's agent under the Terms ``grant`` asks for, approved by the
    controller's passkey (``authorize``), and return the provider record and annotation its
    sandbox is created with. The provider's one credential, ``TENZRO_AGENT_TOKEN``, is the
    agent's DID: the Tenzro credential driver mints a short-lived token from it on every
    resolve, and neither reaches the sandbox's environment."""
    terms = openshell_terms(policy, grant, options)
    delegated = delegate_agent(rpc, account_address, terms, authorize)
    did = ((delegated or {}).get("identity") or {}).get("did")
    if not did:
        raise ValueError("the node returned no agent DID")
    return {
        "agent_did": did,
        "provider": {"name": "tenzro", "type": "tenzro", "credentials": {"TENZRO_AGENT_TOKEN": did}},
        "annotation": {OPENSHELL_AGENT_ANNOTATION: did},
        "delegated": delegated,
    }


def parse_openshell_entries(text: str) -> list[dict[str, str]]:
    """Signed entries from JSON Lines (one per line) or a JSON array."""
    t = text.strip()
    rows = json.loads(t) if t.startswith("[") else [json.loads(line) for line in t.splitlines() if line.strip()]
    out = []
    for i, r in enumerate(rows):
        if not isinstance(r, dict) or not isinstance(r.get("body"), str) or not isinstance(r.get("signature"), str):
            raise ValueError(f"entry {i} is not a signed entry")
        out.append({"body": r["body"], "signature": r["signature"]})
    return out


def _strip(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _bag(peaks: list[bytes]) -> bytes:
    if not peaks:
        return bytes(32)
    acc = peaks[-1]
    for p in reversed(peaks[:-1]):
        acc = _node(p, acc)
    return acc


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise RuntimeError("verifying OpenShell records needs the cryptography package: pip install tenzro[verify]") from e
    return InvalidSignature, hashes, ec, ed25519


def _ml_dsa_verify(vk: bytes, ctx: bytes, msg: bytes, sig: bytes) -> bool:
    if len(vk) != _ML_DSA_65_VK_LEN or len(sig) != _ML_DSA_65_SIG_LEN:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as e:
        raise RuntimeError(
            "this record carries an ML-DSA-65 signature, and verifying it needs cryptography 50 or later: "
            "pip install tenzro[verify]"
        ) from e
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(vk).verify(sig, msg, ctx)
        return True
    except InvalidSignature:
        return False


def _bytes(v: Any, what: str) -> bytes:
    if not isinstance(v, list) or any(not isinstance(x, int) or isinstance(x, bool) or not 0 <= x <= 255 for x in v):
        raise ValueError(f"{what} is not a byte array")
    return bytes(v)


def _raw_p256(sig: bytes) -> tuple[int, int]:
    if len(sig) == 64:
        return int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    try:
        return decode_dss_signature(sig)
    except ValueError as e:
        raise ValueError("the P-256 leg is neither raw r || s nor DER") from e


def _verify_composite(identity: dict[str, Any], message: bytes, sig: dict[str, Any]) -> bool:
    InvalidSignature, hashes, ec, _ = _crypto()
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    classical = (sig or {}).get("classical") or {}
    if classical.get("form") != "raw" or not isinstance(classical.get("signature"), str):
        raise ValueError("the certificate's P-256 leg is not a raw hardware signature")
    m = composite_message_representative(_CERTIFICATE_CONTEXT, message)
    xy = bytes.fromhex(_strip(identity["p256"]))
    if len(xy) != 64:
        raise ValueError("the identity's P-256 key is not x || y")
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + xy)
    r, s = _raw_p256(bytes.fromhex(_strip(classical["signature"])))
    try:
        key.verify(encode_dss_signature(r, s), m, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    pq = bytes.fromhex(_strip(sig["pq"])) if sig.get("pq") is not None else None
    enrolled = bytes.fromhex(_strip(identity["pq"])) if identity.get("pq") else None
    if pq is not None and enrolled is None:
        raise ValueError("ML-DSA-65 leg present for an identity with no ML-DSA-65 key")
    if enrolled is not None and pq is None:
        return False
    if pq is not None and enrolled is not None:
        return _ml_dsa_verify(enrolled, COMPOSITE_LABEL_MLDSA65_P256, m, pq)
    return True


def _verify_session_key(key: dict[str, Any], message: bytes, sig: dict[str, Any]) -> bool:
    InvalidSignature, _, _, ed25519 = _crypto()
    k = _bytes(key.get("bytes"), "the session key")
    s = _bytes((sig or {}).get("bytes"), "the session signature")

    def ed(pk: bytes, sg: bytes) -> bool:
        if len(pk) != 32 or len(sg) != 64:
            return False
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sg, message)
            return True
        except InvalidSignature:
            return False

    if key.get("key_type") == "Ed25519":
        return sig.get("key_type") == "Ed25519" and ed(k, s)
    if key.get("key_type") == "Ed25519MlDsa65":
        if sig.get("key_type") != "Ed25519MlDsa65" or len(k) != 32 + _ML_DSA_65_VK_LEN or len(s) <= 64:
            return False
        return ed(k[:32], s[:64]) and _ml_dsa_verify(k[32:], _HYBRID_SESSION_CONTEXT, message, s[64:])
    return False


def verify_openshell_signature(
    body: bytes,
    signature: bytes,
    at_ms: int,
    identity: dict[str, Any],
    hybrid_records_from_ms: int | None = None,
) -> bool:
    """Check one session signature over ``body`` made at ``at_ms``: ``identity`` (``{"p256":
    x||y hex, "pq": ML-DSA-65 hex}``) certified the session key, the certificate was valid at
    ``at_ms``, the session key signed ``body``, and a record made once hybrid records are in
    force (``hybrid_records_from_ms``, from chain state; not in force when None) carries a
    hybrid session key. Returns whether the session key is hybrid."""
    try:
        s = json.loads(signature)
    except ValueError as e:
        raise ValueError("the signature is not a session signature") from e
    cert = (s or {}).get("certificate") or {}
    key = cert.get("session_key") or {}
    key_type = key.get("key_type")
    if key_type not in ("Ed25519", "Ed25519MlDsa65"):
        raise ValueError("a session key must be Ed25519 or Ed25519 with ML-DSA-65")
    hybrid = key_type == "Ed25519MlDsa65"
    if hybrid_records_from_ms is not None and at_ms >= hybrid_records_from_ms and not hybrid:
        raise ValueError(f"a record made at {at_ms} ms needs a hybrid session signature")
    not_after = cert.get("not_after_ms")
    if not isinstance(not_after, int) or isinstance(not_after, bool):
        raise ValueError("the certificate names no expiry")
    if at_ms > not_after:
        raise ValueError(f"the session certificate expired at {not_after} ms, before {at_ms} ms")
    p256 = bytes.fromhex(_strip(identity["p256"]))
    pq = bytes.fromhex(_strip(identity["pq"])) if identity.get("pq") else None
    sk = _bytes(key.get("bytes"), "the session key")
    message = struct.pack("<I", len(p256)) + p256
    message += (b"\x01" + struct.pack("<I", len(pq)) + pq) if pq is not None else b"\x00"
    message += bytes([_KEY_TYPE_TAGS[key_type]]) + struct.pack("<I", len(sk)) + sk + struct.pack("<Q", not_after)
    if not _verify_composite(identity, message, cert.get("signature") or {}):
        raise ValueError("the session certificate does not verify under the identity")
    if not _verify_session_key(key, body, s.get("signature") or {}):
        raise ValueError("the session signature does not verify")
    return hybrid


def _decode(body: bytes, i: int) -> dict[str, Any]:
    try:
        return json.loads(body)
    except ValueError as e:
        raise ValueError(f"entry {i} is not an agent audit entry") from e


def _leaf(body: bytes, signature: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + struct.pack("<Q", len(body)) + body + signature).digest()


def _record(e: dict[str, Any], leaf: str, hybrid: bool) -> dict[str, Any]:
    r = {
        "session_id": _strip(str(e["session_id"])).lower(),
        "seq": e["seq"],
        "at_ms": e["at_ms"],
        "agent": e["agent"],
        "kind": e["kind"],
        "action": e["action"],
        "outcome": e["outcome"],
        "detail": e["detail"],
        "leaf": leaf,
        "hybrid": hybrid,
    }
    for k in ("linked_tx", "image", "call"):
        if k in e:
            r[k] = e[k]
    return r


def verify_openshell_session(
    entries: list[dict[str, str]],
    identity: dict[str, Any],
    hybrid_records_from_ms: int | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Verify a session from its entries alone, as the extensions' own verifier does: every
    entry signed under a session key ``identity`` certified, numbered from 0 with no gap, of one
    session and one agent, each chained to the leaf hash of the entry before it. Returns
    ``{session_id, agent, count, root, entries}``."""
    if not entries:
        raise ValueError("the session has no entries")
    session = _strip(session_id).lower() if session_id else None
    agent = None
    prev = "00" * 32
    peaks: list[tuple[int, bytes]] = []
    out = []
    for i, entry in enumerate(entries):
        body = bytes.fromhex(_strip(entry["body"]))
        signature = bytes.fromhex(_strip(entry["signature"]))
        e = _decode(body, i)
        try:
            hybrid = verify_openshell_signature(body, signature, e["at_ms"], identity, hybrid_records_from_ms)
        except ValueError as err:
            raise ValueError(f"entry {i}: {err}") from err
        if e.get("seq") != i:
            raise ValueError(f"entry {i} is numbered {e.get('seq')}")
        if _strip(str(e.get("prev"))).lower() != prev:
            raise ValueError(f"entry {i} does not chain to the entry before it")
        sid = _strip(str(e["session_id"])).lower()
        session = session or sid
        if sid != session:
            raise ValueError(f"entry {i} names another session")
        agent = agent if agent is not None else e["agent"]
        if e["agent"] != agent:
            raise ValueError(f"entry {i} names another agent")
        leaf = _leaf(body, signature)
        prev = leaf.hex()
        h, node = 0, leaf
        while peaks and peaks[-1][0] == h:
            node = _node(peaks.pop()[1], node)
            h += 1
        peaks.append((h, node))
        out.append(_record(e, prev, hybrid))
    return {
        "session_id": session,
        "agent": agent,
        "count": len(out),
        "root": _bag([p for _, p in peaks]).hex(),
        "entries": out,
    }


def verify_openshell_receipt(
    header: str, identity: dict[str, Any], hybrid_records_from_ms: int | None = None
) -> dict[str, Any]:
    """Verify the signed record a model call returns in ``x-tenzro-receipt`` (base64url of the
    signed entry's JSON): its signature only, as one entry of the agent's session."""
    h = header.strip()
    raw = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    entry = parse_openshell_entries(json.dumps([raw]))[0]
    body = bytes.fromhex(_strip(entry["body"]))
    signature = bytes.fromhex(_strip(entry["signature"]))
    e = _decode(body, 0)
    hybrid = verify_openshell_signature(body, signature, e["at_ms"], identity, hybrid_records_from_ms)
    return _record(e, _leaf(body, signature).hex(), hybrid)


def openshell_payments(session: dict[str, Any]) -> list[dict[str, Any]]:
    """The payments of a verified session, in order: every ``spend`` entry (action
    ``"<rail> <url>"``) and every model call that names the settlement of its charge."""
    out = []
    for e in session["entries"]:
        if e["kind"] == "spend":
            rail, sep, target = e["action"].partition(" ")
            if not sep or not rail:
                raise ValueError(f"entry {e['seq']} names no payment rail")
        elif e["kind"] == "model_call" and e.get("linked_tx"):
            rail, target = "inference", e["action"]
        else:
            continue
        out.append(
            {
                "seq": e["seq"],
                "at_ms": e["at_ms"],
                "rail": rail,
                "target": target,
                "outcome": e["outcome"],
                "linked_tx": e.get("linked_tx"),
            }
        )
    return out
