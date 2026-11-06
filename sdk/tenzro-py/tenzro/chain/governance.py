"""Offline verification of governance receipts.

:func:`verify_governance_receipt` checks a receipt (as
``tenzro_getGovernanceReceipt`` returns it) against the state root of a
checkpoint the caller holds as certified (from a light client, the finality
verifier, or ``tenzro governance receipt --verify``, which proves the
receipt's checkpoint from the genesis anchor). Nothing the node says is
trusted.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

STEM_LEN = 31
EMPTY = bytes(32)
SYSTEM_ADDRESS_HEX = "ff" * 20
_HEX = re.compile(r"^[0-9a-fA-F]*$")


class GovernanceReceiptError(ValueError):
    def __init__(self, msg: str):
        super().__init__(f"governance receipt: {msg}")


@dataclass(frozen=True)
class GovernanceReceiptReport:
    """What a verified governance receipt establishes, read from its proven records only."""

    #: The proposal record, as consensus stores it.
    proposal: dict[str, Any]
    #: The tally record, if a vote was cast.
    tally: dict[str, Any] | None
    #: TNZO locked in the veto escrow, base units.
    veto_locked: int
    #: Height the proposal was enacted at, if it was.
    executed_height: int | None
    #: The scheduled activation, for an enacted protocol upgrade.
    activation: dict[str, Any] | None


def _sha(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _from_hex(h: Any, what: str) -> bytes:
    if not isinstance(h, str) or len(h) % 2 or not _HEX.match(h):
        raise GovernanceReceiptError(f"{what} is not hex")
    return bytes.fromhex(h)


def _fixed(v: Any, n: int, what: str) -> bytes:
    """Bytes as the node serves them: hex, or an array of byte values."""
    out: bytes | None = None
    if isinstance(v, str):
        out = _from_hex(v, what)
    elif isinstance(v, list) and all(isinstance(b, int) and not isinstance(b, bool) and 0 <= b < 256 for b in v):
        out = bytes(v)
    if out is None or len(out) != n:
        raise GovernanceReceiptError(f"{what} is not {n} bytes")
    return out


def system_slot_tree_key(slot: str) -> bytes:
    """The tree key of system storage slot ``slot`` in namespace ``state``."""
    key = f"storage:{SYSTEM_ADDRESS_HEX}:{slot.encode().hex()}"
    return _sha(b"tenzro.state-trie.key", bytes([5, 0]), b"state", key.encode())


def _bit(stem: bytes, depth: int) -> int:
    return (stem[depth >> 3] >> (7 - (depth & 7))) & 1


def _slot_pair(left: bytes, right: bytes) -> bytes:
    if left == EMPTY and right == EMPTY:
        return EMPTY
    return _sha(b"\x03", left, right)


def verify_state_proof(root: bytes, tree_key: bytes, value: bytes | None, proof: Any) -> bool:
    """Whether, under ``root``, the entry ``tree_key`` holds ``value`` (or is absent, for ``None``), by ``proof``."""
    if not isinstance(proof, dict) or not isinstance(proof.get("siblings"), list):
        raise GovernanceReceiptError("a proof has no siblings")
    siblings = [_fixed(s, 32, "a sibling") for s in proof["siblings"]]
    if len(siblings) > STEM_LEN * 8:
        return False
    depth = len(siblings)
    stem = tree_key[:STEM_LEN]
    terminal = proof.get("terminal")
    if terminal == "Empty":
        if value is not None:
            return False
        acc = EMPTY
    elif isinstance(terminal, dict) and "OtherStem" in terminal:
        other = _fixed(terminal["OtherStem"].get("stem"), STEM_LEN, "a stem")
        slots_root = _fixed(terminal["OtherStem"].get("slots_root"), 32, "a slots root")
        if value is not None or other == stem:
            return False
        if any(_bit(other, d) != _bit(stem, d) for d in range(depth)):
            return False
        acc = _sha(b"\x02", other, slots_root)
    elif isinstance(terminal, dict) and "Stem" in terminal:
        sibs = terminal["Stem"].get("slot_siblings")
        if not isinstance(sibs, list) or len(sibs) != 8:
            raise GovernanceReceiptError("a stem proof needs 8 slot siblings")
        s = _sha(b"\x00", value) if value is not None else EMPTY
        index = tree_key[STEM_LEN]
        for raw in sibs:
            sib = _fixed(raw, 32, "a slot sibling")
            s = _slot_pair(s, sib) if index & 1 == 0 else _slot_pair(sib, s)
            index >>= 1
        if s == EMPTY:
            return False
        acc = _sha(b"\x02", stem, s)
    else:
        raise GovernanceReceiptError("a proof has an unknown terminal")
    for d in range(depth - 1, -1, -1):
        acc = _sha(b"\x01", acc, siblings[d]) if _bit(stem, d) == 0 else _sha(b"\x01", siblings[d], acc)
    return acc == root


def _json(b: bytes | None) -> Any:
    if not b:
        return None
    try:
        return json.loads(b.decode())
    except (UnicodeDecodeError, ValueError):
        return None


def verify_governance_receipt(receipt: Any, certified_state_root: bytes) -> GovernanceReceiptReport:
    """Check a governance receipt offline against a certified state root. Raises on any failure.

    Every record must be proven under that root and be about the receipt's
    proposal; the proposal, tally, veto and decision records must all be
    proven (present or absent); and a decision must be of exactly the proven
    proposal record.
    """
    if not isinstance(receipt, dict):
        raise GovernanceReceiptError("not a receipt")
    root = _fixed(receipt.get("state_root"), 32, "state_root")
    if root != bytes(certified_state_root):
        raise GovernanceReceiptError("the receipt names another state root than the certified one")
    pid = receipt.get("proposal_id")
    if not isinstance(pid, str):
        raise GovernanceReceiptError("no proposal_id")
    records = receipt.get("records")
    if not isinstance(records, list):
        raise GovernanceReceiptError("no records")
    values: dict[str, bytes | None] = {}
    for r in records:
        kind = r.get("kind") if isinstance(r, dict) else None
        if not isinstance(kind, str):
            raise GovernanceReceiptError("a record has no kind")
        if r.get("subject") != pid:
            raise GovernanceReceiptError(f"a {kind} record is about another proposal")
        if not isinstance(r.get("slot"), str):
            raise GovernanceReceiptError("a record has no slot")
        value = None if r.get("value") is None else _from_hex(r["value"], f"the {kind} value")
        if not verify_state_proof(root, system_slot_tree_key(r["slot"]), value, r.get("proof")):
            raise GovernanceReceiptError(f"the {kind} record is not proven under the certified root")
        if kind in values:
            raise GovernanceReceiptError(f"the receipt carries two {kind} records")
        values[kind] = value
    proposal_bytes = values.get("proposal")
    if proposal_bytes is None:
        raise GovernanceReceiptError("the receipt proves no proposal record")
    proposal = _json(proposal_bytes)
    if not isinstance(proposal, dict):
        raise GovernanceReceiptError("the proposal record is not JSON")
    if proposal.get("id") != pid:
        raise GovernanceReceiptError("the proposal record is of another proposal")
    for kind in ("tally", "veto_total", "decision"):
        if kind not in values:
            raise GovernanceReceiptError(f"the receipt does not prove the {kind} record")
    executed_height = None
    decision = values.get("decision")
    if decision is not None:
        if len(decision) != 40:
            raise GovernanceReceiptError("the decision record is malformed")
        if decision[:32] != _sha(proposal_bytes):
            raise GovernanceReceiptError("the decision record is not of the proven proposal record")
        if proposal.get("status") != "executed":
            raise GovernanceReceiptError("a decision is recorded for a proposal that is not executed")
        executed_height = int.from_bytes(decision[32:], "big")
    veto = values.get("veto_total")
    veto_locked = int.from_bytes(veto, "little") if veto and len(veto) == 16 else 0
    return GovernanceReceiptReport(
        proposal=proposal,
        tally=_json(values.get("tally")),
        veto_locked=veto_locked,
        executed_height=executed_height,
        activation=_json(values.get("activation")),
    )


def reinstate_validator_proposal(validator: str, memo: str):
    """A proposal to return a jailed validator to candidacy at the next epoch boundary.

    It ends the jail ahead of its governed term. The validator is admitted
    again like any candidate and slashing is not undone. For a validator that
    is not jailed it does nothing. ``validator`` is the 32 byte account, hex.
    """
    from ..typed_tx import TypedTransaction

    h = validator.removeprefix("0x")
    try:
        raw = bytes.fromhex(h)
    except ValueError as e:
        raise ValueError("validator must be 32 bytes of hex") from e
    if len(raw) != 32:
        raise ValueError("validator must be 32 bytes of hex")
    action = json.dumps(
        {"action": "reinstate_validator", "validator": list(raw), "memo": memo},
        separators=(",", ":"),
    )
    return TypedTransaction(
        kind="GovernancePropose",
        fields={"proposal": list(action.encode())},
        gas_limit=100_000,
    )


def parameter_change_proposal(key: str, value: int, memo: str):
    """A proposal to change one governed network parameter, ready to sign and send.

    Read the parameters, their bounds and any waiting change with
    ``get_network_params``. The node refuses the proposal at submission when
    ``value`` is outside the parameter's bounds; once enacted the value
    applies from the next epoch, or after the tightening grace window when it
    asks more of those the rule binds.
    """
    from ..typed_tx import TypedTransaction

    if not 0 <= value <= 2**64 - 1:
        raise ValueError("a parameter value is an unsigned 64-bit integer")
    action = json.dumps(
        {"action": "parameter_change", "key": key, "value": value, "memo": memo},
        separators=(",", ":"),
    )
    return TypedTransaction(
        kind="GovernancePropose",
        fields={"proposal": list(action.encode())},
        gas_limit=100_000,
    )
