"""Governance receipts from sdk/fixtures/governance_receipt, certified from genesis by the chain's own types."""

import copy

import pytest
from conftest import fixture

from tenzro.chain import GovernanceReceiptError, verify_governance_receipt

FIXTURE = fixture("governance_receipt", "receipt_from_genesis.json")
ROOT = bytes.fromhex(FIXTURE["certified_state_root"])


def _at(r, kind):
    return next(i for i, x in enumerate(r["records"]) if x["kind"] == kind)


def test_a_certified_receipt_verifies_offline():
    report = verify_governance_receipt(FIXTURE["receipt"], ROOT)
    assert report.executed_height == int(FIXTURE["executed_height"])
    assert report.proposal["status"] == "executed"
    assert report.tally["yes"] == "3"
    assert report.veto_locked == 0


def test_every_tampering_is_refused():
    with pytest.raises(GovernanceReceiptError, match="another state root"):
        verify_governance_receipt(FIXTURE["receipt"], bytes([9]) * 32)
    r = copy.deepcopy(FIXTURE["receipt"])
    r["records"][_at(r, "tally")]["value"] = b'{"yes":"4","no":"0","total_eligible":"4"}'.hex()
    with pytest.raises(GovernanceReceiptError, match="not proven"):
        verify_governance_receipt(r, ROOT)
    r = copy.deepcopy(FIXTURE["receipt"])
    r["records"][_at(r, "veto_total")]["value"] = "01" + "00" * 15
    with pytest.raises(GovernanceReceiptError, match="not proven"):
        verify_governance_receipt(r, ROOT)
    r = copy.deepcopy(FIXTURE["receipt"])
    del r["records"][_at(r, "decision")]
    with pytest.raises(GovernanceReceiptError, match="decision"):
        verify_governance_receipt(r, ROOT)
    r = copy.deepcopy(FIXTURE["receipt"])
    r["records"][0]["subject"] = "cd" * 32
    with pytest.raises(GovernanceReceiptError, match="another proposal"):
        verify_governance_receipt(r, ROOT)
    r = copy.deepcopy(FIXTURE["receipt"])
    sib = r["records"][_at(r, "proposal")]["proof"]["siblings"]
    if isinstance(sib[0], str):
        sib[0] = f"{int(sib[0][:2], 16) ^ 1:02x}" + sib[0][2:]
    else:
        sib[0][0] ^= 1
    with pytest.raises(GovernanceReceiptError, match="not proven"):
        verify_governance_receipt(r, ROOT)


def _proof_json(h):
    b = bytes.fromhex(h)
    depth = int.from_bytes(b[:2], "big")

    def word(i):
        return b[i:i + 32].hex()

    siblings = [word(2 + 32 * d) for d in range(depth)]
    t = 2 + 32 * depth
    if b[t] == 0:
        terminal = "Empty"
    elif b[t] == 1:
        terminal = {"OtherStem": {"stem": b[t + 1:t + 32].hex(), "slots_root": word(t + 32)}}
    else:
        terminal = {"Stem": {"slot_siblings": [word(t + 1 + 32 * i) for i in range(8)]}}
    return {"siblings": siblings, "terminal": terminal}


def test_the_finality_verifier_vectors_verify_here():
    v = fixture("governance_receipt", "vectors.json")
    pid = v["proposal_id"]

    def record(kind, prefix, value, proof):
        return {"kind": kind, "subject": pid, "slot": prefix + pid, "value": value, "proof": _proof_json(v[proof])}

    receipt = {
        "state_root": v["state_root"],
        "proposal_id": pid,
        "records": [
            record("proposal", "proposal:", v["proposal_record"], "proposal_proof"),
            record("decision", "governance_decision:", v["decision"], "decision_proof"),
        ],
    }
    root = bytes.fromhex(v["state_root"])
    with pytest.raises(GovernanceReceiptError, match="tally"):
        verify_governance_receipt(receipt, root)
    receipt["records"][1]["value"] = v["decision"][:78] + "00"
    with pytest.raises(GovernanceReceiptError, match="not proven"):
        verify_governance_receipt(receipt, root)
