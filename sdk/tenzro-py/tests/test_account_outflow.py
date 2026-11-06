import json
import sys
import types
from pathlib import Path

# Load the module without the package's network dependencies.
try:
    import httpx  # noqa: F401
except ImportError:  # a bare interpreter: stand in for the HTTP client
    from unittest import mock

    sys.modules["httpx"] = mock.MagicMock()
pkg = types.ModuleType("tenzro")
pkg.__path__ = [str(Path(__file__).resolve().parents[1] / "tenzro")]
sys.modules.setdefault("tenzro", pkg)

from tenzro.account_outflow import (  # noqa: E402
    OutflowPolicy,
    claim_release,
    describe,
    outflow_transaction,
    approval_target,
    request_release,
    set_policy,
)

T, H, D = 10**18, 3_600_000, 86_400_000
ACCT = bytes([0xA1]) * 32
POLICY = OutflowPolicy(D, 10 * T, 24 * H, "did:tenzro:human:g1")


def test_first_policy_names_cap_hold_and_guardian():
    t = " ".join(describe(set_policy(ACCT, D, 10 * T, 24 * H, "did:tenzro:human:g1"), None, 0))
    assert "at most 10 TNZO per 24 hours" in t and "waits 24 hours" in t and "your guardian" in t
    assert "takes effect at once" in t


def test_no_guardian_is_called_out():
    assert "No guardian" in " ".join(describe(set_policy(ACCT, D, T, H), None, 0))


def test_loosening_is_queued_and_tightening_is_immediate():
    loose = " ".join(describe(set_policy(ACCT, D, 100 * T, 24 * H, "did:tenzro:human:g1"), POLICY, 0))
    assert "loosens the policy" in loose and "1970-01-02 00:00 UTC" in loose
    tight = " ".join(describe(set_policy(ACCT, D, T, 48 * H, "did:tenzro:human:g1"), POLICY, 0))
    assert "tightens the policy" in tight


def test_release_names_who_can_cancel_and_the_wire_form_is_the_vm_op():
    op = request_release(ACCT, bytes([0xB1]) * 32, 3 * T // 2)
    t = " ".join(describe(op, POLICY, 0))
    assert "1.5 TNZO" in t and "You or your guardian can cancel" in t
    assert "no outflow policy" in " ".join(describe(op, None, 0))
    assert op["op"] == "request_release" and op["amount"] == str(3 * T // 2)
    tx = outflow_transaction(claim_release(ACCT, 7))
    assert tx.kind == "AccountOutflow"
    assert json.loads(bytes(tx.fields["op"]))["claim_release"]["id"] == 7


def test_guardian_approval_target_is_length_prefixed_and_step_bound():
    a = approval_target(b"\x01\x02", "claim_release", 7, 3)
    assert a[:4] == (2).to_bytes(4, "big")
    assert a != approval_target(b"\x01\x02", "claim_release", 7, 4)
    assert a != approval_target(b"\x01\x02", "cancel_release", 7, 3)
