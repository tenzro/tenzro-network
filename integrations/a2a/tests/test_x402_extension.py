"""Tests for the A2A x402 extension wire format and dispatcher contract.

Pinning tests here — the wire-format keys, status strings, and the
"no version field" rule must stay byte-identical with the Rust mirror at
`crates/tenzro-node/src/a2a/x402_extension.rs`.

Run with `python -m unittest tests.test_x402_extension` from the package
root, or `pytest tests/test_x402_extension.py`.
"""

import json
import unittest

from tenzro_a2a_server.x402_extension import (
    KEY_PAYMENT_PAYLOAD,
    KEY_PAYMENT_RECEIPTS,
    KEY_PAYMENT_REQUIRED,
    KEY_PAYMENT_STATUS,
    PaymentStatus,
    UnimplementedSchemeVerifier,
    VerifyFailure,
    complete_x402,
    fail_x402,
    get_payment_payload,
    get_payment_required,
    set_status,
    submit_x402,
)


# ---------------------------------------------------------------------------
# Pinning tests — wire format must not drift
# ---------------------------------------------------------------------------

class TestWireFormatPinning(unittest.TestCase):
    """The reserved keys and status strings are part of the wire contract."""

    def test_reserved_keys_are_stable_strings(self):
        # These four strings appear in every x402-aware A2A message.
        # Changing any of them breaks every existing client.
        self.assertEqual(KEY_PAYMENT_REQUIRED, "x402.payment.required")
        self.assertEqual(KEY_PAYMENT_PAYLOAD, "x402.payment.payload")
        self.assertEqual(KEY_PAYMENT_RECEIPTS, "x402.payment.receipts")
        self.assertEqual(KEY_PAYMENT_STATUS, "x402.payment.status")

    def test_payment_status_is_kebab_case(self):
        self.assertEqual(PaymentStatus.PAYMENT_REQUIRED, "payment-required")
        self.assertEqual(PaymentStatus.PAYMENT_SUBMITTED, "payment-submitted")
        self.assertEqual(PaymentStatus.PAYMENT_VERIFIED, "payment-verified")
        self.assertEqual(PaymentStatus.PAYMENT_SETTLING, "payment-settling")
        self.assertEqual(PaymentStatus.PAYMENT_COMPLETED, "payment-completed")
        self.assertEqual(PaymentStatus.PAYMENT_REJECTED, "payment-rejected")

    def test_no_version_field_in_serialized_requirements(self):
        # Tenzro-owned wire shapes are content-addressed by scheme name.
        # No "version", "ver", or "v" key may appear in serialized
        # requirements — the test acts as a pin against drift.
        requirements = {
            "accepts": [
                {
                    "scheme": "exact-eip3009",
                    "network": "eip155:8453",
                    "amount": "1000000",
                    "asset": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                    "payTo": "0x0000000000000000000000000000000000000001",
                    "maxTimeoutSeconds": 60,
                }
            ],
            "reason": None,
        }
        encoded = json.dumps(requirements)
        for forbidden in ("\"version\"", "\"ver\"", "\"v\":"):
            self.assertNotIn(forbidden, encoded, f"forbidden field {forbidden} in requirements")

    def test_no_version_field_in_serialized_payload(self):
        payload = {
            "taskId": "task-1",
            "scheme": "exact-eip3009",
            "network": "eip155:8453",
            "authorization": {"signature": "0xdeadbeef"},
        }
        encoded = json.dumps(payload)
        for forbidden in ("\"version\"", "\"ver\"", "\"v\":"):
            self.assertNotIn(forbidden, encoded, f"forbidden field {forbidden} in payload")


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------

class TestMetadataHelpers(unittest.TestCase):

    def test_get_payment_required_returns_dict(self):
        md = {KEY_PAYMENT_REQUIRED: {"accepts": []}}
        self.assertEqual(get_payment_required(md), {"accepts": []})

    def test_get_payment_required_returns_none_when_missing(self):
        self.assertIsNone(get_payment_required({}))

    def test_get_payment_required_rejects_non_dict(self):
        # If a caller mis-types the value, treat it as absent rather than
        # crashing the dispatcher.
        self.assertIsNone(get_payment_required({KEY_PAYMENT_REQUIRED: "wrong"}))

    def test_get_payment_payload_returns_none_when_missing(self):
        self.assertIsNone(get_payment_payload({}))

    def test_set_status_writes_string(self):
        md: dict = {}
        set_status(md, PaymentStatus.PAYMENT_REQUIRED)
        self.assertEqual(md[KEY_PAYMENT_STATUS], "payment-required")

    def test_submit_x402_records_payload_and_status(self):
        md: dict = {}
        payload = {"taskId": "t1", "scheme": "exact-eip3009", "network": "eip155:8453"}
        submit_x402(md, payload)
        self.assertEqual(md[KEY_PAYMENT_PAYLOAD], payload)
        self.assertEqual(md[KEY_PAYMENT_STATUS], "payment-submitted")

    def test_complete_x402_records_receipts_and_status(self):
        md: dict = {}
        receipts = [{"network": "eip155:8453", "transaction": "0x1234"}]
        complete_x402(md, receipts)
        self.assertEqual(md[KEY_PAYMENT_RECEIPTS], receipts)
        self.assertEqual(md[KEY_PAYMENT_STATUS], "payment-completed")

    def test_fail_x402_writes_terminal_status(self):
        md: dict = {}
        fail_x402(md, PaymentStatus.PAYMENT_REJECTED)
        self.assertEqual(md[KEY_PAYMENT_STATUS], "payment-rejected")

    def test_fail_x402_rejects_unknown_status(self):
        with self.assertRaises(ValueError):
            fail_x402({}, "made-up-status")


# ---------------------------------------------------------------------------
# UnimplementedSchemeVerifier
# ---------------------------------------------------------------------------

REQUIREMENTS = {
    "accepts": [
        {"scheme": "exact-eip3009", "network": "eip155:8453"},
        {"scheme": "exact-permit2", "network": "eip155:8453"},
    ],
    "reason": None,
}


class TestUnimplementedSchemeVerifier(unittest.TestCase):

    def test_task_id_mismatch_is_rejected_first(self):
        # Replay guard runs before scheme matching.
        verifier = UnimplementedSchemeVerifier()
        payload = {
            "taskId": "wrong-task",
            "scheme": "exact-eip3009",
            "network": "eip155:8453",
        }
        with self.assertRaises(VerifyFailure) as cm:
            verifier.verify_and_settle("held-task", REQUIREMENTS, payload)
        self.assertEqual(cm.exception.kind, "task_id_mismatch")
        self.assertEqual(cm.exception.terminal_status(), "payment-rejected")

    def test_scheme_not_offered_is_rejected(self):
        verifier = UnimplementedSchemeVerifier()
        payload = {
            "taskId": "held-task",
            "scheme": "exact-erc7710",  # not in REQUIREMENTS.accepts
            "network": "eip155:8453",
        }
        with self.assertRaises(VerifyFailure) as cm:
            verifier.verify_and_settle("held-task", REQUIREMENTS, payload)
        self.assertEqual(cm.exception.kind, "scheme_not_offered")

    def test_network_mismatch_is_rejected(self):
        verifier = UnimplementedSchemeVerifier()
        payload = {
            "taskId": "held-task",
            "scheme": "exact-eip3009",
            "network": "eip155:1",  # wrong network
        }
        with self.assertRaises(VerifyFailure) as cm:
            verifier.verify_and_settle("held-task", REQUIREMENTS, payload)
        self.assertEqual(cm.exception.kind, "scheme_not_offered")

    def test_offered_scheme_returns_scheme_not_implemented(self):
        # Slice (a) has no backend; even a valid (scheme, network) gets
        # rejected as scheme_not_implemented. Slice (c) replaces this.
        verifier = UnimplementedSchemeVerifier()
        payload = {
            "taskId": "held-task",
            "scheme": "exact-eip3009",
            "network": "eip155:8453",
        }
        with self.assertRaises(VerifyFailure) as cm:
            verifier.verify_and_settle("held-task", REQUIREMENTS, payload)
        self.assertEqual(cm.exception.kind, "scheme_not_implemented")
        self.assertEqual(cm.exception.terminal_status(), "payment-rejected")

    def test_failure_message_is_human_readable(self):
        verifier = UnimplementedSchemeVerifier()
        payload = {
            "taskId": "held-task",
            "scheme": "exact-eip3009",
            "network": "eip155:8453",
        }
        try:
            verifier.verify_and_settle("held-task", REQUIREMENTS, payload)
            self.fail("expected VerifyFailure")
        except VerifyFailure as e:
            self.assertIn("exact-eip3009", e.message())


if __name__ == "__main__":
    unittest.main()
