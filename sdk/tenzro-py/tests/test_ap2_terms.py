"""The AP2 mandate-to-Terms vectors shared with the Rust and TypeScript SDKs:
each case decides after the mandate's constraints and the Terms per-payment
limit."""

import json
import time
from pathlib import Path

from tenzro.ap2 import MandatePayment, MandateRefusal, check_mandate_constraints

VECTORS = Path(__file__).resolve().parents[2] / "fixtures" / "ap2_terms" / "vectors.json"


def test_every_ap2_mandate_to_terms_vector_decides_as_stated():
    file = json.loads(VECTORS.read_text())
    txid = "checkout-digest"
    instrument = {"id": "tenzro-wallet", "type": "tenzro"}
    now = int(time.time())
    assert len(file["cases"]) >= 15
    for case in file["cases"]:
        constraints = json.loads(json.dumps(case["constraints"]).replace("$PAYEE", file["payee"]))
        if not case.get("omit_reference"):
            constraints = [{"type": "payment.reference", "conditional_transaction_id": txid}] + constraints
        payment = MandatePayment(file["payee"], case["amount"], file["currency"])
        try:
            check_mandate_constraints(constraints, payment, txid, instrument, now)
            got = "accept" if case["amount"] <= case["terms_max"] else "refuse"
        except MandateRefusal:
            got = "refuse"
        assert got == case["expect"], case["name"]
