"""OpenShell vectors (sdk/fixtures/openshell): grants to Terms, session ids, and sessions the
tenzro-openshell extensions signed, verified offline, with every tampering refused."""

import json

import pytest

from conftest import fixture
from tenzro.agents.openshell import (
    mint_openshell_credential,
    openshell_payments,
    openshell_session_id,
    openshell_terms,
    parse_openshell_entries,
    verify_openshell_receipt,
    verify_openshell_session,
)

V = fixture("openshell", "vectors.json")
P = fixture("openshell", "policy_terms.json")


def test_every_grant_maps_to_the_terms_the_vectors_state():
    assert len(P["cases"]) >= 4
    for c in P["cases"]:
        assert openshell_terms(c["policy"], c["grant"], P["options"]) == c["terms"], c["name"]


@pytest.mark.parametrize("c", P["refusals"], ids=[c["name"] for c in P["refusals"]])
def test_every_grant_or_policy_the_mapping_must_refuse_is_refused_with_its_reason(c):
    with pytest.raises(ValueError, match=None) as e:
        openshell_terms(c["policy"], c["grant"], P["options"])
    assert c["error"] in str(e.value)


def test_session_ids_are_the_extensions_layout():
    for c in V["session_ids"]:
        assert openshell_session_id(c["gateway"], c["session"]) == c["session_id"]


@pytest.mark.parametrize("s", V["sessions"], ids=[s["name"] for s in V["sessions"]])
def test_sessions_the_extensions_signed_verify(s):
    x = s["expect"]
    v = verify_openshell_session(s["entries"], s["identity"], s["hybrid_records_from_ms"], x["session_id"])
    assert (v["session_id"], v["agent"], v["count"], v["root"]) == (x["session_id"], x["agent"], x["count"], x["root"])
    assert [e["kind"] for e in v["entries"]] == x["kinds"]
    assert all(e["image"] == x["image"] for e in v["entries"])
    assert openshell_payments(v) == x["payments"]
    assert all(e["call"]["surface"] == "openshell" for e in v["entries"] if e["kind"] == "tool_call")


def test_hybrid_session_keys_are_reported():
    s = V["sessions"][1]
    v = verify_openshell_session(s["entries"], s["identity"], s["hybrid_records_from_ms"])
    assert all(e["hybrid"] for e in v["entries"])


def test_entries_parse_from_json_lines_and_from_an_array():
    entries = V["sessions"][0]["entries"]
    assert parse_openshell_entries("\n".join(json.dumps(e) for e in entries)) == entries
    assert parse_openshell_entries(json.dumps(entries)) == entries


def test_a_model_calls_receipt_header_verifies():
    r = V["receipt"]
    e = verify_openshell_receipt(r["header"], r["identity"], r["hybrid_records_from_ms"])
    assert (e["kind"], e["action"], e["linked_tx"]) == (r["expect"]["kind"], r["expect"]["action"], r["expect"]["linked_tx"])


@pytest.mark.parametrize("c", V["refusals"], ids=[c["name"] for c in V["refusals"]])
def test_every_tampering_is_refused(c):
    with pytest.raises(ValueError) as e:
        verify_openshell_session(c["entries"], c["identity"], c["hybrid_records_from_ms"])
    assert c["error"] in str(e.value)


def test_minting_a_credential_delegates_the_agent_under_the_grant_with_the_passkey():
    c = P["cases"][0]

    class Rpc:
        def __init__(self):
            self.sent = []

        def call(self, method, params=None):
            self.sent.append((method, params))
            if method == "tenzro_createCustodyChallenge":
                return {"challenge_id": "ch-1", "delegation": params["delegation"]}
            if method == "tenzro_onboardDelegatedAgent":
                return {"identity": {"did": "did:tenzro:agent:minted"}, "token_delivery": []}
            raise AssertionError(method)

    rpc = Rpc()
    approvals = []

    def authorize(challenge):
        approvals.append(challenge["challenge_id"])
        return {"challenge_id": challenge["challenge_id"], "assertion": "passkey"}

    cred = mint_openshell_credential(rpc, "0x" + "11" * 20, c["policy"], c["grant"], P["options"], authorize)
    assert [m for m, _ in rpc.sent] == ["tenzro_createCustodyChallenge", "tenzro_onboardDelegatedAgent"]
    assert rpc.sent[0][1]["operation"] == "delegate_agent"
    assert rpc.sent[0][1]["delegation"] == c["terms"]
    assert approvals == ["ch-1"]
    assert cred["agent_did"] == "did:tenzro:agent:minted"
    assert cred["provider"] == {"name": "tenzro", "type": "tenzro", "credentials": {"TENZRO_AGENT_TOKEN": "did:tenzro:agent:minted"}}
    assert cred["annotation"] == {"tenzro.agent": "did:tenzro:agent:minted"}
