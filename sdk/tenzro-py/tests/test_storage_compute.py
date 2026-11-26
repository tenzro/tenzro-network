"""Storage and compute rental against a recording node: the reads send the
params the node's handlers read and return their answers; renting signs a
CreateEscrow with stream release, checked against the node's signing payload
before anything is signed."""

import base64
import hashlib
import json

import httpx
import pytest

from tenzro import RpcClient
from tenzro.chain import (
    SLA_EPOCH_MS,
    ComputeClient,
    RentRequest,
    StorageClient,
    rent_transaction,
)
from tenzro.typed_tx import SigningPayloadMismatch

PROVIDER = "0x" + "ab" * 32
BOND = {
    "provider_did": "did:tenzro:machine:a",
    "provider_address": PROVIDER,
    "amount": "5",
    "status": "Active",
    "cooldown_until": None,
    "vault": "0xcd",
    "is_eligible": True,
    "effective_amount": "5",
}


def node(answers, *, tamper=False):
    """A client whose node answers each method from ``answers`` (a value or a
    function of the params), encodes signing payloads as the chain does, and
    records every request."""
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        method, params = body["method"], body["params"]
        if method == "tenzro_getSigningPayload":
            action = params["tx_type"]
            if tamper:
                action = {"CreateEscrow": {**action["CreateEscrow"], "payee": [1] * 32}}
            pre = {
                "chain_id": params["chain_id"],
                "from": params["from"][2:],
                "to": params["to"][2:],
                "nonce": params["nonce"],
                "gas_limit": params["gas_limit"],
                "gas_price": params["gas_price"],
                "timestamp": params["timestamp"],
                "valid_until": params["valid_until"],
                "action": action,
            }
            text = json.dumps(pre)
            result = {
                "kind": "typed_action",
                "preimage": text,
                "digest": hashlib.sha256(text.encode()).hexdigest(),
            }
        else:
            answer = {
                "tenzro_getNonce": "0x2",
                "eth_chainId": "0x539",
                "eth_gasPrice": "0x1",
                **answers,
            }.get(method)
            result = answer(params) if callable(answer) else answer
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": body["id"], "result": result}
        )

    return RpcClient("http://node.test", transport=httpx.MockTransport(handle)), seen


class Signer:
    def p256_public_key(self):
        return bytes([7]) * 64

    def ml_dsa_public_key(self):
        return None

    def sign_composite(self, m_prime):
        return bytes([1]) * 64, None


def test_storage_sends_what_the_node_reads():
    rpc, seen = node(
        {
            "tenzro_storageStoreObject": {
                "object_id": "o",
                "size_bytes": 2,
                "data_shards": 4,
                "parity_shards": 2,
                "descriptor_digest": "ee",
            },
            "tenzro_storageRetrieveObject": {
                "object_id": "o",
                "size_bytes": 2,
                "data": "aGk=",
            },
            "tenzro_storageSetPricing": {"mode": "fixed", "effective_rate_wei": "7"},
            "tenzro_storageStatus": {
                "is_storage_provider": True,
                "effective_rate_wei": "7",
                "object_count": 1,
            },
            "tenzro_getStorageHoldingReceipt": None,
            "tenzro_listStorageProviders": {"providers": [], "new_provider_share_bps": 2000},
        }
    )
    s = StorageClient(rpc)
    stored = s.store_object("o", PROVIDER, b"hi", "did:tenzro:human:o", Signer())
    assert stored["descriptor_digest"] == "ee"
    sent = seen[-1]["params"]
    assert seen[-1]["method"] == "tenzro_storageStoreObject"
    assert {
        k: sent[k]
        for k in (
            "object_id",
            "owner",
            "data",
            "data_shards",
            "parity_shards",
            "owner_did",
        )
    } == {
        "object_id": "o",
        "owner": PROVIDER,
        "data": base64.b64encode(b"hi").decode(),
        "data_shards": 4,
        "parity_shards": 2,
        "owner_did": "did:tenzro:human:o",
    }
    assert isinstance(sent["did_envelope"], str)
    assert "placement" not in sent
    s.store_object(
        "o", PROVIDER, b"hi", "did:tenzro:human:o", Signer(), placement={"jurisdiction": ["DE"]}
    )
    assert seen[-1]["params"]["placement"] == {"jurisdiction": ["DE"]}
    assert s.retrieve_object("o", "did:tenzro:human:o", Signer()) == b"hi"
    assert seen[-1]["params"]["object_id"] == "o" and isinstance(
        seen[-1]["params"]["did_envelope"], str
    )
    assert "voucher" not in seen[-1]["params"]
    s.store_object("c", PROVIDER, b"hi", "did:tenzro:human:o", Signer(), storage_class="cold")
    assert seen[-1]["params"]["class"] == "cold"
    with pytest.raises(ValueError):
        s.store_object("c", PROVIDER, b"hi", "did:tenzro:human:o", Signer(), storage_class="icy")
    paid = {"cumulative_amount": "5"}
    assert s.retrieve_object("c", "did:tenzro:human:o", Signer(), voucher=paid) == b"hi"
    assert seen[-1]["params"]["voucher"] == paid
    s.set_read_rates(7, 300, 20, 1)
    assert seen[-1]["params"] == [
        {"mode": "fixed", "rate": "7", "read_rates": {"hot": "300", "warm": "20", "cold": "1"}}
    ]
    s.set_fixed_rate(7)
    assert seen[-1]["method"] == "tenzro_storageSetPricing" and seen[-1]["params"] == [
        {"mode": "fixed", "rate": "7"}
    ]
    assert s.status()["object_count"] == 1
    assert seen[-1]["method"] == "tenzro_storageStatus" and seen[-1]["params"] == []
    assert s.holding_receipt("o") is None
    assert seen[-1]["method"] == "tenzro_getStorageHoldingReceipt" and seen[-1]["params"] == [
        {"object_id": "o"}
    ]
    assert s.providers()["new_provider_share_bps"] == 2000
    assert seen[-1]["method"] == "tenzro_listStorageProviders" and seen[-1]["params"] == {}
    with pytest.raises(ValueError):
        s.set_fixed_rate(-1)


def test_compute_reads_send_what_the_node_reads():
    claim = {
        "claim_id": "c1",
        "state": {"state": "held"},
        "storage_descriptor": "ee",
        "collateral": "36893488147419103232",
    }
    feed = {
        "window_ms": 86_400_000,
        "min_distinct_observers": 2,
        "total": 0,
        "entries": [],
        "claims_note": "n",
    }
    rpc, seen = node(
        {
            "tenzro_computeBondParams": {"min_bond_wei": "1000", "cooldown_ms": 60000},
            "tenzro_getComputeBond": lambda p: (
                BOND if p[0]["provider_did"] == BOND["provider_did"] else None
            ),
            "tenzro_listComputeBonds": {"count": 1, "bonds": [BOND]},
            "tenzro_computeGetClaim": claim,
            "tenzro_computeListClaims": {"total": 3, "claims": [claim]},
            "tenzro_computePriceFeed": feed,
        }
    )
    c = ComputeClient(rpc)
    cases = [
        (
            lambda: c.bond_params(),
            "tenzro_computeBondParams",
            [],
            {"min_bond_wei": "1000", "cooldown_ms": 60000},
        ),
        (
            lambda: c.get_bond(BOND["provider_did"]),
            "tenzro_getComputeBond",
            [{"provider_did": BOND["provider_did"]}],
            BOND,
        ),
        (
            lambda: c.get_bond("did:tenzro:machine:b"),
            "tenzro_getComputeBond",
            [{"provider_did": "did:tenzro:machine:b"}],
            None,
        ),
        (lambda: c.list_bonds(), "tenzro_listComputeBonds", [], [BOND]),
        (
            lambda: c.get_claim("c1"),
            "tenzro_computeGetClaim",
            {"claim_id": "c1"},
            claim,
        ),
        (
            lambda: c.list_claims(PROVIDER),
            "tenzro_computeListClaims",
            {"party": PROVIDER},
            {"total": 3, "claims": [claim]},
        ),
        (
            lambda: c.list_claims(PROVIDER, 1),
            "tenzro_computeListClaims",
            {"party": PROVIDER, "limit": 1},
            {"total": 3, "claims": [claim]},
        ),
        (
            lambda: c.price_feed(hardware_class="cpu", attested_only=True),
            "tenzro_computePriceFeed",
            {"hardware_class": "cpu", "attested_only": True},
            feed,
        ),
        (lambda: c.price_feed(), "tenzro_computePriceFeed", {}, feed),
    ]
    for call, method, params, want in cases:
        assert call() == want, method
        assert seen[-1]["method"] == method and seen[-1]["params"] == params, method


def test_a_rental_is_a_stream_escrow_to_the_bonded_address():
    tx = rent_transaction(RentRequest(PROVIDER, 7, 3, reference="0x" + "09" * 32), 1000)
    assert tx.kind == "CreateEscrow"
    assert tx.fields == {
        "payee": [0xAB] * 32,
        "amount": 21,
        "asset_id": "TNZO",
        "usd_e6": 0,
        "expires_at": 1000 + 4 * SLA_EPOCH_MS,
        "release_conditions": {
            "Stream": {"rate_per_epoch": 7, "epoch_ms": SLA_EPOCH_MS}
        },
        "reference": "09" * 32,
    }
    huge = rent_transaction(RentRequest(PROVIDER, 2**64, 2), 0)
    assert huge.fields["amount"] == str(2**65)
    assert huge.fields["release_conditions"]["Stream"]["rate_per_epoch"] == str(2**64)
    assert RentRequest.for_bond(BOND, 1, 1).provider_address == PROVIDER


@pytest.mark.parametrize(
    "request_",
    [
        RentRequest(PROVIDER, 0, 3),
        RentRequest(PROVIDER, 7, 0),
        RentRequest(PROVIDER, 7, 3, epoch_ms=0),
        RentRequest("0xab", 7, 3),
        RentRequest(PROVIDER, 2**127, 4),
    ],
)
def test_a_rental_of_nothing_or_to_a_malformed_address_is_refused(request_):
    with pytest.raises(ValueError):
        rent_transaction(request_, 0)


def test_rent_signs_the_escrow_the_node_encodes_and_submits_it():
    rpc, seen = node({"tenzro_sendRawTransaction": {"hash": "0x01"}})
    rate = 1_234_567_890_123_456_789
    assert ComputeClient(rpc).rent(Signer(), RentRequest.for_bond(BOND, rate, 2)) == {
        "hash": "0x01"
    }
    sent = next(s["params"] for s in seen if s["method"] == "tenzro_sendRawTransaction")
    escrow = sent["tx_type"]["CreateEscrow"]
    assert escrow["amount"] == 2 * rate and escrow["payee"] == [0xAB] * 32
    assert escrow["release_conditions"] == {
        "Stream": {"rate_per_epoch": rate, "epoch_ms": SLA_EPOCH_MS}
    }
    room = escrow["expires_at"] - sent["timestamp"]
    assert 3 * SLA_EPOCH_MS - 5000 < room <= 3 * SLA_EPOCH_MS


def test_rent_submits_nothing_when_the_payload_names_another_escrow():
    rpc, seen = node({}, tamper=True)
    with pytest.raises(SigningPayloadMismatch):
        ComputeClient(rpc).rent(Signer(), RentRequest(PROVIDER, 7, 1))
    assert "tenzro_sendRawTransaction" not in [s["method"] for s in seen]
