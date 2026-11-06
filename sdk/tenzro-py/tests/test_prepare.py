"""A typed transaction dry run: the node encodes the signing payload, the SDK
checks it, and nothing is signed or submitted."""

import hashlib
import json

import httpx
import pytest

from tenzro import RpcClient, TypedTransaction, TypedTxClient
from tenzro.typed_tx import SigningPayloadMismatch

SENDER = "0x" + "11" * 32
TO = "0x" + "22" * 32


def node(skew_nonce: int = 0):
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        method, params = body["method"], body["params"]
        answers = {"tenzro_getNonce": "0x7", "eth_chainId": "0x539", "eth_gasPrice": "0x1"}
        if method in answers:
            result = answers[method]
        elif method == "tenzro_getSigningPayload":
            pre = {
                "chain_id": params["chain_id"],
                "from": params["from"][2:],
                "to": params["to"][2:],
                "nonce": params["nonce"] + skew_nonce,
                "gas_limit": params["gas_limit"],
                "gas_price": params["gas_price"],
                "timestamp": params["timestamp"],
                "valid_until": params["valid_until"],
                "action": params["tx_type"],
            }
            text = json.dumps(pre)
            result = {"kind": "typed_action", "preimage": text, "digest": hashlib.sha256(text.encode()).hexdigest()}
        else:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601, "message": method}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    return RpcClient("http://node.test", transport=httpx.MockTransport(handle)), seen


def test_prepare_checks_the_node_encoding_and_sends_nothing():
    rpc, seen = node()
    tx = TypedTransaction(kind="Transfer", fields={"amount": 5}, to=TO)
    out = TypedTxClient(rpc).prepare(SENDER, tx)
    assert out["request"]["from"] == SENDER and out["request"]["nonce"] == 7 and out["request"]["chain_id"] == 1337
    assert "signature" not in out["request"] and len(bytes.fromhex(out["digest"])) == 32
    assert [s["method"] for s in seen] == ["tenzro_getNonce", "eth_chainId", "eth_gasPrice", "tenzro_getSigningPayload"]


def test_prepare_refuses_a_payload_that_is_not_the_transaction():
    rpc, seen = node(skew_nonce=1)
    with pytest.raises(SigningPayloadMismatch, match="nonce"):
        TypedTxClient(rpc).prepare(SENDER, TypedTransaction(kind="Transfer", fields={"amount": 5}, to=TO))
    assert "tenzro_sendRawTransaction" not in [s["method"] for s in seen]
