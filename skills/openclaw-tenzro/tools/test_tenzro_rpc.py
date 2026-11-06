#!/usr/bin/env python3
"""Tests for tenzro_rpc.py — TenzroClaw OpenClaw skill.

All tests use unittest.mock to patch requests so no live node is needed.
Run: python -m pytest test_tenzro_rpc.py -v
  or: python -m unittest test_tenzro_rpc -v
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure the module under test is importable
sys.path.insert(0, os.path.dirname(__file__))
import tenzro_rpc


def _mock_rpc_response(result):
    """Build a mock requests.Response for a JSON-RPC success."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": result}
    resp.raise_for_status = MagicMock()
    return resp


def _mock_rpc_error(code, message):
    """Build a mock requests.Response for a JSON-RPC error."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": code, "message": message},
    }
    resp.raise_for_status = MagicMock()
    return resp


def _mock_api_response(body):
    """Build a mock requests.Response for a REST API call."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = body
    resp.raise_for_status = MagicMock()
    return resp


class TestWallet(unittest.TestCase):

    @patch("tenzro_rpc.requests.post")
    def test_get_balance(self, mock_post):
        mock_post.return_value = _mock_rpc_response("0xde0b6b3a7640000")
        result = tenzro_rpc.get_balance("0x1234")
        self.assertEqual(result["address"], "0x1234")
        self.assertIn("balance_wei", result)
        self.assertEqual(result["balance_wei"], "1000000000000000000")

    @patch("tenzro_rpc.requests.post")
    def test_send_self_custody_transaction(self, mock_post):
        # Self-custody path: nonce + chain_id fixed at signing time, so only
        # one RPC fires (tenzro_sendRawTransaction) carrying the pre-signed
        # Ed25519 + ML-DSA-65 material. The node never sees the secret.
        mock_post.side_effect = [
            _mock_rpc_response(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            ),
        ]
        result = tenzro_rpc.send_self_custody_transaction(
            from_addr="0xfrom",
            to_addr="0xto",
            value=10**18,
            signature="0xedsig",
            public_key="0xedpub",
            pq_signature="0xpqsig",
            pq_public_key="0xpqpub",
            timestamp=1_700_000_000_000,
            nonce=4,
            chain_id=13380,
        )
        self.assertEqual(len(result), 64)
        sent = mock_post.call_args.kwargs["json"]
        self.assertEqual(sent["method"], "tenzro_sendRawTransaction")
        params = sent["params"]
        self.assertEqual(params["from"], "0xfrom")
        self.assertEqual(params["value"], str(10**18))
        self.assertEqual(params["nonce"], 4)
        self.assertEqual(params["chain_id"], 13380)
        self.assertEqual(params["timestamp"], 1_700_000_000_000)
        self.assertEqual(params["public_key"], "0xedpub")
        self.assertEqual(params["signature"], "0xedsig")
        self.assertEqual(params["pq_public_key"], "0xpqpub")
        self.assertEqual(params["pq_signature"], "0xpqsig")


class TestNodeStatus(unittest.TestCase):
    @patch("tenzro_rpc.requests.get")
    def test_get_status(self, mock_get):
        mock_get.return_value = _mock_api_response({
            "status": "ok",
            "block_height": 42,
            "peer_count": 3,
        })
        result = tenzro_rpc.get_status()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["block_height"], 42)

    @patch("tenzro_rpc.requests.get")
    def test_get_health(self, mock_get):
        mock_get.return_value = _mock_api_response({"healthy": True})
        result = tenzro_rpc.get_health()
        self.assertTrue(result["healthy"])

    @patch("tenzro_rpc.requests.post")
    def test_block_height(self, mock_post):
        mock_post.return_value = _mock_rpc_response("0x2a")
        result = tenzro_rpc.block_height()
        self.assertEqual(result["block_height"], 42)
        self.assertEqual(result["hex"], "0x2a")

    @patch("tenzro_rpc.requests.post")
    def test_get_block(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "height": 0,
            "hash": "0x000",
            "transactions": [],
        })
        result = tenzro_rpc.get_block(0)
        self.assertEqual(result["height"], 0)

    @patch("tenzro_rpc.requests.post")
    def test_chain_id(self, mock_post):
        mock_post.return_value = _mock_rpc_response("0x3444")
        result = tenzro_rpc.chain_id()
        self.assertEqual(result["chain_id"], 13380)

    @patch("tenzro_rpc.requests.post")
    def test_an_unreadable_chain_id_is_an_error_not_a_default(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"code": -32000})
        with self.assertRaises(RuntimeError) as e:
            tenzro_rpc._read_quantity("chain id", "eth_chainId", [])
        self.assertIn("could not read the chain id", str(e.exception))
        mock_post.side_effect = ConnectionError("refused")
        with self.assertRaises(RuntimeError):
            tenzro_rpc._read_quantity("nonce", "eth_getTransactionCount", ["0xa", "latest"])


class TestIdentity(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_register_identity(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "did": "did:tenzro:human:abc-123",
            "status": "active",
        })
        result = tenzro_rpc.register_identity("Alice")
        self.assertEqual(result["did"], "did:tenzro:human:abc-123")

    @patch("tenzro_rpc.requests.post")
    def test_resolve_did(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "did": "did:tenzro:human:abc-123",
            "display_name": "Alice",
            "status": "active",
        })
        result = tenzro_rpc.resolve_did("did:tenzro:human:abc-123")
        self.assertEqual(result["display_name"], "Alice")

    @patch("tenzro_rpc.requests.post")
    def test_resolve_did_document(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tenzro:human:abc-123",
        })
        result = tenzro_rpc.resolve_did_document("did:tenzro:human:abc-123")
        self.assertIn("@context", result)

class TestVerification(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_verify_zk_proof(self, mock_post):
        mock_post.return_value = _mock_api_response({
            "valid": True,
            "circuit_id": "inference",
            "proof_system": "plonky3",
        })
        result = tenzro_rpc.verify_zk_proof("0xproof", ["0x01000000"], "inference")
        self.assertTrue(result["valid"])

    @patch("tenzro_rpc.requests.post")
    def test_verify_tee_attestation(self, mock_post):
        mock_post.return_value = _mock_api_response({
            "valid": True,
            "vendor": "intel-tdx",
        })
        result = tenzro_rpc.verify_tee_attestation("intel-tdx", "0xreport")
        self.assertTrue(result["valid"])


class TestTokenRegistry(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_get_token_info(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "symbol": "TNZO",
            "name": "Tenzro",
            "decimals": 18,
        })
        result = tenzro_rpc.get_token_info(symbol="TNZO")
        self.assertEqual(result["symbol"], "TNZO")

    @patch("tenzro_rpc.requests.post")
    def test_list_tokens(self, mock_post):
        mock_post.return_value = _mock_rpc_response([
            {"symbol": "TNZO"},
            {"symbol": "MYT"},
        ])
        result = tenzro_rpc.list_tokens()
        self.assertEqual(len(result), 2)

    @patch("tenzro_rpc.requests.post")
    def test_get_token_balance_all_vms(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "native": "1000000",
            "evm": "1000000",
        })
        result = tenzro_rpc.get_token_balance_all_vms("0x1234")
        self.assertIn("native", result)

    @patch("tenzro_rpc.requests.post")
    def test_deploy_contract(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "status": "admitted",
            "tx_hash": "0xabc",
        })
        signed = {"tx_type": {"ContractDeploy": {"code": [96, 0], "args": []}},
                  "public_key": "04", "signature": {}}
        result = tenzro_rpc.deploy_contract(signed)
        self.assertEqual(result["tx_hash"], "0xabc")
        sent = mock_post.call_args.kwargs["json"]
        self.assertEqual(sent["method"], "tenzro_deployContract")
        self.assertEqual(sent["params"], signed)

    def test_get_token_info_no_args(self):
        result = tenzro_rpc.get_token_info()
        self.assertIn("error", result)


class TestInference(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_chat(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "output": "Hello! I can help with that.",
            "input_tokens": 10,
            "output_tokens": 8,
        })
        result = tenzro_rpc.chat("gemma4-9b", "Hello")
        self.assertIn("output", result)
        self.assertEqual(result["output"], "Hello! I can help with that.")

    @patch("tenzro_rpc.requests.post")
    def test_route_intent(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "model_id": "qwen3-4b",
            "tier": "cheap",
            "estimated_cost": "420000000000000",
            "alternates": ["qwen3-4b", "gemma4-9b"],
            "cluster": 3,
            "expected_error": 0.08,
            "provider": "0x" + "11" * 20,
            "endpoint": "https://provider.example/v1",
            "reason": "cheapest model above the quality floor",
        })
        result = tenzro_rpc.route_intent(
            "reasoning", budget=10**18, optimize=0.7, quality_floor="strong",
        )
        self.assertEqual(result["model_id"], "qwen3-4b")
        self.assertEqual(result["cluster"], 3)
        self.assertEqual(result["expected_error"], 0.08)
        self.assertEqual(result["provider"], "0x" + "11" * 20)

    @patch("tenzro_rpc.requests.post")
    def test_chat_by_intent(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "output": "A trait bound constrains a generic parameter.",
            "input_tokens": 12,
            "output_tokens": 9,
            "route": {
                "model_id": "qwen3-4b",
                "tier": "cheap",
                "estimated_cost": "420000000000000",
                "cluster": 3,
            },
        })
        result = tenzro_rpc.chat_by_intent("code", "Explain this trait bound")
        self.assertIn("route", result)
        self.assertEqual(result["route"]["model_id"], "qwen3-4b")
        self.assertIn("output", result)

    @patch("tenzro_rpc.requests.post")
    def test_record_route_outcome(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"retained": True})
        result = tenzro_rpc.record_route_outcome("qwen3-4b", 3, "escalated")
        self.assertTrue(result["retained"])

    @patch("tenzro_rpc.requests.post")
    def test_route_difficulty_stats(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "enabled": True,
            "cluster_count": 4,
            "clusters": [
                {"cluster": 0, "prompts": 120},
                {"cluster": 3, "prompts": 44},
            ],
        })
        result = tenzro_rpc.route_difficulty_stats("qwen3-4b")
        self.assertTrue(result["enabled"])
        self.assertEqual(result["cluster_count"], 4)

    @patch("tenzro_rpc.requests.post")
    def test_route_difficulty_stats_disabled(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "enabled": False,
            "cluster_count": 0,
            "clusters": [],
        })
        result = tenzro_rpc.route_difficulty_stats()
        self.assertFalse(result["enabled"])
        self.assertEqual(result["clusters"], [])


class TestPayments(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_create_payment_challenge(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "challenge_id": "ch-123",
            "protocol": "x402",
        })
        result = tenzro_rpc.create_payment_challenge(
            "x402", "/api/inference", 100, "USDC", "0xrecipient"
        )
        self.assertEqual(result["challenge_id"], "ch-123")


class TestDuties(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_list_duties(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"count": 1, "duties": [{"id": "aa"}]})
        result = tenzro_rpc.list_duties()
        self.assertEqual(result["count"], 1)

    @patch("tenzro_rpc.requests.post")
    def test_get_duty(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"id": "aa", "state": "open"})
        result = tenzro_rpc.get_duty("aa")
        self.assertEqual(result["state"], "open")


class TestStaking(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_role_stakes(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"stakes": []})
        tenzro_rpc.role_stakes("0xabc")
        body = mock_post.call_args.kwargs["json"]
        self.assertEqual((body["method"], body["params"]), ("tenzro_getRoleStakes", {"address": "0xabc"}))

    @patch("tenzro_rpc.requests.post")
    def test_provider_stats(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "total_inferences": 100,
            "total_staked": "500000",
        })
        result = tenzro_rpc.provider_stats()
        self.assertEqual(result["total_inferences"], 100)


class TestSkillBundlePinning(unittest.TestCase):
    """The registry is permissionless, so pinning is the caller's protection.

    These assert the wire shape, since a dropped pin would silently widen what
    the caller is willing to pay to run.
    """

    SHA = "a" * 64

    @staticmethod
    def _sent_params(mock_post):
        call_args = mock_post.call_args
        body = call_args[1]["json"] if "json" in call_args[1] else call_args[0][1]
        return body["params"]


class TestEventsWebhooks(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_get_events(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "events": [
                {"sequence": 1, "type": "transfer"},
                {"sequence": 2, "type": "mint"},
            ],
            "next_sequence": 3,
        })
        result = tenzro_rpc.get_events()
        self.assertEqual(len(result["events"]), 2)

    @patch("tenzro_rpc.requests.post")
    def test_get_events_with_filter(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "events": [{"sequence": 5, "type": "transfer"}],
            "next_sequence": 6,
        })
        result = tenzro_rpc.get_events(
            filter={"event_types": ["log"]}, from_cursor="4:0:0", limit=10
        )
        self.assertEqual(len(result["events"]), 1)

    @patch("tenzro_rpc.requests.post")
    def test_get_event_status(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "latest_sequence": 1000,
            "lag": 0,
            "status": "synced",
        })
        result = tenzro_rpc.get_event_status()
        self.assertEqual(result["status"], "synced")

class TestErrorHandling(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_rpc_error_response(self, mock_post):
        mock_post.return_value = _mock_rpc_error(-32601, "Method not found")
        result = tenzro_rpc._rpc("nonexistent_method")
        self.assertIn("error", result)

    @patch("tenzro_rpc.requests.post")
    def test_rpc_formats_params_correctly(self, mock_post):
        mock_post.return_value = _mock_rpc_response({})
        tenzro_rpc._rpc("test_method", {"key": "value"})
        call_args = mock_post.call_args
        body = call_args[1]["json"] if "json" in call_args[1] else call_args[0][1]
        self.assertEqual(body["method"], "test_method")
        self.assertEqual(body["params"], {"key": "value"})
        self.assertEqual(body["jsonrpc"], "2.0")


class TestCLIDispatch(unittest.TestCase):
    def test_all_commands_are_registered(self):
        """Verify the COMMANDS dict covers all documented commands."""
        expected = [
            "join_network",
            "get_balance", "status", "health",
            "block_height", "get_block", "chain_id", "node_info",
            "register_identity", "resolve_did", "resolve_did_document",
            "revoke_did", "forget_identity",
            "verify_zk_proof",
            # Escrow inspection (secondary indices)
            "get_escrow", "list_escrows_by_payer", "list_escrows_by_payee",
            "verify_transaction", "verify_settlement", "verify_inference",
            "total_supply", "token_balance", "chat",
            "list_model_endpoints", "list_models",
            "route_intent", "chat_by_intent",
            "record_route_outcome", "route_difficulty_stats",
            "create_payment", "verify_payment",
            "get_token_info", "list_tokens",
            "get_token_balance", "deploy_contract",
            "role_stakes", "provider_stats",
            # Events & Webhooks
            "get_events", "get_event_status",
            # SLA Fault Detector
            "sla_issue_probe", "sla_list_outstanding_probes", "sla_get_params",
            # Snapshot (State Sync)
            "list_snapshots", "get_snapshot_manifest",
            "governance_get",
            # Agent Terms
            "get_agent_terms",
        ]
        for cmd in expected:
            self.assertIn(cmd, tenzro_rpc.COMMANDS, f"Missing command: {cmd}")


class TestTrustRecords(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_model_provenance_by_name_and_by_root(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"manifests": []})
        tenzro_rpc.get_model_provenance("org/model", "model.gguf")
        body = mock_post.call_args[1]["json"]
        self.assertEqual(body["method"], "tenzro_getModelProvenance")
        self.assertEqual(body["params"], {"name": "org/model", "file": "model.gguf"})
        tenzro_rpc.get_model_provenance("ab" * 32)
        self.assertEqual(mock_post.call_args[1]["json"]["params"], {"root": "ab" * 32})

    @patch("tenzro_rpc.requests.post")
    def test_submit_trust_record_passes_the_record_through(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"new": True})
        record = {"type": ["VerifiableCredential"], "proof": {"type": "DataIntegrityProof"}}
        result = tenzro_rpc.submit_trust_record(record)
        self.assertTrue(result["new"])
        body = mock_post.call_args[1]["json"]
        self.assertEqual(body["method"], "tenzro_submitTrustRecord")
        self.assertEqual(body["params"], {"record": record})


if __name__ == "__main__":
    unittest.main()
