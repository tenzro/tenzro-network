#!/usr/bin/env python3
"""Tests for tenzro_rpc.py — TenzroClaw OpenClaw skill.

All tests use unittest.mock to patch requests so no live node is needed.
Run: python -m pytest test_tenzro_rpc.py -v
  or: python -m unittest test_tenzro_rpc -v
"""

import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

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
    def test_create_wallet(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "wallet_id": "w-123",
            "address": "0x" + "ab" * 32,
            "display_address": "TenzroDisplayAddress",
            "public_key": "0xpub",
            "key_type": "ed25519",
            "threshold": 2,
            "total_shares": 3,
        })
        result = tenzro_rpc.create_wallet("ed25519")
        self.assertEqual(result["wallet_id"], "w-123")
        self.assertEqual(len(result["address"]), 66)  # 0x + 64 hex chars (32 bytes)
        self.assertEqual(result["threshold"], 2)
        self.assertEqual(result["total_shares"], 3)

    @patch("tenzro_rpc.requests.post")
    def test_get_balance(self, mock_post):
        mock_post.return_value = _mock_rpc_response("0xde0b6b3a7640000")
        result = tenzro_rpc.get_balance("0x1234")
        self.assertEqual(result["address"], "0x1234")
        self.assertIn("balance_tnzo", result)
        self.assertEqual(result["balance_tnzo"], "1.000000")

    @patch("tenzro_rpc.requests.post")
    def test_send_transaction(self, mock_post):
        # Three RPC calls: eth_getTransactionCount, eth_chainId,
        # tenzro_signAndSendTransaction (server-side hybrid-signing path).
        # The server identifies the signing wallet from the ambient
        # DPoP-bound JWT — no private key travels over the wire.
        mock_post.side_effect = [
            _mock_rpc_response("0x0"),
            _mock_rpc_response("0x539"),
            _mock_rpc_response(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            ),
        ]
        result = tenzro_rpc.send_transaction("0xfrom", "0xto", 10**18)
        # Server returns the bare 64-char hex tx hash.
        self.assertEqual(len(result), 64)

class TestFaucet(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_request_faucet(self, mock_post):
        mock_post.return_value = _mock_api_response({
            "success": True,
            "amount": "100",
            "transaction_hash": "0xabc",
        })
        result = tenzro_rpc.request_faucet("0x1234")
        self.assertTrue(result["success"])
        self.assertEqual(result["amount"], "100")


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
        mock_post.return_value = _mock_rpc_response("0x539")
        result = tenzro_rpc.chain_id()
        self.assertEqual(result["chain_id"], 1337)


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

    @patch("tenzro_rpc.requests.post")
    def test_join_as_micro_node(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "did": "did:tenzro:human:new-user",
            "wallet_address": "0xabc",
        })
        result = tenzro_rpc.join_as_micro_node("TestUser")
        self.assertIn("did", result)


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
    def test_create_token(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "token_id": "tok-123",
            "symbol": "MYT",
            "evm_address": "0xtoken",
        })
        result = tenzro_rpc.create_token("My Token", "MYT", "0xcreator", "1000000")
        self.assertEqual(result["symbol"], "MYT")

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
    def test_cross_vm_transfer(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "status": "completed",
            "tx_hash": "0xabc",
        })
        result = tenzro_rpc.cross_vm_transfer(
            "TNZO", "1000", "evm", "svm", "0xfrom", "0xto"
        )
        self.assertEqual(result["status"], "completed")

    @patch("tenzro_rpc.requests.post")
    def test_deploy_contract(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "contract_address": "0xcontract",
            "tx_hash": "0xabc",
        })
        result = tenzro_rpc.deploy_contract("evm", "0x6060", "0xdeployer")
        self.assertEqual(result["contract_address"], "0xcontract")

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


class TestTaskMarketplace(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_post_task(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "task_id": "task-123",
            "status": "open",
        })
        result = tenzro_rpc.post_task(
            "Review code", "Review this Rust code", "code_review", 50 * 10**18
        )
        self.assertEqual(result["task_id"], "task-123")

    @patch("tenzro_rpc.requests.post")
    def test_list_tasks(self, mock_post):
        mock_post.return_value = _mock_rpc_response([
            {"task_id": "task-1", "status": "open"},
            {"task_id": "task-2", "status": "assigned"},
        ])
        result = tenzro_rpc.list_tasks()
        self.assertEqual(len(result), 2)

    @patch("tenzro_rpc.requests.post")
    def test_get_task(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "task_id": "task-123",
            "title": "Review code",
            "status": "open",
        })
        result = tenzro_rpc.get_task("task-123")
        self.assertEqual(result["title"], "Review code")

    @patch("tenzro_rpc.requests.post")
    def test_cancel_task(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "task_id": "task-123",
            "status": "cancelled",
        })
        result = tenzro_rpc.cancel_task("task-123")
        self.assertEqual(result["status"], "cancelled")

    @patch("tenzro_rpc.requests.post")
    def test_submit_quote(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "task_id": "task-123",
            "status": "quoted",
        })
        result = tenzro_rpc.submit_quote("task-123", 40 * 10**18, "gemma4-9b", 30)
        self.assertEqual(result["status"], "quoted")


class TestAgentTemplates(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_list_agent_templates(self, mock_post):
        mock_post.return_value = _mock_rpc_response([
            {"template_id": "t-1", "name": "Code Reviewer"},
        ])
        result = tenzro_rpc.list_agent_templates()
        self.assertEqual(len(result), 1)

    @patch("tenzro_rpc.requests.post")
    def test_register_agent_template(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "template_id": "t-new",
            "name": "Code Reviewer",
        })
        result = tenzro_rpc.register_agent_template(
            "Code Reviewer", "Reviews code", "specialist", "You are a code reviewer"
        )
        self.assertEqual(result["name"], "Code Reviewer")

    @patch("tenzro_rpc.requests.post")
    def test_get_agent_template(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "template_id": "t-1",
            "name": "Code Reviewer",
        })
        result = tenzro_rpc.get_agent_template("t-1")
        self.assertEqual(result["template_id"], "t-1")


class TestAgents(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_register_agent(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "agent_id": "agent-1",
            "status": "active",
        })
        result = tenzro_rpc.register_agent("my-agent", "0xaddr", ["nlp", "code"])
        self.assertEqual(result["agent_id"], "agent-1")

    @patch("tenzro_rpc.requests.post")
    def test_spawn_agent(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "agent_id": "agent-child",
            "parent_id": "agent-1",
        })
        result = tenzro_rpc.spawn_agent("agent-1", "sub-agent", ["data"])
        self.assertEqual(result["parent_id"], "agent-1")

    @patch("tenzro_rpc.requests.post")
    def test_run_agent_task(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "output": "Network has 3 peers and block height 42",
        })
        result = tenzro_rpc.run_agent_task("agent-1", "Summarize stats")
        self.assertIn("output", result)


class TestSwarm(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_create_swarm(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "swarm_id": "swarm-1",
            "orchestrator": "agent-1",
            "agent_count": 2,
        })
        result = tenzro_rpc.create_swarm(
            "agent-1", ["researcher:nlp,data", "coder:code"]
        )
        self.assertEqual(result["swarm_id"], "swarm-1")

    @patch("tenzro_rpc.requests.post")
    def test_get_swarm_status(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "swarm_id": "swarm-1",
            "status": "active",
        })
        result = tenzro_rpc.get_swarm_status("swarm-1")
        self.assertEqual(result["status"], "active")

    @patch("tenzro_rpc.requests.post")
    def test_terminate_swarm(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "swarm_id": "swarm-1",
            "status": "terminated",
        })
        result = tenzro_rpc.terminate_swarm("swarm-1")
        self.assertEqual(result["status"], "terminated")


class TestBridge(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_bridge_tokens(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "bridge_id": "br-123",
            "status": "pending",
        })
        result = tenzro_rpc.bridge_tokens(
            "tenzro", "ethereum", "TNZO", 10**18, "0xsender", "0xrecipient"
        )
        self.assertEqual(result["status"], "pending")


class TestStaking(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_stake_tokens(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "status": "staked",
            "amount": "1000000000000000000",
        })
        result = tenzro_rpc.stake_tokens(10**18, "Validator")
        self.assertEqual(result["status"], "staked")

    @patch("tenzro_rpc.requests.post")
    def test_unstake_tokens(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "status": "unbonding",
        })
        result = tenzro_rpc.unstake_tokens(10**18)
        self.assertEqual(result["status"], "unbonding")

    @patch("tenzro_rpc.requests.post")
    def test_register_provider(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "provider_id": "prov-1",
            "role": "model-provider",
        })
        result = tenzro_rpc.register_provider("model-provider")
        self.assertEqual(result["role"], "model-provider")

    @patch("tenzro_rpc.requests.post")
    def test_provider_stats(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "total_inferences": 100,
            "total_staked": "500000",
        })
        result = tenzro_rpc.provider_stats()
        self.assertEqual(result["total_inferences"], 100)


class TestUsername(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_set_username(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "did": "did:tenzro:human:abc-123",
            "username": "alice",
            "status": "set",
        })
        result = tenzro_rpc.set_username("did:tenzro:human:abc-123", "alice")
        self.assertEqual(result["username"], "alice")
        self.assertEqual(result["status"], "set")

    @patch("tenzro_rpc.requests.post")
    def test_resolve_username(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "did": "did:tenzro:human:abc-123",
            "username": "alice",
            "display_name": "Alice",
        })
        result = tenzro_rpc.resolve_username("alice")
        self.assertEqual(result["did"], "did:tenzro:human:abc-123")
        self.assertEqual(result["username"], "alice")


class TestSkillToolUsage(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_get_skill_usage(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "skill_id": "sk-123",
            "total_invocations": 500,
            "unique_callers": 42,
            "revenue_wei": "10000000000000000000",
        })
        result = tenzro_rpc.get_skill_usage("sk-123")
        self.assertEqual(result["total_invocations"], 500)
        self.assertEqual(result["unique_callers"], 42)

    @patch("tenzro_rpc.requests.post")
    def test_get_tool_usage(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "tool_id": "tool-456",
            "total_invocations": 1200,
            "unique_callers": 85,
            "error_rate": 0.02,
        })
        result = tenzro_rpc.get_tool_usage("tool-456")
        self.assertEqual(result["total_invocations"], 1200)
        self.assertAlmostEqual(result["error_rate"], 0.02)


class TestAgentTemplatesExtended(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_spawn_agent_from_template(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "agent_id": "agent-spawned",
            "template_id": "t-1",
            "name": "my-reviewer",
        })
        result = tenzro_rpc.spawn_agent_from_template("t-1", "my-reviewer")
        self.assertEqual(result["agent_id"], "agent-spawned")
        self.assertEqual(result["template_id"], "t-1")

    @patch("tenzro_rpc.requests.post")
    def test_rate_agent_template(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "template_id": "t-1",
            "rating": 5,
            "status": "rated",
        })
        result = tenzro_rpc.rate_agent_template("t-1", 5, "Excellent template")
        self.assertEqual(result["rating"], 5)
        self.assertEqual(result["status"], "rated")

    @patch("tenzro_rpc.requests.post")
    def test_search_agent_templates(self, mock_post):
        mock_post.return_value = _mock_rpc_response([
            {"template_id": "t-1", "name": "Code Reviewer"},
            {"template_id": "t-2", "name": "Code Auditor"},
        ])
        result = tenzro_rpc.search_agent_templates("code review")
        self.assertEqual(len(result), 2)

    @patch("tenzro_rpc.requests.post")
    def test_get_agent_template_stats(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "template_id": "t-1",
            "spawn_count": 150,
            "average_rating": 4.5,
            "total_reviews": 30,
            "revenue_wei": "50000000000000000000",
        })
        result = tenzro_rpc.get_agent_template_stats("t-1")
        self.assertEqual(result["spawn_count"], 150)
        self.assertAlmostEqual(result["average_rating"], 4.5)


class TestNftCollections(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_create_nft_collection(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "collection_id": "nft-col-1",
            "name": "Tenzro Nodes",
            "symbol": "TNODE",
            "standard": "erc721",
        })
        result = tenzro_rpc.create_nft_collection(
            "Tenzro Nodes", "TNODE", "0xcreator"
        )
        self.assertEqual(result["collection_id"], "nft-col-1")
        self.assertEqual(result["symbol"], "TNODE")

    @patch("tenzro_rpc.requests.post")
    def test_create_nft_collection_erc1155(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "collection_id": "nft-col-2",
            "standard": "erc1155",
        })
        result = tenzro_rpc.create_nft_collection(
            "Multi Tokens", "MTK", "0xcreator", "erc1155"
        )
        self.assertEqual(result["standard"], "erc1155")

    @patch("tenzro_rpc.requests.post")
    def test_mint_nft(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "collection_id": "nft-col-1",
            "token_id": "1",
            "owner": "0xrecipient",
        })
        result = tenzro_rpc.mint_nft(
            "nft-col-1", "0xrecipient", "1", "ipfs://Qm123"
        )
        self.assertEqual(result["token_id"], "1")

    @patch("tenzro_rpc.requests.post")
    def test_mint_nft_batch(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "collection_id": "nft-col-1",
            "minted": 3,
            "token_ids": ["1", "2", "3"],
        })
        result = tenzro_rpc.mint_nft_batch(
            "nft-col-1", "0xrecipient",
            ["1", "2", "3"],
            ["ipfs://Qm1", "ipfs://Qm2", "ipfs://Qm3"],
        )
        self.assertEqual(result["minted"], 3)

    @patch("tenzro_rpc.requests.post")
    def test_transfer_nft(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "tx_hash": "0xabc",
            "status": "confirmed",
        })
        result = tenzro_rpc.transfer_nft(
            "nft-col-1", "0xfrom", "0xto", "1"
        )
        self.assertEqual(result["status"], "confirmed")

    @patch("tenzro_rpc.requests.post")
    def test_get_nft_owner(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "owner": "0xowner123",
        })
        result = tenzro_rpc.get_nft_owner("nft-col-1", "1")
        self.assertEqual(result["owner"], "0xowner123")

    @patch("tenzro_rpc.requests.post")
    def test_get_nft_balance(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "balance": 5,
        })
        result = tenzro_rpc.get_nft_balance("nft-col-1", "0xowner")
        self.assertEqual(result["balance"], 5)

    @patch("tenzro_rpc.requests.post")
    def test_get_nft_collection(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "collection_id": "nft-col-1",
            "name": "Tenzro Nodes",
            "symbol": "TNODE",
            "total_supply": 100,
            "standard": "erc721",
        })
        result = tenzro_rpc.get_nft_collection("nft-col-1")
        self.assertEqual(result["name"], "Tenzro Nodes")
        self.assertEqual(result["total_supply"], 100)

    @patch("tenzro_rpc.requests.post")
    def test_list_nft_collections(self, mock_post):
        mock_post.return_value = _mock_rpc_response([
            {"collection_id": "nft-col-1", "name": "Tenzro Nodes"},
            {"collection_id": "nft-col-2", "name": "Multi Tokens"},
        ])
        result = tenzro_rpc.list_nft_collections()
        self.assertEqual(len(result), 2)


class TestBridgeExtended(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_bridge_quote(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "fee_wei": "500000000000000",
            "estimated_time_secs": 120,
            "protocol": "layerzero",
        })
        result = tenzro_rpc.bridge_quote(
            "tenzro", "ethereum", "TNZO", 10**18
        )
        self.assertIn("fee_wei", result)
        self.assertEqual(result["protocol"], "layerzero")

    @patch("tenzro_rpc.requests.post")
    def test_bridge_quote_with_protocol(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "fee_wei": "300000000000000",
            "protocol": "ccip",
        })
        result = tenzro_rpc.bridge_quote(
            "tenzro", "ethereum", "TNZO", 10**18, "ccip"
        )
        self.assertEqual(result["protocol"], "ccip")

    @patch("tenzro_rpc.requests.post")
    def test_bridge_execute(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "transfer_id": "br-exec-1",
            "status": "pending",
            "tx_hash": "0xabc",
        })
        result = tenzro_rpc.bridge_execute(
            "tenzro", "ethereum", "TNZO", 10**18,
            "0xsender", "0xrecipient"
        )
        self.assertEqual(result["transfer_id"], "br-exec-1")
        self.assertEqual(result["status"], "pending")

    @patch("tenzro_rpc.requests.post")
    def test_bridge_status(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "transfer_id": "br-exec-1",
            "status": "delivered",
            "confirmations": 12,
        })
        result = tenzro_rpc.bridge_status("br-exec-1")
        self.assertEqual(result["status"], "delivered")

    @patch("tenzro_rpc.requests.post")
    def test_bridge_with_hook(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "transfer_id": "br-hook-1",
            "status": "pending",
            "hook_target": "0xhook",
        })
        result = tenzro_rpc.bridge_with_hook(
            "tenzro", "ethereum", "TNZO", 10**18,
            "0xsender", "0xhook", "0xcalldata"
        )
        self.assertEqual(result["transfer_id"], "br-hook-1")
        self.assertEqual(result["hook_target"], "0xhook")


class TestCrosschainERC7802(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_crosschain_mint(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "tx_hash": "0xmint",
            "amount": "1000000000000000000",
        })
        result = tenzro_rpc.crosschain_mint(
            "0xbridge", "0xrecipient", 10**18, "0xsender"
        )
        self.assertIn("tx_hash", result)

    @patch("tenzro_rpc.requests.post")
    def test_crosschain_burn(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "tx_hash": "0xburn",
            "amount": "1000000000000000000",
        })
        result = tenzro_rpc.crosschain_burn(
            "0xbridge", "0xfrom", 10**18, "ethereum"
        )
        self.assertIn("tx_hash", result)

    @patch("tenzro_rpc.requests.post")
    def test_authorize_bridge(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "bridge": "0xbridge",
            "name": "LayerZero V2",
            "status": "authorized",
        })
        result = tenzro_rpc.authorize_bridge(
            "0xbridge", "LayerZero V2", 10**22, 10**22
        )
        self.assertEqual(result["status"], "authorized")

    @patch("tenzro_rpc.requests.post")
    def test_list_authorized_bridges(self, mock_post):
        mock_post.return_value = _mock_rpc_response([
            {"bridge": "0xbridge1", "name": "LayerZero V2"},
            {"bridge": "0xbridge2", "name": "CCIP"},
        ])
        result = tenzro_rpc.list_authorized_bridges()
        self.assertEqual(len(result), 2)


class TestComplianceERC3643(unittest.TestCase):
    @patch("tenzro_rpc.requests.post")
    def test_check_compliance(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "compliant": True,
            "checks_passed": ["kyc", "jurisdiction"],
        })
        result = tenzro_rpc.check_compliance(
            "tok-sec-1", "0xfrom", "0xto", 10**18
        )
        self.assertTrue(result["compliant"])

    @patch("tenzro_rpc.requests.post")
    def test_check_compliance_rejected(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "compliant": False,
            "reason": "sender_not_kyc_verified",
        })
        result = tenzro_rpc.check_compliance(
            "tok-sec-1", "0xunverified", "0xto", 10**18
        )
        self.assertFalse(result["compliant"])

    @patch("tenzro_rpc.requests.post")
    def test_register_compliance(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "token_id": "tok-sec-1",
            "status": "registered",
            "require_kyc": True,
            "min_kyc_tier": 2,
        })
        result = tenzro_rpc.register_compliance(
            "tok-sec-1", require_kyc=True, min_kyc_tier=2
        )
        self.assertEqual(result["status"], "registered")
        self.assertTrue(result["require_kyc"])

    @patch("tenzro_rpc.requests.post")
    def test_freeze_address(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "token_id": "tok-sec-1",
            "address": "0xfrozen",
            "status": "frozen",
        })
        result = tenzro_rpc.freeze_address(
            "tok-sec-1", "0xfrozen", "sanctions"
        )
        self.assertEqual(result["status"], "frozen")

    @patch("tenzro_rpc.requests.post")
    def test_unfreeze_address(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "token_id": "tok-sec-1",
            "address": "0xfrozen",
            "status": "active",
        })
        result = tenzro_rpc.unfreeze_address("tok-sec-1", "0xfrozen")
        self.assertEqual(result["status"], "active")

    @patch("tenzro_rpc.requests.post")
    def test_recover_tokens(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "tx_hash": "0xrecover",
            "amount": "1000000000000000000",
            "status": "recovered",
        })
        result = tenzro_rpc.recover_tokens(
            "tok-sec-1", "0xfrom", "0xto", 10**18, "court_order"
        )
        self.assertEqual(result["status"], "recovered")

    @patch("tenzro_rpc.requests.post")
    def test_add_identity_claim(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "claim_id": "claim-1",
            "address": "0xaddr",
            "topic": "kyc",
        })
        result = tenzro_rpc.add_identity_claim(
            "0xaddr", "kyc", "did:tenzro:human:issuer-1"
        )
        self.assertEqual(result["topic"], "kyc")

    @patch("tenzro_rpc.requests.post")
    def test_add_trusted_issuer(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "issuer_did": "did:tenzro:human:issuer-1",
            "name": "KYC Corp",
            "status": "trusted",
        })
        result = tenzro_rpc.add_trusted_issuer(
            "did:tenzro:human:issuer-1", "KYC Corp", ["kyc", "accredited_investor"]
        )
        self.assertEqual(result["status"], "trusted")


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
            filter={"type": "transfer"}, from_sequence=4, limit=10
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

    @patch("tenzro_rpc.requests.post")
    def test_register_webhook(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "webhook_id": "wh-1",
            "url": "https://example.com/hook",
            "status": "active",
        })
        result = tenzro_rpc.register_webhook("https://example.com/hook")
        self.assertEqual(result["webhook_id"], "wh-1")
        self.assertEqual(result["status"], "active")

    @patch("tenzro_rpc.requests.post")
    def test_list_webhooks(self, mock_post):
        mock_post.return_value = _mock_rpc_response([
            {"webhook_id": "wh-1", "url": "https://example.com/hook"},
        ])
        result = tenzro_rpc.list_webhooks()
        self.assertEqual(len(result), 1)

    @patch("tenzro_rpc.requests.post")
    def test_delete_webhook(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "webhook_id": "wh-1",
            "status": "deleted",
        })
        result = tenzro_rpc.delete_webhook("wh-1")
        self.assertEqual(result["status"], "deleted")


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
            "join_network", "create_wallet",
            "get_balance", "send", "faucet", "status", "health",
            "block_height", "get_block", "chain_id", "node_info",
            "register_identity", "resolve_did", "resolve_did_document",
            "set_username", "resolve_username",
            "set_delegation", "verify_zk_proof",
            "verify_transaction", "verify_settlement", "verify_inference",
            "total_supply", "token_balance", "chat",
            "list_model_endpoints", "list_models",
            "create_payment", "verify_payment",
            "post_task", "list_tasks", "get_task", "cancel_task", "submit_quote",
            "list_agent_templates", "register_agent_template", "get_agent_template",
            "spawn_agent_from_template", "rate_agent_template",
            "search_agent_templates", "get_agent_template_stats",
            "register_agent", "spawn_agent", "run_agent_task",
            "create_swarm", "get_swarm_status", "terminate_swarm",
            "create_token", "get_token_info", "list_tokens",
            "get_token_balance", "cross_vm_transfer", "deploy_contract",
            "bridge_tokens", "stake", "unstake", "register_provider", "provider_stats",
            "list_skills", "register_skill", "search_skills", "use_skill",
            "get_skill_usage", "get_tool_usage",
            "spawn_agent_with_skill",
            # NFT Collections
            "create_nft_collection", "mint_nft", "mint_nft_batch",
            "transfer_nft", "get_nft_owner", "get_nft_balance",
            "get_nft_collection", "list_nft_collections",
            # Bridge (Extended)
            "bridge_quote", "bridge_execute", "bridge_status", "bridge_with_hook",
            # ERC-7802 Crosschain
            "crosschain_mint", "crosschain_burn",
            "authorize_bridge", "list_authorized_bridges",
            # ERC-3643 Compliance
            "check_compliance", "register_compliance",
            "freeze_address", "unfreeze_address", "recover_tokens",
            "add_identity_claim", "add_trusted_issuer",
            # Events & Webhooks
            "get_events", "get_event_status",
            "register_webhook", "list_webhooks", "delete_webhook",
            # AP2 (Agent Payments Protocol)
            "ap2_protocol_info", "ap2_verify_mandate",
            "ap2_validate_mandate_pair", "ap2_create_session",
            "ap2_authorize_payment", "ap2_execute_payment",
            "ap2_cancel_session", "ap2_get_session",
            "ap2_list_agent_sessions",
            # ERC-8004 Trustless Agents
            "erc8004_derive_agent_id", "erc8004_encode_register",
            "erc8004_encode_get_agent", "erc8004_decode_get_agent",
            "erc8004_encode_feedback",
            "erc8004_encode_request_validation",
            "erc8004_encode_submit_validation",
            # Wormhole
            "wormhole_chain_id", "wormhole_parse_vaa_id",
            "wormhole_bridge",
            # CCT pool registry
            "cct_list_pools", "cct_get_pool",
        ]
        for cmd in expected:
            self.assertIn(cmd, tenzro_rpc.COMMANDS, f"Missing command: {cmd}")


class TestAp2(unittest.TestCase):
    """Tests for AP2 (Agent Payments Protocol) wrappers."""

    @patch("tenzro_rpc.requests.post")
    def test_ap2_protocol_info(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "protocol": "ap2",
            "version": "0.1",
            "supported_vdc_types": ["intent", "cart", "payment"],
        })
        result = tenzro_rpc.ap2_protocol_info()
        self.assertEqual(result["protocol"], "ap2")
        # Verify JSON-RPC method name
        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs["json"]["method"], "tenzro_ap2ProtocolInfo")

    @patch("tenzro_rpc.requests.post")
    def test_ap2_verify_mandate(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"valid": True})
        vdc = {
            "type": "intent",
            "issuer": "did:tenzro:human:alice",
            "subject": "did:tenzro:machine:agent-1",
            "payload": {"max_amount": 1000},
            "signature": "0xabcd",
        }
        result = tenzro_rpc.ap2_verify_mandate(vdc)
        self.assertTrue(result["valid"])
        args, kwargs = mock_post.call_args
        self.assertEqual(
            kwargs["json"]["method"], "tenzro_ap2VerifyMandate"
        )
        self.assertEqual(kwargs["json"]["params"]["vdc"], vdc)

    @patch("tenzro_rpc.requests.post")
    def test_ap2_validate_mandate_pair(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "valid": True, "matched_subject": True,
            "delegation_enforced": False,
        })
        intent = {"type": "intent"}
        cart = {"type": "cart"}
        result = tenzro_rpc.ap2_validate_mandate_pair(intent, cart)
        self.assertTrue(result["valid"])
        args, kwargs = mock_post.call_args
        self.assertEqual(
            kwargs["json"]["method"], "tenzro_ap2ValidateMandatePair"
        )
        # Default: enforce_delegation flag is forwarded as False.
        self.assertEqual(
            kwargs["json"]["params"]["enforce_delegation"], False
        )

    @patch("tenzro_rpc.requests.post")
    def test_ap2_validate_mandate_pair_with_delegation(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "valid": True, "matched_subject": True,
            "delegation_enforced": True,
        })
        intent = {"type": "intent"}
        cart = {"type": "cart"}
        result = tenzro_rpc.ap2_validate_mandate_pair(
            intent, cart, enforce_delegation=True,
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["delegation_enforced"])
        args, kwargs = mock_post.call_args
        self.assertEqual(
            kwargs["json"]["method"], "tenzro_ap2ValidateMandatePair"
        )
        self.assertEqual(
            kwargs["json"]["params"]["enforce_delegation"], True
        )

    @patch("tenzro_rpc.requests.post")
    def test_ap2_create_session(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "session_id": "sess-123",
            "status": "active",
        })
        result = tenzro_rpc.ap2_create_session(
            "did:tenzro:machine:agent-1",
            "did:tenzro:machine:provider-1",
            "inference",
            1000,
            "TNZO",
        )
        self.assertEqual(result["session_id"], "sess-123")
        args, kwargs = mock_post.call_args
        params = kwargs["json"]["params"]
        self.assertEqual(params["max_amount"], 1000)
        self.assertEqual(params["asset"], "TNZO")

    @patch("tenzro_rpc.requests.post")
    def test_ap2_authorize_payment(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "authorization_id": "auth-456",
        })
        result = tenzro_rpc.ap2_authorize_payment("sess-123", 100)
        self.assertEqual(result["authorization_id"], "auth-456")

    @patch("tenzro_rpc.requests.post")
    def test_ap2_execute_payment(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "tx_hash": "0xexec",
        })
        result = tenzro_rpc.ap2_execute_payment("sess-123", "auth-456")
        self.assertEqual(result["tx_hash"], "0xexec")

    @patch("tenzro_rpc.requests.post")
    def test_ap2_cancel_session(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"status": "cancelled"})
        result = tenzro_rpc.ap2_cancel_session("sess-123")
        self.assertEqual(result["status"], "cancelled")

    @patch("tenzro_rpc.requests.post")
    def test_ap2_get_session(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "session_id": "sess-123",
            "spent": 450,
        })
        result = tenzro_rpc.ap2_get_session("sess-123")
        self.assertEqual(result["spent"], 450)

    @patch("tenzro_rpc.requests.post")
    def test_ap2_list_agent_sessions(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "sessions": [{"session_id": "sess-123"}],
        })
        result = tenzro_rpc.ap2_list_agent_sessions(
            "did:tenzro:machine:agent-1"
        )
        self.assertEqual(len(result["sessions"]), 1)


class TestErc8004(unittest.TestCase):
    """Tests for ERC-8004 Trustless Agents Registry wrappers."""

    @patch("tenzro_rpc.requests.post")
    def test_derive_agent_id(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "agent_id": "0xdeadbeef",
        })
        result = tenzro_rpc.erc8004_derive_agent_id(
            "0xowner", "0xsalt"
        )
        self.assertEqual(result["agent_id"], "0xdeadbeef")
        args, kwargs = mock_post.call_args
        self.assertEqual(
            kwargs["json"]["method"], "tenzro_erc8004DeriveAgentId"
        )

    @patch("tenzro_rpc.requests.post")
    def test_encode_register(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "calldata": "0xabcdef",
        })
        result = tenzro_rpc.erc8004_encode_register(
            "0xagent", "ipfs://Qm...", "0xowner"
        )
        self.assertTrue(result["calldata"].startswith("0x"))

    @patch("tenzro_rpc.requests.post")
    def test_encode_get_agent(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"calldata": "0x123"})
        result = tenzro_rpc.erc8004_encode_get_agent("0xagent")
        self.assertIn("calldata", result)

    @patch("tenzro_rpc.requests.post")
    def test_decode_get_agent(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "agent_id": "0xagent",
            "owner": "0xowner",
            "registration_data_uri": "ipfs://Qm...",
        })
        result = tenzro_rpc.erc8004_decode_get_agent("0xreturndata")
        self.assertEqual(result["owner"], "0xowner")

    @patch("tenzro_rpc.requests.post")
    def test_encode_feedback(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"calldata": "0xfeed"})
        result = tenzro_rpc.erc8004_encode_feedback(
            "0xagent", 95, "0xauth", "ipfs://feedback"
        )
        self.assertIn("calldata", result)
        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs["json"]["params"]["score"], 95)

    @patch("tenzro_rpc.requests.post")
    def test_encode_request_validation(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"calldata": "0xreq"})
        result = tenzro_rpc.erc8004_encode_request_validation(
            "0xagent", "0xvalidator", "ipfs://req", "0xdatahash"
        )
        self.assertIn("calldata", result)

    @patch("tenzro_rpc.requests.post")
    def test_encode_submit_validation(self, mock_post):
        mock_post.return_value = _mock_rpc_response({"calldata": "0xsub"})
        result = tenzro_rpc.erc8004_encode_submit_validation(
            "0xdatahash", 1, "ipfs://resp", "tag"
        )
        self.assertIn("calldata", result)


class TestWormhole(unittest.TestCase):
    """Tests for Wormhole cross-chain wrappers."""

    @patch("tenzro_rpc.requests.post")
    def test_chain_id(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "chain": "ethereum",
            "wormhole_chain_id": 2,
        })
        result = tenzro_rpc.wormhole_chain_id("ethereum")
        self.assertEqual(result["wormhole_chain_id"], 2)
        args, kwargs = mock_post.call_args
        self.assertEqual(
            kwargs["json"]["method"], "tenzro_wormholeChainId"
        )

    @patch("tenzro_rpc.requests.post")
    def test_parse_vaa_id(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "emitter_chain": 2,
            "emitter_address": "0xemitter",
            "sequence": 42,
        })
        result = tenzro_rpc.wormhole_parse_vaa_id(
            "2/0xemitter/42"
        )
        self.assertEqual(result["sequence"], 42)

    @patch("tenzro_rpc.requests.post")
    def test_bridge(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "vaa_id": "1/0xabc/100",
            "status": "submitted",
        })
        result = tenzro_rpc.wormhole_bridge(
            "tenzro", "ethereum", "TNZO",
            1000000000000000000, "0xsender", "0xrecipient",
        )
        self.assertEqual(result["status"], "submitted")
        args, kwargs = mock_post.call_args
        self.assertEqual(
            kwargs["json"]["method"], "tenzro_wormholeBridge"
        )


class TestCct(unittest.TestCase):
    """Tests for Chainlink CCT pool registry wrappers."""

    @patch("tenzro_rpc.requests.post")
    def test_list_pools(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "pools": [
                {"chain": "ethereum", "pool": "0xpool1", "type": "burn_mint"},
                {"chain": "base", "pool": "0xpool2", "type": "lock_release"},
            ],
        })
        result = tenzro_rpc.cct_list_pools()
        self.assertEqual(len(result["pools"]), 2)
        args, kwargs = mock_post.call_args
        self.assertEqual(
            kwargs["json"]["method"], "tenzro_cctListPools"
        )

    @patch("tenzro_rpc.requests.post")
    def test_get_pool(self, mock_post):
        mock_post.return_value = _mock_rpc_response({
            "chain": "ethereum",
            "pool": "0xpool1",
            "type": "burn_mint",
            "rate_limit": {"capacity": 1000, "refill_rate": 10},
        })
        result = tenzro_rpc.cct_get_pool("ethereum")
        self.assertEqual(result["pool"], "0xpool1")
        self.assertEqual(result["type"], "burn_mint")


if __name__ == "__main__":
    unittest.main()
