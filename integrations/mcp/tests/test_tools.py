"""Tests for tenzro_mcp_server.server MCP tools.

fastmcp 3.x's bare ``@mcp.tool`` decorator registers the tool and returns the
original async function, so tools are invoked directly. ``rpc_call`` /
``api_call`` are replaced by AsyncMocks via the ``mock_rpc`` / ``mock_api``
fixtures (see conftest.py) — each test asserts the exact RPC method name and
params dispatched, plus result passthrough."""

from unittest.mock import call

import tenzro_mcp_server.server as server


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


async def test_all_tools_registered_with_unique_names():
    tools = await server.mcp.list_tools()
    names = [t.name for t in tools]
    assert len(names) == len(set(names))
    assert len(names) >= 250
    for expected in ("get_balance", "register_identity", "chat_completion",
                     "stake_tokens", "bridge_tokens", "canton_allocate_party"):
        assert expected in names


# ---------------------------------------------------------------------------
# Wallet & balance
# ---------------------------------------------------------------------------


async def test_get_balance(mock_rpc):
    mock_rpc.return_value = "0xde0b6b3a7640000"
    result = await server.get_balance("0xabc")
    mock_rpc.assert_awaited_once_with("eth_getBalance", ["0xabc", "latest"])
    assert result == {"address": "0xabc", "balance": "0xde0b6b3a7640000"}


async def test_create_wallet(mock_rpc):
    mock_rpc.return_value = {"wallet_id": "w1", "address": "0xfeed"}
    result = await server.create_wallet()
    mock_rpc.assert_awaited_once_with("tenzro_createWallet", [])
    assert result == {"wallet_id": "w1", "address": "0xfeed"}


async def test_send_transaction_full_flow(mock_rpc):
    def dispatch(method, params=None):
        return {
            "eth_getTransactionCount": "0x5",
            "eth_chainId": "0x539",
            "tenzro_signAndSendTransaction": "0xtxhash",
        }[method]

    mock_rpc.side_effect = dispatch
    result = await server.send_transaction("0xfrom", "0xto", "1000")
    assert mock_rpc.await_args_list == [
        call("eth_getTransactionCount", ["0xfrom", "latest"]),
        call("eth_chainId", []),
        call(
            "tenzro_signAndSendTransaction",
            {
                "from": "0xfrom",
                "to": "0xto",
                "value": "1000",
                "gas_limit": 21000,
                "gas_price": 1_000_000_000,
                "nonce": 5,
                "chain_id": 1337,
            },
        ),
    ]
    assert result == {"tx_hash": "0xtxhash"}


async def test_send_transaction_hex_amount(mock_rpc):
    def dispatch(method, params=None):
        return {
            "eth_getTransactionCount": "0x0",
            "eth_chainId": "0x539",
            "tenzro_signAndSendTransaction": {"status": "accepted"},
        }[method]

    mock_rpc.side_effect = dispatch
    result = await server.send_transaction("0xfrom", "0xto", "0x10")
    sent = mock_rpc.await_args_list[-1]
    assert sent.args[1]["value"] == "16"
    assert result == {"status": "accepted"}


async def test_send_self_custody_transaction_explicit(mock_rpc):
    # nonce + chain_id passed explicitly (fixed at signing time) → only the
    # eth_sendRawTransaction call fires, no live nonce/chain lookup.
    mock_rpc.return_value = "0xselfhash"
    result = await server.send_self_custody_transaction(
        from_addr="0xfrom",
        to_addr="0xto",
        value="1000",
        signature="0xedsig",
        public_key="0xedpub",
        pq_signature="0xpqsig",
        pq_public_key="0xpqpub",
        timestamp=1_700_000_000_000,
        nonce=7,
        chain_id=1337,
    )
    mock_rpc.assert_awaited_once_with(
        "eth_sendRawTransaction",
        {
            "from": "0xfrom",
            "to": "0xto",
            "value": "1000",
            "gas_limit": 21000,
            "gas_price": 1_000_000_000,
            "nonce": 7,
            "chain_id": 1337,
            "timestamp": 1_700_000_000_000,
            "public_key": "0xedpub",
            "signature": "0xedsig",
            "pq_public_key": "0xpqpub",
            "pq_signature": "0xpqsig",
        },
    )
    assert result == {"tx_hash": "0xselfhash"}


async def test_send_self_custody_transaction_queries_nonce_and_chain(mock_rpc):
    def dispatch(method, params=None):
        return {
            "eth_getTransactionCount": "0x3",
            "eth_chainId": "0x539",
            "eth_sendRawTransaction": "0xselfhash",
        }[method]

    mock_rpc.side_effect = dispatch
    result = await server.send_self_custody_transaction(
        from_addr="0xfrom",
        to_addr="0xto",
        value="500",
        signature="0xedsig",
        public_key="0xedpub",
        pq_signature="0xpqsig",
        pq_public_key="0xpqpub",
        timestamp=1_700_000_000_000,
    )
    assert mock_rpc.await_args_list[:2] == [
        call("eth_getTransactionCount", ["0xfrom", "latest"]),
        call("eth_chainId", []),
    ]
    sent = mock_rpc.await_args_list[-1]
    assert sent.args[0] == "eth_sendRawTransaction"
    assert sent.args[1]["nonce"] == 3
    assert sent.args[1]["chain_id"] == 1337
    assert result == {"tx_hash": "0xselfhash"}


async def test_request_faucet(mock_rpc):
    mock_rpc.return_value = {"granted": "100"}
    result = await server.request_faucet("0xabc")
    mock_rpc.assert_awaited_once_with("tenzro_faucet", {"address": "0xabc"})
    assert result == {"granted": "100"}


async def test_token_balance(mock_rpc):
    mock_rpc.return_value = "500"
    result = await server.token_balance("0xabc")
    mock_rpc.assert_awaited_once_with("tenzro_tokenBalance", {"address": "0xabc"})
    assert result == {"address": "0xabc", "balance": "500"}


async def test_total_supply(mock_rpc):
    mock_rpc.return_value = "1000000000"
    result = await server.total_supply()
    mock_rpc.assert_awaited_once_with("tenzro_totalSupply", [])
    assert result == {"total_supply": "1000000000"}


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


async def test_register_identity(mock_rpc):
    mock_rpc.return_value = {"did": "did:tenzro:human:u1"}
    result = await server.register_identity("human", "Alice")
    mock_rpc.assert_awaited_once_with(
        "tenzro_registerIdentity", ["human", "Alice"]
    )
    assert result == {"did": "did:tenzro:human:u1"}


async def test_resolve_did(mock_rpc):
    did = "did:tenzro:machine:m1"
    await server.resolve_did(did)
    mock_rpc.assert_awaited_once_with("tenzro_resolveIdentity", {"did": did})


async def test_revoke_did_default_reason(mock_rpc):
    await server.revoke_did("did:tenzro:human:u1")
    mock_rpc.assert_awaited_once_with(
        "tenzro_revokeDid",
        {"did": "did:tenzro:human:u1", "reason": "revoked via MCP"},
    )


async def test_set_delegation_scope_omits_unset_optionals(mock_rpc):
    await server.set_delegation_scope("did:tenzro:machine:m1")
    mock_rpc.assert_awaited_once_with(
        "tenzro_setDelegationScope", {"machine_did": "did:tenzro:machine:m1"}
    )


async def test_set_delegation_scope_full(mock_rpc):
    await server.set_delegation_scope(
        "did:tenzro:machine:m1",
        max_transaction_value=1000,
        allowed_operations=["transfer"],
    )
    mock_rpc.assert_awaited_once_with(
        "tenzro_setDelegationScope",
        {
            "machine_did": "did:tenzro:machine:m1",
            "max_transaction_value": 1000,
            "allowed_operations": ["transfer"],
        },
    )


async def test_resolve_username(mock_rpc):
    await server.resolve_username("alice")
    mock_rpc.assert_awaited_once_with(
        "tenzro_resolveUsername", {"username": "alice"}
    )


# ---------------------------------------------------------------------------
# Payments
# ---------------------------------------------------------------------------


async def test_create_payment_challenge(mock_rpc):
    await server.create_payment_challenge("mpp", "/chat", "10")
    mock_rpc.assert_awaited_once_with(
        "tenzro_createPaymentChallenge",
        {"protocol": "mpp", "resource": "/chat", "amount": "10"},
    )


async def test_verify_payment(mock_rpc):
    await server.verify_payment("ch1", "x402", "did:tenzro:human:u1", "10")
    mock_rpc.assert_awaited_once_with(
        "tenzro_verifyPayment",
        {
            "challenge_id": "ch1",
            "protocol": "x402",
            "payer_did": "did:tenzro:human:u1",
            "amount": "10",
        },
    )


async def test_list_payment_protocols(mock_rpc):
    mock_rpc.return_value = {"protocols": ["mpp", "x402", "native"]}
    result = await server.list_payment_protocols()
    mock_rpc.assert_awaited_once_with("tenzro_paymentGatewayInfo", [])
    assert result == {"protocols": ["mpp", "x402", "native"]}


async def test_settle_payment(mock_rpc):
    await server.settle_payment("0xfrom", "0xto", "42", "inference")
    mock_rpc.assert_awaited_once_with(
        "tenzro_settle",
        {
            "from": "0xfrom",
            "to": "0xto",
            "amount": "42",
            "service_type": "inference",
        },
    )


# ---------------------------------------------------------------------------
# Inference & chat
# ---------------------------------------------------------------------------


async def test_list_models_no_filters(mock_rpc):
    await server.list_models()
    mock_rpc.assert_awaited_once_with("tenzro_listModels", [])


async def test_list_models_with_filters(mock_rpc):
    await server.list_models(category="llm", name="qwen")
    mock_rpc.assert_awaited_once_with(
        "tenzro_listModels", {"category": "llm", "name": "qwen"}
    )


async def test_chat_completion_defaults(mock_rpc):
    mock_rpc.return_value = {"response": "hi"}
    result = await server.chat_completion("qwen3-0.6b", "hello")
    mock_rpc.assert_awaited_once_with(
        "tenzro_chat",
        {
            "model": "qwen3-0.6b",
            "message": "hello",
            "temperature": 0.7,
            "max_tokens": 1024,
        },
    )
    assert result == {"response": "hi"}


async def test_serve_model(mock_rpc):
    await server.serve_model("m1")
    mock_rpc.assert_awaited_once_with("tenzro_serveModel", {"model_id": "m1"})


async def test_stop_model(mock_rpc):
    await server.stop_model("m1")
    mock_rpc.assert_awaited_once_with("tenzro_stopModel", {"model_id": "m1"})


# ---------------------------------------------------------------------------
# Staking & providers
# ---------------------------------------------------------------------------


async def test_stake_tokens(mock_rpc):
    await server.stake_tokens("10000", "Validator")
    mock_rpc.assert_awaited_once_with(
        "tenzro_stake", {"amount": "10000", "provider_type": "Validator"}
    )


async def test_unstake_tokens(mock_rpc):
    await server.unstake_tokens("500", "ModelProvider")
    mock_rpc.assert_awaited_once_with(
        "tenzro_unstake", {"amount": "500", "provider_type": "ModelProvider"}
    )


async def test_register_provider(mock_rpc):
    await server.register_provider("TeeProvider", "https://tee.example")
    mock_rpc.assert_awaited_once_with(
        "tenzro_registerProvider",
        {"provider_type": "TeeProvider", "endpoint": "https://tee.example"},
    )


async def test_get_provider_stats_positional(mock_rpc):
    await server.get_provider_stats("0xabc")
    mock_rpc.assert_awaited_once_with("tenzro_providerStats", ["0xabc"])


async def test_get_provider_stats_no_address(mock_rpc):
    await server.get_provider_stats()
    mock_rpc.assert_awaited_once_with("tenzro_providerStats", [])


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


async def test_create_token(mock_rpc):
    await server.create_token("Test", "TST")
    mock_rpc.assert_awaited_once_with(
        "tenzro_createToken",
        {
            "name": "Test",
            "symbol": "TST",
            "decimals": 18,
            "initial_supply": "1000000",
        },
    )


async def test_get_token_info_dispatch_by_evm_address(mock_rpc):
    addr = "0x" + "a" * 40
    await server.get_token_info(addr)
    mock_rpc.assert_awaited_once_with("tenzro_getToken", {"evm_address": addr})


async def test_get_token_info_dispatch_by_token_id(mock_rpc):
    await server.get_token_info("12345")
    mock_rpc.assert_awaited_once_with("tenzro_getToken", {"token_id": "12345"})


async def test_get_token_info_dispatch_by_symbol(mock_rpc):
    await server.get_token_info("TNZO")
    mock_rpc.assert_awaited_once_with("tenzro_getToken", {"symbol": "TNZO"})


async def test_list_tokens_with_vm_filter(mock_rpc):
    await server.list_tokens("evm")
    mock_rpc.assert_awaited_once_with("tenzro_listTokens", ["evm"])


async def test_wrap_tnzo(mock_rpc):
    await server.wrap_tnzo("0xabc", "1000")
    mock_rpc.assert_awaited_once_with(
        "tenzro_wrapTnzo", {"address": "0xabc", "amount": "1000", "to_vm": "evm"}
    )


async def test_get_token_balance(mock_rpc):
    await server.get_token_balance("0xabc")
    mock_rpc.assert_awaited_once_with(
        "tenzro_getTokenBalance", {"address": "0xabc"}
    )


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


async def test_bridge_tokens(mock_rpc):
    await server.bridge_tokens("TNZO", "tenzro", "ethereum", "100", "0xrecv")
    mock_rpc.assert_awaited_once_with(
        "tenzro_bridgeTokens",
        {
            "token": "TNZO",
            "from_chain": "tenzro",
            "to_chain": "ethereum",
            "amount": "100",
            "recipient": "0xrecv",
        },
    )


async def test_get_bridge_routes_positional(mock_rpc):
    await server.get_bridge_routes("tenzro", "solana")
    mock_rpc.assert_awaited_once_with(
        "tenzro_getBridgeRoutes", ["tenzro", "solana"]
    )


async def test_list_bridge_adapters(mock_rpc):
    await server.list_bridge_adapters()
    mock_rpc.assert_awaited_once_with("tenzro_listBridgeAdapters", [])


async def test_bridge_quote(mock_rpc):
    await server.bridge_quote("TNZO", "tenzro", "base", "50")
    mock_rpc.assert_awaited_once_with(
        "tenzro_bridgeQuote",
        {
            "token": "TNZO",
            "from_chain": "tenzro",
            "to_chain": "base",
            "amount": "50",
        },
    )


# ---------------------------------------------------------------------------
# Verification (ZK / signatures / TEE)
# ---------------------------------------------------------------------------


async def test_verify_zk_proof_uses_web_api(mock_api, mock_rpc):
    mock_api.return_value = {"valid": True}
    result = await server.verify_zk_proof("00ff", "inference", ["01000000"])
    mock_api.assert_awaited_once_with(
        "/verify/zk-proof",
        "POST",
        {
            "proof_bytes": "00ff",
            "circuit_id": "inference",
            "public_inputs": ["01000000"],
        },
    )
    mock_rpc.assert_not_awaited()
    assert result == {"valid": True}


async def test_verify_signature(mock_rpc):
    await server.verify_signature("aa" * 32, "deadbeef", "bb" * 64)
    mock_rpc.assert_awaited_once_with(
        "tenzro_verifySignature",
        {
            "public_key": "aa" * 32,
            "message_hex": "deadbeef",
            "signature_hex": "bb" * 64,
        },
    )


async def test_verify_tee_attestation_rpc(mock_rpc):
    await server.verify_tee_attestation_rpc("tdx", "00ff")
    mock_rpc.assert_awaited_once_with(
        "tenzro_verifyTeeAttestation", {"provider": "tdx", "quote_hex": "00ff"}
    )


async def test_create_zk_proof_merges_witness_json(mock_rpc):
    witness = '{"model_checksum": 1, "input_checksum": 2, "computed_output": 3}'
    await server.create_zk_proof("inference", witness)
    mock_rpc.assert_awaited_once_with(
        "tenzro_createZkProof",
        {
            "circuit_id": "inference",
            "model_checksum": 1,
            "input_checksum": 2,
            "computed_output": 3,
        },
    )


async def test_list_zk_circuits(mock_rpc):
    await server.list_zk_circuits()
    mock_rpc.assert_awaited_once_with("tenzro_listCircuits", [])


# ---------------------------------------------------------------------------
# Agents & swarms
# ---------------------------------------------------------------------------


async def test_register_agent(mock_rpc):
    await server.register_agent("scout", ["search", "summarize"])
    mock_rpc.assert_awaited_once_with(
        "tenzro_registerAgent",
        {"name": "scout", "capabilities": ["search", "summarize"]},
    )


async def test_send_agent_message(mock_rpc):
    await server.send_agent_message("a1", "a2", "task", '{"x":1}')
    mock_rpc.assert_awaited_once_with(
        "tenzro_sendAgentMessage",
        {
            "from": "a1",
            "to": "a2",
            "message_type": "task",
            "payload": '{"x":1}',
        },
    )


async def test_spawn_agent(mock_rpc):
    await server.spawn_agent("did:tenzro:human:u1", "worker", "executor")
    mock_rpc.assert_awaited_once_with(
        "tenzro_spawnAgent",
        {"parent_did": "did:tenzro:human:u1", "name": "worker", "role": "executor"},
    )


async def test_create_swarm(mock_rpc):
    await server.create_swarm("did:tenzro:machine:orch", 5)
    mock_rpc.assert_awaited_once_with(
        "tenzro_createSwarm",
        {"orchestrator_did": "did:tenzro:machine:orch", "member_count": 5},
    )


async def test_list_agents(mock_rpc):
    await server.list_agents()
    mock_rpc.assert_awaited_once_with("tenzro_listAgents", [])


# ---------------------------------------------------------------------------
# Canton
# ---------------------------------------------------------------------------


async def test_canton_list_domains(mock_rpc):
    await server.canton_list_domains()
    mock_rpc.assert_awaited_once_with("tenzro_listCantonDomains", {})


async def test_canton_list_contracts_optional_query(mock_rpc):
    await server.canton_list_contracts(["Splice.Amulet:Amulet"])
    mock_rpc.assert_awaited_once_with(
        "tenzro_listDamlContracts", {"template_ids": ["Splice.Amulet:Amulet"]}
    )


async def test_canton_submit_command_create(mock_rpc):
    await server.canton_submit_command(
        "create", "Main:Asset", arguments={"owner": "p1"}
    )
    mock_rpc.assert_awaited_once_with(
        "tenzro_submitDamlCommand",
        {
            "command_type": "create",
            "template_id": "Main:Asset",
            "arguments": {"owner": "p1"},
        },
    )


async def test_canton_submit_command_exercise(mock_rpc):
    await server.canton_submit_command(
        "exercise",
        "Main:Asset",
        contract_id="#1:0",
        choice="Transfer",
        choice_argument={"newOwner": "p2"},
    )
    mock_rpc.assert_awaited_once_with(
        "tenzro_submitDamlCommand",
        {
            "command_type": "exercise",
            "template_id": "Main:Asset",
            "contract_id": "#1:0",
            "choice": "Transfer",
            "choice_argument": {"newOwner": "p2"},
        },
    )


async def test_canton_allocate_party(mock_rpc):
    await server.canton_allocate_party("tenant-1", display_name="Tenant One")
    mock_rpc.assert_awaited_once_with(
        "tenzro_allocateParty",
        {"party_id_hint": "tenant-1", "display_name": "Tenant One"},
    )


async def test_canton_allocate_party_no_display_name(mock_rpc):
    await server.canton_allocate_party("tenant-2")
    mock_rpc.assert_awaited_once_with(
        "tenzro_allocateParty", {"party_id_hint": "tenant-2"}
    )


async def test_canton_health(mock_rpc):
    mock_rpc.return_value = {"alive": True, "ready": True}
    result = await server.canton_health()
    mock_rpc.assert_awaited_once_with("tenzro_canton_health", {})
    assert result == {"alive": True, "ready": True}


async def test_canton_coin_balance(mock_rpc):
    await server.canton_coin_balance()
    mock_rpc.assert_awaited_once_with("tenzro_canton_coinBalance", {})


async def test_canton_upload_dar(mock_rpc):
    await server.canton_upload_dar("QkFTRTY0")
    mock_rpc.assert_awaited_once_with(
        "tenzro_canton_uploadDar", {"dar_content_base64": "QkFTRTY0"}
    )
