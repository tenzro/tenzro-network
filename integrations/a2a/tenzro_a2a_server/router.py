"""4-tier keyword routing for natural language messages to handler skills."""

import re


def route_message(text: str) -> str:
    """Route a natural language message to the appropriate handler skill.

    Routing uses four priority tiers:
      Tier 1 - Multi-word compound phrases (highest priority)
      Tier 2 - Token sub-commands
      Tier 3 - Single-keyword domain routes
      Tier 4 - Generic / fallback (lowest priority)
    """
    t = text.lower()

    # ------------------------------------------------------------------
    # Tier 1: Multi-word compound phrases (highest priority)
    # ------------------------------------------------------------------
    if any(k in t for k in [
        "refresh token", "refresh access token", "refresh my token",
        "link wallet for auth", "link my wallet", "link wallet to auth",
        "onboard human", "onboard delegated", "onboard autonomous",
        "delegated agent", "autonomous agent",
        "dpop", "access token", "auth token",
    ]):
        return "auth"
    if any(k in t for k in ["join", "micronode", "onboard", "participate"]):
        return "join"
    if (
        "agent template" in t
        or "agent marketplace" in t
        or ("list" in t and "template" in t)
    ):
        return "agent_marketplace"
    if (
        "task marketplace" in t
        or "post task" in t
        or "open task" in t
        or ("task" in t and "marketplace" in t)
    ):
        return "task_marketplace"
    if any(k in t for k in ["spawn", "child agent", "sub-agent", "subagent"]):
        return "agent_spawning"
    if any(k in t for k in ["swarm", "orchestrat"]):
        return "swarm_orchestration"
    if any(k in t for k in [
        "kill-switch", "kill switch", "killswitch",
        "pause agent", "quarantine agent", "terminate agent",
        "agent lifecycle", "lifecycle receipt",
    ]):
        return "lifecycle"

    # ------------------------------------------------------------------
    # Tier 2: Token sub-commands
    # ------------------------------------------------------------------
    if "token" in t:
        if any(k in t for k in ["create", "mint"]):
            return "create_token"
        if any(k in t for k in ["info", "details", "lookup"]):
            return "token_info"
        if "balance" in t:
            return "token_balance"
        if "cross" in t and "vm" in t:
            return "cross_vm_transfer"
        if "wrap" in t and "tnzo" in t:
            return "wrap_tnzo"
        return "list_tokens"

    # ------------------------------------------------------------------
    # Tier 2b: Crypto / TEE / Custody / ZK compound phrases
    # ------------------------------------------------------------------
    if any(k in t for k in ["key exchange", "x25519", "diffie-hellman"]):
        return "crypto"
    if any(k in t for k in ["mpc wallet", "keystore", "session key", "spending limit", "custody", "key share", "key rotation"]):
        return "custody"
    if any(k in t for k in ["zk proof", "zero knowledge", "zk circuit", "plonky3", "stark"]):
        return "zk"
    if any(k in t for k in ["tee enclave", "tee attestation", "tee provider", "seal data", "unseal data", "trusted execution"]):
        return "tee"

    # ------------------------------------------------------------------
    # Tier 2c: AP2 mandate, ERC-8004, Wormhole, CCT compound phrases
    # ------------------------------------------------------------------
    if any(k in t for k in [
        "ap2 mandate", "verify mandate", "validate mandate", "intent vdc", "cart vdc",
        "payment vdc", "mandate pair", "ap2 session", "ap2 protocol", "ap2 intent",
        "ap2 cart", "ap2 payment",
    ]):
        return "ap2"
    if any(k in t for k in [
        "erc-8004", "erc8004", "agent id", "agentid", "trustless agent",
        "reputation feedback", "request validation", "submit validation",
    ]):
        return "erc8004"
    if any(k in t for k in ["wormhole", "vaa"]):
        return "wormhole"
    if any(k in t for k in ["cct pool", "cct pools", "chainlink cross-chain token", "lockrelease pool", "burnmint pool"]):
        return "cct"
    if any(k in t for k in [
        "capital intent", "capital allocation", "reserve attestation",
        "attested mint", "tokenized asset", "1:1 backed", "regulated capital",
    ]):
        return "capital"
    if any(k in t for k in [
        "saga workflow", "multi-party workflow", "multi-agent workflow",
        "workflow open", "workflow step", "workflow finalize",
        "compensate step", "verify step", "obligation", "approval gate",
        "fee route", "privacy domain",
    ]):
        return "workflow"
    if any(k in t for k in [
        "did envelope", "did-envelope", "verify envelope", "signed envelope",
    ]):
        return "verification"

    # ------------------------------------------------------------------
    # Tier 2d: EVM primitives + cross-chain reach + CAIP discovery
    # ------------------------------------------------------------------
    if any(k in t for k in [
        "eip-7702", "eip7702", "7702 delegation", "set eoa code", "eoa code",
        "delegation designator", "pectra delegation",
    ]):
        return "eip7702"
    if any(k in t for k in [
        "permit2", "signaturetransfer", "signature transfer", "permit2 nonce",
        "permit2 digest", "permit2 witness",
    ]):
        return "permit2"
    if any(k in t for k in [
        "secure-mint", "secure mint", "reserve attestation", "por feed",
        "proof of reserve", "1:1 backing", "tokenized rwa", "xstock",
        "tokenized equity", "tokenized treasury",
    ]):
        return "secure-mint"
    if any(k in t for k in [
        "treasury withdrawal", "treasury multisig", "pending withdrawal",
        "approve withdrawal", "execute withdrawal", "add withdrawer",
        "remove withdrawer", "withdrawal threshold",
    ]):
        return "treasury"
    if any(k in t for k in [
        "stable-asset", "stable asset", "stable unit", "stablecoin issuance",
        "issue stable", "mint stable", "redeem stable", "stable-unit",
    ]):
        return "stable-asset"
    if any(k in t for k in [
        "hyperlane", "tenzro-ism", "hyperlane mailbox", "sovereign ism",
    ]):
        return "hyperlane"
    if any(k in t for k in [
        "axelar", "gmp", "call contract", "axelar gas service",
        "cosmos chain", "stellar reach", "xrpl reach",
    ]):
        return "axelar"
    if any(k in t for k in [
        "babylon", "finality provider", "bitcoin staking", "btc staking",
        "eots", "extractable one-time signature",
    ]):
        return "babylon"
    if any(k in t for k in [
        "caip", "caip-2", "caip-10", "caip-19", "chain-agnostic",
        "slip-44", "slip44 coin", "asset namespace", "casa",
    ]):
        return "caip"

    # ------------------------------------------------------------------
    # Tier 2e: Operability inspection, storage market, compute rental,
    # MoE sharding, local discovery
    #
    # Operability phrases must precede the MoE route ("sealed-shard
    # manifest" contains "shard") and the broad Tier 3 routes. MoE and
    # local-discovery phrases must precede the broad Tier 3 "model" and
    # "network" routes because both share keywords.
    # ------------------------------------------------------------------
    if any(k in t for k in [
        "tenzro train", "training run", "training receipt", "sealed receipt",
        "sealed manifest", "sealed-shard manifest", "sla probe", "sla fault",
        "sla param", "liveness probe", "outstanding probe", "snapshot",
        "state-sync",
    ]):
        return "operability"
    if any(k in t for k in [
        "expert", "moe", "shard map", "shard", "expert-shard",
        "dispatch plan", "plan dispatch", "replication policy",
    ]):
        return "moe"
    if any(k in t for k in [
        "local peers", "local peer", "cluster", "discover peers",
        "mdns", "reachability", "node profile", "hardware profile",
    ]):
        return "discovery"
    if any(k in t for k in [
        "storage", "store object", "storage deal", "store ",
        "por challenge", "charge epoch",
    ]):
        return "storage"
    if any(k in t for k in [
        "compute rental", "compute provider", "book rental",
        "settle epoch", "rent compute", "rental",
    ]) or re.search(r"\brent\b", t):
        return "compute"

    # ------------------------------------------------------------------
    # Tier 3: Single-keyword domain routes
    # ------------------------------------------------------------------
    if any(k in t for k in ["sign", "encrypt", "decrypt", "keccak"]):
        return "crypto"
    if any(k in t for k in ["tee", "enclave", "attestation", "seal"]):
        return "tee"
    if any(k in t for k in ["deploy", "contract", "bytecode"]):
        return "contract"
    if any(k in t for k in ["nft", "collection", "mint nft"]):
        return "nft"
    if any(k in t for k in ["debridge", "dln", "same chain swap"]):
        return "debridge"
    if any(k in t for k in ["bridge", "cross-chain", "layerzero", "ccip"]):
        return "bridge"
    if any(k in t for k in ["compliance", "kyc", "t-rex", "erc-3643", "whitelist"]):
        return "compliance"
    if any(k in t for k in ["erc-7802", "crosschain token"]):
        return "crosschain"
    if any(k in t for k in ["event", "subscribe", "webhook", "listen"]):
        return "events"
    if any(k in t for k in ["identity", "did", "register identity", "resolve", "username"]):
        return "identity"
    if any(k in t for k in ["balance", "wallet", "send", "transfer"]):
        return "wallet"
    if "faucet" in t:
        return "faucet"
    if any(k in t for k in ["model", "inference", "ai ", "chat"]):
        return "inference"
    # Validator-lifecycle: registry reads + key rotation. Must precede the
    # broader "staking" rule because both match the word "validator".
    if any(
        k in t
        for k in [
            "rotate key", "rotate-key", "rotate the key",
            "list validator", "list active validator",
            "active validator", "list candidate", "list jailed",
            "validator state", "validator registry",
        ]
    ) or ("rotate" in t and "validator" in t):
        return "validator-lifecycle"
    if any(k in t for k in ["stake", "staking", "unstake", "validator"]):
        return "staking"
    if any(k in t for k in ["provider", "serving", "earnings"]):
        return "provider"
    if "ap2" in t:
        return "ap2"
    if any(k in t for k in ["payment", "challenge", "mpp", "x402"]):
        return "payment"
    if any(k in t for k in ["verify", "proof", "attestation", "zk"]):
        return "verification"
    if any(k in t for k in [
        "block", "height", "transaction", "block range", "sync from",
        "catch up", "catch-up",
        "fee market", "gas price", "gasprice", "priority tip",
        "fee history", "1559", "eip-1559", "eip1559",
    ]):
        return "block"
    if any(k in t for k in ["canton", "daml"]):
        return "canton"

    # ------------------------------------------------------------------
    # Tier 4: Most generic (lowest priority)
    # ------------------------------------------------------------------
    if any(k in t for k in ["peer", "network"]):
        return "network"
    if any(k in t for k in ["status", "health", "node"]):
        return "status"

    return "help"
