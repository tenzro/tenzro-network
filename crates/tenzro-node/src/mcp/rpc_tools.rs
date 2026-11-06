//! Tools that each mirror one JSON-RPC method the node serves.
//!
//! Every row forwards its `params` argument to the method unchanged and
//! returns the result as `{ "result": ... }`, under the caller's own
//! credentials: the method's gate in `rpc_gates` applies exactly as it does on
//! the JSON-RPC endpoint. Nothing here holds or uses a user key. A method that
//! changes state on the owner's behalf takes the owner's proof (signature,
//! passkey assertion or DPoP-bound token) made on the owner's device; a
//! transaction is built with `transaction_signing_payload` and signed by the
//! caller's wallet before it is sent.

/// Who may call a mirrored method, from its class in `rpc_gates`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Access {
    /// Open read or stateless computation.
    Read,
    /// Open write that is permissionless by design.
    OpenWrite,
    /// The handler checks the owner's proof carried in `params`.
    Owner,
    /// The operator DID or a policy admin.
    Operator,
}

pub(super) struct RpcTool {
    pub method: &'static str,
    pub name: &'static str,
    pub access: Access,
    pub description: &'static str,
}

pub(super) const RPC_TOOLS: &[RpcTool] = &[
    RpcTool {
        method: "tenzro_checkDelegateTarget",
        name: "check_delegate_target",
        access: Access::Read,
        description: "Whether the code at an address is on the governed list of delegate code hashes. Params: `address` (hex). Returns whether the target is allowed.",
    },
    RpcTool {
        method: "tenzro_getAccountOutflow",
        name: "get_account_outflow",
        access: Access::Read,
        description: "An account's opt-in outflow policy, its pending change and its releases. Params: `account` (hex). Returns the policy, or `null` when none is set.",
    },
    RpcTool {
        method: "tenzro_getKeystore",
        name: "get_keystore",
        access: Access::Read,
        description: "A passkey account's keystore from consensus state: its linked passkeys, policy, recovery signers and pending recovery, its commitment (the previous_commitment its next KeystoreUpdate names) and whether its passkeys may spend now. Pass `anchor` for an account with no keystore on chain to get its genesis record.",
    },
    RpcTool {
        method: "tenzro_getToolCallRecords",
        name: "get_tool_call_records",
        access: Access::Read,
        description: "`agent_did`, optional `limit`: the signed records of the tool calls this node served the agent (tool, argument and result digests, decision, approval, delegating root), and whether this node records at all. On a private node only the agent's controller reads them.",
    },
    RpcTool {
        method: "tenzro_resolveCredential",
        name: "resolve_credential",
        access: Access::Read,
        description: "The accounts whose keystore on chain links a passkey, found from its WebAuthn credential id (hex) and the relying party it is registered on. Params: `{credential_id, rp_id}`.",
    },
    RpcTool {
        method: "tenzro_listAdminAudit",
        name: "list_admin_audit",
        access: Access::Operator,
        description: "The node's administrative audit log: who called which administrative method, from where, with which credential, and what came of it. Params (all optional): `method`, `principal` (a DID), `since` and `until` (RFC 3339 or Unix milliseconds), `limit` (default 100, at most 1000). Returns the most recent matching records, oldest first, each with its hash. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_verifyAdminAudit",
        name: "verify_admin_audit",
        access: Access::Operator,
        description: "Check the node's administrative audit log: every record matches its hash and follows the one before it, every checkpoint verifies under this node's hardware identity key, and the log ends where the node last wrote. Returns `ok` and every problem found. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_acceptClusterMembership",
        name: "accept_cluster_membership",
        access: Access::Operator,
        description: "This machine accepts its inclusion in list `seq` of `cluster_did`, signing with its own hardware key. For node administrators only: only the machine's operator decides which clusters it joins. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_attestFinalityProof",
        name: "attest_finality_proof",
        access: Access::OpenWrite,
        description: "Bind a Groth16-wrapped finality proof (the classical compact form, not quantum-safe) made on this machine to an attestation of this node's TEE. Params: `image_id`, `journal`, `seal` (hex, as `tenzro-finality-prover wrap` writes them). The seal is verified first; the attestation's report data commits to the program, the journal, the seal and the Groth16 prover. Returns `tee_finality_proof` and the measurement registers. Permissionless write.",
    },
    RpcTool {
        method: "tenzro_auditInferenceChallenge",
        name: "audit_inference_challenge",
        access: Access::Read,
        description: "Or `{ challenge }` → the audit, plus whether each seat's key is the one this node's registry holds for it. Params: `{ challenge_id }`.",
    },
    RpcTool {
        method: "tenzro_autotuneDecisions",
        name: "autotune_decisions",
        access: Access::Read,
        description: "What the controller has decided, and why. A node that changes its own configuration and cannot say why is one an operator has to reverse-engineer during an incident. Each entry carries the action, the reasoning citing the measurements it acted on, and whether it was actually applied — an observing-only node records its proposals so the behaviour can be watched before it is trusted.",
    },
    RpcTool {
        method: "tenzro_bindDevice",
        name: "bind_device",
        access: Access::Operator,
        description: "Record what a registration proved about a device. The attestation is verified and graded against the vendor roots this node pins; nothing the client asserts about its own hardware is taken on trust. The registration must be user-verified and made on this node's relying party, and the caller must hold the identity (see the module docs). Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_blockNumber",
        name: "block_number",
        access: Access::Read,
        description: "Current block height of this node's chain.",
    },
    RpcTool {
        method: "tenzro_buildModelManifest",
        name: "build_model_manifest",
        access: Access::Operator,
        description: "(admin): params `name`, `path`. Hashes the model's files, records the manifest and gossips it. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_buildReserveAttestationFromPor",
        name: "build_reserve_attestation_from_por",
        access: Access::Read,
        description: "Read the live PoR feed and return an UNSIGNED `ReserveAttestation{source: chainlink_por}` skeleton. Per the custody model, this node never signs the attestation: the attestor signs `signing_payload()` off-node with its own key, then submits the signed record via `tenzro_submitReserveAttestation`. Params: `(asset_id, attestor_did)`.",
    },
    RpcTool {
        method: "tenzro_chat",
        name: "chat",
        access: Access::Read,
        description: "Send a chat completion request to a served model and return the response.",
    },
    RpcTool {
        method: "tenzro_cleanupIdleLocalModelServices",
        name: "cleanup_idle_local_model_services",
        access: Access::Operator,
        description: "On-demand sweep of idle local model service instances. Mirrors the periodic 60s heartbeat in the EventLoop, but available as an operator-callable RPC for forcing eviction without waiting for the next tick (e.g. after a manual model unload, or during a rolling restart). Returns the number of evicted ModelServiceInstance rows and the number of cleared `served_models` flags. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_layerPipelineStatus",
        name: "layer_pipeline_status",
        access: Access::Operator,
        description: "What this machine does in the model the operator serves across several of its own machines (the [layer_pipeline] table): the model, whether this machine drives the pipeline or serves a later stage, its layer range, the digest of the plan every machine agreed on, its state, and the last error. Operator only.",
    },
    RpcTool {
        method: "tenzro_clusterMembers",
        name: "cluster_members",
        access: Access::Read,
        description: "The members of a cluster. For a cluster DID, its verified member DIDs and its aggregated reputation record; for this node's own cluster, also the members found on the local network with the hardware each one announced. Nothing is disclosed about a member beyond its DID and what that machine itself chose to announce.",
    },
    RpcTool {
        method: "tenzro_computeBondParams",
        name: "compute_bond_params",
        access: Access::Read,
        description: "The admission dials a provider needs before it posts. `min_bond_wei` is the smallest bond the read model counts as eligible; `cooldown_ms` is how long a `WithdrawComputeBond` sits in Cooldown before `FinalizeComputeBondWithdrawal` will release the vault.",
    },
    RpcTool {
        method: "tenzro_computeGetClaim",
        name: "compute_get_claim",
        access: Access::Read,
        description: "One compute claim from chain state, by `claim_id`. Claims are written and bought with the `ComputeClaim` native transaction.",
    },
    RpcTool {
        method: "tenzro_createTeeZkProof",
        name: "create_tee_zk_proof",
        access: Access::OpenWrite,
        description: "Prove a settlement statement inside this node's TEE and bind the enclave's attestation to that exact proof. Params: `circuit_id` (`\"settlement\"`), `vendor`, `witness`, `binding`. Permissionless write.",
    },
    RpcTool {
        method: "tenzro_currentHeader",
        name: "current_header",
        access: Access::Read,
        description: "Return the latest finalized header + its age in seconds. Clients use the age to render staleness tiers: - `age_secs < 384` (1 epoch): **live**, balances trusted. - `age_secs < 3600` (1 hour): **stale (yellow)**, signing allowed with a warning. - `age_secs < 1_209_600` (14 days): **stale (red)**, value transfers blocked. - otherwise: **invalid**, force resync against a fresh checkpoint.",
    },
    RpcTool {
        method: "tenzro_decodeAction",
        name: "decode_action",
        access: Access::Read,
        description: "The typed preimage a privileged transaction is signed over, its digest, and what it does in words, generated from the preimage alone. Given the preimage bytes (hex) it decodes them; given an unsigned transaction it builds them. Params: `{ transaction } | { preimage }`.",
    },
    RpcTool {
        method: "tenzro_deriveClusterMembership",
        name: "derive_cluster_membership",
        access: Access::Read,
        description: "The first step of creating a cluster or changing its members. Derives the cluster DID from the operator and name and returns what must be signed: the custody challenge request the operator's passkey answers, and the digest each member's hardware key accepts. Computes only; stores nothing.",
    },
    RpcTool {
        method: "tenzro_eventStatus",
        name: "event_status",
        access: Access::Read,
        description: "Status of this node's event index: how far it has indexed and what it retains.",
    },
    RpcTool {
        method: "tenzro_exportConfig",
        name: "export_config",
        access: Access::Operator,
        description: "Export this node's running configuration (secrets omitted). Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_exportEvidencePack",
        name: "export_evidence_pack",
        access: Access::OpenWrite,
        description: "Optionally `audit` (entry proofs from the agents' recorder), `receipts` (their signed session receipts), `agents` (the root's agents to cover) and `payments` (pay_refs of the covered agents' payments), `proposals` (governance decisions touching the subject), `tokens` (tokens whose issuer actions to prove) and `contracts` (contracts whose cards to prove). Params: `{ agent_did } | { root_did }`. Permissionless write.",
    },
    RpcTool {
        method: "tenzro_fabricProfile",
        name: "fabric_profile",
        access: Access::Read,
        description: "Top-level dispatcher for `tenzro_chat`. Routes by shape: - presence of `messages` → rich shape (multi-turn, tools, content blocks) - presence of `message` → simple shape (single-turn string) - both or neither → error See `docs/chat-api.md` for the public contract. `tenzro_fabricProfile` — how this node's accelerators and network are wired.",
    },
    RpcTool {
        method: "tenzro_flagAgentAudit",
        name: "flag_agent_audit",
        access: Access::Operator,
        description: "`epoch`, `findings`: submit this validator's findings, such as quarantining an agent on the network's authority or tripping the bridge circuit breaker. They take effect once validators holding two thirds of bonded stake have made them. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_get7702Delegation",
        name: "get7702_delegation",
        access: Access::Read,
        description: "Read the active delegation pointer for an EVM authority. Returns `{ delegated: false }` when no delegation is active. Params: `{ \"authority\": \"0x...\" }`.",
    },
    RpcTool {
        method: "tenzro_getAccountContention",
        name: "get_account_contention",
        access: Access::Read,
        description: "Read the rolling Block-STM contention score for an account over the last 64 blocks. Params: `{ \"address\": \"0x...\" }` (hex-encoded, with or without `0x` prefix).",
    },
    RpcTool {
        method: "tenzro_getAgentAuditCommit",
        name: "get_agent_audit_commit",
        access: Access::Read,
        description: "`committer`, `epoch`: the root recorded on chain. Served from chain state, so any node answers it.",
    },
    RpcTool {
        method: "tenzro_getAgentQuarantine",
        name: "get_agent_quarantine",
        access: Access::Read,
        description: "`agent_did`: the quarantine chain state holds and, for a delegated agent, its guardrail state.",
    },
    RpcTool {
        method: "tenzro_registerKeyRelease",
        name: "register_key_release",
        access: Access::Owner,
        description: "Register a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy.",
    },
    RpcTool {
        method: "tenzro_revokeKeyRelease",
        name: "revoke_key_release",
        access: Access::Owner,
        description: "Revoke a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy.",
    },
    RpcTool {
        method: "tenzro_requestKeyRelease",
        name: "request_key_release",
        access: Access::Owner,
        description: "Submit an attested environment's release request (`request`), which the provider node verifies and records.",
    },
    RpcTool {
        method: "tenzro_getKeyRelease",
        name: "get_key_release",
        access: Access::Read,
        description: "A model's release policy and releases (`model_id`), or for a recorded `request` the content key sealed to the environment.",
    },
    RpcTool {
        method: "tenzro_commitTrainingRound",
        name: "commit_training_round",
        access: Access::Operator,
        description: "Commit a training round's signed receipt against its milestone escrow.",
    },
    RpcTool {
        method: "tenzro_settleTrainingRound",
        name: "settle_training_round",
        access: Access::Operator,
        description: "Settle a committed training round (`receipt_id`) once its challenge window has closed.",
    },
    RpcTool {
        method: "tenzro_trainedModelProvenance",
        name: "trained_model_provenance",
        access: Access::Operator,
        description: "The provenance of a trained model (`model_id`) from its committed training rounds (`rounds`).",
    },
    RpcTool {
        method: "tenzro_agentNodePqKey",
        name: "agent_node_pq_key",
        access: Access::OpenWrite,
        description: "This node's ML-DSA-65 key for an agent (`agent_did`) and its proof of possession.",
    },
    RpcTool {
        method: "tenzro_getAttestationLog",
        name: "get_attestation_log",
        access: Access::Read,
        description: "Get attestation log.",
    },
    RpcTool {
        method: "tenzro_getBridgeCircuit",
        name: "get_bridge_circuit",
        access: Access::Read,
        description: "`source_chain`, optional `adapter`: the circuit-breaker pauses chain state holds for the routes to and from `source_chain`, one adapter's or every adapter's.",
    },
    RpcTool {
        method: "tenzro_getBridgeOutflow",
        name: "get_bridge_outflow",
        access: Access::Read,
        description: "The network-wide bridge exit limits: each unit's cap in force per epoch (the lower of its governed cap and the stake-backed cap), its governed cap, what has left over every route this epoch and what waits in the exit queue; the security ratio of slashable stake to what one attack can take out, with its inputs; the exit delay rule, the most one proposal may raise a cap, and the last exit id queued.",
    },
    RpcTool {
        method: "tenzro_getBridgeExit",
        name: "get_bridge_exit",
        access: Access::Read,
        description: "`id`: a queued bridge exit, its sender, destination, amount and when it may be released, and whether anyone may cancel it after a proven committee fault.",
    },
    RpcTool {
        method: "tenzro_getCommittee",
        name: "get_committee",
        access: Access::Read,
        description: "The committee of `epoch`: its root and its members as hex bincode (`Vec<tenzro_consensus::Member>`).",
    },
    RpcTool {
        method: "tenzro_getCompactCertificate",
        name: "get_compact_certificate",
        access: Access::Read,
        description: "The compact certificate with `index`, or the latest, and the session certificates its slots name, as hex bincode (`tenzro_consensus::compact::CompactCertificate`, `Vec<tenzro_consensus::SessionCertificate>`).",
    },
    RpcTool {
        method: "tenzro_getConsensusMetrics",
        name: "get_consensus_metrics",
        access: Access::Read,
        description: "What this validator's running core measures: round time, ordered latency, reliable-broadcast path split, certificate size and egress. Read-only; `null` on a follower.",
    },
    RpcTool {
        method: "tenzro_getDaBackends",
        name: "get_da_backends",
        access: Access::Read,
        description: "List configured DA backends and their status. Params: none. Returns: `[{ backend, healthy, last_submission_ms, last_fetch_ms, error_rate_bps }]`. The only configured backend is `inline_fallback`, which refuses offload — receipts must use `storage_mode = Inline`. EigenDA / Celestia / Avail entries appear when their feature-gated adapters land.",
    },
    RpcTool {
        method: "tenzro_getEconomyMetrics",
        name: "get_economy_metrics",
        access: Access::Read,
        description: "Growth and concentration for one reward epoch (the current one by default): settled value, payments per settlement, unique paying roots, organic against unattributed volume, burn against rewards released from the genesis-funded pool (released_from_pool; also under its earlier name emitted), and the holder distribution.",
    },
    RpcTool {
        method: "tenzro_getEpochHandover",
        name: "get_epoch_handover",
        access: Access::Read,
        description: "How a light client moves past `epoch`: the certificate of the checkpoint that ends it, the session certificates that certificate names, and the members of the committee it commits, all hex bincode.",
    },
    RpcTool {
        method: "tenzro_getEventProof",
        name: "get_event_proof",
        access: Access::Read,
        description: "Get event proof.",
    },
    RpcTool {
        method: "tenzro_getFeeRate",
        name: "get_fee_rate",
        access: Access::Read,
        description: "The TNZO/USD rate fees are priced at, its hourly rise and fall caps, the safety rate safety checks value TNZO at (the lower of the rate and the lowest median of the safety window), where it came from, the next block's base fee in USD and in TNZO, and the settlement fee, from consensus state. With `{\"symbol\": \"ETH\"}` it answers the committed USD rate of that symbol instead.",
    },
    RpcTool {
        method: "tenzro_getFinality",
        name: "get_finality",
        access: Access::Read,
        description: "Both finality levels. - `ordered`: the highest height this node has ordered. Final for every honest validator the moment it is ordered; it cannot be reverted. - `certified`: the highest height covered by a checkpoint certificate a quorum signed. Transferable to anyone who knows the committee, and what bridges act on.",
    },
    RpcTool {
        method: "tenzro_getFinalizedBlock",
        name: "get_finalized_block",
        access: Access::Read,
        description: "The highest height a checkpoint certificate covers, hex-encoded. This is the finality a bridge or any other party that must convince someone else acts on.",
    },
    RpcTool {
        method: "tenzro_getGeneration",
        name: "get_generation",
        access: Access::Read,
        description: "Read back the recorded stats for one generation, by the id the caller already holds. A caller that consumed a stream and let the terminal chunk go by — or one reconciling a billing period against its own request log — has the completion id and nothing else. This resolves that id to the token counts, latency, serving provider and TNZO cost that were recorded when the generation finished.",
    },
    RpcTool {
        method: "tenzro_getInsuranceClaim",
        name: "get_insurance_claim",
        access: Access::Read,
        description: "Get insurance claim. Params: `{ claim_id }`.",
    },
    RpcTool {
        method: "tenzro_getKillSwitchReceipt",
        name: "get_kill_switch_receipt",
        access: Access::Read,
        description: "The receipt in state, or null. Params: `{ receipt_id }`.",
    },
    RpcTool {
        method: "tenzro_getMempoolLane",
        name: "get_mempool_lane",
        access: Access::Read,
        description: "Inspect the lane assignment and current bucket state for a given address. Useful for debugging \"why is my transaction being rate-limited?\" without forcing the caller to submit a probe tx and consume a token. Params (object or positional): `{ address: \"0x...\" }` — the wallet address to look up. The handler synthesizes a minimal `SignedTransaction` shell (only `from` is used by the resolver) and calls `assign_lane(&tx)`.",
    },
    RpcTool {
        method: "tenzro_getMempoolStats",
        name: "get_mempool_stats",
        access: Access::Read,
        description: "admission counters (cumulative since process start) plus current bucket population. Returns one entry per lane (Verified / Delegated / Open) with admit counts, rate-limit rejections, and other (size/count) rejections, along with the lane's configured refill rate, burst capacity, fee floor multiplier, and block-builder draw weight.",
    },
    RpcTool {
        method: "tenzro_getMeterBond",
        name: "get_meter_bond",
        access: Access::Read,
        description: "The bond behind a usage meter. Params: `meter_key` (hex Ed25519). Returns the bond, or `null` when none stands.",
    },
    RpcTool {
        method: "tenzro_getModelEndpoint",
        name: "get_model_endpoint",
        access: Access::Read,
        description: "One registered model endpoint by model id: where it is served and how it is reached.",
    },
    RpcTool {
        method: "tenzro_getNetworkParams",
        name: "get_network_params",
        access: Access::Read,
        description: "Every governed network parameter (fees, slashing rates, bonds, windows, caps, quorums) from chain state: its value, bounds, genesis value, the direction that tightens it, its capture-guard direction (a change against it moves one step and waits `governance.guard_loosening_grace_epochs`), and any enacted change waiting for its epoch. Params: optional `key` for one parameter. A parameter changes only through an enacted `parameter_change` governance proposal, from the next epoch.",
    },
    RpcTool {
        method: "tenzro_listLevers",
        name: "list_levers",
        access: Access::Read,
        description: "Every governance lever, grouped by area: kind (status = enabled/paused/retired, switch = on/off, value = amount or cap), current value and status, bounds, and any enacted change waiting with the epoch it activates in; plus each bridge route's mode after its record and its transport's lever. A status lever a protocol guardian pause is holding reads paused and carries `guardian_pause_until_epoch`. Params: optional `area` (fees, bridge, roles, keystore, zk, consensus, ...). Levers change only through an enacted `parameter_change` proposal, at an epoch boundary; a proposal that only pauses a status lever runs on the expedited track.",
    },
    RpcTool {
        method: "tenzro_getNonce",
        name: "get_nonce",
        access: Access::Read,
        description: "Next transaction nonce for an address, to fill an unsigned transaction before the wallet signs it.",
    },
    RpcTool {
        method: "tenzro_getOperatorPolicy",
        name: "get_operator_policy",
        access: Access::Read,
        description: "Get operator policy.",
    },
    RpcTool {
        method: "tenzro_getReserveFeed",
        name: "get_reserve_feed",
        access: Access::Read,
        description: "The Proof-of-Reserve feed governance installed for an asset (a SetReserveFeed vote), from consensus state: aggregator address, CAIP-2 chain, decimals and staleness bound; `feed` is null when none is installed. Params: `{ asset_id }` (`tnzo:<route key>` for a bridge route).",
    },
    RpcTool {
        method: "tenzro_getRewardEpoch",
        name: "get_reward_epoch",
        access: Access::Read,
        description: "The settled summary of a closed epoch, from consensus state.",
    },
    RpcTool {
        method: "tenzro_getRewardSchedule",
        name: "get_reward_schedule",
        access: Access::Read,
        description: "The active payout schedule (per-year rights and role split) plus the aggregate counters, from consensus state.",
    },
    RpcTool {
        method: "tenzro_getSettlementPreference",
        name: "get_settlement_preference",
        access: Access::Read,
        description: "What asset a payee is paid in.",
    },
    RpcTool {
        method: "tenzro_getStateProof",
        name: "get_state_proof",
        access: Access::Read,
        description: "Get state proof.",
    },
    RpcTool {
        method: "tenzro_getStateRoot",
        name: "get_state_root",
        access: Access::Read,
        description: "Get state root.",
    },
    RpcTool {
        method: "tenzro_getStatusList",
        name: "get_status_list",
        access: Access::Read,
        description: "Params `issuer`.",
    },
    RpcTool {
        method: "tenzro_getTerritoryPolicy",
        name: "get_territory_policy",
        access: Access::Read,
        description: "Get territory policy.",
    },
    RpcTool {
        method: "tenzro_getTransactionHistory",
        name: "get_transaction_history",
        access: Access::Read,
        description: "Transactions sent from or to an address, newest first, from the node's index of committed blocks. Params: `address`, `cursor` (from the previous page), `limit` (default 25, at most 100). Each entry: `hash`, `block_height`, `tx_index`, `direction` (sent, received or self), `type`, `from`, `to`, `value`, `status` (success or reverted), `fee_paid`. Also `total`, `kept` (the latest 10,000 per address) and `indexed_from_height`.",
    },
    RpcTool {
        method: "tenzro_listNetworkLegs",
        name: "list_network_legs",
        access: Access::Read,
        description: "The provider legs this node owes for calls it forwarded, newest first. Each is a payment record bound to the call: `payment_id` (= `request_digest`, over the model, the receipt nonce, the provider, the served `output_hash` and the provider's `receipt_digest`), `quote_digest` (the offer the routing decision scored: card, units, amount), `cost_wei`, `status` (queued, pending, settled, failed or free), `attempts`, `errors` (every refused attempt's reason), and once paid `tx_hash`, `pay_ref`, `network_fee` (the treasury leg) and `payee_credit`. Params (all optional): `status`, `provider`, `limit` (default 50, at most 500).",
    },
    RpcTool {
        method: "tenzro_retryNetworkLeg",
        name: "retry_network_leg",
        access: Access::Operator,
        description: "Drive a failed provider leg of a forwarded call again, under the same signed payment, so it can never pay twice. Params: `payment_id`. Returns the leg as it stands after the attempts.",
    },
    RpcTool {
        method: "tenzro_listSettlements",
        name: "list_settlements",
        access: Access::Read,
        description: "The paid calls this node served or routed, newest first. Node-local: `work_class`, `model_id`, `units`, `serving_node`, `cap_key`, `hardware_tier`, `call_attribution`, `requested_at_ms`, `latency_ms`. From the chain, for a ledger settlement: `tx_hash`, `pay_ref`, `status`, `settled_at_ms`, `fee`, `burned`, `treasury_leg`, `receipts`; a channel call names its escrow and whether it is claimed. `sources` lists which fields came from where. Params (all optional): `cursor`, `limit` (default 50, at most 200), `work_class`, `provider`, `payer`, `from_ms`, `to_ms`.",
    },
    RpcTool {
        method: "tenzro_listPeers",
        name: "list_peers",
        access: Access::Read,
        description: "This node and every peer whose signed announcement it holds: `peer_id` (iroh endpoint), `account`, `machine_did`, `roles`, `hardware_tier`, `identity_anchor` (tpm, enclave, delegated_tpm or passkey, as declared), `region` (only when declared, with `region_source`), and `version` (this node's own; peers do not announce one).",
    },
    RpcTool {
        method: "tenzro_getProviderScorecard",
        name: "get_provider_scorecard",
        access: Access::Read,
        description: "One provider's scorecard. Params: `provider` (account address). Returns its standing on chain (identity, compute bond, role stakes, validator entry), this node's reputation score for it, the price cards it announced, and, from the settlements this node recorded, its settled count, value and p50/p95 latency over the last 24 hours and 7 days.",
    },
    RpcTool {
        method: "tenzro_getNetworkActivity",
        name: "get_network_activity",
        access: Access::Read,
        description: "Settlement activity on the chain by reward epoch, newest first, from consensus state: value settled, settlements, payments, paying roots, organic value, settlement fees and burn, with totals. Params: `epochs` (default 24, at most 168; epochs whose records are pruned are left out).",
    },
    RpcTool {
        method: "tenzro_sponsoredInference",
        name: "sponsored_inference",
        access: Access::OpenWrite,
        description: "A short inference paid by a sponsoring agent, for a page that holds no key. Params: `model`, `input` (at most 4096 bytes), `max_tokens` (optional, up to the node's cap), `sponsor` (the agent's DID). Returns `provider`, `model`, `output`, `units`, `cost`, `tx_hash` and `pay_ref` of the agent's payment. Off unless the operator configured it; held to a per-source and a global rate and a daily budget.",
    },
    RpcTool {
        method: "tenzro_getTrustCredentials",
        name: "get_trust_credentials",
        access: Access::Read,
        description: "Params `subject`.",
    },
    RpcTool {
        method: "tenzro_getVesting",
        name: "get_vesting",
        access: Access::Read,
        description: "An address's vesting schedules and what they have accrued, from consensus state.",
    },
    RpcTool {
        method: "tenzro_getWalletProvider",
        name: "get_wallet_provider",
        access: Access::Read,
        description: "Whether a staked wallet provider serves a passkey relying-party domain. Params: `{rp_id}`. `staked` is true when an account holds a wallet provider bond for that domain and the validators' latest check found the domain's /.well-known/tenzro-provider naming it; `providers` lists every account bonded for the domain, verified ones first.",
    },
    RpcTool {
        method: "tenzro_gossipStats",
        name: "gossip_stats",
        access: Access::Operator,
        description: "Peer and gossip neighbour statistics for operators. Backs `tenzro node gossip-stats`. Admin-token-gated. No params. Topics whose mesh cannot be queried (not subscribed on this node) are omitted. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_gracefulExit",
        name: "graceful_exit",
        access: Access::Operator,
        description: "Admin RPC for clean validator shutdown. Pattern: Solana `agave-validator exit` + Cosmos SDK `cosmovisor` halt. The caller (operator, K8s preStop hook, or systemd unit) requests an orderly stand-down; we wait until the local replica leads none of the rounds its leader schedule looks ahead over, then trigger the existing `NodeEvent::Shutdown` path. The 5s drain in `main.rs` does the rest. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_getHardwareProfile",
        name: "get_hardware_profile",
        access: Access::Read,
        description: "Detect and return the hardware profile of the local node (CPU, RAM, GPU, TEE).",
    },
    RpcTool {
        method: "tenzro_hostModel",
        name: "host_model",
        access: Access::Operator,
        description: "(admin): params `root` or `name`, and `path`. Checks the files against the manifest, then publishes each to this node's blob store; peers fetch them by BLAKE3 and verify every chunk as it streams. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_inferenceRequest",
        name: "inference_request",
        access: Access::Read,
        description: "Submit an inference request to the network's providers for a model, paid by the caller's own payment credential.",
    },
    RpcTool {
        method: "tenzro_installSealedModel",
        name: "install_sealed_model",
        access: Access::Operator,
        description: "Fetch, verify, and decrypt a sealed model into local model storage using this node's hybrid X25519 + ML-KEM-768 recipient key. The manifest comes either from the local sealed-model store (`model_id`) or inline (`manifest`). Operator-only. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_iroh_getEndpointId",
        name: "iroh_get_endpoint_id",
        access: Access::Read,
        description: "This node's peer-to-peer endpoint id.",
    },
    RpcTool {
        method: "tenzro_iroh_listAlpns",
        name: "iroh_list_alpns",
        access: Access::Read,
        description: "Application protocols this node accepts on its peer-to-peer transport.",
    },
    RpcTool {
        method: "tenzro_iroh_resolveTenzroUri",
        name: "iroh_resolve_tenzro_uri",
        access: Access::Read,
        description: "Generic dispatcher for any content-addressed `tenzro://` URI: validates the URI and fetches it through the iroh resolver's `fetch_blob` path.",
    },
    RpcTool {
        method: "tenzro_issueKyaCredential",
        name: "issue_kya_credential",
        access: Access::OpenWrite,
        description: "Issue kya credential. Permissionless write.",
    },
    RpcTool {
        method: "tenzro_listAgentBondsByController",
        name: "list_agent_bonds_by_controller",
        access: Access::Read,
        description: "Every bond posted by `controller_did`.",
    },
    RpcTool {
        method: "tenzro_listComputeBonds",
        name: "list_compute_bonds",
        access: Access::Read,
        description: "List every compute bond on chain.",
    },
    RpcTool {
        method: "tenzro_listIdentities",
        name: "list_identities",
        access: Access::Read,
        description: "Identities registered in this node's identity registry, with paging.",
    },
    RpcTool {
        method: "tenzro_listInferenceUsage",
        name: "list_inference_usage",
        access: Access::Read,
        description: "Inspect inference usage stats recorded by the per-token accounting layer. Optional params (all optional — combine to scope the result): - `model_id`: return stats for this specific model only - `provider`: hex-encoded provider address; return stats for this provider only With no filter, returns global stats plus per-model and per-provider summaries.",
    },
    RpcTool {
        method: "tenzro_listInsuranceClaims",
        name: "list_insurance_claims",
        access: Access::Read,
        description: "Every paid claim, oldest first.",
    },
    RpcTool {
        method: "tenzro_listKillSwitchByAgent",
        name: "list_kill_switch_by_agent",
        access: Access::Read,
        description: "List kill switch by agent. Params: `{ agent_did, .. }`.",
    },
    RpcTool {
        method: "tenzro_listKillSwitchByController",
        name: "list_kill_switch_by_controller",
        access: Access::Read,
        description: "Kill-switch receipts in chain order from their logs, each with its event cursor. Params: `{ agent_did, .. }`.",
    },
    RpcTool {
        method: "tenzro_getHardwareLevel",
        name: "get_hardware_level",
        access: Access::Read,
        description: "An address's hardware security level and hardware type (TPM vendor and specification, signature scheme), derived on chain from verified attestation: the record the last reward epoch close wrote and the level derived now. Params: `{ address }`.",
    },
    RpcTool {
        method: "tenzro_listRewardCoupons",
        name: "list_reward_coupons",
        access: Access::Read,
        description: "All reward coupons of an address (issued, claimed, expired), from consensus state.",
    },
    RpcTool {
        method: "tenzro_listTtsCatalog",
        name: "list_tts_catalog",
        access: Access::Read,
        description: "The speech models this node knows. Includes `supports_voice_cloning` per checkpoint so an operator can see which carry the capability before turning it on.",
    },
    RpcTool {
        method: "tenzro_listZkCircuits",
        name: "node_list_zk_circuits",
        access: Access::Read,
        description: "The same catalogue as a top-level array.",
    },
    RpcTool {
        method: "tenzro_livenessStats",
        name: "liveness_stats",
        access: Access::Read,
        description: "Runs one liveness sweep now and returns what it changed. Useful for monitoring and for checking TTL settings in production.",
    },
    RpcTool {
        method: "tenzro_loadMediaModel",
        name: "load_media_model",
        access: Access::Operator,
        description: "Load media model. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_memoryBudget",
        name: "memory_budget",
        access: Access::Read,
        description: "How the node's memory is divided and spoken for. Shows the reserve held back for the OS, RocksDB and services, each tier's ceiling and headroom, and every live commitment. An operator diagnosing \"why was my model refused\" reads this.",
    },
    RpcTool {
        method: "tenzro_modelLifecycle",
        name: "model_lifecycle",
        access: Access::Read,
        description: "Which models are warm, and the state of any that are not. With no `model_id`, lists the warm set. With one, reports that model's state: idle time and in-flight count when warm, elapsed and remaining estimate when warming.",
    },
    RpcTool {
        method: "tenzro_modelMetadata",
        name: "model_metadata",
        access: Access::Read,
        description: "Full catalog metadata for `model_id`: the serving profile (sampler defaults, jinja, reasoning), multimodal projector (mmproj) flags, speculative-decoding pairing (drafter_id / mtp_kind / draft_n), MoE topology, and architecture. This is the general per-model metadata surface that clients (SDKs, CLI) read to render or apply the catalog's recommended serving config. The catalog is the single source of truth; this RPC is its read API.",
    },
    RpcTool {
        method: "tenzro_moeDisputeReceipt",
        name: "moe_dispute_receipt",
        access: Access::Owner,
        description: "Re-execute a sampled receipt's exact request carrier against this node's own copy of the expert and compare the output rows to the committed activation sketch. A failing comparison is a fraud proof against the signed receipt: the holder is hit with the stream-grade reputation penalty (quarantine-weight, same as a corrupted stream). This node must hold the disputed expert. Needs the owner's proof (signature, passkey assertion or DPoP-bound token), made on the owner's device and passed in `params`; nothing is signed here.",
    },
    RpcTool {
        method: "tenzro_moeExecute",
        name: "moe_execute",
        access: Access::Operator,
        description: "Execute one batched expert-FFN request against the local runtime. This is also the HTTP fallback target that router peers POST to when a holder has no reachable iroh endpoint. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_moeExpertUnload",
        name: "moe_expert_unload",
        access: Access::Operator,
        description: "Drop one resident expert. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_moeGateUnload",
        name: "moe_gate_unload",
        access: Access::Operator,
        description: "Drop one resident gating network. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_moeListReceipts",
        name: "moe_list_receipts",
        access: Access::Read,
        description: "Summaries of the sampled execution receipts this router has persisted, newest key first, one page at a time. Params (all optional): `model_id`, `limit` (default 100, at most 1000), `cursor` (the `next_cursor` of the page before). Returns `{receipts, count, next_cursor}`.",
    },
    RpcTool {
        method: "tenzro_moeRoute",
        name: "moe_route",
        access: Access::Read,
        description: "Run the locally-loaded gating network over a hidden-state batch and return the per-token top-k expert selection with renormalized weights.",
    },
    RpcTool {
        method: "tenzro_nodeVisibility",
        name: "node_visibility",
        access: Access::Read,
        description: "The node's visibility and any per-resource overrides.",
    },
    RpcTool {
        method: "tenzro_onboardAutonomousAgent",
        name: "onboard_autonomous_agent",
        access: Access::OpenWrite,
        description: "Provisions a machine identity with `controller_did = self` (no human controller), rooted in its own secure element: `device_public_key` and `machine_id`. The agent's bond must already be locked on chain: an active `PostAgentBond` of at least 1 TNZO for the DID the device key derives. Permissionless write.",
    },
    RpcTool {
        method: "tenzro_onboardHuman",
        name: "onboard_human",
        access: Access::Owner,
        description: "Provisions a human TDIP identity + wallet, returns an `AuthEngine` JWT scoped for self-custody. Needs the owner's proof (signature, passkey assertion or DPoP-bound token), made on the owner's device and passed in `params`; nothing is signed here.",
    },
    RpcTool {
        method: "tenzro_peerCount",
        name: "peer_count",
        access: Access::Read,
        description: "Number of peers this node is connected to.",
    },
    RpcTool {
        method: "tenzro_pinModel",
        name: "pin_model",
        access: Access::Operator,
        description: "Exempt a model from LRU eviction. The operator's way of saying \"this one is the product\". Pinning does not load a model; it only stops a loaded one being reclaimed to make room for something else. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_prefixProbe",
        name: "prefix_probe",
        access: Access::Read,
        description: "`{digests: [hex; <=256]}` to `{matches: {model_id: runs}}`.",
    },
    RpcTool {
        method: "tenzro_previewServe",
        name: "preview_serve",
        access: Access::Read,
        description: "Preview what serving a model on this node would take (memory, accelerator fit, expected throughput) without loading it.",
    },
    RpcTool {
        method: "tenzro_produceSnapshot",
        name: "produce_snapshot",
        access: Access::Operator,
        description: "A snapshot of the committed state at the start of the current epoch, the most recent height a snapshot can be taken at. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_pruneModelRegistry",
        name: "prune_model_registry",
        access: Access::Operator,
        description: "Manual admin reconcile of the model registry. Auto-reloads served models whose GGUF file is present but not yet in the runtime, clears stale served flags, and prunes orphaned ModelServiceInstance entries. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_publishTeeMeasurement",
        name: "publish_tee_measurement",
        access: Access::Operator,
        description: "Params `report` (a JSON attestation report), `nonce` (32 bytes from `tenzro_teeAttestationChallenge`), `publisher_key_hex` (uncompressed SEC1 P-256) and `signature_hex` (raw `r || s` over SHA-256 of `publication_statement`). The measurement published is the report's own, not one the caller names, so a publisher can only log the build it is running. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_readPorReserve",
        name: "read_por_reserve",
        access: Access::Read,
        description: "Read the live PoR aggregator for `asset_id` and return the validated reading. Fail-closed: unregistered asset, negative/overflowing answer, incomplete round, or stale reading all reject. For a bridge route's reserve feed (`tnzo:<route key>`) the result also carries `route_check`, the reading set against the route's supply record. Params: `(asset_id)`.",
    },
    RpcTool {
        method: "tenzro_recordAgentAuditSession",
        name: "record_agent_audit_session",
        access: Access::Operator,
        description: "`session_id`, `mmr_root`, `count`: the latest line of an agent audit session this node supervises, reported by the agent's runtime on this machine. The node commits each ended epoch's lines in one `AgentAuditCommit` from its own account, attested by its TPM where it has one. A line covering fewer entries than one already recorded for its session, or another root over as many, is refused. Returns the epoch it will be committed in. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_redeemSealedDelivery",
        name: "redeem_sealed_delivery",
        access: Access::OpenWrite,
        description: "Redeem a sealed delivery this node offered. Params: `escrow_id` (hex, the HashLock escrow paying this node's payee) and `network_escrow_id` (hex, the HashLock escrow paying the network's share under the same lock). The node checks both on chain, claims the first with the content key, which publishes it, then claims the second. Returns the claim transactions and the key. Permissionless write.",
    },
    RpcTool {
        method: "tenzro_registerMachineIdentity",
        name: "register_machine_identity",
        access: Access::Owner,
        description: "Register a machine identity under its owner; needs the owner's signed proof, made on the owner's device. Needs the owner's proof (signature, passkey assertion or DPoP-bound token), made on the owner's device and passed in `params`; nothing is signed here.",
    },
    RpcTool {
        method: "tenzro_registerModelEndpoint",
        name: "register_model_endpoint",
        access: Access::Operator,
        description: "Register an endpoint this node serves a model at. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_resolveAgentKey",
        name: "resolve_agent_key",
        access: Access::Read,
        description: "Resolve agent key. Params: `{ agent_did, keyid }`.",
    },
    RpcTool {
        method: "tenzro_getDidServices",
        name: "get_did_services",
        access: Access::Read,
        description: "The service entries of a DID's document and the version of the list, from consensus state. Params: `{did}`. Every node returns the same list; a change is an IdentityServices transaction the DID's root approves for this version.",
    },
    RpcTool {
        method: "tenzro_resolveDidDocument",
        name: "resolve_did_document",
        access: Access::Read,
        description: "Resolve a DID to its DID document.",
    },
    RpcTool {
        method: "tenzro_revokeBoundDevice",
        name: "revoke_bound_device",
        access: Access::Operator,
        description: "Unbind a device and end the sessions it granted. The two happen together, and that is the point: removing the device without ending its sessions would leave a lost phone's access live, which is the exact situation the user is trying to fix. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_getRole",
        name: "get_role",
        access: Access::Read,
        description: "Returns the node's current runtime roles plus the local iroh endpoint id (when the endpoint is bound). Useful for operators verifying which roles a deployed pod has settled into after `--roles` plus any runtime promotion.",
    },
    RpcTool {
        method: "tenzro_rotateIdentityToPq",
        name: "rotate_identity_to_pq",
        access: Access::OpenWrite,
        description: "Rotate an identity to a post-quantum composite key; needs the identity's signed rotation proof. Permissionless write.",
    },
    RpcTool {
        method: "tenzro_scanModelFiles",
        name: "scan_model_files",
        access: Access::Operator,
        description: "(admin): params `root` or `name`, and `path`. Returns the scan report and the claim a scanning party would sign as a `safety-scan` credential. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_sealModel",
        name: "seal_model",
        access: Access::Operator,
        description: "Split a local model artifact into encrypted shards and publish them to the blob layer with per-recipient wrapped content keys (`x25519-mlkem768-hkdf-sha256-envelope-aes-256-gcm`). The manifest is signed with the node announce key and stored in the sealed-model store. Operator-only. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_deployContract",
        name: "deploy_contract",
        access: Access::OpenWrite,
        description: "Submit a contract deployment the deployer signed on their own hardware: the same fields as `send_raw_transaction`, with `tx_type` a `ContractDeploy` carrying the EVM creation code and constructor arguments. The signature covers the code, nonce, chain and sender; the contract is created when a block executes the transaction, at the address its receipt reports.",
    },
    RpcTool {
        method: "tenzro_sendRawTransaction",
        name: "send_raw_transaction",
        access: Access::OpenWrite,
        description: "Submit a transaction the sender signed on their own hardware: `from`, `to`, `value`, `gas_limit`, `gas_price`, `nonce`, `chain_id`, `timestamp`, `valid_until`, `tx_type`, `public_key` and the composite `signature` over the transaction hash. The node verifies the signature against the sender's account and never signs for it.",
    },
    RpcTool {
        method: "tenzro_setClusterMembership",
        name: "set_cluster_membership",
        access: Access::Owner,
        description: "Hold a new membership list: the first list creates the cluster, a later one with a higher sequence number adds or removes members. The operator's passkey must have answered a custody challenge this node issued for exactly this list, and every member must have accepted with its own hardware key. Needs the owner's proof (signature, passkey assertion or DPoP-bound token), made on the owner's device and passed in `params`; nothing is signed here.",
    },
    RpcTool {
        method: "tenzro_setDraining",
        name: "set_draining",
        access: Access::Operator,
        description: "Toggle the consensus drain flag. While draining, this validator stops cutting new batches but keeps ordering and signing checkpoints, so in-flight finality is unaffected. Backs `tenzro node drain`. Admin-token-gated. Optional param `draining` (bool, defaults to `true`). Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_setNodeVisibility",
        name: "set_node_visibility",
        access: Access::Operator,
        description: "Set the node's visibility. Params: `{visibility: \"public\" | \"gated\" | \"private\"}`. Admin-gated: this is the operator's own machine policy. Every resource without an override takes the new value on the next announcement heartbeat, which re-announces or stops announcing it. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_setRole",
        name: "set_role",
        access: Access::Operator,
        description: "Set this node's role (validator, model provider, light client, and so on). Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_setSettlementPreference",
        name: "set_settlement_preference",
        access: Access::Owner,
        description: "Choose what asset you are paid in. **Permissionless and self-service.** A settlement preference belongs to the payee, not to whoever runs the node they happen to be settling through. On a shared node, gating this behind node administration would mean every provider had to ask their host to change how they get paid — and would let that host change it for them. Needs the owner's proof (signature, passkey assertion or DPoP-bound token), made on the owner's device and passed in `params`; nothing is signed here.",
    },
    RpcTool {
        method: "tenzro_shutdown",
        name: "shutdown",
        access: Access::Operator,
        description: "Shut this node down gracefully. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_signChallengeVote",
        name: "sign_challenge_vote",
        access: Access::Operator,
        description: "Or `{ challenge_id, verdict, salt }` → `{ voter, public_key, signature }`. Params: `{ challenge_id, commit_hash }`. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_signalUpgradeReady",
        name: "signal_upgrade_ready",
        access: Access::Operator,
        description: "Hash the binary staged in this node's data directory, and if it is the one named, quote it with this machine's TPM and send `UpgradeReady` from the validator account. Params: `{ code_hash }`. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_slaVerdict",
        name: "sla_verdict",
        access: Access::Read,
        description: "The SLA verdict validators committed on chain for a provider's bond and epoch. Params: `provider_did`, `epoch` (hours since the Unix epoch). `null` until attesters holding two thirds of bonded stake have spoken.",
    },
    RpcTool {
        method: "tenzro_standbyQuote",
        name: "standby_quote",
        access: Access::OpenWrite,
        description: "Live operators holding `model_id` on standby in `jurisdiction`, cheapest first, with the account a reservation escrow must pay and the hourly fee each one advertises. A buyer funds a stream escrow to the returned `operator` before the session starts. Params: `{model_id, jurisdiction}`.",
    },
    RpcTool {
        method: "tenzro_submitTrustRecord",
        name: "submit_trust_record",
        access: Access::OpenWrite,
        description: "Params `record` (a signed credential, revocation, issuer revocation, operator policy, origin attestation, an unsigned model manifest, or violation evidence). Permissionless write.",
    },
    RpcTool {
        method: "tenzro_syncing",
        name: "syncing",
        access: Access::Read,
        description: "Whether this node is syncing, and its current and target heights.",
    },
    RpcTool {
        method: "tenzro_teeAttestationChallenge",
        name: "tee_attestation_challenge",
        access: Access::Read,
        description: "A fresh nonce for one verification.",
    },
    RpcTool {
        method: "tenzro_trafficStats",
        name: "traffic_stats",
        access: Access::Read,
        description: "What the node is currently admitting and refusing. `goodput_pct` is the number to watch. Throughput can hold steady while it collapses, which is the node busily producing results that arrive too late to be useful — the failure a throughput chart cannot show.",
    },
    RpcTool {
        method: "tenzro_transferMachineOwnership",
        name: "transfer_machine_ownership",
        access: Access::Operator,
        description: "Move a machine to another identity. The authority required is whatever anchors the machine, and the two are not interchangeable: a delegated machine moves on its controller's authority, a hardware-rooted one on a signature by the machine's own key. Holding the hardware cannot take a machine that has an accountable party. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_unloadMediaModel",
        name: "unload_media_model",
        access: Access::Operator,
        description: "Unload media model. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_unpinModel",
        name: "unpin_model",
        access: Access::Operator,
        description: "Return a model to eviction candidacy. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_unregisterModelEndpoint",
        name: "unregister_model_endpoint",
        access: Access::Operator,
        description: "Remove a model endpoint this node registered. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_updateIdentity",
        name: "update_identity",
        access: Access::Operator,
        description: "Controller-signed update per did:tenzro spec §3.3. The implementation dispatches to the per-field handlers based on an `update` discriminator. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_updatePaymentChannel",
        name: "update_payment_channel",
        access: Access::Owner,
        description: "Pay `charge` on a channel with the payer's next cumulative voucher. Params: `{ voucher, charge }`. Needs the owner's proof (signature, passkey assertion or DPoP-bound token), made on the owner's device and passed in `params`; nothing is signed here.",
    },
    RpcTool {
        method: "tenzro_validatorPublicKeys",
        name: "validator_public_keys",
        access: Access::Operator,
        description: "This node's own validator entry, formatted for a genesis file. Everything a founding validator entry needs: the account, the two public halves of the hardware consensus key, the node key, and both keys' proofs of possession over the registration. A node without a TPM 2.0 or Secure Enclave has no entry to give. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_validatorSelfStake",
        name: "validator_self_stake",
        access: Access::Operator,
        description: "Raise this validator's self-stake, signed by its TPM-sealed keyset. A machine identity's wallet is watch-only — its signer is the sealed validator keyset — so `tenzro_sendRawTransaction` cannot sign for the validator address, and the pre-signed CLI route wants the secret in a password keystore, which is not a custody this network allows. The key is already here and already sealed to this machine's TPM, so the signing happens in place. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_verifyAgentAuditAttestation",
        name: "verify_agent_audit_attestation",
        access: Access::Read,
        description: "`committer`, `epoch`: check the hardware attestation over the commitment recorded on chain. Served from chain state, so any node answers it.",
    },
    RpcTool {
        method: "tenzro_verifyDaPointer",
        name: "verify_da_pointer",
        access: Access::Read,
        description: "Probe whether a DA pointer is dereferenceable right now without paying the retrieval bandwidth.",
    },
    RpcTool {
        method: "tenzro_verifyInferenceReceipt",
        name: "verify_inference_receipt",
        access: Access::Read,
        description: "→ `{ valid, error?, ... }`. With `level: \"tee\"` a receipt without TEE evidence is not valid. Params: `{ receipt, level? }`.",
    },
    RpcTool {
        method: "tenzro_verifyKyaCredential",
        name: "verify_kya_credential",
        access: Access::Read,
        description: "Params `credential` (the JSON credential).",
    },
    RpcTool {
        method: "tenzro_verifyModelFiles",
        name: "verify_model_files",
        access: Access::Operator,
        description: "(admin): params `root` or `name`, and `path`. Operator only: the access policy admits the operator DID or a policy admin.",
    },
    RpcTool {
        method: "tenzro_verifyNodeDidDocument",
        name: "verify_node_did_document",
        access: Access::Read,
        description: "Check a node DID Document someone handed you. A node document travels over whatever path the holder found it on: a relay, a directory, a peer that offered it. That path is not trusted, so the document has to certify itself. This answers whether it does: the proof verifies under the key the document names, and the document's DID derives from that key, so a relay cannot serve a modified copy re-signed with a key of its own.",
    },
    RpcTool {
        method: "tenzro_verifyPayment",
        name: "node_verify_payment",
        access: Access::Read,
        description: "Check a payment credential against the challenge it answers, without settling. Params: `credential` (the payer's signed credential: `challenge_id`, `protocol`, `payer_did`, `payer_address`, `amount`, `asset`, the composite `signature` over the payment authorization and `extra.public_key`, signed on the payer's device). Returns `verified`, the `amount` and the account it would debit (`leg`, `debits`), or the `reason` it would not pay; it never reports success for a credential that would not pay.",
    },
    RpcTool {
        method: "tenzro_verifyTeeFinalityProof",
        name: "verify_tee_finality_proof",
        access: Access::Read,
        description: "Verify a finality proof bundle from `tenzro_attestFinalityProof`. Params: `tee_finality_proof`. `admitted` is true only when the seal verifies, the prover is the published Groth16 prover, the attestation's signed report data carries the binding digest, and the attestation passes `tenzro_tee::verify_report`. Returns the verified measurement registers to compare with the published image measurements.",
    },
    RpcTool {
        method: "tenzro_verifyTeeZkProof",
        name: "verify_tee_zk_proof",
        access: Access::Read,
        description: "Verify a TEE-bound proof bundle. Params: `tee_zk_proof` (the bundle returned by `tenzro_createTeeZkProof`). `admitted` is true only when the STARK verifies, the attestation's signed report data equals the proof's binding digest, and the attestation passes `tenzro_tee::verify_report` (vendor signature chained to a pinned root, current collateral, and that binding digest as its signed report data).",
    },
    RpcTool {
        method: "tenzro_verifyTrustCredential",
        name: "verify_trust_credential",
        access: Access::Read,
        description: "Verify trust credential.",
    },
];
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_gates::{ADMIN_METHODS, OPEN_METHODS, OPEN_WRITES, OWNER_METHODS};
    use std::collections::BTreeSet;

    fn class(method: &str) -> Access {
        if ADMIN_METHODS.contains(&method) {
            Access::Operator
        } else if OWNER_METHODS.contains(&method) {
            Access::Owner
        } else if OPEN_WRITES.iter().any(|(m, _)| *m == method) {
            Access::OpenWrite
        } else {
            assert!(OPEN_METHODS.contains(&method), "{method} is not served");
            Access::Read
        }
    }

    /// Each row names a served method, states its gate as `rpc_gates` does,
    /// and names a tool no other row or typed tool uses (a route added under
    /// a taken name would replace that tool).
    #[test]
    fn rows_match_the_gates_and_names_are_unique() {
        let typed: BTreeSet<String> = super::super::server::TenzroMcpServer::typed_tool_names();
        let mut names = BTreeSet::new();
        let mut methods = BTreeSet::new();
        for row in RPC_TOOLS {
            assert_eq!(row.access, class(row.method), "{}", row.method);
            assert!(names.insert(row.name), "duplicate tool name {}", row.name);
            assert!(
                methods.insert(row.method),
                "duplicate method {}",
                row.method
            );
            assert!(
                !typed.contains(row.name),
                "{} is already a typed tool",
                row.name
            );
            assert!(!row.description.is_empty(), "{}", row.method);
        }
    }
}
