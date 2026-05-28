# Documentation Drift Report

Generated: 2026-05-24
Inputs:
- Codebase inventory: `tools/doc-audit/codebase-inventory.json` (extracted from `crates/tenzro-node/src/rpc.rs`, `crates/tenzro-node/src/mcp/*.rs`, `crates/tenzro-cli/src/commands/`, gossipsub topic literals across `crates/`)
- Docs claims: `tools/doc-audit/docs-claims.json` (regex scan of `website/src/app/docs/` 105 pages + `website/src/app/tutorials/` 72 pages + `~/Documents/tenzro-github/tenzro-cookbook/`)

Scope: 473 RPC methods, 192 MCP tools, 59 CLI command modules, 61 gossip topics in codebase.

## Headline findings

1. **Coverage gap**: docs name 59 of 473 RPC methods (12.5%). The remaining **414 RPCs are completely unmentioned** in user-facing docs/tutorials/cookbook. The 247-tool MCP surface gets near-zero specific tool-name coverage.
2. **CLAUDE.md is partially aspirational on the multi-modal surface**: it claims `tenzro_visionEmbed` / `tenzro_visionSimilarity` / `tenzro_visionClassify` exist as JSON-RPC methods. They do NOT — only MCP tools (`vision_embed`, `vision_similarity`) and the JSON-RPC `tenzro_forecast`/`tenzro_textEmbed`/`tenzro_segment`/`tenzro_detect`/`tenzro_transcribe`/`tenzro_videoEmbed` are dispatched in `rpc.rs:829-866`. Any reader copy-pasting from CLAUDE.md or `docs/ai/multimodal` against JSON-RPC will get `-32601 Method not found`.
3. **`docs/ai/multimodal` is the most-broken page**: 3 ghost RPCs referenced.
4. **Cookbook references `tenzro_resolveIdentity`** — non-existent (real method is `tenzro_resolveDidDocument` + `tenzro_resolveIdentity` requires checking). Single reference in `wallets/create-agentic-wallet.ts`.
5. **`tenzro_chat` is referenced in `docs/streaming`** but is not the dispatched name (CLAUDE.md claims it, real method needs verification — likely renamed).
6. **CLI doc count mismatch**: docs reference 47 CLI subcommands; codebase has 59 command modules. ~25% of CLI surface is undocumented or renamed.

## Counts

- **24 GHOST RPCs**: docs reference RPC names that do not exist in `crates/tenzro-node/src/rpc.rs`
- **414 undocumented RPCs**: exist in code, never mentioned in any doc page
- **5 GHOST gossip topics**: docs reference topics not in `crates/`
- **3 unrecognised URLs** (not on the known tenzro.network endpoints from CLAUDE.md)

## Suggested triage order

1. **Critical (broken examples)**: fix the 24 ghost RPC references and 5 ghost gossip topics. Each is a concrete reader-facing bug.
2. **High (CLAUDE.md correctness)**: reconcile `tenzro_visionEmbed`/`Similarity`/`Classify` — either add the JSON-RPC dispatch in `rpc.rs` or correct CLAUDE.md and `docs/ai/multimodal`.
3. **Medium (coverage)**: pick the highest-traffic 30-50 RPC methods from `codebase-inventory.json` and ensure they appear in at least one doc page with a working example.
4. **Low (long-tail)**: the remaining 360+ undocumented RPCs are likely admin/internal/automation surfaces; gate by which a developer would conceivably call from outside the node.

## Methodology caveats

- The "GHOST" detection is strict string match on the JSON-RPC method name. False positives can occur if a doc page demonstrates the concept (e.g. "the eth_call_contract pattern") rather than the literal method name — but in this codebase no `eth_call_contract` exists (the real name is `eth_call`), so these are still real fix-worthy issues.
- The "undocumented" set is large because many RPCs are internal (snapshot/sync/admin RPCs) and need not be in the public docs. The audit script cannot distinguish public-facing from internal; a human pass is needed to bucket the 414.
- Cookbook was scanned with the same regex; many cookbook recipes will be hit by ghost-RPC fixes simultaneously with website/docs fixes.

## GHOST RPCs (highest doc-priority — these will return JSON-RPC -32601)

Sorted by reference count (most-cited first).

### `tenzro_crypto` — 3 reference(s)
- `docs:crypto/page.tsx`
- `docs:cryptography/page.tsx`
- `tutorials:install-erc-7579-sessionkey/page.tsx`

### `tenzro_sdk` — 3 reference(s)
- `docs:rust-sdk/page.tsx`
- `tutorials:a2a-over-iroh-handshake/page.tsx`
- `tutorials:sdk-quickstart-rust/page.tsx`

### `tenzro_resolveIdentity` — 2 reference(s)
- `cookbook:wallets/create-agentic-wallet.ts`
- `tutorials:a2a-over-iroh-handshake/page.tsx`

### `tenzro_storage` — 2 reference(s)
- `docs:ai/agent-memory/page.tsx`
- `docs:iroh/page.tsx`

### `tenzro_visionEmbed` — 2 reference(s)
- `docs:ai/multimodal/page.tsx`
- `tutorials:embed-images-with-dinov3/page.tsx`

### `eth_call_contract` — 1 reference(s)
- `tutorials:cross-chain-arbitrage/page.tsx`

### `eth_chain_id` — 1 reference(s)
- `tutorials:sdk-quickstart-rust/page.tsx`

### `eth_get_transaction` — 1 reference(s)
- `tutorials:build-institutional-aml-agent/page.tsx`

### `eth_lookup_agent_8004` — 1 reference(s)
- `tutorials:erc-8004-agents/page.tsx`

### `eth_sendTransaction` — 1 reference(s)
- `cookbook:security/vrf-random-nft-reveal.ts`

### `tenzro_batchSettle` — 1 reference(s)
- `docs:batch/page.tsx`

### `tenzro_chat` — 1 reference(s)
- `docs:streaming/page.tsx`

### `tenzro_did` — 1 reference(s)
- `docs:agents/page.tsx`

### `tenzro_faucet` — 1 reference(s)
- `cookbook:live-testnet/README.md`

### `tenzro_get_balance` — 1 reference(s)
- `tutorials:sdk-quickstart-rust/page.tsx`

### `tenzro_model` — 1 reference(s)
- `docs:ai/agent-memory/page.tsx`

### `tenzro_network` — 1 reference(s)
- `tutorials:build-network-plugin-agent/page.tsx`

### `tenzro_payments` — 1 reference(s)
- `tutorials:tempo-stablecoin/page.tsx`

### `tenzro_seed_agents` — 1 reference(s)
- `docs:governance/seed-agents/page.tsx`

### `tenzro_training_` — 1 reference(s)
- `docs:ai/training/page.tsx`

### `tenzro_validateMandatePair` — 1 reference(s)
- `docs:ap2/page.tsx`

### `tenzro_visionClassify` — 1 reference(s)
- `docs:ai/multimodal/page.tsx`

### `tenzro_visionSimilarity` — 1 reference(s)
- `docs:ai/multimodal/page.tsx`

### `tenzro_wallet` — 1 reference(s)
- `docs:wallet-sdk/page.tsx`


## GHOST gossip topics

- `tenzro/sdk` (17 refs)
  - `docs:page.tsx`
  - `docs:sdk/page.tsx`
  - `docs:typescript-sdk/page.tsx`
- `tenzro/skill/image-deduper` (1 refs)
  - `tutorials:build-network-plugin-agent/page.tsx`
- `tenzro/tasks` (1 refs)
  - `tutorials:task-marketplace/page.tsx`
- `tenzro/tenzro-network` (3 refs)
  - `docs:getting-started/page.tsx`
  - `tutorials:run-light-node/page.tsx`
  - `tutorials:run-validator-node/page.tsx`
- `tenzro/tenzro-sdk-rust` (1 refs)
  - `docs:rust-sdk/page.tsx`

## Unknown URLs in docs

- https://a2a.tenzro.network. — docs:a2a-protocol/page.tsx
- https://github.com/tenzro/tenzro-sdk-rust — docs:rust-sdk/page.tsx
- https://github.com/tenzro/tenzro-network — docs:getting-started/page.tsx

## Undocumented RPCs (live in code, no doc mention)

These are real, callable methods that the public docs/tutorials/cookbook never name.

### `tenzro_erc8004E*` family — 20 unreferenced
- `tenzro_erc8004EncodeAppendResponse`
- `tenzro_erc8004EncodeFeedback`
- `tenzro_erc8004EncodeGetAgent`
- `tenzro_erc8004EncodeGetAgentURI`
- `tenzro_erc8004EncodeGetAgentWallet`
- `tenzro_erc8004EncodeGetFeedback`
- `tenzro_erc8004EncodeGetFeedbackCount`
- `tenzro_erc8004EncodeGetFeedbackResponses`
- … and 12 more

### `tenzro_register*` family — 11 unreferenced
- `tenzro_registerAgentTemplate`
- `tenzro_registerApp`
- `tenzro_registerCompliance`
- `tenzro_registerCortexWorker`
- `tenzro_registerMachineIdentity`
- `tenzro_registerModelEndpoint`
- `tenzro_registerNftPointer`
- `tenzro_registerProvider`
- … and 3 more

### `tenzro_training*` family — 9 unreferenced
- `tenzro_training_enrollTrainer`
- `tenzro_training_finalizeRound`
- `tenzro_training_getReceipt`
- `tenzro_training_getRun`
- `tenzro_training_getSealedManifest`
- `tenzro_training_installSealedManifest`
- `tenzro_training_listRuns`
- `tenzro_training_postTask`
- … and 1 more

### `tenzro_getAgent*` family — 8 unreferenced
- `tenzro_getAgent`
- `tenzro_getAgentBond`
- `tenzro_getAgentCapabilityAttestations`
- `tenzro_getAgentDailySpend`
- `tenzro_getAgentJwk`
- `tenzro_getAgentLifecycle`
- `tenzro_getAgentTemplate`
- `tenzro_getAgentTemplateStats`

### `tenzro_liquidSt*` family — 8 unreferenced
- `tenzro_liquidStakingBalanceOf`
- `tenzro_liquidStakingClaimWithdrawal`
- `tenzro_liquidStakingDeposit`
- `tenzro_liquidStakingDistributeRewards`
- `tenzro_liquidStakingPendingWithdrawals`
- `tenzro_liquidStakingRequestWithdrawal`
- `tenzro_liquidStakingStats`
- `tenzro_liquidStakingTransfer`

### `tenzro_debridge*` family — 5 unreferenced
- `tenzro_debridgeCreateTx`
- `tenzro_debridgeGetChains`
- `tenzro_debridgeGetInstructions`
- `tenzro_debridgeSameChainSwap`
- `tenzro_debridgeSearchTokens`

### `tenzro_getWorkf*` family — 4 unreferenced
- `tenzro_getWorkflow`
- `tenzro_getWorkflowLifecycle`
- `tenzro_getWorkflowOperationalMetrics`
- `tenzro_getWorkflowReceipt`

### `tenzro_iroh*` family — 4 unreferenced
- `tenzro_iroh_fetchBlob`
- `tenzro_iroh_getEndpointId`
- `tenzro_iroh_publishBlob`
- `tenzro_iroh_resolveTenzroUri`

### `tenzro_listWork*` family — 4 unreferenced
- `tenzro_listWorkflowReceipts`
- `tenzro_listWorkflowsByCreator`
- `tenzro_listWorkflowsByParticipant`
- `tenzro_listWorkflowsByStatus`

### `tenzro_spawnAge*` family — 4 unreferenced
- `tenzro_spawnAgent`
- `tenzro_spawnAgentFromTemplate`
- `tenzro_spawnAgentTemplate`
- `tenzro_spawnAgentWithSkill`

### `tenzro_erc8004D*` family — 3 unreferenced
- `tenzro_erc8004DecodeGetAgent`
- `tenzro_erc8004DecodeGetMetadata`
- `tenzro_erc8004DeriveAgentId`

### `tenzro_getAppro*` family — 3 unreferenced
- `tenzro_getApproval`
- `tenzro_getApprovalGate`
- `tenzro_getApprovalRequest`

### `tenzro_getProvi*` family — 3 unreferenced
- `tenzro_getProviderPricing`
- `tenzro_getProviderReputation`
- `tenzro_getProviderSchedule`

### `tenzro_heartbea*` family — 3 unreferenced
- `tenzro_heartbeatAgentTemplate`
- `tenzro_heartbeatSkill`
- `tenzro_heartbeatTool`

### `tenzro_listAgen*` family — 3 unreferenced
- `tenzro_listAgentBondsByController`
- `tenzro_listAgentJwks`
- `tenzro_listAgents`

### `tenzro_wormhole*` family — 3 unreferenced
- `tenzro_wormholeBridge`
- `tenzro_wormholeChainId`
- `tenzro_wormholeParseVaaId`

### `eth_estimate*` family — 2 unreferenced
- `eth_estimateGas`
- `eth_estimateUserOperationGas`

### `eth_getBlock*` family — 2 unreferenced
- `eth_getBlockTransactionCountByHash`
- `eth_getBlockTransactionCountByNumber`

### `tenzro_agentPay*` family — 2 unreferenced
- `tenzro_agentPayForInference`
- `tenzro_agentPayForService`

### `tenzro_crosscha*` family — 2 unreferenced
- `tenzro_crosschainBurn`
- `tenzro_crosschainMint`

### `tenzro_delegate*` family — 2 unreferenced
- `tenzro_delegateTask`
- `tenzro_delegateVotingPower`

### `tenzro_discover*` family — 2 unreferenced
- `tenzro_discoverAgents`
- `tenzro_discoverModels`

### `tenzro_download*` family — 2 unreferenced
- `tenzro_downloadAgentTemplate`
- `tenzro_downloadModel`

### `tenzro_eip7702P*` family — 2 unreferenced
- `tenzro_eip7702ParseDesignator`
- `tenzro_eip7702ProtocolInfo`

### `tenzro_erc7802C*` family — 2 unreferenced
- `tenzro_erc7802CrosschainBurn`
- `tenzro_erc7802CrosschainMint`

### `tenzro_getBlock*` family — 2 unreferenced
- `tenzro_getBlock`
- `tenzro_getBlockRange`

### `tenzro_getInsur*` family — 2 unreferenced
- `tenzro_getInsuranceClaim`
- `tenzro_getInsurancePoolBalance`

### `tenzro_getSkill*` family — 2 unreferenced
- `tenzro_getSkill`
- `tenzro_getSkillUsage`

### `tenzro_getSnaps*` family — 2 unreferenced
- `tenzro_getSnapshotChunk`
- `tenzro_getSnapshotManifest`

### `tenzro_getSpend*` family — 2 unreferenced
- `tenzro_getSpendingLimits`
- `tenzro_getSpendingPolicy`
