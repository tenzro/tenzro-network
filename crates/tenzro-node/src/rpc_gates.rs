//! Default-deny classification of the JSON-RPC method surface.
//!
//! Every method the dispatcher serves is named in exactly one of
//! [`ADMIN_METHODS`], [`OWNER_METHODS`] or [`OPEN_METHODS`]. A method in none
//! of them is unreachable — [`handle_request`](super::handle_request) refuses
//! it before dispatch.
//!
//! # Why a list rather than a predicate
//!
//! An allowlist of methods that need node administration leaves every
//! newly added method open until someone remembers to close it. Default-deny
//! moves that failure from "silently reachable in production" to "the
//! classification test fails in CI" — see
//! [`tests::every_dispatched_method_is_classified`], which reads the
//! dispatcher's own source and refuses to pass while any arm is unclassified.
//! Adding an RPC without deciding its gate is no longer possible.
//!
//! # The three classes
//!
//! - **Admin** — the caller must be the operator DID or an admin named in the
//!   access policy, checked before dispatch. Machine
//!   policy, and every state change that has no proof of its own yet.
//! - **Owner** — any caller may reach the handler, and the handler itself
//!   checks a proof from whoever owns what is being changed: a signed DID
//!   envelope, an address signature, a passkey assertion, or a DPoP-bound
//!   access token. [`tests::owner_methods_check_a_proof`] reads each
//!   handler and refuses a method here whose handler checks nothing.
//! - **Open** — reads, stateless computation, and a short list of writes that
//!   are permissionless by design, each with its reason in [`OPEN_WRITES`].
//!   [`tests::open_methods_do_not_change_state`] refuses an open method whose
//!   name reads as a write unless it is in that list.
//!
//! A write whose handler cannot tell who is calling belongs in Admin until it
//! can. Moving it to Owner is a change to its handler first and to this file
//! second, and the tests check the order.
//!
//! Both arrays are sorted so lookup is a binary search, and a test pins the
//! sort order rather than trusting it.

/// Methods only the operator DID or a policy admin may call.
///
/// These either mutate operator-controlled state (provider schedule and
/// pricing, spending policy and limits, key issuance, staking against the
/// operator's own account, compliance actions, participant administration),
/// decide what the operator's own hardware runs and stores (serving, stopping,
/// downloading and deleting models, model endpoints), or read across every
/// tenant on the node.
///
/// The rest of the list is every state change whose handler takes the actor
/// from the parameters without checking a proof: the model loaders and
/// unloaders, MoE expert and gate placement, the registry sweeps, storage and
/// compute pricing and epoch charging, tool and skill registration and invocation, the
/// transfer, bridge, swap, payment and capital-intent writes, fill and hash
/// recording, agent lifecycle and spending, approvals, and the node's own
/// shutdown. Each is operator-only until its handler checks the owner's
/// proof; then it moves to [`OWNER_METHODS`].
pub const ADMIN_METHODS: &[&str] = &[
    "tenzro_acceptClusterMembership",
    "tenzro_bindDevice",
    "tenzro_buildModelManifest",
    "tenzro_cleanupIdleLocalModelServices",
    "tenzro_commitChallengeVote",
    "tenzro_commitTrainingRound",
    "tenzro_daChallenge",
    "tenzro_deleteModel",
    "tenzro_exportConfig",
    "tenzro_flagAgentAudit",
    "tenzro_forgetIdentity",
    "tenzro_getAccessPolicy",
    "tenzro_gossipStats",
    "tenzro_gracefulExit",
    "tenzro_hostModel",
    "tenzro_installSealedModel",
    "tenzro_layerPipelineStatus",
    "tenzro_listAccessTokens",
    "tenzro_listAdminAudit",
    "tenzro_loadAudioModel",
    "tenzro_loadDecisionModel",
    "tenzro_loadDetectionModel",
    "tenzro_loadForecastModel",
    "tenzro_loadMediaModel",
    "tenzro_loadRerankModel",
    "tenzro_loadSegmentationModel",
    "tenzro_loadSpeechModel",
    "tenzro_loadTextEmbeddingModel",
    "tenzro_loadTextSegmentationModel",
    "tenzro_loadTrainingModel",
    "tenzro_loadVideoModel",
    "tenzro_loadVisionModel",
    "tenzro_mirrorSettlement",
    "tenzro_moeExecute",
    "tenzro_moeExpertLoad",
    "tenzro_moeExpertUnload",
    "tenzro_moeForward",
    "tenzro_moeGateLoad",
    "tenzro_moeGateUnload",
    "tenzro_moePrepareExperts",
    "tenzro_pinModel",
    "tenzro_previewAccess",
    "tenzro_produceSnapshot",
    "tenzro_pruneModelRegistry",
    "tenzro_publishTeeMeasurement",
    "tenzro_recordAgentAuditSession",
    "tenzro_recordRouteOutcome",
    "tenzro_registerModelEndpoint",
    "tenzro_retryNetworkLeg",
    "tenzro_revealChallengeVote",
    "tenzro_revokeAccessToken",
    "tenzro_revokeBoundDevice",
    "tenzro_scanModelFiles",
    "tenzro_sealModel",
    "tenzro_serveModel",
    "tenzro_setAccessPolicy",
    "tenzro_setDraining",
    "tenzro_setNodeVisibility",
    "tenzro_setProviderPricing",
    "tenzro_setRole",
    "tenzro_settleTrainingRound",
    "tenzro_shutdown",
    "tenzro_signChallengeVote",
    "tenzro_signalUpgradeReady",
    "tenzro_slaIssueProbe",
    "tenzro_stopModel",
    "tenzro_storageRetrieveObject",
    "tenzro_storageSetPricing",
    "tenzro_storageStoreObject",
    "tenzro_trainRound",
    "tenzro_trainedModelProvenance",
    "tenzro_transferMachineOwnership",
    "tenzro_unloadAudioModel",
    "tenzro_unloadDecisionModel",
    "tenzro_unloadDetectionModel",
    "tenzro_unloadForecastModel",
    "tenzro_unloadMediaModel",
    "tenzro_unloadRerankModel",
    "tenzro_unloadSegmentationModel",
    "tenzro_unloadSpeechModel",
    "tenzro_unloadTextEmbeddingModel",
    "tenzro_unloadTextSegmentationModel",
    "tenzro_unloadTrainingModel",
    "tenzro_unloadVideoModel",
    "tenzro_unloadVisionModel",
    "tenzro_unpinModel",
    "tenzro_unregisterModelEndpoint",
    "tenzro_updateIdentity",
    "tenzro_validatorPublicKeys",
    "tenzro_validatorSelfStake",
    "tenzro_verifyAdminAudit",
    "tenzro_verifyModelFiles",
];

/// Methods any caller may reach, whose handler authorizes the change itself
/// with a proof from the owner of what is changed.
///
/// Node administration is deliberately not the gate for these: the thing changed
/// belongs to a tenant, a wallet holder or a DID, and a shared node's operator
/// must not be able to act in their name any more than a stranger can.
/// [`tests::owner_methods_check_a_proof`] reads every handler here and refuses
/// one that checks no proof at all. It cannot judge whether the proof checked
/// is the *right* one; the per-method authorization tests do that.
pub const OWNER_METHODS: &[&str] = &[
    "tenzro_addMachineAccess",
    "tenzro_agentAct",
    "tenzro_agentVoucher",
    "tenzro_closePaymentChannel",
    "tenzro_enrollPasskey",
    "tenzro_exchangeToken",
    "tenzro_listMachineAccess",
    "tenzro_moeDisputeReceipt",
    "tenzro_onboardDelegatedAgent",
    "tenzro_onboardHuman",
    "tenzro_registerIdentity",
    "tenzro_registerKeyRelease",
    "tenzro_registerMachineIdentity",
    "tenzro_requestKeyRelease",
    "tenzro_requestRemoteGrant",
    "tenzro_revokeIdentity",
    "tenzro_revokeJwt",
    "tenzro_revokeKeyRelease",
    "tenzro_revokeMachineAccess",
    "tenzro_setClusterMembership",
    "tenzro_setSettlementPreference",
    "tenzro_settle",
    "tenzro_signRemoteAction",
    "tenzro_signRemoteChannelVoucher",
    "tenzro_submitReserveAttestation",
    "tenzro_updateAgentTerms",
    "tenzro_updatePaymentChannel",
];

/// Methods any caller may reach without administering the node.
///
/// "Open" here means *open with respect to this classification*. Each call
/// still passes the node access policy and per-handler authorization; the
/// classification below is only about node administration.
///
/// An open method must not change state that belongs to someone else. The
/// exceptions are permissionless by design and named in [`OPEN_WRITES`].
pub const OPEN_METHODS: &[&str] = &[
    "eth_accounts",
    "eth_blockNumber",
    "eth_call",
    "eth_chainId",
    "eth_estimateGas",
    "eth_feeHistory",
    "eth_gasPrice",
    "eth_getBalance",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getBlockReceipts",
    "eth_getBlockTransactionCountByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getCode",
    "eth_getCompilers",
    "eth_getLogs",
    "eth_getStorageAt",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionByHash",
    "eth_getTransactionCount",
    "eth_getTransactionReceipt",
    "eth_hashrate",
    "eth_maxPriorityFeePerGas",
    "eth_mining",
    "eth_sendRawTransaction",
    "eth_syncing",
    "getAccountInfo",
    "getBalance",
    "getBlockHeight",
    "getFeeForMessage",
    "getHealth",
    "getLatestBlockhash",
    "getMinimumBalanceForRentExemption",
    "getSignatureStatuses",
    "getSlot",
    "getVersion",
    "isBlockhashValid",
    "net_listening",
    "net_peerCount",
    "net_version",
    "sendTransaction",
    "simulateTransaction",
    "tenzro_accessChallenge",
    "tenzro_agentAccounts",
    "tenzro_agentNodePqKey",
    "tenzro_agentWalletConsent",
    "tenzro_attestFinalityProof",
    "tenzro_auditInferenceChallenge",
    "tenzro_autotuneDecisions",
    "tenzro_blockNumber",
    "tenzro_buildRemoteAction",
    "tenzro_buildReserveAttestationFromPor",
    "tenzro_canTransfer",
    "tenzro_chat",
    "tenzro_chatByIntent",
    "tenzro_checkDelegateTarget",
    "tenzro_clusterMembers",
    "tenzro_computeBondParams",
    "tenzro_computeGetClaim",
    "tenzro_computeListClaims",
    "tenzro_computePriceFeed",
    "tenzro_createCustodyChallenge",
    "tenzro_createPasskeySession",
    "tenzro_createPaymentChallenge",
    "tenzro_createTeeZkProof",
    "tenzro_createZkProof",
    "tenzro_currentHeader",
    "tenzro_daAvailability",
    "tenzro_daCommittee",
    "tenzro_daListBlobs",
    "tenzro_daListChallenges",
    "tenzro_decide",
    "tenzro_decodeAction",
    "tenzro_deployContract",
    "tenzro_deriveClusterMembership",
    "tenzro_detect",
    "tenzro_detectTee",
    "tenzro_discoverModels",
    "tenzro_eventStatus",
    "tenzro_exportEvidencePack",
    "tenzro_fabricProfile",
    "tenzro_fileInferenceChallenge",
    "tenzro_finalizeChallenge",
    "tenzro_forecast",
    "tenzro_get7702Delegation",
    "tenzro_getAccountContention",
    "tenzro_getAccountOutflow",
    "tenzro_getAgentAuditCommit",
    "tenzro_getAgentBond",
    "tenzro_getAgentGrantProof",
    "tenzro_getAgentQuarantine",
    "tenzro_getAgentTerms",
    "tenzro_getAttestationLog",
    "tenzro_getBalance",
    "tenzro_getBeacon",
    "tenzro_getBlock",
    "tenzro_getBlockRange",
    "tenzro_getBridgeCircuit",
    "tenzro_getBridgeExit",
    "tenzro_getBridgeOutbound",
    "tenzro_getBridgeOutflow",
    "tenzro_getBridgeRoute",
    "tenzro_getBurnRateConfig",
    "tenzro_getBurnRateRecommendation",
    "tenzro_getCatalogEntry",
    "tenzro_getCheckpointCertificate",
    "tenzro_getCommittee",
    "tenzro_getCompactCertificate",
    "tenzro_getComputeBond",
    "tenzro_getConnectivity",
    "tenzro_getConsensusMetrics",
    "tenzro_getContentProvenance",
    "tenzro_getDaBackends",
    "tenzro_getDaObject",
    "tenzro_getDaRetention",
    "tenzro_getDidServices",
    "tenzro_getDuty",
    "tenzro_getEconomicPolicy",
    "tenzro_getEconomyMetrics",
    "tenzro_getEngineReleases",
    "tenzro_getEpochHandover",
    "tenzro_getEscrow",
    "tenzro_getEventProof",
    "tenzro_getFeeMarket",
    "tenzro_getFeeRate",
    "tenzro_getFinality",
    "tenzro_getFinalizedBlock",
    "tenzro_getGeneration",
    "tenzro_getGovernanceReceipt",
    "tenzro_getGrant",
    "tenzro_getGuardianState",
    "tenzro_getHandoverChain",
    "tenzro_getHardwareLevel",
    "tenzro_getHardwareProfile",
    "tenzro_getInferenceChallenge",
    "tenzro_getInferenceCommitment",
    "tenzro_getInsuranceClaim",
    "tenzro_getInsurancePoolBalance",
    "tenzro_getKeyRelease",
    "tenzro_getKeystore",
    "tenzro_getKillSwitchReceipt",
    "tenzro_getLegReceipt",
    "tenzro_getMempoolLane",
    "tenzro_getMempoolStats",
    "tenzro_getMeterBond",
    "tenzro_getModelEndpoint",
    "tenzro_getModelProvenance",
    "tenzro_getModelStacks",
    "tenzro_getNettingBatch",
    "tenzro_getNetworkActivity",
    "tenzro_getNetworkParams",
    "tenzro_getNetworkStats",
    "tenzro_getNodeStatus",
    "tenzro_getNonce",
    "tenzro_getOperatorPolicy",
    "tenzro_getPasskeySession",
    "tenzro_getPayeeSplit",
    "tenzro_getPayment",
    "tenzro_getPlan",
    "tenzro_getPlanDecision",
    "tenzro_getPolicy",
    "tenzro_getPriceCard",
    "tenzro_getProposal",
    "tenzro_getProviderPricing",
    "tenzro_getProviderScorecard",
    "tenzro_getProviderStats",
    "tenzro_getReconciliation",
    "tenzro_getRegistryEntry",
    "tenzro_getReserve",
    "tenzro_getReserveFeed",
    "tenzro_getRewardEpoch",
    "tenzro_getRewardSchedule",
    "tenzro_getRole",
    "tenzro_getRoleStakes",
    "tenzro_getRouterMetrics",
    "tenzro_getSealedModel",
    "tenzro_getSettlementPreference",
    "tenzro_getSigningPayload",
    "tenzro_getSnapshotManifest",
    "tenzro_getSponsoredBond",
    "tenzro_getStateProof",
    "tenzro_getStateRoot",
    "tenzro_getStatusList",
    "tenzro_getSupplyMetrics",
    "tenzro_getTeeAttestation",
    "tenzro_getTerritoryPolicy",
    "tenzro_getToken",
    "tenzro_getTokenBalance",
    "tenzro_getToolCallRecords",
    "tenzro_getTransaction",
    "tenzro_getTransactionHistory",
    "tenzro_getTreasuryAccounts",
    "tenzro_getTreasuryPayouts",
    "tenzro_getTrustCredentials",
    "tenzro_getUpgradeReadiness",
    "tenzro_getValidatorState",
    "tenzro_getVesting",
    "tenzro_getVotingPower",
    "tenzro_getWalletProvider",
    "tenzro_getZkAttestation",
    "tenzro_imageEmbed",
    "tenzro_imageTextSimilarity",
    "tenzro_inferenceRequest",
    "tenzro_introspectToken",
    "tenzro_iroh_fetchBlob",
    "tenzro_iroh_getEndpointId",
    "tenzro_iroh_getInfo",
    "tenzro_iroh_listAlpns",
    "tenzro_iroh_publishBlob",
    "tenzro_iroh_resolveTenzroUri",
    "tenzro_issueAccessToken",
    "tenzro_issueKyaCredential",
    "tenzro_joinAsMicroNode",
    "tenzro_listActiveValidators",
    "tenzro_listAgentBondsByController",
    "tenzro_listAudioCatalog",
    "tenzro_listBoundDevices",
    "tenzro_listBridgeRoutes",
    "tenzro_listCatalog",
    "tenzro_listCircuits",
    "tenzro_listComputeBonds",
    "tenzro_listDecisionCatalog",
    "tenzro_listDetectionCatalog",
    "tenzro_listDuties",
    "tenzro_listEscrowsByPayee",
    "tenzro_listEscrowsByPayer",
    "tenzro_listForecastCatalog",
    "tenzro_listIdentities",
    "tenzro_listInferenceChallenges",
    "tenzro_listInferenceUsage",
    "tenzro_listInsuranceClaims",
    "tenzro_listKillSwitchByAgent",
    "tenzro_listKillSwitchByController",
    "tenzro_listLevers",
    "tenzro_listMismatches",
    "tenzro_listModelEndpoints",
    "tenzro_listModels",
    "tenzro_listNetworkLegs",
    "tenzro_listPayments",
    "tenzro_listPeers",
    "tenzro_listPlans",
    "tenzro_listProposals",
    "tenzro_listProviders",
    "tenzro_listRegistry",
    "tenzro_listRelays",
    "tenzro_listRerankCatalog",
    "tenzro_listRewardCoupons",
    "tenzro_listRoleEndpoints",
    "tenzro_listRpcMethods",
    "tenzro_listSealedModels",
    "tenzro_listSegmentationCatalog",
    "tenzro_listSettlements",
    "tenzro_listSnapshots",
    "tenzro_listTeeProviders",
    "tenzro_listTextEmbeddingCatalog",
    "tenzro_listTextSegmentationCatalog",
    "tenzro_listTokens",
    "tenzro_listTtsCatalog",
    "tenzro_listValidators",
    "tenzro_listVideoCatalog",
    "tenzro_listVisionCatalog",
    "tenzro_listZkCircuits",
    "tenzro_livenessStats",
    "tenzro_mediaGen_listCatalog",
    "tenzro_mediaGen_render",
    "tenzro_memoryBudget",
    "tenzro_modelLifecycle",
    "tenzro_modelMetadata",
    "tenzro_modelRecipientKey",
    "tenzro_moeCatalogShape",
    "tenzro_moeExpertStatus",
    "tenzro_moeListReceipts",
    "tenzro_moePlanDispatch",
    "tenzro_moePrepareStatus",
    "tenzro_moeReplicationPolicy",
    "tenzro_moeRoute",
    "tenzro_moeShardMap",
    "tenzro_nodeDidDocument",
    "tenzro_nodeProfile",
    "tenzro_nodeVisibility",
    "tenzro_oauthDiscovery",
    "tenzro_onboardAutonomousAgent",
    "tenzro_openPaymentChannel",
    "tenzro_peerCount",
    "tenzro_permit2NonceUsed",
    "tenzro_permit2VerifyAndConsume",
    "tenzro_prefixProbe",
    "tenzro_previewServe",
    "tenzro_previewSplit",
    "tenzro_priceCardToPublish",
    "tenzro_queryEvents",
    "tenzro_quoteBridgeFeeInTnzo",
    "tenzro_quoteInference",
    "tenzro_quotePayment",
    "tenzro_readPorReserve",
    "tenzro_redeemSealedDelivery",
    "tenzro_refreshToken",
    "tenzro_rerank",
    "tenzro_resolveAgentKey",
    "tenzro_resolveCredential",
    "tenzro_resolveDidDocument",
    "tenzro_resolveIdentity",
    "tenzro_rotateIdentityToPq",
    "tenzro_routeDifficultyStats",
    "tenzro_routeIntent",
    "tenzro_segment",
    "tenzro_sendRawTransaction",
    "tenzro_settlementNetworks",
    "tenzro_slaGetParams",
    "tenzro_slaListOutstandingProbes",
    "tenzro_slaVerdict",
    "tenzro_speak",
    "tenzro_sponsoredInference",
    "tenzro_standbyQuote",
    "tenzro_storageStatus",
    "tenzro_submitReconciliation",
    "tenzro_submitTrustRecord",
    "tenzro_subscribe",
    "tenzro_syncing",
    "tenzro_teeAttestationChallenge",
    "tenzro_textEmbed",
    "tenzro_textSegment",
    "tenzro_tokenBalance",
    "tenzro_totalSupply",
    "tenzro_trafficStats",
    "tenzro_transcribe",
    "tenzro_transcribeStream",
    "tenzro_urwaGetFrozenTokens",
    "tenzro_urwaIsKillSwitched",
    "tenzro_verifyAgentAuditAttestation",
    "tenzro_verifyDaPointer",
    "tenzro_verifyDidEnvelope",
    "tenzro_verifyEventProof",
    "tenzro_verifyEvidence",
    "tenzro_verifyInferenceCommitment",
    "tenzro_verifyInferenceReceipt",
    "tenzro_verifyKyaCredential",
    "tenzro_verifyNodeDidDocument",
    "tenzro_verifyPayment",
    "tenzro_verifySignature",
    "tenzro_verifyTeeAttestation",
    "tenzro_verifyTeeFinalityProof",
    "tenzro_verifyTeeZkProof",
    "tenzro_verifyTrustCredential",
    "tenzro_verifyVrfProof",
    "tenzro_verifyZkProof",
    "tenzro_videoEmbed",
    "tenzro_walletReadiness",
    "web3_clientVersion",
    "web3_sha3",
];

/// Open methods whose names read as writes, with the reason each may stay
/// open. Every entry must be in [`OPEN_METHODS`]; every open method whose name
/// reads as a write must be here.
pub const OPEN_WRITES: &[(&str, &str)] = &[
    (
        "tenzro_agentNodePqKey",
        "returns this node's ML-DSA-65 key for an agent and its proof of possession: the key derives in memory from the hardware root, the only signature is that fixed proof, and nothing is written",
    ),
    (
        "tenzro_sponsoredInference",
        "payer-granted: spends only under the grant the sponsoring agent's controller signed on chain (its terms, naming this node), each call checked against that grant's models, caps, expiry and standing before it is served, within a per-source and a global rate, an output cap and a daily budget; off unless the operator configures it",
    ),
    (
        "tenzro_createPasskeySession",
        "opens a pending enrolment ceremony; completing it enrols only a passkey that proves possession of its own key",
    ),
    (
        "tenzro_accessChallenge",
        "issues a single-use, in-memory sign-in challenge; writes no state",
    ),
    (
        "tenzro_attestFinalityProof",
        "attests caller input with this node's own TEE and returns the bundle; stores nothing",
    ),
    (
        "tenzro_issueAccessToken",
        "issues a token only to a caller that answered its challenge with its own passkey or hardware key",
    ),
    (
        "tenzro_exportEvidencePack",
        "reads a proof bundle from certified state; the caller must be allowed to read the subject's audit",
    ),
    (
        "eth_call",
        "executes against a scratch copy of state and returns the result",
    ),
    (
        "tenzro_submitReconciliation",
        "checks a reconciliation against the stored one and returns the transaction for the caller to sign; writes no state",
    ),
    (
        "eth_sendRawTransaction",
        "carries the external wallet's secp256k1 signature, from which the sender is recovered before admission",
    ),
    (
        "sendTransaction",
        "carries the external wallet's Ed25519 signatures, verified before admission",
    ),
    (
        "simulateTransaction",
        "executes against a scratch copy of state and returns the outcome",
    ),
    (
        "eth_estimateGas",
        "executes against a scratch copy of state and returns the gas used",
    ),
    (
        "tenzro_sendRawTransaction",
        "carries the sender's hardware composite signature, verified against the enrolled account keys before admission",
    ),
    (
        "tenzro_deployContract",
        "admits a ContractDeploy transaction carrying the sender's hardware composite signature over its code, nonce and chain; it executes only in a block",
    ),
    (
        "tenzro_canTransfer",
        "evaluates a transfer against token policy and balances without executing it; changes nothing",
    ),
    (
        "tenzro_createCustodyChallenge",
        "issues a challenge that is worthless without an enrolled credential to sign it",
    ),
    (
        "tenzro_createPaymentChallenge",
        "quotes a resource's price to an unpaid caller, which is how a caller learns what to pay",
    ),
    (
        "tenzro_createTeeZkProof",
        "proves over caller input and returns the proof; stores nothing",
    ),
    (
        "tenzro_createZkProof",
        "proves over caller input and returns the proof; stores nothing",
    ),
    (
        "tenzro_fileInferenceChallenge",
        "opens a dispute on a stored commitment; the verdict comes from a stake-weighted validator committee",
    ),
    (
        "tenzro_finalizeChallenge",
        "tallies votes the committee already cast; the verdict is theirs, and finalizing twice returns the same verdict",
    ),
    (
        "tenzro_iroh_publishBlob",
        "stores a content-addressed blob; nothing serves it until an owner-signed deploy names its hash",
    ),
    (
        "tenzro_issueKyaCredential",
        "issues a credential only for a DID the presented key derives, attesting nothing the proof does not show",
    ),
    (
        "tenzro_joinAsMicroNode",
        "creates a new node identity from the keys the caller presents",
    ),
    (
        "tenzro_onboardAutonomousAgent",
        "creates a new self-controlled identity bonded from its own new wallet",
    ),
    (
        "tenzro_openPaymentChannel",
        "opens a channel over an escrow the payer already funded to this node; every charge still needs the payer's signed voucher",
    ),
    (
        "tenzro_redeemSealedDelivery",
        "pays only the escrow's payee, and only against the preimage the escrow commits to",
    ),
    (
        "tenzro_refreshToken",
        "the refresh token presented is the credential, with a DPoP proof from the key it is bound to; each one is spent by its exchange",
    ),
    (
        "tenzro_rotateIdentityToPq",
        "rotates only with the current root key's signature and the new key's own proof",
    ),
    (
        "tenzro_submitTrustRecord",
        "each record carries its author's signature or a recomputed content address, re-verified before it is stored",
    ),
    (
        "tenzro_queryEvents",
        "reads the chain's event log and builds proofs from stored blocks and checkpoints; writes nothing",
    ),
    (
        "tenzro_subscribe",
        "reads the chain's event log after the caller's cursor, waiting for new blocks; writes nothing",
    ),
    (
        "tenzro_standbyQuote",
        "reads the live provider announcements this node has heard and returns who holds a model on standby at what fee; writes nothing",
    ),
];

/// Whether `method` has been classified at all.
///
/// A dispatched method that nobody classified returns `false` and is refused
/// before it runs. That is the default-deny direction: forgetting to classify
/// makes a method unreachable rather than making it public.
pub(crate) fn is_classified(method: &str) -> bool {
    is_known_method(method)
}

/// Every method the dispatcher serves, sorted, with no duplicates.
///
/// The union of [`ADMIN_METHODS`], [`OWNER_METHODS`] and [`OPEN_METHODS`].
/// Because the classification test refuses to pass while any dispatch arm is
/// unclassified, this is not an approximation of the method surface — it *is*
/// the method surface, and a caller enumerating it has enumerated everything
/// the node can do.
///
/// That property is what the discovery surfaces are built on: rather than each
/// client shipping its own hand-maintained list that drifts, they all ask the
/// node.
pub fn all_methods() -> Vec<&'static str> {
    let mut all: Vec<&'static str> = ADMIN_METHODS
        .iter()
        .copied()
        .chain(OWNER_METHODS.iter().copied())
        .chain(OPEN_METHODS.iter().copied())
        .collect();
    all.sort_unstable();
    all
}

/// Whether `method` is one the dispatcher serves at all.
pub fn is_known_method(method: &str) -> bool {
    gate_class(method).is_some()
}

/// How a method is gated, for discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateClass {
    /// Requires the operator DID or a policy admin.
    Admin,
    /// Open to any caller; the handler requires a proof from the owner of
    /// what it changes.
    Owner,
    /// Open to any caller the access policy admits.
    Open,
}

/// The gate class of `method`, or `None` if the dispatcher does not serve it.
pub fn gate_class(method: &str) -> Option<GateClass> {
    if ADMIN_METHODS.binary_search(&method).is_ok() {
        Some(GateClass::Admin)
    } else if OWNER_METHODS.binary_search(&method).is_ok() {
        Some(GateClass::Owner)
    } else if OPEN_METHODS.binary_search(&method).is_ok() {
        Some(GateClass::Open)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    /// The faucet is gone, so no faucet method carries a gate. A gate on a
    /// method that refuses would say the method exists.
    #[test]
    fn no_faucet_method_is_gated() {
        for m in [
            "tenzro_faucet",
            "tenzro_faucetTransfer",
            "tenzro_faucetInfo",
            "tenzro_requestFaucet",
        ] {
            assert_eq!(gate_class(m), None, "{m} must carry no gate");
        }
    }

    /// Signing with the node's own sealed validator keyset is an operator
    /// action: it spends the node's balance and moves its consensus weight.
    /// Open would let any caller drain the validator into its own stake.
    #[test]
    fn signing_with_the_sealed_validator_keyset_is_admin_only() {
        assert_eq!(
            gate_class("tenzro_validatorSelfStake"),
            Some(GateClass::Admin)
        );
    }

    /// Storing objects, reading them back and pricing them belong to the
    /// provider running the node. Compute claim, observation and SLA reads are public; ACP checkouts spend for the authenticated caller.
    #[test]
    fn compute_claim_methods_are_classified() {
        for m in [
            "tenzro_storageSetPricing",
            "tenzro_storageStoreObject",
            "tenzro_storageRetrieveObject",
            "tenzro_slaIssueProbe",
        ] {
            assert_eq!(gate_class(m), Some(GateClass::Admin), "{m}");
        }
        for m in [
            "tenzro_computeGetClaim",
            "tenzro_computeListClaims",
            "tenzro_computePriceFeed",
            "tenzro_slaVerdict",
        ] {
            assert_eq!(gate_class(m), Some(GateClass::Open), "{m}");
        }
        // The settle RPC that took the provider's word for its own uptime is
        // gone; billing follows the committed SLA verdicts.
        assert_eq!(gate_class("tenzro_computeSettleEpoch"), None);
    }

    #[test]
    fn the_registry_is_the_whole_method_surface() {
        // The tables are sorted and disjoint (pinned by the tests below), so
        // their union is every method, once.
        let all = all_methods();
        assert_eq!(
            all.len(),
            ADMIN_METHODS.len() + OWNER_METHODS.len() + OPEN_METHODS.len()
        );
        let mut deduped = all.clone();
        deduped.dedup();
        assert_eq!(deduped.len(), all.len(), "a method is classified twice");
        assert!(all.windows(2).all(|w| w[0] <= w[1]), "not sorted");
    }

    #[test]
    fn gate_class_agrees_with_the_tables() {
        assert_eq!(gate_class("tenzro_setAccessPolicy"), Some(GateClass::Admin));
        assert_eq!(gate_class("tenzro_settle"), Some(GateClass::Owner));
        assert_eq!(gate_class("eth_blockNumber"), Some(GateClass::Open));
        assert_eq!(gate_class("tenzro_notAMethod"), None);
        assert!(is_known_method("tenzro_storageStatus"));
        assert!(!is_known_method(""));
    }

    use super::*;
    use std::collections::BTreeSet;

    /// Prefixes of every JSON-RPC method this node serves. Used to tell a
    /// dispatch arm from an unrelated `match` on strings elsewhere in the file.
    const RPC_PREFIXES: &[&str] = &["tenzro_", "eth_", "net_", "web3_"];

    fn is_rpc_name(s: &str) -> bool {
        RPC_PREFIXES.iter().any(|p| s.starts_with(p))
    }

    /// Pull every method literal out of the dispatcher's `match` arms.
    ///
    /// Reads the source rather than a hand-kept list, because a hand-kept list
    /// is the thing that drifts. Walks backwards from each `=>` collecting the
    /// `"lit" | "lit" | …` run that precedes it.
    fn dispatched_methods(src: &str) -> BTreeSet<&str> {
        let bytes = src.as_bytes();
        let mut found = BTreeSet::new();
        let mut cursor = 0usize;

        while let Some(offset) = src[cursor..].find("=>") {
            let arrow = cursor + offset;
            // Solana wallet methods carry no namespace prefix; their arms are
            // the ones that hand the call to the Solana handlers.
            let svm_arm = src[arrow + 2..]
                .trim_start()
                .trim_start_matches('{')
                .trim_start()
                .starts_with("crate::svm_rpc::");
            let mut end = arrow;
            loop {
                while end > 0 && bytes[end - 1].is_ascii_whitespace() {
                    end -= 1;
                }
                if end == 0 || bytes[end - 1] != b'"' {
                    break;
                }
                let close = end - 1;
                let Some(open) = src[..close].rfind('"') else {
                    break;
                };
                let literal = &src[open + 1..close];
                if !(is_rpc_name(literal) || svm_arm) {
                    break;
                }
                found.insert(literal);
                end = open;
                while end > 0 && bytes[end - 1].is_ascii_whitespace() {
                    end -= 1;
                }
                if end > 0 && bytes[end - 1] == b'|' {
                    end -= 1;
                } else {
                    break;
                }
            }
            cursor = arrow + 2;
        }
        found
    }

    /// The invariant this module exists for: you cannot add an RPC without
    /// deciding whether it needs node administration.
    #[test]
    fn every_dispatched_method_is_classified() {
        let src = include_str!("rpc.rs");
        let dispatched = dispatched_methods(src);
        assert!(
            dispatched.len() > 400,
            "extraction found only {} methods — the dispatcher's shape changed \
             and this test is no longer reading it",
            dispatched.len()
        );

        let unclassified: Vec<_> = dispatched
            .iter()
            .filter(|m| !is_classified(m))
            .copied()
            .collect();
        assert!(
            unclassified.is_empty(),
            "these RPCs are dispatched but unclassified, so they are refused \
             before they run — add each to ADMIN_METHODS, OWNER_METHODS or \
             OPEN_METHODS in rpc_gates.rs: {unclassified:?}"
        );
    }

    /// The other direction: a classification for a method that no longer
    /// exists is stale, and stale entries are how a list stops describing
    /// reality.
    #[test]
    fn no_classification_names_a_method_that_is_not_dispatched() {
        let src = include_str!("rpc.rs");
        let dispatched = dispatched_methods(src);
        let orphans: Vec<_> = all_methods()
            .into_iter()
            .filter(|m| !dispatched.contains(m))
            .collect();
        assert!(
            orphans.is_empty(),
            "classified but not dispatched — delete these from rpc_gates.rs: \
             {orphans:?}"
        );
    }

    #[test]
    fn the_lists_are_sorted_and_disjoint() {
        for list in [ADMIN_METHODS, OWNER_METHODS, OPEN_METHODS] {
            assert!(
                list.windows(2).all(|w| w[0] < w[1]),
                "list must be sorted and duplicate-free for binary_search"
            );
        }
        let admin: BTreeSet<_> = ADMIN_METHODS.iter().collect();
        let owner: BTreeSet<_> = OWNER_METHODS.iter().collect();
        let open: BTreeSet<_> = OPEN_METHODS.iter().collect();
        for (a, b) in [(&admin, &owner), (&admin, &open), (&owner, &open)] {
            let both: Vec<_> = a.intersection(b).collect();
            assert!(both.is_empty(), "classified twice: {both:?}");
        }
    }

    #[test]
    fn an_unknown_method_is_not_classified() {
        assert!(!is_classified("tenzro_methodThatDoesNotExist"));
        assert!(!is_classified(""));
    }

    #[test]
    fn known_gates_land_where_they_should() {
        assert_eq!(gate_class("tenzro_setAccessPolicy"), Some(GateClass::Admin));
        assert_eq!(gate_class("eth_blockNumber"), Some(GateClass::Open));
        assert_ne!(gate_class("tenzro_enrollPasskey"), Some(GateClass::Admin));
        assert!(is_classified("eth_blockNumber"));
    }

    /// Subsystem prefixes a method name may carry before its verb:
    /// `tenzro_moeExpertLoad` is the `load` verb of the `moeExpert`
    /// subsystem.
    const NAME_PREFIXES: &[&str] = &[
        "tenzro_",
        "eth_",
        "net_",
        "web3_",
        "mediaGen_",
        "training_",
        "iroh_",
        "site",
        "function",
        "machine",
        "storage",
        "compute",
        "moe",
        "moeExpert",
        "moeGate",
        "moePrepare",
        "treasury",
        "x402",
        "erc8004",
        "prepaid",
        "memory",
        "da",
        "sla",
        "urwa",
        "eip7702",
        "permit2",
        "siwt",
        "vrf",
        "dvp",
        "mpc",
        "agent",
        "model",
        "cluster",
        "nft",
        "autotune",
        "route",
        "node",
        "peer",
        "provider",
        "bridge",
        "settlement",
        "file",
        "identity",
        "passkey",
        "session",
        "keri",
        "ivms101",
        "mastercardKya",
        "stripeSpt",
        "tempo",
        "universalResolver",
        "signedAgentCard",
        "global",
        "liveness",
        "traffic",
        "rentable",
        "hardware",
        "fabric",
        "hf",
        "oauth",
        "caip",
        "irohInfo",
        "daCommittee",
        "svm",
        "bridgeXyz",
    ];

    /// Leading verbs of methods that only read, verify or compute. An open
    /// method is taken to change nothing only when its verb is here; any
    /// other verb needs its reason in [`OPEN_WRITES`]. A new verb is
    /// therefore a write until someone says otherwise.
    const READ_VERBS: &[&str] = &[
        "accounts",
        "alias",
        "attested",
        "audit",
        "availability",
        "balance",
        "block",
        "bond",
        "budget",
        "build",
        "caip",
        "can",
        "canonical",
        "capacity",
        "catalog",
        "chain",
        "chat",
        "check",
        "client",
        "commitment",
        "committed",
        "committee",
        "connected",
        "count",
        "current",
        "customer",
        "deal",
        "decide",
        "decisions",
        "decode",
        "derive",
        "detect",
        "did",
        "difficulty",
        "digest",
        "discover",
        "discovery",
        "domain",
        "download",
        "embed",
        "encode",
        "epsilon",
        "estimate",
        "evaluate",
        "event",
        "fee",
        "fetch",
        "find",
        "forecast",
        "gas",
        "get",
        "hash",
        "hashrate",
        "health",
        "image",
        "inference",
        "info",
        "intent",
        "introspect",
        "iroh",
        "is",
        "known",
        "lanes",
        "lifecycle",
        "list",
        "listening",
        "local",
        "max",
        "members",
        "metadata",
        "methods",
        "mining",
        "networks",
        "nonce",
        "ntt",
        "owner",
        "parse",
        "payment",
        "pending",
        "plan",
        "prefix",
        "preview",
        "price",
        "profile",
        "protocol",
        "quote",
        "rank",
        "reachability",
        "read",
        "recall",
        "recipient",
        "render",
        "rental",
        "replication",
        "rerank",
        "resolve",
        "revalidate",
        "role",
        "route",
        "routes",
        "same",
        "sealing",
        "search",
        "segment",
        "sha",
        "shard",
        "signing",
        "speak",
        "stats",
        "status",
        "step",
        "summarize",
        "supply",
        "supported",
        "syncing",
        "tee",
        "text",
        "token",
        "total",
        "track",
        "transcribe",
        "usage",
        "validate",
        "verdict",
        "verifier",
        "verify",
        "version",
        "video",
        "visibility",
        "vision",
        "wallet",
        "wallets",
        "watch",
    ];

    /// The verb a method name leads with, after its subsystem prefixes.
    fn leading_verb(method: &str) -> String {
        let mut rest = method.to_string();
        loop {
            let best = NAME_PREFIXES
                .iter()
                .filter(|p| {
                    rest.len() > p.len()
                        && rest.starts_with(**p)
                        && (p.ends_with('_') || rest.as_bytes()[p.len()].is_ascii_uppercase())
                })
                .max_by_key(|p| p.len());
            match best {
                Some(p) => {
                    let tail = &rest[p.len()..];
                    let mut chars = tail.chars();
                    let first = chars.next().map(|c| c.to_ascii_lowercase());
                    rest = first.into_iter().chain(chars).collect();
                }
                None => break,
            }
        }
        rest.chars()
            .skip_while(|c| !c.is_ascii_alphabetic())
            .enumerate()
            .take_while(|(i, c)| c.is_ascii_lowercase() || (*i == 0 && c.is_ascii_uppercase()))
            .map(|(_, c)| c.to_ascii_lowercase())
            .collect()
    }

    #[test]
    fn leading_verb_reads_through_subsystem_prefixes() {
        assert_eq!(leading_verb("tenzro_moeExpertLoad"), "load");
        assert_eq!(leading_verb("tenzro_moeExpertStatus"), "status");
        assert_eq!(leading_verb("tenzro_mediaGen_render"), "render");
        assert_eq!(leading_verb("tenzro_installSealedModel"), "install");
        assert_eq!(leading_verb("tenzro_sendRawTransaction"), "send");
    }

    /// An open method must not change anyone else's state. The name is the
    /// only thing a table can check mechanically, so this refuses every open
    /// method whose verb is not on the read-only list [`READ_VERBS`] unless
    /// [`OPEN_WRITES`] says why it may stay open.
    #[test]
    fn open_methods_do_not_change_state() {
        let explained: BTreeSet<&str> = OPEN_WRITES.iter().map(|(m, _)| *m).collect();
        let unexplained: Vec<_> = OPEN_METHODS
            .iter()
            .filter(|m| !READ_VERBS.contains(&leading_verb(m).as_str()))
            .filter(|m| !explained.contains(*m))
            .collect();
        assert!(
            unexplained.is_empty(),
            "open methods not known to be read-only, with no reason in \
             OPEN_WRITES — move each to ADMIN_METHODS, or to OWNER_METHODS once \
             its handler checks the owner's proof: {unexplained:?}"
        );
    }

    /// The reason a method was missed before: a verb nobody listed as a write
    /// (`report`) passed as a read. Under the read-only list it cannot.
    #[test]
    fn an_unlisted_verb_is_not_read_only() {
        assert!(!READ_VERBS.contains(&leading_verb("tenzro_slaReportOutage").as_str()));
        assert!(!READ_VERBS.contains(&leading_verb("tenzro_somethingNew").as_str()));
    }

    #[test]
    fn open_writes_are_open_and_explained() {
        for (method, reason) in OPEN_WRITES {
            assert_eq!(
                gate_class(method),
                Some(GateClass::Open),
                "{method} is in OPEN_WRITES but not open"
            );
            assert!(!reason.trim().is_empty(), "{method} has no reason");
        }
    }

    /// Writes that were once open with nothing checking the caller. Each
    /// changes state that belongs to the operator or to someone other than
    /// the caller, so none may be open again.
    #[test]
    fn unauthenticated_writes_are_not_open() {
        const MUST_NOT_BE_OPEN: &[&str] = &[
            "tenzro_buildModelManifest",
            "tenzro_cleanupIdleLocalModelServices",
            "tenzro_hostModel",
            "tenzro_loadAudioModel",
            "tenzro_loadVisionModel",
            "tenzro_moeExpertLoad",
            "tenzro_moeExpertUnload",
            "tenzro_moeGateLoad",
            "tenzro_moeGateUnload",
            "tenzro_pruneModelRegistry",
            "tenzro_scanModelFiles",
            "tenzro_shutdown",
            "tenzro_storageSetPricing",
            "tenzro_unloadAudioModel",
            "tenzro_unregisterModelEndpoint",
            "tenzro_verifyModelFiles",
        ];
        let open: Vec<_> = MUST_NOT_BE_OPEN
            .iter()
            .filter(|m| gate_class(m) == Some(GateClass::Open))
            .collect();
        assert!(open.is_empty(), "back in OPEN_METHODS: {open:?}");
        for m in MUST_NOT_BE_OPEN {
            assert!(is_known_method(m), "{m} is not dispatched any more");
        }
    }

    /// Calls that, found in a handler, show it checks a proof from the owner
    /// of what it changes. `approve_withdrawal` and `update_channel` hand the
    /// signature to the treasury and the channel ledger, which verify it.
    const PROOF_MARKERS: &[&str] = &[
        "require_did_owner",
        "require_address_owner",
        "require_signed_owner_request",
        "require_registration_proof",
        "require_key_possession(",
        " = party(",
        "bearer(node, auth_ctx)",
        "bearer_did(node, auth_ctx)",
        "pay_with_voucher(",
        "ledger_payment::settle(",
        ": Signed",
        "verify_creator_signature",
        "authenticate_bearer",
        "enforce_memory_access",
        "authenticate_db_caller",
        "enforce_database_scope",
        "require_account_control",
        "approve_as_root(",
        "require_machine_owner",
        "webauthn_validator",
        "verify_agent_key_binding",
        "validate_jwt",
        "verify_expert_receipt",
        "VerifiedMembership::verify",
        "_signed(",
        "tenant_did(",
        "acting_agent(",
        "verify(&",
        "verify_composite(",
        "approve_withdrawal(",
        "update_channel(",
        "PaymentExpectation::Resource",
        "identity_revocation::authorize(",
        "verify_release(",
    ];

    /// Sources holding the handlers the dispatcher calls.
    fn handler_sources() -> String {
        [
            include_str!("rpc.rs"),
            include_str!("passkey_rpc.rs"),
            include_str!("machine_access.rs"),
            include_str!("moe.rs"),
            include_str!("rpc_integrations.rs"),
            include_str!("payment_channels.rs"),
            include_str!("event_index.rs"),
            include_str!("payment_rpc.rs"),
            include_str!("zk_rpc.rs"),
            include_str!("cluster_identity.rs"),
            include_str!("agent_delegation.rs"),
            include_str!("agent_accounts.rs"),
            include_str!("key_release_rpc.rs"),
        ]
        .concat()
    }

    /// The body of `fn name`, braces included.
    fn fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
        let mut from = 0;
        let start = loop {
            let at = from + src[from..].find(&format!("fn {name}"))?;
            let after = &src[at + 3 + name.len()..];
            if after.starts_with('(') || after.starts_with('<') {
                break at;
            }
            from = at + 3;
        };
        let open = start + src[start..].find('{')?;
        let mut depth = 0usize;
        for (i, b) in src.as_bytes()[open..].iter().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[start..open + i + 1]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// The function a dispatch arm calls first.
    fn dispatched_handler<'a>(dispatcher: &'a str, method: &str) -> Option<&'a str> {
        let main = dispatcher.find("let result = match request.method.as_str() {")?;
        let arm = main + dispatcher[main..].find(&format!("\"{method}\""))?;
        let rest = &dispatcher[arm..];
        let body = &rest[rest.find("=>")? + 2..];
        let mut ident_start = None;
        for (i, c) in body.char_indices() {
            match (ident_start, c) {
                (None, c) if c.is_ascii_alphabetic() || c == '_' => ident_start = Some(i),
                (Some(_), c) if c.is_ascii_alphanumeric() || c == '_' || c == ':' => {}
                (Some(s), '(') => {
                    let path = &body[s..i];
                    return path.rsplit("::").next();
                }
                (Some(_), _) => ident_start = None,
                _ => {}
            }
        }
        None
    }

    /// Every owner-class method's handler, or a handler it calls directly,
    /// must check some proof. A floor, not a proof of correctness: it catches
    /// a method moved here whose handler still believes whatever the caller
    /// says.
    #[test]
    fn owner_methods_check_a_proof() {
        let dispatcher = include_str!("rpc.rs");
        let sources = handler_sources();
        let mut unchecked = Vec::new();
        for method in OWNER_METHODS {
            let handler = dispatched_handler(dispatcher, method)
                .unwrap_or_else(|| panic!("no dispatch arm found for {method}"));
            let body = fn_body(&sources, handler)
                .unwrap_or_else(|| panic!("no body found for {handler} ({method})"));
            let mut text = body.to_string();
            let mut i = 0;
            while let Some(at) = body[i..].find("handle_") {
                let s = i + at;
                let e = s + body[s..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(body.len() - s);
                if body[e..].starts_with('(')
                    && let Some(callee) = fn_body(&sources, &body[s..e])
                {
                    text.push_str(callee);
                }
                i = e;
            }
            if !PROOF_MARKERS.iter().any(|m| text.contains(m)) {
                unchecked.push(*method);
            }
        }
        assert!(
            unchecked.is_empty(),
            "OWNER_METHODS whose handlers check no proof — move them to \
             ADMIN_METHODS: {unchecked:?}"
        );
    }
}
