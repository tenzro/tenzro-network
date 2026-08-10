//! Default-deny classification of the JSON-RPC method surface.
//!
//! Every method the dispatcher serves is named in exactly one of
//! [`ADMIN_METHODS`] or [`OPEN_METHODS`]. A method in neither is
//! unreachable — [`handle_request`](super::handle_request) refuses it
//! before dispatch.
//!
//! # Why a list rather than a predicate
//!
//! The gate used to be an allowlist of methods that *needed* the operator
//! admin token, which meant a newly added method was open until someone
//! remembered to close it. That default already produced gaps: the M14 wave
//! had to retrofit the gate across thirteen methods that were shipping
//! unauthenticated.
//!
//! Inverting it moves the failure from "silently reachable in production" to
//! "the classification test fails in CI" — see
//! [`tests::every_dispatched_method_is_classified`], which reads the
//! dispatcher's own source and refuses to pass while any arm is unclassified.
//! Adding an RPC without deciding its gate is no longer possible.
//!
//! Both arrays are sorted so lookup is a binary search, and a test pins the
//! sort order rather than trusting it.

/// Methods behind the operator admin token (`X-Tenzro-Admin-Token`).
///
/// Four were moved here after an audit found them reachable with no credential
/// at all, each confirmed against a running node:
///
/// - `tenzro_setProviderSchedule` — a stranger could set `enabled: false` and
///   stop the operator serving. An unauthenticated kill switch on someone
///   else's revenue.
/// - `tenzro_setProviderPricing` — a stranger could set the operator's prices
///   to 1 wei, or high enough that nobody buys.
/// - `tenzro_setSpendingPolicy` / `tenzro_setSpendingLimits` — the *runtime*
///   ceiling on what an agent may spend. Raising it unauthenticated defeats the
///   delegation-scope model these exist to enforce; the probe raised a victim
///   agent's cap to ~1e12 and the node answered `success: true`.
///
/// The model-management group joined them for the same reason. `stopModel`,
/// `deleteModel`, `cancelDownload`, `downloadModel`, `serveModel` and
/// `registerModelEndpoint` decide what an operator's own hardware runs and what
/// occupies its disk — and were open. Probed on a running node, a stranger
/// stopped a served model, deleted one, and cancelled an in-flight download,
/// each answering `success: true`. `pinModel` / `unpinModel` were already here,
/// which is what made the omission visible: the same subsystem was half gated.
///
/// All are machine policy belonging to whoever runs the node, which is
/// what the admin token authenticates. They were open for the same reason the
/// M14 wave found thirteen others open: the gate used to be an allowlist of
/// methods that needed closing, so anything new was open until someone
/// remembered. That default is inverted now — see the module docs — but the
/// methods that predate the inversion still had to be audited one at a time.
///
/// These either mutate operator-controlled state (key issuance, staking
/// against the operator's own account, compliance actions, participant
/// administration) or read across every tenant on the node.
pub const ADMIN_METHODS: &[&str] = &[
    "tenzro_addServiceKey",
    "tenzro_addTrustedIssuer",
    "tenzro_allocateParty",
    "tenzro_applyCorporateActions",
    "tenzro_authorizeCrosschainBridge",
    "tenzro_bindDevice",
    "tenzro_cancelDownload",
    "tenzro_canton_aggregateAnalytics",
    "tenzro_canton_coinBalance",
    "tenzro_canton_createIdp",
    "tenzro_canton_deleteIdp",
    "tenzro_canton_grantUserRights",
    "tenzro_canton_listApiKeyAnalytics",
    "tenzro_canton_listIdps",
    "tenzro_canton_listPackages",
    "tenzro_canton_listParties",
    "tenzro_canton_listUserRights",
    "tenzro_canton_mirrorReceipt",
    "tenzro_canton_streamEvents",
    "tenzro_canton_uploadDar",
    "tenzro_clearSecureMintPolicy",
    "tenzro_consumeDamlEvents",
    "tenzro_createApiKey",
    "tenzro_createContributorVesting",
    "tenzro_createGrantVesting",
    "tenzro_crosschainBurn",
    "tenzro_crosschainMint",
    "tenzro_delegateSponsorship",
    "tenzro_deleteModel",
    "tenzro_deleteModelMcp",
    "tenzro_downloadModel",
    "tenzro_dvpExecuteSaga",
    "tenzro_dvpFinalizeSaga",
    "tenzro_dvpOpenSaga",
    "tenzro_enrollTeeKey",
    "tenzro_evictMcpSubprocess",
    "tenzro_exportConfig",
    "tenzro_forgetIdentity",
    "tenzro_forgetMcpSecret",
    "tenzro_forgetServiceKey",
    "tenzro_freezeAddress",
    "tenzro_getAccessLease",
    "tenzro_gossipStats",
    "tenzro_installSealedModel",
    "tenzro_listAccessLeases",
    "tenzro_listApiKeys",
    "tenzro_listBridgeAnalytics",
    "tenzro_listShellSessionReceipts",
    "tenzro_mediaGen_removeWorker",
    "tenzro_memoryAdmit",
    "tenzro_memoryRelease",
    "tenzro_mirrorObligationToCanton",
    "tenzro_mirrorSettlement",
    "tenzro_mirrorWorkflowToCanton",
    "tenzro_mpcKeygen",
    "tenzro_mpcKeygenStatus",
    "tenzro_nettingCompute",
    "tenzro_nettingSettle",
    "tenzro_openAccessLease",
    "tenzro_overrideModelHash",
    "tenzro_pinModel",
    "tenzro_produceSnapshot",
    "tenzro_recordInteraction",
    "tenzro_recoverTokens",
    "tenzro_registerModelEndpoint",
    "tenzro_registerPorFeed",
    "tenzro_registerProvider",
    "tenzro_retryUnpaidSettlement",
    "tenzro_revokeAccessLease",
    "tenzro_revokeApiKey",
    "tenzro_revokeBoundDevice",
    "tenzro_revokeBridge",
    "tenzro_revokeDid",
    "tenzro_revokeIdentity",
    "tenzro_revokeServiceKey",
    "tenzro_revokeSponsorship",
    "tenzro_revokeTeeKey",
    "tenzro_scheduleCorporateAction",
    "tenzro_sealModel",
    "tenzro_serveModel",
    "tenzro_serveModelMcp",
    "tenzro_serviceKeyStatus",
    "tenzro_setBridgeFeeRate",
    "tenzro_setCountryRestriction",
    "tenzro_setDelegationScope",
    "tenzro_setDraining",
    "tenzro_setEquityProfile",
    "tenzro_setGlobalIssuancePause",
    "tenzro_setNodeVisibility",
    "tenzro_setProviderPricing",
    "tenzro_setProviderSchedule",
    "tenzro_setSecureMintPaused",
    "tenzro_setSecureMintPolicy",
    "tenzro_setSpendingLimits",
    "tenzro_setSpendingPolicy",
    "tenzro_setSponsorshipEnabled",
    "tenzro_setSponsorshipRefillThreshold",
    "tenzro_slashSponsorshipBond",
    "tenzro_stake",
    "tenzro_stakeTokens",
    "tenzro_stopModel",
    "tenzro_storeMcpSecret",
    "tenzro_transferMachineOwnership",
    "tenzro_treasuryAddWithdrawer",
    "tenzro_treasuryRemoveWithdrawer",
    "tenzro_treasurySetWithdrawalThreshold",
    "tenzro_unfreezeAddress",
    "tenzro_unpinModel",
    "tenzro_unstake",
    "tenzro_unstakeTokens",
    "tenzro_updateBridgeLimits",
    "tenzro_urwaClearKillSwitch",
    "tenzro_urwaSetFrozenTokens",
    "tenzro_urwaTriggerKillSwitch",
    "tenzro_whitelistAddress",
];
/// Methods any caller may reach without the operator admin token.
///
/// "Open" here means *open with respect to this gate*. Several of these
/// still pass through the scoped API-key gate
/// ([`gate_api_key`](super::gate_api_key)), the node admission gate, or
/// per-handler authorization; the classification below is only about the
/// admin token.
pub const OPEN_METHODS: &[&str] = &[
    "eth_accounts",
    "eth_blockNumber",
    "eth_call",
    "eth_chainId",
    "eth_estimateGas",
    "eth_estimateUserOperationGas",
    "eth_feeHistory",
    "eth_gasPrice",
    "eth_getBalance",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getBlockTransactionCountByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getCode",
    "eth_getCompilers",
    "eth_getLogs",
    "eth_getStorageAt",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionCount",
    "eth_getTransactionReceipt",
    "eth_getUserOperationReceipt",
    "eth_hashrate",
    "eth_maxPriorityFeePerGas",
    "eth_mining",
    "eth_sendRawTransaction",
    "eth_sendUserOperation",
    "eth_supportedEntryPoints",
    "eth_syncing",
    "net_listening",
    "net_peerCount",
    "net_version",
    "tenzro_addCredential",
    "tenzro_addGuardian",
    "tenzro_addHardwareSigner",
    "tenzro_addIdentityClaim",
    "tenzro_addPasskey",
    "tenzro_addResource",
    "tenzro_addService",
    "tenzro_addWallet",
    "tenzro_agentHeartbeat",
    "tenzro_agentPayForInference",
    "tenzro_agentPayForService",
    "tenzro_ap2ProtocolInfo",
    "tenzro_ap2ReportMandateViolation",
    "tenzro_ap2SignMandate",
    "tenzro_ap2ValidateMandatePair",
    "tenzro_ap2VerifyMandate",
    "tenzro_assignTask",
    "tenzro_attestedClockNow",
    "tenzro_attestedMint",
    "tenzro_authorizeBridge",
    "tenzro_authorizeDatabaseRead",
    "tenzro_authorizeSession",
    "tenzro_autotuneDecisions",
    "tenzro_axelarCallContract",
    "tenzro_axelarGetMessage",
    "tenzro_axelarListChains",
    "tenzro_axelarPayGas",
    "tenzro_babylonGetFinalityProvider",
    "tenzro_babylonListDelegations",
    "tenzro_babylonListFinalityProviders",
    "tenzro_babylonRegisterFinalityProvider",
    "tenzro_babylonSubmitFinalitySignature",
    "tenzro_babylonTotalStakeForProvider",
    "tenzro_bitvm2VerifierKinds",
    "tenzro_blockNumber",
    "tenzro_bridgeQuote",
    "tenzro_bridgeRoutes",
    "tenzro_bridgeStatus",
    "tenzro_bridgeTokens",
    "tenzro_bridgeWithHook",
    "tenzro_buildReserveAttestationFromPor",
    "tenzro_caip10",
    "tenzro_caip19",
    "tenzro_caip2",
    "tenzro_cancelTask",
    "tenzro_canton_connectedSynchronizers",
    "tenzro_canton_feeSchedule",
    "tenzro_canton_getMyAnalytics",
    "tenzro_canton_getMyUser",
    "tenzro_canton_getTransaction",
    "tenzro_canton_health",
    "tenzro_canton_listMirroredContracts",
    "tenzro_canton_submitWithMandate",
    "tenzro_canton_version",
    "tenzro_canton_watchParty",
    "tenzro_capitalIntentAssign",
    "tenzro_capitalIntentCompensate",
    "tenzro_capitalIntentExecute",
    "tenzro_capitalIntentOpen",
    "tenzro_capitalIntentQuote",
    "tenzro_capitalIntentSettle",
    "tenzro_capitalIntentVerify",
    "tenzro_ccipBridge",
    "tenzro_ccipGetFee",
    "tenzro_ccipLanes",
    "tenzro_ccipRateLimits",
    "tenzro_ccipSend",
    "tenzro_ccipSupportedChains",
    "tenzro_ccipSupportedTokens",
    "tenzro_ccipTokenPool",
    "tenzro_ccipTrack",
    "tenzro_cctBuildMessage",
    "tenzro_cctGetPool",
    "tenzro_cctListPools",
    "tenzro_chat",
    "tenzro_chatByIntent",
    "tenzro_chatCompletion",
    "tenzro_chatStream",
    "tenzro_checkCompliance",
    "tenzro_claimRewards",
    "tenzro_cleanupIdleLocalModelServices",
    "tenzro_closePaymentChannel",
    "tenzro_clusterMembers",
    "tenzro_clusterPlan",
    "tenzro_clusterPreview",
    "tenzro_commitChallengeVote",
    "tenzro_completeTask",
    "tenzro_computeBondParams",
    "tenzro_computeBookRental",
    "tenzro_computeFeeRoutePayouts",
    "tenzro_computeGetRental",
    "tenzro_computeRental",
    "tenzro_computeSetPricing",
    "tenzro_computeSettleEpoch",
    "tenzro_computeStatus",
    "tenzro_cortexInference",
    "tenzro_cortexReason",
    "tenzro_createAccount",
    "tenzro_createCustodyChallenge",
    "tenzro_createDatabase",
    "tenzro_createMpcWallet",
    "tenzro_createNftCollection",
    "tenzro_createPasskeySession",
    "tenzro_createPaymentChallenge",
    "tenzro_createProposal",
    "tenzro_createSwarm",
    "tenzro_createTeeZkProof",
    "tenzro_createToken",
    "tenzro_createWallet",
    "tenzro_createZkProof",
    "tenzro_crossVmTransfer",
    "tenzro_currentHeader",
    "tenzro_daAvailability",
    "tenzro_daChallenge",
    "tenzro_daCommittee",
    "tenzro_daListBlobs",
    "tenzro_daListChallenges",
    "tenzro_databaseQuery",
    "tenzro_databaseUsage",
    "tenzro_debridgeCreateTx",
    "tenzro_debridgeGetChains",
    "tenzro_debridgeGetInstructions",
    "tenzro_debridgeSameChainSwap",
    "tenzro_debridgeSearchTokens",
    "tenzro_decideApproval",
    "tenzro_decodeResult",
    "tenzro_decrypt",
    "tenzro_decryptData",
    "tenzro_delegateTask",
    "tenzro_delegateVotingPower",
    "tenzro_deleteFile",
    "tenzro_deleteWebhook",
    "tenzro_deployContract",
    "tenzro_deregisterAgent",
    "tenzro_deriveKey",
    "tenzro_detect",
    "tenzro_detectTee",
    "tenzro_discoverAgents",
    "tenzro_discoverModels",
    "tenzro_disputeTask",
    "tenzro_downloadAgentTemplate",
    "tenzro_downloadFile",
    "tenzro_dropDatabase",
    "tenzro_dvpGetSaga",
    "tenzro_dvpListSagasByCreator",
    "tenzro_eip7702BuildDesignator",
    "tenzro_eip7702ParseDesignator",
    "tenzro_eip7702ProtocolInfo",
    "tenzro_eip7702SigningHash",
    "tenzro_embed",
    "tenzro_encodeFunction",
    "tenzro_encrypt",
    "tenzro_encryptData",
    "tenzro_enrollPasskey",
    "tenzro_erc7802CrosschainBurn",
    "tenzro_erc7802CrosschainMint",
    "tenzro_erc7802GetCrossChainSupply",
    "tenzro_erc8004DecodeGetAgent",
    "tenzro_erc8004DecodeGetMetadata",
    "tenzro_erc8004DeriveAgentId",
    "tenzro_erc8004EncodeAppendResponse",
    "tenzro_erc8004EncodeFeedback",
    "tenzro_erc8004EncodeGetAgent",
    "tenzro_erc8004EncodeGetAgentURI",
    "tenzro_erc8004EncodeGetAgentWallet",
    "tenzro_erc8004EncodeGetFeedback",
    "tenzro_erc8004EncodeGetFeedbackCount",
    "tenzro_erc8004EncodeGetFeedbackResponses",
    "tenzro_erc8004EncodeGetMetadata",
    "tenzro_erc8004EncodeGetValidation",
    "tenzro_erc8004EncodeIsFeedbackRevoked",
    "tenzro_erc8004EncodeRegister",
    "tenzro_erc8004EncodeRegisterWithMetadata",
    "tenzro_erc8004EncodeRegisterWithUri",
    "tenzro_erc8004EncodeRevokeFeedback",
    "tenzro_erc8004EncodeSetAgentURI",
    "tenzro_erc8004EncodeSetAgentWallet",
    "tenzro_erc8004EncodeSetMetadata",
    "tenzro_erc8004EncodeValidationRequest",
    "tenzro_erc8004EncodeValidationResponse",
    "tenzro_eventStatus",
    "tenzro_exchangeToken",
    "tenzro_exportIdentityCar",
    "tenzro_exportKeystore",
    "tenzro_fabricProfile",
    "tenzro_faucet",
    "tenzro_faucetInfo",
    "tenzro_fileInferenceChallenge",
    "tenzro_fileInsuranceClaim",
    "tenzro_fileStorageUsage",
    "tenzro_fileZkFraudProof",
    "tenzro_finalizeChallenge",
    "tenzro_finalizeRecovery",
    "tenzro_findBestAgentForCapability",
    "tenzro_forecast",
    "tenzro_functionDeploy",
    "tenzro_functionGet",
    "tenzro_functionRemove",
    "tenzro_fundAgent",
    "tenzro_generateKeypair",
    "tenzro_generateVrfKeyPair",
    "tenzro_generateVrfProof",
    "tenzro_get7683Order",
    "tenzro_get7702Delegation",
    "tenzro_getAccountContention",
    "tenzro_getAccountRecord",
    "tenzro_getAgent",
    "tenzro_getAgentBond",
    "tenzro_getAgentCapabilityAttestations",
    "tenzro_getAgentDailySpend",
    "tenzro_getAgentJwk",
    "tenzro_getAgentLifecycle",
    "tenzro_getAgentTemplate",
    "tenzro_getAgentTemplateStats",
    "tenzro_getApp",
    "tenzro_getApproval",
    "tenzro_getApprovalGate",
    "tenzro_getApprovalRequest",
    "tenzro_getAttestation",
    "tenzro_getBalance",
    "tenzro_getBlock",
    "tenzro_getBlockRange",
    "tenzro_getBridgeAnalytics",
    "tenzro_getBridgeRoutes",
    "tenzro_getBurnQuota",
    "tenzro_getBurnRateConfig",
    "tenzro_getBurnRateRecommendation",
    "tenzro_getCapabilityAttestations",
    "tenzro_getCapitalIntent",
    "tenzro_getComputeBond",
    "tenzro_getContentProvenance",
    "tenzro_getDaBackends",
    "tenzro_getDatabase",
    "tenzro_getDatabasePartition",
    "tenzro_getDispute",
    "tenzro_getDownloadProgress",
    "tenzro_getEconomicPolicy",
    "tenzro_getEquityProfile",
    "tenzro_getEscrow",
    "tenzro_getEvents",
    "tenzro_getFeeRoute",
    "tenzro_getFile",
    "tenzro_getFill7683",
    "tenzro_getFinalizedBlock",
    "tenzro_getGeneration",
    "tenzro_getHardwareProfile",
    "tenzro_getInferenceChallenge",
    "tenzro_getInferenceCommitment",
    "tenzro_getInsuranceClaim",
    "tenzro_getInsurancePoolBalance",
    "tenzro_getInteraction",
    "tenzro_getKeyShares",
    "tenzro_getKillSwitchReceipt",
    "tenzro_getKnowledge",
    "tenzro_getKyaRecord",
    "tenzro_getLeasesForApp",
    "tenzro_getMempoolLane",
    "tenzro_getMempoolStats",
    "tenzro_getModelEndpoint",
    "tenzro_getModelHash",
    "tenzro_getNetworkActivity",
    "tenzro_getNetworkStats",
    "tenzro_getNftCollection",
    "tenzro_getNftInfo",
    "tenzro_getNodeStatus",
    "tenzro_getNonce",
    "tenzro_getObligation",
    "tenzro_getPasskeyPolicy",
    "tenzro_getPasskeySession",
    "tenzro_getPaymentReceipt",
    "tenzro_getPrice",
    "tenzro_getPrivacyDomain",
    "tenzro_getProposal",
    "tenzro_getProviderPricing",
    "tenzro_getProviderReputation",
    "tenzro_getProviderSchedule",
    "tenzro_getProviderStats",
    "tenzro_getReceiptPrincipalChain",
    "tenzro_getReserve",
    "tenzro_getRewardEpoch",
    "tenzro_getRewardSchedule",
    "tenzro_getRole",
    "tenzro_getRouterMetrics",
    "tenzro_getSealedModel",
    "tenzro_getSecureMintPolicy",
    "tenzro_getSeedAgentCharter",
    "tenzro_getSeedAgentDaemonStatus",
    "tenzro_getSettleAuthorizedOutcome",
    "tenzro_getSettlement",
    "tenzro_getSettlementPreference",
    "tenzro_getSkill",
    "tenzro_getSkillUsage",
    "tenzro_getSmartAccount",
    "tenzro_getSnapshotChunk",
    "tenzro_getSnapshotManifest",
    "tenzro_getSpendingLimits",
    "tenzro_getSpendingPolicy",
    "tenzro_getSponsorshipPool",
    "tenzro_getSponsorshipSlot",
    "tenzro_getStableAsset",
    "tenzro_getSupplyMetrics",
    "tenzro_getSwarmStatus",
    "tenzro_getTask",
    "tenzro_getTeeAttestation",
    "tenzro_getToken",
    "tenzro_getTokenBalance",
    "tenzro_getTokenInfo",
    "tenzro_getTool",
    "tenzro_getToolUsage",
    "tenzro_getTrainerDaemonStatus",
    "tenzro_getTransaction",
    "tenzro_getTransactionHistory",
    "tenzro_getTreasuryEarmark",
    "tenzro_getValidatorState",
    "tenzro_getVesting",
    "tenzro_getVotingPower",
    "tenzro_getWorkflow",
    "tenzro_getWorkflowLifecycle",
    "tenzro_getWorkflowOperationalMetrics",
    "tenzro_getWorkflowReceipt",
    "tenzro_getWorkflowSaga",
    "tenzro_getWorkflowTemplate",
    "tenzro_getZkAttestation",
    "tenzro_globalSupplyCirculating",
    "tenzro_globalSupplyPolicy",
    "tenzro_gracefulExit",
    "tenzro_grantSessionKey",
    "tenzro_hardwareProfile",
    "tenzro_hashKeccak256",
    "tenzro_hashSha256",
    "tenzro_heartbeatAgentTemplate",
    "tenzro_heartbeatSkill",
    "tenzro_heartbeatTool",
    "tenzro_hfTokenStatus",
    "tenzro_hyperbridgeMintControlsDefault",
    "tenzro_hyperlaneDispatch",
    "tenzro_hyperlaneGetMessage",
    "tenzro_hyperlaneListChains",
    "tenzro_hyperlaneQuoteDispatch",
    "tenzro_ibcEurekaCommitmentTag",
    "tenzro_imageEmbed",
    "tenzro_imageTextSimilarity",
    "tenzro_importIdentity",
    "tenzro_importIdentityCar",
    "tenzro_importKeystore",
    "tenzro_inferenceRequest",
    "tenzro_initiateRecovery",
    "tenzro_install7702Delegation",
    "tenzro_instantiateWorkflow",
    "tenzro_introspectToken",
    "tenzro_irohInfo",
    "tenzro_irohListAlpns",
    "tenzro_irohStatus",
    "tenzro_iroh_fetchBlob",
    "tenzro_iroh_getConfig",
    "tenzro_iroh_getEndpointId",
    "tenzro_iroh_getInfo",
    "tenzro_iroh_listAlpns",
    "tenzro_iroh_publishBlob",
    "tenzro_iroh_resolveTenzroUri",
    "tenzro_issueCredential",
    "tenzro_issueDatabaseConnection",
    "tenzro_ivms101Hash",
    "tenzro_joinAsMicroNode",
    "tenzro_keriBuildInception",
    "tenzro_linkWalletForAuth",
    "tenzro_liquidStakingBalanceOf",
    "tenzro_liquidStakingClaimWithdrawal",
    "tenzro_liquidStakingDeposit",
    "tenzro_liquidStakingDistributeRewards",
    "tenzro_liquidStakingPendingWithdrawals",
    "tenzro_liquidStakingRequestWithdrawal",
    "tenzro_liquidStakingStats",
    "tenzro_liquidStakingTransfer",
    "tenzro_list7683Orders",
    "tenzro_listAccounts",
    "tenzro_listActiveValidators",
    "tenzro_listAdaptiveBurnProposals",
    "tenzro_listAgentBondsByController",
    "tenzro_listAgentJwks",
    "tenzro_listAgentTemplates",
    "tenzro_listAgentTransactions",
    "tenzro_listAgents",
    "tenzro_listApps",
    "tenzro_listAudioCatalog",
    "tenzro_listAudioModels",
    "tenzro_listAuthorizedBridges",
    "tenzro_listBoundDevices",
    "tenzro_listBridgeAdapters",
    "tenzro_listBridgeSponsorshipPools",
    "tenzro_listCantonDomains",
    "tenzro_listCapabilities",
    "tenzro_listChains",
    "tenzro_listCircuits",
    "tenzro_listComputeBonds",
    "tenzro_listCorporateActions",
    "tenzro_listCortexWorkers",
    "tenzro_listDamlContracts",
    "tenzro_listDatabaseEngines",
    "tenzro_listDatabasePartitions",
    "tenzro_listDatabases",
    "tenzro_listDetectionCatalog",
    "tenzro_listDetectionModels",
    "tenzro_listDisputesByChannel",
    "tenzro_listEscrowsByPayee",
    "tenzro_listEscrowsByPayer",
    "tenzro_listFeeRoutes",
    "tenzro_listFiles",
    "tenzro_listFills7683",
    "tenzro_listForecastCatalog",
    "tenzro_listForecastModels",
    "tenzro_listFunctions",
    "tenzro_listIdentities",
    "tenzro_listInferenceChallenges",
    "tenzro_listInferenceUsage",
    "tenzro_listInsuranceClaims",
    "tenzro_listKillSwitchByAgent",
    "tenzro_listKillSwitchByController",
    "tenzro_listKnowledge",
    "tenzro_listLeases",
    "tenzro_listMachines",
    "tenzro_listMandates",
    "tenzro_listMemoryRecords",
    "tenzro_listModelEndpoints",
    "tenzro_listModelHashes",
    "tenzro_listModels",
    "tenzro_listMyApiKeys",
    "tenzro_listNftCollections",
    "tenzro_listNodeAliases",
    "tenzro_listPasskeys",
    "tenzro_listPaymentProtocols",
    "tenzro_listPaymentSessions",
    "tenzro_listPendingApprovals",
    "tenzro_listPendingRecoveries",
    "tenzro_listPrivacyDomainsForDid",
    "tenzro_listProposals",
    "tenzro_listProviderCapacity",
    "tenzro_listProviders",
    "tenzro_listReceiptsByActor",
    "tenzro_listReceiptsByController",
    "tenzro_listRemoteCortexWorkers",
    "tenzro_listResources",
    "tenzro_listRewardCoupons",
    "tenzro_listRpcMethods",
    "tenzro_listSealedModels",
    "tenzro_listSeedAgentCharters",
    "tenzro_listSeedAgents",
    "tenzro_listSegmentationCatalog",
    "tenzro_listSegmentationModels",
    "tenzro_listSiteAliases",
    "tenzro_listSiteDomains",
    "tenzro_listSitePlacements",
    "tenzro_listSites",
    "tenzro_listSkills",
    "tenzro_listSmartAccounts",
    "tenzro_listSnapshots",
    "tenzro_listSponsorshipSlots",
    "tenzro_listSubscriptions",
    "tenzro_listSupportedChains",
    "tenzro_listSwarms",
    "tenzro_listTasks",
    "tenzro_listTeeProviders",
    "tenzro_listTextEmbeddingCatalog",
    "tenzro_listTextEmbeddingModels",
    "tenzro_listTextSegmentationCatalog",
    "tenzro_listTextSegmentationModels",
    "tenzro_listTokens",
    "tenzro_listTools",
    "tenzro_listTrustedIssuers",
    "tenzro_listTtsCatalog",
    "tenzro_listUnpaidSettlements",
    "tenzro_listValidators",
    "tenzro_listVideoCatalog",
    "tenzro_listVideoModels",
    "tenzro_listVisionCatalog",
    "tenzro_listVisionModels",
    "tenzro_listWebhooks",
    "tenzro_listWorkflowReceipts",
    "tenzro_listWorkflowTemplates",
    "tenzro_listWorkflowsByCreator",
    "tenzro_listWorkflowsByParticipant",
    "tenzro_listWorkflowsByStatus",
    "tenzro_listX402Schemes",
    "tenzro_listZkCircuits",
    "tenzro_livenessStats",
    "tenzro_loadAudioModel",
    "tenzro_loadDetectionModel",
    "tenzro_loadForecastModel",
    "tenzro_loadSegmentationModel",
    "tenzro_loadTextEmbeddingModel",
    "tenzro_loadTextSegmentationModel",
    "tenzro_loadVideoModel",
    "tenzro_loadVisionModel",
    "tenzro_localPeers",
    "tenzro_machineDeploy",
    "tenzro_machineGet",
    "tenzro_machineRemove",
    "tenzro_machineSealingKey",
    "tenzro_machineStatus",
    "tenzro_mastercardKyaProtocolInfo",
    "tenzro_mediaGen_cancelJob",
    "tenzro_mediaGen_claimJob",
    "tenzro_mediaGen_enrollWorker",
    "tenzro_mediaGen_failJob",
    "tenzro_mediaGen_fetchInput",
    "tenzro_mediaGen_fetchLatent",
    "tenzro_mediaGen_fetchOutput",
    "tenzro_mediaGen_getJob",
    "tenzro_mediaGen_getReceipt",
    "tenzro_mediaGen_listCatalog",
    "tenzro_mediaGen_listJobs",
    "tenzro_mediaGen_listWorkers",
    "tenzro_mediaGen_markRunning",
    "tenzro_mediaGen_postJob",
    "tenzro_mediaGen_publishOutput",
    "tenzro_mediaGen_quote",
    "tenzro_mediaGen_recordHandoff",
    "tenzro_mediaGen_submitReceipt",
    "tenzro_memoryArchive",
    "tenzro_memoryBudget",
    "tenzro_memoryGrant",
    "tenzro_memoryRecall",
    "tenzro_mintNft",
    "tenzro_mintNftBatch",
    "tenzro_mintStableAsset",
    "tenzro_modelLifecycle",
    "tenzro_modelMetadata",
    "tenzro_modelRecipientKey",
    "tenzro_moeCatalogShape",
    "tenzro_moeDisputeReceipt",
    "tenzro_moeExecute",
    "tenzro_moeExpertLoad",
    "tenzro_moeExpertStatus",
    "tenzro_moeExpertUnload",
    "tenzro_moeForward",
    "tenzro_moeGateLoad",
    "tenzro_moeGateUnload",
    "tenzro_moeListReceipts",
    "tenzro_moePlanDispatch",
    "tenzro_moePrepareExperts",
    "tenzro_moePrepareStatus",
    "tenzro_moeReplicationPolicy",
    "tenzro_moeRoute",
    "tenzro_moeShardMap",
    "tenzro_mpcPkrStatus",
    "tenzro_mpcPresignStats",
    "tenzro_nearChainSigEpsilon",
    "tenzro_nettingGetBatch",
    "tenzro_nettingListBatches",
    "tenzro_nftBalanceOf",
    "tenzro_nftOwnerOf",
    "tenzro_nodeAliasConsent",
    "tenzro_nodeDidDocument",
    "tenzro_nodeInfo",
    "tenzro_nodeProfile",
    "tenzro_nodeReachability",
    "tenzro_nodeVisibility",
    "tenzro_oauthDiscovery",
    "tenzro_onboardAutonomousAgent",
    "tenzro_onboardDelegatedAgent",
    "tenzro_onboardHuman",
    "tenzro_open7683Order",
    "tenzro_openPaymentChannel",
    "tenzro_orchestrate",
    "tenzro_participate",
    "tenzro_payMastercard",
    "tenzro_payMpp",
    "tenzro_payVisaTap",
    "tenzro_payX402",
    "tenzro_paymentGatewayInfo",
    "tenzro_peerCount",
    "tenzro_permit2Digest",
    "tenzro_permit2DomainSeparator",
    "tenzro_permit2NonceUsed",
    "tenzro_permit2VerifyAndConsume",
    "tenzro_postTask",
    "tenzro_prepaidBalance",
    "tenzro_prepaidDeposit",
    "tenzro_prepaidWithdraw",
    "tenzro_previewServe",
    "tenzro_processSptGrantedTokenDeactivated",
    "tenzro_processSptSettlementOutcome",
    "tenzro_processTapPayerAuthOutcome",
    "tenzro_providerStats",
    "tenzro_pruneAgentRegistry",
    "tenzro_pruneModelRegistry",
    "tenzro_pruneSkillRegistry",
    "tenzro_pruneTaskRegistry",
    "tenzro_pruneToolRegistry",
    "tenzro_publishAccountRecord",
    "tenzro_quoteBridge",
    "tenzro_quoteBridgeFeeInTnzo",
    "tenzro_quoteRental",
    "tenzro_quoteTask",
    "tenzro_rateAgentTemplate",
    "tenzro_readPorReserve",
    "tenzro_recordFill7683",
    "tenzro_recordModelHash",
    "tenzro_recordRouteOutcome",
    "tenzro_redeemStableAsset",
    "tenzro_refillSeedAgent",
    "tenzro_refreshToken",
    "tenzro_registerAgent",
    "tenzro_registerAgentTemplate",
    "tenzro_registerApp",
    "tenzro_registerCompliance",
    "tenzro_registerCortexWorker",
    "tenzro_registerIdentity",
    "tenzro_registerKnowledge",
    "tenzro_registerMachineIdentity",
    "tenzro_registerNftPointer",
    "tenzro_registerSkill",
    "tenzro_registerStableAsset",
    "tenzro_registerTool",
    "tenzro_registerUsername",
    "tenzro_registerWebhook",
    "tenzro_registerWorkflowTemplate",
    "tenzro_releaseVesting",
    "tenzro_removePasskey",
    "tenzro_rentableCapacity",
    "tenzro_requestFaucet",
    "tenzro_requestShellSession",
    "tenzro_rescaleDatabase",
    "tenzro_resolveDid",
    "tenzro_resolveDidDocument",
    "tenzro_resolveIdentity",
    "tenzro_resolveNodeAlias",
    "tenzro_resolveUsername",
    "tenzro_resumeAgent",
    "tenzro_revalidateUserOp",
    "tenzro_revealChallengeVote",
    "tenzro_revoke7702Delegation",
    "tenzro_revokeJwt",
    "tenzro_revokeMyApiKey",
    "tenzro_revokeSession",
    "tenzro_revokeSessionKey",
    "tenzro_role",
    "tenzro_rotateKeys",
    "tenzro_rotateValidatorKey",
    "tenzro_routeDifficultyStats",
    "tenzro_routeIntent",
    "tenzro_runAgentTask",
    "tenzro_runAgentTemplate",
    "tenzro_sealData",
    "tenzro_searchAgentTemplates",
    "tenzro_searchKnowledge",
    "tenzro_searchSkills",
    "tenzro_searchTools",
    "tenzro_secureMintApply",
    "tenzro_secureMintCheck",
    "tenzro_secureMintRecordBurn",
    "tenzro_segment",
    "tenzro_sendAgentMessage",
    "tenzro_setAppStatus",
    "tenzro_setPasskeyPolicy",
    "tenzro_setPrimaryWallet",
    "tenzro_setRole",
    "tenzro_setSettlementPreference",
    "tenzro_setSpendingLimit",
    "tenzro_setUsername",
    "tenzro_settle",
    "tenzro_settleAuthorized",
    "tenzro_settlePayment",
    "tenzro_settlementNetworks",
    "tenzro_shutdown",
    "tenzro_signAndSendTransaction",
    "tenzro_signMessage",
    "tenzro_signTransaction",
    "tenzro_signWithPasskey",
    "tenzro_signedAgentCardCanonicalHash",
    "tenzro_siteClaimDomain",
    "tenzro_siteGet",
    "tenzro_siteGetAlias",
    "tenzro_siteGetDomain",
    "tenzro_siteGetPlacement",
    "tenzro_sitePublish",
    "tenzro_siteRemove",
    "tenzro_siteRemoveAlias",
    "tenzro_siteRemoveDomain",
    "tenzro_siteRemovePlacement",
    "tenzro_siteSetAlias",
    "tenzro_siteSetPlacement",
    "tenzro_siteVerifyDomain",
    "tenzro_siwtBuildMessage",
    "tenzro_siwtParseMessage",
    "tenzro_slaGetParams",
    "tenzro_slaIssueProbe",
    "tenzro_slaListOutstandingProbes",
    "tenzro_spawnAgent",
    "tenzro_spawnAgentFromTemplate",
    "tenzro_spawnAgentTemplate",
    "tenzro_spawnAgentWithSkill",
    "tenzro_spawnChildAgent",
    "tenzro_sponsorBridgeFee",
    "tenzro_stargateV2KnownPools",
    "tenzro_storageChargeEpoch",
    "tenzro_storageDeal",
    "tenzro_storageGetDeal",
    "tenzro_storageOpenDeal",
    "tenzro_storageSetPricing",
    "tenzro_storageStatus",
    "tenzro_storageStoreObject",
    "tenzro_stripeSptProtocolInfo",
    "tenzro_submitDamlCommand",
    "tenzro_submitRecoverySignature",
    "tenzro_submitReserveAttestation",
    "tenzro_subscribeEvents",
    "tenzro_subscribeEventsStream",
    "tenzro_summarizeController",
    "tenzro_suspendAgent",
    "tenzro_svmDispatch",
    "tenzro_swapToken",
    "tenzro_syncing",
    "tenzro_tempoProtocolInfo",
    "tenzro_terminateSwarm",
    "tenzro_textEmbed",
    "tenzro_textSegment",
    "tenzro_tokenBalance",
    "tenzro_totalSupply",
    "tenzro_trafficStats",
    "tenzro_training_challengeCommitment",
    "tenzro_training_decideRound",
    "tenzro_training_enrollTrainer",
    "tenzro_training_finalizeRound",
    "tenzro_training_getReceipt",
    "tenzro_training_getRun",
    "tenzro_training_getSealedManifest",
    "tenzro_training_installSealedManifest",
    "tenzro_training_listRuns",
    "tenzro_training_postTask",
    "tenzro_training_submitOuterGradient",
    "tenzro_transcribe",
    "tenzro_transferNft",
    "tenzro_treasuryApproveWithdrawal",
    "tenzro_treasuryExecuteWithdrawal",
    "tenzro_treasuryGetPendingWithdrawal",
    "tenzro_universalResolverMethods",
    "tenzro_unloadAudioModel",
    "tenzro_unloadDetectionModel",
    "tenzro_unloadForecastModel",
    "tenzro_unloadSegmentationModel",
    "tenzro_unloadTextEmbeddingModel",
    "tenzro_unloadTextSegmentationModel",
    "tenzro_unloadVideoModel",
    "tenzro_unloadVisionModel",
    "tenzro_unregisterModelEndpoint",
    "tenzro_unsealData",
    "tenzro_updateAgentTemplate",
    "tenzro_updateIdentity",
    "tenzro_updatePaymentChannel",
    "tenzro_updateSkill",
    "tenzro_updateTask",
    "tenzro_updateTool",
    "tenzro_uploadFile",
    "tenzro_urwaGetFrozenTokens",
    "tenzro_urwaIsKillSwitched",
    "tenzro_useKnowledge",
    "tenzro_useResource",
    "tenzro_useSkill",
    "tenzro_useTool",
    "tenzro_validateLei",
    "tenzro_validateMandatePair",
    "tenzro_verifyDaPointer",
    "tenzro_verifyDidEnvelope",
    "tenzro_verifyInferenceCommitment",
    "tenzro_verifyInteraction",
    "tenzro_verifyPayment",
    "tenzro_verifySignature",
    "tenzro_verifyTeeAttestation",
    "tenzro_verifyTeeZkProof",
    "tenzro_verifyVrfProof",
    "tenzro_verifyZkProof",
    "tenzro_videoEmbed",
    "tenzro_visaTapProtocolInfo",
    "tenzro_visionEmbed",
    "tenzro_visionSimilarity",
    "tenzro_vote",
    "tenzro_voteOnProposal",
    "tenzro_vrfGenerateKeyPair",
    "tenzro_walletReadiness",
    "tenzro_workflowFinalize",
    "tenzro_workflowOpen",
    "tenzro_workflowSetStepDeadline",
    "tenzro_workflowStepCompensate",
    "tenzro_workflowStepExecute",
    "tenzro_workflowStepVerify",
    "tenzro_wormholeBridge",
    "tenzro_wormholeChainId",
    "tenzro_wormholeNttListChains",
    "tenzro_wormholeParseVaaId",
    "tenzro_wrapTnzo",
    "tenzro_x25519KeyExchange",
    "tenzro_x402DeregisterResource",
    "tenzro_x402DiscoverResources",
    "tenzro_x402PaymentId",
    "tenzro_x402ProtocolInfo",
    "tenzro_x402RegisterResource",
    "tenzro_x402VerifyOffer",
    "web3_clientVersion",
    "web3_sha3",
];

/// Whether `method` is gated behind the operator admin token.
pub(crate) fn requires_admin_token(method: &str) -> bool {
    ADMIN_METHODS.binary_search(&method).is_ok()
}

/// Whether `method` has been classified at all.
///
/// A dispatched method that nobody classified returns `false` and is refused
/// before it runs. That is the default-deny direction: forgetting to classify
/// makes a method unreachable rather than making it public.
pub(crate) fn is_classified(method: &str) -> bool {
    OPEN_METHODS.binary_search(&method).is_ok() || requires_admin_token(method)
}

/// Every method the dispatcher serves, sorted, with no duplicates.
///
/// The union of [`ADMIN_METHODS`] and [`OPEN_METHODS`]. Because the
/// classification test refuses to pass while any dispatch arm is unclassified,
/// this is not an approximation of the method surface — it *is* the method
/// surface, and a caller enumerating it has enumerated everything the node can
/// do.
///
/// That property is what the discovery surfaces are built on: rather than each
/// client shipping its own hand-maintained list that drifts, they all ask the
/// node.
pub fn all_methods() -> Vec<&'static str> {
    let mut all: Vec<&'static str> = ADMIN_METHODS
        .iter()
        .copied()
        .chain(OPEN_METHODS.iter().copied())
        .collect();
    all.sort_unstable();
    all
}

/// Whether `method` is one the dispatcher serves at all.
pub fn is_known_method(method: &str) -> bool {
    ADMIN_METHODS.binary_search(&method).is_ok() || OPEN_METHODS.binary_search(&method).is_ok()
}

/// How a method is gated, for discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateClass {
    /// Requires the operator admin token.
    Admin,
    /// Open to any caller, subject to any API-key scope the method carries.
    Open,
}

/// The gate class of `method`, or `None` if the dispatcher does not serve it.
pub fn gate_class(method: &str) -> Option<GateClass> {
    if ADMIN_METHODS.binary_search(&method).is_ok() {
        Some(GateClass::Admin)
    } else if OPEN_METHODS.binary_search(&method).is_ok() {
        Some(GateClass::Open)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_registry_is_the_whole_method_surface() {
        // Both tables are sorted and disjoint (pinned by the tests below), so
        // their union is every method, once.
        let all = all_methods();
        assert_eq!(all.len(), ADMIN_METHODS.len() + OPEN_METHODS.len());
        let mut deduped = all.clone();
        deduped.dedup();
        assert_eq!(deduped.len(), all.len(), "a method is classified twice");
        assert!(all.windows(2).all(|w| w[0] <= w[1]), "not sorted");
    }

    #[test]
    fn gate_class_agrees_with_the_tables() {
        assert_eq!(gate_class("tenzro_createApiKey"), Some(GateClass::Admin));
        assert_eq!(gate_class("eth_blockNumber"), Some(GateClass::Open));
        assert_eq!(gate_class("tenzro_notAMethod"), None);
        assert!(is_known_method("tenzro_listFiles"));
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
                if !is_rpc_name(literal) {
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
    /// deciding whether it needs the operator admin token.
    #[test]
    fn every_dispatched_method_is_classified() {
        let src = include_str!("rpc.rs");
        let dispatched = dispatched_methods(src);
        assert!(
            dispatched.len() > 500,
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
             before they run — add each to ADMIN_METHODS or OPEN_METHODS in \
             rpc_gates.rs: {unclassified:?}"
        );
    }

    /// The other direction: a classification for a method that no longer
    /// exists is stale, and stale entries are how a list stops describing
    /// reality.
    #[test]
    fn no_classification_names_a_method_that_is_not_dispatched() {
        let src = include_str!("rpc.rs");
        let dispatched = dispatched_methods(src);
        let orphans: Vec<_> = ADMIN_METHODS
            .iter()
            .chain(OPEN_METHODS)
            .filter(|m| !dispatched.contains(*m))
            .copied()
            .collect();
        assert!(
            orphans.is_empty(),
            "classified but not dispatched — delete these from rpc_gates.rs: \
             {orphans:?}"
        );
    }

    #[test]
    fn both_lists_are_sorted_and_disjoint() {
        for list in [ADMIN_METHODS, OPEN_METHODS] {
            assert!(
                list.windows(2).all(|w| w[0] < w[1]),
                "list must be sorted and duplicate-free for binary_search"
            );
        }
        let admin: BTreeSet<_> = ADMIN_METHODS.iter().collect();
        let open: BTreeSet<_> = OPEN_METHODS.iter().collect();
        let both: Vec<_> = admin.intersection(&open).collect();
        assert!(both.is_empty(), "classified twice: {both:?}");
    }

    #[test]
    fn an_unknown_method_is_not_classified() {
        assert!(!is_classified("tenzro_methodThatDoesNotExist"));
        assert!(!is_classified(""));
    }

    #[test]
    fn known_gates_land_where_they_should() {
        assert!(requires_admin_token("tenzro_createApiKey"));
        assert!(requires_admin_token("tenzro_freezeAddress"));
        assert!(!requires_admin_token("eth_blockNumber"));
        assert!(is_classified("eth_blockNumber"));
    }
}
