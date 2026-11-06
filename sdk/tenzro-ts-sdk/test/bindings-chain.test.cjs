// Node and chain bindings against a recording node: each binding names the
// method the node dispatches, sends the parameters its handler reads, and
// returns what the handler answers.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist");

const ADDR = "0x" + "03".repeat(32);

/** A node answering each method from `answers` (`"0x1"` otherwise) and recording each call. */
function node(answers = {}) {
  const sent = [];
  const transport = {
    async call(method, params) {
      sent.push({ method, params });
      return method in answers ? answers[method] : "0x1";
    },
  };
  const rpc = new sdk.RpcClient("http://node.test", undefined, 1000, transport);
  return {
    rpc,
    sent,
    answers,
    last(method) {
      const r = [...sent].reverse().find((s) => s.method === method);
      assert.ok(r, `no call to ${method}`);
      return r.params;
    },
  };
}

/** Answers `method` with `result`, runs `call`, and checks the params sent (every key of an object, or the whole value). */
async function check(n, method, result, call, params) {
  n.answers[method] = result;
  const out = await call();
  const got = n.last(method);
  if (params && typeof params === "object" && !Array.isArray(params)) {
    const obj = Array.isArray(got) ? got[0] : got;
    for (const [k, v] of Object.entries(params)) assert.deepEqual(obj?.[k], v, `${method}: ${k}`);
  } else {
    assert.deepEqual(got, params, method);
  }
  return out;
}

test("chain reads on the top-level client", async () => {
  const n = node();
  const c = new sdk.TenzroClient({ endpoint: "http://node.test", timeout: 1000 }, {
    call: (m, p) => n.rpc.call(m, p),
  });
  assert.equal(await check(n, "tenzro_blockNumber", "0x2a", () => c.getBlockNumber(), []), 42);
  await check(n, "tenzro_getBlock", { height: 7 }, () => c.getBlock(7), [{ block_number: 7 }]);
  await check(n, "tenzro_getBlock", { height: 7 }, () => c.getLatestBlock(), [{ height: "latest" }]);
  await check(n, "tenzro_getBlockRange", { blocks: [], nextHeight: 11 }, () => c.getBlockRange(1, 10, 5), { startHeight: 1, endHeight: 10, maxResults: 5 });
  await check(n, "tenzro_getTransaction", null, () => c.getTransaction("0xaa"), ["0xaa"]);
  assert.equal(await check(n, "tenzro_getBalance", "0x10", () => c.getBalance(ADDR), [ADDR]), 16n);
  assert.equal(await check(n, "tenzro_getNonce", "0x3", () => c.getNonce(ADDR), [ADDR]), 3);
  const report = await check(n, "tenzro_getNodeStatus", { state: "Running", block_height: 9 }, () => c.nodeInfo(), []);
  assert.equal(report.state, "Running");
  assert.equal(await check(n, "tenzro_totalSupply", "1000", () => c.totalSupply(), []), "1000");
  assert.equal(await check(n, "tenzro_peerCount", "0x4", () => c.peerCount(), []), 4);
  await check(n, "tenzro_getNetworkStats", { available: false }, () => c.getNetworkStats(), []);
  assert.equal(await check(n, "tenzro_syncing", false, () => c.isSyncing(), []), false);
  assert.equal(
    await check(n, "tenzro_syncing", { syncing: true, startingBlock: "0x0", currentBlock: "0x1", highestBlock: "0x9" }, () => c.isSyncing(), []),
    true,
  );
  assert.equal(await check(n, "tenzro_getFinalizedBlock", "0x8", () => c.getFinalizedBlock(), []), 8);
  await check(n, "tenzro_exportConfig", { config: {} }, () => c.exportConfig(), []);
  await check(n, "tenzro_getTransactionHistory", { transactions: [] }, () => c.getTransactionHistory(ADDR, 5, "9:0"), { address: ADDR, limit: 5, cursor: "9:0" });
  await check(n, "tenzro_listSettlements", { settlements: [] }, () => c.listSettlements({ payer: ADDR, limit: 3 }), { payer: ADDR, limit: 3 });
  await check(n, "tenzro_listPeers", { peers: [] }, () => c.listPeers(), []);
  await check(n, "tenzro_getProviderScorecard", { provider: ADDR }, () => c.getProviderScorecard(ADDR), { provider: ADDR });
  await check(n, "tenzro_getNetworkActivity", { epochs: [] }, () => c.getNetworkActivity(24), { epochs: 24 });
  await check(n, "tenzro_sponsoredInference", { output: "hi" }, () => c.sponsoredInference({ model: "m", input: "hello", sponsor: "did:a", max_tokens: 16 }), { model: "m", input: "hello", sponsor: "did:a", max_tokens: 16 });
});

test("node operation", async () => {
  const n = node();
  const c = new sdk.NodeClient(n.rpc);
  for (const [method, call] of [
    ["tenzro_autotuneDecisions", () => c.autotuneDecisions()],
    ["tenzro_cleanupIdleLocalModelServices", () => c.cleanupIdleLocalModelServices()],
    ["tenzro_layerPipelineStatus", () => c.layerPipelineStatus()],
    ["tenzro_fabricProfile", () => c.fabricProfile()],
    ["tenzro_gossipStats", () => c.gossipStats()],
    ["tenzro_livenessStats", () => c.livenessStats()],
    ["tenzro_memoryBudget", () => c.memoryBudget()],
    ["tenzro_nodeVisibility", () => c.nodeVisibility()],
    ["tenzro_produceSnapshot", () => c.produceSnapshot()],
    ["tenzro_shutdown", () => c.shutdown()],
    ["tenzro_trafficStats", () => c.trafficStats()],
  ]) {
    assert.deepEqual(await check(n, method, { ok: method }, call, []), { ok: method });
  }
  await check(n, "tenzro_acceptClusterMembership", {}, () => c.acceptClusterMembership({ cluster_did: "did:c", seq: 2 }), { cluster_did: "did:c", seq: 2 });
  await check(n, "tenzro_gracefulExit", {}, () => c.gracefulExit({ max_wait_secs: 30 }), { max_wait_secs: 30 });
  await check(n, "tenzro_setDraining", {}, () => c.setDraining({ draining: true }), { draining: true });
  await check(n, "tenzro_standbyQuote", [], () => c.standbyQuote({ model_id: "m", jurisdiction: "DE" }), { model_id: "m", jurisdiction: "DE" });
  await check(n, "tenzro_setNodeVisibility", {}, () => c.setNodeVisibility({ visibility: "gated" }), { visibility: "gated" });
  await check(n, "tenzro_previewServe", { fits: true }, () => c.previewServe({ model_id: "m", context_length: 4096 }), { model_id: "m", context_length: 4096 });
  await check(n, "tenzro_nodeDidDocument", { id: "did:x" }, () => new sdk.IdentityClient(n.rpc).nodeDidDocument(), []);
});

test("consensus, state and validator reads", async () => {
  const n = node();
  const v = new sdk.ValidatorClient(n.rpc);
  await check(n, "tenzro_getValidatorState", null, () => v.getState(ADDR), [{ address: ADDR }]);
  await check(n, "tenzro_listValidators", { count: 0, validators: [] }, () => v.list("Active"), [{ status: "Active" }]);
  await check(n, "tenzro_listActiveValidators", { count: 0, validators: [] }, () => v.listActive(), []);
  const header = await check(n, "tenzro_currentHeader", { height: 9, tier: "live" }, () => v.currentHeader(), []);
  assert.equal(header.tier, "live");
  await check(n, "tenzro_getCheckpointCertificate", { index: 4 }, () => v.getCheckpointCertificate({ index: 4 }), { index: 4 });
  await check(n, "tenzro_getCommittee", { epoch: 2 }, () => v.getCommittee({ epoch: 2 }), { epoch: 2 });
  await check(n, "tenzro_getCompactCertificate", { index: 4 }, () => v.getCompactCertificate(), {});
  await check(n, "tenzro_getConsensusMetrics", {}, () => v.getConsensusMetrics(), []);
  await check(n, "tenzro_getEpochHandover", { epoch: 2 }, () => v.getEpochHandover({ epoch: 2 }), { epoch: 2 });
  const fin = await check(n, "tenzro_getFinality", { ordered: 12, certified: 10, certificate: null }, () => v.getFinality(), []);
  assert.equal(fin.certified, 10);
  await check(n, "tenzro_getRewardEpoch", { epoch: 3 }, () => v.getRewardEpoch({ epoch: 3 }), { epoch: 3 });
  await check(n, "tenzro_getRewardSchedule", {}, () => v.getRewardSchedule(), []);
  await check(n, "tenzro_getStateProof", { value: null }, () => v.getStateProof({ namespace: "accounts", key: "ab" }), { namespace: "accounts", key: "ab" });
  await check(n, "tenzro_getStateRoot", { height: 9 }, () => v.getStateRoot(), []);
  await check(n, "tenzro_getVesting", {}, () => v.getVesting({ address: ADDR }), { address: ADDR });
  await check(n, "tenzro_getHardwareLevel", {}, () => v.getHardwareLevel({ address: ADDR }), { address: ADDR });
  await check(n, "tenzro_listRewardCoupons", {}, () => v.listRewardCoupons({ address: ADDR }), { address: ADDR });
  await check(n, "tenzro_validatorPublicKeys", {}, () => v.validatorPublicKeys(), []);
  await check(n, "tenzro_validatorSelfStake", "0xh", () => v.validatorSelfStake({ additional: 5 }), { additional: 5 });
  await check(n, "tenzro_verifyVrfProof", { valid: true }, () => v.verifyVrfProof({ pubkey: "0xk", proof: "0xp", alpha: "0xa" }), { pubkey: "0xk", proof: "0xp", alpha: "0xa" });

  const q = new sdk.QuotaClient(n.rpc);
  await check(n, "tenzro_getMempoolStats", {}, () => q.getMempoolStats(), []);
  await check(n, "tenzro_getMempoolLane", {}, () => q.getMempoolLane(ADDR), { address: ADDR });
  await check(n, "tenzro_getAccountContention", {}, () => q.getAccountContention(ADDR), { address: ADDR });
  await check(n, "tenzro_getDaBackends", [], () => q.getDaBackends(), []);
  await check(n, "tenzro_verifyDaPointer", {}, () => q.verifyDaPointer({ backend: "inline" }), { pointer: { backend: "inline" } });
});

test("discovery and mixture-of-experts dispatch", async () => {
  const n = node();
  const d = new sdk.DiscoveryClient(n.rpc);
  await check(n, "tenzro_moeShardMap", {}, () => d.moeShardMap("m"), { model_id: "m" });
  const routings = [{ token_index: 0, experts: [{ layer: 1, expert: 2 }] }];
  await check(n, "tenzro_moePlanDispatch", {}, () => d.moePlanDispatch("m", routings, true), { model_id: "m", routings, allow_cold: true });
  await check(n, "tenzro_moeReplicationPolicy", {}, () => d.moeReplicationPolicy(), []);
  await check(n, "tenzro_moeCatalogShape", {}, () => d.moeCatalogShape("m"), { model_id: "m" });
  await check(n, "tenzro_moeExpertStatus", {}, () => d.moeExpertStatus(), []);
  await check(n, "tenzro_moePrepareExperts", {}, () => d.moePrepareExperts("m", 1, { experts: [2, 3], includeGate: true }), { model_id: "m", layer: 1, experts: [2, 3], include_gate: true });
  const hidden = [1, -2.5, 0.25];
  const encoded = sdk.encodeF32Base64(hidden);
  await check(n, "tenzro_moeForward", { outputs: encoded }, () => d.moeForward("m", 1, 3, hidden), { model_id: "m", layer: 1, d_model: 3, hidden_states: encoded });
  assert.deepEqual(Array.from(sdk.decodeF32Base64(encoded)), hidden);
  // The Rust SDK's encoding of the same values.
  assert.equal(Buffer.from(encoded, "base64").toString("hex"), "0000803f000020c00000803e");
  await check(n, "tenzro_nodeProfile", {}, () => d.nodeProfile(), []);
  await check(n, "tenzro_deriveClusterMembership", {}, () => d.deriveClusterMembership("did:op", "c", 1, ["did:m"]), { operator_did: "did:op", name: "c", seq: 1, members: ["did:m"] });
  await check(n, "tenzro_setClusterMembership", {}, () => d.setClusterMembership({ m: 1 }, "ch"), { membership: { m: 1 }, challenge_id: "ch" });
  await check(n, "tenzro_clusterMembers", {}, () => d.clusterMembers("did:c"), { entry: "did:c" });
});

test("data availability, storage and the platform reads", async () => {
  const n = node();
  const s = new sdk.StorageClient(n.rpc);
  const owner = {
    p256PublicKey: () => new Uint8Array(64).fill(7),
    mlDsaPublicKey: () => null,
    signComposite: async () => [new Uint8Array(64).fill(9), null],
  };
  await check(n, "tenzro_storageStoreObject", { object_id: "o" }, () => s.storeObject("o", ADDR, new Uint8Array([104, 105]), 4, 2, "did:tenzro:human:o", owner), { object_id: "o", owner: ADDR, data: "aGk=", data_shards: 4, parity_shards: 2, owner_did: "did:tenzro:human:o" });
  assert.ok(typeof n.last("tenzro_storageStoreObject").did_envelope === "string");
  assert.deepEqual(Array.from(await check(n, "tenzro_storageRetrieveObject", { data: "aGk=" }, () => s.retrieveObject("o", "did:tenzro:human:o", owner), { object_id: "o" })), [104, 105]);
  assert.ok(typeof n.last("tenzro_storageRetrieveObject").did_envelope === "string");
  await check(n, "tenzro_storageSetPricing", {}, () => s.setFixedRate(7n), [{ mode: "fixed", rate: "7" }]);
  await check(n, "tenzro_storageStatus", {}, () => s.status(), []);
  await check(n, "tenzro_daAvailability", {}, () => s.daAvailability({ address: ADDR }), { address: ADDR });
  await check(n, "tenzro_daChallenge", {}, () => s.daChallenge({ commitment: "0xcc", target_index: 3 }), { commitment: "0xcc", target_index: 3 });
  await check(n, "tenzro_daCommittee", {}, () => s.daCommittee(), []);
  await check(n, "tenzro_daListBlobs", {}, () => s.daListBlobs(), []);
  await check(n, "tenzro_daListChallenges", {}, () => s.daListChallenges({ limit: 4 }), { limit: 4 });

  const da = new sdk.DaRetentionClient(n.rpc);
  await check(n, "tenzro_getDaObject", {}, () => da.object("0xcc"), { commitment: "0xcc" });
  await check(n, "tenzro_getDaRetention", {}, () => da.retention(), {});
  await check(n, "tenzro_getBeacon", {}, () => new sdk.BeaconClient(n.rpc).get({ round: 3 }), { round: 3 });
  await check(n, "tenzro_getFeeMarket", {}, () => sdk.getFeeMarket(n.rpc), {});
});

test("zero-knowledge proofs, TEE and signatures", async () => {
  const n = node();
  const zk = new sdk.ZkClient(n.rpc);
  const proof = await check(
    n,
    "tenzro_createZkProof",
    { circuit_id: "settlement", public_inputs: ["0x01", "0x02"], statement_commitment: "0xsc", proofs: [{ system: "s", proof: "0xpp", proof_size_bytes: 2 }] },
    () => zk.createProof("settlement", "0xw", "0xb"),
    { circuit_id: "settlement", witness: "0xw", binding: "0xb" },
  );
  await check(n, "tenzro_verifyZkProof", { valid: true }, () => zk.verifyProof(proof.circuit_id, proof.public_inputs, proof.proofs), {
    circuit_id: "settlement",
    public_inputs: ["0x01", "0x02"],
    proofs: [{ system: "s", proof: "0xpp" }],
  });
  const circuit = { type: "settlement", name: "PreimageAir" };
  assert.deepEqual(await check(n, "tenzro_listCircuits", { circuits: [circuit], total: 1 }, () => zk.listCircuits(), {}), [circuit]);
  await check(n, "tenzro_listZkCircuits", [circuit], () => zk.listZkCircuits(), {});
  await check(n, "tenzro_attestFinalityProof", {}, () => zk.attestFinalityProof({ image_id: "0xi", journal: "0xj", seal: "0xs" }), { image_id: "0xi", journal: "0xj", seal: "0xs" });
  await check(n, "tenzro_verifyTeeFinalityProof", {}, () => zk.verifyTeeFinalityProof({ tee_finality_proof: { b: 2 } }), { tee_finality_proof: { b: 2 } });
  await check(n, "tenzro_createTeeZkProof", {}, () => zk.createTeeZkProof({ circuit_id: "settlement", vendor: "intel-tdx", witness: "0xw", binding: "0xb" }), { circuit_id: "settlement", vendor: "intel-tdx" });
  await check(n, "tenzro_getZkAttestation", { attested: true }, () => zk.getZkAttestation({ commitment: "0xcc" }), { commitment: "0xcc" });
  await check(n, "tenzro_verifyTeeZkProof", { admitted: false }, () => zk.verifyTeeZkProof({ tee_zk_proof: { b: 1 } }), { tee_zk_proof: { b: 1 } });

  const tee = new sdk.TeeClient(n.rpc);
  await check(n, "tenzro_detectTee", { available: false }, () => tee.detectTee(), []);
  await check(n, "tenzro_getTeeAttestation", {}, () => tee.getAttestation("0xab"), { user_data: "0xab" });
  await check(n, "tenzro_teeAttestationChallenge", { nonce: "0xn" }, () => tee.attestationChallenge(), {});
  await check(n, "tenzro_verifyTeeAttestation", { valid: false }, () => tee.verifyAttestation("0xr", "0xn"), { report_hex: "0xr", nonce: "0xn" });
  const list = await check(n, "tenzro_listTeeProviders", { providers: [], total: 0, local_tee_available: false, local_vendor: null }, () => tee.listTeeProviders(), []);
  assert.equal(list.total, 0);

  const crypto = new sdk.CryptoClient(n.rpc);
  const sig = { p256: "aa", ml_dsa: null };
  const v = await check(n, "tenzro_verifySignature", { valid: true, pq_leg_verified: false, pq_enrolled: false }, () => crypto.verifySignature("0x04ab", "6869", sig), {
    public_key: "0x04ab",
    message_hex: "6869",
    signature: sig,
  });
  assert.equal(v.valid, true);
  await check(n, "tenzro_verifyVrfProof", { valid: true, output: "0xoo" }, () => crypto.verifyVrfProof("0xk", "0xp", "0xa"), { pubkey: "0xk", proof: "0xp", alpha: "0xa" });
});

test("events, iroh, staking, SLA and duties", async () => {
  const n = node();
  const ev = new sdk.EventsClient(n.rpc);
  const filter = { event_types: ["Log"] };
  await check(n, "tenzro_subscribe", { events: [] }, () => ev.subscribe(filter, "1:0:0", 100, true), { filter, wait_ms: 100, proofs: true, from_cursor: "1:0:0" });
  await check(n, "tenzro_queryEvents", { events: [] }, () => ev.query(filter, undefined, "9:0:0", 10), { filter, limit: 10, to_cursor: "9:0:0" });
  assert.deepEqual(await check(n, "tenzro_getEventProof", { proof: { p: 1 } }, () => ev.proof("1:0:0", 2), { cursor: "1:0:0", anchor_index: 2 }), { p: 1 });
  await check(n, "tenzro_eventStatus", {}, () => ev.eventStatus(), {});
  await check(n, "tenzro_verifyEventProof", { valid: true }, () => ev.verifyEventProof({ proof: { p: 1 } }), { proof: { p: 1 } });

  const iroh = new sdk.IrohClient(n.rpc);
  const info = await check(n, "tenzro_iroh_getInfo", { endpoint_id: "e", bound_alpns: ["iroh-blobs"] }, () => iroh.getInfo(), [{}]);
  assert.deepEqual(info.bound_alpns, ["iroh-blobs"]);
  await check(n, "tenzro_iroh_getEndpointId", {}, () => iroh.getEndpointId(), [{}]);
  await check(n, "tenzro_iroh_listAlpns", { alpns: [] }, () => iroh.listAlpns(), [{}]);
  await check(n, "tenzro_iroh_publishBlob", { tenzro_uri: "u" }, () => iroh.publishBlob(new Uint8Array([104, 105])), { bytes_b64: "aGk=" });
  assert.deepEqual(Array.from(await check(n, "tenzro_iroh_fetchBlob", { bytes_b64: "aGk=" }, () => iroh.fetchBlob("u"), { tenzro_uri: "u" })), [104, 105]);
  await check(n, "tenzro_iroh_resolveTenzroUri", {}, () => iroh.resolveTenzroUri({ tenzro_uri: "u" }), { tenzro_uri: "u" });

  const st = new sdk.StakingClient(n.rpc);
  await check(n, "tenzro_getRoleStakes", {}, () => st.roleStakes(ADDR), { address: ADDR });
  await check(n, "tenzro_getWalletProvider", {}, () => st.walletProvider("tenzro.com"), { rp_id: "tenzro.com" });
  await check(n, "tenzro_listRoleEndpoints", {}, () => st.roleEndpoints(), { role: "rpc" });
  await check(n, "tenzro_listRelays", {}, () => st.relays(), {});
  await check(n, "tenzro_getConnectivity", {}, () => st.connectivity(), {});

  const sla = new sdk.SlaClient(n.rpc);
  await check(n, "tenzro_slaIssueProbe", {}, () => sla.issueProbe("did:p", 1, 2, 99), { provider_did: "did:p", epoch: 1, round: 2, deadline_ms: 99 });
  await check(n, "tenzro_slaListOutstandingProbes", {}, () => sla.listOutstandingProbes(), []);
  await check(n, "tenzro_slaGetParams", {}, () => sla.getParams(), []);
  await check(n, "tenzro_slaVerdict", {}, () => sla.slaVerdict({ provider_did: "did:p", epoch: 4 }), { provider_did: "did:p", epoch: 4 });

  const duty = new sdk.DutyClient(n.rpc);
  await check(n, "tenzro_listDuties", { count: 0, duties: [] }, () => duty.list(), {});
  await check(n, "tenzro_getDuty", null, () => duty.get("0xd"), { duty_id: "0xd" });
  await check(n, "tenzro_verifyEvidence", { items: [] }, () => duty.verifyEvidence([]), { items: [] });

  const ins = new sdk.InsuranceClient(n.rpc);
  await check(n, "tenzro_listInsuranceClaims", { count: 0, claims: [] }, () => ins.listClaims(), {});
  await check(n, "tenzro_getInsuranceClaim", null, () => ins.getClaim("0xc"), { claim_id: "0xc" });
  await check(n, "tenzro_getInsurancePoolBalance", {}, () => ins.pool(), {});

  const snap = new sdk.SnapshotClient(n.rpc);
  await check(n, "tenzro_listSnapshots", { snapshots: [] }, () => snap.listSnapshots(), []);
  await check(n, "tenzro_getSnapshotManifest", { height: 1 }, () => snap.getSnapshotManifest(1), [{ height: 1 }]);
});

test("tokens, reserves, economics, gateway and payments", async () => {
  const n = node();
  const t = new sdk.TokenClient(n.rpc);
  await check(n, "tenzro_getToken", { symbol: "TNZO" }, () => t.getTokenInfo({ symbol: "TNZO" }), [{ symbol: "TNZO" }]);
  await check(n, "tenzro_listTokens", { count: 0, tokens: [] }, () => t.listTokens({ vm_type: "evm" }), [{ vm_type: "evm" }]);
  await check(n, "tenzro_canTransfer", { allowed: true }, () => t.canTransfer("0xt", ADDR, ADDR, 5n), [{ token_id: "0xt", from: ADDR, to: ADDR, amount: "5" }]);
  await check(n, "tenzro_getTokenBalance", { address: ADDR }, () => t.getTokenBalance(ADDR), { address: ADDR });
  assert.equal(n.last("tenzro_getTokenBalance").token, undefined);

  const r = new sdk.ReserveClient(n.rpc);
  await check(n, "tenzro_submitReserveAttestation", {}, () => r.submitReserveAttestation({ asset_id: "a" }), { attestation: { asset_id: "a" } });
  await check(n, "tenzro_getReserve", {}, () => r.getReserve("a"), { asset_id: "a" });
  await check(n, "tenzro_buildReserveAttestationFromPor", {}, () => r.buildReserveAttestationFromPor({ asset_id: "a", attestor_did: "did:x" }), { asset_id: "a", attestor_did: "did:x" });
  await check(n, "tenzro_readPorReserve", {}, () => r.readPorReserve({ asset_id: "a" }), { asset_id: "a" });
  await check(n, "tenzro_getReserveFeed", { feed: null }, () => r.getReserveFeed({ asset_id: "a" }), { asset_id: "a" });

  const u = new sdk.UrwaClient(n.rpc);
  await check(n, "tenzro_urwaIsKillSwitched", { active: false }, () => u.isKillSwitched("ab"), [{ token_id_hex: "ab" }]);
  await check(n, "tenzro_urwaGetFrozenTokens", {}, () => u.getFrozenTokens("ab", "cd"), [{ token_id_hex: "ab", account_hex: "cd" }]);

  const b = new sdk.AdaptiveBurnClient(n.rpc);
  await check(n, "tenzro_getBurnRateConfig", {}, () => b.getBurnRateConfig(), [{}]);
  await check(n, "tenzro_getEconomicPolicy", {}, () => b.getEconomicPolicy(), [{}]);
  await check(n, "tenzro_getSupplyMetrics", {}, () => b.getSupplyMetrics(), [{}]);
  await check(n, "tenzro_getBurnRateRecommendation", {}, () => b.getBurnRateRecommendation(), [{}]);
  await check(n, "tenzro_getFeeRate", {}, () => b.getFeeRate("ETH"), [{ symbol: "ETH" }]);
  await check(n, "tenzro_getEconomyMetrics", {}, () => b.getEconomyMetrics(2), [{ epoch: 2 }]);

  const dir = await check(n, "tenzro_listRpcMethods", { methods: [{ method: "tenzro_getBalance" }], count: 1 }, () => new sdk.GatewayClient(n.rpc).methods({ namespace: "tenzro" }), [{ namespace: "tenzro" }]);
  assert.equal(dir.methods[0].method, "tenzro_getBalance");
  await check(
    n,
    "tenzro_quotePayment",
    { usd_e6: 1, unit: { basket: "USD", version: 1 }, rate_epoch: null, assets: [{ asset: "TNZO", amount: "5", fee: "1", fee_asset: "TNZO", rate_epoch: null }] },
    () => new sdk.PaymentClient(n.rpc).quote({ price: { amount: "0.000001", unit: "USD" } }),
    { price: { amount: "0.000001", unit: "USD" } },
  );
  await check(n, "tenzro_agentVoucher", { voucher: {} }, () => new sdk.AuthClient(n.rpc).agentVoucher("0xch", "10"), { channel_id: "0xch", cumulative_amount: "10" });
});

test("a contract deploy signs only the payload it checked, and sends nothing when the node payload does not match", async () => {
  const n = node({ tenzro_getNonce: "0x2", eth_chainId: "0x20aa9", eth_gasPrice: "0x1", tenzro_getSigningPayload: { kind: "plain", tx_type_json: "{}" } });
  let signed = false;
  const signer = {
    p256PublicKey: () => new Uint8Array(64).fill(7),
    mlDsaPublicKey: () => null,
    signComposite: async () => {
      signed = true;
      return [new Uint8Array(64).fill(9), null];
    },
  };
  await assert.rejects(new sdk.ContractClient(n.rpc).deploy(signer, { code: new Uint8Array([0x60, 0x00]) }), /signing payload/);
  assert.equal(signed, false);
  assert.ok(n.sent.some((s) => s.method === "tenzro_getSigningPayload"));
  assert.ok(!n.sent.some((s) => s.method === "tenzro_deployContract"));
});
