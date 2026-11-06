// Identity, access, agents, payments, settlement, governance and bridge
// bindings: each one names the node's method and sends the params its handler
// reads (as the node sees them, a one-object array unwrapped), and returns
// what the node answered.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const sdk = require("../dist");

const ENDPOINT = "http://node.test";
const DID = "did:tenzro:human:aa";
const AGENT = "did:tenzro:machine:aa:bb";
const H32 = "ab".repeat(32);
const ADDR = "0x" + "03".repeat(32);

const u = (v, n, signed = false) => {
  const b = Buffer.alloc(n);
  if (signed) b.writeBigInt64LE(BigInt(v));
  else b.writeBigUInt64LE(BigInt(v));
  return b;
};
const unhex = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");

// The node's `plain` signing payload for a typed transaction.
function plainPayload(r) {
  const encoded = JSON.stringify(r.tx_type);
  const digest = crypto
    .createHash("sha256")
    .update(
      Buffer.concat([
        u(r.chain_id, 8),
        unhex(r.from),
        unhex(r.to),
        u(r.nonce, 8),
        u(r.gas_limit, 8),
        u(r.gas_price, 8),
        u(r.timestamp, 8, true),
        u(r.valid_until, 8, true),
        Buffer.from(encoded),
      ]),
    )
    .digest();
  return { kind: "plain", digest: digest.toString("hex"), tx_type_json: encoded };
}

const CHALLENGE = {
  challenge_id: "c1",
  challenge_hex: "0x" + "33".repeat(32),
  webauthn_challenge: "w",
  account_address: "0x" + "11".repeat(32),
  target_hex: "0x",
  nonce_hex: "0x" + "22".repeat(16),
  expires_in_secs: 60,
  delegation: { completed: true },
};

const DECODE_PREIMAGE = Buffer.from(JSON.stringify({ action: { Transfer: { amount: 1 } } }));

function answer(method, params) {
  switch (method) {
    case "tenzro_getBalance":
    case "tenzro_getNonce":
      return "0x5";
    case "eth_chainId":
      return "0x3444";
    case "eth_gasPrice":
      return "0x1";
    case "tenzro_getSigningPayload":
      return plainPayload(params);
    case "tenzro_createCustodyChallenge":
      return CHALLENGE;
    case "tenzro_setAccessPolicy":
      return { version: 3 };
    case "tenzro_listBridgeRoutes":
      return { total: 0, routes: [] };
    case "tenzro_listIdentities":
      return {
        human_count: 1,
        machine_count: 1,
        total_count: 2,
        truncated: false,
        identities: [
          { did: DID, type: "human" },
          { did: AGENT, type: "machine" },
        ],
      };
    case "tenzro_decodeAction":
      return {
        preimage_hex: DECODE_PREIMAGE.toString("hex"),
        digest: crypto.createHash("sha256").update(DECODE_PREIMAGE).digest("hex"),
      };
    default:
      return { answered: method };
  }
}

/** A node answering each call, recording what it was sent. */
function node() {
  const sent = [];
  const record = async (method, params) => {
    sent.push({ method, params });
    return answer(method, params);
  };
  return {
    sent,
    getEndpoint: () => ENDPOINT,
    getApiEndpoint: () => ENDPOINT,
    call: record,
    callWithProof: record,
  };
}

function signer() {
  return {
    p256PublicKey: () => new Uint8Array(64).fill(7),
    mlDsaPublicKey: () => null,
    signComposite: async () => [new Uint8Array(64).fill(9), null],
  };
}

/** What the node's dispatcher hands a handler: a one-object array unwrapped. */
function seen(params) {
  if (Array.isArray(params) && params.length === 1 && params[0] && typeof params[0] === "object" && !Array.isArray(params[0])) {
    return params[0];
  }
  return params;
}

const assertion = {
  credential_id: "Y3JlZA",
  authenticator_data_b64: "YQ",
  client_data_json_b64: "Yw",
  signature_b64: "cw",
};
const hex = (s) => Buffer.from(s).toString("hex");

// [method, call, the params the node reads (or a check of them)]
const CASES = [
  // Access
  ["tenzro_accessChallenge", (c) => c.access.challenge(DID, "jkt"), { did: DID, dpop_jkt: "jkt" }],
  [
    "tenzro_issueAccessToken",
    (c) => c.access.issue("c1", { kind: "device", public_key: "aa", signature: "bb" }),
    { challenge_id: "c1", proof: { kind: "device", public_key: "aa", signature: "bb" } },
  ],
  ["tenzro_getAccessPolicy", (c) => c.access.getPolicy(), {}],
  ["tenzro_setAccessPolicy", (c) => c.access.setPolicy("x = 1"), { toml: "x = 1" }],
  ["tenzro_previewAccess", (c) => c.access.preview("rpc", "tenzro_getBalance", DID), { surface: "rpc", method: "tenzro_getBalance", did: DID }],
  ["tenzro_listAccessTokens", (c) => c.access.listTokens(), {}],
  ["tenzro_revokeAccessToken", (c) => c.access.revokeToken("j1"), { jti: "j1" }],
  ["tenzro_listAdminAudit", (c) => c.access.auditLog({ method: "tenzro_stopModel", limit: 5 }), { method: "tenzro_stopModel", limit: 5 }],
  ["tenzro_verifyAdminAudit", (c) => c.access.verifyAuditLog(), {}],
  // Auth, onboarding and agents
  [
    "tenzro_onboardHuman",
    (c) => c.auth.onboardHuman("Alice", "cd", "07".repeat(64), async () => ({ ok: 1 })),
    { display_name: "Alice", credential_id: "cd", public_key: "07".repeat(64), authorization: { ok: 1 } },
  ],
  [
    "tenzro_onboardDelegatedAgent",
    (c) => c.auth.delegateAgent("0x11", { agent_name: "a" }, async () => ({ ok: 1 })),
    { delegation: { completed: true }, authorization: { ok: 1 } },
  ],
  ["tenzro_onboardAutonomousAgent", (c) => c.auth.onboardAutonomousAgent("04aa", "m1"), { device_public_key: "04aa", machine_id: "m1" }],
  ["tenzro_agentAct", (c) => c.auth.agentAct({ operation: "pay", counterparty: ADDR }), { operation: "pay", counterparty: ADDR }],
  ["tenzro_agentVoucher", (c) => c.auth.agentVoucher(H32, "10"), { channel_id: H32, cumulative_amount: "10" }],
  [
    "tenzro_updateAgentTerms",
    (c) => c.auth.updateAgentTerms("0x11", AGENT, { agent_name: "a" }, true, async () => ({ ok: 1 })),
    { agent_did: AGENT, delegation: { completed: true }, rotate_tokens: true, authorization: { ok: 1 } },
  ],
  [
    "tenzro_revokeIdentity",
    (c, s) => c.auth.revokeIdentity(s, "0x11", AGENT, async () => ({ root_public_key: [7], signature: { classical: {} } })),
    (p) => {
      assert.ok(p.public_key && p.signature, "signed");
      assert.equal(p.tx_type.RevokeIdentity.op.did, AGENT);
    },
  ],
  [
    "tenzro_refreshToken",
    (c) => c.auth.refreshToken("r1", { jkt: async () => "j", proof: async () => "p" }),
    { refresh_token: "r1" },
  ],
  ["tenzro_revokeJwt", (c) => c.auth.revokeJwt("j1", "ee", "lost"), { jti: "j1", did_envelope: "ee", reason: "lost" }],
  ["tenzro_forgetIdentity", (c) => c.auth.forgetIdentity(DID), { did: DID }],
  [
    "tenzro_exchangeToken",
    (c) => c.auth.exchangeToken("t", AGENT, "jkt", [], [], 60),
    { subject_token: "t", child_bearer_did: AGENT, child_dpop_jkt: "jkt", requested_rar: [], requested_aap_capabilities: [], requested_ttl_secs: 60 },
  ],
  ["tenzro_introspectToken", (c) => c.auth.introspectToken("t"), { token: "t" }],
  ["tenzro_oauthDiscovery", (c) => c.auth.oauthDiscovery(), []],
  // Passkeys and custody
  [
    "tenzro_enrollPasskey",
    (c) => c.passkey.enroll({ passkey_public_key_hex: "aa", credential_id_hex: "cd", authorization: { challenge_id: "c1" } }),
    { passkey_public_key_hex: "aa", credential_id_hex: "cd", authorization: { challenge_id: "c1" } },
  ],
  [
    "tenzro_createCustodyChallenge",
    (c) => c.device.challenge("bind_device", DID, "phone"),
    { account_address: hex(DID), operation: "bind_device", target_hex: hex("phone") },
  ],
  ["tenzro_createPasskeySession", (c) => c.passkey.createSession({ kind: "enroll", display_name: "A" }), { kind: "enroll", display_name: "A" }],
  ["tenzro_getPasskeySession", (c) => c.passkey.getSession("s1"), { session_id: "s1" }],
  // Identity
  [
    "tenzro_registerIdentity",
    (c) => c.identity.registerHuman({ displayName: "Alice", publicKey: "aa", credentialId: "cd", proof: { classical: {} } }),
    { identity_type: "human", display_name: "Alice", public_key: "aa", credential_id: "cd", proof: { classical: {} } },
  ],
  [
    "tenzro_registerMachineIdentity",
    (c, s) => c.identity.registerMachine({ controllerDid: DID, publicKey: "aa", capabilities: ["x"] }, s),
    (p) => {
      assert.equal(p.controller_did, DID);
      assert.deepEqual(p.capabilities, ["x"]);
      assert.equal(typeof p.did_envelope, "string");
    },
  ],
  ["tenzro_resolveIdentity", (c) => c.identity.resolve(DID), { did: DID }],
  ["tenzro_resolveDidDocument", (c) => c.identity.resolveDidDocument(DID), { did: DID }],
  ["tenzro_getDidServices", (c) => c.identity.didServices(DID), { did: DID }],
  ["tenzro_listIdentities", (c) => c.identity.listIdentities(), {}],
  ["tenzro_verifyDidEnvelope", (c) => c.identity.verifyDidEnvelope({ did: DID }), { envelope: { did: DID } }],
  ["tenzro_get7702Delegation", (c) => c.identity.get7702Delegation({ authority: "0x" + "01".repeat(20) }), { authority: "0x" + "01".repeat(20) }],
  ["tenzro_issueKyaCredential", (c) => c.identity.issueKyaCredential({ did: AGENT, validity_secs: 60 }), { did: AGENT, validity_secs: 60 }],
  ["tenzro_verifyKyaCredential", (c) => c.identity.verifyKyaCredential({ credential: { a: 1 } }), { credential: { a: 1 } }],
  ["tenzro_verifyNodeDidDocument", (c) => c.identity.verifyNodeDidDocument({ document: { id: DID } }), { document: { id: DID } }],
  [
    "tenzro_rotateIdentityToPq",
    (c) => c.identity.rotateIdentityToPq({ did: DID, new_pq_key: "aa", backend: "tpm", sequence: 1, authority_signature: "bb", new_key_signature: "cc" }),
    { did: DID, new_pq_key: "aa", backend: "tpm", sequence: 1, authority_signature: "bb", new_key_signature: "cc" },
  ],
  ["tenzro_updateIdentity", (c) => c.identity.updateIdentity({ did: DID, update: { kind: "resource" } }), { did: DID, update: { kind: "resource" } }],
  [
    "tenzro_mirrorSettlement",
    (c) => c.identity.mirrorSettlement({ interaction: { a: 1 }, targets: [], primary_committed: true }),
    { interaction: { a: 1 }, targets: [], primary_committed: true },
  ],
  // Devices
  [
    "tenzro_bindDevice",
    (c) =>
      c.device.bindDevice({
        identity_did: DID,
        label: "phone",
        attestation_object_b64: "YQ",
        client_data_json_b64: "Yw",
        challenge_id: "c1",
        authorization: assertion,
      }),
    { identity_did: DID, label: "phone", attestation_object_b64: "YQ", client_data_json_b64: "Yw", challenge_id: "c1", authorization: assertion },
  ],
  ["tenzro_listBoundDevices", (c) => c.device.listBoundDevices(DID), { identity_did: DID }],
  [
    "tenzro_revokeBoundDevice",
    (c) => c.device.revokeBoundDevice(DID, "Y3JlZA", "c1", assertion),
    { identity_did: DID, credential_id: "Y3JlZA", challenge_id: "c1", authorization: assertion },
  ],
  ["tenzro_walletReadiness", (c) => c.device.walletReadiness(DID), { identity_did: DID, this_device_credential_id: null }],
  [
    "tenzro_transferMachineOwnership",
    (c) => c.device.transferMachineOwnership(AGENT, DID, "c1", { kind: "machine_key", machineSignatureHex: "aa" }),
    { machine_did: AGENT, new_owner_did: DID, challenge_id: "c1", authority: "machine_key", machine_signature_hex: "aa" },
  ],
  ["tenzro_settlementNetworks", (c) => c.device.routePayment("100", "usdc", 5), { amount_wei: "100", asset: "usdc", tnzo_micro_usd: 5 }],
  // Keystore and machine access
  ["tenzro_getKeystore", (c) => c.keystore.getKeystore("0x" + "01".repeat(20)), { account: "0x" + "01".repeat(20) }],
  ["tenzro_resolveCredential", (c) => c.keystore.resolveCredential("cd", "tenzro.com"), { credential_id: "cd", rp_id: "tenzro.com" }],
  [
    "tenzro_addMachineAccess",
    (c) => c.machineAccess.add({ grantee_did: AGENT, resources: [], operations: ["read"], expires_at_ms: 1 }, { a: 1 }),
    { grantee_did: AGENT, resources: [], operations: ["read"], expires_at_ms: 1, authorization: { a: 1 } },
  ],
  ["tenzro_listMachineAccess", (c) => c.machineAccess.list({ a: 1 }), { authorization: { a: 1 } }],
  ["tenzro_revokeMachineAccess", (c) => c.machineAccess.revoke("g1", { a: 1 }), { grant_id: "g1", authorization: { a: 1 } }],
  // Wallet and transactions
  ["tenzro_getBalance", (c) => c.wallet.getBalance(ADDR), [ADDR]],
  ["tenzro_tokenBalance", (c) => c.wallet.getTokenBalance(ADDR), { address: ADDR }],
  ["tenzro_getNonce", (c) => c.wallet.getNonce(ADDR), [ADDR]],
  [
    "tenzro_getSigningPayload",
    (c, s) => c.tx.send(s, { kind: "Transfer", fields: { amount: 1 } }),
    (p) => assert.deepEqual(p.tx_type, { Transfer: { amount: 1 } }),
  ],
  [
    "tenzro_sendRawTransaction",
    (c, s) => c.tx.send(s, { kind: "Transfer", fields: { amount: 1 } }),
    (p) => {
      assert.equal(p.public_key, "07".repeat(64));
      assert.equal(p.chain_id, 13380);
      assert.equal(p.nonce, 5);
    },
  ],
  // Trust
  ["tenzro_submitTrustRecord", (c) => c.trust.submit({ a: 1 }), { record: { a: 1 } }],
  ["tenzro_verifyTrustCredential", (c) => c.trust.verifyCredential({ a: 1 }), { credential: { a: 1 } }],
  ["tenzro_getTrustCredentials", (c) => c.trust.credentials(DID), { subject: DID }],
  ["tenzro_getStatusList", (c) => c.trust.statusList(DID), { issuer: DID }],
  ["tenzro_getOperatorPolicy", (c) => c.trust.operatorPolicy(DID), { operator: DID }],
  ["tenzro_getModelProvenance", (c) => c.trust.modelProvenance("qwen", "a.gguf"), { name: "qwen", file: "a.gguf" }],
  ["tenzro_hostModel", (c) => c.trust.hostModel({ name: "qwen" }), { name: "qwen" }],
  ["tenzro_scanModelFiles", (c) => c.trust.scanModelFiles({ path: "/m" }), { path: "/m" }],
  ["tenzro_verifyModelFiles", (c) => c.trust.verifyModelFiles({ root: H32 }), { root: H32 }],
  [
    "tenzro_publishTeeMeasurement",
    (c) => c.trust.publishTeeMeasurement({ report: { a: 1 }, nonce: H32, publisher_key_hex: "04aa", signature_hex: "bb" }),
    { report: { a: 1 }, nonce: H32, publisher_key_hex: "04aa", signature_hex: "bb" },
  ],
  // Governance
  ["tenzro_listProposals", (c) => c.governance.listProposals({ limit: 5, kind: "policy_update" }), { limit: 5, kind: "policy_update" }],
  ["tenzro_getProposal", (c) => c.governance.getProposal(H32), (p) => assert.ok(typeof p.proposal_id === "string")],
  ["tenzro_getTreasuryAccounts", (c) => c.governance.getTreasuryAccounts(), {}],
  ["tenzro_getGuardianState", (c) => c.governance.getGuardianState(ADDR), { address: ADDR }],
  ["tenzro_getVotingPower", (c) => c.governance.getVotingPower(ADDR), { address: ADDR }],
  ["tenzro_getPolicy", (c) => c.governance.getPolicy("economic_policy"), { kind: "economic_policy" }],
  ["tenzro_getGovernanceReceipt", (c) => c.governance.getGovernanceReceipt(H32), { proposal_id: H32 }],
  [
    "tenzro_decodeAction",
    (c) => c.governance.decodeAction({ tx_type: { Transfer: { amount: 1 } } }),
    { transaction: { tx_type: { Transfer: { amount: 1 } } } },
  ],
  ["tenzro_getUpgradeReadiness", (c) => c.governance.getUpgradeReadiness(H32), { code_hash: H32 }],
  ["tenzro_getNetworkParams", (c) => c.governance.getNetworkParam("fee_bps"), { key: "fee_bps" }],
  ["tenzro_listLevers", (c) => c.governance.listLevers("bridge"), { area: "bridge" }],
  ["tenzro_signalUpgradeReady", (c) => c.validator.signalUpgradeReady({ code_hash: H32 }), { code_hash: H32 }],
  ["tenzro_getGrant", (c) => c.funding.getGrant("0x" + H32), { grant_id: H32 }],
  // Agents
  ["tenzro_discoverModels", (c) => c.agent.discoverModels({ modality: "text", servingOnly: true, query: "q" }), { modality: "text", serving_only: true, query: "q" }],
  ["tenzro_getAgentAuditCommit", (c) => c.agent.getAuditCommit("0xaa", 3), { committer: "0xaa", epoch: 3 }],
  ["tenzro_verifyAgentAuditAttestation", (c) => c.agent.verifyAuditAttestation("0xaa", 3), { committer: "0xaa", epoch: 3 }],
  ["tenzro_getAgentQuarantine", (c) => c.agent.getQuarantine(AGENT), { agent_did: AGENT }],
  ["tenzro_resolveAgentKey", (c) => c.agent.resolveAgentKey(AGENT, "k1"), { agent_did: AGENT, keyid: "k1" }],
  ["tenzro_getBridgeCircuit", (c) => c.agent.getBridgeCircuit("eip155:1", "ccip"), { source_chain: "eip155:1", adapter: "ccip" }],
  ["tenzro_exportEvidencePack", (c) => c.agent.exportEvidencePack({ agent_did: AGENT }), { agent_did: AGENT }],
  ["tenzro_flagAgentAudit", (c) => c.agent.flagAgentAudit({ epoch: 2, findings: [{ a: 1 }] }), { epoch: 2, findings: [{ a: 1 }] }],
  [
    "tenzro_recordAgentAuditSession",
    (c) => c.agent.recordAgentAuditSession({ session_id: H32, mmr_root: H32, count: 4 }),
    { session_id: H32, mmr_root: H32, count: 4 },
  ],
  ["tenzro_getKillSwitchReceipt", (c) => c.lifecycle.getKillSwitchReceipt(H32), { receipt_id: H32 }],
  ["tenzro_listKillSwitchByAgent", (c) => c.lifecycle.listKillSwitchByAgent(AGENT, "1:0:0"), { agent_did: AGENT, from_cursor: "1:0:0" }],
  ["tenzro_listKillSwitchByController", (c) => c.lifecycle.listKillSwitchByController(DID), { controller_did: DID }],
  ["tenzro_getAgentBond", (c) => c.bond.getAgentBond(AGENT), { agent_did: AGENT }],
  ["tenzro_listAgentBondsByController", (c) => c.bond.listAgentBondsByController(DID), { controller_did: DID }],
  ["tenzro_getAgentTerms", (c) => c.agentPayments.getTerms(AGENT), { agent_did: AGENT }],
  // Agent accounts on other chains
  ["tenzro_agentAccounts", (c) => c.accounts.accounts(AGENT), { did: AGENT }],
  ["tenzro_requestRemoteGrant", (c) => c.accounts.requestGrant("eip155:8453", { a: 1 }), { chain: "eip155:8453", grant: { a: 1 } }],
  ["tenzro_getAgentGrantProof", (c) => c.accounts.grantProof(AGENT, "eip155:8453", 2), { did: AGENT, chain: "eip155:8453", checkpoint: 2 }],
  ["tenzro_buildRemoteAction", (c) => c.accounts.buildAction(AGENT, "eip155:8453", 1, { a: 1 }), { did: AGENT, chain: "eip155:8453", nonce: 1, action: { a: 1 } }],
  [
    "tenzro_agentWalletConsent",
    (c) => c.accounts.walletConsent(AGENT, "eip155:8453", 7, "0x" + "01".repeat(20), 100),
    { did: AGENT, chain: "eip155:8453", agent_id: 7, owner: "0x" + "01".repeat(20), deadline: 100 },
  ],
  ["tenzro_signRemoteAction", (c) => c.accounts.signAction("eip155:8453", 1, { a: 1 }), { chain: "eip155:8453", nonce: 1, action: { a: 1 } }],
  [
    "tenzro_signRemoteChannelVoucher",
    (c) => c.accounts.signChannelVoucher("eip155:8453", 3, 10n),
    { chain: "eip155:8453", channel_id: 3, cumulative_amount: "10" },
  ],
  // Bridge
  ["tenzro_listBridgeRoutes", (c) => c.bridge.listRoutes(), {}],
  ["tenzro_getBridgeRoute", (c) => c.bridge.getRoute("ccip", "eip155:1"), { adapter: "ccip", source_chain: "eip155:1" }],
  ["tenzro_getBridgeOutbound", (c) => c.bridge.getOutbound("ccip", "eip155:1", 4), { adapter: "ccip", source_chain: "eip155:1", sequence: 4 }],
  ["tenzro_getBridgeOutflow", (c) => c.bridge.getOutflow(), {}],
  ["tenzro_getBridgeExit", (c) => c.bridge.getExit(9), { id: 9 }],
  [
    "tenzro_quoteBridgeFeeInTnzo",
    (c) => c.bridgeFee.quote({ adapter: "ccip", dest_chain: "eip155:1", native_fee_smallest_unit: "5" }),
    { adapter: "ccip", dest_chain: "eip155:1", native_fee_smallest_unit: "5" },
  ],
  // Payments
  [
    "tenzro_createPaymentChallenge",
    (c) => c.payment.createChallenge("/r", 5n, "TNZO", "x402"),
    { resource: "/r", amount: "5", asset: "TNZO", protocol: "x402" },
  ],
  ["tenzro_quotePayment", (c) => c.payment.quote({ usdE6: 1000, accept: ["TNZO"] }), { usd_e6: 1000, accept: ["TNZO"] }],
  ["tenzro_verifyPayment", (c) => c.payment.verifyPayment({ challenge_id: "c1" }), { credential: { challenge_id: "c1" } }],
  ["tenzro_getSettlementPreference", (c) => c.payment.getSettlementPreference({ payee_did: DID }), { payee_did: DID }],
  [
    "tenzro_setSettlementPreference",
    (c, s) => c.payment.setSettlementPreference(s, DID, "tnzo"),
    (p) => {
      assert.equal(p.payee_did, DID);
      assert.equal(p.asset, "tnzo");
      assert.equal(p.public_key, "07".repeat(64));
      assert.equal(p.signature.classical.form, "raw");
      assert.equal(typeof p.timestamp_ms, "number");
    },
  ],
  [
    "tenzro_updatePaymentChannel",
    (c) => c.payment.updatePaymentChannel({ voucher: { a: 1 }, charge: "5" }),
    { voucher: { a: 1 }, charge: "5" },
  ],
  [
    "tenzro_permit2VerifyAndConsume",
    (c) => c.permit2.verifyAndConsume({ owner: "0x01", signature: "0x02" }),
    { owner: "0x01", signature: "0x02" },
  ],
  ["tenzro_permit2NonceUsed", (c) => c.permit2.nonceUsed("0x01", "0x02"), { owner: "0x01", nonce: "0x02" }],
  // Settlement
  ["tenzro_settle", (c) => c.settlement.settle({ payee: ADDR, amount: "5", payment: { a: 1 } }), { payee: ADDR, amount: "5", payment: { a: 1 } }],
  ["tenzro_getPayment", (c) => c.settlement.getPayment({ pay_ref: H32 }), { pay_ref: H32 }],
  ["tenzro_listPayments", (c) => c.settlement.listPayments({ payee: ADDR, limit: 2 }), { payee: ADDR, limit: 2 }],
  ["tenzro_getPayeeSplit", (c) => c.settlement.getPayeeSplit(ADDR), { payee: ADDR }],
  ["tenzro_getEscrow", (c) => c.settlement.getEscrow(H32), { escrow_id: "0x" + H32 }],
  ["tenzro_listEscrowsByPayer", (c) => c.settlement.listEscrowsByPayer(ADDR, "1:0:0"), { payer: ADDR, from_cursor: "1:0:0" }],
  ["tenzro_listEscrowsByPayee", (c) => c.settlement.listEscrowsByPayee(ADDR), { payee: ADDR, from_cursor: undefined }],
  ["tenzro_openPaymentChannel", (c) => c.settlement.openPaymentChannel(H32), { channel_id: H32 }],
  [
    "tenzro_closePaymentChannel",
    (c, s) => c.settlement.closePaymentChannel(s, H32),
    (p) => {
      assert.equal(p.channel_id, H32);
      assert.equal(p.public_key, "07".repeat(64));
      assert.equal(p.signature.classical.form, "raw");
      assert.equal(typeof p.timestamp_ms, "number");
    },
  ],
  ["tenzro_getMeterBond", (c) => c.provider.getMeterBond(H32), { meter_id: H32 }],
  ["tenzro_redeemSealedDelivery", (c) => c.provider.redeemSealedDelivery({ escrow_id: H32 }), { escrow_id: H32 }],
  ["tenzro_previewSplit", (c) => c.settle.previewSplit(100n, { a: 1 }), { gross: "100", split: { a: 1 }, network_fees: "0" }],
  [
    "tenzro_submitReconciliation",
    (c) => c.settle.submitReconciliation("ccip", "eip155:1", [], "0xabcd"),
    { adapter: "ccip", chain: "eip155:1", entries: [], checkpoint: "abcd" },
  ],
  ["tenzro_getReconciliation", (c) => c.settle.getReconciliation("ccip", "eip155:1"), { adapter: "ccip", chain: "eip155:1" }],
  ["tenzro_listMismatches", (c) => c.settle.listMismatches("ccip", "eip155:1"), { adapter: "ccip", chain: "eip155:1" }],
  ["tenzro_getNettingBatch", (c) => c.settle.getNettingBatch(H32, { seq: 2 }), { asset: H32, seq: 2 }],
  ["tenzro_getPlan", (c) => c.settle.getPlan(H32), { plan_id: H32 }],
  ["tenzro_getPlanDecision", (c) => c.settle.getDecision(H32), { plan_id: H32 }],
  ["tenzro_getLegReceipt", (c) => c.settle.getLegReceipt(H32, 1), { plan_id: H32, index: 1 }],
  ["tenzro_listPlans", (c) => c.settle.listPlans({ status: "open", limit: 3 }), { status: "open", limit: 3 }],
];

function clients(rpc) {
  return {
    access: new sdk.AccessClient(rpc),
    auth: new sdk.AuthClient(rpc),
    passkey: new sdk.PasskeyRpcClient(rpc),
    identity: new sdk.IdentityClient(rpc),
    device: new sdk.DeviceClient(rpc),
    keystore: new sdk.KeystoreClient(rpc),
    machineAccess: new sdk.MachineAccessClient(rpc),
    wallet: new sdk.WalletClient(rpc),
    tx: new sdk.TypedTxClient(rpc),
    trust: new sdk.TrustClient(rpc),
    governance: new sdk.GovernanceClient(rpc),
    validator: new sdk.ValidatorClient(rpc),
    funding: new sdk.FundingClient(rpc),
    agent: new sdk.AgentClient(rpc),
    lifecycle: new sdk.LifecycleClient(rpc),
    bond: new sdk.BondClient(rpc),
    agentPayments: new sdk.AgentPaymentClient(rpc),
    accounts: new sdk.AgentAccountsClient(rpc),
    bridge: new sdk.BridgeClient(rpc),
    bridgeFee: new sdk.BridgeFeeClient(rpc),
    payment: new sdk.PaymentClient(rpc),
    permit2: new sdk.Permit2Client(rpc),
    settlement: new sdk.SettlementClient(rpc),
    provider: new sdk.ProviderClient(rpc),
    settle: new sdk.SettleClient(rpc),
  };
}

for (const [method, call, expected] of CASES) {
  test(`${method} sends the params the node reads`, async () => {
    const rpc = node();
    await call(clients(rpc), signer());
    const sent = rpc.sent.filter((r) => r.method === method);
    assert.ok(sent.length > 0, `${method} was not called (sent: ${rpc.sent.map((r) => r.method).join(", ")})`);
    const params = seen(sent[sent.length - 1].params);
    if (typeof expected === "function") expected(params);
    else assert.deepEqual(JSON.parse(JSON.stringify(params ?? null)), JSON.parse(JSON.stringify(expected)));
  });
}

test("a binding returns what the node answered", async () => {
  const rpc = node();
  const c = clients(rpc);
  assert.deepEqual(await c.access.verifyAuditLog(), { answered: "tenzro_verifyAdminAudit" });
  assert.equal(await c.access.setPolicy("x = 1"), 3);
  assert.equal(await c.wallet.getBalance(ADDR), 5n);
  const all = await c.identity.listIdentities();
  assert.equal(all.identities.length, 2);
  const humans = await c.identity.listIdentities("Human");
  assert.deepEqual(humans.identities.map((i) => i.did), [DID]);
});

test("the owner-signed close message is the node's", () => {
  const id = Buffer.from(H32, "hex");
  const m = Buffer.from(sdk.ownerRequestMessage("tenzro_closePaymentChannel", id, 1000));
  const want = Buffer.concat([
    Buffer.from("tenzro/rpc-owner/v1"),
    Buffer.from([0]),
    Buffer.from("tenzro_closePaymentChannel"),
    Buffer.from([0]),
    id,
    u(1000, 8, true),
  ]);
  assert.deepEqual(m, want);
});

test("every binding in the area is exercised", () => {
  assert.equal(new Set(CASES.map((c) => c[0])).size, CASES.length);
});
