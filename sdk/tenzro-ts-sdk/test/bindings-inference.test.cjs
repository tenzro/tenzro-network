// Every inference binding against a recording node: the method name and the
// params each one sends are the ones the node's handler reads, and the answer
// comes back decoded as documented.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist");

const ENDPOINT = "http://node.test";

/** A node answering each method from `answers`; anything else answers `{ ok: method }`. */
function node(answers = {}) {
  const sent = [];
  return {
    sent,
    getEndpoint: () => ENDPOINT,
    call: async (method, params) => {
      sent.push({ method, params });
      return method in answers ? answers[method] : { ok: method };
    },
  };
}

const MODEL = "qwen3-0.6b";
const ROUTING = { verification: "receipt", provider: "0xab" };

// [client, label, call, method, params, answer?, check?]
// `check(result, answer)` defaults to: the result is the answer unchanged.
const CASES = [
  // Provider: serving, roles, stats, bonds, endpoints, pricing, sealed models
  ["provider", "serveModel", (c) => c.serveModel(MODEL), "tenzro_serveModel", { model_id: MODEL }, {}, (r) => assert.equal(r, undefined)],
  ["provider", "serveModel with options", (c) => c.serveModel(MODEL, { visibility: "gated", maxConcurrent: 4, loadDrafter: false }), "tenzro_serveModel", { model_id: MODEL, visibility: "gated", max_concurrent: 4, load_drafter: false }, {}, (r) => assert.equal(r, undefined)],
  ["provider", "stopModel", (c) => c.stopModel(MODEL), "tenzro_stopModel", { model_id: MODEL }, {}, (r) => assert.equal(r, undefined)],
  ["provider", "deleteModel", (c) => c.deleteModel(MODEL), "tenzro_deleteModel", { model_id: MODEL }, {}, (r) => assert.equal(r, undefined)],
  ["provider", "chat", (c) => c.chat(MODEL, [{ role: "user", content: "hi" }]), "tenzro_chat", { model_id: MODEL, messages: [{ role: "user", content: "hi" }] },
    { model: MODEL, content: [{ type: "thinking", thinking: "x" }, { type: "text", text: "he" }, { type: "text", text: "llo" }], usage: { input_tokens: 3, output_tokens: 2 } },
    (r) => assert.deepEqual(r, { response: "hello", model_id: MODEL, tokens_used: 5 })],
  ["provider", "chatWith", (c) => c.chatWith(MODEL, [{ role: "user", content: "hi" }], { max_tokens: 8, draft_n: 2 }), "tenzro_chat", { model_id: MODEL, messages: [{ role: "user", content: "hi" }], max_tokens: 8, draft_n: 2 },
    { model: MODEL, content: [{ type: "text", text: "ok" }], usage: { input_tokens: 1, output_tokens: 1 } },
    (r) => assert.deepEqual(r, { response: "ok", model_id: MODEL, tokens_used: 2 })],
  ["provider", "getHardwareProfile", (c) => c.getHardwareProfile(), "tenzro_getHardwareProfile", []],
  ["provider", "setRoles", (c) => c.setRoles("validator,ai"), "tenzro_setRole", [{ roles: "validator,ai" }], {}, (r) => assert.equal(r, undefined)],
  ["provider", "getRoles", (c) => c.getRoles(), "tenzro_getRole", [], { roles: ["ai"], roles_str: "ai" }, (r) => assert.deepEqual(r, ["ai"])],
  ["provider", "stats", (c) => c.stats(), "tenzro_getProviderStats", {}],
  ["provider", "stats of an address", (c) => c.stats("0xab"), "tenzro_getProviderStats", { address: "0xab" },
    { address: "0xab", total_requests: 2, served_models: 1, role_stakes: [], utilization: "Active", total_revenue_wei: "7" }],
  ["provider", "previewServe", (c) => c.previewServe({ model_id: MODEL, quant: "q4_k_m", context_length: 4096, max_concurrent: 2 }), "tenzro_previewServe", { model_id: MODEL, quant: "q4_k_m", context_length: 4096, max_concurrent: 2 }],
  ["provider", "modelMetadata", (c) => c.modelMetadata(MODEL), "tenzro_modelMetadata", { model_id: MODEL }],
  ["provider", "computeBondParams", (c) => c.computeBondParams(), "tenzro_computeBondParams", [], { min_bond_wei: "1", cooldown_ms: 5 }],
  ["provider", "getComputeBond", (c) => c.getComputeBond("did:tenzro:machine:a"), "tenzro_getComputeBond", [{ provider_did: "did:tenzro:machine:a" }], null, (r) => assert.equal(r, null)],
  ["provider", "listComputeBonds", (c) => c.listComputeBonds(), "tenzro_listComputeBonds", [], { count: 1, bonds: [{ provider_did: "d" }] }, (r) => assert.deepEqual(r, [{ provider_did: "d" }])],
  ["provider", "listModelEndpoints", (c) => c.listModelEndpoints(), "tenzro_listModelEndpoints", [], []],
  ["provider", "listProviders", (c) => c.listProviders("ai"), "tenzro_listProviders", {},
    [{ provider_type: "ai", endpoint_id: "a" }, { provider_type: "tee", endpoint_id: "b" }],
    (r) => assert.deepEqual(r, [{ provider_type: "ai", endpoint_id: "a" }])],
  ["provider", "quoteInference", (c) => c.quoteInference(MODEL, { input_tokens: 800 }, "receipt"), "tenzro_quoteInference", { model: MODEL, units: { input_tokens: 800 }, verification: "receipt", provider: null }],
  ["provider", "joinAsMicroNode", (c) => c.joinAsMicroNode({ public_key: "04ab", credential_id: "cd" }, "alice"), "tenzro_joinAsMicroNode", { public_key: "04ab", credential_id: "cd", display_name: "alice" }],
  ["provider", "joinAsMicroNode as a machine", (c) => c.joinAsMicroNode({ public_key: "04ab", machine_id: "m1" }, undefined, "machine"), "tenzro_joinAsMicroNode", { public_key: "04ab", machine_id: "m1", participant_type: "machine" }],
  ["provider", "getModelStacks", (c) => c.getModelStacks(), "tenzro_getModelStacks", []],
  ["provider", "setProviderPricing", (c) => c.setProviderPricing({ default: { lines: {} } }), "tenzro_setProviderPricing", [{ default: { lines: {} } }]],
  ["provider", "getProviderPricing", (c) => c.getProviderPricing(), "tenzro_getProviderPricing", []],
  ["provider", "getModelEndpoint", (c) => c.getModelEndpoint("i1"), "tenzro_getModelEndpoint", [{ instance_id: "i1" }]],
  ["provider", "registerModelEndpoint", (c) => c.registerModelEndpoint(MODEL, "https://m.test/mcp", "Qwen", "p"), "tenzro_registerModelEndpoint", [{ model_id: MODEL, mcp_endpoint: "https://m.test/mcp", model_name: "Qwen", provider_name: "p" }]],
  ["provider", "unregisterModelEndpoint", (c) => c.unregisterModelEndpoint("i1"), "tenzro_unregisterModelEndpoint", [{ instance_id: "i1" }]],
  ["provider", "computeGetClaim", (c) => c.computeGetClaim({ claim_id: "0x01" }), "tenzro_computeGetClaim", { claim_id: "0x01" }],
  ["provider", "computeListClaims", (c) => c.computeListClaims({ party: "0xab", limit: 5 }), "tenzro_computeListClaims", { party: "0xab", limit: 5 }],
  ["provider", "computePriceFeed", (c) => c.computePriceFeed({ model_id: MODEL, region: "eu" }), "tenzro_computePriceFeed", { model_id: MODEL, region: "eu" }],
  ["provider", "getSealedModel", (c) => c.getSealedModel({ model_id: MODEL }), "tenzro_getSealedModel", { model_id: MODEL }],
  ["provider", "installSealedModel", (c) => c.installSealedModel({ recipient_did: "did:a", model_id: MODEL }), "tenzro_installSealedModel", { recipient_did: "did:a", model_id: MODEL }],
  ["provider", "listSealedModels", (c) => c.listSealedModels(), "tenzro_listSealedModels", undefined],
  ["provider", "modelRecipientKey", (c) => c.modelRecipientKey(), "tenzro_modelRecipientKey", undefined],
  ["provider", "sealModel", (c) => c.sealModel({ model_id: MODEL, path: "/m", owner_did: "did:o", recipients: [{ did: "did:r", recipient_key: "aa" }] }), "tenzro_sealModel", { model_id: MODEL, path: "/m", owner_did: "did:o", recipients: [{ did: "did:r", recipient_key: "aa" }] }],

  // Inference: models, requests, routing, usage, challenges, MoE
  ["inference", "listModels", (c) => c.listModels(), "tenzro_listModels", undefined, [{ id: MODEL }]],
  ["inference", "listLoadedModels", (c) => c.listLoadedModels(), "tenzro_listModels", [{ loaded: true }], { models: [] }],
  ["inference", "request", (c) => c.request(MODEL, "hi", 16), "tenzro_inferenceRequest", { model_id: MODEL, input: "hi", max_tokens: 16 },
    { model_id: MODEL, output: "x", input_tokens: 1, output_tokens: 1, cost_wei: "0", provider: "local" }],
  ["inference", "routeIntent", (c) => c.routeIntent({ useCase: "chat", budget: "cheap", maxP95Ms: 900 }), "tenzro_routeIntent", [{ use_case: "chat", budget: "cheap", max_p95_ms: 900 }]],
  ["inference", "chatByIntent", (c) => c.chatByIntent({ useCase: "chat", message: "hi" }), "tenzro_chatByIntent", [{ use_case: "chat", message: "hi" }]],
  ["inference", "recordRouteOutcome", (c) => c.recordRouteOutcome(MODEL, 3, "resolved"), "tenzro_recordRouteOutcome", [{ model_id: MODEL, cluster: 3, outcome: "resolved" }]],
  ["inference", "routeDifficultyStats", (c) => c.routeDifficultyStats(MODEL), "tenzro_routeDifficultyStats", [{ model_id: MODEL }]],
  ["inference", "routerMetrics", (c) => c.routerMetrics(), "tenzro_getRouterMetrics", undefined],
  ["inference", "getProvenance", (c) => c.getProvenance("ab"), "tenzro_getContentProvenance", [{ content_hash: "ab" }]],
  ["inference", "getGeneration", (c) => c.getGeneration("gen-1"), "tenzro_getGeneration", [{ id: "gen-1" }]],
  ["inference", "listInferenceUsage", (c) => c.listInferenceUsage({ modelId: MODEL }), "tenzro_listInferenceUsage", [{ model_id: MODEL }]],
  ["inference", "listTtsCatalog", (c) => c.listTtsCatalog(), "tenzro_listTtsCatalog", undefined],
  ["inference", "modelLifecycle", (c) => c.modelLifecycle({ model_id: MODEL }), "tenzro_modelLifecycle", { model_id: MODEL }],
  ["inference", "moeDisputeReceipt", (c) => c.moeDisputeReceipt({ key: "k" }), "tenzro_moeDisputeReceipt", { key: "k" }],
  ["inference", "moeListReceipts", (c) => c.moeListReceipts({ model_id: MODEL, limit: 2 }), "tenzro_moeListReceipts", { model_id: MODEL, limit: 2 }],
  ["inference", "moePrepareStatus", (c) => c.moePrepareStatus({ job_id: "j" }), "tenzro_moePrepareStatus", { job_id: "j" }],
  ["inference", "moeRoute", (c) => c.moeRoute({ model_id: MODEL, layer: 1, d_model: 8, hidden_states: "AAAA", top_k: 2 }), "tenzro_moeRoute", { model_id: MODEL, layer: 1, d_model: 8, hidden_states: "AAAA", top_k: 2 }],
  ["inference", "prefixProbe", (c) => c.prefixProbe({ digests: ["aa"] }), "tenzro_prefixProbe", { digests: ["aa"] }],

  // Multimodal: catalog, load, unload and the inference verb of each modality
  ["multimodal", "listForecastCatalog", (c) => c.listForecastCatalog(), "tenzro_listForecastCatalog", undefined, { models: [] }],
  ["multimodal", "loadForecastModel", (c) => c.loadForecastModel({ model_id: "chronos" }), "tenzro_loadForecastModel", [{ model_id: "chronos" }]],
  ["multimodal", "unloadForecastModel", (c) => c.unloadForecastModel("chronos"), "tenzro_unloadForecastModel", [{ model_id: "chronos" }]],
  ["multimodal", "forecast", (c) => c.forecast({ model_id: "chronos", history: [1, 2], horizon: 3, ...ROUTING }), "tenzro_forecast", [{ model_id: "chronos", history: [1, 2], horizon: 3, ...ROUTING }]],
  ["multimodal", "listVisionCatalog", (c) => c.listVisionCatalog(), "tenzro_listVisionCatalog", undefined, { models: [] }],
  ["multimodal", "loadVisionModel", (c) => c.loadVisionModel({ model_id: "clip" }), "tenzro_loadVisionModel", [{ model_id: "clip" }]],
  ["multimodal", "unloadVisionModel", (c) => c.unloadVisionModel("clip"), "tenzro_unloadVisionModel", [{ model_id: "clip" }]],
  ["multimodal", "imageEmbed", (c) => c.imageEmbed({ model_id: "clip", image_base64: "AA==" }), "tenzro_imageEmbed", [{ model_id: "clip", image_base64: "AA==" }]],
  ["multimodal", "imageTextSimilarity", (c) => c.imageTextSimilarity([1, 0], [0, 1]), "tenzro_imageTextSimilarity", [{ image_embedding: [1, 0], text_embedding: [0, 1] }], { similarity: 0, dim: 2 }],
  ["multimodal", "listTextEmbeddingCatalog", (c) => c.listTextEmbeddingCatalog(), "tenzro_listTextEmbeddingCatalog", undefined, { models: [] }],
  ["multimodal", "loadTextEmbeddingModel", (c) => c.loadTextEmbeddingModel({ model_id: "e5" }), "tenzro_loadTextEmbeddingModel", [{ model_id: "e5" }]],
  ["multimodal", "unloadTextEmbeddingModel", (c) => c.unloadTextEmbeddingModel("e5"), "tenzro_unloadTextEmbeddingModel", [{ model_id: "e5" }]],
  ["multimodal", "textEmbed", (c) => c.textEmbed({ model_id: "e5", inputs: ["a"] }), "tenzro_textEmbed", [{ model_id: "e5", inputs: ["a"] }]],
  ["multimodal", "listSegmentationCatalog", (c) => c.listSegmentationCatalog(), "tenzro_listSegmentationCatalog", undefined, { models: [] }],
  ["multimodal", "loadSegmentationModel", (c) => c.loadSegmentationModel({ model_id: "sam" }), "tenzro_loadSegmentationModel", [{ model_id: "sam" }]],
  ["multimodal", "unloadSegmentationModel", (c) => c.unloadSegmentationModel("sam"), "tenzro_unloadSegmentationModel", [{ model_id: "sam" }]],
  ["multimodal", "segment", (c) => c.segment({ model_id: "sam", image_base64: "AA==", prompts: [] }), "tenzro_segment", [{ model_id: "sam", image_base64: "AA==", prompts: [] }]],
  ["multimodal", "listTextSegmentationCatalog", (c) => c.listTextSegmentationCatalog(), "tenzro_listTextSegmentationCatalog", undefined, { models: [] }],
  ["multimodal", "loadTextSegmentationModel", (c) => c.loadTextSegmentationModel({ model_id: "sam3" }), "tenzro_loadTextSegmentationModel", [{ model_id: "sam3" }]],
  ["multimodal", "unloadTextSegmentationModel", (c) => c.unloadTextSegmentationModel("sam3"), "tenzro_unloadTextSegmentationModel", [{ model_id: "sam3" }]],
  ["multimodal", "textSegment", (c) => c.textSegment({ model_id: "sam3", image_base64: "AA==", text_prompt: "cat" }), "tenzro_textSegment", [{ model_id: "sam3", image_base64: "AA==", text_prompt: "cat" }]],
  ["multimodal", "listDetectionCatalog", (c) => c.listDetectionCatalog(), "tenzro_listDetectionCatalog", undefined, { models: [] }],
  ["multimodal", "loadDetectionModel", (c) => c.loadDetectionModel({ model_id: "rfdetr" }), "tenzro_loadDetectionModel", [{ model_id: "rfdetr" }]],
  ["multimodal", "unloadDetectionModel", (c) => c.unloadDetectionModel("rfdetr"), "tenzro_unloadDetectionModel", [{ model_id: "rfdetr" }]],
  ["multimodal", "detect", (c) => c.detect({ model_id: "rfdetr", image_base64: "AA==" }), "tenzro_detect", [{ model_id: "rfdetr", image_base64: "AA==" }],
    { detections: [{ bbox: [0, 0, 1, 1], label_id: 3, label: "car", score: 0.9 }], generation_time_ms: 4, cost_wei: "0" }],
  ["multimodal", "listDecisionCatalog", (c) => c.listDecisionCatalog(), "tenzro_listDecisionCatalog", undefined, { models: [] }],
  ["multimodal", "loadDecisionModel", (c) => c.loadDecisionModel({ model_id: "laya" }), "tenzro_loadDecisionModel", [{ model_id: "laya" }], { model_id: "laya", loaded: true }],
  ["multimodal", "unloadDecisionModel", (c) => c.unloadDecisionModel("laya"), "tenzro_unloadDecisionModel", [{ model_id: "laya" }], { model_id: "laya", removed: true }],
  ["multimodal", "decide", (c) => c.decide({ model_id: "laya", state: "hello", questions: [{ id: "spam", type: "noul", instructions: "Is it spam?" }] }), "tenzro_decide", [{ model_id: "laya", state: "hello", questions: [{ id: "spam", type: "noul", instructions: "Is it spam?" }] }], { answers: [] }],
  ["multimodal", "listRerankCatalog", (c) => c.listRerankCatalog(), "tenzro_listRerankCatalog", undefined, { models: [] }],
  ["multimodal", "loadRerankModel", (c) => c.loadRerankModel({ model_id: "bge" }), "tenzro_loadRerankModel", [{ model_id: "bge" }]],
  ["multimodal", "unloadRerankModel", (c) => c.unloadRerankModel("bge"), "tenzro_unloadRerankModel", [{ model_id: "bge" }]],
  ["multimodal", "rerank", (c) => c.rerank({ model_id: "bge", query: "q", documents: ["a", "b"], top_n: 1 }), "tenzro_rerank", [{ model_id: "bge", query: "q", documents: ["a", "b"], top_n: 1 }]],
  ["multimodal", "loadTrainingModel", (c) => c.loadTrainingModel(MODEL), "tenzro_loadTrainingModel", { model_id: MODEL }],
  ["multimodal", "unloadTrainingModel", (c) => c.unloadTrainingModel(MODEL), "tenzro_unloadTrainingModel", { model_id: MODEL }],
  ["multimodal", "trainRound", (c) => c.trainRound({ model_id: MODEL, recipe: { rank: 8 }, records: [{ prompt: "p", completion: "c" }], sample_seed: 1, steps: 2, adapter_seed: 3 }), "tenzro_trainRound",
    { model_id: MODEL, recipe: { rank: 8 }, records: [{ prompt: "p", completion: "c" }], sample_seed: 1, steps: 2, adapter_seed: 3 }],
  ["multimodal", "loadSpeechModel", (c) => c.loadSpeechModel({ model_id: "kokoro" }), "tenzro_loadSpeechModel", [{ model_id: "kokoro" }]],
  ["multimodal", "unloadSpeechModel", (c) => c.unloadSpeechModel("kokoro"), "tenzro_unloadSpeechModel", [{ model_id: "kokoro" }]],
  ["multimodal", "speak", (c) => c.speak({ model_id: "kokoro", input: "hello", seed: 1 }), "tenzro_speak", [{ model_id: "kokoro", input: "hello", seed: 1 }]],
  ["multimodal", "listAudioCatalog", (c) => c.listAudioCatalog(), "tenzro_listAudioCatalog", undefined, { models: [] }],
  ["multimodal", "loadAudioModel", (c) => c.loadAudioModel({ model_id: "whisper" }), "tenzro_loadAudioModel", [{ model_id: "whisper" }]],
  ["multimodal", "unloadAudioModel", (c) => c.unloadAudioModel("whisper"), "tenzro_unloadAudioModel", [{ model_id: "whisper" }]],
  ["multimodal", "transcribe", (c) => c.transcribe({ model_id: "whisper", audio_base64: "AA==" }), "tenzro_transcribe", [{ model_id: "whisper", audio_base64: "AA==" }]],
  ["multimodal", "listVideoCatalog", (c) => c.listVideoCatalog(), "tenzro_listVideoCatalog", undefined, { models: [] }],
  ["multimodal", "loadVideoModel", (c) => c.loadVideoModel({ model_id: "vjepa", vision_model_id: "clip", num_frames: 8 }), "tenzro_loadVideoModel", [{ model_id: "vjepa", vision_model_id: "clip", num_frames: 8 }]],
  ["multimodal", "unloadVideoModel", (c) => c.unloadVideoModel("vjepa"), "tenzro_unloadVideoModel", [{ model_id: "vjepa" }]],
  ["multimodal", "videoEmbed", (c) => c.videoEmbed({ model_id: "vjepa", video_base64: "AA==" }), "tenzro_videoEmbed", [{ model_id: "vjepa", video_base64: "AA==" }]],

  // Media generation
  ["mediaGen", "listCatalog", (c) => c.listCatalog(), "tenzro_mediaGen_listCatalog", [], { count: 0, models: [] }],
  ["mediaGen", "render", (c) => c.render("flux", "image", { prompt: "p" }, { verification: "receipt" }), "tenzro_mediaGen_render", [{ model_id: "flux", kind: "image", params: { prompt: "p" }, inputs_base64: [], verification: "receipt" }]],

  // Catalog and the price registry
  ["catalog", "list", (c) => c.list("praecise"), "tenzro_listCatalog", { engine: "praecise" }],
  ["catalog", "entry", (c) => c.entry(MODEL), "tenzro_getCatalogEntry", { model: MODEL }],
  ["catalog", "engineReleases", (c) => c.engineReleases(), "tenzro_getEngineReleases", {}],
  ["registry", "list", (c) => c.list("price-card", "a", 10), "tenzro_listRegistry", { kind: "price-card", after: "a", limit: 10 }],
  ["registry", "get", (c) => c.get("id-1", 2), "tenzro_getRegistryEntry", { id: "id-1", version: 2 }],
  ["registry", "priceCard", (c) => c.priceCard("0xab", MODEL), "tenzro_getPriceCard", { provider: "0xab", model_id: MODEL }],
  ["registry", "priceCardToPublish", (c) => c.priceCardToPublish("0xab", MODEL), "tenzro_priceCardToPublish", { provider: "0xab", model_id: MODEL }, { entry: null }],
  ["registry", "tnzoUsdNano", (c) => c.tnzoUsdNano(), "tenzro_getFeeRate", {}, { rate_nano_usd: "1500000000" }, (r) => assert.equal(r, 1500000000n)],

  // Verifiable inference: challenges and receipts
  ["trust", "auditInferenceChallenge", (c) => c.auditInferenceChallenge({ challenge_id: "c1" }), "tenzro_auditInferenceChallenge", { challenge_id: "c1" }],
  ["trust", "buildModelManifest", (c) => c.buildModelManifest({ name: MODEL }), "tenzro_buildModelManifest", { name: MODEL }],
  ["trust", "commitChallengeVote", (c) => c.commitChallengeVote({ challenge_id: "c1", voter: "v", commit_hash: "h", signature: "s" }), "tenzro_commitChallengeVote", { challenge_id: "c1", voter: "v", commit_hash: "h", signature: "s" }],
  ["trust", "fileInferenceChallenge", (c) => c.fileInferenceChallenge({ commitment_hash: "h", challenger: "0xab", reason: "r" }), "tenzro_fileInferenceChallenge", { commitment_hash: "h", challenger: "0xab", reason: "r" }],
  ["trust", "finalizeChallenge", (c) => c.finalizeChallenge({ challenge_id: "c1" }), "tenzro_finalizeChallenge", { challenge_id: "c1" }],
  ["trust", "getAttestationLog", (c) => c.getAttestationLog(), "tenzro_getAttestationLog", {}, { head: "00", entries: [] }],
  ["trust", "getInferenceChallenge", (c) => c.getInferenceChallenge({ challenge_id: "c1" }), "tenzro_getInferenceChallenge", { challenge_id: "c1" }],
  ["trust", "getInferenceCommitment", (c) => c.getInferenceCommitment({ commitment_hash: "h" }), "tenzro_getInferenceCommitment", { commitment_hash: "h" }],
  ["trust", "listInferenceChallenges", (c) => c.listInferenceChallenges({ status: "open" }), "tenzro_listInferenceChallenges", { status: "open" }],
  ["trust", "revealChallengeVote", (c) => c.revealChallengeVote({ challenge_id: "c1", voter: "v", verdict: true, salt: "s", signature: "g" }), "tenzro_revealChallengeVote", { challenge_id: "c1", voter: "v", verdict: true, salt: "s", signature: "g" }],
  ["trust", "signChallengeVote", (c) => c.signChallengeVote({ challenge_id: "c1", verdict: true, salt: "s" }), "tenzro_signChallengeVote", { challenge_id: "c1", verdict: true, salt: "s" }],
  ["trust", "verifyInferenceCommitment", (c) => c.verifyInferenceCommitment({ commitment_hash: "h", prompt: "p" }), "tenzro_verifyInferenceCommitment", { commitment_hash: "h", prompt: "p" }],
  ["trust", "verifyInferenceReceipt", (c) => c.verifyInferenceReceipt({ level: "tee", receipt: { model_id: MODEL } }), "tenzro_verifyInferenceReceipt", { level: "tee", receipt: { model_id: MODEL } }],

  // Node operator surface
  ["node", "loadMediaModel", (c) => c.loadMediaModel({ model_id: "flux" }), "tenzro_loadMediaModel", { model_id: "flux" }],
  ["node", "unloadMediaModel", (c) => c.unloadMediaModel({ model_id: "flux" }), "tenzro_unloadMediaModel", { model_id: "flux" }],
  ["node", "moeExecute", (c) => c.moeExecute({ model_id: MODEL, layer: 1, expert: 2, token_indices: [0], d_model: 8, hidden_states: "AAAA" }), "tenzro_moeExecute", { model_id: MODEL, layer: 1, expert: 2, token_indices: [0], d_model: 8, hidden_states: "AAAA" }],
  ["node", "moeExpertLoad", (c) => c.moeExpertLoad({ model_id: MODEL, layer: 1, expert: 2, uri: "tenzro://blob/aa" }), "tenzro_moeExpertLoad", { model_id: MODEL, layer: 1, expert: 2, uri: "tenzro://blob/aa" }],
  ["node", "moeExpertUnload", (c) => c.moeExpertUnload({ model_id: MODEL, layer: 1, expert: 2 }), "tenzro_moeExpertUnload", { model_id: MODEL, layer: 1, expert: 2 }],
  ["node", "moeGateLoad", (c) => c.moeGateLoad({ model_id: MODEL, layer: 1, blob_base64: "AA==" }), "tenzro_moeGateLoad", { model_id: MODEL, layer: 1, blob_base64: "AA==" }],
  ["node", "moeGateUnload", (c) => c.moeGateUnload({ model_id: MODEL, layer: 1 }), "tenzro_moeGateUnload", { model_id: MODEL, layer: 1 }],
  ["node", "pinModel", (c) => c.pinModel({ model_id: MODEL }), "tenzro_pinModel", { model_id: MODEL }],
  ["node", "unpinModel", (c) => c.unpinModel({ model_id: MODEL }), "tenzro_unpinModel", { model_id: MODEL }],
  ["node", "pruneModelRegistry", (c) => c.pruneModelRegistry(), "tenzro_pruneModelRegistry", undefined],
  ["identity", "joinAsMicroNode", (c) => c.joinAsMicroNode({ public_key: "04ab", machine_id: "m1", display_name: "edge" }), "tenzro_joinAsMicroNode", { public_key: "04ab", machine_id: "m1", display_name: "edge" }],
  ["payment", "getTerritoryPolicy", (c) => c.getTerritoryPolicy(), "tenzro_getTerritoryPolicy", undefined],
  ["adaptiveBurn", "getFeeRate", (c) => c.getFeeRate("ETH"), "tenzro_getFeeRate", [{ symbol: "ETH" }]],
  ["iroh", "fetchBlob", (c) => c.fetchBlob("tenzro://blob/aa"), "tenzro_iroh_fetchBlob", [{ tenzro_uri: "tenzro://blob/aa" }],
    { tenzro_uri: "tenzro://blob/aa", size_bytes: 3, bytes_b64: "AQID" }, (r) => assert.deepEqual(Array.from(r), [1, 2, 3])],
  ["umbrella", "nodeInfo", (c) => c.nodeInfo(), "tenzro_getNodeStatus", undefined, { state: "running", block_height: 7 }],
  ["umbrella", "sponsoredInference", (c) => c.sponsoredInference({ model: MODEL, input: "hi", sponsor: "did:tenzro:machine:s", max_tokens: 32 }), "tenzro_sponsoredInference", [{ model: MODEL, input: "hi", sponsor: "did:tenzro:machine:s", max_tokens: 32 }]],
];

const CLIENTS = {
  provider: (rpc) => new sdk.ProviderClient(rpc),
  inference: (rpc) => new sdk.InferenceClient(rpc),
  multimodal: (rpc) => new sdk.MultimodalClient(rpc),
  mediaGen: (rpc) => new sdk.MediaGenClient(rpc),
  catalog: (rpc) => new sdk.CatalogClient(rpc),
  registry: (rpc) => new sdk.RegistryClient(rpc),
  trust: (rpc) => new sdk.TrustClient(rpc),
  node: (rpc) => new sdk.NodeClient(rpc),
  identity: (rpc) => new sdk.IdentityClient(rpc),
  payment: (rpc) => new sdk.PaymentClient(rpc),
  adaptiveBurn: (rpc) => new sdk.AdaptiveBurnClient(rpc),
  iroh: (rpc) => new sdk.IrohClient(rpc),
  umbrella: (rpc) => {
    const c = new sdk.TenzroClient({ endpoint: ENDPOINT });
    c.rpc = rpc;
    return c;
  },
};

for (const [client, label, call, method, params, answer, check] of CASES) {
  test(`${client}.${label} calls ${method}`, async () => {
    const reply = answer === undefined ? { ok: method } : answer;
    const rpc = node({ [method]: reply });
    const result = await call(CLIENTS[client](rpc));
    assert.equal(rpc.sent.length, 1, `${label} made ${rpc.sent.length} calls`);
    assert.equal(rpc.sent[0].method, method);
    assert.deepEqual(rpc.sent[0].params, params);
    if (check) check(result, reply);
    else assert.deepEqual(result, reply);
  });
}

test("every inference method the node serves is covered here", () => {
  const covered = new Set(CASES.map((c) => c[3]));
  const expected = [
    "tenzro_auditInferenceChallenge", "tenzro_buildModelManifest", "tenzro_chat", "tenzro_chatByIntent",
    "tenzro_commitChallengeVote", "tenzro_computeBondParams", "tenzro_computeGetClaim", "tenzro_computeListClaims",
    "tenzro_computePriceFeed", "tenzro_decide", "tenzro_deleteModel", "tenzro_detect",
    "tenzro_fileInferenceChallenge", "tenzro_finalizeChallenge", "tenzro_forecast", "tenzro_getAttestationLog",
    "tenzro_getCatalogEntry", "tenzro_getComputeBond", "tenzro_getContentProvenance", "tenzro_getEngineReleases",
    "tenzro_getFeeRate", "tenzro_getGeneration", "tenzro_getHardwareProfile", "tenzro_getInferenceChallenge",
    "tenzro_getInferenceCommitment", "tenzro_getModelEndpoint", "tenzro_getModelStacks", "tenzro_getNodeStatus",
    "tenzro_getPriceCard", "tenzro_getProviderPricing", "tenzro_getProviderStats", "tenzro_getRegistryEntry",
    "tenzro_getRole", "tenzro_getRouterMetrics", "tenzro_getSealedModel", "tenzro_getTerritoryPolicy",
    "tenzro_imageEmbed", "tenzro_imageTextSimilarity", "tenzro_inferenceRequest", "tenzro_installSealedModel",
    "tenzro_iroh_fetchBlob", "tenzro_joinAsMicroNode", "tenzro_listAudioCatalog", "tenzro_listCatalog",
    "tenzro_listComputeBonds", "tenzro_listDecisionCatalog", "tenzro_listDetectionCatalog", "tenzro_listForecastCatalog",
    "tenzro_listInferenceChallenges", "tenzro_listInferenceUsage", "tenzro_listModelEndpoints", "tenzro_listModels",
    "tenzro_listProviders", "tenzro_listRegistry", "tenzro_listRerankCatalog", "tenzro_listSealedModels",
    "tenzro_listSegmentationCatalog", "tenzro_listTextEmbeddingCatalog", "tenzro_listTextSegmentationCatalog", "tenzro_listTtsCatalog",
    "tenzro_listVideoCatalog", "tenzro_listVisionCatalog", "tenzro_loadAudioModel", "tenzro_loadDecisionModel",
    "tenzro_loadDetectionModel", "tenzro_loadForecastModel", "tenzro_loadMediaModel", "tenzro_loadRerankModel",
    "tenzro_loadSegmentationModel", "tenzro_loadSpeechModel", "tenzro_loadTextEmbeddingModel", "tenzro_loadTextSegmentationModel",
    "tenzro_loadTrainingModel", "tenzro_loadVideoModel", "tenzro_loadVisionModel", "tenzro_mediaGen_listCatalog",
    "tenzro_mediaGen_render", "tenzro_modelLifecycle", "tenzro_modelMetadata", "tenzro_modelRecipientKey",
    "tenzro_moeDisputeReceipt", "tenzro_moeExecute", "tenzro_moeExpertLoad", "tenzro_moeExpertUnload",
    "tenzro_moeGateLoad", "tenzro_moeGateUnload", "tenzro_moeListReceipts", "tenzro_moePrepareStatus",
    "tenzro_moeRoute", "tenzro_pinModel", "tenzro_prefixProbe", "tenzro_previewServe",
    "tenzro_priceCardToPublish", "tenzro_sponsoredInference", "tenzro_pruneModelRegistry", "tenzro_quoteInference",
    "tenzro_recordRouteOutcome", "tenzro_registerModelEndpoint", "tenzro_rerank", "tenzro_revealChallengeVote",
    "tenzro_routeDifficultyStats", "tenzro_routeIntent", "tenzro_sealModel", "tenzro_segment",
    "tenzro_serveModel", "tenzro_setProviderPricing", "tenzro_setRole", "tenzro_signChallengeVote",
    "tenzro_speak", "tenzro_stopModel", "tenzro_textEmbed", "tenzro_textSegment",
    "tenzro_trainRound", "tenzro_transcribe", "tenzro_unloadAudioModel", "tenzro_unloadDecisionModel",
    "tenzro_unloadDetectionModel", "tenzro_unloadForecastModel", "tenzro_unloadMediaModel", "tenzro_unloadRerankModel",
    "tenzro_unloadSegmentationModel", "tenzro_unloadSpeechModel", "tenzro_unloadTextEmbeddingModel", "tenzro_unloadTextSegmentationModel",
    "tenzro_unloadTrainingModel", "tenzro_unloadVideoModel", "tenzro_unloadVisionModel", "tenzro_unpinModel",
    "tenzro_unregisterModelEndpoint", "tenzro_verifyInferenceCommitment", "tenzro_verifyInferenceReceipt", "tenzro_videoEmbed",
  ];
  assert.deepEqual(expected.filter((m) => !covered.has(m)), []);
});

test("a chat answer without content blocks is an error, not an empty reply", async () => {
  const rpc = node({ tenzro_chat: { model: MODEL } });
  await assert.rejects(new sdk.ProviderClient(rpc).chat(MODEL, []), /content/);
});
