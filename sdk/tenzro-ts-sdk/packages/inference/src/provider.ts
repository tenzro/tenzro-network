import { RpcClient } from "@tenzro/core";
import type { ToolCall } from "./chat";
import type { RateCard } from "./pricing";
import { ModelLoadInfo, ModelEndpoint } from "@tenzro/core";
import type { RoleStake } from "@tenzro/core";

/**
 * Who can find a resource and who may use it.
 *
 * A node has one visibility that applies to every resource it offers; a served
 * model may override it.
 *
 * - `public` — announced; any caller may invoke it by paying the operator's
 *   per-use price (free at 0), with no key, even on a node whose service-key
 *   gate is on.
 * - `gated` — announced as access-required; only callers the operator's
 *   access policy names may invoke it. There is no pay-per-use path.
 * - `private` — not announced; only the node's own callers may invoke it.
 */
export type ServeVisibility = "public" | "gated" | "private";

/** Placement and visibility options for {@link ProviderClient.serveModel}. */
export interface ServeOptions {
	/** Visibility override for this model. Omitted, it follows the node's visibility. */
	visibility?: ServeVisibility;
	/** Concurrent requests the operator admits for this model; omitted, the node sizes it. */
	maxConcurrent?: number;
	/** Load the model's catalog drafter for multi-token prediction; the node loads it unless this is false. */
	loadDrafter?: boolean;
}

/** `tenzro_getProviderStats`: measured performance, advertised capacity and role bonds of one provider. */
export interface ProviderStats {
	address: string;
	total_requests: number;
	successful: number;
	failed: number;
	avg_latency_ms: number;
	p95_latency_ms: number | null;
	uptime_percentage: number;
	reputation: number | null;
	inference_count: number;
	total_input_tokens: number;
	total_output_tokens: number;
	measured_tokens_per_sec: number | null;
	/** Revenue in wei, decimal string. */
	total_revenue_wei: string;
	last_inference_ms: number | null;
	max_concurrent: number;
	current_active: number;
	advertised_requests_per_second: number;
	/** How many models this node serves. */
	served_models: number;
	role_stakes: RoleStake[];
	/** `Active` or `Idle`. */
	utilization: string;
}

/** `tenzro_previewServe`: what serving a model would take on this node, without loading it. */
export interface PreviewServeParams {
	model_id: string;
	/** Quantization tier, e.g. `q4_k_m`. */
	quant?: string;
	context_length?: number;
	max_concurrent?: number;
}

/** The identity key a micro node's wallet is bound to: a passkey for a human, a secure element for a machine. */
export type MicroNodeIdentity =
	| { public_key: string; credential_id: string }
	| { public_key: string; machine_id: string };

/** The node's chat answer (content blocks, `model`, `usage`) as a {@link ChatResponse}. */
function chatResponse(result: unknown): ChatResponse {
	const r = (result ?? {}) as {
		content?: Array<{ type?: string; text?: string }>;
		model?: string;
		usage?: { input_tokens?: number; output_tokens?: number };
	};
	if (!Array.isArray(r.content)) {
		throw new Error(`chat response missing 'content' blocks: ${JSON.stringify(result)}`);
	}
	return {
		response: r.content
			.filter((b) => b.type === "text" && typeof b.text === "string")
			.map((b) => b.text as string)
			.join(""),
		model_id: r.model ?? "",
		tokens_used: (r.usage?.input_tokens ?? 0) + (r.usage?.output_tokens ?? 0),
	};
}

/**
 * A provider's compute bond — the admission collateral `register` checks
 * before it will accept a provider onto a rung.
 */
export interface ComputeBond {
	provider_did: string;
	provider_address: string;
	/** Bonded amount in wei (10^-18 TNZO) as a decimal string. */
	amount: string;
	/** "Active", "Cooldown", "Returned", or "Slashed". */
	status: string;
	/** Unix ms at which a withdrawal may be finalized; null unless in Cooldown. */
	cooldown_until: number | null;
	/** The bond vault address, hex. */
	vault: string;
	/** Whether this bond can currently back a provider registration. */
	is_eligible: boolean;
	/** Amount counting toward admission in wei — zero once the bond leaves Active. */
	effective_amount: string;
}

/** The admission dials a provider needs before it posts a compute bond. */
export interface ComputeBondParams {
	/**
	 * Minimum bond in wei the node accepts for admission. The operative
	 * requirement is the higher of this floor and the target rung's own bond.
	 */
	min_bond_wei: string;
	/** Milliseconds a withdrawal sits in Cooldown before it can be finalized. */
	cooldown_ms: number;
}

export interface ChatMessage {
	/** `system`, `user`, `assistant` or `tool`. */
	role: string;
	content: string;
	/** Calls an assistant turn made, echoed back in history. */
	tool_calls?: ToolCall[];
	/** On a `tool` turn, the id of the call this message answers. */
	tool_call_id?: string;
}

export interface ChatResponse {
	response: string;
	model_id: string;
	tokens_used: number;
}

/**
 * Optional generation knobs for {@link ProviderClient.chatWith}.
 *
 * MTP throughput uplift requires the target model to declare a
 * drafter in its catalog entry (`HfModelEntry.drafter_id` +
 * `mtp_kind`). Gemma 4 12B and 31B currently advertise this. When
 * `draft_n` is set on a model whose runtime cannot satisfy it,
 * the node returns a structured `MtpUnavailable` error.
 */
export interface ChatOptions {
	/** Sampling temperature (0.0..=2.0). Default: 0.7. */
	temperature?: number;
	/** Top-p nucleus-sampling threshold. Default: 0.9. */
	top_p?: number;
	/** Maximum new tokens to generate. Default: 512. */
	max_tokens?: number;
	/**
	 * Multi-Token-Prediction draft count (1..=6). Only meaningful on
	 * MTP-eligible models. Unsloth recommends 2 as a starting point on
	 * Gemma 4; optimal value is hardware-dependent.
	 */
	draft_n?: number;
}

/**
 * Accelerator vendor as reported by the node's hardware probe. Drives the
 * compute-capability interpretation and the FP8/FP4 derivation rules.
 */
export type GpuVendor = "Nvidia" | "Amd" | "Apple" | "Other";

/**
 * A single accelerator discovered by the node's hardware probe. A node may
 * expose more than one, so `HardwareProfile.gpus` is an array.
 */
export interface GpuDevice {
	/** Accelerator vendor. */
	vendor: GpuVendor;
	/** Device marketing name (e.g. "NVIDIA H100 80GB HBM3", "Apple M3 Max"). */
	name: string;
	/** Device memory in GiB (unified-memory budget on Apple Silicon). */
	vram_gb: number;
	/** Vendor-native compute-capability string: SM version for NVIDIA, gfx
	 * target for AMD, "metal" for Apple. Empty when the probe could not read it. */
	compute_capability: string;
	/** Hardware FP8 matrix/tensor units present. */
	fp8: boolean;
	/** Hardware FP4 matrix/tensor units present. */
	fp4: boolean;
}

export interface HardwareProfile {
	cpu_model: string;
	cpu_cores: number;
	cpu_threads: number;
	total_ram_gb: number;
	/** Every accelerator the node detected. Empty on a CPU-only node. */
	gpus: GpuDevice[];
	storage_available_gb: number;
	tee_available: boolean;
	/** TEE vendor string when `tee_available` (e.g. "Intel TDX"), else null. */
	tee_vendor: string | null;
	os: string;
	arch: string;
	/** Hash of the hardware's descriptive attributes — identifies a hardware
	 * class, not an individual unit. */
	device_fingerprint: string;
	/** Hex SHA-256 over the machine's per-unit hardware identifiers (SMBIOS
	 * system UUID, baseboard serial, NVIDIA GPU UUIDs). Null when the node can
	 * read none of them. */
	hardware_root: string | null;
	/** Labels of the identifier sources behind `hardware_root`, e.g.
	 * `["dmi:product_uuid", "gpu:uuid"]`. Never carries serial values. */
	hardware_root_sources: string[];
}

/**
 * A provider discovered on the Tenzro Network via gossipsub announcements.
 *
 * Providers broadcast a `ProviderAnnouncement` every 60 seconds on the
 * `tenzro/providers` gossipsub topic. All peers merge incoming
 * announcements into their `network_providers` cache so any node can
 * discover every provider without a central registry.
 *
 * Use {@link ProviderClient.listProviders} to discover providers via
 * the `tenzro_listProviders` JSON-RPC method.
 */
export interface NetworkProvider {
	/** iroh endpoint id of the announcing node */
	endpoint_id: string;
	/** Wallet/account address of the provider */
	provider_address: string;
	/**
	 * Provider class: "ai", "tee", "storage", "compute", "general".
	 *
	 * "ai" covers every model class — text, multimodal, image, video,
	 * audio, embeddings.
	 */
	provider_type: string;
	/** Model IDs currently being served by this node */
	served_models: string[];
	/** Capability labels (e.g. "inference", "tee-attestation") */
	capabilities: string[];
	/** Lifecycle status (e.g. "active", "draining") */
	status: string;
	/** Whether this is the local node */
	is_local: boolean;
	/** Coarse region: a country code or a wide region; null when undeclared */
	region?: string | null;
	/** Declared jurisdiction (ISO 3166-1 alpha-2) */
	jurisdiction?: string | null;
	/** Live load of each served model */
	model_load?: ProviderModelLoad[] | null;
	/** When the load was read, ms since the Unix epoch */
	load_as_of_ms?: number | null;
}

/** The live load of one model at a provider, as listProviders reports it. */
export interface ProviderModelLoad {
	model_id: string;
	state: "cold" | "warming" | "warm" | "evicting";
	/** Requests admitted and not yet finished */
	in_flight: number;
	/** Most requests it admits at once */
	max_concurrent: number;
	/** Requests waiting for it to finish loading */
	queue_depth: number;
	/** Estimated time until it is loaded, ms, while warming */
	warm_eta_ms: number | null;
}

/**
 * Client for provider operations including network participation,
 * model serving, and hardware management.
 */
export class ProviderClient {
	private rpc: RpcClient;

	constructor(rpc: RpcClient) {
		this.rpc = rpc;
	}

	/**
	 * Start serving a model on the network.
	 *
	 * When a model is too large for a single host, the node auto-clusters: it
	 * reads the GGUF header for layer count and hidden dimension, discovers LAN
	 * members from gossiped cluster announcements, and runs a layer-wise
	 * pipeline across them. No extra options are required — the node decides
	 * single-host vs. cluster from the model shape and the reachable members.
	 *
	 * Pass `opts` to set:
	 * - `visibility`: `"public"`, `"gated"` or `"private"` for this model.
	 *   Omitted, the model follows the node's visibility.
	 * - `maxConcurrent`: the concurrent requests admitted for this model.
	 * - `loadDrafter`: `false` skips loading the catalog drafter for
	 *   multi-token prediction.
	 *
	 * Use {@link Discovery.clusterPlan} to preview the layer split and
	 * {@link ProviderClient.previewServe} to preview the memory it takes.
	 *
	 * @param modelId - ID of the model to serve
	 * @param opts - Optional visibility and concurrency settings
	 *
	 * @example
	 * ```typescript
	 * await client.provider.serveModel("gemma4-9b");
	 * console.log("Now serving model");
	 * ```
	 */
	async serveModel(modelId: string, opts: ServeOptions = {}): Promise<void> {
		const params: Record<string, unknown> = { model_id: modelId };
		if (opts.visibility) params.visibility = opts.visibility;
		if (opts.maxConcurrent !== undefined) params.max_concurrent = opts.maxConcurrent;
		if (opts.loadDrafter !== undefined) params.load_drafter = opts.loadDrafter;
		await this.rpc.call("tenzro_serveModel", params);
	}

	/**
	 * Stop serving a model
	 *
	 * @param modelId - ID of the model to stop serving
	 *
	 * @example
	 * ```typescript
	 * await client.provider.stopModel("gemma4-9b");
	 * console.log("Stopped serving model");
	 * ```
	 */
	async stopModel(modelId: string): Promise<void> {
		await this.rpc.call("tenzro_stopModel", { model_id: modelId });
	}

	/**
	 * Delete a downloaded model
	 *
	 * @param modelId - ID of the model to delete
	 *
	 * @example
	 * ```typescript
	 * await client.provider.deleteModel("gemma4-9b");
	 * console.log("Model deleted");
	 * ```
	 */
	async deleteModel(modelId: string): Promise<void> {
		await this.rpc.call("tenzro_deleteModel", { model_id: modelId });
	}

	/**
	 * Chat with a loaded model
	 *
	 * @param modelId - ID of the model to use
	 * @param messages - Array of chat messages
	 * @returns Chat completion response
	 *
	 * @example
	 * ```typescript
	 * const messages = [
	 *   { role: "user", content: "What is Tenzro Network?" }
	 * ];
	 * const response = await client.provider.chat("gemma4-9b", messages);
	 * console.log("Response:", response.response);
	 * ```
	 */
	async chat(modelId: string, messages: ChatMessage[]): Promise<ChatResponse> {
		return chatResponse(
			await this.rpc.call("tenzro_chat", { model_id: modelId, messages }),
		);
	}

	/**
	 * Send a chat completion with generation options. Use this when
	 * you need to pass {@link ChatOptions} (Multi-Token Prediction
	 * `draft_n`, `max_tokens`, `temperature`, `top_p`, etc.).
	 *
	 * @example
	 * ```typescript
	 * const response = await client.provider.chatWith(
	 *   "gemma4-12b",
	 *   [{ role: "user", content: "..." }],
	 *   { draft_n: 2, max_tokens: 256 },
	 * );
	 * ```
	 */
	async chatWith(
		modelId: string,
		messages: ChatMessage[],
		opts: ChatOptions = {},
	): Promise<ChatResponse> {
		const params: Record<string, unknown> = {
			model_id: modelId,
			messages,
		};
		if (opts.temperature !== undefined) params.temperature = opts.temperature;
		if (opts.top_p !== undefined) params.top_p = opts.top_p;
		if (opts.max_tokens !== undefined) params.max_tokens = opts.max_tokens;
		if (opts.draft_n !== undefined) params.draft_n = opts.draft_n;
		return chatResponse(await this.rpc.call("tenzro_chat", params));
	}

	/**
	 * Get hardware profile of the node
	 *
	 * @returns Hardware profile with CPU, memory, accelerators, and TEE support
	 *
	 * @example
	 * ```typescript
	 * const profile = await client.provider.getHardwareProfile();
	 * console.log("CPU:", profile.cpu_model);
	 * console.log("Memory:", profile.total_ram_gb, "GB");
	 * for (const gpu of profile.gpus) {
	 *   console.log(gpu.vendor, gpu.name, `${gpu.vram_gb} GiB`);
	 * }
	 * ```
	 */
	async getHardwareProfile(): Promise<HardwareProfile> {
		return await this.rpc.call<HardwareProfile>(
			"tenzro_getHardwareProfile",
			[],
		);
	}

	/**
	 * Set this node's active roles. One stake backs every role.
	 *
	 * @param roles - Comma-separated role tokens: `validator`, `ai`, `storage`,
	 *   `tee`, `user`. The empty string resolves to a client node.
	 *
	 * @example
	 * ```typescript
	 * await client.provider.setRoles("validator,storage,ai");
	 * console.log("Roles updated");
	 * ```
	 */
	async setRoles(roles: string): Promise<void> {
		await this.rpc.call("tenzro_setRole", [{ roles }]);
	}

	/**
	 * Get this node's active roles (normalized role-token strings).
	 */
	async getRoles(): Promise<string[]> {
		const result = await this.rpc.call<{ roles?: string[] }>(
			"tenzro_getRole",
			[],
		);
		return result.roles ?? [];
	}

	/**
	 * Get provider statistics
	 *
	 * @returns Provider statistics with serving state and inference count
	 *
	 * @example
	 * ```typescript
	 * const stats = await client.provider.stats();
	 * console.log("Requests:", stats.total_requests, "served models:", stats.served_models);
	 * ```
	 *
	 * @param address - The provider to read; omitted, this node's own wallet.
	 */
	async stats(address?: string): Promise<ProviderStats> {
		return await this.rpc.call<ProviderStats>(
			"tenzro_getProviderStats",
			address === undefined ? {} : { address },
		);
	}

	/**
	 * What serving `model_id` would take on this node (memory, quantization,
	 * context and concurrency), without loading it.
	 */
	async previewServe(params: PreviewServeParams): Promise<Record<string, unknown>> {
		return await this.rpc.call<Record<string, unknown>>("tenzro_previewServe", { ...params });
	}

	/**
	 * A catalog model's architecture and serving metadata: mixture-of-experts
	 * shape, drafter, multimodal projector and the recommended sampler.
	 */
	async modelMetadata(modelId: string): Promise<Record<string, unknown>> {
		return await this.rpc.call<Record<string, unknown>>("tenzro_modelMetadata", { model_id: modelId });
	}

	/**
	 * Read the compute-bond floor and withdrawal cooldown this node enforces.
	 *
	 * Call this before {@link register} — a registration whose backing bond is
	 * below the floor is refused at admission.
	 *
	 * @example
	 * ```typescript
	 * const params = await client.provider.computeBondParams();
	 * console.log("Minimum bond:", params.min_bond_wei, "wei");
	 * ```
	 */
	async computeBondParams(): Promise<ComputeBondParams> {
		return await this.rpc.call<ComputeBondParams>(
			"tenzro_computeBondParams",
			[],
		);
	}

	/**
	 * Fetch the compute bond posted against `providerDid`, or null when that
	 * provider has never posted one.
	 *
	 * @param providerDid - Provider DID (e.g. "did:tenzro:machine:...")
	 */
	async getComputeBond(providerDid: string): Promise<ComputeBond | null> {
		return await this.rpc.call<ComputeBond | null>("tenzro_getComputeBond", [
			{ provider_did: providerDid },
		]);
	}

	/** List every compute bond this node knows about. */
	async listComputeBonds(): Promise<ComputeBond[]> {
		const result = await this.rpc.call<{ count: number; bonds: ComputeBond[] }>(
			"tenzro_listComputeBonds",
			[],
		);
		return result.bonds ?? [];
	}

	/**
	 * List all model service endpoints with load information
	 *
	 * @returns Array of model endpoints with load data
	 *
	 * @example
	 * ```typescript
	 * const endpoints = await client.provider.listModelEndpoints();
	 * for (const ep of endpoints) {
	 *   console.log(`${ep.model_name}: ${ep.status} (${ep.location})`);
	 *   if (ep.load) {
	 *     console.log(`  Load: ${ep.load.active_requests}/${ep.load.max_concurrent} (${ep.load.utilization_percent}%)`);
	 *   }
	 * }
	 * ```
	 */
	async listModelEndpoints(): Promise<ModelEndpoint[]> {
		return await this.rpc.call<ModelEndpoint[]>(
			"tenzro_listModelEndpoints",
			[],
		);
	}

	/**
	 * Get load information for a specific model
	 *
	 * @param modelId - ID of the model to check
	 * @returns Load info if the model is being served, undefined otherwise
	 *
	 * @example
	 * ```typescript
	 * const load = await client.provider.getModelLoad("gemma3-270m");
	 * if (load) {
	 *   console.log(`Load: ${load.active_requests}/${load.max_concurrent} (${load.utilization_percent}%)`);
	 * }
	 * ```
	 */
	async getModelLoad(modelId: string): Promise<ModelLoadInfo | undefined> {
		const endpoints = await this.listModelEndpoints();
		const ep = endpoints.find(
			(e) => e.model_id === modelId || e.model_name === modelId,
		);
		return ep?.load;
	}

	/**
	 * List all providers discovered on the Tenzro Network.
	 *
	 * Queries the `tenzro_listProviders` JSON-RPC method which merges:
	 * - The local node's own provider info (if it is serving models)
	 * - All remote providers discovered via the `tenzro/providers`
	 *   gossipsub topic (announcements refreshed every 60 seconds)
	 *
	 * @param providerType - Optional filter by provider class (e.g. "ai",
	 * "tee", "storage"), applied to the node's full list.
	 * @returns Array of discovered network providers
	 *
	 * @example
	 * ```typescript
	 * // List all providers
	 * const providers = await client.provider.listProviders();
	 * for (const p of providers) {
	 *   console.log(`${p.endpoint_id}:${p.provider_type} — models: ${p.served_models.join(", ")}`);
	 * }
	 *
	 * // List only model providers
	 * const aiProviders = await client.provider.listProviders("ai");
	 * ```
	 */
	async listProviders(providerType?: string): Promise<NetworkProvider[]> {
		const all = await this.rpc.call<NetworkProvider[]>("tenzro_listProviders", {});
		return providerType === undefined
			? all
			: all.filter((p) => p.provider_type === providerType);
	}

	/**
	 * Price one request for `model` at every provider serving it, cheapest
	 * first, on each provider's announced rate card plus the governed
	 * surcharge for the verification level.
	 * @param units - Billable units, e.g. `{ input_tokens: 800, output_tokens: 200 }`
	 * @param verification - none, receipt, optimistic or tee
	 */
	async quoteInference(
		model: string,
		units: Record<string, number>,
		verification: "none" | "receipt" | "optimistic" | "tee" = "none",
		provider?: string,
	): Promise<unknown> {
		return await this.rpc.call("tenzro_quoteInference", {
			model,
			units,
			verification,
			provider: provider ?? null,
		});
	}

	/**
	 * Join the network as a micro node. The wallet is bound to the caller's
	 * identity key: the node never mints one.
	 * @param identity - The P-256 public key (x || y, hex) with the passkey
	 *   credential id of a human, or the machine id of a secure-element key
	 * @param displayName - Optional display name for the node
	 * @param participantType - Optional participant type
	 * @returns Micro node registration response
	 */
	async joinAsMicroNode(
		identity: MicroNodeIdentity,
		displayName?: string,
		participantType?: string,
	): Promise<any> {
		const params: Record<string, unknown> = { ...identity };
		if (displayName !== undefined) params.display_name = displayName;
		if (participantType !== undefined) params.participant_type = participantType;
		return await this.rpc.call("tenzro_joinAsMicroNode", params);
	}

	/**
	 * Get the node's model stacks: the stack serving now and until when, the
	 * next stack and when it starts, and every configured stack.
	 * @returns `{ active, next, stacks, node_time }`
	 */
	async getModelStacks(): Promise<any> {
		return await this.rpc.call("tenzro_getModelStacks", []);
	}

	/**
	 * Set this node's price cards: a default card and per-model cards. Operator only.
	 * @param pricing - `{ default: RateCard, models?: { [modelId]: RateCard } }`
	 * @returns The cards now in force
	 */
	async setProviderPricing(pricing: { default: RateCard; models?: Record<string, RateCard> }): Promise<any> {
		return await this.rpc.call("tenzro_setProviderPricing", [pricing]);
	}

	/**
	 * Get this node's price cards.
	 * @returns `{ default: RateCard, models: { [modelId]: RateCard } }`
	 */
	async getProviderPricing(): Promise<any> {
		return await this.rpc.call("tenzro_getProviderPricing", []);
	}

	/**
	 * Get a specific model endpoint.
	 * @param instanceId - The model endpoint instance ID
	 * @returns Model endpoint details
	 */
	async getModelEndpoint(instanceId: string): Promise<any> {
		return await this.rpc.call("tenzro_getModelEndpoint", [
			{ instance_id: instanceId },
		]);
	}

	/**
	 * Register a remote model endpoint.
	 * @param modelId - ID of the model
	 * @param mcpEndpoint - Optional MCP endpoint URL
	 * @param modelName - Optional human-readable model name
	 * @param providerName - Optional provider name
	 * @returns Registration result
	 */
	async registerModelEndpoint(
		modelId: string,
		mcpEndpoint?: string,
		modelName?: string,
		providerName?: string,
	): Promise<any> {
		return await this.rpc.call("tenzro_registerModelEndpoint", [
			{
				model_id: modelId,
				mcp_endpoint: mcpEndpoint,
				model_name: modelName,
				provider_name: providerName,
			},
		]);
	}

	/**
	 * Unregister a model endpoint.
	 * @param instanceId - The model endpoint instance ID to remove
	 * @returns Unregistration result
	 */
	async unregisterModelEndpoint(instanceId: string): Promise<any> {
		return await this.rpc.call("tenzro_unregisterModelEndpoint", [
			{ instance_id: instanceId },
		]);
	}

  /** `tenzro_computeGetClaim`. */
  computeGetClaim<T = unknown>(params: { claim_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_computeGetClaim", params);
  }

  /** `tenzro_computeListClaims`. */
  computeListClaims<T = unknown>(params: { party: string; limit?: number }): Promise<T> {
    return this.rpc.call<T>("tenzro_computeListClaims", params);
  }

  /** `tenzro_computePriceFeed`. */
  computePriceFeed<T = unknown>(params: { attested_only?: unknown; limit?: unknown; model_id?: unknown; region?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_computePriceFeed", params);
  }

  /**
   * A meter's bond by its 32-byte id (hex): owner, amount, withdrawal request
   * time and the dispute window, or `null` when it has none.
   */
  getMeterBond(meterId: string): Promise<{
    meter_id: string;
    owner: string;
    amount: string;
    withdrawal_requested_at_ms: number | null;
    dispute_window_ms: number | null;
  } | null> {
    return this.rpc.call("tenzro_getMeterBond", { meter_id: meterId });
  }

  /** `tenzro_getSealedModel`. */
  getSealedModel<T = unknown>(params: { model_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getSealedModel", params);
  }

  /** `tenzro_installSealedModel` (operator only). */
  installSealedModel<T = unknown>(params: { manifest?: unknown; model_id?: unknown; recipient_did?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_installSealedModel", params);
  }


  /** `tenzro_listSealedModels`. */
  listSealedModels<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_listSealedModels");
  }

  /** `tenzro_modelRecipientKey`. */
  modelRecipientKey<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_modelRecipientKey");
  }

  /** `tenzro_redeemSealedDelivery`. */
  redeemSealedDelivery<T = unknown>(params: { escrow_id?: unknown; network_escrow_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_redeemSealedDelivery", params);
  }

  /** `tenzro_sealModel` (operator only). */
  sealModel<T = unknown>(params: { artifact_name?: unknown; did?: unknown; enclave_measurement_hex?: unknown; model_id?: unknown; owner_did?: unknown; path?: unknown; recipients?: unknown; shard_bytes?: unknown; recipient_key?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_sealModel", params);
  }
}
