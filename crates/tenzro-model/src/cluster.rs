//! Deterministic orchestration for a local-network cluster that jointly
//! serves a model too large for any single member.
//!
//! A cluster is a set of machines on one local segment that split a model
//! into contiguous transformer-layer ranges and run it as a layer-wise
//! pipeline: each member executes its range and forwards only the boundary
//! activation to the next member. To the wider network the cluster is a
//! single logical provider (see [`tenzro_types::model::LanCluster`]); the
//! head fans the pipeline across members internally over the LAN.
//!
//! Pipeline parallelism is the deliberate choice for commodity local
//! networks: it moves only the boundary activation between members
//! (`hidden_dim × dtype_bytes` per token), so it tolerates ordinary
//! Ethernet/Wi-Fi RTTs. Expert-parallel all-to-all and tensor-parallel
//! row-splits need NVLink/RDMA fabrics and collapse on a LAN.
//!
//! Nothing here runs a model or makes a generative decision. Placement,
//! ordering and admission are all deterministic functions of measured
//! inputs (declared VRAM, a probed latency/bandwidth matrix, reachability
//! tier). Two members fed identical inputs compute the identical plan with
//! no coordinator round — a split assignment would corrupt the pipeline.
//!
//! ## What this module decides
//!
//! 0. [`admit_members`] — only machines the cluster's verified membership
//!    names are candidates at all.
//! 1. [`single_box_fit`] / [`should_cluster`] — the fit policy: a cluster
//!    is only worth forming when no single member can hold the model.
//! 2. [`assign_layers`] — VRAM-weighted bin-packing of layers into
//!    contiguous [`PipelineStage`] ranges.
//! 3. [`HardwareGate`] — per-member admission: can this member load its
//!    range on its backend, and does its build commit match the cluster's.
//! 4. [`NetworkGate`] / [`order_stages`] — communication-aware stage
//!    ordering over a probed cost graph, plus admission of only
//!    data-plane-reachable members.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use tenzro_types::model::PipelineStage;
use tenzro_types::primitives::Address;

/// Bytes-per-element of the activation dtype crossing member boundaries.
/// Most GGUF pipelines forward fp16 activations regardless of weight quant.
const ACTIVATION_DTYPE_BYTES: u32 = 2;

/// A candidate member discovered on the local segment, normalized into the
/// fields orchestration needs. Built from the ggml device API enriched with
/// vendor capability data; see the discovery layer for how it is populated.
/// Only candidates the cluster's verified membership names take part in a
/// plan (see [`admit_members`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClusterMember {
    /// DID of the member machine, the identity the cluster's membership list
    /// names.
    pub machine_did: String,
    /// Member's address — the same key used everywhere else for a node.
    pub address: Address,
    /// VRAM (or unified memory) this member contributes, in GB. Drives the
    /// layer bin-packing: more memory earns proportionally more layers.
    pub vram_gb: f32,
    /// Compute backend this member will execute its range on.
    pub backend: Backend,
    /// Capability key for the backend — e.g. CUDA compute capability
    /// (`"sm_89"`), AMD gfx target (`"gfx1100"`), Apple chip family. Opaque
    /// here; only compared against per-quant kernel requirements upstream.
    pub cap_key: String,
    /// llama.cpp build commit this member runs. The RPC wire protocol has
    /// no version negotiation, so every member must share one commit.
    pub llama_commit: String,
    /// LAN endpoint for intra-cluster pipeline traffic.
    pub local_endpoint: String,
    /// Data-plane reachability of this member from the head's vantage.
    /// Only `Direct` / `LocalDirect` members may carry pipeline activations.
    pub reachability: MemberReachability,
}

/// Compute backend a member executes on. Mirrors the in-tree ggml backends
/// that are RPC-exposable; mixing different backends in one pipeline is
/// natively supported because there is one model file on the head and the
/// members are device executors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Backend {
    /// CPU with runtime SIMD dispatch. Always available; the fallback when
    /// a GPU backend lacks a kernel for a given op.
    Cpu,
    /// NVIDIA CUDA — the reference GPU backend.
    Cuda,
    /// Apple Metal over unified memory.
    Metal,
    /// Vulkan — the universal "any GPU" fallback. Weaker prompt-processing,
    /// no multi-GPU row-split, but broad device coverage.
    Vulkan,
    /// AMD HIP / ROCm — mature on supported gfx targets only.
    Hip,
    /// Intel SYCL.
    Sycl,
}

/// Data-plane reachability of a candidate member. Re-exported from the
/// engine-agnostic cluster substrate: only members the head can reach directly
/// may carry pipeline activations; relayed or symmetric-NAT members cannot
/// sustain per-token traffic.
pub use tenzro_cluster::MemberReachability;

/// Why a candidate member was rejected from a cluster, for surfacing to the
/// user in the assisted-setup UI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RejectReason {
    /// Member's llama.cpp build commit differs from the cluster's. The RPC
    /// wire protocol cannot bridge commits.
    CommitMismatch {
        /// The cluster's reference commit.
        expected: String,
        /// The member's commit.
        found: String,
    },
    /// Member is not reachable on the data plane (relay-only / symmetric
    /// NAT). It can still participate in control-plane coordination.
    NotDataPlaneReachable(MemberReachability),
    /// Member's contributed VRAM is below the floor needed to hold any
    /// non-empty layer range.
    InsufficientVram {
        /// VRAM the member offered, in GB.
        offered_gb: f32,
        /// Minimum needed to hold one layer, in GB.
        needed_gb: f32,
    },
}

/// Outcome of the per-member hardware gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardwareGate {
    /// Members admitted: commit matches and they can hold a non-empty range.
    pub admitted: Vec<ClusterMember>,
    /// Members rejected, each with the reason (for UI display).
    pub rejected: Vec<(Address, RejectReason)>,
}

/// Static facts about the model needed to plan a cluster. Read from the GGUF
/// header / model card; not provider-specific.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ModelShape {
    /// Total transformer layers to distribute across members.
    pub layers: u32,
    /// Hidden dimension — sets boundary-activation size per token.
    pub hidden_dim: u32,
    /// Total weights footprint when loaded, in GB. Compared against a
    /// single member's VRAM for the fit policy.
    pub total_vram_gb: f32,
    /// KV attention heads (`<arch>.attention.head_count_kv`). `None` when the
    /// gguf did not declare it — the KV estimate is then unavailable, not zero.
    pub head_count_kv: Option<u32>,
    /// Per-head key/value dimension (`<arch>.attention.key_length`). `None` if
    /// absent.
    pub key_length: Option<u32>,
    /// The model's trained context length (`<arch>.context_length`). `None` if
    /// absent. Used as the default and the ceiling for a KV estimate.
    pub context_length: Option<u32>,
    /// Layers that carry a KV cache. `None` means every layer does, which is
    /// the dense-transformer case. A hybrid model (Nemotron-H: Mamba-2, MoE
    /// and a few attention layers) lists per-layer KV heads, and only the
    /// layers with a non-zero count hold keys and values.
    pub attention_layers: Option<u32>,
    /// Fixed per-sequence bytes of recurrent (state-space) state, summed over
    /// the recurrent layers: the convolution window plus the selective-scan
    /// state, kept in f32. It does not grow with the context. Zero for a
    /// model with no recurrent layers.
    pub recurrent_state_bytes: u64,
}

impl ModelShape {
    /// Bytes of boundary activation crossing one member boundary per token.
    pub fn activation_bytes_per_token(&self) -> u32 {
        self.hidden_dim * ACTIVATION_DTYPE_BYTES
    }

    /// Bytes of KV cache to hold `context_tokens` tokens.
    ///
    /// This is the term a naive "weights fit in VRAM" check omits, and it is
    /// frequently the one that decides whether a model runs at the requested
    /// context. Per layer, per token, the cache holds a key and a value vector
    /// of `head_count_kv * key_length` elements each, at `KV_DTYPE_BYTES`:
    ///
    ///   2 (K and V) * layers * head_count_kv * key_length * KV_DTYPE_BYTES * tokens
    ///
    /// Only the layers that carry a KV cache count (`attention_layers`), and
    /// the fixed recurrent state of a hybrid model is added once: it does not
    /// scale with the context.
    ///
    /// Returns `None` when the gguf omitted the attention metadata — the caller
    /// must then say "KV unknown", never silently assume zero.
    pub fn kv_cache_bytes(&self, context_tokens: u32) -> Option<u64> {
        let heads = self.head_count_kv? as u64;
        let key_dim = self.key_length? as u64;
        let layers = self.attention_layers.unwrap_or(self.layers) as u64;
        let tokens = context_tokens as u64;
        Some(
            (2 * layers * heads * key_dim * KV_DTYPE_BYTES as u64 * tokens)
                .saturating_add(self.recurrent_state_bytes),
        )
    }

    /// The trained context, if known — the sensible default for a fit check.
    pub fn default_context(&self) -> Option<u32> {
        self.context_length
    }

    /// Bytes of KV cache per token, per layer — the real per-layer figure the
    /// serve advisor needs to replace its representative 4096 constant.
    /// when the gguf omitted the attention dimensions.
    ///
    /// The advisor multiplies this by `layers`, so for a hybrid model the
    /// figure is spread over all layers (attention layers only hold a cache;
    /// rounded up so the product never under-counts).
    pub fn kv_bytes_per_token_per_layer(&self) -> Option<u64> {
        let heads = self.head_count_kv? as u64;
        let key_dim = self.key_length? as u64;
        // 2 for K and V.
        let per_attention_layer = 2 * heads * key_dim * KV_DTYPE_BYTES as u64;
        let attn = self.attention_layers.unwrap_or(self.layers) as u64;
        let layers = (self.layers as u64).max(1);
        Some((per_attention_layer * attn).div_ceil(layers))
    }
}

/// Bytes per KV cache element. GGUF KV cache defaults to fp16.
const KV_DTYPE_BYTES: u32 = 2;

/// Decision of the fit policy: whether a cluster is warranted at all.
///
/// A cluster trades roughly half the decode speed (each token becomes a
/// network round-trip) for capacity. So it is only worth forming when the
/// model does not fit on the single biggest member, unless the user forces
/// it. [`should_cluster`] encodes that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FitDecision {
    /// The model fits on the biggest single member — run there, no cluster.
    RunLocal,
    /// No single member can hold the model — a cluster is required.
    ClusterRequired,
    /// The model would fit locally, but the user explicitly chose a cluster.
    ClusterForced,
}

impl FitDecision {
    /// Whether this decision results in forming a cluster.
    pub fn forms_cluster(self) -> bool {
        matches!(self, Self::ClusterRequired | Self::ClusterForced)
    }
}

/// The candidates `membership` admits to a plan: only machines the cluster's
/// verified membership list names, in their original order. A candidate the
/// operator never listed, or has since removed, is dropped before any fit or
/// placement decision sees it.
pub fn admit_members(
    membership: &tenzro_cluster::VerifiedMembership,
    candidates: Vec<ClusterMember>,
) -> Vec<ClusterMember> {
    candidates
        .into_iter()
        .filter(|m| membership.contains(&m.machine_did))
        .collect()
}

/// The single member that can hold the whole model, if any. Used by the fit
/// policy: if some member's VRAM covers `model.total_vram_gb`, prefer it.
pub fn single_box_fit<'a>(
    model: ModelShape,
    members: impl IntoIterator<Item = &'a ClusterMember>,
) -> Option<Address> {
    members
        .into_iter()
        .filter(|m| m.vram_gb >= model.total_vram_gb)
        .max_by(|a, b| {
            a.vram_gb
                .partial_cmp(&b.vram_gb)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|m| m.address)
}

/// Apply the fit policy: run-local-advise-only unless the model does not fit
/// on any single member, or the user forced a cluster.
pub fn should_cluster<'a>(
    model: ModelShape,
    members: impl IntoIterator<Item = &'a ClusterMember>,
    user_forced: bool,
) -> FitDecision {
    let fits_single = single_box_fit(model, members).is_some();
    match (fits_single, user_forced) {
        (true, false) => FitDecision::RunLocal,
        (true, true) => FitDecision::ClusterForced,
        (false, _) => FitDecision::ClusterRequired,
    }
}

/// Per-member hardware gate: admit members whose build commit matches the
/// reference and that can hold at least one layer; reject the rest with a
/// reason. `min_gb_per_layer` is the model's per-layer footprint.
pub fn hardware_gate(
    reference_commit: &str,
    min_gb_per_layer: f32,
    members: impl IntoIterator<Item = ClusterMember>,
) -> HardwareGate {
    let mut admitted = Vec::new();
    let mut rejected = Vec::new();
    for m in members {
        if m.llama_commit != reference_commit {
            rejected.push((
                m.address,
                RejectReason::CommitMismatch {
                    expected: reference_commit.to_string(),
                    found: m.llama_commit.clone(),
                },
            ));
            continue;
        }
        if m.vram_gb < min_gb_per_layer {
            rejected.push((
                m.address,
                RejectReason::InsufficientVram {
                    offered_gb: m.vram_gb,
                    needed_gb: min_gb_per_layer,
                },
            ));
            continue;
        }
        admitted.push(m);
    }
    HardwareGate { admitted, rejected }
}

/// VRAM-weighted bin-packing of `total_layers` into contiguous ranges, one
/// per member, proportional to each member's VRAM. The result is keyed by
/// member address and deterministic: callers pass members in a stable order
/// (sorted by address) and every member computes the identical assignment.
///
/// Every admitted member gets a non-empty range; remainder layers go to the
/// highest-VRAM members first. Members must already be ordered (see
/// [`order_stages`]); this assigns the *sizes*, ordering assigns *which*
/// contiguous slice each holds.
pub fn assign_layers(
    total_layers: u32,
    members: &[ClusterMember],
) -> HashMap<Address, PipelineStage> {
    let mut out = HashMap::new();
    if members.is_empty() || total_layers == 0 {
        return out;
    }
    let n = members.len() as u32;
    // Cannot give every member a non-empty range; cap at one layer each.
    if total_layers <= n {
        let mut cursor = 0u32;
        for m in members {
            let end = (cursor + 1).min(total_layers);
            if cursor < total_layers {
                out.insert(
                    m.address,
                    PipelineStage {
                        start_layer: cursor,
                        end_layer: end,
                    },
                );
                cursor = end;
            }
        }
        return out;
    }

    let total_vram: f32 = members.iter().map(|m| m.vram_gb).sum();
    // Largest-remainder apportionment so the layer counts sum exactly.
    let mut counts: Vec<(usize, u32, f32)> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let exact = total_layers as f32 * (m.vram_gb / total_vram);
            let floor = exact.floor() as u32;
            // Floor at 1 so no member is starved of layers.
            let base = floor.max(1);
            (i, base, exact - floor as f32)
        })
        .collect();

    let assigned: u32 = counts.iter().map(|(_, c, _)| *c).sum();
    if assigned < total_layers {
        let mut remainder = total_layers - assigned;
        // Hand leftover layers to the largest fractional remainders first.
        let mut order: Vec<usize> = (0..counts.len()).collect();
        order.sort_by(|&a, &b| {
            counts[b]
                .2
                .partial_cmp(&counts[a].2)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for &idx in &order {
            if remainder == 0 {
                break;
            }
            counts[idx].1 += 1;
            remainder -= 1;
        }
    } else if assigned > total_layers {
        // Over-assigned by the floor-at-1 step; trim from smallest remainders.
        let mut over = assigned - total_layers;
        let mut order: Vec<usize> = (0..counts.len()).collect();
        order.sort_by(|&a, &b| {
            counts[a]
                .2
                .partial_cmp(&counts[b].2)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for &idx in &order {
            if over == 0 {
                break;
            }
            if counts[idx].1 > 1 {
                counts[idx].1 -= 1;
                over -= 1;
            }
        }
    }

    let mut cursor = 0u32;
    for (i, count, _) in counts {
        let end = cursor + count;
        out.insert(
            members[i].address,
            PipelineStage {
                start_layer: cursor,
                end_layer: end,
            },
        );
        cursor = end;
    }
    out
}

/// A probed pairwise link between two candidate members: round-trip latency
/// and usable bandwidth. Re-exported from the engine-agnostic cluster
/// substrate; populated by the active probe burst at form time. For pipeline
/// serving the per-token transfer weight is one boundary activation.
pub use tenzro_cluster::LinkProbe;

/// Network gate result: the data-plane-eligible members ordered to minimize
/// total pipeline latency across all stages, plus the members excluded with a reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkGate {
    /// Members in pipeline order (stage 0 first). The head connects to the
    /// first and the last produces logits.
    pub ordered: Vec<Address>,
    /// Members excluded from the data plane, each with the reason.
    pub excluded: Vec<(Address, RejectReason)>,
}

/// Admit only data-plane-reachable members and order them to minimize total
/// pipeline transfer cost. Delegates the ordering to the engine-agnostic
/// [`tenzro_cluster::order_members`] greedy nearest-neighbour chain over the
/// probed cost graph, then maps its opaque member ids back to [`Address`] and
/// its exclusions to [`RejectReason`]. `probes` is keyed by an unordered
/// member pair; `activation_bytes` sets the per-token transfer weight.
pub fn order_stages(
    head: Address,
    members: &[ClusterMember],
    probes: &HashMap<(Address, Address), LinkProbe>,
    activation_bytes: u32,
) -> NetworkGate {
    use tenzro_cluster::{CostMember, MemberId, order_members};

    let head_id = address_member_id(head);
    let cost_members: Vec<CostMember> = members
        .iter()
        .map(|m| CostMember {
            id: address_member_id(m.address),
            reachability: m.reachability,
        })
        .collect();

    // Re-key the probe graph onto opaque member ids. `address_member_id` is
    // order-preserving hex, so the id-order tie-break matches address order.
    let id_probes: HashMap<(MemberId, MemberId), LinkProbe> = probes
        .iter()
        .map(|((a, b), p)| {
            (
                tenzro_cluster::link_key(&address_member_id(*a), &address_member_id(*b)),
                *p,
            )
        })
        .collect();

    let out = order_members(&head_id, &cost_members, &id_probes, activation_bytes);

    // Map ids back to addresses via the member roster.
    let by_id: HashMap<String, Address> = members
        .iter()
        .map(|m| (address_member_id(m.address).0, m.address))
        .collect();
    let ordered: Vec<Address> = out
        .ordered
        .iter()
        .filter_map(|id| by_id.get(&id.0).copied())
        .collect();
    let excluded: Vec<(Address, RejectReason)> = out
        .excluded
        .into_iter()
        .filter_map(|(id, reach)| {
            by_id
                .get(&id.0)
                .map(|a| (*a, RejectReason::NotDataPlaneReachable(reach)))
        })
        .collect();

    NetworkGate { ordered, excluded }
}

/// Order-preserving [`MemberId`] for an address: fixed-width lowercase hex, so
/// lexicographic id order equals the address's byte-array order and the
/// shared ordering's id-order tie-break stays byte-for-byte identical.
fn address_member_id(addr: Address) -> tenzro_cluster::MemberId {
    tenzro_cluster::MemberId(hex::encode(addr.0))
}

/// Canonical (order-independent) key for a member-pair probe.
pub fn link_key(a: Address, b: Address) -> (Address, Address) {
    if a.0 <= b.0 { (a, b) } else { (b, a) }
}

/// A concrete, launchable cluster plan: the pipeline-ordered members, each with
/// its layer range and the `--tensor-split` weight the head passes to the
/// runtime. The head loads the single GGUF and attaches members as RPC devices
/// in this exact order; the runtime fills devices in `--rpc` order against the
/// `--tensor-split` proportions, so order and weights must agree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaunchPlan {
    /// Members in pipeline order (stage 0 first), each carrying its layer range.
    pub stages: Vec<LaunchStage>,
    /// `--tensor-split` proportions, one per stage, in pipeline order. These
    /// are integer-normalized layer counts (the runtime only needs relative
    /// proportions), which keeps the split identical to the layer assignment.
    pub tensor_split: Vec<u32>,
}

/// One stage of a [`LaunchPlan`]: which member, its layer range, and its LAN
/// endpoint the head dials (through the authenticated tunnel) as an RPC device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaunchStage {
    /// The member serving this stage.
    pub address: Address,
    /// Inclusive-exclusive transformer-layer range this member holds.
    pub stage: PipelineStage,
    /// The member's LAN endpoint for the RPC device connection.
    pub local_endpoint: String,
}

/// Fold a network ordering plus a layer assignment into a launchable plan. The
/// `--tensor-split` weights are the per-stage layer counts in pipeline order,
/// so the runtime's proportional device fill reproduces exactly the layer
/// ranges the planner assigned. Members in `ordered` without an assignment
/// (none, in practice) are skipped.
pub fn launch_plan(
    gate: &NetworkGate,
    assignment: &HashMap<Address, PipelineStage>,
    members: &[ClusterMember],
) -> LaunchPlan {
    let endpoint_of = |addr: Address| {
        members
            .iter()
            .find(|m| m.address == addr)
            .map(|m| m.local_endpoint.clone())
            .unwrap_or_default()
    };
    let mut stages = Vec::new();
    let mut tensor_split = Vec::new();
    for &addr in &gate.ordered {
        if let Some(stage) = assignment.get(&addr) {
            tensor_split.push(stage.end_layer - stage.start_layer);
            stages.push(LaunchStage {
                address: addr,
                stage: *stage,
                local_endpoint: endpoint_of(addr),
            });
        }
    }
    LaunchPlan {
        stages,
        tensor_split,
    }
}

/// Per-member sustained compute, in tokens/s, used by the time-aware balancer.
/// Keyed by member address; absent members fall back to a VRAM-proportional
/// estimate so the balancer degrades to [`assign_layers`] when no compute
/// telemetry is available.
pub type ComputeRates = HashMap<Address, f32>;

/// Time-aware (water-filling) layer apportionment: distribute layers so each
/// stage's *execution time* — layers ÷ tokens-per-second — is balanced, rather
/// than balancing memory alone. On heterogeneous compute a VRAM-balanced split
/// can be time-imbalanced (the slowest stage bottlenecks the pipeline); this
/// balances the bottleneck instead. Still respects the VRAM ceiling: a member
/// is never given more layers than its memory can hold.
///
/// This is a compute-time-weighted (water-filling) refinement. It is provided
/// as a ready alternative to [`assign_layers`]; the default serving path uses
/// the VRAM-weighted [`assign_layers`] until per-host compute calibration is
/// validated across machines.
pub fn assign_layers_timed(
    total_layers: u32,
    members: &[ClusterMember],
    rates: &ComputeRates,
    gb_per_layer: f32,
) -> HashMap<Address, PipelineStage> {
    let mut out = HashMap::new();
    if members.is_empty() || total_layers == 0 {
        return out;
    }
    // Effective rate per member: measured tokens/s, else VRAM-proportional.
    let rate_of = |m: &ClusterMember| -> f32 {
        rates
            .get(&m.address)
            .copied()
            .filter(|r| *r > 0.0)
            .unwrap_or_else(|| m.vram_gb.max(0.01))
    };
    // Memory ceiling: max layers each member can hold.
    let cap_of = |m: &ClusterMember| -> u32 {
        if gb_per_layer <= 0.0 {
            total_layers
        } else {
            (m.vram_gb / gb_per_layer).floor().max(1.0) as u32
        }
    };

    // Water-filling: hand out layers one at a time to whichever member would
    // have the lowest resulting per-stage time (count+1)/rate, subject to its
    // memory cap. Deterministic: ties break on address order.
    let mut order: Vec<usize> = (0..members.len()).collect();
    order.sort_by(|&a, &b| members[a].address.0.cmp(&members[b].address.0));
    let mut counts: Vec<u32> = vec![0; members.len()];
    let caps: Vec<u32> = members.iter().map(cap_of).collect();
    let rates_v: Vec<f32> = members.iter().map(rate_of).collect();

    for _ in 0..total_layers {
        let mut best: Option<usize> = None;
        let mut best_time = f32::INFINITY;
        for &i in &order {
            if counts[i] >= caps[i] {
                continue;
            }
            let t = (counts[i] + 1) as f32 / rates_v[i];
            if t < best_time {
                best_time = t;
                best = Some(i);
            }
        }
        match best {
            Some(i) => counts[i] += 1,
            // Every member at its memory cap — total capacity is exceeded.
            None => break,
        }
    }

    let mut cursor = 0u32;
    for i in &order {
        let count = counts[*i];
        if count == 0 {
            continue;
        }
        let end = cursor + count;
        out.insert(
            members[*i].address,
            PipelineStage {
                start_layer: cursor,
                end_layer: end,
            },
        );
        cursor = end;
    }
    out
}

impl Backend {
    /// Map a ggml backend registry name ("CUDA", "Vulkan", "Metal", "CPU",
    /// "ROCm"/"HIP", "SYCL") to the orchestration backend enum. Unknown
    /// names fall back to [`Backend::Cpu`] — a member always has a CPU path.
    pub fn from_ggml_name(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        if lower.contains("cuda") {
            Self::Cuda
        } else if lower.contains("metal") {
            Self::Metal
        } else if lower.contains("vulkan") {
            Self::Vulkan
        } else if lower.contains("rocm") || lower.contains("hip") {
            Self::Hip
        } else if lower.contains("sycl") {
            Self::Sycl
        } else {
            Self::Cpu
        }
    }

    /// Lower-case ggml backend family name (`cuda`, `metal`, `vulkan`,
    /// `rocm`, `sycl`, `cpu`). The inverse of [`Self::from_ggml_name`] over
    /// canonical names, used when serializing a backend onto the wire.
    pub fn ggml_name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cuda => "cuda",
            Self::Metal => "metal",
            Self::Vulkan => "vulkan",
            Self::Hip => "rocm",
            Self::Sycl => "sycl",
        }
    }
}

/// One compute device on the local node, normalized from the ggml runtime
/// device API. The discovery layer collects these for the local machine and
/// broadcasts a terse summary over mDNS; the head assembles peers' devices
/// into [`ClusterMember`] records for orchestration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalDevice {
    /// Backend this device executes on.
    pub backend: Backend,
    /// ggml device type (GPU / integrated GPU / CPU / accelerator).
    pub dev_type: DeviceType,
    /// Human description from ggml (e.g. "NVIDIA GeForce RTX 4090",
    /// "Apple M3 Max"). The capability-key enrichment step refines this.
    pub description: String,
    /// Capability key for the backend — refined from the description by the
    /// vendor enrichment step (CUDA compute capability, AMD gfx target,
    /// Apple chip family). Before enrichment this mirrors `description`.
    pub cap_key: String,
    /// Free device memory in bytes at detection time.
    pub mem_free: u64,
    /// Total device memory in bytes.
    pub mem_total: u64,
}

impl LocalDevice {
    /// Memory this device can contribute to a cluster, in GB (free memory).
    pub fn vram_gb(&self) -> f32 {
        self.mem_free as f32 / 1_073_741_824.0
    }
}

/// ggml device type, mirrored from the bindings so the cluster module does
/// not depend on the llama backend being initialized to talk about devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    /// Discrete or unified-memory GPU.
    Gpu,
    /// Integrated GPU sharing system memory.
    IntegratedGpu,
    /// CPU device.
    Cpu,
    /// Dedicated accelerator (NPU/TPU-class).
    Accelerator,
    /// Unrecognized device type.
    Unknown,
}

/// The local node's hardware self-profile: every compute device plus the
/// llama.cpp build commit. Broadcast (as a terse summary) over mDNS so peers
/// can decide cluster membership; the full profile is pulled over unicast.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeProfile {
    /// llama.cpp build commit. The RPC wire protocol has no version
    /// negotiation, so every cluster member must share this exact value.
    pub llama_commit: String,
    /// CPU architecture (`x86_64`, `aarch64`).
    pub cpu_arch: String,
    /// Operating system.
    pub os: String,
    /// Every compute device the ggml runtime reports, best (most memory)
    /// first. The first GPU-class device, if any, is the serving device.
    pub devices: Vec<LocalDevice>,
}

impl NodeProfile {
    /// Total contributable memory across GPU-class devices, in GB. Falls
    /// back to the largest CPU device when no GPU is present.
    pub fn serving_vram_gb(&self) -> f32 {
        let gpu_total: f32 = self
            .devices
            .iter()
            .filter(|d| matches!(d.dev_type, DeviceType::Gpu | DeviceType::IntegratedGpu))
            .map(|d| d.vram_gb())
            .sum();
        if gpu_total > 0.0 {
            gpu_total
        } else {
            self.devices.iter().map(|d| d.vram_gb()).fold(0.0, f32::max)
        }
    }

    /// The backend the node would serve on: the first GPU-class device's
    /// backend, else CPU.
    pub fn serving_backend(&self) -> Backend {
        self.devices
            .iter()
            .find(|d| matches!(d.dev_type, DeviceType::Gpu | DeviceType::IntegratedGpu))
            .map(|d| d.backend)
            .unwrap_or(Backend::Cpu)
    }

    /// The capability key of the serving device (used by per-quant kernel
    /// checks), or the CPU arch when serving on CPU.
    pub fn serving_cap_key(&self) -> String {
        self.devices
            .iter()
            .find(|d| matches!(d.dev_type, DeviceType::Gpu | DeviceType::IntegratedGpu))
            .map(|d| d.cap_key.clone())
            .unwrap_or_else(|| self.cpu_arch.clone())
    }

    /// Project this node into a [`ClusterMember`] for orchestration, given
    /// the node's machine DID and address, its LAN endpoint, and its measured
    /// data-plane reachability from the head.
    pub fn to_member(
        &self,
        machine_did: impl Into<String>,
        address: Address,
        local_endpoint: impl Into<String>,
        reachability: MemberReachability,
    ) -> ClusterMember {
        ClusterMember {
            machine_did: machine_did.into(),
            address,
            vram_gb: self.serving_vram_gb(),
            backend: self.serving_backend(),
            cap_key: self.serving_cap_key(),
            llama_commit: self.llama_commit.clone(),
            local_endpoint: local_endpoint.into(),
            reachability,
        }
    }
}

/// The llama.cpp source this binary links against, as the engine records it at
/// build time. Cluster members must share this value.
#[cfg(feature = "engine")]
pub const LLAMA_CPP_COMMIT: &str = llama_cpp_sys_2::LLAMA_SOURCE_ID;

/// Detect the local node's hardware self-profile from the ggml runtime
/// device API, stamped with the linked llama.cpp commit. Devices are sorted
/// best (most free memory) first so [`NodeProfile`] accessors pick the
/// strongest serving device.
///
/// `cap_key` starts as the ggml description; the vendor-SMI enrichment step
/// (NVML / amd-smi / IOKit / Level-Zero) refines it into a precise
/// capability key. Enrichment is layered on top so this function stays
/// dependency-light and works on any backend.
#[cfg(feature = "engine")]
pub fn detect_node_profile() -> NodeProfile {
    let mut devices: Vec<LocalDevice> = llama_cpp_2::list_llama_ggml_backend_devices()
        .into_iter()
        .map(|d| {
            let dev_type = match d.device_type {
                llama_cpp_2::LlamaBackendDeviceType::Gpu => DeviceType::Gpu,
                llama_cpp_2::LlamaBackendDeviceType::IntegratedGpu => DeviceType::IntegratedGpu,
                llama_cpp_2::LlamaBackendDeviceType::Cpu => DeviceType::Cpu,
                llama_cpp_2::LlamaBackendDeviceType::Accelerator => DeviceType::Accelerator,
                llama_cpp_2::LlamaBackendDeviceType::Unknown => DeviceType::Unknown,
            };
            LocalDevice {
                backend: Backend::from_ggml_name(&d.backend),
                dev_type,
                cap_key: d.description.clone(),
                description: d.description,
                mem_free: d.memory_free as u64,
                mem_total: d.memory_total as u64,
            }
        })
        .collect();
    devices.sort_by_key(|b| std::cmp::Reverse(b.mem_free));

    NodeProfile {
        llama_commit: LLAMA_CPP_COMMIT.to_string(),
        cpu_arch: std::env::consts::ARCH.to_string(),
        os: std::env::consts::OS.to_string(),
        devices,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(addr: u8, vram_gb: f32, commit: &str, reach: MemberReachability) -> ClusterMember {
        ClusterMember {
            machine_did: format!("did:tenzro:machine:m{addr}"),
            address: Address::new([addr; 32]),
            vram_gb,
            backend: Backend::Cuda,
            cap_key: "sm_89".into(),
            llama_commit: commit.into(),
            local_endpoint: format!("10.0.0.{}:8080", addr),
            reachability: reach,
        }
    }

    fn shape(layers: u32, hidden: u32, total_gb: f32) -> ModelShape {
        ModelShape {
            attention_layers: None,
            recurrent_state_bytes: 0,
            head_count_kv: None,
            key_length: None,
            context_length: None,
            layers,
            hidden_dim: hidden,
            total_vram_gb: total_gb,
        }
    }

    #[test]
    fn fit_policy_runs_local_when_model_fits() {
        let big = member(1, 80.0, "c", MemberReachability::LocalDirect);
        let small = member(2, 24.0, "c", MemberReachability::LocalDirect);
        let model = shape(80, 8192, 70.0);
        assert_eq!(
            should_cluster(model, [&big, &small], false),
            FitDecision::RunLocal
        );
        assert_eq!(single_box_fit(model, [&big, &small]), Some(big.address));
    }

    #[test]
    fn fit_policy_clusters_when_model_too_big() {
        let a = member(1, 24.0, "c", MemberReachability::LocalDirect);
        let b = member(2, 24.0, "c", MemberReachability::LocalDirect);
        let model = shape(80, 8192, 70.0);
        assert_eq!(
            should_cluster(model, [&a, &b], false),
            FitDecision::ClusterRequired
        );
        assert_eq!(single_box_fit(model, [&a, &b]), None);
    }

    #[test]
    fn fit_policy_honours_user_force() {
        let big = member(1, 80.0, "c", MemberReachability::LocalDirect);
        let model = shape(80, 8192, 70.0);
        assert_eq!(
            should_cluster(model, [&big], true),
            FitDecision::ClusterForced
        );
        assert!(FitDecision::ClusterForced.forms_cluster());
        assert!(!FitDecision::RunLocal.forms_cluster());
    }

    #[test]
    fn hardware_gate_rejects_commit_mismatch() {
        let ok = member(1, 24.0, "abc", MemberReachability::LocalDirect);
        let bad = member(2, 24.0, "xyz", MemberReachability::LocalDirect);
        let gate = hardware_gate("abc", 1.0, [ok.clone(), bad]);
        assert_eq!(gate.admitted.len(), 1);
        assert_eq!(gate.admitted[0].address, ok.address);
        assert_eq!(gate.rejected.len(), 1);
        matches!(gate.rejected[0].1, RejectReason::CommitMismatch { .. });
    }

    #[test]
    fn hardware_gate_rejects_starved_member() {
        let ok = member(1, 24.0, "abc", MemberReachability::LocalDirect);
        let tiny = member(2, 0.5, "abc", MemberReachability::LocalDirect);
        let gate = hardware_gate("abc", 1.0, [ok, tiny]);
        assert_eq!(gate.admitted.len(), 1);
        assert!(matches!(
            gate.rejected[0].1,
            RejectReason::InsufficientVram { .. }
        ));
    }

    #[test]
    fn assign_layers_is_vram_weighted_and_contiguous() {
        // 80 layers, member A has 3x the VRAM of B.
        let a = member(1, 72.0, "c", MemberReachability::LocalDirect);
        let b = member(2, 24.0, "c", MemberReachability::LocalDirect);
        let plan = assign_layers(80, &[a.clone(), b.clone()]);
        let sa = plan[&a.address];
        let sb = plan[&b.address];
        // A gets ~3/4 of the layers.
        assert_eq!(sa.start_layer, 0);
        assert_eq!(sa.end_layer, 60);
        assert_eq!(sb.start_layer, 60);
        assert_eq!(sb.end_layer, 80);
        // Contiguous, no gaps, covers all layers.
        assert_eq!(sa.end_layer, sb.start_layer);
        assert_eq!(sb.end_layer, 80);
    }

    #[test]
    fn assign_layers_sums_exactly_with_uneven_split() {
        let a = member(1, 10.0, "c", MemberReachability::LocalDirect);
        let b = member(2, 7.0, "c", MemberReachability::LocalDirect);
        let c = member(3, 3.0, "c", MemberReachability::LocalDirect);
        let plan = assign_layers(33, &[a.clone(), b.clone(), c.clone()]);
        let total: u32 = plan.values().map(|s| s.layer_count()).sum();
        assert_eq!(total, 33);
        // Every member gets a non-empty, contiguous, gapless range.
        let mut stages: Vec<_> = plan.values().copied().collect();
        stages.sort_by_key(|s| s.start_layer);
        assert_eq!(stages[0].start_layer, 0);
        for w in stages.windows(2) {
            assert_eq!(w[0].end_layer, w[1].start_layer);
            assert!(w[0].layer_count() >= 1);
        }
        assert_eq!(stages.last().unwrap().end_layer, 33);
    }

    #[test]
    fn assign_layers_handles_more_members_than_layers() {
        let members: Vec<_> = (1..=4)
            .map(|i| member(i, 8.0, "c", MemberReachability::LocalDirect))
            .collect();
        let plan = assign_layers(2, &members);
        // Only 2 layers: only 2 members get a range.
        let total: u32 = plan.values().map(|s| s.layer_count()).sum();
        assert_eq!(total, 2);
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn order_stages_excludes_relay_and_symmetric_nat() {
        let head = Address::new([1; 32]);
        let direct = member(2, 24.0, "c", MemberReachability::Direct);
        let relay = member(3, 24.0, "c", MemberReachability::RelayOnly);
        let nat = member(4, 24.0, "c", MemberReachability::SymmetricNat);
        let probes = HashMap::new();
        let gate = order_stages(
            head,
            &[direct.clone(), relay.clone(), nat.clone()],
            &probes,
            16384,
        );
        assert_eq!(gate.ordered, vec![direct.address]);
        assert_eq!(gate.excluded.len(), 2);
    }

    #[test]
    fn order_stages_prefers_cheaper_links() {
        let head = Address::new([1; 32]);
        let near = member(2, 24.0, "c", MemberReachability::LocalDirect);
        let far = member(3, 24.0, "c", MemberReachability::LocalDirect);
        let mut probes = HashMap::new();
        // Head -> near is fast; head -> far is slow.
        probes.insert(
            link_key(head, near.address),
            LinkProbe {
                rtt_ms: 1.0,
                bandwidth_gbps: 10.0,
            },
        );
        probes.insert(
            link_key(head, far.address),
            LinkProbe {
                rtt_ms: 50.0,
                bandwidth_gbps: 1.0,
            },
        );
        // near -> far link so the chain can complete.
        probes.insert(
            link_key(near.address, far.address),
            LinkProbe {
                rtt_ms: 2.0,
                bandwidth_gbps: 10.0,
            },
        );
        let gate = order_stages(head, &[far.clone(), near.clone()], &probes, 16384);
        assert_eq!(gate.ordered, vec![near.address, far.address]);
    }

    #[test]
    fn link_probe_transfer_cost_accounts_for_bandwidth() {
        let fast = LinkProbe {
            rtt_ms: 1.0,
            bandwidth_gbps: 100.0,
        };
        let slow = LinkProbe {
            rtt_ms: 1.0,
            bandwidth_gbps: 1.0,
        };
        let bytes = 16384;
        assert!(fast.transfer_ms(bytes) < slow.transfer_ms(bytes));
    }

    #[test]
    fn activation_bytes_scales_with_hidden_dim() {
        let s7b = shape(32, 4096, 14.0);
        let s70b = shape(80, 8192, 70.0);
        assert_eq!(s7b.activation_bytes_per_token(), 4096 * 2);
        assert_eq!(s70b.activation_bytes_per_token(), 8192 * 2);
    }

    #[test]
    fn backend_maps_from_ggml_names() {
        assert_eq!(Backend::from_ggml_name("CUDA"), Backend::Cuda);
        assert_eq!(Backend::from_ggml_name("Vulkan"), Backend::Vulkan);
        assert_eq!(Backend::from_ggml_name("Metal"), Backend::Metal);
        assert_eq!(Backend::from_ggml_name("ROCm"), Backend::Hip);
        assert_eq!(Backend::from_ggml_name("HIP"), Backend::Hip);
        assert_eq!(Backend::from_ggml_name("SYCL"), Backend::Sycl);
        assert_eq!(Backend::from_ggml_name("CPU"), Backend::Cpu);
        assert_eq!(Backend::from_ggml_name("something-else"), Backend::Cpu);
    }

    fn gpu_device(backend: Backend, free_gb: f32) -> LocalDevice {
        LocalDevice {
            backend,
            dev_type: DeviceType::Gpu,
            description: "test gpu".into(),
            cap_key: "test gpu".into(),
            mem_free: (free_gb * 1_073_741_824.0) as u64,
            mem_total: (free_gb * 1_073_741_824.0) as u64,
        }
    }

    fn cpu_device(free_gb: f32) -> LocalDevice {
        LocalDevice {
            backend: Backend::Cpu,
            dev_type: DeviceType::Cpu,
            description: "cpu".into(),
            cap_key: "cpu".into(),
            mem_free: (free_gb * 1_073_741_824.0) as u64,
            mem_total: (free_gb * 1_073_741_824.0) as u64,
        }
    }

    #[test]
    fn node_profile_sums_gpu_vram() {
        let profile = NodeProfile {
            llama_commit: "abc".into(),
            cpu_arch: "aarch64".into(),
            os: "macos".into(),
            devices: vec![
                gpu_device(Backend::Cuda, 24.0),
                gpu_device(Backend::Cuda, 24.0),
                cpu_device(64.0),
            ],
        };
        // Two 24GB GPUs -> 48GB serving capacity; CPU not counted when GPUs present.
        assert!((profile.serving_vram_gb() - 48.0).abs() < 0.01);
        assert_eq!(profile.serving_backend(), Backend::Cuda);
    }

    #[test]
    fn node_profile_falls_back_to_cpu_when_no_gpu() {
        let profile = NodeProfile {
            llama_commit: "abc".into(),
            cpu_arch: "x86_64".into(),
            os: "linux".into(),
            devices: vec![cpu_device(128.0)],
        };
        assert!((profile.serving_vram_gb() - 128.0).abs() < 0.01);
        assert_eq!(profile.serving_backend(), Backend::Cpu);
        assert_eq!(profile.serving_cap_key(), "x86_64");
    }

    #[test]
    fn node_profile_projects_to_member() {
        let profile = NodeProfile {
            llama_commit: "abc123".into(),
            cpu_arch: "aarch64".into(),
            os: "macos".into(),
            devices: vec![gpu_device(Backend::Metal, 64.0)],
        };
        let addr = Address::new([7; 32]);
        let m = profile.to_member(
            "did:tenzro:machine:m7",
            addr,
            "10.0.0.7:8080",
            MemberReachability::LocalDirect,
        );
        assert_eq!(m.machine_did, "did:tenzro:machine:m7");
        assert_eq!(m.address, addr);
        assert_eq!(m.backend, Backend::Metal);
        assert_eq!(m.llama_commit, "abc123");
        assert!((m.vram_gb - 64.0).abs() < 0.01);
        assert_eq!(m.reachability, MemberReachability::LocalDirect);
    }

    #[test]
    fn split_inference_admits_only_verified_members() {
        use tenzro_cluster::membership::testing::{Key, RP_ID, custody_digest, membership};
        use tenzro_cluster::{MembershipBook, VerifiedMembership};

        let (op, a, b, stranger) = (Key::new(1), Key::new(2), Key::new(3), Key::new(4));
        let with_did = |key: &Key, addr: u8| ClusterMember {
            machine_did: key.machine_did(),
            ..member(addr, 24.0, "c", MemberReachability::LocalDirect)
        };
        let candidates = || vec![with_did(&a, 1), with_did(&stranger, 2), with_did(&b, 3)];
        let verify = |seq, keys: &[&Key]| {
            VerifiedMembership::verify(membership(&op, "lab", seq, keys), RP_ID, custody_digest)
                .unwrap()
        };

        let mut book = MembershipBook::new();
        let first = verify(1, &[&a, &b]);
        let cluster = first.cluster_did().to_string();
        book.offer(first).unwrap();
        let admitted = admit_members(book.get(&cluster).unwrap(), candidates());
        let dids: Vec<_> = admitted.iter().map(|m| m.machine_did.clone()).collect();
        assert_eq!(dids, vec![a.machine_did(), b.machine_did()]);

        // The operator removes b; the next plan no longer sees it.
        book.offer(verify(2, &[&a])).unwrap();
        let admitted = admit_members(book.get(&cluster).unwrap(), candidates());
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].machine_did, a.machine_did());
    }

    #[test]
    fn local_device_vram_gb_converts_bytes() {
        let d = gpu_device(Backend::Cuda, 16.0);
        assert!((d.vram_gb() - 16.0).abs() < 0.01);
    }

    #[test]
    fn launch_plan_tensor_split_matches_stage_layer_counts() {
        // The clustered model load relies on tensor_split[i] being stage i's
        // layer count, in the same order as stages, so llama.cpp's proportional
        // device fill reproduces the planner's layer ranges exactly.
        let a = member(1, 72.0, "c", MemberReachability::LocalDirect);
        let b = member(2, 24.0, "c", MemberReachability::LocalDirect);
        let model = shape(80, 8192, 70.0);
        let probes = HashMap::new();
        let gate = order_stages(
            a.address,
            &[a.clone(), b.clone()],
            &probes,
            model.activation_bytes_per_token(),
        );
        let assignment = assign_layers(model.layers, &[a.clone(), b.clone()]);
        let plan = launch_plan(&gate, &assignment, &[a.clone(), b.clone()]);

        assert_eq!(plan.stages.len(), plan.tensor_split.len());
        for (stage, &split) in plan.stages.iter().zip(plan.tensor_split.iter()) {
            assert_eq!(stage.stage.layer_count(), split);
        }
        // Splits cover every layer exactly once.
        let total: u32 = plan.tensor_split.iter().sum();
        assert_eq!(total, model.layers);
    }

    /// The registry's largest models are planned, never refused for size: a
    /// model that fits no member clusters, every member holds a non-empty
    /// range, and the ranges cover every layer exactly once.
    #[test]
    fn registry_scale_models_are_planned_across_members() {
        // (name, layers, hidden, weights GB, member VRAM GB, members)
        let cases: [(&str, u32, u32, f32, f32, u8); 6] = [
            // Nemotron 3 Ultra UD-IQ1_M: 108 layers, 188 GB, two 128 GB boxes.
            ("ultra-iq1m", 108, 8192, 188.0, 128.0, 2),
            // Ultra UD-Q4_K_XL: 360 GB over four 128 GB boxes.
            ("ultra-q4kxl", 108, 8192, 360.2, 128.0, 4),
            // Ultra BF16: 1.1 TB over ten 128 GB boxes.
            ("ultra-bf16", 108, 8192, 1099.0, 128.0, 10),
            // Nemotron 3.5 Bolt 74B Q8_0 over three 32 GB cards.
            ("bolt74-q8", 88, 4096, 78.9, 32.0, 3),
            // Mistral Large 4 UD-IQ1_S: 72 layers, 233 GB, two 128 GB boxes.
            ("ml4-iq1s", 72, 6144, 233.0, 128.0, 2),
            // Mistral Large 4 Q8_0: 1.1 TB over nine 128 GB boxes.
            ("ml4-q8", 72, 6144, 1115.0, 128.0, 9),
        ];
        for (name, layers, hidden, gb, vram, n) in cases {
            let members: Vec<ClusterMember> = (1..=n)
                .map(|i| member(i, vram, "c", MemberReachability::LocalDirect))
                .collect();
            let model = shape(layers, hidden, gb);
            assert_eq!(
                should_cluster(model, members.iter(), false),
                FitDecision::ClusterRequired,
                "{name}"
            );
            assert!(
                members.iter().map(|m| m.vram_gb).sum::<f32>() >= gb,
                "{name}: the members together must hold the weights"
            );
            let plan = assign_layers(layers, &members);
            assert_eq!(
                plan.len(),
                members.len(),
                "{name}: every member holds a range"
            );
            let mut covered = 0u32;
            for st in plan.values() {
                assert!(st.layer_count() > 0, "{name}");
                covered += st.layer_count();
            }
            assert_eq!(covered, layers, "{name}: every layer exactly once");
        }
    }

    /// Nemotron 3 Ultra does not run on one machine at any build the registry
    /// publishes (the smallest is 175 GiB), so it is planned, from its own
    /// registry entry, across two 128 GB nodes: the entry names that tier, the
    /// fit policy asks for a cluster, both nodes are admitted, each gets half
    /// of the 108 layers, and the weights share plus the cache of a
    /// 1M-token request fit each node.
    #[test]
    fn ultra_smallest_build_is_planned_across_two_nodes_from_its_registry_entry() {
        tenzro_catalog::install_test_seed();
        let e = crate::catalog::get_model_by_id("nemotron-3-ultra-550b-a55b-ud-iq1-m")
            .expect("the smallest Ultra build is in the registry");
        assert!(
            e.hardware_tiers
                .iter()
                .any(|t| t.nodes == 2 && t.memory_gb_per_node == 128),
            "{:?}",
            e.hardware_tiers
        );
        let weights_gib = e.size_bytes as f32 / 1_073_741_824.0;
        let model = shape(108, 8192, weights_gib);
        // Two nodes with 128 GB of unified memory each, about 117 GiB usable.
        let nodes: Vec<ClusterMember> = (1..=2)
            .map(|i| member(i, 117.0, "c", MemberReachability::LocalDirect))
            .collect();
        assert_eq!(single_box_fit(model, nodes.iter()), None);
        assert_eq!(
            should_cluster(model, nodes.iter(), false),
            FitDecision::ClusterRequired
        );
        let gate = hardware_gate("c", weights_gib / 108.0, nodes.clone());
        assert_eq!(gate.admitted.len(), 2);
        assert!(gate.rejected.is_empty());
        let plan = assign_layers(108, &gate.admitted);
        let layers: Vec<u32> = plan.values().map(|s| s.layer_count()).collect();
        assert_eq!(layers.iter().sum::<u32>(), 108);
        assert!(layers.iter().all(|n| *n == 54), "{layers:?}");
        // Cache of a 1M-token request on the hybrid layout (12 attention
        // layers, 2 KV heads of 128, plus the fixed recurrent state).
        let kv = 2.0f32 * 12.0 * 2.0 * 128.0 * 2.0 * 1_048_576.0 / 1_073_741_824.0;
        let per_node = weights_gib / 2.0 + (kv + 0.4) / 2.0;
        assert!(per_node < 117.0, "{per_node} GiB per node");
    }
}
