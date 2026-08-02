//! What serving a model will cost, and what to do about it.
//!
//! # Advise, do not block
//!
//! An operator asking to serve a model that may not fit is making a judgement
//! about their own machine. They may know something this code does not — that
//! the other tenant is about to leave, that they are willing to swap, that
//! they simply want to try. So nothing here refuses. [`ServePlan::fits`]
//! reports, [`ServePlan::advice`] suggests, and the decision stays with the
//! person who owns the hardware.
//!
//! That is deliberate and worth preserving. The memory budget already refuses
//! loads that would overcommit the node — that bound exists to stop one model
//! taking down another. This module is upstream of it and answers a different
//! question: *should you want to?*
//!
//! # KV cache is the term that surprises people
//!
//! Operators size a model by its weights, because that is the number in the
//! catalog. But KV cache scales with **context length times concurrency**, and
//! at long contexts it dwarfs the weights: a 21 GB model at 262k context and
//! 8 concurrent requests can want more cache than weights. Quoting only the
//! file size is how a serve that "obviously fits" ends up thrashing.
//!
//! So [`estimate_footprint`] prices weights, KV, and activations separately,
//! and the advice targets whichever term actually dominates.

use serde::{Deserialize, Serialize};

/// Bytes of KV cache per token, per layer, per concurrent sequence.
///
/// From the standard arithmetic `2 * n_kv_heads * head_dim * bytes_per_elem`
/// — two tensors (K and V), at a grouped-query config of 8 KV heads and a
/// head dimension of 128, in fp16: `2 * 8 * 128 * 2 = 4096`.
///
/// An approximation, because the catalog records none of those three numbers.
/// It is checkable rather than magic: at 32k context over 64 layers this puts
/// a single sequence at ~8.6 GB, which is the figure operators report for
/// 32B-class models, so the assumed config is representative of what is
/// actually being served.
///
/// Deliberately not lowered for cache quantization or MQA. Under-estimating
/// here produces an operator who was told it would fit and then ran out;
/// over-estimating produces one who was warned unnecessarily. The second is
/// much cheaper.
pub const KV_BYTES_PER_TOKEN_PER_LAYER: u64 = 4096;

/// Layer count assumed when the catalog does not record one.
///
/// Transformer depth scales roughly with the log of parameter count over the
/// range the catalog covers; 32 is the mode for the 7B–35B band that most
/// serving happens in.
pub const ASSUMED_LAYERS: u64 = 32;

/// Fraction of weight size taken by activations and framework overhead.
pub const ACTIVATION_OVERHEAD_PCT: u64 = 15;

/// What a serve would consume, broken down so the dominant term is visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Footprint {
    /// Model weights, from the catalog's on-disk size.
    pub weights_bytes: u64,
    /// KV cache across all concurrent sequences at the requested context.
    pub kv_cache_bytes: u64,
    /// Activations and framework overhead.
    pub activation_bytes: u64,
}

impl Footprint {
    /// Everything the serve will hold.
    pub fn total_bytes(&self) -> u64 {
        self.weights_bytes
            .saturating_add(self.kv_cache_bytes)
            .saturating_add(self.activation_bytes)
    }

    /// Whether KV cache, not weights, is the dominant cost.
    ///
    /// When true the useful advice is about context and concurrency; when
    /// false it is about quantization. Getting this the wrong way round sends
    /// an operator to shrink a model when their real problem is a 262k
    /// context they did not need.
    pub fn kv_dominates(&self) -> bool {
        self.kv_cache_bytes > self.weights_bytes
    }
}

/// What the machine has right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    /// Bytes still claimable in the resident tier.
    pub resident_available_bytes: u64,
    /// The resident tier's ceiling.
    pub resident_ceiling_bytes: u64,
    /// Free disk at the data directory.
    pub storage_available_bytes: u64,
    /// Concurrent request slots free across the node.
    pub free_concurrency: u32,
}

/// A suggestion, with the saving it would produce.
///
/// Every variant carries a number. "Use a smaller quantization" is not
/// actionable; "UD-Q3_K_XL would save 4.2 GB" is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "advice", rename_all = "kebab-case")]
pub enum Advice {
    /// Serve at a lower precision.
    LowerQuantization {
        /// Tier to move to.
        tier: String,
        /// Bytes this would free.
        saves_bytes: u64,
        /// What it costs in quality, in plain terms.
        quality_note: String,
    },
    /// Shorten the context window.
    ReduceContext {
        /// Suggested context length.
        context_length: u32,
        /// Bytes this would free.
        saves_bytes: u64,
    },
    /// Serve fewer requests at once.
    ReduceConcurrency {
        /// Suggested concurrency.
        max_concurrent: u32,
        /// Bytes this would free.
        saves_bytes: u64,
    },
    /// Spread the model across more than one machine.
    DistributeAcrossCluster {
        /// How many machines the model would need.
        machines_needed: u32,
        /// How many are currently reachable.
        machines_available: u32,
    },
    /// Turn on speculative decoding.
    EnableSpeculativeDecoding {
        /// The drafter to pair with.
        drafter_id: String,
    },
    /// Prefer a mixture-of-experts model of similar quality.
    ///
    /// Matters most on unified-memory hardware, where a dense model's whole
    /// weight set is read per token: community measurement puts a dense 31B
    /// at roughly 7 tok/s on a GB10, while an MoE with 3B active runs far
    /// faster at comparable quality.
    PreferMoe {
        /// Why, in terms of measured behaviour.
        reason: String,
    },
}

/// The answer to "what happens if I serve this?"
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServePlan {
    /// What it would consume.
    pub footprint: Footprint,
    /// Whether it fits in the resident tier as requested.
    ///
    /// **Not a permission.** An operator may proceed regardless; this only
    /// says what the node expects.
    pub fits: bool,
    /// Resident bytes left afterwards, or 0 if it would overcommit.
    pub remaining_after_bytes: u64,
    /// How much more would be needed to fit. Zero when it fits.
    pub shortfall_bytes: u64,
    /// Suggestions, most effective first.
    pub advice: Vec<Advice>,
    /// What proceeding anyway would mean, when it does not fit.
    ///
    /// `None` when it fits. Present so a CLI can show the operator the
    /// consequence next to the confirm prompt rather than after it.
    pub risk_if_forced: Option<String>,
}

/// Estimate what a serve will hold.
///
/// `weights_bytes` is the on-disk size; `layers` comes from the GGUF header
/// where known and falls back to [`ASSUMED_LAYERS`].
pub fn estimate_footprint(
    weights_bytes: u64,
    context_length: u32,
    max_concurrent: u32,
    layers: Option<u64>,
) -> Footprint {
    let layers = layers.unwrap_or(ASSUMED_LAYERS);
    let kv_cache_bytes = u64::from(context_length)
        .saturating_mul(layers)
        .saturating_mul(KV_BYTES_PER_TOKEN_PER_LAYER)
        .saturating_mul(u64::from(max_concurrent.max(1)));
    Footprint {
        weights_bytes,
        kv_cache_bytes,
        activation_bytes: weights_bytes / 100 * ACTIVATION_OVERHEAD_PCT,
    }
}

/// Inputs describing the serve being considered.
///
/// Not `Eq`: bits-per-weight is a float, and exact equality is not a
/// meaningful comparison on it.
#[derive(Debug, Clone, PartialEq)]
pub struct ServeRequest {
    /// On-disk weight size at the chosen quantization.
    pub weights_bytes: u64,
    /// Requested context length.
    pub context_length: u32,
    /// Requested concurrency.
    pub max_concurrent: u32,
    /// Transformer depth, when known.
    pub layers: Option<u64>,
    /// Bits per weight of the current tier, for sizing a step down.
    pub current_bits_per_weight: f32,
    /// A lower tier available for this model, if any: `(name, bits)`.
    pub lower_tier: Option<(String, f32)>,
    /// A vocab-matched drafter, if the catalog pairs one.
    pub drafter_id: Option<String>,
    /// Whether this is a dense model rather than an MoE.
    pub is_dense: bool,
    /// Machines reachable for a distributed serve, excluding this one.
    pub cluster_peers: u32,
}

/// Work out what serving this would cost and what to suggest.
///
/// Advice is ordered by how much it saves, so the first item is the one worth
/// doing. It is produced whether or not the model fits: an operator with room
/// to spare may still want to know that halving their context would double
/// their concurrency.
pub fn plan(request: &ServeRequest, snapshot: &ResourceSnapshot) -> ServePlan {
    let footprint = estimate_footprint(
        request.weights_bytes,
        request.context_length,
        request.max_concurrent,
        request.layers,
    );
    let total = footprint.total_bytes();
    let available = snapshot.resident_available_bytes;
    let fits = total <= available;

    let mut advice = Vec::new();

    // Quantization, when weights dominate. Stepping down does nothing for a
    // KV-bound serve, so suggesting it there would waste the operator's time.
    if !footprint.kv_dominates()
        && let Some((tier, bits)) = &request.lower_tier
        && *bits < request.current_bits_per_weight
        && request.current_bits_per_weight > 0.0
    {
        let ratio = f64::from(*bits) / f64::from(request.current_bits_per_weight);
        let new_weights = (request.weights_bytes as f64 * ratio) as u64;
        advice.push(Advice::LowerQuantization {
            tier: tier.clone(),
            saves_bytes: request.weights_bytes.saturating_sub(new_weights),
            quality_note: quality_note_for(*bits),
        });
    }

    // Context, when KV dominates. Halving is the useful unit: it halves the
    // cache, and most workloads never approach the context they were given.
    if footprint.kv_dominates() && request.context_length > 4096 {
        let halved = request.context_length / 2;
        let after = estimate_footprint(
            request.weights_bytes,
            halved,
            request.max_concurrent,
            request.layers,
        );
        advice.push(Advice::ReduceContext {
            context_length: halved,
            saves_bytes: total.saturating_sub(after.total_bytes()),
        });
    }

    // Concurrency, when there is more than one to give up.
    if request.max_concurrent > 1 {
        let halved = (request.max_concurrent / 2).max(1);
        let after = estimate_footprint(
            request.weights_bytes,
            request.context_length,
            halved,
            request.layers,
        );
        let saves = total.saturating_sub(after.total_bytes());
        if saves > 0 {
            advice.push(Advice::ReduceConcurrency {
                max_concurrent: halved,
                saves_bytes: saves,
            });
        }
    }

    // Distribution, only when it does not fit and there is somewhere to go.
    if !fits && request.cluster_peers > 0 && available > 0 {
        let machines_needed = total.div_ceil(available).max(2) as u32;
        advice.push(Advice::DistributeAcrossCluster {
            machines_needed,
            machines_available: request.cluster_peers + 1,
        });
    }

    // Throughput advice, which applies whether or not memory is tight.
    if let Some(drafter) = &request.drafter_id {
        advice.push(Advice::EnableSpeculativeDecoding {
            drafter_id: drafter.clone(),
        });
    }
    if request.is_dense && request.weights_bytes > 15_000_000_000 {
        advice.push(Advice::PreferMoe {
            reason: "dense models read their whole weight set per token; on unified-memory \
                     hardware a 31B dense model measures around 7 tok/s, where an MoE with 3B \
                     active runs far faster at comparable quality"
                .to_string(),
        });
    }

    // Most effective first, so the operator reads the fix that matters.
    advice.sort_by_key(|a| std::cmp::Reverse(saving_of(a)));

    ServePlan {
        footprint,
        fits,
        remaining_after_bytes: available.saturating_sub(total),
        shortfall_bytes: total.saturating_sub(available),
        risk_if_forced: (!fits).then(|| {
            format!(
                "This needs {:.1} GB more than the resident tier has free. Serving it anyway \
                 will evict other models to make room, and if nothing is evictable the load \
                 will be refused. On a machine where accelerator memory is shared with system \
                 memory, overcommitting can also slow everything else running on it.",
                total.saturating_sub(available) as f64 / 1e9
            )
        }),
        advice,
    }
}

/// How much a piece of advice saves, for ordering.
fn saving_of(a: &Advice) -> u64 {
    match a {
        Advice::LowerQuantization { saves_bytes, .. }
        | Advice::ReduceContext { saves_bytes, .. }
        | Advice::ReduceConcurrency { saves_bytes, .. } => *saves_bytes,
        // Not memory savings; they rank below anything that frees bytes but
        // above nothing.
        Advice::DistributeAcrossCluster { .. } => 1,
        Advice::EnableSpeculativeDecoding { .. } | Advice::PreferMoe { .. } => 0,
    }
}

/// Plain-language quality note for a precision tier.
fn quality_note_for(bits: f32) -> String {
    if bits >= 8.0 {
        "essentially lossless".to_string()
    } else if bits >= 4.5 {
        "differences are subtle and usually need close inspection to spot".to_string()
    } else if bits >= 3.0 {
        "noticeable on hard prompts, still good for most work".to_string()
    } else if bits >= 2.0 {
        "clearly degraded; worth it only if the model otherwise will not fit".to_string()
    } else {
        "heavily degraded — a last resort so a frontier model runs at all".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1_000_000_000;

    fn snapshot(available_gb: u64) -> ResourceSnapshot {
        ResourceSnapshot {
            resident_available_bytes: available_gb * GB,
            resident_ceiling_bytes: 63 * GB,
            storage_available_bytes: 2_500 * GB,
            free_concurrency: 40,
        }
    }

    fn request() -> ServeRequest {
        ServeRequest {
            weights_bytes: 21 * GB,
            context_length: 8192,
            max_concurrent: 4,
            layers: Some(48),
            current_bits_per_weight: 4.9,
            lower_tier: Some(("UD-Q3_K_XL".to_string(), 3.9)),
            drafter_id: None,
            is_dense: false,
            cluster_peers: 0,
        }
    }

    #[test]
    fn a_serve_that_fits_says_so_and_reports_what_is_left() {
        let outcome = plan(&request(), &snapshot(63));
        assert!(outcome.fits);
        assert!(outcome.risk_if_forced.is_none());
        assert_eq!(outcome.shortfall_bytes, 0);
        assert!(outcome.remaining_after_bytes > 0);
    }

    #[test]
    fn a_serve_that_does_not_fit_is_reported_not_refused() {
        // The governing principle: the operator decides.
        let big = ServeRequest {
            weights_bytes: 75 * GB,
            ..request()
        };
        let outcome = plan(&big, &snapshot(63));
        assert!(!outcome.fits);
        assert!(outcome.shortfall_bytes > 0);
        assert_eq!(outcome.remaining_after_bytes, 0);
        let risk = outcome
            .risk_if_forced
            .expect("must explain the consequence");
        assert!(risk.contains("evict"), "{risk}");
        assert!(
            risk.contains("GB more"),
            "the operator needs the number: {risk}"
        );
    }

    #[test]
    fn kv_cache_dominates_at_long_context_and_the_advice_follows() {
        // The term that surprises people. A 21 GB model at 262k context and 8
        // concurrent sequences wants more cache than weights, and telling the
        // operator to shrink the model would be the wrong fix.
        let long = ServeRequest {
            context_length: 262_144,
            max_concurrent: 8,
            ..request()
        };
        let f = estimate_footprint(long.weights_bytes, 262_144, 8, Some(48));
        assert!(
            f.kv_dominates(),
            "kv {} should exceed weights {}",
            f.kv_cache_bytes,
            f.weights_bytes
        );

        let outcome = plan(&long, &snapshot(200));
        assert!(
            outcome
                .advice
                .iter()
                .any(|a| matches!(a, Advice::ReduceContext { .. })),
            "should suggest context, got {:?}",
            outcome.advice
        );
        assert!(
            !outcome
                .advice
                .iter()
                .any(|a| matches!(a, Advice::LowerQuantization { .. })),
            "quantization does nothing for a KV-bound serve"
        );
    }

    #[test]
    fn quantization_is_suggested_when_weights_dominate() {
        let outcome = plan(&request(), &snapshot(63));
        let q = outcome
            .advice
            .iter()
            .find_map(|a| match a {
                Advice::LowerQuantization {
                    tier, saves_bytes, ..
                } => Some((tier.clone(), *saves_bytes)),
                _ => None,
            })
            .expect("weights dominate at 8k context");
        assert_eq!(q.0, "UD-Q3_K_XL");
        // 4.9 -> 3.9 bits on 21 GB is roughly 4 GB.
        assert!(q.1 > 3 * GB && q.1 < 6 * GB, "saved {}", q.1);
    }

    #[test]
    fn advice_is_ordered_by_how_much_it_saves() {
        // An operator reads the first line. It should be the one that matters.
        let outcome = plan(&request(), &snapshot(63));
        let savings: Vec<u64> = outcome.advice.iter().map(saving_of).collect();
        for w in savings.windows(2) {
            assert!(w[0] >= w[1], "advice out of order: {savings:?}");
        }
    }

    #[test]
    fn every_suggestion_carries_a_number() {
        // "Use a smaller quant" is not actionable; "saves 4.2 GB" is.
        let outcome = plan(&request(), &snapshot(63));
        for a in &outcome.advice {
            match a {
                Advice::LowerQuantization { saves_bytes, .. }
                | Advice::ReduceContext { saves_bytes, .. }
                | Advice::ReduceConcurrency { saves_bytes, .. } => {
                    assert!(*saves_bytes > 0, "{a:?}");
                }
                Advice::DistributeAcrossCluster {
                    machines_needed, ..
                } => assert!(*machines_needed >= 2),
                Advice::EnableSpeculativeDecoding { drafter_id } => {
                    assert!(!drafter_id.is_empty())
                }
                Advice::PreferMoe { reason } => assert!(reason.contains("tok/s")),
            }
        }
    }

    #[test]
    fn clustering_is_offered_only_when_it_does_not_fit_and_peers_exist() {
        let big = ServeRequest {
            weights_bytes: 200 * GB,
            cluster_peers: 3,
            ..request()
        };
        let outcome = plan(&big, &snapshot(63));
        let d = outcome
            .advice
            .iter()
            .find_map(|a| match a {
                Advice::DistributeAcrossCluster {
                    machines_needed,
                    machines_available,
                } => Some((*machines_needed, *machines_available)),
                _ => None,
            })
            .expect("should offer distribution");
        assert!(d.0 >= 2);
        assert_eq!(d.1, 4, "three peers plus this machine");

        // With no peers there is nowhere to distribute to, so suggesting it
        // would be noise.
        let alone = ServeRequest {
            cluster_peers: 0,
            ..big
        };
        assert!(
            !plan(&alone, &snapshot(63))
                .advice
                .iter()
                .any(|a| matches!(a, Advice::DistributeAcrossCluster { .. }))
        );
    }

    #[test]
    fn a_fitting_serve_still_gets_throughput_advice() {
        // Memory is not the only thing worth improving.
        let with_drafter = ServeRequest {
            drafter_id: Some("gemma4-31b-mtp-draft".to_string()),
            ..request()
        };
        let outcome = plan(&with_drafter, &snapshot(63));
        assert!(outcome.fits);
        assert!(
            outcome
                .advice
                .iter()
                .any(|a| matches!(a, Advice::EnableSpeculativeDecoding { .. }))
        );
    }

    #[test]
    fn a_large_dense_model_is_flagged_on_unified_memory_hardware() {
        let dense = ServeRequest {
            weights_bytes: 20 * GB,
            is_dense: true,
            ..request()
        };
        let outcome = plan(&dense, &snapshot(63));
        assert!(
            outcome
                .advice
                .iter()
                .any(|a| matches!(a, Advice::PreferMoe { .. })),
            "a 20 GB dense model deserves the MoE note"
        );

        // An MoE of the same size should not get it.
        let moe = ServeRequest {
            is_dense: false,
            ..dense
        };
        assert!(
            !plan(&moe, &snapshot(63))
                .advice
                .iter()
                .any(|a| matches!(a, Advice::PreferMoe { .. }))
        );
    }

    #[test]
    fn quality_notes_get_blunter_as_precision_drops() {
        assert!(quality_note_for(8.5).contains("lossless"));
        assert!(quality_note_for(4.9).contains("subtle"));
        assert!(quality_note_for(3.9).contains("most work"));
        assert!(quality_note_for(2.4).contains("will not fit"));
        assert!(quality_note_for(1.8).contains("last resort"));
    }

    #[test]
    fn concurrency_multiplies_kv_cost() {
        // Doubling concurrent requests doubles the cache, which is why it is
        // one of the dials worth offering.
        let one = estimate_footprint(10 * GB, 32_768, 1, Some(32));
        let eight = estimate_footprint(10 * GB, 32_768, 8, Some(32));
        assert_eq!(eight.kv_cache_bytes, one.kv_cache_bytes * 8);
        assert_eq!(eight.weights_bytes, one.weights_bytes, "weights load once");
    }

    #[test]
    fn a_zero_concurrency_request_is_treated_as_one() {
        // Guards the multiply; a serve always holds at least one sequence.
        let f = estimate_footprint(GB, 4096, 0, Some(32));
        assert!(f.kv_cache_bytes > 0);
    }

    #[test]
    fn an_empty_machine_and_a_full_one_both_produce_a_plan() {
        // No panics at the boundaries.
        let _ = plan(&request(), &snapshot(0));
        let _ = plan(&request(), &snapshot(10_000));
    }
}
