//! What serving a language model on the batching engine allocates.
//!
//! The batching engine of the open-source Praecise engine sizes itself at
//! load: it gives every sequence slot a whole context of KV cache in a stream
//! of its own, fits as many slots as its KV budget holds (at least one, at
//! most `max_slots`), keeps one more sequence for moving sessions between
//! engines, holds the recurrent state of a hybrid model once per sequence and
//! once more per token it may draft, and reserves prompt checkpoints for
//! prefix reuse out of a checkpoint budget. Its two budgets come from
//! `BATCH_KV_MEMORY` and `BATCH_CHECKPOINT_MEMORY` when set, otherwise from
//! the memory it finds free (half of it for KV; half of what is left above a
//! tenth of the machine for checkpoints).
//!
//! [`allocation`] applies those same rules to the figures of one model so a
//! node can see the whole footprint before the engine takes it, and refuse a
//! load that does not fit instead of finding out from the kernel. Measured
//! on a unified-memory host serving a 27B hybrid model at 32768 tokens: KV
//! 43008 MiB for 21 sequences, recurrent state 15710 MiB, 18 checkpoints per
//! slot of 156.9 MB over 20 slots, and two compute buffers of about 2.5 GB;
//! the test `a_hybrid_model_on_free_memory_budgets_matches_the_measured_load`
//! reproduces each of them.

use serde::{Deserialize, Serialize};

/// The engine rounds each sequence's context up to this many positions.
pub const CONTEXT_PAD: u32 = 256;

/// Most sequence slots the engine opens by default.
pub const MAX_SLOTS: usize = 32;

/// Most prompt checkpoints the engine keeps per slot by default.
pub const MAX_CHECKPOINTS_PER_SLOT: usize = 32;

/// Compute buffers per context, as a share of the weights. Measured at
/// 2.52 GB for 16.7 GB of weights with the engine's 2048-token batch.
pub const COMPUTE_PCT: u64 = 15;

/// Figures of one model that decide its footprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelFigures {
    /// Weights resident once loaded.
    pub weights_bytes: u64,
    /// KV cache one sequence holds per token of context.
    pub kv_bytes_per_token: u64,
    /// Fixed state one sequence holds whatever its length: the recurrent
    /// state of a hybrid or recurrent model, zero for pure attention.
    pub sequence_state_bytes: u64,
    /// One prompt checkpoint; zero when the model needs none (pure
    /// attention rewinds by position).
    pub checkpoint_bytes: u64,
}

/// The budgets the engine sizes against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineBudgets {
    /// Bytes the KV cache of all slots may take.
    pub kv_bytes: u64,
    /// Bytes prompt checkpoints of all slots may take.
    pub checkpoint_bytes: u64,
    /// Most sequence slots.
    pub max_slots: usize,
    /// Most checkpoints per slot.
    pub checkpoints_per_slot: usize,
}

impl EngineBudgets {
    /// The budgets the engine will use: `BATCH_KV_MEMORY`,
    /// `BATCH_CHECKPOINT_MEMORY`, `BATCH_MAX_SLOTS` and
    /// `BATCH_PROMPT_CHECKPOINTS` when set, otherwise its own defaults and
    /// its own share of `free_bytes` (memory free once the weights are in) on
    /// a machine of `total_bytes`.
    pub fn resolve(free_bytes: u64, total_bytes: u64) -> Self {
        let env = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        let kv_bytes = env("BATCH_KV_MEMORY").unwrap_or(free_bytes / 2);
        let checkpoint_bytes = env("BATCH_CHECKPOINT_MEMORY").unwrap_or_else(|| {
            let keep = (total_bytes / 10).max(2 << 30);
            free_bytes.saturating_sub(keep) / 2
        });
        let checkpoints_per_slot = std::env::var("BATCH_PROMPT_CHECKPOINTS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(MAX_CHECKPOINTS_PER_SLOT);
        Self {
            kv_bytes,
            checkpoint_bytes,
            max_slots: env("BATCH_MAX_SLOTS")
                .filter(|n| *n > 0)
                .map_or(MAX_SLOTS, |n| usize::try_from(n).unwrap_or(usize::MAX)),
            checkpoints_per_slot,
        }
    }
}

/// Everything a batched serve holds, by part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServeAllocation {
    /// Context per sequence, in tokens, as requested.
    pub context_length: u32,
    /// Sequence slots the engine will open.
    pub slots: usize,
    pub weights_bytes: u64,
    pub kv_cache_bytes: u64,
    /// Recurrent state of every sequence, including the copies kept to roll
    /// back rejected drafts.
    pub sequence_state_bytes: u64,
    /// Prompt checkpoints at the most the budget lets the engine keep.
    pub checkpoint_bytes: u64,
    pub compute_bytes: u64,
}

impl ServeAllocation {
    pub fn total_bytes(&self) -> u64 {
        self.weights_bytes
            .saturating_add(self.kv_cache_bytes)
            .saturating_add(self.sequence_state_bytes)
            .saturating_add(self.checkpoint_bytes)
            .saturating_add(self.compute_bytes)
    }

    /// Everything but the weights: what the engine adds once they are in.
    pub fn beyond_weights_bytes(&self) -> u64 {
        self.total_bytes().saturating_sub(self.weights_bytes)
    }
}

/// What serving `model` at `context_length` tokens per sequence allocates,
/// drafting up to `drafted` tokens per step (0 without speculation).
pub fn allocation(
    model: &ModelFigures,
    context_length: u32,
    drafted: u8,
    budgets: &EngineBudgets,
) -> ServeAllocation {
    let per_slot = model.sequence_state_bytes.saturating_add(
        model
            .kv_bytes_per_token
            .saturating_mul(u64::from(context_length)),
    );
    let slots = budgets
        .kv_bytes
        .checked_div(per_slot)
        .map_or(budgets.max_slots, |n| {
            usize::try_from(n).unwrap_or(usize::MAX)
        })
        .clamp(1, budgets.max_slots.max(1));
    // One sequence past the slots stages sessions moved between engines.
    let sequences = slots as u64 + 1;
    let padded = u64::from(context_length.div_ceil(CONTEXT_PAD) * CONTEXT_PAD);
    let kv_cache_bytes = sequences
        .saturating_mul(padded)
        .saturating_mul(model.kv_bytes_per_token);
    let rollback_copies = if drafted > 0 && model.sequence_state_bytes > 0 {
        u64::from(drafted)
    } else {
        0
    };
    let sequence_state_bytes = model
        .sequence_state_bytes
        .saturating_mul(sequences)
        .saturating_mul(1 + rollback_copies);
    let checkpoint_bytes = budgets
        .checkpoint_bytes
        .checked_div(model.checkpoint_bytes)
        .map_or(0, |fit| {
            let per_slot = (fit / slots as u64).min(budgets.checkpoints_per_slot as u64);
            per_slot
                .saturating_mul(slots as u64)
                .saturating_mul(model.checkpoint_bytes)
        });
    // A draft context beside the target has buffers of its own.
    let contexts = if drafted > 0 { 2 } else { 1 };
    let compute_bytes = model.weights_bytes / 100 * COMPUTE_PCT * contexts;
    ServeAllocation {
        context_length,
        slots,
        weights_bytes: model.weights_bytes,
        kv_cache_bytes,
        sequence_state_bytes,
        checkpoint_bytes,
        compute_bytes,
    }
}

/// The engine budgets a node sets for itself out of the resident tier's
/// ceiling: three eighths for the KV cache and a sixteenth for prompt
/// checkpoints, so a model whose weights take up to half the tier still
/// fits beside its own cache. Without them the engine takes half of
/// whatever memory is free for KV and most of the rest for checkpoints,
/// whatever else the machine runs.
pub fn node_engine_budgets(resident_ceiling_bytes: u64) -> (u64, u64) {
    (resident_ceiling_bytes / 8 * 3, resident_ceiling_bytes / 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;

    /// The 27B hybrid model of the measured load: 16 attention layers of
    /// 4 KV heads of 256 at f16, 149.62 MiB of recurrent state per sequence.
    fn hybrid_27b() -> ModelFigures {
        ModelFigures {
            weights_bytes: 16_735 * MIB,
            kv_bytes_per_token: 65_536,
            sequence_state_bytes: 156_894_364,
            checkpoint_bytes: 156_894_364,
        }
    }

    #[test]
    fn a_hybrid_model_on_free_memory_budgets_matches_the_measured_load() {
        // The budgets the engine logged for that load.
        let budgets = EngineBudgets {
            kv_bytes: 46_875_064_320,
            checkpoint_bytes: 58_797_503_078,
            max_slots: 32,
            checkpoints_per_slot: MAX_CHECKPOINTS_PER_SLOT,
        };
        let a = allocation(&hybrid_27b(), 32_768, 4, &budgets);
        assert_eq!(a.slots, 20);
        assert_eq!(a.kv_cache_bytes, 43_008 * MIB);
        // 15710.62 MiB in the log.
        assert_eq!(a.sequence_state_bytes / MIB, 15_710);
        assert_eq!(a.checkpoint_bytes, 18 * 20 * 156_894_364);
        // About 2.5 GB per context, two contexts.
        assert!((4_900 * MIB..5_400 * MIB).contains(&a.compute_bytes));
        // More than the whole machine: the load that drove it out of memory.
        assert!(a.total_bytes() > 121 * GIB);
    }

    #[test]
    fn the_context_is_padded_per_sequence() {
        let budgets = EngineBudgets {
            kv_bytes: 43_484_907_520,
            checkpoint_bytes: 0,
            max_slots: 32,
            checkpoints_per_slot: MAX_CHECKPOINTS_PER_SLOT,
        };
        // 66082 tokens on the budget logged for that load: 9 slots, each
        // stream 66304 positions, 41440 MiB of KV.
        let a = allocation(&hybrid_27b(), 66_082, 4, &budgets);
        assert_eq!(a.slots, 9);
        assert_eq!(a.kv_cache_bytes, 41_440 * MIB);
    }

    #[test]
    fn node_budgets_fit_the_model_inside_a_validator_tier() {
        // 121 GiB machine, 24 GiB validator reserve, 60% resident tier.
        let ceiling = (121 - 24) * GIB / 100 * 60;
        let (kv, ck) = node_engine_budgets(ceiling);
        let budgets = EngineBudgets {
            kv_bytes: kv,
            checkpoint_bytes: ck,
            max_slots: 32,
            checkpoints_per_slot: MAX_CHECKPOINTS_PER_SLOT,
        };
        let a = allocation(&hybrid_27b(), 32_768, 4, &budgets);
        assert!(a.total_bytes() <= ceiling, "{a:?} over {ceiling}");
        assert!(a.slots >= 8, "{a:?}");
        // The full trained context of 262144 tokens gets one slot whose
        // cache alone is larger than the KV budget, and does not fit.
        let long = allocation(&hybrid_27b(), 262_144, 4, &budgets);
        assert_eq!(long.slots, 1);
        assert!(long.kv_cache_bytes > kv);
    }

    #[test]
    fn pure_attention_holds_no_state_or_checkpoints() {
        let model = ModelFigures {
            weights_bytes: 8 * GIB,
            kv_bytes_per_token: 131_072,
            sequence_state_bytes: 0,
            checkpoint_bytes: 0,
        };
        let budgets = EngineBudgets {
            kv_bytes: 16 * GIB,
            checkpoint_bytes: 8 * GIB,
            max_slots: 4,
            checkpoints_per_slot: MAX_CHECKPOINTS_PER_SLOT,
        };
        let a = allocation(&model, 8192, 0, &budgets);
        assert_eq!(a.slots, 4);
        assert_eq!(a.sequence_state_bytes, 0);
        assert_eq!(a.checkpoint_bytes, 0);
        assert_eq!(a.kv_cache_bytes, 5 * 8192 * 131_072);
        assert_eq!(a.compute_bytes, 8 * GIB / 100 * COMPUTE_PCT);
    }
}
