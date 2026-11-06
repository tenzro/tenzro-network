# Speculative Decoding for Tenzro Inference

## Implementation

Speculation runs in two places.

**Batch engine** (Praecise Engine `praecise-runtime/src/batching.rs`, `BatchSpeculation`). Every generating sequence drafts a block each step, and all blocks are verified inside the same step's one target decode. Each sequence keeps the longest prefix its own sampler agrees with, so the output is exactly what plain decoding would have produced. Three drafters: the target's own MTP head (`spec_type` 0, a draft context of type `Mtp` over the target's weights), a DFlash block drafter (1), and a DSpark drafter (2), the last two shipped as separate GGUFs. Rejected drafts are removed from both caches by position; a model with recurrent layers cannot rewind that way, so the target context keeps `n_rs_seq = n_max` recurrent snapshots per sequence to roll back to. Measured on qwen3.8-27b on a GB10, tokens per second at 1 / 4 / 16 streams:

| Drafter | 1 | 4 | 16 |
|---|---|---|---|
| none | 13.2 | 43.6 | 92.4 |
| MTP head, 4 drafted | 23.1 | 40.9 | 87.6 |
| DFlash2, 7 drafted | 32.8 | 67.4 | 102.5 |

So the MTP head drafts only while at most two sequences are generating, and a block drafter at every width (`BATCH_SPEC_MAX_ACTIVE` overrides both).

Speculation and prefix reuse share the slot: when a request is admitted and its slot's cache is rewound (see `docs/AI.md` §2.6.1), the draft context is trimmed to the same position, and the drafter is started on a sequence when its prompt finishes prefilling. Sequences carrying media never draft, because their image positions were decoded outside any batch the drafter saw. A verifiable request (`commitment_k`) records the top-k logits of every verified row it emits, so speculation does not cost it its commitment.

**Serial path** (`speculative.rs`, `generate_speculative`), used when the host prefers a dedicated drafter context for a model (`TENZRO_PREFER_SPECULATION`). A verifiable request gets its top-k commitment there too, one record per emitted token. Each step's draft block is cut to what `max_tokens` and the context still allow, so the path never emits more than `max_tokens` tokens or verifies a position past the context, and it reports `length` when either runs out.

Not implemented: per-request `draft_n_accepted` in `InferenceResult`; acceptance is only logged.
