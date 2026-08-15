//! llama.cpp sampler-chain assembly.
//!
//! Backend-gated: this references the bundled llama.cpp backend, so it is
//! compiled only under the `bundled-llama` feature. A host that provides its
//! own backend builds its sampler chain with its own binding.

use llama_cpp_2::sampling::LlamaSampler;

use crate::config::GenerationConfig;

/// Assemble the llama.cpp sampler chain for a request.
///
/// Stage order mirrors llama.cpp's own default (penalties before truncation,
/// truncation before the distribution draw). The optional `top_k` and `min_p`
/// stages are omitted entirely when unset rather than passed a neutral value,
/// so a request that does not ask for them samples exactly as it did before
/// those knobs existed.
pub fn build_sampler_chain(config: &GenerationConfig, n_vocab: i32) -> LlamaSampler {
    build_sampler_chain_with_grammar(config, None, n_vocab)
}

/// [`build_sampler_chain`] with an optional grammar stage in front.
///
/// The grammar goes first so it masks the tokens that would spell a malformed
/// constrained output before any truncation or temperature stage sees the
/// distribution — constraining after a truncation stage has already discarded
/// candidates can leave nothing legal to draw from. `None` reproduces
/// [`build_sampler_chain`] exactly.
pub fn build_sampler_chain_with_grammar(
    config: &GenerationConfig,
    grammar: Option<LlamaSampler>,
    n_vocab: i32,
) -> LlamaSampler {
    let mut stages = Vec::new();
    if let Some(g) = grammar {
        stages.push(g);
    }
    stages.push(LlamaSampler::penalties(
        n_vocab,
        config.repeat_last_n as i32,
        config.repeat_penalty,
        config.frequency_penalty,
        config.presence_penalty,
    ));
    if let Some(k) = config.top_k {
        stages.push(LlamaSampler::top_k(k as i32));
    }
    stages.push(LlamaSampler::temp(config.temperature as f32));
    stages.push(LlamaSampler::top_p(config.top_p as f32, 1));
    if let Some(p) = config.min_p {
        stages.push(LlamaSampler::min_p(p as f32, 1));
    }
    stages.push(LlamaSampler::dist(config.seed as u32));
    LlamaSampler::chain_simple(stages)
}
