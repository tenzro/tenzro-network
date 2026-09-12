//! Prefill throughput against `n_batch` / `n_ubatch`.
//!
//! `tuned_context_params` sets the KV cache type and the attention policy but
//! leaves both batch knobs at llama.cpp's defaults (2048 logical / 512
//! physical). This sweeps them against the real prefill loop so the production
//! value is chosen from a measurement on this host rather than from a guess.
//!
//! ```text
//! cargo run --release -p tenzro-model --features cuda \
//!   --example prefill_sweep -- ~/.tenzro/models/muse-glimmer-30b.gguf
//! ```

use std::path::PathBuf;
use std::time::Instant;

use llama_cpp_2::context::params::{KvCacheType, LlamaContextParams};
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::token::LlamaToken;

/// Prompt lengths to prefill, in tokens.
const LENGTHS: &[usize] = &[1024, 4096, 8192, 16384];

/// `(n_batch, n_ubatch)` pairs. The first is llama.cpp's default.
const KNOBS: &[(u32, u32)] = &[
    (2048, 512),
    (4096, 2048),
    (8192, 4096),
    (16384, 8192),
    (32768, 16384),
];

/// Timed passes per cell. The first sweep of this took one sample per cell in
/// a fixed order and the numbers did not reproduce: the cold first cell read
/// 704 tok/s against 887 on a second run, and the last row — measured on a
/// fully warm device — came out 68% faster at 4k than the identical
/// configuration had a run earlier. One sample per cell measures the schedule,
/// not the setting.
const REPEATS: usize = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gguf: PathBuf = std::env::args()
        .nth(1)
        .ok_or("usage: prefill_sweep <model.gguf>")?
        .into();

    // What the production tier in `batch_params` keys off, so a sweep on this
    // host says which row of the table this host will actually get.
    let hw = tenzro_types::HardwareCapabilities::detect();
    println!(
        "detected={} vram_gb={} interconnect={:?} ram_gb={}",
        hw.detected, hw.vram_gb, hw.interconnect, hw.ram_gb
    );

    let backend = LlamaBackend::init()?;
    let model_params = LlamaModelParams::default().with_n_gpu_layers(1000);
    let load = Instant::now();
    let model = LlamaModel::load_from_file(&backend, &gguf, &model_params)?;
    println!(
        "loaded {} in {:.1}s",
        gguf.display(),
        load.elapsed().as_secs_f64()
    );

    // One filler prompt, tokenized once, sliced per length — so every knob
    // setting prefills byte-identical tokens and only the batching differs.
    let filler = "alpha bravo charlie delta echo foxtrot golf hotel india juliet ".repeat(4096);
    let all = model.str_to_token(&filler, AddBos::Always)?;
    let longest = *LENGTHS.iter().max().unwrap_or(&1024);
    if all.len() < longest {
        return Err(format!("filler tokenizes to {} tokens, need {longest}", all.len()).into());
    }

    // Bring the device to a steady clock before anything is recorded, so the
    // first cell measured is not the one paying for CUDA's first-call setup.
    eprintln!("warming...");
    for _ in 0..2 {
        let _ = timed_prefill(&model, &backend, longest, 2048, 512, 4096);
    }

    println!("median of {REPEATS} timed passes per cell, tok/s");
    print!("{:>8} {:>8}", "n_batch", "n_ubatch");
    for len in LENGTHS {
        print!(" {:>16}", format!("{len}tok"));
    }
    println!();

    for &(n_batch, n_ubatch) in KNOBS {
        print!("{n_batch:>8} {n_ubatch:>8}");
        for &len in LENGTHS {
            let mut rates = Vec::with_capacity(REPEATS);
            for _ in 0..REPEATS {
                match timed_prefill(&model, &backend, longest, n_batch, n_ubatch, len) {
                    Ok(secs) => rates.push(len as f64 / secs),
                    Err(e) => {
                        print!(" {:>16}", format!("err:{e}"));
                        rates.clear();
                        break;
                    }
                }
            }
            if rates.is_empty() {
                continue;
            }
            rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            // Median and spread together: a tight spread is what makes the
            // median worth quoting, and a wide one says the cell is not a
            // measurement at all.
            let median = rates[rates.len() / 2];
            let spread = (rates[rates.len() - 1] - rates[0]) / median * 100.0;
            print!(" {:>16}", format!("{median:.0} ±{spread:.0}%"));
        }
        println!();
    }
    Ok(())
}

/// Build a context at these knobs and time one prefill of `len` tokens.
///
/// A fresh context per pass: the serving path builds one per generation, so
/// reusing one here would measure a warm KV cache production never has.
fn timed_prefill(
    model: &LlamaModel,
    backend: &LlamaBackend,
    n_ctx: usize,
    n_batch: u32,
    n_ubatch: u32,
    len: usize,
) -> Result<f64, Box<dyn std::error::Error>> {
    let filler = "alpha bravo charlie delta echo foxtrot golf hotel india juliet ".repeat(4096);
    let all = model.str_to_token(&filler, AddBos::Always)?;
    let params = LlamaContextParams::default()
        .with_n_ctx(std::num::NonZeroU32::new(n_ctx as u32 + 512))
        .with_type_k(KvCacheType::Q8_0)
        .with_type_v(KvCacheType::Q8_0)
        .with_flash_attention_policy(llama_cpp_sys_2::LLAMA_FLASH_ATTN_TYPE_ENABLED)
        .with_n_batch(n_batch)
        .with_n_ubatch(n_ubatch);
    let mut ctx = model.new_context(backend, params)?;
    let t0 = Instant::now();
    prefill(&mut ctx, &all[..len], n_batch as usize)?;
    Ok(t0.elapsed().as_secs_f64())
}

/// The same chunk-by-`n_batch` loop `ModelRuntime::prefill_in_batches` runs.
fn prefill(
    ctx: &mut llama_cpp_2::context::LlamaContext,
    tokens: &[LlamaToken],
    n_batch: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let last = tokens.len() - 1;
    let mut batch = LlamaBatch::new(n_batch.min(tokens.len()), 1);
    let mut start = 0usize;
    while start < tokens.len() {
        let end = (start + n_batch).min(tokens.len());
        batch.clear();
        for (offset, token) in tokens[start..end].iter().enumerate() {
            let pos = start + offset;
            batch.add(*token, pos as i32, &[0], pos == last)?;
        }
        ctx.decode(&mut batch)?;
        start = end;
    }
    Ok(())
}
