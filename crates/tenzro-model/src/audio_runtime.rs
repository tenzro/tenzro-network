//! Audio (ASR) runtime backed by ONNX Runtime.
//!
//! Five concrete transcriber implementations cover the wave-1 catalog:
//!
//! - **Moonshine v2** (`MoonshineTranscriber`) — raw 16 kHz waveform input,
//!   encoder + autoregressive decoder loop with merged-decoder KV-cache
//!   (`use_cache_branch` bool input). Single output `last_hidden_state`
//!   per step → argmax token → SentencePiece detokenize.
//! - **Distil-Whisper** small.en / medium.en / large-v3 and **Whisper
//!   large-v3-turbo** (`WhisperTranscriber`) — 80 or 128 log-mel
//!   spectrogram input, encoder + autoregressive decoder loop with
//!   `use_cache_branch` merged decoder. BPE detokenize.
//!
//! `AudioRuntime` exposes `load_moonshine` and `load_whisper` to
//! construct these from on-disk `tokenizer.json` + ONNX bundles
//! produced by the standard transformers.js / Optimum exports.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// Configuration for a transcription request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TranscribeConfig {
    /// Target language (ISO code, e.g. "en", "fr"). `None` = auto-detect
    /// when the model supports it; explicit when the model is single-language.
    #[serde(default)]
    pub language: Option<String>,
    /// Emit per-token timestamps when supported.
    #[serde(default)]
    pub timestamps: bool,
    /// Optional decoding temperature for sampling-capable models.
    #[serde(default)]
    pub temperature: Option<f32>,
}

/// A single transcript segment with optional timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptSegment {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_seconds: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_seconds: Option<f32>,
}

/// Result of a transcription call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscribeResult {
    /// Concatenated transcript text.
    pub text: String,
    /// Optional per-segment breakdown when `timestamps=true`.
    #[serde(default)]
    pub segments: Vec<TranscriptSegment>,
    /// Detected language (when auto-detection runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub generation_time_ms: u64,
}

/// Trait for ASR models.
pub trait Transcriber: Send + Sync {
    fn transcribe(&self, audio_bytes: &[u8], config: &TranscribeConfig) -> Result<TranscribeResult>;
    fn sample_rate(&self) -> u32;
    fn max_audio_seconds(&self) -> u32;
}

/// Whisper-family variant. Drives mel-bin count and special-token IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhisperFamily {
    /// Distil-Whisper small.en / medium.en — 80-mel, English-only.
    DistilEn,
    /// Distil-Whisper large-v3 — 128-mel, multilingual.
    DistilLargeV3,
    /// Whisper large-v3-turbo — 128-mel, multilingual.
    LargeV3Turbo,
}

impl WhisperFamily {
    /// Number of mel filterbank bins this variant expects.
    pub fn n_mels(self) -> usize {
        match self {
            WhisperFamily::DistilEn => 80,
            WhisperFamily::DistilLargeV3 | WhisperFamily::LargeV3Turbo => 128,
        }
    }

    /// Whether this variant decodes multiple languages.
    pub fn is_multilingual(self) -> bool {
        !matches!(self, WhisperFamily::DistilEn)
    }
}

mod preprocessing {
    //! Audio decoding and Whisper log-mel spectrogram preprocessing.

    use std::f32::consts::PI;
    use std::io::Cursor;

    use realfft::RealFftPlanner;
    use rubato::{
        Resampler, SincFixedIn, SincInterpolationParameters, SincInterpolationType, WindowFunction,
    };
    use symphonia::core::audio::{AudioBufferRef, Signal};
    use symphonia::core::codecs::{CODEC_TYPE_NULL, DecoderOptions};
    use symphonia::core::errors::Error as SymphoniaError;
    use symphonia::core::formats::FormatOptions;
    use symphonia::core::io::MediaSourceStream;
    use symphonia::core::meta::MetadataOptions;
    use symphonia::core::probe::Hint;

    use crate::error::{ModelError, Result};

    /// Whisper canonical preprocessing constants.
    pub const N_FFT: usize = 400;
    pub const HOP_LENGTH: usize = 160;
    pub const SAMPLE_RATE: u32 = 16_000;
    /// 30-second window in samples (Whisper canonical input length).
    pub const N_SAMPLES: usize = 30 * SAMPLE_RATE as usize;
    /// Number of mel frames covering N_SAMPLES at HOP_LENGTH.
    pub const N_FRAMES: usize = N_SAMPLES / HOP_LENGTH;

    /// Decode arbitrary audio bytes (WAV/MP3/FLAC/OGG) into mono 16 kHz f32 PCM.
    ///
    /// WAV is handled directly via `hound` for predictable behaviour;
    /// everything else falls through to symphonia, which auto-probes the
    /// container and dispatches the right codec.
    pub fn decode_to_mono_16k(bytes: &[u8]) -> Result<Vec<f32>> {
        // Try WAV first via hound (faster, simpler, no probe).
        if looks_like_wav(bytes) {
            if let Ok(samples) = decode_wav(bytes) {
                return Ok(samples);
            }
            // Fall through to symphonia on hound failure.
        }
        decode_symphonia(bytes)
    }

    fn looks_like_wav(bytes: &[u8]) -> bool {
        bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WAVE"
    }

    fn decode_wav(bytes: &[u8]) -> Result<Vec<f32>> {
        let cursor = Cursor::new(bytes);
        let reader = hound::WavReader::new(cursor)
            .map_err(|e| ModelError::InferenceError(format!("WAV parse: {}", e)))?;
        let spec = reader.spec();
        let channels = spec.channels.max(1) as usize;
        let in_rate = spec.sample_rate;

        let samples: Vec<f32> = match spec.sample_format {
            hound::SampleFormat::Float => reader
                .into_samples::<f32>()
                .filter_map(|s| s.ok())
                .collect(),
            hound::SampleFormat::Int => {
                // Normalize to [-1, 1] using the bits_per_sample range.
                let max_amp = match spec.bits_per_sample {
                    8 => i8::MAX as f32,
                    16 => i16::MAX as f32,
                    24 => 8_388_607.0_f32,
                    32 => i32::MAX as f32,
                    n => (1u64 << (n.saturating_sub(1))) as f32,
                };
                reader
                    .into_samples::<i32>()
                    .filter_map(|s| s.ok())
                    .map(|v| v as f32 / max_amp)
                    .collect()
            }
        };
        let mono = downmix_to_mono(samples, channels);
        resample_to_16k(mono, in_rate)
    }

    fn decode_symphonia(bytes: &[u8]) -> Result<Vec<f32>> {
        let cursor = Cursor::new(bytes.to_vec());
        let mss = MediaSourceStream::new(Box::new(cursor), Default::default());
        let probed = symphonia::default::get_probe()
            .format(
                &Hint::new(),
                mss,
                &FormatOptions::default(),
                &MetadataOptions::default(),
            )
            .map_err(|e| ModelError::InferenceError(format!("audio probe: {}", e)))?;

        let mut format = probed.format;
        let track = format
            .tracks()
            .iter()
            .find(|t| t.codec_params.codec != CODEC_TYPE_NULL)
            .ok_or_else(|| ModelError::InferenceError("no decodable audio track".to_string()))?;
        let track_id = track.id;
        let codec_params = track.codec_params.clone();
        let in_rate = codec_params
            .sample_rate
            .ok_or_else(|| ModelError::InferenceError("missing sample_rate".to_string()))?;
        let channels = codec_params
            .channels
            .map(|c| c.count())
            .unwrap_or(1)
            .max(1);

        let mut decoder = symphonia::default::get_codecs()
            .make(&codec_params, &DecoderOptions::default())
            .map_err(|e| ModelError::InferenceError(format!("codec init: {}", e)))?;

        let mut samples: Vec<f32> = Vec::new();
        loop {
            let packet = match format.next_packet() {
                Ok(p) => p,
                Err(SymphoniaError::IoError(ref e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                }
                Err(e) => {
                    return Err(ModelError::InferenceError(format!("packet read: {}", e)));
                }
            };
            if packet.track_id() != track_id {
                continue;
            }
            match decoder.decode(&packet) {
                Ok(decoded) => append_audio_buffer(&decoded, &mut samples),
                Err(SymphoniaError::DecodeError(_)) => continue,
                Err(e) => {
                    return Err(ModelError::InferenceError(format!("decode: {}", e)));
                }
            }
        }

        let mono = downmix_to_mono(samples, channels);
        resample_to_16k(mono, in_rate)
    }

    fn append_audio_buffer(buf: &AudioBufferRef<'_>, out: &mut Vec<f32>) {
        match buf {
            AudioBufferRef::F32(b) => {
                let chans = b.spec().channels.count();
                let frames = b.frames();
                for f in 0..frames {
                    for c in 0..chans {
                        out.push(b.chan(c)[f]);
                    }
                }
            }
            AudioBufferRef::S16(b) => {
                let chans = b.spec().channels.count();
                let frames = b.frames();
                for f in 0..frames {
                    for c in 0..chans {
                        out.push(b.chan(c)[f] as f32 / i16::MAX as f32);
                    }
                }
            }
            AudioBufferRef::S32(b) => {
                let chans = b.spec().channels.count();
                let frames = b.frames();
                for f in 0..frames {
                    for c in 0..chans {
                        out.push(b.chan(c)[f] as f32 / i32::MAX as f32);
                    }
                }
            }
            AudioBufferRef::U8(b) => {
                let chans = b.spec().channels.count();
                let frames = b.frames();
                for f in 0..frames {
                    for c in 0..chans {
                        let v = b.chan(c)[f] as f32;
                        out.push((v - 128.0) / 128.0);
                    }
                }
            }
            _ => {
                // Fallback: convert via f32 buffer copy.
                let mut fbuf =
                    symphonia::core::audio::AudioBuffer::<f32>::new(buf.capacity() as u64, *buf.spec());
                buf.convert(&mut fbuf);
                let chans = fbuf.spec().channels.count();
                let frames = fbuf.frames();
                for f in 0..frames {
                    for c in 0..chans {
                        out.push(fbuf.chan(c)[f]);
                    }
                }
            }
        }
    }

    /// Average interleaved channels down to mono.
    fn downmix_to_mono(interleaved: Vec<f32>, channels: usize) -> Vec<f32> {
        if channels <= 1 {
            return interleaved;
        }
        let frames = interleaved.len() / channels;
        let mut out = Vec::with_capacity(frames);
        for f in 0..frames {
            let base = f * channels;
            let mut acc = 0.0_f32;
            for c in 0..channels {
                acc += interleaved[base + c];
            }
            out.push(acc / channels as f32);
        }
        out
    }

    /// Resample a mono f32 PCM stream to 16 kHz using `rubato`'s sinc
    /// resampler. Pass-through when input is already 16 kHz.
    fn resample_to_16k(samples: Vec<f32>, in_rate: u32) -> Result<Vec<f32>> {
        if in_rate == SAMPLE_RATE {
            return Ok(samples);
        }
        if samples.is_empty() {
            return Ok(samples);
        }
        let params = SincInterpolationParameters {
            sinc_len: 256,
            f_cutoff: 0.95,
            interpolation: SincInterpolationType::Linear,
            oversampling_factor: 256,
            window: WindowFunction::BlackmanHarris2,
        };
        let mut resampler = SincFixedIn::<f32>::new(
            SAMPLE_RATE as f64 / in_rate as f64,
            2.0,
            params,
            samples.len(),
            1,
        )
        .map_err(|e| ModelError::InferenceError(format!("resampler init: {}", e)))?;
        let waves_in = vec![samples];
        let waves_out = resampler
            .process(&waves_in, None)
            .map_err(|e| ModelError::InferenceError(format!("resample: {}", e)))?;
        Ok(waves_out.into_iter().next().unwrap_or_default())
    }

    /// Pad or truncate to exactly N_SAMPLES (30s @ 16 kHz). Whisper's
    /// canonical input window.
    pub fn pad_or_truncate_30s(samples: &[f32]) -> Vec<f32> {
        if samples.len() >= N_SAMPLES {
            samples[..N_SAMPLES].to_vec()
        } else {
            let mut out = Vec::with_capacity(N_SAMPLES);
            out.extend_from_slice(samples);
            out.resize(N_SAMPLES, 0.0);
            out
        }
    }

    /// Compute the Whisper log-mel spectrogram for a 30s waveform.
    ///
    /// Returns a `[n_mels, N_FRAMES]` row-major flat vec. Pipeline:
    /// pad, STFT (n_fft=400, hop=160, Hanning window), magnitude squared,
    /// mel filterbank projection, log10 with floor, normalize per Whisper:
    /// `log_spec = log10(max(mel, 1e-10))`, then
    /// `log_spec = (log_spec.max() - 8.0).max(log_spec)`, then
    /// `log_spec = (log_spec + 4.0) / 4.0`.
    pub fn log_mel_spectrogram(samples: &[f32], n_mels: usize) -> Vec<f32> {
        let padded = pad_or_truncate_30s(samples);
        let window = hanning_window(N_FFT);

        // Reflective padding by N_FFT/2 on each end so STFT frame
        // centers sit at sample positions [0, hop, 2*hop, ...].
        let half = N_FFT / 2;
        let mut padded_for_stft = Vec::with_capacity(padded.len() + N_FFT);
        for i in 0..half {
            padded_for_stft.push(padded[half - i]);
        }
        padded_for_stft.extend_from_slice(&padded);
        for i in 0..half {
            let idx = padded.len() - 2 - i;
            padded_for_stft.push(padded[idx]);
        }

        let mut planner = RealFftPlanner::<f32>::new();
        let r2c = planner.plan_fft_forward(N_FFT);
        let mut frame_buf = vec![0.0_f32; N_FFT];
        let mut spec_buf = r2c.make_output_vec();

        let n_freq = N_FFT / 2 + 1;
        let mel_filters = mel_filterbank(SAMPLE_RATE, N_FFT, n_mels);

        // Output [n_mels, N_FRAMES] row-major.
        let mut log_mel = vec![0.0_f32; n_mels * N_FRAMES];

        for t in 0..N_FRAMES {
            let start = t * HOP_LENGTH;
            // Apply Hanning window.
            for i in 0..N_FFT {
                frame_buf[i] = padded_for_stft[start + i] * window[i];
            }
            r2c.process(&mut frame_buf, &mut spec_buf)
                .expect("FFT length matches plan");

            // Magnitude squared of the half-spectrum.
            let mut power = vec![0.0_f32; n_freq];
            for (k, c) in spec_buf.iter().enumerate() {
                power[k] = c.re * c.re + c.im * c.im;
            }

            // Project through mel filters.
            for m in 0..n_mels {
                let filt = &mel_filters[m];
                let mut acc = 0.0_f32;
                for k in 0..n_freq {
                    acc += filt[k] * power[k];
                }
                log_mel[m * N_FRAMES + t] = acc;
            }
        }

        // Whisper log scaling: log10, clamp to top 80 dB, normalize to [-1, 1].
        let mut max_v = f32::MIN;
        for v in log_mel.iter_mut() {
            *v = v.max(1e-10).log10();
            if *v > max_v {
                max_v = *v;
            }
        }
        let floor = max_v - 8.0;
        for v in log_mel.iter_mut() {
            if *v < floor {
                *v = floor;
            }
            *v = (*v + 4.0) / 4.0;
        }

        log_mel
    }

    fn hanning_window(n: usize) -> Vec<f32> {
        // Periodic Hanning window matching numpy.hanning + Whisper convention.
        (0..n)
            .map(|i| 0.5 - 0.5 * ((2.0 * PI * i as f32) / n as f32).cos())
            .collect()
    }

    /// Slaney-normalized mel filterbank matching `librosa.filters.mel`
    /// defaults used by Whisper preprocessing.
    fn mel_filterbank(sample_rate: u32, n_fft: usize, n_mels: usize) -> Vec<Vec<f32>> {
        let n_freq = n_fft / 2 + 1;
        let f_min = 0.0;
        let f_max = sample_rate as f32 / 2.0;

        let mel_min = hz_to_mel(f_min);
        let mel_max = hz_to_mel(f_max);

        // n_mels + 2 mel-spaced points → n_mels triangular filters.
        let mel_pts: Vec<f32> = (0..n_mels + 2)
            .map(|i| mel_min + (mel_max - mel_min) * i as f32 / (n_mels + 1) as f32)
            .collect();
        let hz_pts: Vec<f32> = mel_pts.iter().map(|m| mel_to_hz(*m)).collect();

        // FFT bin center frequencies.
        let bin_freqs: Vec<f32> = (0..n_freq)
            .map(|k| k as f32 * sample_rate as f32 / n_fft as f32)
            .collect();

        let mut filters = vec![vec![0.0_f32; n_freq]; n_mels];
        for m in 0..n_mels {
            let f_left = hz_pts[m];
            let f_center = hz_pts[m + 1];
            let f_right = hz_pts[m + 2];
            // Slaney normalization: 2 / (f_right - f_left).
            let enorm = 2.0 / (f_right - f_left).max(1e-12);
            for k in 0..n_freq {
                let f = bin_freqs[k];
                let weight = if f < f_left || f > f_right {
                    0.0
                } else if f <= f_center {
                    (f - f_left) / (f_center - f_left).max(1e-12)
                } else {
                    (f_right - f) / (f_right - f_center).max(1e-12)
                };
                filters[m][k] = weight * enorm;
            }
        }
        filters
    }

    fn hz_to_mel(hz: f32) -> f32 {
        // Slaney: linear below 1 kHz, log above.
        let f_min = 0.0_f32;
        let f_sp = 200.0 / 3.0;
        let min_log_hz = 1000.0_f32;
        let min_log_mel = (min_log_hz - f_min) / f_sp;
        let logstep = (6.4_f32).ln() / 27.0;
        if hz >= min_log_hz {
            min_log_mel + (hz / min_log_hz).ln() / logstep
        } else {
            (hz - f_min) / f_sp
        }
    }

    fn mel_to_hz(mel: f32) -> f32 {
        let f_min = 0.0_f32;
        let f_sp = 200.0 / 3.0;
        let min_log_hz = 1000.0_f32;
        let min_log_mel = (min_log_hz - f_min) / f_sp;
        let logstep = (6.4_f32).ln() / 27.0;
        if mel >= min_log_mel {
            min_log_hz * ((mel - min_log_mel) * logstep).exp()
        } else {
            f_min + f_sp * mel
        }
    }
}

mod onnx_backend {
    use super::*;
    use ndarray::{Array2, Array3, Array4};
    use ort::session::{Session, SessionInputValue, builder::GraphOptimizationLevel};
    use ort::value::Tensor;
    use parking_lot::Mutex;
    use std::time::Instant;
    use tokenizers::Tokenizer;

    use super::preprocessing::{N_FRAMES, SAMPLE_RATE, decode_to_mono_16k, log_mel_spectrogram};

    /// Open an ONNX session from disk with Level3 optimizations.
    fn load_session(path: impl AsRef<std::path::Path>) -> Result<Session> {
        Session::builder()
            .map_err(|e| ModelError::InvalidModel(format!("ORT session builder: {}", e)))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| ModelError::InvalidModel(format!("ORT optimization level: {}", e)))?
            .commit_from_file(path.as_ref())
            .map_err(|e| {
                ModelError::ProviderNotAvailable(format!("ORT load failed: {}", e))
            })
    }

    /// Pair of `past_key_values.*` decoder inputs and `present.*` outputs
    /// captured at load time. The merged decoder ONNX returns a fresh
    /// `present.*` for every `past_key_values.*` input; we feed it back
    /// in on the next step.
    #[derive(Clone, Debug)]
    struct KvCacheBinding {
        /// Decoder input names like
        /// `past_key_values.0.decoder.key`,
        /// `past_key_values.0.decoder.value`,
        /// `past_key_values.0.encoder.key`,
        /// `past_key_values.0.encoder.value`.
        past_input_name: String,
        /// Matching decoder output name `present.<...>` written every step.
        present_output_name: String,
        /// Whether this is an encoder-cross-attention KV pair (fixed
        /// across decode steps and re-fed verbatim) vs a self-attention
        /// pair (grows by 1 step every iteration). Encoder pairs are
        /// recognised by the substring `.encoder.` in the name.
        is_encoder_cross: bool,
    }

    fn discover_kv_bindings(session: &Session) -> Vec<KvCacheBinding> {
        let mut out = Vec::new();
        let input_names: Vec<&str> = session.inputs.iter().map(|i| i.name.as_str()).collect();
        let output_names: Vec<&str> = session.outputs.iter().map(|o| o.name.as_str()).collect();
        for inp in &input_names {
            if let Some(suffix) = inp.strip_prefix("past_key_values.") {
                let present_name = format!("present.{}", suffix);
                if output_names.iter().any(|o| *o == present_name) {
                    out.push(KvCacheBinding {
                        past_input_name: (*inp).to_string(),
                        present_output_name: present_name,
                        is_encoder_cross: suffix.contains(".encoder."),
                    });
                }
            }
        }
        out
    }

    /// Detect a token name (or fall through to a numeric default).
    fn token_id_or(tokenizer: &Tokenizer, name: &str, fallback: u32) -> u32 {
        tokenizer.token_to_id(name).unwrap_or(fallback)
    }

    /// ───────────────────────── Moonshine ─────────────────────────────

    /// ORT-backed transcriber for Moonshine v2 (tiny / base).
    ///
    /// Moonshine consumes raw 16 kHz f32 mono audio (`input_values`,
    /// shape `[1, T]`) directly — no mel spectrogram. The encoder
    /// emits `last_hidden_state` `[1, S, D]`. A merged decoder ONNX
    /// runs autoregressively keyed by `use_cache_branch` (false on the
    /// first prefill, true thereafter); we feed back `present.*` →
    /// `past_key_values.*` between steps and stop on EOS.
    pub struct MoonshineTranscriber {
        encoder: Mutex<Session>,
        decoder: Mutex<Session>,
        tokenizer: Tokenizer,
        kv_bindings: Vec<KvCacheBinding>,
        encoder_input_name: String,
        encoder_output_name: String,
        decoder_input_ids_name: String,
        decoder_encoder_hidden_name: String,
        decoder_use_cache_branch_name: Option<String>,
        eos_token_id: u32,
        decoder_start_token_id: u32,
        max_new_tokens: usize,
        max_audio_seconds: u32,
    }

    impl MoonshineTranscriber {
        pub fn from_onnx(
            encoder_path: impl AsRef<std::path::Path>,
            decoder_path: impl AsRef<std::path::Path>,
            tokenizer_path: impl AsRef<std::path::Path>,
            max_audio_seconds: u32,
        ) -> Result<Self> {
            let encoder = load_session(encoder_path)?;
            let decoder = load_session(decoder_path)?;
            let kv_bindings = discover_kv_bindings(&decoder);
            let encoder_input_name = encoder
                .inputs
                .first()
                .map(|i| i.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("encoder has no inputs".to_string()))?;
            let encoder_output_name = encoder
                .outputs
                .first()
                .map(|o| o.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("encoder has no outputs".to_string()))?;
            let (decoder_input_ids_name, decoder_encoder_hidden_name, decoder_use_cache_branch_name) =
                resolve_decoder_io(&decoder)?;
            let tokenizer = Tokenizer::from_file(tokenizer_path.as_ref())
                .map_err(|e| ModelError::InvalidModel(format!("tokenizer load: {}", e)))?;
            // Moonshine tokenizer special tokens: <s>=1, </s>=2 in the
            // upstream LLaMA-style sentencepiece. We look these up by
            // name first and fall back to those defaults.
            let decoder_start_token_id = token_id_or(&tokenizer, "<s>", 1);
            let eos_token_id = token_id_or(&tokenizer, "</s>", 2);
            Ok(Self {
                encoder: Mutex::new(encoder),
                decoder: Mutex::new(decoder),
                tokenizer,
                kv_bindings,
                encoder_input_name,
                encoder_output_name,
                decoder_input_ids_name,
                decoder_encoder_hidden_name,
                decoder_use_cache_branch_name,
                eos_token_id,
                decoder_start_token_id,
                max_new_tokens: 448,
                max_audio_seconds,
            })
        }
    }

    impl Transcriber for MoonshineTranscriber {
        fn transcribe(
            &self,
            audio_bytes: &[u8],
            _config: &TranscribeConfig,
        ) -> Result<TranscribeResult> {
            let start = Instant::now();
            let pcm = decode_to_mono_16k(audio_bytes)?;
            // Moonshine accepts variable-length raw waveform; clamp to the
            // catalog-declared max for safety.
            let max_samples = self.max_audio_seconds as usize * SAMPLE_RATE as usize;
            let pcm = if pcm.len() > max_samples {
                pcm[..max_samples].to_vec()
            } else {
                pcm
            };
            if pcm.is_empty() {
                return Err(ModelError::InferenceError("empty audio".to_string()));
            }
            let n_samples = pcm.len();

            // Encoder forward: input_values [1, T] → last_hidden_state [1, S, D].
            let encoder_input =
                Array2::<f32>::from_shape_vec((1, n_samples), pcm).map_err(|e| {
                    ModelError::InferenceError(format!("encoder input shape: {}", e))
                })?;
            let encoder_tensor = Tensor::from_array(encoder_input).map_err(|e| {
                ModelError::InferenceError(format!("encoder tensor: {}", e))
            })?;

            let (encoder_hidden, encoder_hidden_shape) = {
                let mut sess = self.encoder.lock();
                let outputs = sess
                    .run(ort::inputs![self.encoder_input_name.as_str() => encoder_tensor])
                    .map_err(|e| {
                        ModelError::InferenceError(format!("encoder run: {}", e))
                    })?;
                let out_value = outputs.get(self.encoder_output_name.as_str()).ok_or_else(|| {
                    ModelError::InferenceError(format!(
                        "missing encoder output {}",
                        self.encoder_output_name
                    ))
                })?;
                let (shape, data) = out_value
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("encoder extract: {}", e)))?;
                (data.to_vec(), shape.iter().copied().collect::<Vec<i64>>())
            };
            if encoder_hidden_shape.len() != 3 {
                return Err(ModelError::InferenceError(format!(
                    "expected encoder output [1, S, D], got {:?}",
                    encoder_hidden_shape
                )));
            }
            let s_dim = encoder_hidden_shape[1] as usize;
            let d_dim = encoder_hidden_shape[2] as usize;

            // Decode loop.
            let token_ids = autoregressive_decode(
                &self.decoder,
                &self.kv_bindings,
                &self.decoder_input_ids_name,
                &self.decoder_encoder_hidden_name,
                self.decoder_use_cache_branch_name.as_deref(),
                &encoder_hidden,
                s_dim,
                d_dim,
                self.decoder_start_token_id,
                self.eos_token_id,
                self.max_new_tokens,
            )?;

            let text = self
                .tokenizer
                .decode(&token_ids, true)
                .map_err(|e| ModelError::InferenceError(format!("detokenize: {}", e)))?;

            Ok(TranscribeResult {
                text,
                segments: Vec::new(),
                language: Some("en".into()),
                generation_time_ms: start.elapsed().as_millis() as u64,
            })
        }

        fn sample_rate(&self) -> u32 {
            SAMPLE_RATE
        }
        fn max_audio_seconds(&self) -> u32 {
            self.max_audio_seconds
        }
    }

    /// ───────────────────────── Whisper family ─────────────────────────

    /// ORT-backed transcriber for Whisper / Distil-Whisper variants.
    ///
    /// Encoder consumes log-mel spectrogram `[1, n_mels, N_FRAMES]`
    /// (80 or 128 mels). Merged decoder runs autoregressively keyed by
    /// `use_cache_branch` and feeds back `present.*` → `past_key_values.*`.
    pub struct WhisperTranscriber {
        encoder: Mutex<Session>,
        decoder: Mutex<Session>,
        tokenizer: Tokenizer,
        kv_bindings: Vec<KvCacheBinding>,
        encoder_input_name: String,
        encoder_output_name: String,
        decoder_input_ids_name: String,
        decoder_encoder_hidden_name: String,
        decoder_use_cache_branch_name: Option<String>,
        family: WhisperFamily,
        n_mels: usize,
        eos_token_id: u32,
        sot_token_id: u32,
        no_timestamps_token_id: u32,
        transcribe_token_id: u32,
        max_new_tokens: usize,
        max_audio_seconds: u32,
    }

    impl WhisperTranscriber {
        pub fn from_onnx(
            encoder_path: impl AsRef<std::path::Path>,
            decoder_path: impl AsRef<std::path::Path>,
            tokenizer_path: impl AsRef<std::path::Path>,
            family: WhisperFamily,
            max_audio_seconds: u32,
        ) -> Result<Self> {
            let encoder = load_session(encoder_path)?;
            let decoder = load_session(decoder_path)?;
            let kv_bindings = discover_kv_bindings(&decoder);
            let encoder_input_name = encoder
                .inputs
                .first()
                .map(|i| i.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("encoder has no inputs".to_string()))?;
            let encoder_output_name = encoder
                .outputs
                .first()
                .map(|o| o.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("encoder has no outputs".to_string()))?;
            let (decoder_input_ids_name, decoder_encoder_hidden_name, decoder_use_cache_branch_name) =
                resolve_decoder_io(&decoder)?;
            let tokenizer = Tokenizer::from_file(tokenizer_path.as_ref())
                .map_err(|e| ModelError::InvalidModel(format!("tokenizer load: {}", e)))?;
            // Whisper / Distil-Whisper canonical special token IDs.
            // 50258 = <|startoftranscript|>, 50362 = <|notimestamps|>,
            // 50359 = <|transcribe|>, 50257 = <|endoftext|>.
            // Look up by canonical name; fall back to those numeric IDs.
            let sot_token_id = token_id_or(&tokenizer, "<|startoftranscript|>", 50258);
            let no_timestamps_token_id = token_id_or(&tokenizer, "<|notimestamps|>", 50362);
            let transcribe_token_id = token_id_or(&tokenizer, "<|transcribe|>", 50359);
            let eos_token_id = token_id_or(&tokenizer, "<|endoftext|>", 50257);
            Ok(Self {
                encoder: Mutex::new(encoder),
                decoder: Mutex::new(decoder),
                tokenizer,
                kv_bindings,
                encoder_input_name,
                encoder_output_name,
                decoder_input_ids_name,
                decoder_encoder_hidden_name,
                decoder_use_cache_branch_name,
                family,
                n_mels: family.n_mels(),
                eos_token_id,
                sot_token_id,
                no_timestamps_token_id,
                transcribe_token_id,
                max_new_tokens: 448,
                max_audio_seconds,
            })
        }

        /// Build the Whisper decoder prompt prefix. The first generated
        /// token follows this prefix; the prefix itself is fed into the
        /// initial prefill step but not included in the final transcript.
        ///
        /// English / single-language: `[SOT, transcribe, no_timestamps]`.
        /// Multilingual: `[SOT, lang, transcribe, no_timestamps]` —
        /// language token is the BPE id for `<|en|>` etc.
        fn build_prompt(&self, language: Option<&str>) -> Vec<u32> {
            let mut prompt = vec![self.sot_token_id];
            if self.family.is_multilingual() {
                let lang_code = language.unwrap_or("en");
                let lang_token = format!("<|{}|>", lang_code);
                if let Some(id) = self.tokenizer.token_to_id(&lang_token) {
                    prompt.push(id);
                }
            }
            prompt.push(self.transcribe_token_id);
            prompt.push(self.no_timestamps_token_id);
            prompt
        }
    }

    impl Transcriber for WhisperTranscriber {
        fn transcribe(
            &self,
            audio_bytes: &[u8],
            config: &TranscribeConfig,
        ) -> Result<TranscribeResult> {
            let start = Instant::now();
            let pcm = decode_to_mono_16k(audio_bytes)?;
            if pcm.is_empty() {
                return Err(ModelError::InferenceError("empty audio".to_string()));
            }

            // Encoder input: log-mel spectrogram [1, n_mels, N_FRAMES].
            let mel = log_mel_spectrogram(&pcm, self.n_mels);
            let encoder_input = Array3::<f32>::from_shape_vec(
                (1, self.n_mels, N_FRAMES),
                mel,
            )
            .map_err(|e| ModelError::InferenceError(format!("mel shape: {}", e)))?;
            let encoder_tensor = Tensor::from_array(encoder_input).map_err(|e| {
                ModelError::InferenceError(format!("encoder tensor: {}", e))
            })?;
            let (encoder_hidden, encoder_hidden_shape) = {
                let mut sess = self.encoder.lock();
                let outputs = sess
                    .run(ort::inputs![self.encoder_input_name.as_str() => encoder_tensor])
                    .map_err(|e| {
                        ModelError::InferenceError(format!("encoder run: {}", e))
                    })?;
                let out_value = outputs.get(self.encoder_output_name.as_str()).ok_or_else(|| {
                    ModelError::InferenceError(format!(
                        "missing encoder output {}",
                        self.encoder_output_name
                    ))
                })?;
                let (shape, data) = out_value
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("encoder extract: {}", e)))?;
                (data.to_vec(), shape.iter().copied().collect::<Vec<i64>>())
            };
            if encoder_hidden_shape.len() != 3 {
                return Err(ModelError::InferenceError(format!(
                    "expected encoder output [1, S, D], got {:?}",
                    encoder_hidden_shape
                )));
            }
            let s_dim = encoder_hidden_shape[1] as usize;
            let d_dim = encoder_hidden_shape[2] as usize;

            // Build prompt prefix.
            let prompt = self.build_prompt(config.language.as_deref());
            let prompt_len = prompt.len();

            // Run a prefill step with the full prompt (cache OFF), then
            // step token-by-token (cache ON) until EOS or max_new_tokens.
            let token_ids = autoregressive_decode_with_prompt(
                &self.decoder,
                &self.kv_bindings,
                &self.decoder_input_ids_name,
                &self.decoder_encoder_hidden_name,
                self.decoder_use_cache_branch_name.as_deref(),
                &encoder_hidden,
                s_dim,
                d_dim,
                &prompt,
                self.eos_token_id,
                self.max_new_tokens,
            )?;

            // Strip prompt + special tokens for the human-readable text.
            let generated: Vec<u32> = token_ids.into_iter().skip(prompt_len).collect();
            let text = self
                .tokenizer
                .decode(&generated, true)
                .map_err(|e| ModelError::InferenceError(format!("detokenize: {}", e)))?;

            Ok(TranscribeResult {
                text,
                segments: Vec::new(),
                language: config.language.clone(),
                generation_time_ms: start.elapsed().as_millis() as u64,
            })
        }

        fn sample_rate(&self) -> u32 {
            SAMPLE_RATE
        }
        fn max_audio_seconds(&self) -> u32 {
            self.max_audio_seconds
        }
    }

    /// Resolve the canonical decoder input names from a loaded merged-decoder
    /// session. Returns `(input_ids_name, encoder_hidden_states_name,
    /// use_cache_branch_name?)`. Uses exact-name match, falling back to
    /// substring match for unconventional exports. `use_cache_branch` is
    /// optional — non-merged decoder exports omit it.
    fn resolve_decoder_io(session: &Session) -> Result<(String, String, Option<String>)> {
        let names: Vec<&str> = session.inputs.iter().map(|i| i.name.as_str()).collect();
        let exact = |needle: &str| -> Option<String> {
            names.iter().find(|n| **n == needle).map(|n| (*n).to_string())
        };
        let contains = |needle: &str| -> Option<String> {
            names
                .iter()
                .find(|n| n.contains(needle))
                .map(|n| (*n).to_string())
        };
        let input_ids = exact("input_ids")
            .or_else(|| contains("input_ids"))
            .ok_or_else(|| ModelError::InvalidModel("decoder missing input_ids input".into()))?;
        let encoder_hidden = exact("encoder_hidden_states")
            .or_else(|| contains("encoder_hidden_states"))
            .ok_or_else(|| {
                ModelError::InvalidModel("decoder missing encoder_hidden_states input".into())
            })?;
        let use_cache = exact("use_cache_branch").or_else(|| contains("use_cache_branch"));
        Ok((input_ids, encoder_hidden, use_cache))
    }

    /// Run a single-token prefill + greedy autoregressive loop on a
    /// merged-decoder ONNX. Used by Moonshine, which seeds the loop with
    /// just the `decoder_start_token_id`.
    #[allow(clippy::too_many_arguments)]
    fn autoregressive_decode(
        decoder: &Mutex<Session>,
        kv_bindings: &[KvCacheBinding],
        input_ids_name: &str,
        encoder_hidden_name: &str,
        use_cache_branch_name: Option<&str>,
        encoder_hidden: &[f32],
        s_dim: usize,
        d_dim: usize,
        decoder_start_token_id: u32,
        eos_token_id: u32,
        max_new_tokens: usize,
    ) -> Result<Vec<u32>> {
        let prompt = vec![decoder_start_token_id];
        autoregressive_decode_with_prompt(
            decoder,
            kv_bindings,
            input_ids_name,
            encoder_hidden_name,
            use_cache_branch_name,
            encoder_hidden,
            s_dim,
            d_dim,
            &prompt,
            eos_token_id,
            max_new_tokens,
        )
    }

    /// Greedy autoregressive loop on a merged-decoder ONNX with a
    /// multi-token prompt prefix.
    ///
    /// Step 0 (prefill): feed the full `prompt` with `use_cache_branch=false`,
    /// no `past_key_values.*`. Read step 0's `present.*` outputs.
    /// Step k>0 (decode): feed `[next_token]`, `use_cache_branch=true`,
    /// `past_key_values.*` = previous `present.*`. Greedy-sample
    /// argmax(logits[-1]); stop on EOS.
    #[allow(clippy::too_many_arguments)]
    fn autoregressive_decode_with_prompt(
        decoder: &Mutex<Session>,
        kv_bindings: &[KvCacheBinding],
        input_ids_name: &str,
        encoder_hidden_name: &str,
        use_cache_branch_name: Option<&str>,
        encoder_hidden: &[f32],
        s_dim: usize,
        d_dim: usize,
        prompt: &[u32],
        eos_token_id: u32,
        max_new_tokens: usize,
    ) -> Result<Vec<u32>> {
        // Carry the rolling KV cache (one f32 buffer per binding) between
        // steps. The shape per binding is [1, num_heads, past_len, head_dim]
        // (self-attn) or [1, num_heads, S, head_dim] (cross-attn). We
        // re-feed verbatim — ORT discovers the dims at runtime.
        let mut past_kv: Vec<Option<(Vec<i64>, Vec<f32>)>> = vec![None; kv_bindings.len()];
        let mut tokens: Vec<u32> = prompt.to_vec();
        let mut step = 0usize;

        // Encoder hidden tensor reused every step (cross-attention).
        // We rebuild the Tensor each call because ort 2.x consumes them.
        let encoder_hidden_owned = encoder_hidden.to_vec();

        loop {
            let use_cache = step > 0;
            // Input ids for this step. Step 0 = full prompt; later steps =
            // last token only.
            let step_ids: Vec<i64> = if step == 0 {
                prompt.iter().map(|t| *t as i64).collect()
            } else {
                vec![*tokens.last().unwrap() as i64]
            };
            let l = step_ids.len();
            let input_ids_arr = Array2::<i64>::from_shape_vec((1, l), step_ids)
                .map_err(|e| ModelError::InferenceError(format!("input_ids shape: {}", e)))?;
            let input_ids_tensor = Tensor::from_array(input_ids_arr).map_err(|e| {
                ModelError::InferenceError(format!("input_ids tensor: {}", e))
            })?;

            let encoder_arr = Array3::<f32>::from_shape_vec(
                (1, s_dim, d_dim),
                encoder_hidden_owned.clone(),
            )
            .map_err(|e| ModelError::InferenceError(format!("encoder hidden shape: {}", e)))?;
            let encoder_tensor = Tensor::from_array(encoder_arr).map_err(|e| {
                ModelError::InferenceError(format!("encoder hidden tensor: {}", e))
            })?;

            // Build the input feed.
            let mut feed: Vec<(String, SessionInputValue<'_>)> = Vec::new();
            feed.push((input_ids_name.to_string(), input_ids_tensor.into()));
            feed.push((encoder_hidden_name.to_string(), encoder_tensor.into()));

            if let Some(name) = use_cache_branch_name {
                let arr = ndarray::Array1::<bool>::from_vec(vec![use_cache]);
                let v = Tensor::from_array(arr).map_err(|e| {
                    ModelError::InferenceError(format!("use_cache_branch tensor: {}", e))
                })?;
                feed.push((name.to_string(), v.into()));
            }

            // KV cache feed.
            for (i, binding) in kv_bindings.iter().enumerate() {
                let payload = if use_cache {
                    past_kv[i].clone()
                } else {
                    // Pre-fill step: feed an empty placeholder buffer
                    // shaped [1, num_heads, 0, head_dim]. We don't know
                    // num_heads/head_dim ahead of time — but the merged
                    // decoder declares the input dims dynamic, and ORT
                    // accepts an empty length-0 axis. Construct from the
                    // binding's first present output shape after step 0
                    // is impossible (chicken-and-egg), so we feed a
                    // 4-D zero tensor of shape [1, 1, 0, 1] which the
                    // model ignores when use_cache_branch=false.
                    Some((vec![1, 1, 0, 1], Vec::<f32>::new()))
                };
                let (shape, data) = payload.unwrap_or((vec![1, 1, 0, 1], Vec::new()));
                let dims: Vec<usize> = shape.iter().map(|d| *d as usize).collect();
                let arr = Array4::<f32>::from_shape_vec(
                    (dims[0], dims[1], dims[2], dims[3]),
                    data,
                )
                .map_err(|e| {
                    ModelError::InferenceError(format!(
                        "kv cache shape ({:?}): {}",
                        binding.past_input_name, e
                    ))
                })?;
                let t = Tensor::from_array(arr).map_err(|e| {
                    ModelError::InferenceError(format!("kv cache tensor: {}", e))
                })?;
                feed.push((binding.past_input_name.clone(), t.into()));
            }

            // Run.
            let (logits, present_outputs) = {
                let mut sess = decoder.lock();
                let outputs = sess
                    .run(feed)
                    .map_err(|e| ModelError::InferenceError(format!("decoder run: {}", e)))?;
                // Logits output (canonical name "logits").
                let logits_value = outputs.get("logits").ok_or_else(|| {
                    ModelError::InferenceError("decoder missing 'logits' output".into())
                })?;
                let (logits_shape, logits_data) = logits_value
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("logits extract: {}", e)))?;
                let logits_shape: Vec<i64> = logits_shape.iter().copied().collect();
                let logits = (logits_shape, logits_data.to_vec());

                // Read all `present.*` outputs and pair them with bindings.
                let mut present: Vec<Option<(Vec<i64>, Vec<f32>)>> =
                    vec![None; kv_bindings.len()];
                for (i, binding) in kv_bindings.iter().enumerate() {
                    if let Some(v) = outputs.get(binding.present_output_name.as_str()) {
                        let (s, d) = v.try_extract_tensor::<f32>().map_err(|e| {
                            ModelError::InferenceError(format!(
                                "present.* extract ({}): {}",
                                binding.present_output_name, e
                            ))
                        })?;
                        present[i] = Some((s.iter().copied().collect(), d.to_vec()));
                    }
                }
                (logits, present)
            };

            // Update past KV cache. Encoder cross-attn KVs are re-fed
            // verbatim every step; self-attn KVs grow.
            let mut present_outputs = present_outputs;
            for (i, binding) in kv_bindings.iter().enumerate() {
                if let Some(p) = present_outputs[i].take() {
                    if !binding.is_encoder_cross || past_kv[i].is_none() {
                        past_kv[i] = Some(p);
                    }
                }
            }

            // Greedy argmax over the *last* time step of logits.
            // logits shape is [1, T, V].
            let logits_shape = &logits.0;
            if logits_shape.len() != 3 {
                return Err(ModelError::InferenceError(format!(
                    "expected logits [1, T, V], got {:?}",
                    logits_shape
                )));
            }
            let t_dim = logits_shape[1] as usize;
            let v_dim = logits_shape[2] as usize;
            // Last time step starts at (t_dim - 1) * v_dim.
            let last_offset = (t_dim - 1) * v_dim;
            let last_slice = &logits.1[last_offset..last_offset + v_dim];
            let next_token = argmax_u32(last_slice);

            tokens.push(next_token);
            if next_token == eos_token_id {
                break;
            }
            step += 1;
            if step > max_new_tokens {
                break;
            }
        }
        Ok(tokens)
    }

    fn argmax_u32(v: &[f32]) -> u32 {
        let mut best_i: usize = 0;
        let mut best_v: f32 = f32::NEG_INFINITY;
        for (i, x) in v.iter().enumerate() {
            if *x > best_v {
                best_v = *x;
                best_i = i;
            }
        }
        best_i as u32
    }

}

pub use onnx_backend::{MoonshineTranscriber, WhisperTranscriber};

/// Runtime that owns multiple loaded ASR models.
pub struct AudioRuntime {
    models: dashmap::DashMap<String, Arc<dyn Transcriber>>,
}

impl Default for AudioRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn Transcriber>) {
        self.models.insert(model_id.into(), model);
    }

    /// Load a Moonshine v2 ASR model from a downloaded HF bundle.
    /// `encoder_path` and `decoder_path` are the encoder/decoder ONNX files;
    /// `tokenizer_path` is the SentencePiece-derived `tokenizer.json`.
    pub fn load_moonshine(
        &self,
        model_id: impl Into<String>,
        encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        tokenizer_path: impl AsRef<Path>,
        max_audio_seconds: u32,
    ) -> Result<()> {
        let model = MoonshineTranscriber::from_onnx(
            encoder_path,
            decoder_path,
            tokenizer_path,
            max_audio_seconds,
        )?;
        self.models.insert(
            model_id.into(),
            Arc::new(model) as Arc<dyn Transcriber>,
        );
        Ok(())
    }

    /// Load a Whisper-family ASR model (Distil-Whisper or Whisper-turbo).
    pub fn load_whisper(
        &self,
        model_id: impl Into<String>,
        encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        tokenizer_path: impl AsRef<Path>,
        family: WhisperFamily,
        max_audio_seconds: u32,
    ) -> Result<()> {
        let model = WhisperTranscriber::from_onnx(
            encoder_path,
            decoder_path,
            tokenizer_path,
            family,
            max_audio_seconds,
        )?;
        self.models.insert(
            model_id.into(),
            Arc::new(model) as Arc<dyn Transcriber>,
        );
        Ok(())
    }

    pub fn unregister(&self, model_id: &str) -> bool {
        self.models.remove(model_id).is_some()
    }

    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.models.contains_key(model_id)
    }

    pub fn loaded_models(&self) -> Vec<String> {
        self.models.iter().map(|kv| kv.key().clone()).collect()
    }

    pub async fn transcribe(
        &self,
        model_id: &str,
        audio_bytes: Vec<u8>,
        config: TranscribeConfig,
    ) -> Result<TranscribeResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| kv.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.transcribe(&audio_bytes, &config))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_starts_empty() {
        let rt = AudioRuntime::new();
        assert!(rt.loaded_models().is_empty());
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = AudioRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[tokio::test]
    async fn transcribe_on_unknown_model_returns_not_found() {
        let rt = AudioRuntime::new();
        let res = rt
            .transcribe("missing", vec![], TranscribeConfig::default())
            .await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    #[test]
    fn segment_serializes_round_trip() {
        let s = TranscriptSegment {
            text: "hello".into(),
            start_seconds: Some(0.0),
            end_seconds: Some(1.0),
        };
        let json = serde_json::to_string(&s).unwrap();
        let _: TranscriptSegment = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn whisper_family_n_mels() {
        assert_eq!(WhisperFamily::DistilEn.n_mels(), 80);
        assert_eq!(WhisperFamily::DistilLargeV3.n_mels(), 128);
        assert_eq!(WhisperFamily::LargeV3Turbo.n_mels(), 128);
        assert!(!WhisperFamily::DistilEn.is_multilingual());
        assert!(WhisperFamily::DistilLargeV3.is_multilingual());
        assert!(WhisperFamily::LargeV3Turbo.is_multilingual());
    }

    #[test]
    fn log_mel_spectrogram_shape_is_n_mels_by_n_frames() {
        // 1 second of silence at 16 kHz.
        let pcm = vec![0.0_f32; 16_000];
        let mel80 = preprocessing::log_mel_spectrogram(&pcm, 80);
        assert_eq!(mel80.len(), 80 * preprocessing::N_FRAMES);
        let mel128 = preprocessing::log_mel_spectrogram(&pcm, 128);
        assert_eq!(mel128.len(), 128 * preprocessing::N_FRAMES);
    }

    #[test]
    fn pad_or_truncate_30s_returns_exactly_n_samples() {
        let short = vec![0.5_f32; 8000];
        let padded = preprocessing::pad_or_truncate_30s(&short);
        assert_eq!(padded.len(), preprocessing::N_SAMPLES);
        let long = vec![0.1_f32; preprocessing::N_SAMPLES * 2];
        let trunc = preprocessing::pad_or_truncate_30s(&long);
        assert_eq!(trunc.len(), preprocessing::N_SAMPLES);
    }
}
