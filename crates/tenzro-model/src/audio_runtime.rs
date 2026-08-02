//! Audio (ASR) runtime backed by ONNX Runtime.
//!
//! Four concrete transcriber families cover the full catalog:
//!
//! - **Moonshine v2** (`MoonshineTranscriber`) — raw 16 kHz waveform input,
//!   encoder + autoregressive decoder loop with merged-decoder KV-cache
//!   (`use_cache_branch` bool input). Single output `last_hidden_state`
//!   per step → argmax token → SentencePiece detokenize.
//! - **Distil-Whisper** small.en / medium.en / large-v3 and **Whisper
//!   large-v3-turbo** (`WhisperTranscriber`) — 80 or 128 log-mel
//!   spectrogram input, encoder + autoregressive decoder loop with
//!   `use_cache_branch` merged decoder. BPE detokenize.
//! - **NeMo Parakeet TDT 0.6B v3** (`ParakeetTranscriber`) — Token-and-
//!   Duration Transducer. Three ORT sessions: NeMo-exported 128-mel
//!   preprocessor (`waveforms` → `features`), Conformer encoder
//!   (`audio_signal` → `outputs, encoded_lengths`), fused
//!   decoder+joint network (vocab + duration logits per step, two LSTM
//!   states). Inner loop emits up to `max_tokens_per_step` per encoder
//!   frame; duration logits select how many frames to skip.
//!   `vocab.txt` is parsed line-by-line (`token id`, last entry
//!   `<blk> N` marks the blank index).
//! - **NVIDIA Canary 1B Flash** (`CanaryTranscriber`) — NeMo Conformer
//!   AED (attention encoder-decoder). Supports English, German, Spanish,
//!   French with cross-lingual translation. SentencePiece detokenize.
//!
//! `AudioRuntime` exposes `load_moonshine`, `load_whisper`,
//! `load_parakeet`, and `load_canary` to construct these from on-disk
//! ONNX bundles produced by Optimum / transformers.js /
//! istupakov-onnx-asr / NeMo exports.

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
    /// Duration of audio actually transcribed, in milliseconds. ASR is billed
    /// per second of audio, and a clip longer than the model's window is
    /// truncated before inference — so this measures the decoded PCM the
    /// encoder consumed, not the length of the bytes the caller uploaded.
    pub audio_ms: u64,
    pub generation_time_ms: u64,
}

/// Trait for ASR models.
pub trait Transcriber: Send + Sync {
    fn transcribe(&self, audio_bytes: &[u8], config: &TranscribeConfig)
    -> Result<TranscribeResult>;
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

    /// Milliseconds of audio a mono 16 kHz sample count represents. Rounds up so
    /// a clip shorter than a millisecond still bills as audio rather than as
    /// nothing.
    pub fn samples_to_ms(n_samples: usize) -> u64 {
        (n_samples as u64 * 1000).div_ceil(SAMPLE_RATE as u64)
    }

    /// Decode arbitrary audio bytes (WAV/MP3/FLAC/OGG) into mono 16 kHz f32 PCM.
    ///
    /// WAV is handled directly via `hound` for predictable behaviour;
    /// everything else falls through to symphonia, which auto-probes the
    /// container and dispatches the right codec.
    pub fn decode_to_mono_16k(bytes: &[u8]) -> Result<Vec<f32>> {
        // Try WAV first via hound (faster, simpler, no probe).
        // Fall through to symphonia on hound failure.
        if looks_like_wav(bytes)
            && let Ok(samples) = decode_wav(bytes)
        {
            return Ok(samples);
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
        let channels = codec_params.channels.map(|c| c.count()).unwrap_or(1).max(1);

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
                let mut fbuf = symphonia::core::audio::AudioBuffer::<f32>::new(
                    buf.capacity() as u64,
                    *buf.spec(),
                );
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
    use ort::session::{Session, SessionInputValue};
    use ort::value::Tensor;
    use parking_lot::Mutex;
    use std::time::Instant;
    use tokenizers::Tokenizer;

    use super::preprocessing::{
        N_FRAMES, N_SAMPLES, SAMPLE_RATE, decode_to_mono_16k, log_mel_spectrogram, samples_to_ms,
    };

    /// Open an ONNX session from disk via the shared execution-provider-aware
    /// session builder (Level3 optimizations, GPU providers when compiled in).
    fn load_session(path: impl AsRef<std::path::Path>) -> Result<Session> {
        crate::onnx_session::build_onnx_session(path, "model")
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
            let (
                decoder_input_ids_name,
                decoder_encoder_hidden_name,
                decoder_use_cache_branch_name,
            ) = resolve_decoder_io(&decoder)?;
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
            let encoder_input = Array2::<f32>::from_shape_vec((1, n_samples), pcm)
                .map_err(|e| ModelError::InferenceError(format!("encoder input shape: {}", e)))?;
            let encoder_tensor = Tensor::from_array(encoder_input)
                .map_err(|e| ModelError::InferenceError(format!("encoder tensor: {}", e)))?;

            let (encoder_hidden, encoder_hidden_shape) = {
                let mut sess = self.encoder.lock();
                let outputs = sess
                    .run(ort::inputs![self.encoder_input_name.as_str() => encoder_tensor])
                    .map_err(|e| ModelError::InferenceError(format!("encoder run: {}", e)))?;
                let out_value =
                    outputs
                        .get(self.encoder_output_name.as_str())
                        .ok_or_else(|| {
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
                audio_ms: samples_to_ms(n_samples),
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
            let (
                decoder_input_ids_name,
                decoder_encoder_hidden_name,
                decoder_use_cache_branch_name,
            ) = resolve_decoder_io(&decoder)?;
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
            let encoder_input = Array3::<f32>::from_shape_vec((1, self.n_mels, N_FRAMES), mel)
                .map_err(|e| ModelError::InferenceError(format!("mel shape: {}", e)))?;
            let encoder_tensor = Tensor::from_array(encoder_input)
                .map_err(|e| ModelError::InferenceError(format!("encoder tensor: {}", e)))?;
            let (encoder_hidden, encoder_hidden_shape) = {
                let mut sess = self.encoder.lock();
                let outputs = sess
                    .run(ort::inputs![self.encoder_input_name.as_str() => encoder_tensor])
                    .map_err(|e| ModelError::InferenceError(format!("encoder run: {}", e)))?;
                let out_value =
                    outputs
                        .get(self.encoder_output_name.as_str())
                        .ok_or_else(|| {
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
                // The mel window is padded up to 30s, so a shorter clip bills
                // for its own length and a longer one bills for the window the
                // encoder actually saw.
                audio_ms: samples_to_ms(pcm.len().min(N_SAMPLES)),
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

    /// ───────────────────────── Parakeet TDT ──────────────────────────
    /// Vocabulary parsed from a NeMo `vocab.txt`.
    ///
    /// Lines are `token id` (single space). Tokens contain the
    /// SentencePiece word-boundary marker `▁` (U+2581) for leading
    /// space; we keep them raw and re-stitch at decode time. The blank
    /// index is the entry whose token is exactly `<blk>` (always the
    /// last entry in the istupakov bundle, but we look it up by name
    /// rather than rely on position).
    struct ParakeetVocab {
        /// id → token (raw, ▁ kept).
        tokens: Vec<String>,
        /// Number of vocabulary entries excluding `<blk>`. The TDT
        /// decoder_joint output is `[vocab_size + n_durations]`; we
        /// slice at `vocab_size` to separate token logits from
        /// duration logits.
        vocab_size: usize,
        /// Index of the `<blk>` token. Emitted by the joint when no
        /// vocab token fires at the current encoder frame.
        blank_idx: usize,
    }

    impl ParakeetVocab {
        fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
            let raw = std::fs::read_to_string(path.as_ref())
                .map_err(|e| ModelError::InvalidModel(format!("vocab.txt read: {}", e)))?;
            // Order tokens by their declared id, not file order, in case
            // the export ever rearranges. Build a (token, id) list first.
            let mut pairs: Vec<(String, usize)> = Vec::new();
            for line in raw.lines() {
                let line = line.trim_end_matches('\n');
                if line.is_empty() {
                    continue;
                }
                // Split on the LAST space — tokens themselves never
                // contain a literal space (the SentencePiece `▁` marker
                // stands in for leading space).
                let sp = line.rfind(' ').ok_or_else(|| {
                    ModelError::InvalidModel(format!("vocab.txt bad line: {:?}", line))
                })?;
                let token = line[..sp].to_string();
                let id_str = &line[sp + 1..];
                let id: usize = id_str.parse().map_err(|e| {
                    ModelError::InvalidModel(format!("vocab.txt id parse {:?}: {}", id_str, e))
                })?;
                pairs.push((token, id));
            }
            if pairs.is_empty() {
                return Err(ModelError::InvalidModel("vocab.txt empty".into()));
            }
            pairs.sort_by_key(|p| p.1);
            // IDs must be contiguous starting at 0.
            for (expected, (_, id)) in pairs.iter().enumerate() {
                if *id != expected {
                    return Err(ModelError::InvalidModel(format!(
                        "vocab.txt non-contiguous ids: expected {}, got {}",
                        expected, id
                    )));
                }
            }
            let tokens: Vec<String> = pairs.into_iter().map(|(t, _)| t).collect();
            let blank_idx = tokens
                .iter()
                .position(|t| t == "<blk>")
                .ok_or_else(|| ModelError::InvalidModel("vocab.txt missing <blk>".into()))?;
            // vocab_size excludes <blk>'s LM-output slot conceptually,
            // but the joint output uses `vocab_size = total_tokens`
            // and emits blank as one of the logits. The duration logits
            // come AFTER the full token bank. Following the istupakov
            // convention: `vocab_size = self._vocab_size = len(vocab)`.
            let vocab_size = tokens.len();
            Ok(Self {
                tokens,
                vocab_size,
                blank_idx,
            })
        }

        /// Decode a list of vocab ids into a UTF-8 string.
        ///
        /// `▁` (U+2581) is replaced with a leading space per the
        /// SentencePiece convention. Following the istupakov / NeMo
        /// detokenization pattern, we concatenate tokens raw then
        /// replace `▁` → ` `, finally trimming any leading space.
        fn decode(&self, ids: &[usize]) -> String {
            let mut out = String::new();
            for &id in ids {
                if id < self.tokens.len() {
                    out.push_str(&self.tokens[id]);
                }
            }
            // U+2581 → ASCII space.
            let stitched: String = out
                .chars()
                .map(|c| if c == '\u{2581}' { ' ' } else { c })
                .collect();
            stitched.trim_start().to_string()
        }
    }

    /// ORT-backed transcriber for NeMo Parakeet TDT 0.6B v3.
    ///
    /// Three ONNX sessions:
    /// - `preprocessor` (`nemo128.onnx`): `waveforms [1, T_samples] f32`,
    ///   `waveforms_lens [1] i64` → `features [1, 128, T_frames] f32`,
    ///   `features_lens [1] i64`.
    /// - `encoder` (`encoder-model.onnx`): `audio_signal [1, 128, T_frames]`,
    ///   `length [1] i64` → `outputs [1, D, S]`, `encoded_lengths [1] i64`.
    ///   Note `outputs` is channel-first — we transpose to `[1, S, D]` to
    ///   index encoder frames as the leading dim, matching the istupakov
    ///   reference impl.
    /// - `decoder_joint` (`decoder_joint-model.onnx`): inputs
    ///   `encoder_outputs [1, D, 1]`, `targets [1, 1] i64`,
    ///   `target_length [1] i64`, `input_states_1 [L1, 1, H1]`,
    ///   `input_states_2 [L2, 1, H2]` → outputs
    ///   `outputs [vocab_size + n_durations]`, `output_states_1`,
    ///   `output_states_2`. Vocab logits drive token emission; duration
    ///   logits drive the encoder-frame skip.
    pub struct ParakeetTranscriber {
        preprocessor: Mutex<Session>,
        encoder: Mutex<Session>,
        decoder_joint: Mutex<Session>,
        vocab: ParakeetVocab,
        /// State 1 shape `[L1, 1, H1]` discovered from decoder inputs.
        state1_shape: (usize, usize, usize),
        /// State 2 shape `[L2, 1, H2]` discovered from decoder inputs.
        state2_shape: (usize, usize, usize),
        /// Inner-loop cap — emit up to N tokens at the same encoder
        /// frame before forcibly advancing. NeMo / istupakov default 10.
        max_tokens_per_step: usize,
        max_audio_seconds: u32,
    }

    impl ParakeetTranscriber {
        pub fn from_onnx(
            preprocessor_path: impl AsRef<std::path::Path>,
            encoder_path: impl AsRef<std::path::Path>,
            decoder_joint_path: impl AsRef<std::path::Path>,
            vocab_path: impl AsRef<std::path::Path>,
            max_audio_seconds: u32,
        ) -> Result<Self> {
            let preprocessor = load_session(preprocessor_path)?;
            let encoder = load_session(encoder_path)?;
            let decoder_joint = load_session(decoder_joint_path)?;
            let vocab = ParakeetVocab::load(vocab_path)?;

            // Discover LSTM state shapes from decoder_joint declared inputs.
            let state1_shape = discover_state_shape(&decoder_joint, "input_states_1")?;
            let state2_shape = discover_state_shape(&decoder_joint, "input_states_2")?;

            Ok(Self {
                preprocessor: Mutex::new(preprocessor),
                encoder: Mutex::new(encoder),
                decoder_joint: Mutex::new(decoder_joint),
                vocab,
                state1_shape,
                state2_shape,
                max_tokens_per_step: 10,
                max_audio_seconds,
            })
        }
    }

    /// Read a 3-D state shape `[L, 1, H]` from a declared session input.
    /// Returns an error if the input is missing or has a non-3-D shape.
    /// Dynamic dims (None) are not expected for these states in the
    /// istupakov export and are rejected.
    fn discover_state_shape(session: &Session, name: &str) -> Result<(usize, usize, usize)> {
        let input = session
            .inputs
            .iter()
            .find(|i| i.name == name)
            .ok_or_else(|| {
                ModelError::InvalidModel(format!("decoder_joint missing {} input", name))
            })?;
        let dims: Vec<i64> = match &input.input_type {
            ort::value::ValueType::Tensor { shape, .. } => shape.iter().copied().collect(),
            _ => {
                return Err(ModelError::InvalidModel(format!(
                    "decoder_joint {} not a tensor input",
                    name
                )));
            }
        };
        if dims.len() != 3 {
            return Err(ModelError::InvalidModel(format!(
                "decoder_joint {} expected 3-D, got {:?}",
                name, dims
            )));
        }
        // Dimensions are i64; -1 (or 0) typically means dynamic. The
        // istupakov export pins all three for the LSTM states.
        let to_usize = |d: i64| -> Result<usize> {
            if d <= 0 {
                Err(ModelError::InvalidModel(format!(
                    "decoder_joint {} has dynamic dim",
                    name
                )))
            } else {
                Ok(d as usize)
            }
        };
        Ok((to_usize(dims[0])?, to_usize(dims[1])?, to_usize(dims[2])?))
    }

    impl Transcriber for ParakeetTranscriber {
        fn transcribe(
            &self,
            audio_bytes: &[u8],
            _config: &TranscribeConfig,
        ) -> Result<TranscribeResult> {
            let start = Instant::now();
            let pcm = decode_to_mono_16k(audio_bytes)?;
            if pcm.is_empty() {
                return Err(ModelError::InferenceError("empty audio".to_string()));
            }
            let max_samples = self.max_audio_seconds as usize * SAMPLE_RATE as usize;
            let pcm = if pcm.len() > max_samples {
                pcm[..max_samples].to_vec()
            } else {
                pcm
            };
            let n_samples = pcm.len();

            // ── 1. Preprocessor: waveform → 128-mel features ──────────
            let wave_arr = Array2::<f32>::from_shape_vec((1, n_samples), pcm)
                .map_err(|e| ModelError::InferenceError(format!("waveform shape: {}", e)))?;
            let wave_lens = ndarray::Array1::<i64>::from_vec(vec![n_samples as i64]);
            let wave_tensor = Tensor::from_array(wave_arr)
                .map_err(|e| ModelError::InferenceError(format!("waveform tensor: {}", e)))?;
            let wave_lens_tensor = Tensor::from_array(wave_lens)
                .map_err(|e| ModelError::InferenceError(format!("waveform lens tensor: {}", e)))?;
            let (features_data, features_shape, features_lens_val) = {
                let mut sess = self.preprocessor.lock();
                let outputs = sess
                    .run(ort::inputs![
                        "waveforms" => wave_tensor,
                        "waveforms_lens" => wave_lens_tensor,
                    ])
                    .map_err(|e| ModelError::InferenceError(format!("preprocessor run: {}", e)))?;
                let feat_val = outputs.get("features").ok_or_else(|| {
                    ModelError::InferenceError("preprocessor missing 'features' output".into())
                })?;
                let (fshape, fdata) = feat_val
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("features extract: {}", e)))?;
                let fshape: Vec<i64> = fshape.iter().copied().collect();
                let flens_val = outputs.get("features_lens").ok_or_else(|| {
                    ModelError::InferenceError("preprocessor missing 'features_lens' output".into())
                })?;
                let (_, flens_data) = flens_val.try_extract_tensor::<i64>().map_err(|e| {
                    ModelError::InferenceError(format!("features_lens extract: {}", e))
                })?;
                let flens_val = flens_data
                    .first()
                    .copied()
                    .ok_or_else(|| ModelError::InferenceError("empty features_lens".into()))?;
                (fdata.to_vec(), fshape, flens_val)
            };
            if features_shape.len() != 3 {
                return Err(ModelError::InferenceError(format!(
                    "expected features [1, 128, T], got {:?}",
                    features_shape
                )));
            }
            let feat_chans = features_shape[1] as usize;
            let feat_t = features_shape[2] as usize;

            // ── 2. Encoder: features → encoder outputs ────────────────
            let feat_arr = Array3::<f32>::from_shape_vec((1, feat_chans, feat_t), features_data)
                .map_err(|e| ModelError::InferenceError(format!("feat shape: {}", e)))?;
            let feat_tensor = Tensor::from_array(feat_arr)
                .map_err(|e| ModelError::InferenceError(format!("feat tensor: {}", e)))?;
            let feat_lens = ndarray::Array1::<i64>::from_vec(vec![features_lens_val]);
            let feat_lens_tensor = Tensor::from_array(feat_lens)
                .map_err(|e| ModelError::InferenceError(format!("feat lens tensor: {}", e)))?;
            let (enc_out_data, enc_out_shape, enc_out_len) = {
                let mut sess = self.encoder.lock();
                let outputs = sess
                    .run(ort::inputs![
                        "audio_signal" => feat_tensor,
                        "length" => feat_lens_tensor,
                    ])
                    .map_err(|e| ModelError::InferenceError(format!("encoder run: {}", e)))?;
                let out_val = outputs.get("outputs").ok_or_else(|| {
                    ModelError::InferenceError("encoder missing 'outputs'".into())
                })?;
                let (oshape, odata) = out_val.try_extract_tensor::<f32>().map_err(|e| {
                    ModelError::InferenceError(format!("encoder outputs extract: {}", e))
                })?;
                let oshape: Vec<i64> = oshape.iter().copied().collect();
                let elen_val = outputs.get("encoded_lengths").ok_or_else(|| {
                    ModelError::InferenceError("encoder missing 'encoded_lengths'".into())
                })?;
                let (_, elen_data) = elen_val.try_extract_tensor::<i64>().map_err(|e| {
                    ModelError::InferenceError(format!("encoded_lengths extract: {}", e))
                })?;
                let elen = elen_data
                    .first()
                    .copied()
                    .ok_or_else(|| ModelError::InferenceError("empty encoded_lengths".into()))?;
                (odata.to_vec(), oshape, elen)
            };
            // Encoder outputs are channel-first `[1, D, S]`. We index
            // per-frame via D-stride arithmetic — no transpose needed.
            if enc_out_shape.len() != 3 {
                return Err(ModelError::InferenceError(format!(
                    "expected encoder outputs [1, D, S], got {:?}",
                    enc_out_shape
                )));
            }
            let d_dim = enc_out_shape[1] as usize;
            let s_dim = enc_out_shape[2] as usize;
            let usable_frames = (enc_out_len as usize).min(s_dim);

            // ── 3. TDT decoding inner loop ───────────────────────────
            let mut tokens: Vec<usize> = Vec::new();
            let mut state1: Vec<f32> =
                vec![0.0; self.state1_shape.0 * self.state1_shape.1 * self.state1_shape.2];
            let mut state2: Vec<f32> =
                vec![0.0; self.state2_shape.0 * self.state2_shape.1 * self.state2_shape.2];
            let blank_idx = self.vocab.blank_idx;
            let vocab_size = self.vocab.vocab_size;
            let max_decode_steps = (usable_frames * (self.max_tokens_per_step + 2)).max(64);
            let mut total_steps = 0usize;

            let mut t = 0usize;
            let mut emitted_at_t = 0usize;
            while t < usable_frames {
                if total_steps > max_decode_steps {
                    break;
                }
                total_steps += 1;

                // Slice encoder frame at time t: `[1, D, 1]` indexed
                // from the channel-first encoder output. For each
                // d ∈ [0, D), pick enc_out_data[d*s_dim + t].
                let mut frame: Vec<f32> = Vec::with_capacity(d_dim);
                for d in 0..d_dim {
                    frame.push(enc_out_data[d * s_dim + t]);
                }
                let frame_arr =
                    Array3::<f32>::from_shape_vec((1, d_dim, 1), frame).map_err(|e| {
                        ModelError::InferenceError(format!("encoder frame shape: {}", e))
                    })?;
                let frame_tensor = Tensor::from_array(frame_arr)
                    .map_err(|e| ModelError::InferenceError(format!("frame tensor: {}", e)))?;

                // Previous token: last emitted vocab token, or blank
                // if none emitted yet.
                let prev_tok = tokens.last().copied().unwrap_or(blank_idx) as i64;
                let targets_arr = Array2::<i64>::from_shape_vec((1, 1), vec![prev_tok])
                    .map_err(|e| ModelError::InferenceError(format!("targets shape: {}", e)))?;
                let targets_tensor = Tensor::from_array(targets_arr)
                    .map_err(|e| ModelError::InferenceError(format!("targets tensor: {}", e)))?;
                let target_length_arr = ndarray::Array1::<i64>::from_vec(vec![1]);
                let target_length_tensor = Tensor::from_array(target_length_arr).map_err(|e| {
                    ModelError::InferenceError(format!("target_length tensor: {}", e))
                })?;

                let state1_arr =
                    Array3::<f32>::from_shape_vec(self.state1_shape, state1.clone())
                        .map_err(|e| ModelError::InferenceError(format!("state1 shape: {}", e)))?;
                let state2_arr =
                    Array3::<f32>::from_shape_vec(self.state2_shape, state2.clone())
                        .map_err(|e| ModelError::InferenceError(format!("state2 shape: {}", e)))?;
                let state1_tensor = Tensor::from_array(state1_arr)
                    .map_err(|e| ModelError::InferenceError(format!("state1 tensor: {}", e)))?;
                let state2_tensor = Tensor::from_array(state2_arr)
                    .map_err(|e| ModelError::InferenceError(format!("state2 tensor: {}", e)))?;

                let (joint_logits, new_state1, new_state2) = {
                    let mut sess = self.decoder_joint.lock();
                    let outputs = sess
                        .run(ort::inputs![
                            "encoder_outputs" => frame_tensor,
                            "targets" => targets_tensor,
                            "target_length" => target_length_tensor,
                            "input_states_1" => state1_tensor,
                            "input_states_2" => state2_tensor,
                        ])
                        .map_err(|e| {
                            ModelError::InferenceError(format!("decoder_joint run: {}", e))
                        })?;
                    let out_val = outputs.get("outputs").ok_or_else(|| {
                        ModelError::InferenceError("decoder_joint missing 'outputs'".into())
                    })?;
                    let (_, odata) = out_val.try_extract_tensor::<f32>().map_err(|e| {
                        ModelError::InferenceError(format!("joint outputs extract: {}", e))
                    })?;
                    let s1_val = outputs.get("output_states_1").ok_or_else(|| {
                        ModelError::InferenceError("decoder_joint missing 'output_states_1'".into())
                    })?;
                    let (_, s1_data) = s1_val.try_extract_tensor::<f32>().map_err(|e| {
                        ModelError::InferenceError(format!("state1 extract: {}", e))
                    })?;
                    let s2_val = outputs.get("output_states_2").ok_or_else(|| {
                        ModelError::InferenceError("decoder_joint missing 'output_states_2'".into())
                    })?;
                    let (_, s2_data) = s2_val.try_extract_tensor::<f32>().map_err(|e| {
                        ModelError::InferenceError(format!("state2 extract: {}", e))
                    })?;
                    (odata.to_vec(), s1_data.to_vec(), s2_data.to_vec())
                };

                // Split joint output into vocab logits (first vocab_size)
                // and duration logits (remaining).
                if joint_logits.len() < vocab_size {
                    return Err(ModelError::InferenceError(format!(
                        "joint output {} smaller than vocab_size {}",
                        joint_logits.len(),
                        vocab_size
                    )));
                }
                let token_logits = &joint_logits[..vocab_size];
                let duration_logits = &joint_logits[vocab_size..];

                let token = argmax_usize(token_logits);
                let duration_step = if duration_logits.is_empty() {
                    -1
                } else {
                    argmax_usize(duration_logits) as i32
                };

                if token != blank_idx {
                    // Commit the vocab token and the freshly-produced
                    // decoder state.
                    tokens.push(token);
                    state1 = new_state1;
                    state2 = new_state2;
                    emitted_at_t += 1;
                }

                // Advance time. Mirrors the istupakov reference:
                // if duration > 0, jump that many frames (resetting
                // the per-frame emit counter). Otherwise if we emitted
                // blank, or hit the per-frame cap, step forward by 1.
                if duration_step > 0 {
                    t += duration_step as usize;
                    emitted_at_t = 0;
                } else if token == blank_idx || emitted_at_t == self.max_tokens_per_step {
                    t += 1;
                    emitted_at_t = 0;
                }
                // Otherwise: same `t`, accumulate another emit on the
                // same frame (capped by max_tokens_per_step).
            }

            let text = self.vocab.decode(&tokens);

            Ok(TranscribeResult {
                text,
                segments: Vec::new(),
                language: None,
                audio_ms: samples_to_ms(n_samples),
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

    fn argmax_usize(v: &[f32]) -> usize {
        let mut best_i: usize = 0;
        let mut best_v: f32 = f32::NEG_INFINITY;
        for (i, x) in v.iter().enumerate() {
            if *x > best_v {
                best_v = *x;
                best_i = i;
            }
        }
        best_i
    }

    /// ───────────────────────── Canary ────────────────────────────────
    /// Vocabulary parser for NVIDIA Canary-1B-Flash, an attention
    /// encoder-decoder (AED) NeMo Conformer ASR with 5249 vocab entries
    /// served as `token id` per line. Unlike Parakeet (TDT, RNN-T joint),
    /// Canary has NO blank token — the decoder generates tokens
    /// autoregressively until `<|endoftext|>`. The `▁` (U+2581) marker
    /// is replaced with a literal space AT PARSE TIME, matching the
    /// istupakov/onnx-asr reference (`asr.py`: `token.replace("\u2581", " ")`).
    /// That makes id 1151 (the bare `▁`) decode to a literal " " token,
    /// which Canary's decoder uses as the first prefix entry.
    ///
    /// The decoder consumes a 10-token prefix selecting source language,
    /// target language, punctuation/case (`<|pnc|>` vs `<|nopnc|>`),
    /// timestamp and diarization modes. We look up specials by name
    /// (the reverse `name → id` map is built once at load time).
    struct CanaryVocab {
        /// id → token, with `▁` already replaced by " ".
        tokens: Vec<String>,
        /// name → id reverse index. Built from `tokens` after
        /// replacement, so callers look up `" "` rather than `"▁"`
        /// for the bare boundary token.
        by_name: std::collections::HashMap<String, u32>,
        /// `<|endoftext|>` id — terminates the decoding loop.
        eos_id: u32,
    }

    impl CanaryVocab {
        fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
            let raw = std::fs::read_to_string(path.as_ref())
                .map_err(|e| ModelError::InvalidModel(format!("vocab.txt read: {}", e)))?;
            let mut pairs: Vec<(String, usize)> = Vec::new();
            for line in raw.lines() {
                let line = line.trim_end_matches('\n');
                if line.is_empty() {
                    continue;
                }
                let sp = line.rfind(' ').ok_or_else(|| {
                    ModelError::InvalidModel(format!("vocab.txt bad line: {:?}", line))
                })?;
                let token_raw = &line[..sp];
                let id_str = &line[sp + 1..];
                let id: usize = id_str.parse().map_err(|e| {
                    ModelError::InvalidModel(format!("vocab.txt id parse {:?}: {}", id_str, e))
                })?;
                // Per istupakov: replace ▁ with literal space at parse
                // time. That makes the bare ▁ decode to " ", which the
                // decoder prefix relies on.
                let token = token_raw.replace('\u{2581}', " ");
                pairs.push((token, id));
            }
            if pairs.is_empty() {
                return Err(ModelError::InvalidModel("vocab.txt empty".into()));
            }
            pairs.sort_by_key(|p| p.1);
            for (expected, (_, id)) in pairs.iter().enumerate() {
                if *id != expected {
                    return Err(ModelError::InvalidModel(format!(
                        "vocab.txt non-contiguous ids: expected {}, got {}",
                        expected, id
                    )));
                }
            }
            let tokens: Vec<String> = pairs.into_iter().map(|(t, _)| t).collect();
            let mut by_name: std::collections::HashMap<String, u32> =
                std::collections::HashMap::with_capacity(tokens.len());
            for (i, t) in tokens.iter().enumerate() {
                by_name.insert(t.clone(), i as u32);
            }
            let eos_id = *by_name.get("<|endoftext|>").ok_or_else(|| {
                ModelError::InvalidModel("vocab.txt missing <|endoftext|>".into())
            })?;
            Ok(Self {
                tokens,
                by_name,
                eos_id,
            })
        }

        fn lookup(&self, name: &str) -> Result<u32> {
            self.by_name.get(name).copied().ok_or_else(|| {
                ModelError::InvalidModel(format!("vocab missing special token {:?}", name))
            })
        }

        /// Detokenize a list of vocab ids into a string. Filters
        /// `<|...|>` specials, concatenates remaining tokens, and
        /// collapses whitespace around word boundaries per istupakov
        /// `asr.py`: drop leading whitespace and trim spaces around
        /// word boundaries (`\s\B`).
        fn decode(&self, ids: &[u32]) -> String {
            let mut joined = String::new();
            for &id in ids {
                if id as usize >= self.tokens.len() {
                    continue;
                }
                let tok = &self.tokens[id as usize];
                // Skip `<|...|>` specials.
                if tok.starts_with("<|") && tok.ends_with("|>") {
                    continue;
                }
                joined.push_str(tok);
            }
            // Trim leading whitespace and collapse double-spaces. The
            // Python reference uses `re.sub(r"\A\s|\s\B|(\s)\b", r"\1",
            // text)`; we approximate by trimming leading whitespace
            // and collapsing runs of spaces to single spaces, which
            // matches the SentencePiece detokenization for ASR output.
            let trimmed = joined.trim_start();
            let mut out = String::with_capacity(trimmed.len());
            let mut prev_space = false;
            for c in trimmed.chars() {
                let is_space = c == ' ';
                if is_space && prev_space {
                    continue;
                }
                out.push(c);
                prev_space = is_space;
            }
            out
        }
    }

    /// ORT-backed transcriber for NVIDIA Canary-1B-Flash.
    ///
    /// Three ONNX sessions:
    /// - `preprocessor` (`nemo128.onnx`, shared with Parakeet):
    ///   `waveforms [1, T_samples] f32`, `waveforms_lens [1] i64` →
    ///   `features [1, 128, T_frames] f32`, `features_lens [1] i64`.
    /// - `encoder` (`encoder-model.onnx`): NeMo Conformer encoder.
    ///   Inputs `audio_signal [1, 128, T_frames]`, `length [1] i64` →
    ///   `outputs [1, S, D]` (sequence-first, unlike Parakeet which is
    ///   channel-first), `encoded_lengths [1] i64`.
    /// - `decoder` (`decoder-model.onnx`): cross-attention decoder.
    ///   Inputs `targets [1, L_in] i64`, `encoder_outputs [1, S, D] f32`,
    ///   `encoder_mask [1, S] bool`, `decoder_mems [num_layers, 1, L_kv, H] f32`,
    ///   `decoder_mask [1, L_in] bool` →
    ///   `logits [1, L_in, V] f32`, `decoder_mems_new`.
    ///
    /// Decoding is autoregressive (AED, no blank): seed with a 10-token
    /// prefix selecting source lang, target lang, PNC, timestamp, and
    /// diarization modes; argmax greedy decode until `<|endoftext|>`
    /// or `max_sequence_length` (1024).
    pub struct CanaryTranscriber {
        preprocessor: Mutex<Session>,
        encoder: Mutex<Session>,
        decoder: Mutex<Session>,
        vocab: CanaryVocab,
        /// Decoder mems shape `[num_layers, batch=1, L_kv, hidden_dim]`
        /// discovered from decoder declared inputs. `L_kv` is dynamic
        /// (grows by one position per step), so we read num_layers and
        /// hidden_dim only.
        decoder_num_layers: usize,
        decoder_hidden_dim: usize,
        /// Default source language for the prefix (e.g. `"en"`).
        default_source_lang: String,
        /// Default target language for the prefix (e.g. `"en"`).
        default_target_lang: String,
        max_audio_seconds: u32,
        /// Cap on autoregressive steps, per istupakov default.
        max_sequence_length: usize,
    }

    impl CanaryTranscriber {
        pub fn from_onnx(
            preprocessor_path: impl AsRef<std::path::Path>,
            encoder_path: impl AsRef<std::path::Path>,
            decoder_path: impl AsRef<std::path::Path>,
            vocab_path: impl AsRef<std::path::Path>,
            source_lang: impl Into<String>,
            target_lang: impl Into<String>,
            max_audio_seconds: u32,
        ) -> Result<Self> {
            let preprocessor = load_session(preprocessor_path)?;
            let encoder = load_session(encoder_path)?;
            let decoder = load_session(decoder_path)?;
            let vocab = CanaryVocab::load(vocab_path)?;
            let (decoder_num_layers, decoder_hidden_dim) = discover_canary_mems_shape(&decoder)?;
            Ok(Self {
                preprocessor: Mutex::new(preprocessor),
                encoder: Mutex::new(encoder),
                decoder: Mutex::new(decoder),
                vocab,
                decoder_num_layers,
                decoder_hidden_dim,
                default_source_lang: source_lang.into(),
                default_target_lang: target_lang.into(),
                max_audio_seconds,
                max_sequence_length: 1024,
            })
        }

        /// Build the 10-token Canary prefix per istupakov reference
        /// (`models/nemo.py:NemoConformerAED._tokens` slot order):
        /// `[" ", "<|startofcontext|>", "<|startoftranscript|>",
        ///   "<|emo:undefined|>", source_lang_tag, target_lang_tag,
        ///   "<|pnc|>", "<|noitn|>", "<|notimestamp|>",
        ///   "<|nodiarize|>"]`. Languages are tagged `<|{code}|>`,
        ///   e.g. `<|en|>`.
        fn build_prefix(&self, src_lang: &str, tgt_lang: &str) -> Result<Vec<u32>> {
            let v = &self.vocab;
            let src_tag = format!("<|{}|>", src_lang);
            let tgt_tag = format!("<|{}|>", tgt_lang);
            Ok(vec![
                v.lookup(" ")?,
                v.lookup("<|startofcontext|>")?,
                v.lookup("<|startoftranscript|>")?,
                v.lookup("<|emo:undefined|>")?,
                v.lookup(&src_tag)?,
                v.lookup(&tgt_tag)?,
                v.lookup("<|pnc|>")?,
                v.lookup("<|noitn|>")?,
                v.lookup("<|notimestamp|>")?,
                v.lookup("<|nodiarize|>")?,
            ])
        }
    }

    /// Read `(num_layers, hidden_dim)` from the `decoder_mems` declared
    /// input shape `[L, B, T, H]`. `L_kv` (dim 2) is dynamic.
    fn discover_canary_mems_shape(session: &Session) -> Result<(usize, usize)> {
        let input = session
            .inputs
            .iter()
            .find(|i| i.name == "decoder_mems")
            .ok_or_else(|| {
                ModelError::InvalidModel("decoder missing 'decoder_mems' input".into())
            })?;
        let dims: Vec<i64> = match &input.input_type {
            ort::value::ValueType::Tensor { shape, .. } => shape.iter().copied().collect(),
            _ => {
                return Err(ModelError::InvalidModel(
                    "decoder_mems not a tensor input".into(),
                ));
            }
        };
        if dims.len() != 4 {
            return Err(ModelError::InvalidModel(format!(
                "decoder_mems expected 4-D, got {:?}",
                dims
            )));
        }
        let to_usize = |d: i64, name: &str| -> Result<usize> {
            if d <= 0 {
                Err(ModelError::InvalidModel(format!(
                    "decoder_mems {} dim is dynamic ({})",
                    name, d
                )))
            } else {
                Ok(d as usize)
            }
        };
        let num_layers = to_usize(dims[0], "num_layers")?;
        let hidden_dim = to_usize(dims[3], "hidden_dim")?;
        Ok((num_layers, hidden_dim))
    }

    impl Transcriber for CanaryTranscriber {
        fn transcribe(
            &self,
            audio_bytes: &[u8],
            _config: &TranscribeConfig,
        ) -> Result<TranscribeResult> {
            let start = Instant::now();
            let pcm = decode_to_mono_16k(audio_bytes)?;
            if pcm.is_empty() {
                return Err(ModelError::InferenceError("empty audio".to_string()));
            }
            let max_samples = self.max_audio_seconds as usize * SAMPLE_RATE as usize;
            let pcm = if pcm.len() > max_samples {
                pcm[..max_samples].to_vec()
            } else {
                pcm
            };
            let n_samples = pcm.len();

            // ── 1. Preprocessor: waveform → 128-mel features ──────────
            let wave_arr = Array2::<f32>::from_shape_vec((1, n_samples), pcm)
                .map_err(|e| ModelError::InferenceError(format!("waveform shape: {}", e)))?;
            let wave_lens = ndarray::Array1::<i64>::from_vec(vec![n_samples as i64]);
            let wave_tensor = Tensor::from_array(wave_arr)
                .map_err(|e| ModelError::InferenceError(format!("waveform tensor: {}", e)))?;
            let wave_lens_tensor = Tensor::from_array(wave_lens)
                .map_err(|e| ModelError::InferenceError(format!("waveform lens tensor: {}", e)))?;
            let (features_data, features_shape, features_lens_val) = {
                let mut sess = self.preprocessor.lock();
                let outputs = sess
                    .run(ort::inputs![
                        "waveforms" => wave_tensor,
                        "waveforms_lens" => wave_lens_tensor,
                    ])
                    .map_err(|e| ModelError::InferenceError(format!("preprocessor run: {}", e)))?;
                let feat_val = outputs.get("features").ok_or_else(|| {
                    ModelError::InferenceError("preprocessor missing 'features' output".into())
                })?;
                let (fshape, fdata) = feat_val
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("features extract: {}", e)))?;
                let fshape: Vec<i64> = fshape.iter().copied().collect();
                let flens_val = outputs.get("features_lens").ok_or_else(|| {
                    ModelError::InferenceError("preprocessor missing 'features_lens' output".into())
                })?;
                let (_, flens_data) = flens_val.try_extract_tensor::<i64>().map_err(|e| {
                    ModelError::InferenceError(format!("features_lens extract: {}", e))
                })?;
                let flens_val = flens_data
                    .first()
                    .copied()
                    .ok_or_else(|| ModelError::InferenceError("empty features_lens".into()))?;
                (fdata.to_vec(), fshape, flens_val)
            };
            if features_shape.len() != 3 {
                return Err(ModelError::InferenceError(format!(
                    "expected features [1, 128, T], got {:?}",
                    features_shape
                )));
            }
            let feat_chans = features_shape[1] as usize;
            let feat_t = features_shape[2] as usize;

            // ── 2. Encoder: features → encoder outputs ────────────────
            let feat_arr = Array3::<f32>::from_shape_vec((1, feat_chans, feat_t), features_data)
                .map_err(|e| ModelError::InferenceError(format!("feat shape: {}", e)))?;
            let feat_tensor = Tensor::from_array(feat_arr)
                .map_err(|e| ModelError::InferenceError(format!("feat tensor: {}", e)))?;
            let feat_lens = ndarray::Array1::<i64>::from_vec(vec![features_lens_val]);
            let feat_lens_tensor = Tensor::from_array(feat_lens)
                .map_err(|e| ModelError::InferenceError(format!("feat lens tensor: {}", e)))?;
            let (enc_out_data, enc_out_shape, enc_out_len) = {
                let mut sess = self.encoder.lock();
                let outputs = sess
                    .run(ort::inputs![
                        "audio_signal" => feat_tensor,
                        "length" => feat_lens_tensor,
                    ])
                    .map_err(|e| ModelError::InferenceError(format!("encoder run: {}", e)))?;
                let out_val = outputs.get("outputs").ok_or_else(|| {
                    ModelError::InferenceError("encoder missing 'outputs'".into())
                })?;
                let (oshape, odata) = out_val.try_extract_tensor::<f32>().map_err(|e| {
                    ModelError::InferenceError(format!("encoder outputs extract: {}", e))
                })?;
                let oshape: Vec<i64> = oshape.iter().copied().collect();
                let elen_val = outputs.get("encoded_lengths").ok_or_else(|| {
                    ModelError::InferenceError("encoder missing 'encoded_lengths'".into())
                })?;
                let (_, elen_data) = elen_val.try_extract_tensor::<i64>().map_err(|e| {
                    ModelError::InferenceError(format!("encoded_lengths extract: {}", e))
                })?;
                let elen = elen_data
                    .first()
                    .copied()
                    .ok_or_else(|| ModelError::InferenceError("empty encoded_lengths".into()))?;
                (odata.to_vec(), oshape, elen)
            };
            if enc_out_shape.len() != 3 {
                return Err(ModelError::InferenceError(format!(
                    "expected encoder outputs [1, S, D], got {:?}",
                    enc_out_shape
                )));
            }
            // Canary encoder is sequence-first `[1, S, D]`.
            let s_dim = enc_out_shape[1] as usize;
            let d_dim = enc_out_shape[2] as usize;
            let usable_s = (enc_out_len as usize).min(s_dim);

            // Encoder mask: `[1, S]` bool, true for usable frames.
            let mut enc_mask: Vec<bool> = vec![false; s_dim];
            for slot in enc_mask.iter_mut().take(usable_s) {
                *slot = true;
            }

            // ── 3. AED autoregressive decoding ───────────────────────
            let prefix = self.build_prefix(&self.default_source_lang, &self.default_target_lang)?;
            let mut emitted: Vec<u32> = Vec::new();
            // Mems start empty (L_kv = 0). Subsequent steps grow by 1.
            let mut mems: Vec<f32> = Vec::new();
            let mut mems_l_kv: usize = 0;

            // Per istupakov: step 0 feeds the full prefix; subsequent
            // steps feed only the last emitted token, with the
            // accumulated mems carrying the prefix's KV cache.
            let mut step = 0usize;
            loop {
                if step >= self.max_sequence_length {
                    break;
                }
                let in_tokens: Vec<i64> = if step == 0 {
                    prefix.iter().map(|&t| t as i64).collect()
                } else {
                    vec![*emitted.last().unwrap() as i64]
                };
                let l_in = in_tokens.len();

                let targets_arr = Array2::<i64>::from_shape_vec((1, l_in), in_tokens)
                    .map_err(|e| ModelError::InferenceError(format!("targets shape: {}", e)))?;
                let targets_tensor = Tensor::from_array(targets_arr)
                    .map_err(|e| ModelError::InferenceError(format!("targets tensor: {}", e)))?;

                let enc_arr =
                    Array3::<f32>::from_shape_vec((1, s_dim, d_dim), enc_out_data.clone())
                        .map_err(|e| {
                            ModelError::InferenceError(format!("encoder_outputs shape: {}", e))
                        })?;
                let enc_tensor = Tensor::from_array(enc_arr).map_err(|e| {
                    ModelError::InferenceError(format!("encoder_outputs tensor: {}", e))
                })?;

                let enc_mask_arr = Array2::<bool>::from_shape_vec((1, s_dim), enc_mask.clone())
                    .map_err(|e| {
                        ModelError::InferenceError(format!("encoder_mask shape: {}", e))
                    })?;
                let enc_mask_tensor = Tensor::from_array(enc_mask_arr).map_err(|e| {
                    ModelError::InferenceError(format!("encoder_mask tensor: {}", e))
                })?;

                let mems_buf = if mems_l_kv == 0 {
                    // First decode step: KV-cache is empty, shape is
                    // [decoder_num_layers, 1, 0, decoder_hidden_dim].
                    Vec::<f32>::new()
                } else {
                    mems.clone()
                };
                let mems_arr = Array4::<f32>::from_shape_vec(
                    (
                        self.decoder_num_layers,
                        1,
                        mems_l_kv,
                        self.decoder_hidden_dim,
                    ),
                    mems_buf,
                )
                .map_err(|e| ModelError::InferenceError(format!("decoder_mems shape: {}", e)))?;
                let mems_tensor = Tensor::from_array(mems_arr).map_err(|e| {
                    ModelError::InferenceError(format!("decoder_mems tensor: {}", e))
                })?;

                let dec_mask: Vec<bool> = vec![true; l_in];
                let dec_mask_arr =
                    Array2::<bool>::from_shape_vec((1, l_in), dec_mask).map_err(|e| {
                        ModelError::InferenceError(format!("decoder_mask shape: {}", e))
                    })?;
                let dec_mask_tensor = Tensor::from_array(dec_mask_arr).map_err(|e| {
                    ModelError::InferenceError(format!("decoder_mask tensor: {}", e))
                })?;

                let (logits_data, logits_shape, new_mems_data, new_mems_shape) = {
                    let mut sess = self.decoder.lock();
                    let outputs = sess
                        .run(ort::inputs![
                            "targets" => targets_tensor,
                            "encoder_outputs" => enc_tensor,
                            "encoder_mask" => enc_mask_tensor,
                            "decoder_mems" => mems_tensor,
                            "decoder_mask" => dec_mask_tensor,
                        ])
                        .map_err(|e| ModelError::InferenceError(format!("decoder run: {}", e)))?;
                    let logits_val = outputs.get("logits").ok_or_else(|| {
                        ModelError::InferenceError("decoder missing 'logits'".into())
                    })?;
                    let (lshape, ldata) = logits_val.try_extract_tensor::<f32>().map_err(|e| {
                        ModelError::InferenceError(format!("logits extract: {}", e))
                    })?;
                    let lshape: Vec<i64> = lshape.iter().copied().collect();
                    let mems_val = outputs.get("decoder_mems_new").ok_or_else(|| {
                        ModelError::InferenceError("decoder missing 'decoder_mems_new'".into())
                    })?;
                    let (mshape, mdata) = mems_val.try_extract_tensor::<f32>().map_err(|e| {
                        ModelError::InferenceError(format!("decoder_mems_new extract: {}", e))
                    })?;
                    let mshape: Vec<i64> = mshape.iter().copied().collect();
                    (ldata.to_vec(), lshape, mdata.to_vec(), mshape)
                };

                if logits_shape.len() != 3 {
                    return Err(ModelError::InferenceError(format!(
                        "logits expected [1, L, V], got {:?}",
                        logits_shape
                    )));
                }
                let l_out = logits_shape[1] as usize;
                let v_dim = logits_shape[2] as usize;
                // Take the LAST position's logits row.
                let last_row_start = (l_out - 1) * v_dim;
                let last_row = &logits_data[last_row_start..last_row_start + v_dim];
                let next_tok = argmax_usize(last_row) as u32;

                if next_tok == self.vocab.eos_id {
                    break;
                }
                emitted.push(next_tok);

                // Replace mems with the new ones (which now include
                // L_kv = old + l_in positions).
                if new_mems_shape.len() != 4 {
                    return Err(ModelError::InferenceError(format!(
                        "decoder_mems_new expected 4-D, got {:?}",
                        new_mems_shape
                    )));
                }
                mems = new_mems_data;
                mems_l_kv = new_mems_shape[2] as usize;
                step += 1;
            }

            let text = self.vocab.decode(&emitted);

            Ok(TranscribeResult {
                text,
                segments: Vec::new(),
                language: Some(self.default_target_lang.clone()),
                audio_ms: samples_to_ms(n_samples),
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

    #[cfg(test)]
    pub(super) fn canary_vocab_load_for_test(
        path: impl AsRef<std::path::Path>,
    ) -> Result<(Vec<String>, u32)> {
        let v = CanaryVocab::load(path)?;
        Ok((v.tokens, v.eos_id))
    }

    #[cfg(test)]
    pub(super) fn canary_vocab_decode_for_test(tokens: Vec<String>, ids: &[u32]) -> String {
        let mut by_name = std::collections::HashMap::new();
        for (i, t) in tokens.iter().enumerate() {
            by_name.insert(t.clone(), i as u32);
        }
        let eos_id = by_name.get("<|endoftext|>").copied().unwrap_or(0);
        let v = CanaryVocab {
            tokens,
            by_name,
            eos_id,
        };
        v.decode(ids)
    }

    #[cfg(test)]
    pub(super) fn parakeet_vocab_load_for_test(
        path: impl AsRef<std::path::Path>,
    ) -> Result<(Vec<String>, usize, usize)> {
        let v = ParakeetVocab::load(path)?;
        Ok((v.tokens, v.vocab_size, v.blank_idx))
    }

    #[cfg(test)]
    pub(super) fn parakeet_vocab_decode_for_test(
        tokens: Vec<String>,
        blank_idx: usize,
        ids: &[usize],
    ) -> String {
        let v = ParakeetVocab {
            vocab_size: tokens.len(),
            blank_idx,
            tokens,
        };
        v.decode(ids)
    }

    /// Resolve the canonical decoder input names from a loaded merged-decoder
    /// session. Returns `(input_ids_name, encoder_hidden_states_name,
    /// use_cache_branch_name?)`. Uses exact-name match, falling back to
    /// substring match for unconventional exports. `use_cache_branch` is
    /// optional — non-merged decoder exports omit it.
    fn resolve_decoder_io(session: &Session) -> Result<(String, String, Option<String>)> {
        let names: Vec<&str> = session.inputs.iter().map(|i| i.name.as_str()).collect();
        let exact = |needle: &str| -> Option<String> {
            names
                .iter()
                .find(|n| **n == needle)
                .map(|n| (*n).to_string())
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
            let input_ids_tensor = Tensor::from_array(input_ids_arr)
                .map_err(|e| ModelError::InferenceError(format!("input_ids tensor: {}", e)))?;

            let encoder_arr =
                Array3::<f32>::from_shape_vec((1, s_dim, d_dim), encoder_hidden_owned.clone())
                    .map_err(|e| {
                        ModelError::InferenceError(format!("encoder hidden shape: {}", e))
                    })?;
            let encoder_tensor = Tensor::from_array(encoder_arr)
                .map_err(|e| ModelError::InferenceError(format!("encoder hidden tensor: {}", e)))?;

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
                let arr = Array4::<f32>::from_shape_vec((dims[0], dims[1], dims[2], dims[3]), data)
                    .map_err(|e| {
                        ModelError::InferenceError(format!(
                            "kv cache shape ({:?}): {}",
                            binding.past_input_name, e
                        ))
                    })?;
                let t = Tensor::from_array(arr)
                    .map_err(|e| ModelError::InferenceError(format!("kv cache tensor: {}", e)))?;
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
                let mut present: Vec<Option<(Vec<i64>, Vec<f32>)>> = vec![None; kv_bindings.len()];
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
                if let Some(p) = present_outputs[i].take()
                    && (!binding.is_encoder_cross || past_kv[i].is_none())
                {
                    past_kv[i] = Some(p);
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

pub use onnx_backend::{
    CanaryTranscriber, MoonshineTranscriber, ParakeetTranscriber, WhisperTranscriber,
};

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
        self.models
            .insert(model_id.into(), Arc::new(model) as Arc<dyn Transcriber>);
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
        self.models
            .insert(model_id.into(), Arc::new(model) as Arc<dyn Transcriber>);
        Ok(())
    }

    /// Load a NeMo Parakeet TDT 0.6B v3 ASR model from a downloaded
    /// istupakov-style ONNX bundle. Inputs:
    /// - `preprocessor_path`: `nemo128.onnx` (waveform → 128-mel features).
    /// - `encoder_path`: `encoder-model.onnx`.
    /// - `decoder_joint_path`: `decoder_joint-model.onnx`.
    /// - `vocab_path`: `vocab.txt` (`token id` per line, trailing `<blk>`).
    pub fn load_parakeet(
        &self,
        model_id: impl Into<String>,
        preprocessor_path: impl AsRef<Path>,
        encoder_path: impl AsRef<Path>,
        decoder_joint_path: impl AsRef<Path>,
        vocab_path: impl AsRef<Path>,
        max_audio_seconds: u32,
    ) -> Result<()> {
        let model = ParakeetTranscriber::from_onnx(
            preprocessor_path,
            encoder_path,
            decoder_joint_path,
            vocab_path,
            max_audio_seconds,
        )?;
        self.models
            .insert(model_id.into(), Arc::new(model) as Arc<dyn Transcriber>);
        Ok(())
    }

    /// Load an NVIDIA Canary-1B-Flash AED ASR model from a downloaded
    /// istupakov-style ONNX bundle. Inputs:
    /// - `preprocessor_path`: `nemo128.onnx` (shared with Parakeet —
    ///   waveform → 128-mel features).
    /// - `encoder_path`: `encoder-model.onnx` (NeMo Conformer encoder).
    /// - `decoder_path`: `decoder-model.onnx` (cross-attention AED decoder).
    /// - `vocab_path`: `vocab.txt` (`token id` per line, 5249 tokens
    ///   including `<|endoftext|>` and the language/task control tags).
    /// - `source_lang` / `target_lang`: ISO codes (`"en"`, `"de"`,
    ///   `"es"`, `"fr"`) used to build the 10-token decoder prefix.
    pub fn load_canary(
        &self,
        model_id: impl Into<String>,
        preprocessor_path: impl AsRef<Path>,
        encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        vocab_path: impl AsRef<Path>,
        source_lang: impl Into<String>,
        target_lang: impl Into<String>,
        max_audio_seconds: u32,
    ) -> Result<()> {
        let model = CanaryTranscriber::from_onnx(
            preprocessor_path,
            encoder_path,
            decoder_path,
            vocab_path,
            source_lang,
            target_lang,
            max_audio_seconds,
        )?;
        self.models
            .insert(model_id.into(), Arc::new(model) as Arc<dyn Transcriber>);
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

    #[test]
    fn parakeet_vocab_load_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vocab.txt");
        // Three tokens: ▁hello=0, ▁world=1, <blk>=2
        std::fs::write(&path, "\u{2581}hello 0\n\u{2581}world 1\n<blk> 2\n").unwrap();
        let (tokens, vocab_size, blank_idx) =
            onnx_backend::parakeet_vocab_load_for_test(&path).unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], "\u{2581}hello");
        assert_eq!(tokens[1], "\u{2581}world");
        assert_eq!(tokens[2], "<blk>");
        assert_eq!(vocab_size, 3);
        assert_eq!(blank_idx, 2);
    }

    #[test]
    fn parakeet_vocab_load_rejects_non_contiguous_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vocab.txt");
        // Missing id 1.
        std::fs::write(&path, "tok_a 0\ntok_b 2\n<blk> 3\n").unwrap();
        let res = onnx_backend::parakeet_vocab_load_for_test(&path);
        assert!(matches!(res, Err(ModelError::InvalidModel(_))));
    }

    #[test]
    fn parakeet_vocab_load_rejects_missing_blank() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vocab.txt");
        std::fs::write(&path, "tok_a 0\ntok_b 1\n").unwrap();
        let res = onnx_backend::parakeet_vocab_load_for_test(&path);
        assert!(matches!(res, Err(ModelError::InvalidModel(_))));
    }

    #[test]
    fn parakeet_vocab_load_rejects_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vocab.txt");
        std::fs::write(&path, "").unwrap();
        let res = onnx_backend::parakeet_vocab_load_for_test(&path);
        assert!(matches!(res, Err(ModelError::InvalidModel(_))));
    }

    #[test]
    fn parakeet_vocab_decode_replaces_word_boundary_marker() {
        // ▁hello ▁world → "hello world" (leading space trimmed).
        let tokens = vec![
            "\u{2581}hello".to_string(),
            "\u{2581}world".to_string(),
            "<blk>".to_string(),
        ];
        let out = onnx_backend::parakeet_vocab_decode_for_test(tokens, 2, &[0, 1]);
        assert_eq!(out, "hello world");
    }

    #[test]
    fn parakeet_vocab_decode_concatenates_subword_pieces() {
        // ▁un + believ + able → "unbelievable"
        let tokens = vec![
            "\u{2581}un".to_string(),
            "believ".to_string(),
            "able".to_string(),
            "<blk>".to_string(),
        ];
        let out = onnx_backend::parakeet_vocab_decode_for_test(tokens, 3, &[0, 1, 2]);
        assert_eq!(out, "unbelievable");
    }

    #[test]
    fn parakeet_vocab_decode_handles_empty_input() {
        let tokens = vec!["\u{2581}hi".to_string(), "<blk>".to_string()];
        let out = onnx_backend::parakeet_vocab_decode_for_test(tokens, 1, &[]);
        assert_eq!(out, "");
    }

    #[test]
    fn canary_vocab_load_replaces_word_boundary_marker_at_parse_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vocab.txt");
        // ▁ (bare boundary marker) → " " literal at parse time.
        // ▁hello → " hello", believ → "believ", <|endoftext|> kept as-is.
        std::fs::write(
            &path,
            "\u{2581} 0\n\u{2581}hello 1\nbeliev 2\n<|endoftext|> 3\n",
        )
        .unwrap();
        let (tokens, eos_id) = onnx_backend::canary_vocab_load_for_test(&path).unwrap();
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0], " ");
        assert_eq!(tokens[1], " hello");
        assert_eq!(tokens[2], "believ");
        assert_eq!(tokens[3], "<|endoftext|>");
        assert_eq!(eos_id, 3);
    }

    #[test]
    fn canary_vocab_load_rejects_non_contiguous_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vocab.txt");
        std::fs::write(&path, "tok_a 0\ntok_b 2\n<|endoftext|> 3\n").unwrap();
        let res = onnx_backend::canary_vocab_load_for_test(&path);
        assert!(matches!(res, Err(ModelError::InvalidModel(_))));
    }

    #[test]
    fn canary_vocab_load_rejects_missing_eos() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vocab.txt");
        std::fs::write(&path, "tok_a 0\ntok_b 1\n").unwrap();
        let res = onnx_backend::canary_vocab_load_for_test(&path);
        assert!(matches!(res, Err(ModelError::InvalidModel(_))));
    }

    #[test]
    fn canary_vocab_load_rejects_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vocab.txt");
        std::fs::write(&path, "").unwrap();
        let res = onnx_backend::canary_vocab_load_for_test(&path);
        assert!(matches!(res, Err(ModelError::InvalidModel(_))));
    }

    #[test]
    fn canary_vocab_decode_filters_special_tokens() {
        // Mix of specials (<|...|>) and content. Specials are dropped,
        // content concatenated, leading space trimmed.
        let tokens = vec![
            "<|startoftranscript|>".to_string(), // 0
            " hello".to_string(),                // 1 — leading space (was ▁hello)
            " world".to_string(),                // 2
            "<|endoftext|>".to_string(),         // 3
        ];
        let out = onnx_backend::canary_vocab_decode_for_test(tokens, &[0, 1, 2, 3]);
        assert_eq!(out, "hello world");
    }

    #[test]
    fn canary_vocab_decode_concatenates_subword_pieces() {
        // " un" + "believ" + "able" → "unbelievable" (leading space trimmed).
        let tokens = vec![
            " un".to_string(),
            "believ".to_string(),
            "able".to_string(),
            "<|endoftext|>".to_string(),
        ];
        let out = onnx_backend::canary_vocab_decode_for_test(tokens, &[0, 1, 2]);
        assert_eq!(out, "unbelievable");
    }

    #[test]
    fn canary_vocab_decode_collapses_runs_of_spaces() {
        let tokens = vec![
            " ".to_string(), // bare space (was ▁)
            " hello".to_string(),
            " world".to_string(),
            "<|endoftext|>".to_string(),
        ];
        // Concatenated: " " + " hello" + " world" = "  hello world".
        // Decode: trim leading, collapse double space → "hello world".
        let out = onnx_backend::canary_vocab_decode_for_test(tokens, &[0, 1, 2]);
        assert_eq!(out, "hello world");
    }

    #[test]
    fn canary_vocab_decode_handles_empty_input() {
        let tokens = vec![" hi".to_string(), "<|endoftext|>".to_string()];
        let out = onnx_backend::canary_vocab_decode_for_test(tokens, &[]);
        assert_eq!(out, "");
    }
}
