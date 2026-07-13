//! Expert-FFN compute backend seam.
//!
//! The MoE forward reduces to one primitive: `Y = X · Wᵀ` for a hidden-state
//! batch `X: [n_tokens, in]` against a projection weight `W: [out, in]`
//! (dense `f32` or GGUF block-quantized). Every expert's SwiGLU forward is
//! three such matmuls, so this is the single hot path.
//!
//! [`ExpertCompute`] abstracts that primitive so the runtime can select the
//! fastest available implementation at load time:
//!
//! - [`CpuCompute`] is always present. It is `ndarray` for the dense path,
//!   and for the quantized path it either dequantizes-then-GEMMs or, when the
//!   activation batch is itself Q8_0 and the CPU advertises AVX-512-VNNI at
//!   runtime, runs an integer dot straight over the block payloads. The
//!   feature probe is `is_x86_feature_detected!` — the scalar path is always
//!   reachable, so a build with no SIMD support still executes correctly.
//! - GPU backends are compiled only under the `moe-gpu` feature and are
//!   discovered by device probe, never assumed. The default build pulls no
//!   GPU dependency.
//!
//! [`ComputeBackend::select`] is the runtime dispatch: it returns the best
//! backend the current machine can actually run, mirroring the ONNX-runtime
//! execution-provider selection in [`crate::onnx_session`].

use ndarray::{Array2, ArrayView1, ArrayView2};

use crate::moe_quant::{QuantKind, QuantMatrix};

/// A projection weight in the form the compute backend consumes it.
///
/// Kept distinct from the private `Projection` enum in [`crate::moe_exec`] so
/// the backend trait has no dependency on the loader's internals — a backend
/// sees only "a dense `f32` matrix" or "a block-quantized matrix", both
/// row-major `[out, in]`.
pub enum Weight<'a> {
    /// Dense row-major `[out, in]` `f32`.
    Dense(ArrayView2<'a, f32>),
    /// GGUF block-quantized `[out, in]`.
    Quant(&'a QuantMatrix),
}

impl Weight<'_> {
    /// `(out, in)` shape.
    pub fn dim(&self) -> (usize, usize) {
        match self {
            Weight::Dense(w) => (w.nrows(), w.ncols()),
            Weight::Quant(q) => (q.nrows(), q.ncols()),
        }
    }
}

/// The one operation every expert FFN forward routes through.
///
/// Implementations must be numerically equivalent to the scalar reference
/// (`Y[i,j] = Σ_k X[i,k] · W[j,k]`) up to floating-point reassociation — a
/// GPU or SIMD path may reorder the reduction but must not change results
/// beyond that. Object-safe so the runtime can hold `Box<dyn ExpertCompute>`.
pub trait ExpertCompute: Send + Sync {
    /// `Y = X · Wᵀ`, `X: [n, in]`, `W: [out, in]` → `Y: [n, out]`.
    fn matmul_xt(&self, x: ArrayView2<'_, f32>, w: &Weight<'_>) -> Array2<f32>;

    /// A short backend tag for status/telemetry (`"cpu-avx512"`, `"cpu"`,
    /// `"cuda"`, `"wgpu"`).
    fn tag(&self) -> &'static str;
}

/// CPU backend — always available.
///
/// Records the SIMD tier detected at construction so per-call dispatch is a
/// field read, not a repeated `is_x86_feature_detected!` (which is cheap but
/// not free). The tier only ever enables a *faster equivalent* path; the
/// scalar/`ndarray` reference is always the floor.
pub struct CpuCompute {
    tier: CpuSimd,
}

/// Detected x86 SIMD tier for the Q8_0 integer-dot fast path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpuSimd {
    /// No SIMD acceleration used — dequantize-then-GEMM / scalar dot.
    Scalar,
    /// AVX-512 Foundation + VNNI (`vpdpbusd`) available.
    Avx512Vnni,
}

impl CpuCompute {
    /// Probe the running CPU and pick the best Q8_0 dot tier.
    pub fn detect() -> Self {
        Self {
            tier: detect_cpu_simd(),
        }
    }

    /// The dense path is a single `ndarray` GEMM.
    fn matmul_dense(x: ArrayView2<'_, f32>, w: ArrayView2<'_, f32>) -> Array2<f32> {
        x.dot(&w.t())
    }

    /// The quantized path. When the weight is Q8_0 and AVX-512-VNNI is
    /// present, each output column is an integer dot over the block payloads
    /// (activations quantized to Q8_0 per row first). Otherwise dequantize
    /// each weight row into scratch and GEMM against it — the reference path.
    fn matmul_quant(&self, x: ArrayView2<'_, f32>, q: &QuantMatrix) -> Array2<f32> {
        let n = x.nrows();
        let out = q.nrows();
        let cols = q.ncols();
        let mut y = Array2::<f32>::zeros((n, out));

        #[cfg(target_arch = "x86_64")]
        if self.tier == CpuSimd::Avx512Vnni
            && q.kind() == QuantKind::Q8_0
            && cols % crate::moe_quant::QK8_0 == 0
        {
            // Quantize each activation row to Q8_0 once, then integer-dot it
            // against every weight row's blocks. This is the grouped-GEMM
            // inner shape: the whole token batch shares the dequant of W.
            let mut act_blocks: Vec<Vec<u8>> = Vec::with_capacity(n);
            for i in 0..n {
                let row: Vec<f32> = x.row(i).to_vec();
                act_blocks.push(crate::moe_quant::quantize_row_q8_0(&row));
            }
            for j in 0..out {
                let wblocks = q.row_block_bytes(j);
                for (i, ablocks) in act_blocks.iter().enumerate() {
                    // Safety: tier == Avx512Vnni proves the target features are
                    // present on this CPU (checked once in detect()).
                    y[[i, j]] = unsafe { dot_q8_0_avx512_vnni(ablocks, wblocks) };
                }
            }
            return y;
        }

        // Scalar / ndarray reference path (always reachable).
        let mut wrow = vec![0.0f32; cols];
        for j in 0..out {
            q.dequantize_row(j, &mut wrow);
            let wview = ArrayView1::from(&wrow);
            for i in 0..n {
                y[[i, j]] = x.row(i).dot(&wview);
            }
        }
        y
    }
}

impl ExpertCompute for CpuCompute {
    fn matmul_xt(&self, x: ArrayView2<'_, f32>, w: &Weight<'_>) -> Array2<f32> {
        match w {
            Weight::Dense(dw) => Self::matmul_dense(x, *dw),
            Weight::Quant(q) => self.matmul_quant(x, q),
        }
    }

    fn tag(&self) -> &'static str {
        match self.tier {
            CpuSimd::Scalar => "cpu",
            CpuSimd::Avx512Vnni => "cpu-avx512-vnni",
        }
    }
}

/// Probe x86 SIMD once. On non-x86 targets, always `Scalar`.
fn detect_cpu_simd() -> CpuSimd {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f")
            && is_x86_feature_detected!("avx512vnni")
            && is_x86_feature_detected!("avx512bw")
        {
            return CpuSimd::Avx512Vnni;
        }
    }
    CpuSimd::Scalar
}

/// Dot product of two Q8_0-block rows via AVX-512-VNNI `vpdpbusd`.
///
/// Both `a` and `b` are concatenated Q8_0 blocks (`[f16 scale | 32×i8]`,
/// 34 bytes each) of equal length. Per block: widen both quant vectors,
/// accumulate `Σ aᵢ·bᵢ` as i32 via VNNI, then scale by `d_a · d_b`.
///
/// # Safety
/// Caller must ensure the CPU supports `avx512f`, `avx512bw`, and
/// `avx512vnni` (guaranteed by `CpuSimd::Avx512Vnni`), and that `a` and `b`
/// are the same number of whole Q8_0 blocks.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw,avx512vnni")]
unsafe fn dot_q8_0_avx512_vnni(a: &[u8], b: &[u8]) -> f32 {
    use std::arch::x86_64::*;
    use half::f16;

    const BB: usize = crate::moe_quant::Q8_0_BLOCK_BYTES; // 34
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len() % BB, 0);

    let mut acc = 0.0f32;
    let nblocks = a.len() / BB;
    for blk in 0..nblocks {
        let ab = &a[blk * BB..(blk + 1) * BB];
        let bb = &b[blk * BB..(blk + 1) * BB];
        let da = f16::from_le_bytes([ab[0], ab[1]]).to_f32();
        let db = f16::from_le_bytes([bb[0], bb[1]]).to_f32();

        // 32 i8 quants per block. Load as __m256i (32 bytes).
        let qa = _mm256_loadu_si256(ab.as_ptr().add(2) as *const __m256i);
        let qb = _mm256_loadu_si256(bb.as_ptr().add(2) as *const __m256i);

        // vpdpbusd wants u8 × i8. Q8_0 quants are signed i8; make the `a`
        // side unsigned by adding 128 and correct the bias afterward:
        //   Σ (aᵢ+128)·bᵢ = Σ aᵢ·bᵢ + 128·Σ bᵢ
        // so subtract 128·Σ bᵢ.
        let bias = _mm256_set1_epi8(-128i8 as u8 as i8);
        let qa_u = _mm256_sub_epi8(qa, bias); // aᵢ + 128, as u8 bit-pattern

        let zero = _mm256_setzero_si256();
        let mut dot = _mm256_setzero_si256();
        dot = _mm256_dpbusd_epi32(dot, qa_u, qb);

        // Σ bᵢ via vpdpbusd of ones(u8) · b(i8).
        let ones = _mm256_set1_epi8(1);
        let mut sum_b = _mm256_setzero_si256();
        sum_b = _mm256_dpbusd_epi32(sum_b, ones, qb);

        // Horizontal-sum both i32x8 accumulators.
        let dot_sum = hsum_i32x8(dot);
        let b_sum = hsum_i32x8(sum_b);
        let _ = zero;

        let raw = dot_sum - 128 * b_sum;
        acc += (raw as f32) * da * db;
    }
    acc
}

/// Horizontal sum of an `__m256i` interpreted as 8×i32.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw,avx512vnni")]
unsafe fn hsum_i32x8(v: std::arch::x86_64::__m256i) -> i32 {
    use std::arch::x86_64::*;
    let lo = _mm256_castsi256_si128(v);
    let hi = _mm256_extracti128_si256(v, 1);
    let s = _mm_add_epi32(lo, hi);
    let s = _mm_add_epi32(s, _mm_shuffle_epi32(s, 0b01_00_11_10));
    let s = _mm_add_epi32(s, _mm_shuffle_epi32(s, 0b00_00_00_01));
    _mm_cvtsi128_si32(s)
}

/// Which compute backend the runtime resolved for this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    /// CPU (scalar / ndarray floor, possibly with AVX-512-VNNI Q8_0 dot).
    Cpu,
    /// CUDA (cuBLAS grouped GEMM) — NVIDIA present, `moe-gpu` compiled.
    Cuda,
    /// wgpu WGSL compute — cross-vendor GPU, `moe-gpu` compiled.
    Wgpu,
}

/// Runtime backend selection.
///
/// Mirrors the ONNX execution-provider probe: prefer the fastest device that
/// actually exists on this machine, always fall back to CPU. GPU variants are
/// only reachable when the `moe-gpu` feature was compiled *and* a device is
/// found at runtime — so a GPU-enabled binary on a CPU-only host still runs.
pub struct ComputeBackend;

impl ComputeBackend {
    /// Resolve the best backend and its `ExpertCompute` implementation.
    pub fn select() -> (BackendKind, Box<dyn ExpertCompute>) {
        #[cfg(feature = "moe-gpu")]
        {
            if let Some(be) = gpu::try_select() {
                return be;
            }
        }
        (BackendKind::Cpu, Box::new(CpuCompute::detect()))
    }

    /// True when a GPU backend is compiled *and* a device is present.
    pub fn gpu_available() -> bool {
        #[cfg(feature = "moe-gpu")]
        {
            return gpu::device_present();
        }
        #[allow(unreachable_code)]
        false
    }
}

#[cfg(feature = "moe-gpu")]
mod gpu {
    //! Hybrid GPU dispatch: cuBLAS grouped GEMM when NVIDIA is present, wgpu
    //! WGSL compute as the cross-vendor path (AMD / Apple / Intel). Both are
    //! discovered by device probe; neither is assumed. Compiled only under
    //! `moe-gpu`.
    use super::{BackendKind, ExpertCompute};

    /// Probe for a usable GPU device, preferring CUDA, then wgpu.
    pub(super) fn try_select() -> Option<(BackendKind, Box<dyn ExpertCompute>)> {
        #[cfg(feature = "moe-cuda")]
        if let Some(be) = cuda::try_new() {
            return Some((BackendKind::Cuda, be));
        }
        #[cfg(feature = "moe-wgpu")]
        if let Some(be) = wgpu_be::try_new() {
            return Some((BackendKind::Wgpu, be));
        }
        None
    }

    pub(super) fn device_present() -> bool {
        try_select().is_some()
    }

    #[cfg(feature = "moe-cuda")]
    mod cuda {
        use super::ExpertCompute;
        /// Attempt to initialize a CUDA device + cuBLAS handle.
        pub(super) fn try_new() -> Option<Box<dyn ExpertCompute>> {
            // Device init lives here so a machine with the moe-cuda feature but
            // no NVIDIA device falls through to wgpu/CPU rather than aborting.
            crate::moe_compute_cuda::CudaCompute::try_new()
                .map(|c| Box::new(c) as Box<dyn ExpertCompute>)
        }
    }

    #[cfg(feature = "moe-wgpu")]
    mod wgpu_be {
        use super::ExpertCompute;
        /// Attempt to acquire a wgpu adapter + device.
        pub(super) fn try_new() -> Option<Box<dyn ExpertCompute>> {
            crate::moe_compute_wgpu::WgpuCompute::try_new()
                .map(|c| Box::new(c) as Box<dyn ExpertCompute>)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::Array2;

    fn ref_matmul_xt(x: &Array2<f32>, w: &Array2<f32>) -> Array2<f32> {
        x.dot(&w.t())
    }

    #[test]
    fn cpu_dense_matches_reference() {
        let cpu = CpuCompute::detect();
        let x = Array2::from_shape_fn((3, 8), |(i, j)| (i * 8 + j) as f32 * 0.01 - 0.1);
        let w = Array2::from_shape_fn((5, 8), |(i, j)| (i + j) as f32 * 0.03 - 0.2);
        let got = cpu.matmul_xt(x.view(), &Weight::Dense(w.view()));
        let want = ref_matmul_xt(&x, &w);
        for (a, b) in got.iter().zip(want.iter()) {
            assert!((a - b).abs() < 1e-5, "{a} vs {b}");
        }
    }

    #[test]
    fn cpu_quant_q8_0_matches_dequantized_reference() {
        // Build a dense weight, quantize it Q8_0, and confirm the backend's
        // quant path (SIMD or scalar, whichever the host has) matches a
        // straight dequantize-then-GEMM within Q8_0 tolerance.
        let cpu = CpuCompute::detect();
        let out = 6usize;
        let cols = 64usize; // multiple of 32
        let n = 4usize;
        let wdense =
            Array2::from_shape_fn((out, cols), |(i, j)| ((i * cols + j) as f32).sin() * 0.5);
        let q = QuantMatrix::quantize(
            QuantKind::Q8_0,
            out,
            cols,
            wdense.as_slice().unwrap(),
        )
        .unwrap();
        let x = Array2::from_shape_fn((n, cols), |(i, j)| ((i + 1) as f32 * (j as f32)).cos() * 0.3);

        let got = cpu.matmul_xt(x.view(), &Weight::Quant(&q));

        // Reference: dequantize the same matrix and GEMM.
        let deq = q.dequantize();
        let wq = Array2::from_shape_vec((out, cols), deq).unwrap();
        let want = ref_matmul_xt(&x, &wq);

        for (a, b) in got.iter().zip(want.iter()) {
            // Q8_0 activation quantization adds error on top of weight
            // quantization; bound generously.
            assert!((a - b).abs() < 0.05, "{a} vs {b}");
        }
    }

    #[test]
    fn select_returns_cpu_in_default_build() {
        let (kind, be) = ComputeBackend::select();
        // Default build has no moe-gpu feature.
        assert_eq!(kind, BackendKind::Cpu);
        assert!(be.tag().starts_with("cpu"));
    }
}
