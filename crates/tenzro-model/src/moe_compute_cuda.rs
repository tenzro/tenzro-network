//! cudarc / cuBLAS expert-compute backend (NVIDIA).
//!
//! The NVIDIA half of the hybrid GPU path: `Y = X · Wᵀ` runs as a single
//! cuBLAS SGEMM. Grouped-GEMM is inherent — the whole token batch is one GEMM
//! against one uploaded weight. Quantized weights are dequantized on the host
//! and uploaded dense.
//!
//! Compiled only under `moe-cuda`. [`CudaCompute::try_new`] returns `None`
//! when no CUDA device is present, so `ComputeBackend::select` falls through
//! to wgpu or CPU.
//!
//! ## Column-major mapping
//! cuBLAS is column-major. Host arrays are row-major. A row-major `A: [r, c]`
//! is bit-identical to a column-major `Aᵀ: [c, r]`. We want row-major
//! `Y[n,m] = X[n,k] · W[m,k]ᵀ`. Reading everything as its column-major
//! transpose, this is `Yᵀ[m,n] = W[k,m]?`… — concretely we call
//! `sgemm(op_a = T on W, op_b = N on X)` producing the column-major
//! `[m, n]` result whose row-major reading is exactly `Y[n, m]`.

use ndarray::{Array2, ArrayView2};
use parking_lot::Mutex;

use cudarc::cublas::sys::cublasOperation_t;
use cudarc::cublas::{CudaBlas, Gemm, GemmConfig};
use cudarc::driver::CudaDevice;

use crate::moe_compute::{ExpertCompute, Weight};

/// A CUDA device + cuBLAS handle.
pub struct CudaCompute {
    dev: std::sync::Arc<CudaDevice>,
    blas: CudaBlas,
    /// cuBLAS handle is not `Sync` for concurrent submission; serialize.
    lock: Mutex<()>,
}

// SAFETY: all device/handle access is serialized through `lock`; the raw
// handles are only touched while that mutex is held.
unsafe impl Send for CudaCompute {}
unsafe impl Sync for CudaCompute {}

impl CudaCompute {
    /// Try to initialize CUDA device 0 and a cuBLAS handle. Returns `None`
    /// when no device is present or driver init fails.
    pub fn try_new() -> Option<Self> {
        let dev = CudaDevice::new(0).ok()?;
        let blas = CudaBlas::new(dev.clone()).ok()?;
        Some(Self {
            dev,
            blas,
            lock: Mutex::new(()),
        })
    }

    fn run(&self, x: ArrayView2<'_, f32>, w_rowmajor: &[f32], m: usize, k: usize) -> Array2<f32> {
        let _g = self.lock.lock();
        let n = x.nrows();
        debug_assert_eq!(x.ncols(), k);

        let x_contig: Vec<f32> = x.iter().copied().collect();

        let x_dev = self.dev.htod_sync_copy(&x_contig).expect("htod x");
        let w_dev = self.dev.htod_sync_copy(w_rowmajor).expect("htod w");
        let mut y_dev = self.dev.alloc_zeros::<f32>(n * m).expect("alloc y");

        // Column-major view: X row-major [n,k] == col-major [k,n];
        // W row-major [m,k] == col-major [k,m]. We compute
        //   C[m,n] (col-major) = op(W)·op(X)
        // with op(W)=T (k,m -> m,k), op(X)=N (k,n). Leading dims are the
        // col-major strides: lda(W)=k, ldb(X)=k, ldc=m. The col-major C[m,n]
        // read row-major is Y[n,m] = X·Wᵀ.
        let cfg = GemmConfig {
            transa: cublasOperation_t::CUBLAS_OP_T,
            transb: cublasOperation_t::CUBLAS_OP_N,
            m: m as i32,
            n: n as i32,
            k: k as i32,
            alpha: 1.0f32,
            lda: k as i32,
            ldb: k as i32,
            beta: 0.0f32,
            ldc: m as i32,
        };
        // SAFETY: buffers are sized n*k, m*k, n*m as the config requires.
        unsafe {
            self.blas
                .gemm(cfg, &w_dev, &x_dev, &mut y_dev)
                .expect("cublas sgemm");
        }

        let out = self.dev.dtoh_sync_copy(&y_dev).expect("dtoh y");
        Array2::from_shape_vec((n, m), out).expect("shape matches n*m")
    }
}

impl ExpertCompute for CudaCompute {
    fn matmul_xt(&self, x: ArrayView2<'_, f32>, w: &Weight<'_>) -> Array2<f32> {
        let (m, k) = w.dim();
        match w {
            Weight::Dense(dw) => {
                let contig: Vec<f32> = dw.iter().copied().collect();
                self.run(x, &contig, m, k)
            }
            Weight::Quant(q) => {
                let dense = q.dequantize();
                self.run(x, &dense, m, k)
            }
        }
    }

    fn tag(&self) -> &'static str {
        "cuda"
    }
}
