//! wgpu WGSL expert-compute backend (cross-vendor GPU).
//!
//! The cross-vendor half of the hybrid GPU path: a WGSL compute shader runs
//! `Y = X · Wᵀ` on whatever adapter wgpu finds (Vulkan / Metal / DX12).
//! Quantized weights are dequantized on the host and uploaded dense — the
//! dequant is cheap relative to the matmul and keeps the shader single-path.
//! Grouped-GEMM is inherent: the whole token batch is one dispatch against
//! one uploaded weight.
//!
//! Compiled only under `moe-wgpu`. [`WgpuCompute::try_new`] returns `None`
//! when no adapter is available, so `ComputeBackend::select` falls through to
//! the next backend (or CPU) on a machine with no usable GPU.

use ndarray::{Array2, ArrayView2};
use parking_lot::Mutex;

use crate::moe_compute::{ExpertCompute, Weight};

/// A wgpu device + queue + the compiled matmul pipeline.
pub struct WgpuCompute {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bind_layout: wgpu::BindGroupLayout,
    /// wgpu submission is not `Sync`-friendly to interleave; serialize calls.
    lock: Mutex<()>,
}

const WGSL: &str = r#"
struct Dims { n: u32, k: u32, m: u32, _pad: u32 };
@group(0) @binding(0) var<uniform> dims: Dims;
@group(0) @binding(1) var<storage, read> x: array<f32>;   // [n, k]
@group(0) @binding(2) var<storage, read> w: array<f32>;   // [m, k]  (row-major, Wᵀ implicit)
@group(0) @binding(3) var<storage, read_write> y: array<f32>; // [n, m]

@compute @workgroup_size(8, 8, 1)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x; // token row  [0, n)
    let j = gid.y; // output col [0, m)
    if (i >= dims.n || j >= dims.m) { return; }
    var acc: f32 = 0.0;
    let xoff = i * dims.k;
    let woff = j * dims.k;
    for (var t: u32 = 0u; t < dims.k; t = t + 1u) {
        acc = acc + x[xoff + t] * w[woff + t];
    }
    y[i * dims.m + j] = acc;
}
"#;

impl WgpuCompute {
    /// Try to acquire a wgpu adapter/device and compile the pipeline.
    /// Returns `None` when no adapter exists (headless CPU-only host).
    pub fn try_new() -> Option<Self> {
        pollster::block_on(Self::try_new_async())
    }

    async fn try_new_async() -> Option<Self> {
        let instance = wgpu::Instance::default();
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                force_fallback_adapter: false,
                compatible_surface: None,
            })
            .await?;
        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("tenzro-moe-expert"),
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::downlevel_defaults(),
                    memory_hints: wgpu::MemoryHints::Performance,
                },
                None,
            )
            .await
            .ok()?;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("moe-matmul-xt"),
            source: wgpu::ShaderSource::Wgsl(WGSL.into()),
        });
        let bind_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("moe-matmul-bind"),
            entries: &[
                uniform_entry(0),
                storage_entry(1, true),
                storage_entry(2, true),
                storage_entry(3, false),
            ],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("moe-matmul-pl"),
            bind_group_layouts: &[&bind_layout],
            push_constant_ranges: &[],
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("moe-matmul-pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache: None,
        });

        Some(Self {
            device,
            queue,
            pipeline,
            bind_layout,
            lock: Mutex::new(()),
        })
    }

    fn run(&self, x: ArrayView2<'_, f32>, w_rowmajor: &[f32], m: usize, k: usize) -> Array2<f32> {
        use wgpu::util::DeviceExt;
        let _g = self.lock.lock();
        let n = x.nrows();
        debug_assert_eq!(x.ncols(), k);

        let x_contig: Vec<f32> = x.iter().copied().collect();
        let dims = [n as u32, k as u32, m as u32, 0u32];

        let dims_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("dims"),
            contents: bytemuck::cast_slice(&dims),
            usage: wgpu::BufferUsages::UNIFORM,
        });
        let x_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("x"),
            contents: bytemuck::cast_slice(&x_contig),
            usage: wgpu::BufferUsages::STORAGE,
        });
        let w_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("w"),
            contents: bytemuck::cast_slice(w_rowmajor),
            usage: wgpu::BufferUsages::STORAGE,
        });
        let out_len = (n * m * std::mem::size_of::<f32>()) as u64;
        let y_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("y"),
            size: out_len,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let read_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("y-read"),
            size: out_len,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let bind = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("moe-bind"),
            layout: &self.bind_layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: dims_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 1, resource: x_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 2, resource: w_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 3, resource: y_buf.as_entire_binding() },
            ],
        });

        let mut enc = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("moe-enc") });
        {
            let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("moe-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &bind, &[]);
            let gx = (n as u32).div_ceil(8);
            let gy = (m as u32).div_ceil(8);
            pass.dispatch_workgroups(gx, gy, 1);
        }
        enc.copy_buffer_to_buffer(&y_buf, 0, &read_buf, 0, out_len);
        self.queue.submit(Some(enc.finish()));

        let slice = read_buf.slice(..);
        slice.map_async(wgpu::MapMode::Read, |_| {});
        self.device.poll(wgpu::Maintain::Wait);
        let data = slice.get_mapped_range();
        let out: Vec<f32> = bytemuck::cast_slice(&data).to_vec();
        drop(data);
        read_buf.unmap();

        Array2::from_shape_vec((n, m), out).expect("shape matches n*m")
    }
}

fn uniform_entry(binding: u32) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Uniform,
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}

fn storage_entry(binding: u32, read_only: bool) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Storage { read_only },
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}

impl ExpertCompute for WgpuCompute {
    fn matmul_xt(&self, x: ArrayView2<'_, f32>, w: &Weight<'_>) -> Array2<f32> {
        let (m, k) = w.dim();
        match w {
            Weight::Dense(dw) => {
                let contig: Vec<f32> = dw.iter().copied().collect();
                self.run(x, &contig, m, k)
            }
            Weight::Quant(q) => {
                // Dequantize to dense on the host, then upload. Cheap vs the
                // matmul and keeps the shader single-path.
                let dense = q.dequantize();
                self.run(x, &dense, m, k)
            }
        }
    }

    fn tag(&self) -> &'static str {
        "wgpu"
    }
}
