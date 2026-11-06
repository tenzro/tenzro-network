//! What each build of tenzro-node may do on the machine it runs on.
//!
//! Each platform has a CPU build and GPU builds: CUDA for NVIDIA and Vulkan
//! for AMD, Intel and other Vulkan GPUs on Linux and Windows, Metal on macOS.
//! None falls back to another:
//!
//! - A GPU build on a machine with no usable GPU or driver refuses to start
//!   and names the CPU build ([`check_startup`]).
//! - A CPU build serves the roles that need no accelerator (validator, rpc,
//!   storage, light, ...) and CPU-tier models, and refuses a GPU-tier model
//!   with a message naming the GPU build ([`check_model`]).
//! - Model admission is decided by the accelerators this process can actually
//!   drive ([`usable_accelerators`]), not by the build alone. Role admission
//!   is the node's `validate_role_capability`: the roles a CPU build serves
//!   need no accelerator, and `compute` needs one present on the machine,
//!   since it rents the card to someone else's workload.

/// Largest weight footprint served on the CPU tier. Above it decode on a CPU
/// is too slow to meet a serving deadline, so the model is GPU-tier.
pub const CPU_TIER_MAX_WEIGHT_BYTES: u64 = 6 * 1024 * 1024 * 1024;

/// The accelerator backend a build was compiled with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildFlavour {
    /// No GPU backend: every layer runs on the CPU.
    Cpu,
    /// NVIDIA CUDA.
    Cuda,
    /// Apple Metal.
    Metal,
    /// Another GPU backend (ROCm, Vulkan, SYCL, ...), named by its feature.
    OtherGpu(&'static str),
}

/// GPU backends recognised in a compiled-backend list, in preference order.
const GPU_BACKENDS: &[(&str, BuildFlavour)] = &[
    ("cuda", BuildFlavour::Cuda),
    ("cuda-no-vmm", BuildFlavour::Cuda),
    ("metal", BuildFlavour::Metal),
    ("rocm", BuildFlavour::OtherGpu("rocm")),
    ("vulkan", BuildFlavour::OtherGpu("vulkan")),
    ("sycl", BuildFlavour::OtherGpu("sycl")),
    ("musa", BuildFlavour::OtherGpu("musa")),
    ("cann", BuildFlavour::OtherGpu("cann")),
    ("opencl", BuildFlavour::OtherGpu("opencl")),
    ("webgpu", BuildFlavour::OtherGpu("webgpu")),
];

impl BuildFlavour {
    /// The flavour of a build with these compiled backends
    /// ([`crate::runtime::HardwareInfo::compiled_backends`]).
    pub fn of(compiled: &[String]) -> Self {
        GPU_BACKENDS
            .iter()
            .find(|(name, _)| compiled.iter().any(|c| c == name))
            .map(|(_, f)| *f)
            .unwrap_or(BuildFlavour::Cpu)
    }

    /// The flavour of this binary.
    pub fn current() -> Self {
        if cfg!(any(feature = "cuda", feature = "cuda-no-vmm")) {
            BuildFlavour::Cuda
        } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) || cfg!(feature = "metal")
        {
            BuildFlavour::Metal
        } else if cfg!(feature = "rocm") {
            BuildFlavour::OtherGpu("rocm")
        } else if cfg!(feature = "vulkan") {
            BuildFlavour::OtherGpu("vulkan")
        } else if cfg!(feature = "sycl") {
            BuildFlavour::OtherGpu("sycl")
        } else {
            BuildFlavour::Cpu
        }
    }

    pub fn is_gpu(&self) -> bool {
        *self != BuildFlavour::Cpu
    }

    pub fn label(&self) -> &'static str {
        match self {
            BuildFlavour::Cpu => "CPU",
            BuildFlavour::Cuda => "CUDA",
            BuildFlavour::Metal => "Metal",
            BuildFlavour::OtherGpu("vulkan") => "Vulkan",
            BuildFlavour::OtherGpu("rocm") => "ROCm",
            BuildFlavour::OtherGpu(name) => name,
        }
    }

    /// Whether ONNX Runtime has an execution provider for this build's GPU
    /// backend. It has none for Vulkan and the other cross-vendor backends:
    /// such a build serves llama.cpp models on the GPU and refuses ONNX models
    /// on a GPU that another build accelerates, model by model, so a refused
    /// ONNX plan does not stop it from starting.
    pub fn accelerates_onnx(&self) -> bool {
        matches!(
            self,
            BuildFlavour::Cpu
                | BuildFlavour::Cuda
                | BuildFlavour::Metal
                | BuildFlavour::OtherGpu("rocm")
        )
    }
}

/// Release artifact name of the CPU build for this platform.
pub fn cpu_artifact() -> String {
    format!(
        "tenzro-node-{}-{}-cpu",
        platform_os(),
        std::env::consts::ARCH
    )
}

/// Release artifact names of the GPU builds for this platform.
pub fn gpu_artifact() -> String {
    let arch = std::env::consts::ARCH;
    match platform_os() {
        "macos" => format!("tenzro-node-macos-{arch}-metal"),
        os => format!(
            "tenzro-node-{os}-{arch}-cuda for NVIDIA, tenzro-node-{os}-{arch}-vulkan for AMD, \
             Intel and other Vulkan GPUs"
        ),
    }
}

fn platform_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    }
}

/// Number of GPU devices the compiled backends can drive in this process.
/// Zero on a CPU build, and on a GPU build whose device or driver is missing.
#[cfg(feature = "engine")]
pub fn usable_accelerators() -> usize {
    llama_cpp_2::list_llama_ggml_backend_devices()
        .iter()
        .filter(|d| {
            matches!(
                d.device_type,
                llama_cpp_2::LlamaBackendDeviceType::Gpu
                    | llama_cpp_2::LlamaBackendDeviceType::IntegratedGpu
            )
        })
        .count()
}

/// Whether a build may start with `usable` accelerators. A GPU build with
/// none refuses rather than serving every layer on the CPU.
pub fn check_startup(flavour: BuildFlavour, usable: usize) -> Result<(), String> {
    if flavour.is_gpu() && usable == 0 {
        return Err(format!(
            "this is the {} build of tenzro-node, but no usable {} GPU or driver was found on \
             this machine, and it does not fall back to the CPU. Install the CPU build ({}) to \
             run the validator, rpc, storage or light roles and CPU-tier models, or install the \
             GPU driver.",
            flavour.label(),
            flavour.label(),
            cpu_artifact(),
        ));
    }
    Ok(())
}

/// The hardware a model needs to be served within a deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingTier {
    /// Small enough to serve on CPU cores.
    Cpu,
    /// Needs an accelerator.
    Gpu,
}

impl ServingTier {
    /// Tier of a model whose resident weights take `bytes`.
    pub fn of_weights(bytes: u64) -> Self {
        if bytes > CPU_TIER_MAX_WEIGHT_BYTES {
            ServingTier::Gpu
        } else {
            ServingTier::Cpu
        }
    }
}

/// Whether this process may serve `model_id` with `weight_bytes` of weights
/// when it can drive `usable` accelerators.
pub fn check_model(model_id: &str, weight_bytes: u64, usable: usize) -> Result<(), String> {
    if ServingTier::of_weights(weight_bytes) == ServingTier::Gpu && usable == 0 {
        return Err(format!(
            "model {model_id} is GPU-tier ({:.1} GiB of weights, above the {} GiB CPU tier) and \
             this node has no usable GPU; it serves CPU-tier models only. Serving it needs the \
             GPU build ({}) on a machine with a working GPU.",
            weight_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            CPU_TIER_MAX_WEIGHT_BYTES / (1024 * 1024 * 1024),
            gpu_artifact(),
        ));
    }
    Ok(())
}

/// The startup decision for this binary on this machine. Probes the
/// accelerators, so call it from a blocking thread.
#[cfg(feature = "engine")]
pub fn verify_this_machine() -> Result<(), String> {
    check_startup(BuildFlavour::current(), usable_accelerators())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    /// The node's startup check is this policy applied to this binary on this
    /// machine, and the node runs it before anything else starts: a GPU build
    /// on a host with no usable GPU never comes up, and a CPU build comes up
    /// for the roles that need no accelerator.
    #[cfg(feature = "engine")]
    #[test]
    fn startup_applies_the_policy_to_this_build_on_this_machine() {
        let usable = usable_accelerators();
        assert_eq!(
            verify_this_machine(),
            check_startup(BuildFlavour::current(), usable)
        );
        if !BuildFlavour::current().is_gpu() {
            assert!(verify_this_machine().is_ok());
        }
        let main = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tenzro-node/src/main.rs"),
        )
        .expect("node main");
        let check = main
            .find("spawn_blocking(tenzro_model::hardware_policy::verify_this_machine)")
            .expect("the node runs the hardware policy at startup");
        let start = main.find("print_node_info(&config)").expect("node start");
        assert!(
            check < start,
            "the hardware policy runs before the node starts"
        );
        assert!(
            main[check..start].contains(".map_err(error::NodeError::Config)?"),
            "a refusal stops startup"
        );
    }

    #[test]
    fn a_gpu_build_without_a_usable_gpu_refuses_and_names_the_cpu_build() {
        for flavour in [
            BuildFlavour::Cuda,
            BuildFlavour::Metal,
            BuildFlavour::OtherGpu("rocm"),
            BuildFlavour::OtherGpu("vulkan"),
        ] {
            let err = check_startup(flavour, 0).unwrap_err();
            assert!(err.contains(&cpu_artifact()), "{err}");
            assert!(err.contains("does not fall back"), "{err}");
            assert!(check_startup(flavour, 1).is_ok());
        }
        assert!(check_startup(BuildFlavour::Cpu, 0).is_ok());
        assert!(check_startup(BuildFlavour::Cpu, 2).is_ok());
    }

    #[test]
    fn the_flavour_follows_the_compiled_backends() {
        let with = |b: &[&str]| b.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(BuildFlavour::of(&with(&["cpu"])), BuildFlavour::Cpu);
        assert_eq!(BuildFlavour::of(&with(&["cpu", "blas"])), BuildFlavour::Cpu);
        assert_eq!(
            BuildFlavour::of(&with(&["cpu", "cuda"])),
            BuildFlavour::Cuda
        );
        assert_eq!(
            BuildFlavour::of(&with(&["cpu", "metal"])),
            BuildFlavour::Metal
        );
        assert_eq!(
            BuildFlavour::of(&with(&["cpu", "vulkan"])),
            BuildFlavour::OtherGpu("vulkan")
        );
        assert_eq!(BuildFlavour::OtherGpu("vulkan").label(), "Vulkan");
        assert!(!BuildFlavour::OtherGpu("vulkan").accelerates_onnx());
        assert!(BuildFlavour::Cuda.accelerates_onnx() && BuildFlavour::Cpu.accelerates_onnx());
    }

    #[test]
    fn a_node_without_a_gpu_refuses_gpu_tier_models_only() {
        assert!(check_model("small", 4 * GIB, 0).is_ok());
        assert!(check_model("edge", CPU_TIER_MAX_WEIGHT_BYTES, 0).is_ok());
        let err = check_model("large", 20 * GIB, 0).unwrap_err();
        assert!(
            err.contains("GPU-tier") && err.contains(&gpu_artifact()),
            "{err}"
        );
        assert!(check_model("large", 20 * GIB, 1).is_ok());
    }
}
