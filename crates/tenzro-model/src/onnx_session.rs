//! ONNX sessions, built by the Praecise engine's ONNX backend.
//!
//! [`praecise_onnx::session`] builds every session the ONNX-backed runtimes
//! (timeseries, vision, text-embedding, segmentation, text-segmentation,
//! detection, audio, and video through the vision encoders) load, and picks
//! the execution providers from the GPUs this module declares to it:
//! - On a machine with an NVIDIA GPU every session runs on CUDA, with
//!   TensorRT ahead of it when the linked ONNX Runtime carries the TensorRT
//!   provider and the TensorRT library is installed. A binary that cannot
//!   do that (built without the `cuda` feature, or linked against an ONNX
//!   Runtime without the CUDA provider) refuses: [`verify_accelerators`]
//!   stops the node at startup and every model load fails with the cause.
//! - On a machine with an AMD GPU every session runs on MIGraphX and/or
//!   ROCm, whichever the linked ONNX Runtime lists. A binary built without
//!   the `rocm` feature, or linked against an ONNX Runtime with neither
//!   provider, refuses the same way.
//! - ONNX Runtime has no Vulkan execution provider, so on a machine whose
//!   only GPU is another Vulkan-class device (Intel and others) sessions run
//!   on the CPU provider. The Vulkan build serves llama.cpp models on an
//!   NVIDIA or AMD GPU and refuses ONNX models there, naming the build that
//!   accelerates them.
//! - A provider that is expected and fails to register is an error. The
//!   model does not load, rather than silently running on the CPU.
//! - On Apple builds with `onnx-coreml`, sessions run on CoreML.
//! - Without an accelerator, sessions run on ONNX Runtime's CPU provider.
//!
//! Every model file passes the parse jail before ONNX Runtime opens it.
//!
//! Thread pools are bounded: intra-op and inter-op threads default to a
//! quarter of the detected cores (at least one), so one burst of requests
//! cannot take every core. The node's `[onnx]` config overrides this once
//! for every runtime; see [`OnnxConfig`].

use std::path::Path;
use std::sync::OnceLock;

use crate::error::{ModelError, Result};

// The `[onnx]` table and its resolution build without the engine, so a node
// configuration parses the same in every build.
pub use crate::engine_config::{OnnxConfig, OnnxSettings};
pub use praecise_onnx::session::{Accelerator, ProviderFacts, plan_providers};

static SETTINGS: OnceLock<OnnxSettings> = OnceLock::new();
static DECLARED: OnceLock<std::result::Result<(), String>> = OnceLock::new();

/// Install the operator's ONNX settings for this process. Called once at
/// node startup, before any model loads. Returns `false` when settings were
/// already fixed, in which case the earlier ones stay in force.
pub fn install(settings: OnnxSettings) -> bool {
    SETTINGS.set(settings).is_ok()
}

/// The ONNX settings in force: the installed ones, or the core-derived
/// defaults when nothing was installed.
pub fn settings() -> OnnxSettings {
    *SETTINGS.get_or_init(OnnxSettings::detected)
}

/// Whether this build loads ONNX Runtime at run time instead of linking it.
/// ONNX Runtime publishes no prebuilt library for Intel macOS, so that build
/// finds `libonnxruntime.dylib` (or the file `ORT_DYLIB_PATH` names) when the
/// first ONNX model loads, and has no ONNX models when it is not there.
const RUNTIME_LOADED_AT_RUN_TIME: bool = cfg!(all(target_os = "macos", target_arch = "x86_64"));

/// Load ONNX Runtime where the build links it at run time. Fails with the
/// cause when the library is missing or unusable; every other build has it
/// linked and returns at once.
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn load_runtime() -> std::result::Result<(), String> {
    let path = std::env::var_os("ORT_DYLIB_PATH")
        .filter(|p| !p.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("libonnxruntime.dylib"));
    ort::init_from(&path).map(drop).map_err(|e| {
        format!(
            "ONNX Runtime is not available on this Intel Mac ({e}); ONNX models cannot load \
             until ORT_DYLIB_PATH names an x86_64 libonnxruntime.dylib"
        )
    })
}

#[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
fn load_runtime() -> std::result::Result<(), String> {
    Ok(())
}

/// Hand the engine the settings in force, the GPUs this machine has and the
/// parse jail, once per process, before any session is built. Detection
/// shells out to the GPU vendor tools, so the first call belongs on a
/// blocking thread; node startup makes it through [`verify_accelerators`].
///
/// Fails, for every caller and without building anything, when the ONNX
/// Runtime this build loads at run time is not there.
pub(crate) fn declare() -> Result<()> {
    DECLARED
        .get_or_init(|| {
            load_runtime()?;
            let s = settings();
            let gpus = crate::runtime::detected_gpu_vendors();
            praecise_onnx::session::install(
                praecise_onnx::session::OnnxSettings {
                    threads: s.threads,
                    concurrency: s.concurrency,
                    queue_depth: s.queue_depth,
                },
                praecise_onnx::session::Gpus {
                    nvidia: gpus.contains(&tenzro_types::GpuVendor::Nvidia),
                    amd: gpus.contains(&tenzro_types::GpuVendor::Amd),
                },
            );
            praecise_onnx::session::set_admission(admit);
            Ok(())
        })
        .clone()
        .map_err(ModelError::ProviderNotAvailable)
}

/// Why this node has no ONNX models, when the build loads ONNX Runtime at
/// run time and it is not there. `None` in every other case, including every
/// build that links the runtime.
pub fn runtime_unavailable() -> Option<String> {
    if !RUNTIME_LOADED_AT_RUN_TIME {
        return None;
    }
    match declare() {
        Err(ModelError::ProviderNotAvailable(cause)) => Some(cause),
        _ => None,
    }
}

/// The parse jail's verdict on an ONNX model file.
fn admit(path: &Path) -> std::result::Result<(), String> {
    crate::parse_jail::admit(path, crate::parse_jail::ModelFormat::Onnx)
        .map(drop)
        .map_err(|e| e.to_string())
}

/// The execution providers every ONNX session registers on this machine.
pub fn accelerators() -> Result<&'static [Accelerator]> {
    declare()?;
    praecise_onnx::session::accelerators().map_err(ModelError::from)
}

/// Startup check: fails when this binary cannot run ONNX models on the
/// accelerator this machine has.
///
/// A node whose ONNX Runtime is loaded at run time and is not there still
/// starts: it serves every other model and refuses each ONNX model with the
/// cause, which is logged here once.
pub fn verify_accelerators() -> Result<()> {
    if let Some(cause) = runtime_unavailable() {
        tracing::warn!(%cause, "ONNX models are unavailable on this node");
        return Ok(());
    }
    declare()?;
    praecise_onnx::session::verify_accelerators().map_err(ModelError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cuda_machine() -> ProviderFacts {
        ProviderFacts {
            cuda_gpu: true,
            cuda_build: true,
            cuda_provider: true,
            ..ProviderFacts::default()
        }
    }

    #[test]
    fn cuda_machine_runs_every_session_on_cuda() {
        assert_eq!(plan_providers(&cuda_machine()), Ok(vec![Accelerator::Cuda]));
    }

    #[test]
    fn tensorrt_leads_only_when_listed_and_installed() {
        let listed_not_installed = ProviderFacts {
            tensorrt_provider: true,
            ..cuda_machine()
        };
        assert_eq!(
            plan_providers(&listed_not_installed),
            Ok(vec![Accelerator::Cuda])
        );
        let installed = ProviderFacts {
            tensorrt_provider: true,
            tensorrt_runtime: true,
            ..cuda_machine()
        };
        assert_eq!(
            plan_providers(&installed),
            Ok(vec![Accelerator::TensorRt, Accelerator::Cuda])
        );
    }

    #[test]
    fn cuda_build_with_cpu_only_onnx_runtime_refuses() {
        let facts = ProviderFacts {
            cuda_provider: false,
            ..cuda_machine()
        };
        let cause = plan_providers(&facts).unwrap_err();
        assert!(cause.contains("no CUDA execution provider"), "{cause}");
    }

    #[test]
    fn cpu_build_on_a_gpu_machine_refuses() {
        let facts = ProviderFacts {
            cuda_gpu: true,
            ..ProviderFacts::default()
        };
        let cause = plan_providers(&facts).unwrap_err();
        assert!(cause.contains("without the `cuda` feature"), "{cause}");
    }

    #[test]
    fn vulkan_build_refuses_onnx_on_a_gpu_another_build_accelerates() {
        for (gpu, build) in [
            (
                ProviderFacts {
                    cuda_gpu: true,
                    ..ProviderFacts::default()
                },
                "CUDA build",
            ),
            (
                ProviderFacts {
                    amd_gpu: true,
                    ..ProviderFacts::default()
                },
                "ROCm build",
            ),
        ] {
            let facts = ProviderFacts {
                vulkan_build: true,
                ..gpu
            };
            let cause = plan_providers(&facts).unwrap_err();
            assert!(
                cause.contains("Vulkan build") && cause.contains(build),
                "{cause}"
            );
        }
        let intel = ProviderFacts {
            vulkan_build: true,
            ..ProviderFacts::default()
        };
        assert_eq!(plan_providers(&intel), Ok(Vec::new()));
    }

    #[test]
    fn amd_machine_refuses_the_cpu() {
        let cpu_build = ProviderFacts {
            amd_gpu: true,
            ..ProviderFacts::default()
        };
        let cause = plan_providers(&cpu_build).unwrap_err();
        assert!(cause.contains("without the `rocm` feature"), "{cause}");

        let no_provider = ProviderFacts {
            rocm_build: true,
            ..cpu_build
        };
        let cause = plan_providers(&no_provider).unwrap_err();
        assert!(
            cause.contains("neither the MIGraphX nor the ROCm"),
            "{cause}"
        );

        let rocm = ProviderFacts {
            rocm_provider: true,
            ..no_provider
        };
        assert_eq!(plan_providers(&rocm), Ok(vec![Accelerator::Rocm]));
        let both = ProviderFacts {
            migraphx_provider: true,
            ..rocm
        };
        assert_eq!(
            plan_providers(&both),
            Ok(vec![Accelerator::MiGraphX, Accelerator::Rocm])
        );
    }

    #[test]
    fn machine_without_a_gpu_runs_on_the_cpu() {
        let cuda_build_no_gpu = ProviderFacts {
            cuda_gpu: false,
            ..cuda_machine()
        };
        assert_eq!(plan_providers(&cuda_build_no_gpu), Ok(Vec::new()));
        assert_eq!(plan_providers(&ProviderFacts::default()), Ok(Vec::new()));
    }

    #[test]
    fn coreml_build_needs_the_coreml_provider() {
        let missing = ProviderFacts {
            coreml_build: true,
            ..ProviderFacts::default()
        };
        assert!(plan_providers(&missing).is_err());
        let present = ProviderFacts {
            coreml_build: true,
            coreml_provider: true,
            ..ProviderFacts::default()
        };
        assert_eq!(plan_providers(&present), Ok(vec![Accelerator::CoreMl]));
    }

    #[test]
    fn threads_default_to_a_quarter_of_the_cores() {
        assert_eq!(
            OnnxSettings::resolve(&OnnxConfig::default(), 56).threads,
            14
        );
        assert_eq!(OnnxSettings::resolve(&OnnxConfig::default(), 3).threads, 1);
        assert_eq!(OnnxSettings::resolve(&OnnxConfig::default(), 0).threads, 1);
    }

    #[test]
    fn configured_limits_override_the_defaults() {
        let config = OnnxConfig {
            threads: Some(3),
            concurrency: Some(2),
            queue_depth: Some(5),
        };
        let s = OnnxSettings::resolve(&config, 56);
        assert_eq!(
            s,
            OnnxSettings {
                threads: 3,
                concurrency: 2,
                queue_depth: 5
            }
        );
    }

    #[test]
    fn default_concurrency_fits_the_cores() {
        let s = OnnxSettings::resolve(&OnnxConfig::default(), 56);
        assert!(s.threads as u32 * s.concurrency <= 56);
        assert_eq!(s.queue_depth, s.concurrency * 4);
    }
}
