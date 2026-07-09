//! Hardware capability descriptors used across the Tenzro stack.
//!
//! Both `tenzro-network` (for `ProviderAnnouncementMessage`) and `tenzro-model`
//! (for `ModelProvisioner`) need to describe the hardware envelope of a node.
//! Lifting the type into `tenzro-types` keeps the dependency graph acyclic
//! (`tenzro-network -> tenzro-types`, `tenzro-model -> tenzro-network -> tenzro-types`).
//!
//! Detection is fully automatic: [`HardwareCapabilities::detect`] probes the
//! local accelerators (nvidia-smi / rocm-smi / Apple unified memory) with no
//! operator configuration, and the result is gossiped as-is. Every field is
//! an *advertised* claim — consumers gate advertised hardware on observed
//! serving metrics before trusting it.

use serde::{Deserialize, Serialize};

/// Coarse hardware class the router uses to bias work assignment.
///
/// Deliberately coarse — the router does not need an exact accelerator
/// SKU, only enough to bias assignment toward providers that can serve a
/// given model class at all, then let observed latency separate the rest.
/// The ordering is the routing preference order for a request with no
/// stricter requirement: an accelerator beats many CPUs on token latency
/// for transformer decode regardless of core count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HardwareClass {
    /// Class not declared / undetected. Routed on observed metrics only.
    #[default]
    Unknown,
    /// CPU-only serving (no inference accelerator).
    Cpu,
    /// Consumer / workstation GPU (a single desktop-class card).
    ConsumerGpu,
    /// Datacenter inference accelerator (a serving-class GPU/TPU).
    DatacenterGpu,
    /// Multiple datacenter accelerators on one node.
    MultiAccelerator,
}

impl HardwareClass {
    /// Routing weight in `[0.0, 1.0]` this class contributes before the
    /// observed-performance gate is applied. `Unknown` is neutral (`0.5`)
    /// so an undetected provider is neither rewarded nor punished on the
    /// advertised axis and competes purely on observed metrics.
    pub fn advertised_weight(&self) -> f64 {
        match self {
            HardwareClass::Unknown => 0.5,
            HardwareClass::Cpu => 0.2,
            HardwareClass::ConsumerGpu => 0.5,
            HardwareClass::DatacenterGpu => 0.8,
            HardwareClass::MultiAccelerator => 1.0,
        }
    }

    /// Parses the wire form used on `InferenceParameters.custom` under the
    /// `min_hardware` key (case-insensitive). Returns `None` for an
    /// unrecognized value so a malformed hint is ignored rather than
    /// silently dropping every provider.
    pub fn parse_hint(s: &str) -> Option<HardwareClass> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cpu" => Some(HardwareClass::Cpu),
            "consumer_gpu" | "consumergpu" => Some(HardwareClass::ConsumerGpu),
            "datacenter_gpu" | "datacentergpu" | "gpu" => Some(HardwareClass::DatacenterGpu),
            "multi_accelerator" | "multiaccelerator" => Some(HardwareClass::MultiAccelerator),
            _ => None,
        }
    }

    /// Whether a provider of this class satisfies a request that requires
    /// at least `required`. `Unknown` never satisfies an explicit minimum —
    /// a request that sets a hardware floor is deliberately opting out of
    /// undetected providers.
    pub fn satisfies(&self, required: HardwareClass) -> bool {
        if required == HardwareClass::Unknown {
            return true;
        }
        if *self == HardwareClass::Unknown {
            return false;
        }
        *self >= required
    }
}

/// Accelerator vendor, driving the compute-capability interpretation and
/// the reduced-precision (FP8/FP4) derivation rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuVendor {
    /// NVIDIA — compute capability is the SM version string (`"8.9"`, `"9.0"`).
    Nvidia,
    /// AMD — compute capability is the gfx target (`"gfx942"`, `"gfx1100"`).
    Amd,
    /// Apple Silicon — unified-memory Metal GPU; no discrete VRAM.
    Apple,
    /// Any other accelerator (no precision derivation applied).
    #[default]
    Other,
}

/// One accelerator device visible to the node.
///
/// `fp8` / `fp4` are derived from vendor + compute capability at detection
/// time, never operator-declared: NVIDIA FP8 tensor cores exist from SM 8.9
/// (Ada) and 9.0 (Hopper), FP4 from SM 10.x/12.x (Blackwell); AMD FP8 matrix
/// cores from gfx942 (CDNA3 / MI300) and gfx12 (RDNA4 WMMA), FP4 from gfx950
/// (CDNA4 / MI350); Apple Silicon has neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuDevice {
    /// Accelerator vendor.
    pub vendor: GpuVendor,
    /// Device marketing name as reported by the driver
    /// (`"NVIDIA H100 80GB HBM3"`, `"AMD Instinct MI300X"`, `"Apple M3 Max"`).
    pub name: String,
    /// Device memory in GiB (unified-memory budget for Apple Silicon).
    pub vram_gb: u32,
    /// Vendor-native compute-capability string: SM version for NVIDIA,
    /// gfx target for AMD, `"metal"` for Apple. Empty when the probe could
    /// not determine it.
    pub compute_capability: String,
    /// Whether the device has hardware FP8 matrix/tensor units.
    pub fp8: bool,
    /// Whether the device has hardware FP4 matrix/tensor units.
    pub fp4: bool,
}

impl GpuDevice {
    /// Builds a device descriptor, deriving `fp8` / `fp4` from the vendor's
    /// compute-capability rules so precision support is never a free-form
    /// operator claim.
    pub fn new(
        vendor: GpuVendor,
        name: impl Into<String>,
        vram_gb: u32,
        compute_capability: impl Into<String>,
    ) -> Self {
        let compute_capability = compute_capability.into();
        let (fp8, fp4) = derive_precision(vendor, &compute_capability);
        Self {
            vendor,
            name: name.into(),
            vram_gb,
            compute_capability,
            fp8,
            fp4,
        }
    }
}

/// FP8 / FP4 hardware-unit derivation from vendor + compute capability.
fn derive_precision(vendor: GpuVendor, cc: &str) -> (bool, bool) {
    match vendor {
        GpuVendor::Nvidia => {
            let mut parts = cc.split('.');
            let major: u32 = parts
                .next()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            let minor: u32 = parts
                .next()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            let fp8 = major >= 9 || (major == 8 && minor >= 9);
            let fp4 = major >= 10;
            (fp8, fp4)
        }
        GpuVendor::Amd => {
            let fp8 = cc.starts_with("gfx94") || cc.starts_with("gfx95") || cc.starts_with("gfx12");
            let fp4 = cc.starts_with("gfx95");
            (fp8, fp4)
        }
        GpuVendor::Apple | GpuVendor::Other => (false, false),
    }
}

/// How the node's accelerators reach model weights and each other. Routing
/// and cluster planning use this to distinguish topologies where
/// tensor-parallel / expert-parallel splits are viable (NVLink-class) from
/// those where only layer-pipeline splits make sense (PCIe, LAN).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Interconnect {
    /// Not probed / not applicable.
    #[default]
    Unknown,
    /// CPU and GPU share one memory pool (Apple Silicon) — no weight copy,
    /// no offload boundary.
    UnifiedMemory,
    /// Discrete accelerators over PCIe (no high-bandwidth GPU-to-GPU link).
    Pcie,
    /// NVLink / NVSwitch-class GPU-to-GPU fabric (or vendor equivalent).
    NvlinkClass,
}

/// Hardware capabilities advertised by a provider node.
///
/// Used both as a local provisioning input (in `tenzro-model::ModelProvisioner`)
/// and as part of the gossiped `ProviderAnnouncementMessage` payload so that
/// consumers can route inference / TEE work by available memory, GPU presence,
/// and CPU shape without an extra round-trip RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwareCapabilities {
    /// Total RAM in GiB.
    pub ram_gb: u32,
    /// Total VRAM in GiB across all GPUs visible to the node (0 if no GPU).
    pub vram_gb: u32,
    /// Free disk space in GiB at the configured data directory.
    pub disk_gb: u32,
    /// Whether a usable TEE (TDX / SEV-SNP / Nitro / NVIDIA CC) was detected.
    pub tee_available: bool,
    /// CPU architecture string (`x86_64`, `aarch64`, …) per `std::env::consts::ARCH`.
    pub cpu_arch: String,
    /// Number of CPU cores reported by `std::thread::available_parallelism()`.
    pub cpu_cores: u32,
    /// Per-device accelerator inventory (empty when no accelerator was
    /// detected). `vram_gb` above is the sum over these devices.
    #[serde(default)]
    pub gpus: Vec<GpuDevice>,
    /// Accelerator interconnect topology.
    #[serde(default)]
    pub interconnect: Interconnect,
    /// Whether these values came from a local probe ([`Self::detect`]) as
    /// opposed to the type default. Providers that never ran detection are
    /// classed [`HardwareClass::Unknown`] and compete on observed metrics
    /// alone, rather than being misread as a declared CPU-only box.
    #[serde(default)]
    pub detected: bool,
}

impl Default for HardwareCapabilities {
    fn default() -> Self {
        Self {
            ram_gb: 8,
            vram_gb: 0,
            disk_gb: 50,
            tee_available: false,
            cpu_arch: std::env::consts::ARCH.to_string(),
            cpu_cores: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(4),
            gpus: Vec::new(),
            interconnect: Interconnect::Unknown,
            detected: false,
        }
    }
}

impl HardwareCapabilities {
    /// Detect hardware capabilities from the current system. Zero
    /// configuration: every probe is automatic and failure of any probe
    /// degrades to the coarser answer, never to an error.
    ///
    /// RAM: `/proc/meminfo` on Linux, `sysctl hw.memsize` on macOS.
    /// GPUs: `nvidia-smi` (name, memory, SM version), `rocm-smi` +
    /// `rocminfo` (name, memory, gfx target) on Linux; unified-memory
    /// Apple Silicon on macOS (budget ≈ 3/4 of RAM, matching Metal's
    /// recommended working-set ceiling).
    /// Interconnect: `nvidia-smi nvlink --status` distinguishes
    /// NVLink-class fabric from plain PCIe; Apple Silicon is unified memory.
    ///
    /// Shells out synchronously (tens of milliseconds when the vendor tools
    /// exist, a failed spawn otherwise) — call from a blocking context.
    pub fn detect() -> Self {
        let mut caps = Self::default();
        caps.detected = true;

        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if line.starts_with("MemTotal:")
                        && let Some(kb_str) = line.split_whitespace().nth(1)
                        && let Ok(kb) = kb_str.parse::<u64>()
                    {
                        caps.ram_gb = (kb / 1_048_576) as u32;
                    }
                }
            }

            caps.gpus = detect_nvidia_gpus();
            if caps.gpus.is_empty() {
                caps.gpus = detect_amd_gpus();
                if !caps.gpus.is_empty() {
                    caps.interconnect = Interconnect::Pcie;
                }
            } else {
                caps.interconnect = if nvlink_present() {
                    Interconnect::NvlinkClass
                } else {
                    Interconnect::Pcie
                };
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("sysctl").arg("-n").arg("hw.memsize").output()
                && let Ok(bytes_str) = String::from_utf8(output.stdout)
                && let Ok(bytes) = bytes_str.trim().parse::<u64>()
            {
                caps.ram_gb = (bytes / 1_073_741_824) as u32;
            }

            if std::env::consts::ARCH == "aarch64" {
                // Apple Silicon: the GPU shares the system memory pool.
                // Metal's recommended working-set ceiling is ~3/4 of RAM,
                // so that is the honest accelerator-memory budget.
                let name = Command::new("sysctl")
                    .args(["-n", "machdep.cpu.brand_string"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "Apple Silicon".to_string());
                caps.gpus = vec![GpuDevice::new(
                    GpuVendor::Apple,
                    name,
                    caps.ram_gb.saturating_mul(3) / 4,
                    "metal",
                )];
                caps.interconnect = Interconnect::UnifiedMemory;
            }
        }

        caps.vram_gb = caps.gpus.iter().map(|g| g.vram_gb).sum();
        caps
    }

    /// Derives the coarse [`HardwareClass`] the router uses for work
    /// assignment from the detected envelope. VRAM is the deciding axis
    /// for transformer serving: a node with no accelerator VRAM is
    /// CPU-class regardless of core count, and accelerator tiers separate
    /// on total VRAM. The thresholds are intentionally wide bands, not
    /// exact SKU boundaries — the router only needs enough resolution to
    /// bias assignment, and observed latency does the fine separation.
    ///
    /// A value that never went through [`Self::detect`] (a provider that
    /// omitted the hardware payload entirely) reads as
    /// [`HardwareClass::Unknown`]: it competes on observed metrics with a
    /// neutral advertised weight instead of being misread as CPU-only.
    pub fn class(&self) -> HardwareClass {
        if !self.detected {
            return HardwareClass::Unknown;
        }
        match self.vram_gb {
            0 => HardwareClass::Cpu,
            // A single consumer card tops out around 24 GiB.
            1..=24 => HardwareClass::ConsumerGpu,
            // A single datacenter accelerator sits in the 32–96 GiB band.
            25..=96 => HardwareClass::DatacenterGpu,
            // Beyond one datacenter card's VRAM implies multiple devices.
            _ => HardwareClass::MultiAccelerator,
        }
    }

    /// Whether this node's declared memory can hold a model whose resident
    /// footprint is `model_gb` GiB at all (weights only — the serving
    /// runtime does the finer free-memory admission locally at load time).
    ///
    /// Returns `None` when the hardware was never detected or the model
    /// size is unknown (`<= 0`), so the caller does not filter on an
    /// absent claim — undeclared providers compete neutrally per the
    /// trust-advertised model. The budget is RAM + VRAM because llama.cpp
    /// serves models split across both pools.
    pub fn can_hold_model(&self, model_gb: f32) -> Option<bool> {
        if !self.detected || model_gb <= 0.0 {
            return None;
        }
        let budget = if self.interconnect == Interconnect::UnifiedMemory {
            // Unified memory: RAM *is* the accelerator pool; don't double-count.
            self.ram_gb as f32
        } else {
            (self.ram_gb + self.vram_gb) as f32
        };
        Some(model_gb <= budget)
    }
}

/// Probe NVIDIA devices via `nvidia-smi`. `memory.total` with `nounits`
/// is MiB; `compute_cap` is the SM version (`"8.9"`, `"9.0"`).
#[cfg(target_os = "linux")]
fn detect_nvidia_gpus() -> Vec<GpuDevice> {
    let Ok(output) = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total,compute_cap",
            "--format=csv,noheader,nounits",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let Ok(stdout) = String::from_utf8(output.stdout) else {
        return Vec::new();
    };
    stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            if parts.len() < 3 || parts[0].is_empty() {
                return None;
            }
            let mib: u64 = parts[1].parse().ok()?;
            Some(GpuDevice::new(
                GpuVendor::Nvidia,
                parts[0],
                ((mib + 512) / 1024) as u32,
                parts[2],
            ))
        })
        .collect()
}

/// Probe AMD devices via `rocm-smi --json` (name + VRAM bytes) and pair
/// them positionally with the gfx targets `rocminfo` reports for GPU
/// agents. Either tool failing degrades to the coarser answer.
#[cfg(target_os = "linux")]
fn detect_amd_gpus() -> Vec<GpuDevice> {
    let Ok(output) = std::process::Command::new("rocm-smi")
        .args(["--showproductname", "--showmeminfo", "vram", "--json"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return Vec::new();
    };
    let Some(cards) = json.as_object() else {
        return Vec::new();
    };

    let gfx_targets = rocminfo_gfx_targets();

    let mut card_keys: Vec<&String> = cards.keys().filter(|k| k.starts_with("card")).collect();
    card_keys.sort();

    card_keys
        .iter()
        .enumerate()
        .filter_map(|(i, key)| {
            let card = cards.get(*key)?.as_object()?;
            let name = card
                .iter()
                .find(|(k, _)| k.to_ascii_lowercase().contains("card series")
                    || k.to_ascii_lowercase().contains("card model"))
                .and_then(|(_, v)| v.as_str())
                .unwrap_or("AMD GPU")
                .to_string();
            let vram_bytes: u64 = card
                .iter()
                .find(|(k, _)| k.to_ascii_lowercase().contains("vram total memory"))
                .and_then(|(_, v)| v.as_str())
                .and_then(|s| s.trim().parse().ok())?;
            let gfx = gfx_targets
                .get(i)
                .or_else(|| gfx_targets.first())
                .cloned()
                .unwrap_or_default();
            Some(GpuDevice::new(
                GpuVendor::Amd,
                name,
                ((vram_bytes + 536_870_912) / 1_073_741_824) as u32,
                gfx,
            ))
        })
        .collect()
}

/// gfx target names of GPU agents, in `rocminfo` agent order.
#[cfg(target_os = "linux")]
fn rocminfo_gfx_targets() -> Vec<String> {
    let Ok(output) = std::process::Command::new("rocminfo").output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let Ok(stdout) = String::from_utf8(output.stdout) else {
        return Vec::new();
    };
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let value = trimmed.strip_prefix("Name:")?.trim();
            value.starts_with("gfx").then(|| value.to_string())
        })
        .collect()
}

/// Whether any NVLink lane is up. `nvidia-smi nvlink --status` prints
/// per-link bandwidth lines (`… GB/s`) on NVLink-connected parts and
/// nothing (or an error) on PCIe-only parts.
#[cfg(target_os = "linux")]
fn nvlink_present() -> bool {
    std::process::Command::new("nvidia-smi")
        .args(["nvlink", "--status"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|s| s.contains("GB/s"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_arch_and_cores() {
        let caps = HardwareCapabilities::default();
        assert!(!caps.cpu_arch.is_empty());
        assert!(caps.cpu_cores >= 1);
    }

    #[test]
    fn detect_returns_nonzero_ram() {
        let caps = HardwareCapabilities::detect();
        // Detection may fall back to default on unusual platforms; the
        // default still reports a positive value (8 GiB), so this asserts
        // the contract in either branch.
        assert!(caps.ram_gb > 0);
        assert!(caps.detected);
        // The summed VRAM must equal the per-device inventory.
        let sum: u32 = caps.gpus.iter().map(|g| g.vram_gb).sum();
        assert_eq!(caps.vram_gb, sum);
    }

    #[test]
    fn undetected_reads_as_unknown_class() {
        let caps = HardwareCapabilities::default();
        assert_eq!(caps.class(), HardwareClass::Unknown);
        assert_eq!(caps.can_hold_model(4.0), None);
    }

    #[test]
    fn detected_classes_band_on_vram() {
        let mut caps = HardwareCapabilities {
            detected: true,
            ..Default::default()
        };
        assert_eq!(caps.class(), HardwareClass::Cpu);
        caps.vram_gb = 16;
        assert_eq!(caps.class(), HardwareClass::ConsumerGpu);
        caps.vram_gb = 80;
        assert_eq!(caps.class(), HardwareClass::DatacenterGpu);
        caps.vram_gb = 200;
        assert_eq!(caps.class(), HardwareClass::MultiAccelerator);
    }

    #[test]
    fn nvidia_precision_derivation() {
        let ada = GpuDevice::new(GpuVendor::Nvidia, "RTX 4090", 24, "8.9");
        assert!(ada.fp8);
        assert!(!ada.fp4);
        let hopper = GpuDevice::new(GpuVendor::Nvidia, "H100", 80, "9.0");
        assert!(hopper.fp8);
        assert!(!hopper.fp4);
        let blackwell = GpuDevice::new(GpuVendor::Nvidia, "B200", 192, "10.0");
        assert!(blackwell.fp8);
        assert!(blackwell.fp4);
        let ampere = GpuDevice::new(GpuVendor::Nvidia, "A100", 80, "8.0");
        assert!(!ampere.fp8);
        assert!(!ampere.fp4);
    }

    #[test]
    fn amd_precision_derivation() {
        let mi300 = GpuDevice::new(GpuVendor::Amd, "MI300X", 192, "gfx942");
        assert!(mi300.fp8);
        assert!(!mi300.fp4);
        let mi350 = GpuDevice::new(GpuVendor::Amd, "MI355X", 288, "gfx950");
        assert!(mi350.fp8);
        assert!(mi350.fp4);
        let rdna3 = GpuDevice::new(GpuVendor::Amd, "RX 7900 XTX", 24, "gfx1100");
        assert!(!rdna3.fp8);
        assert!(!rdna3.fp4);
    }

    #[test]
    fn apple_has_no_reduced_precision_units() {
        let m3 = GpuDevice::new(GpuVendor::Apple, "Apple M3 Max", 96, "metal");
        assert!(!m3.fp8);
        assert!(!m3.fp4);
    }

    #[test]
    fn memory_fit_uses_combined_pool_except_unified() {
        let discrete = HardwareCapabilities {
            detected: true,
            ram_gb: 64,
            vram_gb: 24,
            ..Default::default()
        };
        assert_eq!(discrete.can_hold_model(80.0), Some(true));
        assert_eq!(discrete.can_hold_model(100.0), Some(false));

        let unified = HardwareCapabilities {
            detected: true,
            ram_gb: 64,
            vram_gb: 48,
            interconnect: Interconnect::UnifiedMemory,
            ..Default::default()
        };
        // Unified memory must not double-count RAM + VRAM.
        assert_eq!(unified.can_hold_model(60.0), Some(true));
        assert_eq!(unified.can_hold_model(70.0), Some(false));
    }
}
