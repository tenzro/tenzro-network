//! Hardware capability descriptors used across the Tenzro stack.
//!
//! Both `tenzro-network` (for `ProviderAnnouncementMessage`) and `tenzro-model`
//! (for `ModelProvisioner`) need to describe the hardware envelope of a node.
//! Lifting the type into `tenzro-types` keeps the dependency graph acyclic
//! (`tenzro-network -> tenzro-types`, `tenzro-model -> tenzro-network -> tenzro-types`).

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
        }
    }
}

impl HardwareCapabilities {
    /// Detect hardware capabilities from the current system.
    ///
    /// Linux: parses `/proc/meminfo` for `MemTotal:`.
    /// macOS: shells out to `sysctl -n hw.memsize`.
    /// All other fields fall back to the `Default` values; richer detection
    /// (GPU / disk free / TEE probe) is layered in by `tenzro-tee` and the
    /// node's startup sequence before the value is broadcast.
    pub fn detect() -> Self {
        let mut caps = Self::default();

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
        }

        caps
    }

    /// Derives the coarse [`HardwareClass`] the router uses for work
    /// assignment from the detected envelope. VRAM is the deciding axis
    /// for transformer serving: a node with no accelerator VRAM is
    /// CPU-class regardless of core count, and accelerator tiers separate
    /// on total VRAM. The thresholds are intentionally wide bands, not
    /// exact SKU boundaries — the router only needs enough resolution to
    /// bias assignment, and observed latency does the fine separation.
    pub fn class(&self) -> HardwareClass {
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
    }
}
