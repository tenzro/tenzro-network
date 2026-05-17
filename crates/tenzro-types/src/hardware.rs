//! Hardware capability descriptors used across the Tenzro stack.
//!
//! Both `tenzro-network` (for `ProviderAnnouncementMessage`) and `tenzro-model`
//! (for `ModelProvisioner`) need to describe the hardware envelope of a node.
//! Lifting the type into `tenzro-types` keeps the dependency graph acyclic
//! (`tenzro-network -> tenzro-types`, `tenzro-model -> tenzro-network -> tenzro-types`).

use serde::{Deserialize, Serialize};

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
