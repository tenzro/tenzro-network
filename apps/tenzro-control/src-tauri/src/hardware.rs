//! Host hardware probe.
//!
//! Control runs on whatever machine the operator installs it on: a 6 GB
//! Raspberry Pi, an 8 GB Intel laptop with no discrete GPU, a 16 GB Apple
//! Silicon laptop, a 24 GB workstation with an RTX, a 96 GB Mac Studio.
//! Onboarding asks the operator which roles they want to provide, and the
//! answer to "can this machine actually do that" has to come from a real
//! probe rather than from a guess typed into a settings pane.
//!
//! Probe layer: `sysinfo` for RAM, logical cores and disk free space
//! cross-platform, plus OS-native sysctl on macOS for the P-core count and
//! Apple-Silicon detection. GPU class comes from cheap presence checks
//! (`nvidia-smi` / `rocm-smi` in PATH, sysctl `hw.optional.arm64`, Windows
//! WMI `Win32_VideoController`). VRAM accounting via NVML or Metal's
//! `recommendedMaxWorkingSetSize` is not attempted — the model-fit budget
//! works off system RAM, which is the binding constraint on every
//! unified-memory host and a safe under-estimate on discrete-GPU hosts.
//!
//! The node enforces role admission itself in `validate_role_capability`.
//! What this module produces is the UX affordance in front of that gate:
//! the operator sees why a role is unavailable before they pick it, instead
//! of picking it and getting an RPC error.

use std::process::Command;

use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};

/// Coarse GPU class.
///
/// `Cuda` and `Rocm` are constructed only on Linux/Windows code paths in
/// [`probe_gpu_class`]; on macOS those variants exist but are never
/// produced — deliberate cross-platform asymmetry, not dead code. The
/// cfg-scoped allow keeps macOS builds warning-clean without hiding the
/// same warning on Linux/Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub enum GpuClass {
    /// No GPU offload available — CPU-only inference.
    None,
    /// Apple Silicon unified-memory GPU. Shares RAM with the OS.
    AppleSilicon,
    /// Discrete NVIDIA GPU (CUDA path), detected via `nvidia-smi` in PATH.
    Cuda,
    /// Discrete AMD GPU (ROCm path), detected via `rocm-smi` in PATH.
    Rocm,
    /// Intel integrated graphics, AMD APU, or a legacy Intel Mac discrete
    /// GPU. Shares the memory surface with the compositor, same as Apple
    /// Silicon.
    IntelOrIntegrated,
}

#[derive(Debug, Clone)]
pub struct HardwareProfile {
    /// Total system RAM in gigabytes (rounded down to whole GB).
    pub ram_gb: u32,
    /// Physical CPU core count. For SMT machines we want physical, not
    /// logical: inference matmul is memory-bandwidth-bound and SMT siblings
    /// contend on the same FPU and L1.
    pub physical_cores: u32,
    /// Detected GPU class.
    pub gpu_class: GpuClass,
    /// Free space (GB, rounded down) on the disk backing the user's home
    /// directory — the volume models download to and the volume a storage
    /// provider serves shards from.
    pub free_disk_gb: u32,
}

impl HardwareProfile {
    pub fn detect() -> Self {
        let mut sys = System::new();
        sys.refresh_memory();
        sys.refresh_cpu_list(sysinfo::CpuRefreshKind::new());
        let ram_gb = (sys.total_memory() / 1024 / 1024 / 1024) as u32;
        Self {
            ram_gb: ram_gb.max(1),
            physical_cores: probe_physical_cores(&sys),
            gpu_class: probe_gpu_class(),
            free_disk_gb: probe_free_disk_gb(),
        }
    }

    /// A plain-language capability readout for onboarding: what this machine
    /// can offer the network, derived entirely from the detected profile.
    ///
    /// The reserves are deliberately conservative. We never advertise the
    /// machine's full RAM or disk, because the OS, the app and any in-flight
    /// inference all need headroom. `offerable_storage_gb` holds back a
    /// reserve so a storage provider can't fill the boot volume.
    pub fn readout(&self) -> CapabilityReadout {
        // Hold back the larger of 20% of free disk or a flat 20 GB so a
        // storage provider never fills the volume the OS boots from.
        let disk_reserve_gb = (self.free_disk_gb / 5).max(20);
        let offerable_storage_gb = self.free_disk_gb.saturating_sub(disk_reserve_gb);

        CapabilityReadout {
            ram_gb: self.ram_gb,
            physical_cores: self.physical_cores,
            gpu: self.gpu_label().to_string(),
            gpu_class: self.gpu_class,
            free_disk_gb: self.free_disk_gb,
            offerable_storage_gb,
            roles: self.role_capabilities(offerable_storage_gb),
        }
    }

    /// A verdict for every role Control offers, in the order the role picker
    /// lists them.
    ///
    /// Each verdict mirrors the matching check in the node's
    /// `validate_role_capability`, because Control is the affordance in front
    /// of that gate: a role reported available here has to be one the node
    /// will actually accept.
    fn role_capabilities(&self, offerable_storage_gb: u32) -> Vec<RoleCapability> {
        // Serving AI is permissionless: the floor is the smallest catalogue
        // model, Gemma 3 270M (min_ram_gb = 1, ~253 MB Q4), which any machine
        // that boots the node clears. An accelerator only widens which larger
        // models the node can serve, never whether it may join. A stricter
        // floor here would tell a low-RAM box it can't serve AI when the node
        // would have accepted it.
        let can_serve_ai = self.ram_gb >= 1 || self.gpu_class != GpuClass::None;

        // The node counts an accelerator when its own probe returns a device,
        // which happens for discrete NVIDIA, discrete AMD and Apple Silicon.
        // Integrated graphics share the memory surface with the compositor and
        // are not rentable by the hour, so they don't count here either.
        let rentable_accelerator = matches!(
            self.gpu_class,
            GpuClass::AppleSilicon | GpuClass::Cuda | GpuClass::Rocm
        );

        let spare_disk = offerable_storage_gb > 0;
        let enclave = probe_enclave_device();

        vec![
            RoleCapability::new(
                "light",
                can_serve_ai,
                if can_serve_ai {
                    "Models from the catalogue can run on this machine."
                } else {
                    "Not enough memory for even the smallest model in the catalogue."
                },
            ),
            RoleCapability::new(
                "validator",
                true,
                "Nothing about this machine stops it voting on blocks.",
            ),
            RoleCapability::new(
                "ai",
                can_serve_ai,
                if can_serve_ai {
                    "This machine can hold at least one model from the catalogue."
                } else {
                    "Not enough memory for even the smallest model in the catalogue."
                },
            ),
            RoleCapability::new(
                "storage",
                spare_disk,
                if spare_disk {
                    format!(
                        "Up to {offerable_storage_gb} GB can be pledged, keeping a reserve free for the system."
                    )
                } else {
                    "No spare disk after the system reserve.".to_string()
                },
            ),
            RoleCapability::new(
                "compute",
                rentable_accelerator,
                if rentable_accelerator {
                    format!("{} can be rented out by the hour.", self.gpu_label())
                } else if self.gpu_class == GpuClass::IntelOrIntegrated {
                    "Integrated graphics share the display and cannot be rented out.".to_string()
                } else {
                    "No accelerator on this machine to rent out.".to_string()
                },
            ),
            RoleCapability::new(
                "cloud",
                spare_disk,
                if spare_disk {
                    format!(
                        "Sites, functions and machine images fit in the {offerable_storage_gb} GB spare."
                    )
                } else {
                    "No spare disk to hold site and function bundles.".to_string()
                },
            ),
            RoleCapability::new(
                "tee",
                enclave.is_some(),
                match enclave {
                    Some(vendor) => {
                        format!("{vendor} is present, so work can run inside an enclave.")
                    }
                    None => {
                        "No Intel TDX, AMD SEV-SNP or AWS Nitro device on this machine.".to_string()
                    }
                },
            ),
        ]
    }

    /// Short human label for the detected GPU class.
    fn gpu_label(&self) -> &'static str {
        match self.gpu_class {
            GpuClass::None => "CPU only",
            GpuClass::AppleSilicon => "Apple Silicon",
            GpuClass::Cuda => "NVIDIA (CUDA)",
            GpuClass::Rocm => "AMD (ROCm)",
            GpuClass::IntelOrIntegrated => "Integrated",
        }
    }
}

/// A user-facing summary of what this machine can offer on the network.
/// Serialized across the Tauri boundary so the UI never re-derives hardware
/// policy in TypeScript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReadout {
    /// Total system RAM in whole GB.
    pub ram_gb: u32,
    /// Physical CPU core count.
    pub physical_cores: u32,
    /// Human label for the GPU class (e.g. "Apple Silicon", "CPU only").
    pub gpu: String,
    /// Machine-readable GPU class, for UI branching that needs more than the
    /// label (e.g. explaining why a large model is CPU-bound here).
    pub gpu_class: GpuClass,
    /// Free disk space (GB) on the home volume.
    pub free_disk_gb: u32,
    /// Disk a storage provider could offer after holding back the reserve.
    pub offerable_storage_gb: u32,
    /// One verdict per role Control offers, in picker order.
    pub roles: Vec<RoleCapability>,
}

/// Whether this machine can carry one role, and the sentence that explains
/// the verdict to the operator.
///
/// Decided here rather than in the UI so the scan screen and the role picker
/// cannot drift apart: both read this list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleCapability {
    /// Wire token — the same string `NetworkRole` parses and the role cards
    /// are keyed by.
    pub role: String,
    /// Whether the hardware can carry the role. The stake is a separate axis,
    /// checked against the wallet.
    pub available: bool,
    /// One sentence, phrased for whichever verdict it carries.
    pub detail: String,
}

impl RoleCapability {
    fn new(role: &str, available: bool, detail: impl Into<String>) -> Self {
        Self {
            role: role.to_string(),
            available,
            detail: detail.into(),
        }
    }
}

/// Name the enclave device this machine exposes, if any.
///
/// A presence check on the guest device node the node's own TEE providers
/// open. No attestation is attempted — this only answers whether the role is
/// worth offering, and the node re-checks with a real probe before admitting
/// it.
fn probe_enclave_device() -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        for (path, vendor) in [
            ("/dev/tdx_guest", "Intel TDX"),
            ("/dev/tdx-guest", "Intel TDX"),
            ("/dev/sev-guest", "AMD SEV-SNP"),
            ("/dev/nsm", "AWS Nitro"),
        ] {
            if std::path::Path::new(path).exists() {
                return Some(vendor);
            }
        }
    }
    None
}

/// Free space (GB, floored) on the volume backing the user's home directory.
/// Falls back to the largest free volume if the home mount can't be matched,
/// and to 0 when no disk can be read — the readout then reports no offerable
/// storage rather than over-promising.
fn probe_free_disk_gb() -> u32 {
    let disks = Disks::new_with_refreshed_list();
    let home = dirs::home_dir();

    // Prefer the disk whose mount point is the longest prefix of the home
    // directory — that's the volume the home dir actually lives on.
    let mut best_match: Option<(usize, u64)> = None;
    for disk in disks.list() {
        let mount = disk.mount_point();
        if let Some(home) = home.as_ref() {
            if home.starts_with(mount) {
                let len = mount.as_os_str().len();
                let better = best_match.map(|(l, _)| len > l).unwrap_or(true);
                if better {
                    best_match = Some((len, disk.available_space()));
                }
            }
        }
    }
    if let Some((_, bytes)) = best_match {
        return (bytes / 1024 / 1024 / 1024) as u32;
    }

    // No home-mount match: fall back to the volume with the most free space.
    let max_free = disks
        .list()
        .iter()
        .map(|d| d.available_space())
        .max()
        .unwrap_or(0);
    (max_free / 1024 / 1024 / 1024) as u32
}

/// Prefer the OS-native physical-core probe. Apple Silicon's hybrid
/// architecture reports P-core and E-core counts separately; only P-cores
/// carry sustained inference throughput. Falls back to a hyperthreading-aware
/// logical/2 heuristic.
fn probe_physical_cores(sys: &System) -> u32 {
    #[cfg(target_os = "macos")]
    {
        if let Some(n) = sysctl_u64("hw.perflevel0.physicalcpu") {
            return (n as u32).max(1);
        }
        if let Some(n) = sysctl_u64("hw.physicalcpu") {
            return (n as u32).max(1);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            let mut pairs: std::collections::HashSet<(String, String)> =
                std::collections::HashSet::new();
            let mut phys: Option<String> = None;
            let mut core: Option<String> = None;
            for line in cpuinfo.lines() {
                if let Some(rest) = line.strip_prefix("physical id") {
                    phys = rest.split(':').nth(1).map(|s| s.trim().to_string());
                } else if let Some(rest) = line.strip_prefix("core id") {
                    core = rest.split(':').nth(1).map(|s| s.trim().to_string());
                } else if line.is_empty() {
                    if let (Some(p), Some(c)) = (phys.take(), core.take()) {
                        pairs.insert((p, c));
                    }
                }
            }
            if !pairs.is_empty() {
                return pairs.len() as u32;
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = Command::new("wmic")
            .args(["cpu", "get", "NumberOfCores"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            let mut total = 0u32;
            for line in s.lines() {
                if let Ok(n) = line.trim().parse::<u32>() {
                    total = total.saturating_add(n);
                }
            }
            if total > 0 {
                return total;
            }
        }
    }
    let logical = sys.cpus().len() as u32;
    (logical / 2).max(1)
}

fn probe_gpu_class() -> GpuClass {
    #[cfg(target_os = "macos")]
    {
        if sysctl_u64("hw.optional.arm64") == Some(1) {
            return GpuClass::AppleSilicon;
        }
        return GpuClass::IntelOrIntegrated;
    }
    #[cfg(target_os = "linux")]
    {
        if Command::new("nvidia-smi")
            .arg("--query-gpu=name")
            .arg("--format=csv,noheader")
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false)
        {
            return GpuClass::Cuda;
        }
        if Command::new("rocm-smi")
            .arg("--showproductname")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return GpuClass::Rocm;
        }
        if Command::new("lspci")
            .output()
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout).to_lowercase();
                s.contains("intel") && (s.contains("vga") || s.contains("display"))
            })
            .unwrap_or(false)
        {
            return GpuClass::IntelOrIntegrated;
        }
        return GpuClass::None;
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = Command::new("wmic")
            .args(["path", "win32_VideoController", "get", "Name"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            if s.contains("nvidia") || s.contains("rtx") || s.contains("gtx") {
                return GpuClass::Cuda;
            }
            if s.contains("radeon") || s.contains("amd") {
                return GpuClass::Rocm;
            }
            if s.contains("intel") || s.contains("uhd") || s.contains("iris") {
                return GpuClass::IntelOrIntegrated;
            }
        }
        return GpuClass::None;
    }
    #[allow(unreachable_code)]
    GpuClass::None
}

#[cfg(target_os = "macos")]
fn sysctl_u64(key: &str) -> Option<u64> {
    let out = Command::new("/usr/sbin/sysctl")
        .args(["-n", key])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(ram_gb: u32, cores: u32, gpu: GpuClass) -> HardwareProfile {
        HardwareProfile {
            ram_gb,
            physical_cores: cores,
            gpu_class: gpu,
            free_disk_gb: 256,
        }
    }

    fn can(r: &CapabilityReadout, role: &str) -> bool {
        r.roles
            .iter()
            .find(|c| c.role == role)
            .unwrap_or_else(|| panic!("no verdict for the '{role}' role"))
            .available
    }

    #[test]
    fn readout_holds_back_a_disk_reserve() {
        // 1000 GB free → 20% reserve (200) → 800 offerable.
        let mut p = profile(64, 16, GpuClass::AppleSilicon);
        p.free_disk_gb = 1000;
        let r = p.readout();
        assert_eq!(r.offerable_storage_gb, 800);
        assert!(can(&r, "storage"));
    }

    #[test]
    fn readout_answers_for_every_role_the_picker_offers() {
        let r = profile(16, 8, GpuClass::AppleSilicon).readout();
        let roles: Vec<&str> = r.roles.iter().map(|c| c.role.as_str()).collect();
        assert_eq!(
            roles,
            vec!["light", "validator", "ai", "storage", "compute", "cloud", "tee"]
        );
        // Every verdict carries a sentence, whichever way it went.
        assert!(r.roles.iter().all(|c| !c.detail.is_empty()));
    }

    #[test]
    fn readout_offers_validator_on_any_machine() {
        // Validating asks nothing of the hardware; the stake is the gate.
        let mut p = profile(1, 1, GpuClass::None);
        p.free_disk_gb = 0;
        assert!(can(&p.readout(), "validator"));
    }

    #[test]
    fn readout_reserve_floors_at_20gb_on_small_disks() {
        // 50 GB free → 20% is 10, but the flat floor is 20 → 30 offerable.
        let mut p = profile(8, 4, GpuClass::None);
        p.free_disk_gb = 50;
        assert_eq!(p.readout().offerable_storage_gb, 30);
    }

    #[test]
    fn readout_no_offerable_storage_when_disk_below_reserve() {
        let mut p = profile(8, 4, GpuClass::None);
        p.free_disk_gb = 15; // below the 20 GB floor reserve
        let r = p.readout();
        assert_eq!(r.offerable_storage_gb, 0);
        assert!(!can(&r, "storage"));
        // Sites and function bundles live on the same disk.
        assert!(!can(&r, "cloud"));
    }

    #[test]
    fn readout_cpu_only_modest_ram_can_serve_ai() {
        // Permissionless AI floor is the smallest model (Gemma 3 270M,
        // min_ram_gb = 1), so a 4 GB CPU-only box can serve AI.
        let mut p = profile(4, 4, GpuClass::None);
        p.free_disk_gb = 500;
        assert!(can(&p.readout(), "ai"));
    }

    #[test]
    fn readout_subgigabyte_cpu_only_cannot_serve_ai() {
        // Below the 1 GB floor with no GPU offload, even the tiniest model
        // can't load.
        let mut p = profile(0, 2, GpuClass::None);
        p.free_disk_gb = 500;
        assert!(!can(&p.readout(), "ai"));
    }

    #[test]
    fn readout_gpu_host_can_serve_ai_even_on_low_ram() {
        let mut p = profile(4, 4, GpuClass::AppleSilicon);
        p.free_disk_gb = 500;
        assert!(can(&p.readout(), "ai"));
    }

    #[test]
    fn readout_offers_compute_on_a_discrete_or_unified_accelerator() {
        for gpu in [GpuClass::AppleSilicon, GpuClass::Cuda, GpuClass::Rocm] {
            assert!(can(&profile(16, 8, gpu).readout(), "compute"));
        }
    }

    #[test]
    fn readout_refuses_compute_without_a_rentable_accelerator() {
        // The node's own probe returns no device for integrated graphics, so
        // offering the role here would hand the operator a role the node
        // then refuses.
        for gpu in [GpuClass::None, GpuClass::IntelOrIntegrated] {
            assert!(!can(&profile(16, 8, gpu).readout(), "compute"));
        }
    }

    #[test]
    fn readout_carries_machine_readable_gpu_class() {
        let r = profile(16, 8, GpuClass::Cuda).readout();
        assert_eq!(r.gpu_class, GpuClass::Cuda);
        assert_eq!(r.gpu, "NVIDIA (CUDA)");
    }

    /// Detection on the machine running the tests answers with a usable
    /// profile, and its readout never offers more disk than is free.
    #[test]
    fn detection_on_this_machine_reports_a_usable_profile() {
        let p = HardwareProfile::detect();
        assert!(p.ram_gb >= 1);
        assert!(p.physical_cores >= 1);
        let r = p.readout();
        assert_eq!(r.ram_gb, p.ram_gb);
        assert!(r.offerable_storage_gb <= r.free_disk_gb);
        assert!(!r.roles.is_empty());
    }
}
