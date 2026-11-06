//! What the accelerators are wired with.
//!
//! # Why one `Interconnect` field was not enough
//!
//! [`crate::hardware::Interconnect`] answers "how do GPUs in this box talk to
//! each other" and is used to decide whether a model can be tensor-split.
//! That is a real question, but it is not the one a cluster scheduler asks.
//! Placing work across machines depends on how the *machines* are wired, and
//! the two are independent: a box with NVLink internally may reach its peers
//! over ordinary Ethernet, and one with no GPU-to-GPU link at all may sit on
//! InfiniBand.
//!
//! So they are separate here. [`IntraNodeFabric`] is about this box;
//! [`InterNodeFabric`] is about how it reaches others.
//!
//! # Why the numbers matter
//!
//! Cross-node bandwidth roughly halves without GPUDirect RDMA, because the
//! transfer goes GPU → system memory → NIC instead of NIC reading GPU memory
//! directly. That is the difference between a cluster that scales and one
//! that looks like it should. [`FabricProfile::gpudirect_rdma`] is therefore
//! reported separately from the fabric itself: having InfiniBand and *not*
//! having GPUDirect is a common and expensive misconfiguration, and one that
//! shows up as disappointing throughput rather than as an error.
//!
//! # Detection is not trusted blindly
//!
//! NCCL's own auto-detection is reported unreliable on this hardware class —
//! a DGX Spark case on NVIDIA's forums has it finding four RoCE interfaces
//! where two Ethernet interfaces were configured. So every probe here records
//! what it actually read ([`FabricProfile::evidence`]) rather than only its
//! conclusion, and an operator can check the reasoning instead of taking the
//! answer on faith.

use serde::{Deserialize, Serialize};

/// How accelerators inside one machine reach each other.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum IntraNodeFabric {
    /// Not probed, or nothing conclusive was found.
    #[default]
    Unknown,
    /// One accelerator. Nothing to interconnect.
    ///
    /// Distinct from [`Self::Unknown`]: "there is one GPU" is a finding, and
    /// treating it as unknown would have a scheduler keep looking for a
    /// topology that cannot exist.
    Single,
    /// CPU and accelerator share one memory pool — Apple Silicon, GB10.
    ///
    /// The case that most changes decisions elsewhere: there is no copy
    /// across a bus, and equally, granting "the GPU" grants the pool the host
    /// itself runs from.
    UnifiedMemory,
    /// Discrete accelerators over PCIe, no high-bandwidth peer link.
    Pcie,
    /// Direct NVLink between peers.
    NvLink {
        /// How many peer pairs report an NVLink connection.
        peer_links: u32,
    },
    /// NVSwitch fabric — every accelerator reaches every other at full rate.
    NvSwitch,
}

impl IntraNodeFabric {
    /// Whether peers can exchange tensors without traversing PCIe.
    ///
    /// The property tensor-parallel splitting actually depends on. Unified
    /// memory qualifies for a different reason than NVLink does — there is no
    /// transfer at all — but the answer a planner needs is the same.
    pub fn has_fast_peer_path(&self) -> bool {
        matches!(
            self,
            Self::NvLink { .. } | Self::NvSwitch | Self::UnifiedMemory
        )
    }
}

/// How this machine reaches other machines.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum InterNodeFabric {
    /// Not probed, or nothing conclusive was found.
    #[default]
    Unknown,
    /// Ordinary Ethernet with no RDMA verbs.
    Ethernet,
    /// RDMA over Converged Ethernet. Verbs devices whose link layer is
    /// Ethernet.
    RoCe {
        /// Verbs device names, e.g. `mlx5_0`.
        devices: Vec<String>,
    },
    /// InfiniBand. Verbs devices whose link layer is InfiniBand.
    InfiniBand {
        /// Verbs device names.
        devices: Vec<String>,
        /// Link rate in Gb/s, where the port reported one.
        rate_gbps: Option<u32>,
    },
}

impl InterNodeFabric {
    /// Whether cross-node transfers can use RDMA verbs at all.
    pub fn is_rdma(&self) -> bool {
        matches!(self, Self::RoCe { .. } | Self::InfiniBand { .. })
    }

    /// Verbs devices, empty for the non-RDMA cases.
    pub fn devices(&self) -> &[String] {
        match self {
            Self::RoCe { devices } | Self::InfiniBand { devices, .. } => devices,
            _ => &[],
        }
    }
}

/// Everything known about how this node is wired.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FabricProfile {
    /// Accelerator-to-accelerator inside this box.
    pub intra: IntraNodeFabric,
    /// Machine-to-machine.
    pub inter: InterNodeFabric,
    /// Whether a NIC can read accelerator memory directly.
    ///
    /// Reported separately from `inter` on purpose: RDMA hardware without
    /// GPUDirect roughly halves cross-node bandwidth, and it fails as
    /// disappointing throughput rather than as an error, so it needs to be
    /// visible on its own.
    pub gpudirect_rdma: bool,
    /// What was actually read, so the conclusion can be checked.
    ///
    /// Auto-detection on this hardware class is reported unreliable, so the
    /// evidence is part of the answer rather than a debug aid.
    pub evidence: Vec<String>,
}

impl FabricProfile {
    /// Whether cross-node work will run at the fabric's real rate.
    ///
    /// RDMA without GPUDirect is the expensive-but-silent case this exists to
    /// name.
    pub fn full_rate_cross_node(&self) -> bool {
        self.inter.is_rdma() && self.gpudirect_rdma
    }

    /// A one-line summary for an operator.
    pub fn summary(&self) -> String {
        let intra = match &self.intra {
            IntraNodeFabric::Unknown => "unknown intra-node fabric".to_string(),
            IntraNodeFabric::Single => "single accelerator".to_string(),
            IntraNodeFabric::UnifiedMemory => "unified memory".to_string(),
            IntraNodeFabric::Pcie => "PCIe".to_string(),
            IntraNodeFabric::NvLink { peer_links } => format!("NVLink ({peer_links} peer links)"),
            IntraNodeFabric::NvSwitch => "NVSwitch".to_string(),
        };
        let inter = match &self.inter {
            InterNodeFabric::Unknown => "unknown inter-node fabric".to_string(),
            InterNodeFabric::Ethernet => "Ethernet (no RDMA)".to_string(),
            InterNodeFabric::RoCe { devices } => format!("RoCE via {}", devices.join(", ")),
            InterNodeFabric::InfiniBand { devices, rate_gbps } => match rate_gbps {
                Some(r) => format!("InfiniBand {r} Gb/s via {}", devices.join(", ")),
                None => format!("InfiniBand via {}", devices.join(", ")),
            },
        };
        let rdma = if self.inter.is_rdma() {
            if self.gpudirect_rdma {
                ", GPUDirect RDMA available"
            } else {
                ", GPUDirect RDMA NOT available — cross-node bandwidth will be roughly halved"
            }
        } else {
            ""
        };
        format!("{intra}; {inter}{rdma}")
    }
}

/// Parse `nvidia-smi topo -m` output into an intra-node conclusion.
///
/// Pure, so the parsing can be tested against captured output from machines
/// this one is not. `NV#` in the matrix means an NVLink connection between
/// that pair; `SYS`, `NODE` and `PHB` are all PCIe paths of varying distance.
pub fn parse_nvidia_topo(output: &str) -> IntraNodeFabric {
    // A data row is identified by the self-marker `X`, which nvidia-smi puts
    // on every GPU's diagonal. The header carries none.
    //
    // Indentation would also separate them — the header is tab-indented
    // because its first cell is empty — but leading whitespace is lost too
    // easily in captured output, and its first token is `GPU0` either way.
    // Relying on it counted the header as a row and turned a single-GPU box
    // into a two-GPU PCIe one.
    let data_rows: Vec<&str> = output
        .lines()
        .filter(|l| l.trim_start().starts_with("GPU"))
        .filter(|l| l.split_whitespace().any(|tok| tok == "X"))
        .collect();

    if data_rows.is_empty() {
        return IntraNodeFabric::Unknown;
    }
    if data_rows.len() == 1 {
        return IntraNodeFabric::Single;
    }

    let nv_links = data_rows
        .iter()
        .flat_map(|l| l.split_whitespace())
        .filter(|tok| {
            tok.starts_with("NV") && tok.len() > 2 && tok[2..].chars().all(|c| c.is_ascii_digit())
        })
        .count() as u32;

    if output.contains("NV18") || output.to_ascii_uppercase().contains("NVSWITCH") {
        return IntraNodeFabric::NvSwitch;
    }
    if nv_links > 0 {
        // Halved: the matrix is symmetric, so each physical link appears on
        // both peers' rows and counting raw tokens double-counts every one.
        return IntraNodeFabric::NvLink {
            peer_links: nv_links / 2,
        };
    }
    IntraNodeFabric::Pcie
}

/// Classify a verbs device from its sysfs `link_layer`.
///
/// The distinction that decides whether a fabric is InfiniBand or RoCE: both
/// present as verbs devices under `/sys/class/infiniband`, and only the port's
/// link layer separates them. Reading the directory name is not enough —
/// RoCE devices live there too, which is the trap.
pub fn classify_link_layer(link_layer: &str) -> Option<bool> {
    match link_layer.trim().to_ascii_lowercase().as_str() {
        "infiniband" => Some(true),
        "ethernet" => Some(false),
        _ => None,
    }
}

/// Parse a sysfs `rate` line such as `200 Gb/sec (4X HDR)`.
pub fn parse_ib_rate(rate: &str) -> Option<u32> {
    rate.split_whitespace().next()?.parse::<u32>().ok()
}

/// Probe this machine's fabric.
///
/// Shells out to `nvidia-smi` and reads sysfs, so callers must be on a
/// blocking thread. Every branch records what it read into
/// [`FabricProfile::evidence`] — auto-detection on this hardware class is
/// reported unreliable, so a conclusion without its reasoning is not worth
/// much.
///
/// `unified` comes from the caller because [`crate::hardware`] already
/// establishes it and re-deriving it here would give two answers that can
/// disagree.
pub fn detect_fabric(unified_memory: bool) -> FabricProfile {
    let mut evidence = Vec::new();

    let intra = if unified_memory {
        evidence.push("hardware detection reports a unified memory pool".to_string());
        IntraNodeFabric::UnifiedMemory
    } else {
        match std::process::Command::new("nvidia-smi")
            .args(["topo", "-m"])
            .output()
        {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                let parsed = parse_nvidia_topo(&text);
                evidence.push(format!("nvidia-smi topo -m parsed as {parsed:?}"));
                parsed
            }
            Ok(out) => {
                evidence.push(format!("nvidia-smi topo -m exited {}", out.status));
                IntraNodeFabric::Unknown
            }
            Err(e) => {
                evidence.push(format!("nvidia-smi not runnable: {e}"));
                IntraNodeFabric::Unknown
            }
        }
    };

    let inter = detect_inter_node(&mut evidence);
    let gpudirect_rdma = detect_gpudirect(&mut evidence);

    FabricProfile {
        intra,
        inter,
        gpudirect_rdma,
        evidence,
    }
}

/// Read `/sys/class/infiniband` and classify what is there.
///
/// The directory holds RoCE devices as well as InfiniBand ones — that is the
/// trap. Only each port's `link_layer` separates them, so the directory being
/// non-empty says "RDMA verbs exist", not "InfiniBand exists".
fn detect_inter_node(evidence: &mut Vec<String>) -> InterNodeFabric {
    const IB_ROOT: &str = "/sys/class/infiniband";

    let Ok(entries) = std::fs::read_dir(IB_ROOT) else {
        evidence.push(format!("{IB_ROOT} absent — no RDMA verbs devices"));
        return InterNodeFabric::Ethernet;
    };

    let mut ib_devices = Vec::new();
    let mut roce_devices = Vec::new();
    let mut rate_gbps = None;

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let ports = entry.path().join("ports");
        let Ok(port_entries) = std::fs::read_dir(&ports) else {
            evidence.push(format!("{name}: no ports directory"));
            continue;
        };
        // First port only. A device's ports share a link layer in every
        // configuration worth supporting, and reading them all would list the
        // same device once per port.
        let Some(port) = port_entries.flatten().next() else {
            evidence.push(format!("{name}: no ports"));
            continue;
        };
        let layer = std::fs::read_to_string(port.path().join("link_layer")).unwrap_or_default();
        match classify_link_layer(&layer) {
            Some(true) => {
                evidence.push(format!("{name}: link_layer=InfiniBand"));
                if rate_gbps.is_none()
                    && let Ok(r) = std::fs::read_to_string(port.path().join("rate"))
                {
                    rate_gbps = parse_ib_rate(&r);
                }
                ib_devices.push(name.clone());
            }
            Some(false) => {
                evidence.push(format!("{name}: link_layer=Ethernet (RoCE)"));
                roce_devices.push(name.clone());
            }
            None => evidence.push(format!("{name}: link_layer unreadable ({})", layer.trim())),
        }
    }

    if !ib_devices.is_empty() {
        InterNodeFabric::InfiniBand {
            devices: ib_devices,
            rate_gbps,
        }
    } else if !roce_devices.is_empty() {
        InterNodeFabric::RoCe {
            devices: roce_devices,
        }
    } else {
        evidence.push(format!("{IB_ROOT} present but empty"));
        InterNodeFabric::Ethernet
    }
}

/// Whether a NIC can read accelerator memory directly.
///
/// The `nvidia_peermem` module (formerly `nv_peer_mem`) is what exposes GPU
/// memory to the RDMA stack. Its absence is the difference between a cluster
/// running at its fabric's rate and one running at roughly half.
fn detect_gpudirect(evidence: &mut Vec<String>) -> bool {
    for module in ["nvidia_peermem", "nv_peer_mem"] {
        let path = format!("/sys/module/{module}");
        if std::path::Path::new(&path).exists() {
            evidence.push(format!("{module} loaded — GPUDirect RDMA available"));
            return true;
        }
    }
    evidence.push(
        "neither nvidia_peermem nor nv_peer_mem is loaded — GPUDirect RDMA unavailable".to_string(),
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from the GB10 this was built on.
    const GB10_TOPO: &str = "\
	GPU0	CPU Affinity	NUMA Affinity	GPU NUMA ID
GPU0	 X 	0-19	0		N/A

Legend:

  X    = Self
  SYS  = Connection traversing PCIe as well as the SMP interconnect between NUMA nodes
";

    /// An 8-GPU NVLink box, in the shape nvidia-smi prints.
    const NVLINK_TOPO: &str = "\
	GPU0	GPU1	GPU2	GPU3	CPU Affinity
GPU0	 X 	NV12	NV12	NV12	0-63
GPU1	NV12	 X 	NV12	NV12	0-63
GPU2	NV12	NV12	 X 	NV12	0-63
GPU3	NV12	NV12	NV12	 X 	0-63
";

    const PCIE_TOPO: &str = "\
	GPU0	GPU1	CPU Affinity
GPU0	 X 	SYS	0-31
GPU1	SYS	 X 	0-31
";

    #[test]
    fn a_single_gpu_box_is_reported_as_single_not_unknown() {
        // "There is one GPU" is a finding. Reporting it as unknown would have
        // a scheduler keep looking for a topology that cannot exist.
        assert_eq!(parse_nvidia_topo(GB10_TOPO), IntraNodeFabric::Single);
    }

    #[test]
    fn nvlink_peers_are_counted_once_not_twice() {
        // The matrix is symmetric, so every physical link appears on both
        // peers' rows. Counting raw tokens would double every one.
        match parse_nvidia_topo(NVLINK_TOPO) {
            IntraNodeFabric::NvLink { peer_links } => assert_eq!(peer_links, 6),
            other => panic!("expected NVLink, got {other:?}"),
        }
    }

    #[test]
    fn multiple_gpus_with_no_peer_link_are_pcie() {
        assert_eq!(parse_nvidia_topo(PCIE_TOPO), IntraNodeFabric::Pcie);
    }

    #[test]
    fn empty_output_is_unknown_rather_than_a_guess() {
        assert_eq!(parse_nvidia_topo(""), IntraNodeFabric::Unknown);
        assert_eq!(
            parse_nvidia_topo("Legend:\n  X = Self"),
            IntraNodeFabric::Unknown
        );
    }

    #[test]
    fn roce_and_infiniband_are_told_apart_by_link_layer_not_by_directory() {
        // The trap: RoCE devices also appear under /sys/class/infiniband, so
        // the directory name says nothing. Only the port's link layer does.
        assert_eq!(classify_link_layer("InfiniBand"), Some(true));
        assert_eq!(classify_link_layer("Ethernet"), Some(false));
        assert_eq!(classify_link_layer("  ethernet\n"), Some(false));
        assert_eq!(classify_link_layer("Unknown"), None);
    }

    #[test]
    fn link_rates_parse_from_the_sysfs_format() {
        assert_eq!(parse_ib_rate("200 Gb/sec (4X HDR)"), Some(200));
        assert_eq!(parse_ib_rate("400 Gb/sec (4X NDR)"), Some(400));
        assert_eq!(parse_ib_rate("garbage"), None);
        assert_eq!(parse_ib_rate(""), None);
    }

    #[test]
    fn unified_memory_counts_as_a_fast_peer_path() {
        // For a different reason than NVLink — there is no transfer at all —
        // but the answer a tensor-split planner needs is the same.
        assert!(IntraNodeFabric::UnifiedMemory.has_fast_peer_path());
        assert!(IntraNodeFabric::NvSwitch.has_fast_peer_path());
        assert!(IntraNodeFabric::NvLink { peer_links: 4 }.has_fast_peer_path());
        assert!(!IntraNodeFabric::Pcie.has_fast_peer_path());
        assert!(!IntraNodeFabric::Single.has_fast_peer_path());
        assert!(!IntraNodeFabric::Unknown.has_fast_peer_path());
    }

    #[test]
    fn rdma_without_gpudirect_is_called_out_because_it_halves_bandwidth() {
        // The expensive-but-silent misconfiguration: the hardware is there,
        // the throughput is not, and nothing errors.
        let p = FabricProfile {
            intra: IntraNodeFabric::NvLink { peer_links: 6 },
            inter: InterNodeFabric::InfiniBand {
                devices: vec!["mlx5_0".to_string()],
                rate_gbps: Some(400),
            },
            gpudirect_rdma: false,
            evidence: Vec::new(),
        };
        assert!(!p.full_rate_cross_node());
        let s = p.summary();
        assert!(s.contains("roughly halved"), "{s}");

        let with = FabricProfile {
            gpudirect_rdma: true,
            ..p
        };
        assert!(with.full_rate_cross_node());
        assert!(with.summary().contains("GPUDirect RDMA available"));
    }

    #[test]
    fn plain_ethernet_says_nothing_about_gpudirect() {
        // There is no RDMA path to be missing, so warning about GPUDirect
        // would be noise on the majority of nodes.
        let p = FabricProfile {
            intra: IntraNodeFabric::Single,
            inter: InterNodeFabric::Ethernet,
            gpudirect_rdma: false,
            evidence: Vec::new(),
        };
        assert!(!p.full_rate_cross_node());
        let s = p.summary();
        assert!(!s.contains("GPUDirect"), "{s}");
        assert!(s.contains("no RDMA"), "{s}");
    }

    #[test]
    fn the_gb10_profile_reads_the_way_this_machine_actually_is() {
        // Built and checked against the box this was written on: one
        // accelerator, unified memory, no InfiniBand devices present.
        let p = FabricProfile {
            intra: IntraNodeFabric::UnifiedMemory,
            inter: InterNodeFabric::Ethernet,
            gpudirect_rdma: false,
            evidence: vec!["/sys/class/infiniband: empty".to_string()],
        };
        let s = p.summary();
        assert!(s.contains("unified memory"), "{s}");
        assert!(s.contains("Ethernet"), "{s}");
    }

    #[test]
    fn devices_are_only_reported_for_rdma_fabrics() {
        assert!(InterNodeFabric::Ethernet.devices().is_empty());
        assert!(InterNodeFabric::Unknown.devices().is_empty());
        assert_eq!(
            InterNodeFabric::RoCe {
                devices: vec!["mlx5_1".to_string()]
            }
            .devices(),
            ["mlx5_1"]
        );
    }
}
