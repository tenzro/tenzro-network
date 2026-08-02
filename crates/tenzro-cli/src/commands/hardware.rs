//! Local hardware detection for the Tenzro CLI.
//!
//! Ported from the Tauri desktop app so the CLI can detect hardware
//! without requiring a running RPC node.

use crate::output;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Hardware profile matching the Tauri app's HardwareProfile struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_threads: usize,
    pub total_ram_gb: f64,
    pub unified_memory: bool,
    pub gpus: Vec<AcceleratorInfo>,
    pub accelerators: Vec<AcceleratorInfo>,
    pub storage_available_gb: f64,
    pub tee_available: bool,
    pub tee_type: Option<String>,
    pub tee_capabilities: Vec<String>,
    pub os: String,
    pub arch: String,
    pub device_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceleratorInfo {
    pub name: String,
    pub kind: String,
    pub memory_gb: f64,
    pub compute_units: Option<u32>,
}

/// Parse a memory string like "8 GB", "8192 MB" into GB.
fn parse_memory_string(s: &str) -> f64 {
    let lower = s.to_lowercase().trim().to_string();
    let num_str: String = lower
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let value: f64 = num_str.parse().unwrap_or(0.0);

    if lower.contains("tb") || lower.contains("tib") {
        value * 1024.0
    } else if lower.contains("gb") || lower.contains("gib") {
        value
    } else if lower.contains("mb") || lower.contains("mib") {
        (value / 1024.0 * 10.0).round() / 10.0
    } else if lower.contains("kb") || lower.contains("kib") {
        (value / 1_048_576.0 * 10.0).round() / 10.0
    } else {
        if value > 100.0 {
            (value / 1024.0 * 10.0).round() / 10.0
        } else {
            value
        }
    }
}

/// Extract device name from lspci -mm line.
fn extract_lspci_device_name(line: &str) -> String {
    let parts: Vec<&str> = line.split('"').collect();
    if parts.len() >= 8 {
        let vendor = parts[5].trim();
        let device = parts[7].trim();
        if !vendor.is_empty() && !device.is_empty() {
            return format!("{} {}", vendor, device);
        }
    }
    line.split(']')
        .next_back()
        .unwrap_or(line)
        .trim()
        .to_string()
}

/// Decide whether a lone GPU shares the system memory pool, and normalise its
/// reported size if it does. Returns whether the pool is unified.
///
/// Delegates to [`tenzro_types::hardware::shared_memory_pool`], which is the
/// single source of truth for this rule. It used to be re-derived here, and the
/// workspace ended up with three independent copies that each got it wrong in a
/// different way — this crate reported a GB10's GPU with 0 GB, and
/// `tenzro-types` dropped the device entirely.
fn resolve_shared_memory(gpu_memory_gb: &mut f64, total_ram_gb: f64) -> bool {
    // The shared rule works in whole GiB; round to the nearest rather than
    // truncating so a 121.7 GB pool does not read as 121 and miss the
    // seven-eighths comparison by a rounding artefact.
    let vram = gpu_memory_gb.round().max(0.0) as u32;
    let ram = total_ram_gb.round().max(0.0) as u32;
    match tenzro_types::hardware::shared_memory_pool(vram, ram) {
        Some(resolved) => {
            // Report the pool at the precision the caller measured it, so the
            // profile keeps `121.7` rather than degrading to `122`.
            *gpu_memory_gb = if resolved == vram {
                *gpu_memory_gb
            } else {
                total_ram_gb
            };
            true
        }
        None => false,
    }
}

/// Detect GPUs and accelerators using OS-provided enumeration.
///
/// `total_ram_gb` lets the Linux branch tell a coherent CPU/GPU pool from a
/// discrete card: on Grace-Blackwell parts `nvidia-smi` reports the shared
/// system pool, so the two figures coincide and the memory must be counted
/// once.
async fn detect_accelerators(
    total_ram_gb: f64,
) -> (Vec<AcceleratorInfo>, Vec<AcceleratorInfo>, bool) {
    let os = std::env::consts::OS;
    let mut gpus: Vec<AcceleratorInfo> = Vec::new();
    let mut accelerators: Vec<AcceleratorInfo> = Vec::new();
    let mut unified_memory = false;

    match os {
        "macos" => {
            if let Ok(output) = tokio::process::Command::new("system_profiler")
                .args(["SPDisplaysDataType", "-json"])
                .output()
                .await
                && output.status.success()
                    && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
                        && let Some(displays) = json.get("SPDisplaysDataType").and_then(|v| v.as_array()) {
                            for display in displays {
                                let name = display.get("sppci_model")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown GPU")
                                    .to_string();

                                let mut memory_gb = display.get("spdisplays_vram")
                                    .and_then(|v| v.as_str())
                                    .map(parse_memory_string)
                                    .unwrap_or(0.0);

                                if memory_gb == 0.0
                                    && let Some(shared) = display.get("spdisplays_vram_shared")
                                        .and_then(|v| v.as_str())
                                    {
                                        memory_gb = parse_memory_string(shared);
                                        unified_memory = true;
                                    }

                                if memory_gb == 0.0 {
                                    let sys = sysinfo::System::new_with_specifics(
                                        sysinfo::RefreshKind::new().with_memory(sysinfo::MemoryRefreshKind::everything()),
                                    );
                                    let total_gb = sys.total_memory() as f64 / 1_073_741_824.0;
                                    memory_gb = (total_gb * 0.75 * 10.0).round() / 10.0;
                                    unified_memory = true;
                                }

                                let compute_units = display.get("sppci_cores")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| s.parse::<u32>().ok())
                                    .or_else(|| display.get("sppci_cores").and_then(|v| v.as_u64()).map(|v| v as u32));

                                gpus.push(AcceleratorInfo {
                                    name,
                                    kind: "gpu".to_string(),
                                    memory_gb,
                                    compute_units,
                                });
                            }
                        }

            // Detect Neural Engine via ioreg
            if let Ok(output) = tokio::process::Command::new("ioreg")
                .args(["-r", "-d", "1", "-c", "AppleARMIODevice"])
                .output()
                .await
                && output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("ane") || stdout.contains("neural-engine") || stdout.contains("ANE") {
                        accelerators.push(AcceleratorInfo {
                            name: "Neural Engine".to_string(),
                            kind: "npu".to_string(),
                            memory_gb: 0.0,
                            compute_units: None,
                        });
                    }
                }
        },
        "linux" => {
            if let Ok(output) = tokio::process::Command::new("lspci")
                .args(["-mm", "-nn"])
                .output()
                .await
                && output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        let lower = line.to_lowercase();
                        let is_gpu = lower.contains("[0300]") || lower.contains("[0302]") || lower.contains("[0380]")
                            || lower.contains("vga") || lower.contains("3d controller") || lower.contains("display controller");
                        let is_accel = lower.contains("[1200]") || lower.contains("[0b40]")
                            || lower.contains("processing accelerator") || lower.contains("co-processor");

                        if is_gpu || is_accel {
                            let name = extract_lspci_device_name(line);
                            let kind = if is_accel { "accelerator" } else { "gpu" };
                            let entry = AcceleratorInfo {
                                name,
                                kind: kind.to_string(),
                                memory_gb: 0.0,
                                compute_units: None,
                            };
                            if is_accel { accelerators.push(entry); } else { gpus.push(entry); }
                        }
                    }
                }

            // nvidia-smi
            if let Ok(output) = tokio::process::Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
                .output()
                .await
                && output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for (i, line) in stdout.lines().enumerate() {
                        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                        if parts.len() >= 2 {
                            let name = parts[0].to_string();

                            // A coherent CPU/GPU part has no separate VRAM to
                            // report, so `nvidia-smi` answers `[N/A]` rather
                            // than a number — GB10 does exactly this. The old
                            // code ran `parse().unwrap_or(0.0)`, silently
                            // recorded 0 GB, and the unified-memory rule below
                            // then failed against `0.0 >= total * 0.875`. The
                            // node advertised a GPU with no memory, and the
                            // scheduler sized placement as if it had none.
                            //
                            // Treat an unparseable figure as "shared pool" and
                            // count the system memory once, which is what it is.
                            // A coherent CPU/GPU part has no separate VRAM to
                            // report, so `nvidia-smi` answers `[N/A]` rather
                            // than a number — GB10 does exactly this. The old
                            // code ran `parse().unwrap_or(0.0)` and silently
                            // recorded 0 GB. Leave it at 0 here; the shared-pool
                            // rule after all vendor probes resolves it, so the
                            // same handling covers every vendor.
                            let memory_gb = parts[1]
                                .parse::<f64>()
                                .ok()
                                .filter(|mb| *mb > 0.0)
                                .map(|mb| (mb / 1024.0 * 10.0).round() / 10.0)
                                .unwrap_or(0.0);

                            let gpu_count = gpus.len();
                            if let Some(gpu) = gpus.iter_mut().find(|g| g.name.contains(&name) || i < gpu_count) {
                                gpu.memory_gb = memory_gb;
                                // Prefer the vendor name. `lspci` on a part the
                                // local PCI ID database does not know yields
                                // "Device [2e12] NVIDIA Corporation [10de]";
                                // the old guard only replaced empty/"Unknown",
                                // so that raw ID was what reached the registry.
                                if !name.is_empty() {
                                    gpu.name = name;
                                }
                            } else {
                                gpus.push(AcceleratorInfo { name, kind: "gpu".to_string(), memory_gb, compute_units: None });
                            }
                        }
                    }
                }

            // rocm-smi (AMD GPUs)
            if let Ok(output) = tokio::process::Command::new("rocm-smi")
                .args(["--showproductname", "--showmeminfo", "vram", "--csv"])
                .output()
                .await
                && output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines().skip(1) {
                        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                        if parts.len() >= 2 {
                            let name = parts[0].to_string();
                            let memory_gb = parse_memory_string(parts.get(1).unwrap_or(&"0"));
                            if let Some(gpu) = gpus.iter_mut().find(|g| g.name.contains(&name)) {
                                gpu.memory_gb = memory_gb;
                            }
                        }
                    }
                }

            // Resolve unified vs discrete memory once, after every vendor
            // probe, so the rule is the same whoever made the part.
            //
            // Two shapes both mean "one coherent pool", and a single GPU is a
            // precondition for either — more than one accelerator implies
            // discrete cards with their own memory.
            if let [only] = gpus.as_mut_slice() {
                unified_memory = resolve_shared_memory(&mut only.memory_gb, total_ram_gb);
            }

            // NPU devices in /sys/class
            if let Ok(entries) = std::fs::read_dir("/sys/class") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    // Match the sysfs class name exactly, not as a substring.
                    // `name.contains("npu")` also matches `/sys/class/i-npu-t`,
                    // so every mouse, keyboard and evdev node was enumerated and
                    // advertised to the network as an NPU — 29 phantom
                    // accelerators on a DGX Spark, none of them real.
                    const NPU_CLASSES: &[&str] = &["accel", "npu", "habanalabs", "intel_vpu"];
                    if NPU_CLASSES.contains(&name.as_str())
                        && let Ok(devices) = std::fs::read_dir(entry.path()) {
                            for dev in devices.flatten() {
                                let dev_name = dev.file_name().to_string_lossy().to_string();
                                accelerators.push(AcceleratorInfo {
                                    name: dev_name,
                                    kind: "npu".to_string(),
                                    memory_gb: 0.0,
                                    compute_units: None,
                                });
                            }
                        }
                }
            }
        },
        "windows" => {
            if let Ok(output) = tokio::process::Command::new("powershell")
                .args(["-NoProfile", "-Command",
                    "Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM | ConvertTo-Json"])
                .output()
                .await
                && output.status.success()
                    && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                        let items = match json.as_array() {
                            Some(arr) => arr.clone(),
                            None => vec![json],
                        };
                        for item in &items {
                            let name = item.get("Name").and_then(|v| v.as_str()).unwrap_or("Unknown GPU").to_string();
                            let adapter_ram = item.get("AdapterRAM").and_then(|v| v.as_u64()).unwrap_or(0);
                            let memory_gb = (adapter_ram as f64 / 1_073_741_824.0 * 10.0).round() / 10.0;
                            gpus.push(AcceleratorInfo {
                                name,
                                kind: "gpu".to_string(),
                                memory_gb,
                                compute_units: None,
                            });
                        }
                    }
        },
        _ => {}
    }

    (gpus, accelerators, unified_memory)
}

/// Detect TEE capabilities by probing OS device files.
/// What class of hardware security the probe found.
///
/// The distinction is the whole point of this module: a TPM attests what was
/// *loaded*, a TEE protects what is *running*. Conflating them lets a machine
/// with no confidential-compute hardware advertise itself as a TEE provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TeeKind {
    /// A real trust boundary a workload can run inside: Intel TDX / SGX,
    /// AMD SEV / SEV-SNP, an OP-TEE / Trusty TEE subsystem, or Apple SEP.
    HardwareTee,
    /// Boot-chain integrity only — a TPM, and/or UEFI Secure Boot. Real, worth
    /// advertising, but it cannot protect a running workload and must never
    /// satisfy a confidential-compute requirement.
    MeasuredBoot,
}

async fn detect_tee_capabilities() -> (bool, Option<String>, Vec<String>) {
    let os = std::env::consts::OS;
    let mut tee_type = None;
    let mut tee_kind: Option<TeeKind> = None;
    let mut capabilities = Vec::new();

    // Record the strongest class seen. `HardwareTee` wins over `MeasuredBoot`
    // so probe order cannot downgrade a real TEE.
    let note = |kind: TeeKind, slot: &mut Option<TeeKind>| {
        if kind == TeeKind::HardwareTee || slot.is_none() {
            *slot = Some(kind);
        }
    };

    match os {
        "macos" => {
            if let Ok(output) = tokio::process::Command::new("ioreg")
                .args(["-r", "-d", "1", "-c", "AppleSEPManager"])
                .output()
                .await
                && output.status.success()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("AppleSEPManager") || stdout.contains("SEP") {
                    note(TeeKind::HardwareTee, &mut tee_kind);
                    tee_type = Some("Secure Enclave".to_string());
                    capabilities.extend([
                        "secure_key_storage".to_string(),
                        "biometric_auth".to_string(),
                        "hardware_attestation".to_string(),
                        "secure_boot".to_string(),
                    ]);
                }
            }
        }
        "linux" => {
            let tee_devices = [
                ("/dev/tdx_guest", "confidential_vm"),
                ("/dev/tdx-guest", "confidential_vm"),
                ("/dev/sgx_enclave", "enclave"),
                ("/dev/sgx/enclave", "enclave"),
                ("/dev/sev-guest", "confidential_vm"),
                ("/dev/sev", "memory_encryption"),
                ("/dev/tee0", "tee_subsystem"),
                ("/dev/teepriv0", "tee_subsystem"),
                ("/dev/trusty-ipc-dev0", "trusty_tee"),
            ];

            for (path, cap_type) in &tee_devices {
                if std::path::Path::new(path).exists() {
                    note(TeeKind::HardwareTee, &mut tee_kind);
                    if tee_type.is_none() {
                        let device_name = std::path::Path::new(path)
                            .file_name()
                            .and_then(|f| f.to_str())
                            .unwrap_or("unknown");
                        tee_type = Some(format!("TEE ({})", device_name));
                    }
                    capabilities.push(cap_type.to_string());
                    capabilities.push("remote_attestation".to_string());
                    capabilities.push("memory_encryption".to_string());
                }
            }

            // Secure Boot is boot-chain integrity, not a trust boundary. It
            // records a capability but never a `tee_type`.
            if std::path::Path::new("/sys/firmware/efi/efivars").exists() {
                note(TeeKind::MeasuredBoot, &mut tee_kind);
                capabilities.push("secure_boot_capable".to_string());
            }

            if std::path::Path::new("/dev/tpm0").exists()
                || std::path::Path::new("/dev/tpmrm0").exists()
            {
                // Measured boot, not a TEE — deliberately leaves `tee_type`
                // unset. Labelling a TPM as a TEE is what would let a TPM-only
                // machine register as a confidential-compute provider.
                note(TeeKind::MeasuredBoot, &mut tee_kind);
                capabilities.push("tpm_available".to_string());
                capabilities.push("measured_boot".to_string());
            }
        }
        "windows" => {
            if let Ok(output) = tokio::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled | ConvertTo-Json",
                ])
                .output()
                .await
                && output.status.success()
                && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
                && json
                    .get("TpmPresent")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            {
                // Measured boot, not a TEE — see the Linux TPM branch above.
                note(TeeKind::MeasuredBoot, &mut tee_kind);
                capabilities.push("tpm_available".to_string());
                if json
                    .get("TpmEnabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    capabilities.push("tpm_enabled".to_string());
                }
            }

            if let Ok(output) = tokio::process::Command::new("powershell")
                .args(["-NoProfile", "-Command",
                    "Get-CimInstance Win32_DeviceGuard | Select-Object VirtualizationBasedSecurityStatus | ConvertTo-Json"])
                .output()
                .await
                && output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("Running") || stdout.contains("2") {
                        capabilities.push("virtualization_based_security".to_string());
                    }
                }
        }
        _ => {}
    }

    capabilities.sort();
    capabilities.dedup();

    // `tee_available` means "this machine can run a workload inside a hardware
    // trust boundary" — nothing weaker.
    //
    // It used to be `tee_type.is_some() || !capabilities.is_empty()`, which made
    // *any* UEFI machine claim a TEE: `/sys/firmware/efi/efivars` exists on
    // essentially every modern Linux box, that pushed `secure_boot_capable` into
    // `capabilities`, and a non-empty list flipped the flag. A DGX Spark — which
    // has no CPU TEE at all — reported `tee_available: true` on that path.
    //
    // Secure Boot and a TPM are real and worth advertising, but they are
    // *platform integrity*, not confidential computing: secure boot proves what
    // was **loaded**; a TEE proves what is **running** and protects it while it
    // runs. Only the latter can back a confidential-compute claim, so only an
    // actual TEE device sets this flag. The weaker capabilities stay in
    // `capabilities` where a relying party can see them for what they are.
    let available = matches!(tee_kind, Some(TeeKind::HardwareTee));
    (available, tee_type, capabilities)
}

/// Generate a SHA-256 hardware fingerprint.
fn generate_fingerprint(
    cpu_model: &str,
    cpu_cores: usize,
    total_ram_gb: f64,
    device_names: &[String],
    os: &str,
    arch: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let input = format!(
        "{}|{}|{:.0}|{}|{}|{}",
        cpu_model,
        cpu_cores,
        total_ram_gb,
        device_names.join(","),
        os,
        arch,
    );
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)
}

/// Recover a CPU model string where `sysinfo` reports none.
///
/// On aarch64 Linux `/proc/cpuinfo` carries no `model name` line — only
/// `CPU implementer` / `CPU part` — so `sysinfo`'s `brand()` comes back empty
/// and the profile advertised `cpu_model: ""`. That is a field a fleet operator
/// reads, and it also feeds `device_fingerprint`, so an empty value weakens the
/// fingerprint's distinguishing power.
///
/// `lscpu` already decodes the implementer/part pair. A heterogeneous part
/// reports one `Model name` per core cluster, so the distinct values are joined
/// — a DGX Spark's GB10 yields `Cortex-X925 + Cortex-A725`, which is what it
/// actually is, rather than picking one cluster and hiding the other.
#[cfg(target_os = "linux")]
fn cpu_model_fallback() -> Option<String> {
    let out = std::process::Command::new("lscpu").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut models: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case("model name")
        {
            let value = value.trim().to_string();
            if !value.is_empty() && !models.contains(&value) {
                models.push(value);
            }
        }
    }
    (!models.is_empty()).then(|| models.join(" + "))
}

#[cfg(not(target_os = "linux"))]
fn cpu_model_fallback() -> Option<String> {
    None
}

/// Detect full hardware profile locally (no RPC needed).
pub async fn detect_hardware_profile() -> HardwareProfile {
    let mut sys = sysinfo::System::new_with_specifics(sysinfo::RefreshKind::everything());
    sys.refresh_all();

    let cpu_model = sys
        .cpus()
        .first()
        .map(|c| c.brand().to_string())
        .filter(|b| !b.trim().is_empty())
        .or_else(cpu_model_fallback)
        .unwrap_or_else(|| "Unknown CPU".to_string());
    let cpu_cores = sys.physical_core_count().unwrap_or(0);
    let cpu_threads = sys.cpus().len();
    let total_ram_gb = (sys.total_memory() as f64 / 1_073_741_824.0 * 10.0).round() / 10.0;

    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/"));
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let storage_available_gb = disks
        .iter()
        .filter(|d| home.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().to_string_lossy().len())
        .map(|d| (d.available_space() as f64 / 1_073_741_824.0 * 10.0).round() / 10.0)
        .unwrap_or(0.0);

    let (gpus, accelerators, unified_memory) = detect_accelerators(total_ram_gb).await;
    let (tee_available, tee_type, tee_capabilities) = detect_tee_capabilities().await;

    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    let mut all_device_names: Vec<String> = gpus
        .iter()
        .chain(accelerators.iter())
        .map(|d| d.name.clone())
        .collect();
    all_device_names.sort();

    let device_fingerprint = generate_fingerprint(
        &cpu_model,
        cpu_cores,
        total_ram_gb,
        &all_device_names,
        &os,
        &arch,
    );

    HardwareProfile {
        cpu_model,
        cpu_cores,
        cpu_threads,
        total_ram_gb,
        unified_memory,
        gpus,
        accelerators,
        storage_available_gb,
        tee_available,
        tee_type,
        tee_capabilities,
        os,
        arch,
        device_fingerprint,
    }
}

/// Execute the hardware command — prints local hardware profile.
pub async fn execute(format: &str) -> Result<()> {
    let hardware = detect_hardware_profile().await;

    if format == "json" {
        output::print_json(&hardware)?;
        return Ok(());
    }

    output::print_header("Hardware Profile");

    println!();
    output::print_header("CPU");
    println!();
    output::print_field("Model", &hardware.cpu_model);
    output::print_field("Cores", &hardware.cpu_cores.to_string());
    output::print_field("Threads", &hardware.cpu_threads.to_string());

    println!();
    output::print_header("Memory & Storage");
    println!();
    output::print_field("RAM", &format!("{:.1} GB", hardware.total_ram_gb));
    if hardware.unified_memory {
        output::print_field("Memory Type", "Unified (shared with GPU)");
    }
    output::print_field(
        "Available Storage",
        &format!("{:.1} GB", hardware.storage_available_gb),
    );

    if !hardware.gpus.is_empty() {
        println!();
        output::print_header("GPUs");
        println!();
        for (i, gpu) in hardware.gpus.iter().enumerate() {
            let mem = if gpu.memory_gb > 0.0 {
                format!("{:.1} GB", gpu.memory_gb)
            } else {
                "shared".to_string()
            };
            let cu = gpu
                .compute_units
                .map(|c| format!(", {} cores", c))
                .unwrap_or_default();
            output::print_field(
                &format!("GPU {}", i + 1),
                &format!("{} ({}{}", gpu.name, mem, cu),
            );
        }
    }

    if !hardware.accelerators.is_empty() {
        println!();
        output::print_header("Accelerators");
        println!();
        for (i, accel) in hardware.accelerators.iter().enumerate() {
            output::print_field(
                &format!("{} {}", accel.kind.to_uppercase(), i + 1),
                &accel.name,
            );
        }
    }

    println!();
    output::print_header("TEE (Trusted Execution Environment)");
    println!();
    if hardware.tee_available {
        let vendor = hardware.tee_type.as_deref().unwrap_or("Unknown");
        output::print_status("Status", &format!("Available ({})", vendor), true);
        if !hardware.tee_capabilities.is_empty() {
            output::print_field("Capabilities", &hardware.tee_capabilities.join(", "));
        }
    } else {
        output::print_status("Status", "Not available", false);
    }

    println!();
    output::print_header("System");
    println!();
    output::print_field("Operating System", &hardware.os);
    output::print_field("Architecture", &hardware.arch);
    output::print_field(
        "Fingerprint",
        &output::format_hash(&hardware.device_fingerprint),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Coherent parts that report nothing: GB10, Jetson, AMD APUs, Intel iGPUs,
    /// Mali/Adreno. The pool must be reported once, as system memory.
    #[test]
    fn absent_vram_reading_means_a_shared_pool() {
        let mut mem = 0.0;
        assert!(resolve_shared_memory(&mut mem, 121.7));
        assert_eq!(
            mem, 121.7,
            "the shared pool is reported once, as system RAM"
        );
    }

    /// Grace-Hopper class: the vendor tool reports the shared pool, so the two
    /// figures already coincide and the size must be left alone.
    #[test]
    fn vram_matching_system_ram_means_a_shared_pool() {
        let mut mem = 120.0;
        assert!(resolve_shared_memory(&mut mem, 121.7));
        assert_eq!(mem, 120.0, "an already-correct figure is not rewritten");
    }

    /// A discrete card always reports its own figure, well under system RAM.
    #[test]
    fn discrete_vram_is_not_a_shared_pool() {
        let mut mem = 24.0;
        assert!(!resolve_shared_memory(&mut mem, 121.7));
        assert_eq!(mem, 24.0);
    }

    /// Guard the boundary rather than leaving it implied: 87.5% is the cut.
    #[test]
    fn shared_pool_threshold_is_seven_eighths() {
        let mut just_under = 121.7 * 0.874;
        assert!(!resolve_shared_memory(&mut just_under, 121.7));

        let mut just_over = 121.7 * 0.876;
        assert!(resolve_shared_memory(&mut just_over, 121.7));
    }

    /// With no system-memory reading there is nothing to compare against, so
    /// claiming a unified pool would be a guess.
    #[test]
    fn unknown_system_memory_yields_no_claim() {
        let mut mem = 0.0;
        assert!(!resolve_shared_memory(&mut mem, 0.0));
        assert_eq!(mem, 0.0);
    }

    /// `/sys/class` is matched by exact class name. A substring test on "npu"
    /// also matches "input", which enumerated every mouse and evdev node as an
    /// accelerator.
    #[test]
    fn npu_class_match_excludes_input() {
        const NPU_CLASSES: &[&str] = &["accel", "npu", "habanalabs", "intel_vpu"];
        assert!(NPU_CLASSES.contains(&"accel"));
        assert!(NPU_CLASSES.contains(&"npu"));
        assert!(!NPU_CLASSES.contains(&"input"));
        // The trap that produced 29 phantom NPUs on a DGX Spark:
        assert!("input".contains("npu"));
    }
}
