//! Local hardware detection for the Tenzro CLI.
//!
//! Ported from the Tauri desktop app so the CLI can detect hardware
//! without requiring a running RPC node.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::output;

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
    let num_str: String = lower.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
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
        if value > 100.0 { (value / 1024.0 * 10.0).round() / 10.0 } else { value }
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
    line.split(']').next_back().unwrap_or(line).trim().to_string()
}

/// Detect GPUs and accelerators using OS-provided enumeration.
async fn detect_accelerators() -> (Vec<AcceleratorInfo>, Vec<AcceleratorInfo>, bool) {
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
            {
                if output.status.success() {
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                        if let Some(displays) = json.get("SPDisplaysDataType").and_then(|v| v.as_array()) {
                            for display in displays {
                                let name = display.get("sppci_model")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown GPU")
                                    .to_string();

                                let mut memory_gb = display.get("spdisplays_vram")
                                    .and_then(|v| v.as_str())
                                    .map(parse_memory_string)
                                    .unwrap_or(0.0);

                                if memory_gb == 0.0 {
                                    if let Some(shared) = display.get("spdisplays_vram_shared")
                                        .and_then(|v| v.as_str())
                                    {
                                        memory_gb = parse_memory_string(shared);
                                        unified_memory = true;
                                    }
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
                    }
                }
            }

            // Detect Neural Engine via ioreg
            if let Ok(output) = tokio::process::Command::new("ioreg")
                .args(["-r", "-d", "1", "-c", "AppleARMIODevice"])
                .output()
                .await
            {
                if output.status.success() {
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
            }
        },
        "linux" => {
            if let Ok(output) = tokio::process::Command::new("lspci")
                .args(["-mm", "-nn"])
                .output()
                .await
            {
                if output.status.success() {
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
            }

            // nvidia-smi
            if let Ok(output) = tokio::process::Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
                .output()
                .await
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for (i, line) in stdout.lines().enumerate() {
                        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                        if parts.len() >= 2 {
                            let name = parts[0].to_string();
                            let vram_mb: f64 = parts[1].parse().unwrap_or(0.0);
                            let memory_gb = (vram_mb / 1024.0 * 10.0).round() / 10.0;
                            let gpu_count = gpus.len();
                            if let Some(gpu) = gpus.iter_mut().find(|g| g.name.contains(&name) || i < gpu_count) {
                                gpu.memory_gb = memory_gb;
                                if gpu.name.is_empty() || gpu.name == "Unknown" { gpu.name = name; }
                            } else {
                                gpus.push(AcceleratorInfo { name, kind: "gpu".to_string(), memory_gb, compute_units: None });
                            }
                        }
                    }
                }
            }

            // rocm-smi (AMD GPUs)
            if let Ok(output) = tokio::process::Command::new("rocm-smi")
                .args(["--showproductname", "--showmeminfo", "vram", "--csv"])
                .output()
                .await
            {
                if output.status.success() {
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
            }

            // NPU devices in /sys/class
            if let Ok(entries) = std::fs::read_dir("/sys/class") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.contains("npu") || name.contains("accel") || name.contains("habana") || name.contains("intel_vpu") {
                        if let Ok(devices) = std::fs::read_dir(entry.path()) {
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
            }
        },
        "windows" => {
            if let Ok(output) = tokio::process::Command::new("powershell")
                .args(["-NoProfile", "-Command",
                    "Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM | ConvertTo-Json"])
                .output()
                .await
            {
                if output.status.success() {
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
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
                }
            }
        },
        _ => {}
    }

    (gpus, accelerators, unified_memory)
}

/// Detect TEE capabilities by probing OS device files.
async fn detect_tee_capabilities() -> (bool, Option<String>, Vec<String>) {
    let os = std::env::consts::OS;
    let mut tee_type = None;
    let mut capabilities = Vec::new();

    match os {
        "macos" => {
            if let Ok(output) = tokio::process::Command::new("ioreg")
                .args(["-r", "-d", "1", "-c", "AppleSEPManager"])
                .output()
                .await
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("AppleSEPManager") || stdout.contains("SEP") {
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
        },
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

            if std::path::Path::new("/sys/firmware/efi/efivars").exists() {
                capabilities.push("secure_boot_capable".to_string());
            }

            if std::path::Path::new("/dev/tpm0").exists() || std::path::Path::new("/dev/tpmrm0").exists() {
                if tee_type.is_none() { tee_type = Some("TPM".to_string()); }
                capabilities.push("tpm_available".to_string());
                capabilities.push("measured_boot".to_string());
            }
        },
        "windows" => {
            if let Ok(output) = tokio::process::Command::new("powershell")
                .args(["-NoProfile", "-Command",
                    "Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled | ConvertTo-Json"])
                .output()
                .await
            {
                if output.status.success() {
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                        if json.get("TpmPresent").and_then(|v| v.as_bool()).unwrap_or(false) {
                            tee_type = Some("TPM".to_string());
                            capabilities.push("tpm_available".to_string());
                            if json.get("TpmEnabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                                capabilities.push("tpm_enabled".to_string());
                            }
                        }
                    }
                }
            }

            if let Ok(output) = tokio::process::Command::new("powershell")
                .args(["-NoProfile", "-Command",
                    "Get-CimInstance Win32_DeviceGuard | Select-Object VirtualizationBasedSecurityStatus | ConvertTo-Json"])
                .output()
                .await
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("Running") || stdout.contains("2") {
                        capabilities.push("virtualization_based_security".to_string());
                    }
                }
            }
        },
        _ => {}
    }

    capabilities.sort();
    capabilities.dedup();

    let available = tee_type.is_some() || !capabilities.is_empty();
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
    use sha2::{Sha256, Digest};
    let input = format!(
        "{}|{}|{:.0}|{}|{}|{}",
        cpu_model, cpu_cores, total_ram_gb,
        device_names.join(","), os, arch,
    );
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)
}

/// Detect full hardware profile locally (no RPC needed).
pub async fn detect_hardware_profile() -> HardwareProfile {
    let mut sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::everything(),
    );
    sys.refresh_all();

    let cpu_model = sys.cpus().first()
        .map(|c| c.brand().to_string())
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

    let (gpus, accelerators, unified_memory) = detect_accelerators().await;
    let (tee_available, tee_type, tee_capabilities) = detect_tee_capabilities().await;

    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    let mut all_device_names: Vec<String> = gpus.iter().chain(accelerators.iter())
        .map(|d| d.name.clone())
        .collect();
    all_device_names.sort();

    let device_fingerprint = generate_fingerprint(
        &cpu_model, cpu_cores, total_ram_gb,
        &all_device_names, &os, &arch,
    );

    HardwareProfile {
        cpu_model, cpu_cores, cpu_threads, total_ram_gb, unified_memory,
        gpus, accelerators, storage_available_gb,
        tee_available, tee_type, tee_capabilities,
        os, arch, device_fingerprint,
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
    output::print_field("Available Storage", &format!("{:.1} GB", hardware.storage_available_gb));

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
            let cu = gpu.compute_units.map(|c| format!(", {} cores", c)).unwrap_or_default();
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
    output::print_field("Fingerprint", &output::format_hash(&hardware.device_fingerprint));

    Ok(())
}
