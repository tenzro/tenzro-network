//! Runtime NVML bindings for NVIDIA Confidential Computing evidence collection.
//!
//! GPU attestation evidence on NVIDIA hardware comes from NVML — the NVIDIA
//! Management Library that ships with every driver from r535 onward — through
//! four Confidential Computing entry points:
//!
//! ```c
//! nvmlReturn_t nvmlSystemGetConfComputeState(nvmlConfComputeSystemState_t *state);
//! nvmlReturn_t nvmlSystemGetConfComputeGpusReadyState(unsigned int *isAcceptingWork);
//! nvmlReturn_t nvmlDeviceGetConfComputeGpuCertificate(nvmlDevice_t device,
//!         nvmlConfComputeGpuCertificate_t *gpuCert);
//! nvmlReturn_t nvmlDeviceGetConfComputeGpuAttestationReport(nvmlDevice_t device,
//!         nvmlConfComputeGpuAttestationReport_t *gpuAtstReport);
//! ```
//!
//! `libnvidia-nscq.so` is a different library for a different job: NVSwitch and
//! NVLink fabric attestation on multi-GPU protected topologies. It is not
//! involved in single-GPU evidence collection and is not required here.
//!
//! # Binding strategy
//!
//! The library is opened with `dlopen("libnvidia-ml.so.1")` and symbols are
//! resolved with `dlsym` at first use, rather than linked at build time. A
//! Tenzro node binary runs unchanged on hosts with no NVIDIA driver at all;
//! the absence of the library is an ordinary `TeeError::NotAvailable`, not a
//! link failure. `nvmlInit` and `nvmlDeviceGetHandleByIndex` are preprocessor
//! aliases in `nvml.h`, so the `_v2` symbol names are resolved directly.
//!
//! # Struct layout
//!
//! The three CC structs are plain `unsigned int` and `unsigned char[N]` fields
//! with natural 4-byte alignment, no padding, and no version field, and their
//! layout has been stable since r535. Sizes are 12, 9224, and 12332 bytes.
//! The two large ones are heap-allocated.
//!
//! # Nonce
//!
//! `nonce` on the attestation-report struct is an **input** field: the caller
//! writes 32 bytes before the call and the GPU's SPDM responder binds them into
//! the signed measurement response. This is what makes a report non-replayable,
//! so the struct is zeroed, then the nonce is written, then the call is made.
//!
//! # References
//!
//! - NVML API reference: <https://docs.nvidia.com/deploy/nvml-api/>
//! - `nvml.h` in <https://github.com/NVIDIA/go-nvml> (`gen/nvml/nvml.h`)
//! - NVIDIA nvtrust: <https://github.com/NVIDIA/nvtrust>
//! - go-nvtrust: <https://github.com/confidentsecurity/go-nvtrust> (Apache-2.0),
//!   whose package split is the clearest statement that NVML covers GPU
//!   attestation while nscq covers NVSwitch attestation
//! - DMTF SPDM 1.1: <https://www.dmtf.org/standards/spdm>

use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::sync::Arc;

use crate::error::{Result, TeeError};

// ============================================================================
// ABI constants
// ============================================================================

/// `NVML_CC_GPU_CEC_NONCE_SIZE` — SPDM nonce width.
pub const NVML_CC_GPU_CEC_NONCE_SIZE: usize = 0x20;
/// `NVML_CC_GPU_ATTESTATION_REPORT_SIZE` — GPU SPDM measurement response buffer.
pub const NVML_CC_GPU_ATTESTATION_REPORT_SIZE: usize = 0x2000;
/// `NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE` — CEC (board controller) report buffer.
pub const NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE: usize = 0x1000;
/// `NVML_GPU_CERT_CHAIN_SIZE` — device identity certificate chain buffer.
pub const NVML_GPU_CERT_CHAIN_SIZE: usize = 0x1000;
/// `NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE` — attestation-key certificate chain buffer.
pub const NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE: usize = 0x1400;
/// `NVML_DEVICE_UUID_V2_BUFFER_SIZE`.
pub const NVML_DEVICE_UUID_V2_BUFFER_SIZE: usize = 96;

/// `nvmlReturn_t` values this module distinguishes.
mod ret {
    pub const SUCCESS: i32 = 0;
    pub const UNINITIALIZED: i32 = 1;
    pub const INVALID_ARGUMENT: i32 = 2;
    pub const NOT_SUPPORTED: i32 = 3;
    pub const NOT_FOUND: i32 = 6;
    pub const INSUFFICIENT_SIZE: i32 = 7;
}

/// Render an `nvmlReturn_t` as a diagnostic string.
fn nvml_strerror(code: c_int) -> &'static str {
    match code {
        ret::SUCCESS => "success",
        ret::UNINITIALIZED => "NVML was not initialized",
        ret::INVALID_ARGUMENT => "invalid argument",
        ret::NOT_SUPPORTED => "not supported on this device or driver",
        ret::NOT_FOUND => "not found",
        ret::INSUFFICIENT_SIZE => "insufficient buffer size",
        999 => "unknown NVML error",
        _ => "NVML error",
    }
}

/// CPU trusted-execution capability reported by `nvmlConfComputeSystemState_t.environment`'s
/// companion CPU-caps enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcCpuCaps {
    /// No CPU confidential-computing capability.
    None,
    /// AMD SEV (pre-SNP).
    AmdSev,
    /// Intel TDX.
    IntelTdx,
    /// AMD SEV-SNP.
    AmdSevSnp,
    /// AMD SEV-SNP with vTOM.
    AmdSnpVtom,
    /// Value not recognized by this build.
    Unknown(u32),
}

impl CcCpuCaps {
    fn from_raw(v: u32) -> Self {
        match v {
            0 => CcCpuCaps::None,
            1 => CcCpuCaps::AmdSev,
            2 => CcCpuCaps::IntelTdx,
            3 => CcCpuCaps::AmdSevSnp,
            4 => CcCpuCaps::AmdSnpVtom,
            other => CcCpuCaps::Unknown(other),
        }
    }

    /// Whether this capability can anchor a confidential VM.
    ///
    /// NVIDIA GPU CC extends a CPU confidential VM; it does not establish one.
    /// A GPU report collected outside a CVM measures the GPU but proves nothing
    /// about the software holding the model weights and prompts.
    pub fn anchors_cvm(&self) -> bool {
        matches!(
            self,
            CcCpuCaps::IntelTdx | CcCpuCaps::AmdSevSnp | CcCpuCaps::AmdSnpVtom
        )
    }
}

impl std::fmt::Display for CcCpuCaps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CcCpuCaps::None => write!(f, "none"),
            CcCpuCaps::AmdSev => write!(f, "AMD SEV"),
            CcCpuCaps::IntelTdx => write!(f, "Intel TDX"),
            CcCpuCaps::AmdSevSnp => write!(f, "AMD SEV-SNP"),
            CcCpuCaps::AmdSnpVtom => write!(f, "AMD SEV-SNP (vTOM)"),
            CcCpuCaps::Unknown(v) => write!(f, "unknown({})", v),
        }
    }
}

/// Decoded `nvmlConfComputeSystemCaps_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcCapabilities {
    /// CPU confidential-computing capability the driver observes on this host.
    pub cpu: CcCpuCaps,
    /// Whether the installed GPUs are CC-capable silicon.
    pub gpus_cc_capable: bool,
}

/// Decoded `nvmlConfComputeSystemState_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcSystemState {
    /// `NVML_CC_SYSTEM_ENVIRONMENT_*` — 0 unavailable, 1 simulation, 2 production.
    pub environment: u32,
    /// `NVML_CC_SYSTEM_FEATURE_*` — 0 disabled, 1 enabled.
    pub cc_feature: u32,
    /// `NVML_CC_SYSTEM_DEVTOOLS_MODE_*` — 0 off, 1 on.
    pub dev_tools_mode: u32,
}

impl CcSystemState {
    /// Whether Confidential Computing is switched on for this system.
    pub fn cc_enabled(&self) -> bool {
        self.cc_feature == 1
    }

    /// Whether the CC environment is the production one rather than a simulation.
    pub fn production_environment(&self) -> bool {
        self.environment == 2
    }

    /// Whether developer-tools mode is on.
    ///
    /// DevTools mode relaxes CC isolation so a debugger can attach. A report
    /// collected in that posture is a valid signed report of a machine that is
    /// not enforcing confidentiality, and should not carry production weight.
    pub fn dev_tools_on(&self) -> bool {
        self.dev_tools_mode != 0
    }
}

/// GPU attestation evidence as returned by NVML.
#[derive(Debug, Clone)]
pub struct GpuAttestationEvidence {
    /// The 32-byte nonce that was bound into the report.
    pub nonce: [u8; NVML_CC_GPU_CEC_NONCE_SIZE],
    /// SPDM measurement response signed by the GPU's attestation key.
    pub report: Vec<u8>,
    /// CEC (board-level controller) attestation report, when the board carries one.
    pub cec_report: Option<Vec<u8>>,
}

/// GPU certificate chains as returned by NVML.
#[derive(Debug, Clone)]
pub struct GpuCertificateChains {
    /// Device identity certificate chain, terminating at an NVIDIA CA.
    pub cert_chain: Vec<u8>,
    /// Attestation-key certificate chain.
    pub attestation_cert_chain: Vec<u8>,
}

// ============================================================================
// C struct layouts
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct NvmlConfComputeSystemState {
    environment: c_uint,
    cc_feature: c_uint,
    dev_tools_mode: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NvmlConfComputeSystemCaps {
    cpu_caps: c_uint,
    gpus_caps: c_uint,
}

#[repr(C)]
struct NvmlConfComputeGpuCertificate {
    cert_chain_size: c_uint,
    attestation_cert_chain_size: c_uint,
    cert_chain: [u8; NVML_GPU_CERT_CHAIN_SIZE],
    attestation_cert_chain: [u8; NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE],
}

#[repr(C)]
struct NvmlConfComputeGpuAttestationReport {
    is_cec_attestation_report_present: c_uint,
    attestation_report_size: c_uint,
    cec_attestation_report_size: c_uint,
    nonce: [u8; NVML_CC_GPU_CEC_NONCE_SIZE],
    attestation_report: [u8; NVML_CC_GPU_ATTESTATION_REPORT_SIZE],
    cec_attestation_report: [u8; NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE],
}

/// Allocate a zeroed `T` directly on the heap.
///
/// The two CC payload structs are 9 KiB and 12 KiB. Constructing them as
/// values first would put a copy of that size on the caller's stack before the
/// move into the box. All-zero is a valid bit pattern for both — every field is
/// an integer or a byte array.
unsafe fn zeroed_box<T>() -> Box<T> {
    let layout = std::alloc::Layout::new::<T>();
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) } as *mut T;
    if ptr.is_null() {
        std::alloc::handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(ptr) }
}

// ============================================================================
// Symbol table
// ============================================================================

type FnInit = unsafe extern "C" fn() -> c_int;
type FnShutdown = unsafe extern "C" fn() -> c_int;
type FnDeviceGetHandleByIndex = unsafe extern "C" fn(c_uint, *mut *mut c_void) -> c_int;
type FnDeviceGetUuid = unsafe extern "C" fn(*mut c_void, *mut c_char, c_uint) -> c_int;
type FnSystemGetConfComputeState = unsafe extern "C" fn(*mut NvmlConfComputeSystemState) -> c_int;
type FnSystemGetConfComputeCapabilities =
    unsafe extern "C" fn(*mut NvmlConfComputeSystemCaps) -> c_int;
type FnSystemGetConfComputeGpusReadyState = unsafe extern "C" fn(*mut c_uint) -> c_int;
type FnDeviceGetConfComputeGpuCertificate =
    unsafe extern "C" fn(*mut c_void, *mut NvmlConfComputeGpuCertificate) -> c_int;
type FnDeviceGetConfComputeGpuAttestationReport =
    unsafe extern "C" fn(*mut c_void, *mut NvmlConfComputeGpuAttestationReport) -> c_int;

/// An opened NVML handle with the Confidential Computing entry points resolved.
///
/// `nvmlInit_v2` is called on construction and `nvmlShutdown` on drop. NVML
/// reference-counts init/shutdown internally, so more than one live handle in a
/// process is safe.
pub struct Nvml {
    handle: *mut c_void,
    shutdown: FnShutdown,
    device_get_handle_by_index: FnDeviceGetHandleByIndex,
    device_get_uuid: FnDeviceGetUuid,
    system_get_cc_state: FnSystemGetConfComputeState,
    system_get_cc_capabilities: FnSystemGetConfComputeCapabilities,
    system_get_cc_gpus_ready_state: FnSystemGetConfComputeGpusReadyState,
    device_get_cc_certificate: FnDeviceGetConfComputeGpuCertificate,
    device_get_cc_attestation_report: FnDeviceGetConfComputeGpuAttestationReport,
}

// The `dlopen` handle and the `nvmlDevice_t` handles NVML hands back are opaque
// pointers into the driver's own state. NVML's documented threading contract is
// that its API is thread-safe, so the raw pointers are safe to move and share.
unsafe impl Send for Nvml {}
unsafe impl Sync for Nvml {}

/// An NVML device handle.
///
/// Opaque `nvmlDevice_t`. Valid for as long as the [`Nvml`] that produced it.
#[derive(Clone, Copy)]
pub struct NvmlDevice(*mut c_void);

unsafe impl Send for NvmlDevice {}
unsafe impl Sync for NvmlDevice {}

/// Resolve one symbol out of an open shared object.
unsafe fn sym(handle: *mut c_void, name: &str) -> Result<*mut c_void> {
    let c_name = CString::new(name)
        .map_err(|_| TeeError::not_available(format!("invalid NVML symbol name: {}", name)))?;
    // Clear any stale error before the lookup: `dlsym` returning null is a
    // legitimate result for a symbol whose value is null, so `dlerror` is the
    // only way to tell "absent" from "present and null".
    unsafe { libc::dlerror() };
    let ptr = unsafe { libc::dlsym(handle, c_name.as_ptr()) };
    if ptr.is_null() {
        let err = unsafe { libc::dlerror() };
        let detail = if err.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned()
        };
        return Err(TeeError::not_available(format!(
            "NVML symbol {} not found in libnvidia-ml.so.1{}{}",
            name,
            if detail.is_empty() { "" } else { ": " },
            detail
        )));
    }
    Ok(ptr)
}

impl Nvml {
    /// Open `libnvidia-ml.so.1` and resolve the Confidential Computing entry points.
    ///
    /// Returns [`TeeError::NotAvailable`] when the library is absent (no NVIDIA
    /// driver installed) or when it predates r535 and therefore exports none of
    /// the CC symbols.
    pub fn open() -> Result<Arc<Self>> {
        let so_name = CString::new("libnvidia-ml.so.1").expect("static string has no interior nul");
        // RTLD_LOCAL keeps NVML's symbols out of the global namespace so they
        // cannot collide with anything else the process has loaded.
        let handle = unsafe { libc::dlopen(so_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            let err = unsafe { libc::dlerror() };
            let detail = if err.is_null() {
                "library not found".to_string()
            } else {
                unsafe { std::ffi::CStr::from_ptr(err) }
                    .to_string_lossy()
                    .into_owned()
            };
            return Err(TeeError::not_available(format!(
                "libnvidia-ml.so.1 could not be loaded: {}",
                detail
            )));
        }

        let resolve = |name: &str| -> Result<*mut c_void> { unsafe { sym(handle, name) } };

        let init_ptr = match resolve("nvmlInit_v2") {
            Ok(p) => p,
            Err(e) => {
                unsafe { libc::dlclose(handle) };
                return Err(e);
            }
        };

        // Every resolution below is fallible; close the library on any miss so a
        // partially-bound handle is never returned.
        let bind = || -> Result<Nvml> {
            let init: FnInit = unsafe { std::mem::transmute(init_ptr) };
            let shutdown: FnShutdown = unsafe { std::mem::transmute(resolve("nvmlShutdown")?) };
            let device_get_handle_by_index: FnDeviceGetHandleByIndex =
                unsafe { std::mem::transmute(resolve("nvmlDeviceGetHandleByIndex_v2")?) };
            let device_get_uuid: FnDeviceGetUuid =
                unsafe { std::mem::transmute(resolve("nvmlDeviceGetUUID")?) };
            let system_get_cc_state: FnSystemGetConfComputeState =
                unsafe { std::mem::transmute(resolve("nvmlSystemGetConfComputeState")?) };
            let system_get_cc_capabilities: FnSystemGetConfComputeCapabilities =
                unsafe { std::mem::transmute(resolve("nvmlSystemGetConfComputeCapabilities")?) };
            let system_get_cc_gpus_ready_state: FnSystemGetConfComputeGpusReadyState =
                unsafe { std::mem::transmute(resolve("nvmlSystemGetConfComputeGpusReadyState")?) };
            let device_get_cc_certificate: FnDeviceGetConfComputeGpuCertificate =
                unsafe { std::mem::transmute(resolve("nvmlDeviceGetConfComputeGpuCertificate")?) };
            let device_get_cc_attestation_report: FnDeviceGetConfComputeGpuAttestationReport = unsafe {
                std::mem::transmute(resolve("nvmlDeviceGetConfComputeGpuAttestationReport")?)
            };

            let rc = unsafe { init() };
            if rc != ret::SUCCESS {
                return Err(TeeError::not_available(format!(
                    "nvmlInit_v2 failed ({}): {}",
                    rc,
                    nvml_strerror(rc)
                )));
            }

            Ok(Nvml {
                handle,
                shutdown,
                device_get_handle_by_index,
                device_get_uuid,
                system_get_cc_state,
                system_get_cc_capabilities,
                system_get_cc_gpus_ready_state,
                device_get_cc_certificate,
                device_get_cc_attestation_report,
            })
        };

        match bind() {
            Ok(nvml) => {
                tracing::debug!("NVML loaded with Confidential Computing entry points");
                Ok(Arc::new(nvml))
            }
            Err(e) => {
                unsafe { libc::dlclose(handle) };
                Err(e)
            }
        }
    }

    /// Read the system-wide Confidential Computing state.
    pub fn cc_system_state(&self) -> Result<CcSystemState> {
        let mut state = NvmlConfComputeSystemState {
            environment: 0,
            cc_feature: 0,
            dev_tools_mode: 0,
        };
        let rc = unsafe { (self.system_get_cc_state)(&mut state) };
        if rc != ret::SUCCESS {
            return Err(TeeError::not_available(format!(
                "nvmlSystemGetConfComputeState failed ({}): {}",
                rc,
                nvml_strerror(rc)
            )));
        }
        Ok(CcSystemState {
            environment: state.environment,
            cc_feature: state.cc_feature,
            dev_tools_mode: state.dev_tools_mode,
        })
    }

    /// Read the CPU and GPU Confidential Computing capabilities the driver observes.
    ///
    /// The CPU field is what makes this call worth making from Tenzro's side: it
    /// is the GPU driver's independent view of which CPU confidential-VM
    /// technology is active, so it can be cross-checked against the CPU anchor
    /// provider the node believes it is running under.
    pub fn cc_capabilities(&self) -> Result<CcCapabilities> {
        let mut caps = NvmlConfComputeSystemCaps {
            cpu_caps: 0,
            gpus_caps: 0,
        };
        let rc = unsafe { (self.system_get_cc_capabilities)(&mut caps) };
        if rc != ret::SUCCESS {
            return Err(TeeError::not_available(format!(
                "nvmlSystemGetConfComputeCapabilities failed ({}): {}",
                rc,
                nvml_strerror(rc)
            )));
        }
        Ok(CcCapabilities {
            cpu: CcCpuCaps::from_raw(caps.cpu_caps),
            gpus_cc_capable: caps.gpus_caps == 1,
        })
    }

    /// Whether the GPUs are accepting client work in CC mode.
    ///
    /// In CC mode the driver holds the GPUs out of service until the CC
    /// handshake has completed. Evidence collected before that point describes a
    /// GPU that is not yet protecting anything.
    pub fn cc_gpus_ready(&self) -> Result<bool> {
        let mut ready: c_uint = 0;
        let rc = unsafe { (self.system_get_cc_gpus_ready_state)(&mut ready) };
        if rc != ret::SUCCESS {
            return Err(TeeError::not_available(format!(
                "nvmlSystemGetConfComputeGpusReadyState failed ({}): {}",
                rc,
                nvml_strerror(rc)
            )));
        }
        Ok(ready == 1)
    }

    /// Look up a device handle by zero-based index.
    pub fn device_by_index(&self, index: u32) -> Result<NvmlDevice> {
        let mut dev: *mut c_void = std::ptr::null_mut();
        let rc = unsafe { (self.device_get_handle_by_index)(index as c_uint, &mut dev) };
        if rc != ret::SUCCESS {
            return Err(TeeError::not_available(format!(
                "nvmlDeviceGetHandleByIndex_v2({}) failed ({}): {}",
                index,
                rc,
                nvml_strerror(rc)
            )));
        }
        Ok(NvmlDevice(dev))
    }

    /// Read a device's UUID string (`GPU-xxxxxxxx-...`).
    pub fn device_uuid(&self, device: NvmlDevice) -> Result<String> {
        let mut buf = vec![0u8; NVML_DEVICE_UUID_V2_BUFFER_SIZE];
        let rc = unsafe {
            (self.device_get_uuid)(
                device.0,
                buf.as_mut_ptr() as *mut c_char,
                NVML_DEVICE_UUID_V2_BUFFER_SIZE as c_uint,
            )
        };
        if rc != ret::SUCCESS {
            return Err(TeeError::not_available(format!(
                "nvmlDeviceGetUUID failed ({}): {}",
                rc,
                nvml_strerror(rc)
            )));
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
    }

    /// Fetch the device identity and attestation-key certificate chains.
    pub fn cc_certificate_chains(&self, device: NvmlDevice) -> Result<GpuCertificateChains> {
        let mut cert: Box<NvmlConfComputeGpuCertificate> = unsafe { zeroed_box() };
        let rc = unsafe { (self.device_get_cc_certificate)(device.0, cert.as_mut()) };
        if rc != ret::SUCCESS {
            return Err(TeeError::attestation_failed(format!(
                "nvmlDeviceGetConfComputeGpuCertificate failed ({}): {}",
                rc,
                nvml_strerror(rc)
            )));
        }

        let chain_len = (cert.cert_chain_size as usize).min(NVML_GPU_CERT_CHAIN_SIZE);
        let attest_len =
            (cert.attestation_cert_chain_size as usize).min(NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE);

        if chain_len == 0 {
            return Err(TeeError::attestation_failed(
                "NVML returned an empty GPU certificate chain",
            ));
        }

        Ok(GpuCertificateChains {
            cert_chain: cert.cert_chain[..chain_len].to_vec(),
            attestation_cert_chain: cert.attestation_cert_chain[..attest_len].to_vec(),
        })
    }

    /// Collect a nonce-bound GPU attestation report.
    ///
    /// The nonce is written into the request struct before the call; the driver
    /// passes it to the GPU's SPDM responder, which binds it into the signed
    /// measurement response. Reusing a nonce yields a replayable report, so the
    /// caller must supply fresh random bytes for every attestation.
    pub fn cc_attestation_report(
        &self,
        device: NvmlDevice,
        nonce: &[u8; NVML_CC_GPU_CEC_NONCE_SIZE],
    ) -> Result<GpuAttestationEvidence> {
        let mut req: Box<NvmlConfComputeGpuAttestationReport> = unsafe { zeroed_box() };
        req.nonce.copy_from_slice(nonce);

        let rc = unsafe { (self.device_get_cc_attestation_report)(device.0, req.as_mut()) };
        if rc != ret::SUCCESS {
            return Err(TeeError::attestation_failed(format!(
                "nvmlDeviceGetConfComputeGpuAttestationReport failed ({}): {}",
                rc,
                nvml_strerror(rc)
            )));
        }

        let report_len =
            (req.attestation_report_size as usize).min(NVML_CC_GPU_ATTESTATION_REPORT_SIZE);
        if report_len == 0 {
            return Err(TeeError::attestation_failed(
                "NVML returned a zero-length GPU attestation report",
            ));
        }

        // The driver echoes the nonce back in the response struct. A mismatch
        // means the report is not bound to this request and must not be used.
        if req.nonce != *nonce {
            return Err(TeeError::attestation_failed(
                "GPU attestation report nonce does not match the requested nonce",
            ));
        }

        let cec_report = if req.is_cec_attestation_report_present != 0 {
            let cec_len = (req.cec_attestation_report_size as usize)
                .min(NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE);
            if cec_len == 0 {
                None
            } else {
                Some(req.cec_attestation_report[..cec_len].to_vec())
            }
        } else {
            None
        };

        Ok(GpuAttestationEvidence {
            nonce: *nonce,
            report: req.attestation_report[..report_len].to_vec(),
            cec_report,
        })
    }
}

impl Drop for Nvml {
    fn drop(&mut self) {
        unsafe {
            (self.shutdown)();
            libc::dlclose(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cc_struct_sizes_match_nvml_abi() {
        // Layouts are fixed by the driver ABI and stable since r535. A change
        // here means the bindings no longer describe what the driver writes.
        assert_eq!(std::mem::size_of::<NvmlConfComputeSystemState>(), 12);
        assert_eq!(std::mem::size_of::<NvmlConfComputeSystemCaps>(), 8);
        assert_eq!(std::mem::size_of::<NvmlConfComputeGpuCertificate>(), 9224);
        assert_eq!(
            std::mem::size_of::<NvmlConfComputeGpuAttestationReport>(),
            12332
        );
        assert_eq!(
            std::mem::align_of::<NvmlConfComputeGpuAttestationReport>(),
            4
        );
    }

    #[test]
    fn cpu_caps_anchor_classification() {
        assert!(CcCpuCaps::from_raw(2).anchors_cvm());
        assert!(CcCpuCaps::from_raw(3).anchors_cvm());
        assert!(CcCpuCaps::from_raw(4).anchors_cvm());
        // Pre-SNP SEV has no attestation report, so it cannot anchor a
        // verifiable confidential VM.
        assert!(!CcCpuCaps::from_raw(1).anchors_cvm());
        assert!(!CcCpuCaps::from_raw(0).anchors_cvm());
    }

    #[test]
    fn system_state_predicates() {
        let enabled = CcSystemState {
            environment: 2,
            cc_feature: 1,
            dev_tools_mode: 0,
        };
        assert!(enabled.cc_enabled());
        assert!(enabled.production_environment());
        assert!(!enabled.dev_tools_on());

        let devtools = CcSystemState {
            environment: 2,
            cc_feature: 1,
            dev_tools_mode: 1,
        };
        assert!(devtools.dev_tools_on());

        let sim = CcSystemState {
            environment: 1,
            cc_feature: 1,
            dev_tools_mode: 0,
        };
        assert!(!sim.production_environment());
    }

    #[test]
    fn zeroed_box_allocates_zeroed_payload() {
        let b: Box<NvmlConfComputeGpuAttestationReport> = unsafe { zeroed_box() };
        assert_eq!(b.attestation_report_size, 0);
        assert!(b.nonce.iter().all(|&x| x == 0));
        assert!(b.attestation_report.iter().all(|&x| x == 0));
    }

    #[tokio::test]
    async fn open_is_graceful_without_driver() {
        // On a host with no NVIDIA driver this is a NotAvailable error, never a
        // panic or a link failure — the same binary runs on GPU and non-GPU nodes.
        match Nvml::open() {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("libnvidia-ml") || msg.contains("NVML"),
                    "unexpected error text: {}",
                    msg
                );
            }
        }
    }
}
