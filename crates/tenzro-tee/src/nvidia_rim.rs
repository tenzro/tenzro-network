//! NVIDIA reference integrity manifests (RIMs) as GPU reference values.
//!
//! NVIDIA publishes a signed RIM for every GPU VBIOS and driver build it
//! supports: a TCG RIM information model document in ISO/IEC 19770-2 SWID
//! form whose `Payload` lists, per measurement index, whether the index is
//! active and the values it may take (`Hash0`, `Hash1`, ...). The values of
//! the active indices are what a GPU report's measurements must match.
//!
//! [`reference_values`] turns one RIM into the `(index, accepted values)`
//! form governance pins ([`tenzro_types::hardware_level::GpuReferenceValue`]).
//! RIM indices count from 0; SPDM measurement blocks count from 1, so RIM
//! index `i` is SPDM index `i + 1`. This module reads a RIM; it does not
//! check the RIM's XML signature. A RIM's values become governed only by a
//! `GpuReferenceValuesSet` proposal, which voters check against NVIDIA's
//! signed original.

use crate::error::{Result, TeeError};

/// What a RIM states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rim {
    /// The `Meta` element's `product`, such as `GH100`.
    pub product: String,
    /// The `Meta` element's `colloquialVersion`: the VBIOS or driver
    /// version.
    pub version: String,
    /// Active measurements as `(SPDM index, accepted values)`.
    pub references: Vec<(u8, Vec<Vec<u8>>)>,
}

fn fail(msg: impl Into<String>) -> TeeError {
    TeeError::InvalidAttestationReport(format!("RIM: {}", msg.into()))
}

/// The attributes of the element starting at `tag` (after its name).
fn attributes(tag: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = tag;
    while let Some(eq) = rest.find("=\"") {
        let name = rest[..eq]
            .rsplit(|c: char| c.is_whitespace())
            .next()
            .unwrap_or("");
        let after = &rest[eq + 2..];
        let Some(end) = after.find('"') else { break };
        // Drop any namespace prefix: `ns2:Hash0` is `Hash0`.
        let local = name.rsplit(':').next().unwrap_or(name);
        out.push((local, &after[..end]));
        rest = &after[end + 1..];
    }
    out
}

/// Every element named `local` (any namespace prefix), as its attribute
/// text.
fn elements<'a>(xml: &'a str, local: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(open) = xml[at..].find('<') {
        let start = at + open + 1;
        let Some(close) = xml[start..].find('>') else {
            break;
        };
        let body = &xml[start..start + close];
        let name = body
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or("");
        if name.rsplit(':').next() == Some(local) {
            out.push(&body[name.len()..]);
        }
        at = start + close + 1;
    }
    out
}

/// Read a RIM's product, version and active reference values.
pub fn reference_values(xml: &str) -> Result<Rim> {
    let meta = elements(xml, "Meta")
        .into_iter()
        .next()
        .ok_or_else(|| fail("no Meta element"))?;
    let meta = attributes(meta);
    let get = |k: &str| {
        meta.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.to_string())
            .ok_or_else(|| fail(format!("Meta has no {k}")))
    };
    let (product, version) = (get("product")?, get("colloquialVersion")?);

    let mut references = Vec::new();
    for resource in elements(xml, "Resource") {
        let attrs = attributes(resource);
        let attr = |k: &str| attrs.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
        if attr("type") != Some("Measurement") {
            continue;
        }
        if !attr("active").is_some_and(|a| a.eq_ignore_ascii_case("true")) {
            continue;
        }
        let index: u8 = attr("index")
            .and_then(|i| i.parse::<u8>().ok())
            .and_then(|i| i.checked_add(1))
            .ok_or_else(|| fail("a measurement index is not 0..=254"))?;
        let alternatives: usize = attr("alternatives")
            .and_then(|a| a.parse().ok())
            .ok_or_else(|| fail(format!("measurement {index} has no alternatives count")))?;
        let mut values = Vec::with_capacity(alternatives);
        for n in 0..alternatives {
            let hex_value = attr(&format!("Hash{n}"))
                .ok_or_else(|| fail(format!("measurement {index} lacks Hash{n}")))?;
            values.push(hex::decode(hex_value).map_err(|e| fail(e.to_string()))?);
        }
        if values.is_empty() {
            return Err(fail(format!("active measurement {index} accepts no value")));
        }
        references.push((index, values));
    }
    if references.is_empty() {
        return Err(fail("no active measurements"));
    }
    references.sort_by_key(|(i, _)| *i);
    Ok(Rim {
        product,
        version,
        references,
    })
}

/// The reference values of several RIMs, such as a GPU's VBIOS RIM and its
/// driver RIM, which measure disjoint indices.
pub fn combined(rims: &[Rim]) -> Vec<(u8, Vec<Vec<u8>>)> {
    let mut all: Vec<_> = rims.iter().flat_map(|r| r.references.clone()).collect();
    all.sort_by_key(|(i, _)| *i);
    all
}

/// NVIDIA's RIMs fetched from its public RIM service for tests, pinned by
/// hash. The service states no licence for the files, so they are never
/// committed: a test fetches each by id, refuses it unless its SHA-256 is the
/// pinned one, and caches it in the build's target directory.
#[cfg(any(test, feature = "test-ca"))]
pub mod service {
    use sha2::{Digest, Sha256};

    /// The service's RIM endpoint.
    pub const RIM_SERVICE: &str = "https://rim.attestation.nvidia.com/v1/rim/";

    /// The VBIOS RIM for the H100 sample report (GH100, 96.00.9F.00.01).
    pub const H100_SAMPLE_VBIOS: (&str, &str) = (
        "NV_GPU_VBIOS_1010_0200_882_96009F0001",
        "8883dfb88f92658f0359fae4185f263c0e00326dac230308a0f22586ac137099",
    );
    /// The driver RIM for the H100 sample report (GH100, 550.90.07).
    pub const H100_SAMPLE_DRIVER: (&str, &str) = (
        "NV_GPU_DRIVER_GH100_550.90.07",
        "d8febeb2d02b1a5882747daed804cce0131e887e34850216a373aaa1f24eea84",
    );

    /// The cache directory: `<target>/<profile>/nvidia-rim`, beside the test
    /// binary's `deps` directory.
    fn cache_dir() -> std::path::PathBuf {
        let exe = std::env::current_exe().expect("test binary path");
        exe.parent()
            .and_then(|deps| deps.parent())
            .expect("test binary under <target>/<profile>/deps")
            .join("nvidia-rim")
    }

    fn pinned(bytes: &[u8], sha256: &str) -> bool {
        hex::encode(Sha256::digest(bytes)) == sha256
    }

    /// The RIM `(id, sha256)` names, from the cache or the service. Panics
    /// when it cannot be fetched or its hash is not the pinned one: a test
    /// that needs it fails rather than passing without it.
    pub fn fetch((id, sha256): (&str, &str)) -> String {
        let path = cache_dir().join(format!("{id}.swidtag"));
        if let Ok(bytes) = std::fs::read(&path) {
            assert!(
                pinned(&bytes, sha256),
                "cached RIM {id} at {} does not have the pinned SHA-256",
                path.display()
            );
            return String::from_utf8(bytes).expect("a RIM is UTF-8");
        }
        let out = std::process::Command::new("curl")
            .args(["-sSf", "-m", "60", &format!("{RIM_SERVICE}{id}")])
            .output()
            .expect("curl runs");
        assert!(
            out.status.success(),
            "fetching RIM {id} from NVIDIA's RIM service failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let body: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("the RIM service answers JSON");
        use base64::Engine;
        let rim = base64::engine::general_purpose::STANDARD
            .decode(body["rim"].as_str().expect("the answer carries the RIM"))
            .expect("the RIM is base64");
        assert!(
            pinned(&rim, sha256),
            "NVIDIA's RIM service returned {id} with a SHA-256 other than the pinned one"
        );
        std::fs::create_dir_all(cache_dir()).expect("cache directory");
        std::fs::write(&path, &rim).expect("cache the RIM");
        String::from_utf8(rim).expect("a RIM is UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NVIDIA's production VBIOS RIM for GH100 VBIOS 96.00.5E.00.01, from its
    /// open-source local GPU verifier (github.com/NVIDIA/nvtrust,
    /// `guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/samples/`,
    /// Apache-2.0). Offline: it checks the reader, not the sample report,
    /// which ran a different VBIOS.
    const NVTRUST_RIM: &str =
        include_str!("../testdata/nvidia/1010_0200_882_96005E0001_PROD.swidtag");
    /// NVIDIA's sample H100 report (nvtrust, Apache-2.0): VBIOS 96.00.9F.00.01,
    /// driver 550.90.07.
    const REPORT_HEX: &str = include_str!("../testdata/nvidia/hopper_attestation_report.hex");

    #[test]
    fn nvidias_published_sample_rim_reads_as_reference_values() {
        let rim = reference_values(NVTRUST_RIM).unwrap();
        assert_eq!(rim.product, "GH100");
        assert_eq!(rim.version, "96.00.5E.00.01");
        assert_eq!(rim.references.len(), 12);
        assert!(rim.references.iter().all(|(i, v)| *i >= 1 && !v.is_empty()));
        // RIM index 0 is SPDM measurement 1.
        assert_eq!(rim.references[0].0, 1);
    }

    #[test]
    fn the_sample_h100_report_matches_nvidias_rims() {
        let vbios = reference_values(&service::fetch(service::H100_SAMPLE_VBIOS)).unwrap();
        assert_eq!(vbios.version, "96.00.9F.00.01");
        assert_eq!(vbios.references.len(), 12);
        let driver = reference_values(&service::fetch(service::H100_SAMPLE_DRIVER)).unwrap();
        assert_eq!(driver.version, "550.90.07");
        assert_eq!(driver.references.len(), 21);
        let references = combined(&[vbios, driver]);
        let report = hex::decode(REPORT_HEX.trim()).unwrap();
        crate::nvidia_device::check_reference_values(&report, &references).unwrap();
        // Each index with one value changed: the same report is refused.
        for at in 0..references.len() {
            let mut altered = references.clone();
            for v in &mut altered[at].1 {
                v[0] ^= 1;
            }
            assert!(
                crate::nvidia_device::check_reference_values(&report, &altered).is_err(),
                "index {} altered",
                altered[at].0
            );
        }
        // A VBIOS RIM for another build does not admit this report.
        let other = reference_values(NVTRUST_RIM).unwrap();
        assert!(crate::nvidia_device::check_reference_values(&report, &other.references).is_err());
    }

    #[test]
    fn a_rim_without_active_measurements_is_refused() {
        let empty =
            r#"<SoftwareIdentity><Meta product="x" colloquialVersion="1"/></SoftwareIdentity>"#;
        assert!(reference_values(empty).is_err());
        assert!(reference_values("no xml").is_err());
    }
}
