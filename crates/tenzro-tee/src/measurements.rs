//! The measurement registers a report's evidence carries, read without
//! verifying it.
//!
//! An operator comparing a machine against the published measurements of its
//! image needs the registers themselves: on Intel TDX the launch measurement
//! (MRTD) and the four runtime registers (RTMR0-3), on AMD SEV-SNP the launch
//! measurement. These are read straight from the quote or report bytes; a
//! verifier must still check the evidence with [`crate::verify_report`], whose
//! result carries the same registers once the vendor signature is proven.

use tenzro_types::tee::{AttestationReport, Measurement, TeeVendor};

/// TDX quote header length (versions 4 and 5).
const TDX_HEADER_LEN: usize = 48;
/// A version 5 quote puts a body type (2 bytes) and size (4 bytes) before the
/// report body.
const TDX_V5_BODY_PREFIX: usize = 6;
/// Offsets inside the TD report body.
const TDX_MRTD: usize = 136;
const TDX_RTMR0: usize = 328;
const TDX_REGISTER_LEN: usize = 48;
/// SEV-SNP `MEASUREMENT` in the attestation report.
const SNP_MEASUREMENT: std::ops::Range<usize> = 0x90..0xC0;

fn register(index: u32, name: &str, value: &[u8]) -> Measurement {
    Measurement {
        index,
        algorithm: "SHA384".into(),
        value: value.to_vec(),
        register: name.into(),
        description: None,
    }
}

/// The registers in `report`'s evidence, launch measurement first. Empty
/// when the evidence is too short for its vendor's layout.
pub fn evidence_measurements(report: &AttestationReport) -> Vec<Measurement> {
    let evidence: &[u8] = if report.attestation_data.is_empty() {
        &report.quote
    } else {
        &report.attestation_data
    };
    match report.vendor {
        TeeVendor::IntelTdx => tdx_registers(evidence),
        TeeVendor::AmdSevSnp | TeeVendor::AMDSEV => evidence
            .get(SNP_MEASUREMENT)
            .map(|m| vec![register(0, "MEASUREMENT", m)])
            .unwrap_or_default(),
        _ if !report.measurement.is_empty() => {
            vec![register(0, "MEASUREMENT", &report.measurement)]
        }
        _ => Vec::new(),
    }
}

/// MRTD and RTMR0-3 of a TDX quote (version 4 or 5).
pub fn tdx_registers(quote: &[u8]) -> Vec<Measurement> {
    let Some(version) = quote.get(..2).map(|v| u16::from_le_bytes([v[0], v[1]])) else {
        return Vec::new();
    };
    let body = match version {
        4 => TDX_HEADER_LEN,
        5 => TDX_HEADER_LEN + TDX_V5_BODY_PREFIX,
        _ => return Vec::new(),
    };
    let at = |off: usize| quote.get(body + off..body + off + TDX_REGISTER_LEN);
    let Some(mrtd) = at(TDX_MRTD) else {
        return Vec::new();
    };
    let mut out = vec![register(0, "MRTD", mrtd)];
    for i in 0..4 {
        match at(TDX_RTMR0 + i * TDX_REGISTER_LEN) {
            Some(r) => out.push(register(i as u32 + 1, &format!("RTMR{i}"), r)),
            None => return Vec::new(),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote(version: u16) -> Vec<u8> {
        let body = if version == 5 {
            TDX_HEADER_LEN + TDX_V5_BODY_PREFIX
        } else {
            TDX_HEADER_LEN
        };
        let mut q = vec![0u8; body + 584];
        q[..2].copy_from_slice(&version.to_le_bytes());
        q[body + TDX_MRTD..body + TDX_MRTD + 48].fill(0xAA);
        for i in 0..4 {
            let off = body + TDX_RTMR0 + i * 48;
            q[off..off + 48].fill(0x10 + i as u8);
        }
        q
    }

    #[test]
    fn tdx_registers_are_read_from_v4_and_v5_quotes() {
        for v in [4, 5] {
            let regs = tdx_registers(&quote(v));
            let names: Vec<_> = regs.iter().map(|m| m.register.as_str()).collect();
            assert_eq!(names, ["MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"], "v{v}");
            assert_eq!(regs[0].value, vec![0xAA; 48]);
            assert_eq!(regs[3].value, vec![0x12; 48]);
        }
    }

    #[test]
    fn a_short_or_unknown_quote_has_no_registers() {
        assert!(tdx_registers(&quote(4)[..400]).is_empty());
        assert!(tdx_registers(&quote(3)).is_empty());
        assert!(tdx_registers(&[]).is_empty());
    }

    #[test]
    fn snp_measurement_is_read_from_the_report() {
        let mut data = vec![0u8; 0x4A0];
        data[SNP_MEASUREMENT].fill(0x5A);
        let report = AttestationReport::new(TeeVendor::AmdSevSnp, data, vec![], vec![]);
        let regs = evidence_measurements(&report);
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].register, "MEASUREMENT");
        assert_eq!(regs[0].value, vec![0x5A; 48]);
    }
}
