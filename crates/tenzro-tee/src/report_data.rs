//! How a verifier's claim is carried inside a vendor attestation.
//!
//! Every attestation format has a field the attester fills with data of its
//! choosing and the hardware then signs: TDX and SEV-SNP `REPORT_DATA` (64
//! bytes), the Nitro document's `user_data`, the nonce of an NVIDIA
//! measurement request. Binding a key, a response or a verifier's challenge
//! to a report means putting a commitment to it in that field, and a verifier
//! recomputes the same packing to compare.

use tenzro_types::tee::{TeeVendor, pack_user_data_for_vendor};

/// Constant-time comparison of a report's user data with the packing a
/// verifier expects. Length is part of the claim.
pub fn user_data_matches(vendor: TeeVendor, packet: &[u8], report_user_data: &[u8]) -> bool {
    let expected = pack_user_data_for_vendor(vendor, packet);
    expected.len() == report_user_data.len()
        && expected
            .iter()
            .zip(report_user_data)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_vendors_get_64_bytes() {
        assert_eq!(
            pack_user_data_for_vendor(TeeVendor::IntelTdx, b"x").len(),
            64
        );
        assert_eq!(
            pack_user_data_for_vendor(TeeVendor::AmdSevSnp, &[0; 200]).len(),
            64
        );
        assert_eq!(
            pack_user_data_for_vendor(TeeVendor::AwsNitro, b"abc"),
            b"abc"
        );
    }

    #[test]
    fn a_different_packet_does_not_match() {
        let data = pack_user_data_for_vendor(TeeVendor::IntelTdx, b"key-a");
        assert!(user_data_matches(TeeVendor::IntelTdx, b"key-a", &data));
        assert!(!user_data_matches(TeeVendor::IntelTdx, b"key-b", &data));
        assert!(!user_data_matches(
            TeeVendor::IntelTdx,
            b"key-a",
            &data[..63]
        ));
    }
}
