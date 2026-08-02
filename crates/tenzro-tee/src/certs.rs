//! Pinned vendor root certificates for TEE attestation verification.
//!
//! This module contains the official root CA certificates for each TEE vendor,
//! embedded as PEM constants. These are used to verify the certificate chains
//! in attestation reports without relying on external certificate stores.
//!
//! # Certificate Sources
//!
//! - **Intel SGX Root CA**: Downloaded from `certificates.trustedservices.intel.com`
//!   - Algorithm: ECDSA P-256 with SHA-256
//!   - Validity: 2018-05-21 to 2049-12-31
//!   - SHA-256 fingerprint: `44:A0:19:6B:2B:99:F8:89:B8:E1:49:E9:5B:80:7A:35:0E:74:24:96:43:99:E8:85:A7:CB:B8:CC:FA:B6:74:D3`
//!
//! - **AMD SEV-SNP ARK (Milan)**: Downloaded from `kdsintf.amd.com/vcek/v1/Milan/cert_chain`
//!   - Algorithm: RSA-4096 with SHA-384 (RSASSA-PSS)
//!   - Validity: 2020-10-22 to 2045-10-22
//!
//! - **AMD SEV-SNP ARK (Genoa)**: Downloaded from `kdsintf.amd.com/vcek/v1/Genoa/cert_chain`
//!   - Algorithm: RSA-4096 with SHA-384 (RSASSA-PSS)
//!   - Validity: 2022-01-26 to 2047-01-26
//!
//! - **AWS Nitro Enclaves Root CA**: Downloaded from `aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`
//!   - Algorithm: ECDSA P-384 with SHA-384
//!   - Validity: 2019-10-28 to 2049-10-28
//!   - SHA-256 fingerprint: `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`
//!
//! - **NVIDIA GPU CC**: NVIDIA does not publish root CA certificates publicly.
//!   Verification is done via the NVIDIA Remote Attestation Service (NRAS) API
//!   at `https://nras.attestation.nvidia.com/v4/attest/gpu`.

use tenzro_types::tee::TeeVendor;

/// Intel SGX/TDX Provisioning Certification Root CA (Production API v3)
///
/// Subject: CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US
/// Issuer: (self-signed)
/// Algorithm: ECDSA P-256 with SHA-256
/// Valid: 2018-05-21 to 2049-12-31
///
/// Source: https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem
pub const INTEL_SGX_ROOT_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\n\
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\n\
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\n\
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\n\
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\n\
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\n\
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n\
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\n\
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\n\
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\n\
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\n\
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\n\
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\n\
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n\
-----END CERTIFICATE-----";

/// SHA-256 fingerprint of the Intel SGX Root CA certificate
pub const INTEL_SGX_ROOT_CA_SHA256_FINGERPRINT: &str = "44:A0:19:6B:2B:99:F8:89:B8:E1:49:E9:5B:80:7A:35:0E:74:24:96:43:99:E8:85:A7:CB:B8:CC:FA:B6:74:D3";

/// AMD SEV-SNP ARK (AMD Root Key) certificate for Milan processors (EPYC 7003, Zen 3)
///
/// Subject: CN=ARK-Milan, O=Advanced Micro Devices, L=Santa Clara, ST=CA, C=US
/// Issuer: (self-signed)
/// Algorithm: RSA-4096 with SHA-384 (RSASSA-PSS)
/// Valid: 2020-10-22 to 2045-10-22
///
/// Source: https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
pub const AMD_ARK_MILAN_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC\n\
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS\n\
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg\n\
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp\n\
Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy\n\
MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS\n\
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j\n\
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG\n\
9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg\n\
W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta\n\
1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2\n\
SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0\n\
60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05\n\
gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg\n\
bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs\n\
+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi\n\
Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ\n\
eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18\n\
fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j\n\
WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI\n\
rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG\n\
KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG\n\
SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI\n\
AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel\n\
ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw\n\
STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK\n\
dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq\n\
zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp\n\
KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e\n\
pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq\n\
HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh\n\
3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn\n\
JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH\n\
CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4\n\
AFZEAwoKCQ==\n\
-----END CERTIFICATE-----";

/// AMD SEV-SNP ASK (AMD Signing Key) certificate for Milan processors
///
/// Subject: CN=SEV-Milan, O=Advanced Micro Devices, L=Santa Clara, ST=CA, C=US
/// Issuer: CN=ARK-Milan
/// Algorithm: RSA-4096 with SHA-384 (RSASSA-PSS)
///
/// Source: https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
pub const AMD_ASK_MILAN_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
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\n\
-----END CERTIFICATE-----";

/// AMD SEV-SNP ARK (AMD Root Key) certificate for Genoa processors (EPYC 9004, Zen 4)
///
/// Subject: CN=ARK-Genoa, O=Advanced Micro Devices, L=Santa Clara, ST=CA, C=US
/// Issuer: (self-signed)
/// Algorithm: RSA-4096 with SHA-384 (RSASSA-PSS)
/// Valid: 2022-01-26 to 2047-01-26
///
/// Source: https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain
pub const AMD_ARK_GENOA_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
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\n\
/wMz1R1BHg==\n\
-----END CERTIFICATE-----";

/// AMD SEV-SNP ASK (AMD Signing Key) certificate for Genoa processors
///
/// Subject: CN=SEV-Genoa, O=Advanced Micro Devices, L=Santa Clara, ST=CA, C=US
/// Issuer: CN=ARK-Genoa
/// Algorithm: RSA-4096 with SHA-384 (RSASSA-PSS)
///
/// Source: https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain
pub const AMD_ASK_GENOA_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
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\n\
-----END CERTIFICATE-----";

/// AWS Nitro Enclaves Root CA (aws.nitro-enclaves)
///
/// Subject: CN=aws.nitro-enclaves, O=Amazon, OU=AWS, C=US
/// Issuer: (self-signed)
/// Algorithm: ECDSA P-384 with SHA-384
/// Valid: 2019-10-28 to 2049-10-28
///
/// Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
pub const AWS_NITRO_ROOT_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL\n\
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD\n\
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4\n\
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL\n\
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG\n\
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb\n\
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE\n\
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF\n\
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC\n\
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW\n\
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N\n\
IwLz3/Y=\n\
-----END CERTIFICATE-----";

/// SHA-256 fingerprint of the AWS Nitro Root CA certificate
pub const AWS_NITRO_ROOT_CA_SHA256_FINGERPRINT: &str = "64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B";

/// NVIDIA Remote Attestation Service (NRAS) API endpoint
///
/// NVIDIA does not publish root CA certificates publicly. Attestation
/// verification is done via their cloud-based NRAS service.
///
/// Reference: https://docs.nvidia.com/attestation/index.html
pub const NVIDIA_NRAS_ENDPOINT: &str = "https://nras.attestation.nvidia.com/v4/attest/gpu";

/// AMD Key Distribution Service (KDS) base URL
///
/// Used to fetch ARK+ASK cert chains and VCEK certificates per-chip.
///
/// Reference: https://www.amd.com/en/developer/sev.html
pub const AMD_KDS_BASE_URL: &str = "https://kdsintf.amd.com";

/// Intel Provisioning Certification Service (PCS) base URL
///
/// Reference: https://api.portal.trustedservices.intel.com/
pub const INTEL_PCS_BASE_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4";

/// Intel SGX Root CA CRL URL
pub const INTEL_SGX_ROOT_CA_CRL_URL: &str =
    "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";

/// Returns the pinned root CA PEM for a given TEE vendor.
///
/// For AMD SEV-SNP, returns the Milan ARK by default. Use
/// [`get_amd_ark_for_product`] for product-specific certificates.
///
/// Returns `None` for vendors that don't have public root CAs (e.g., NVIDIA).
pub fn get_root_ca_pem(vendor: TeeVendor) -> Option<&'static str> {
    match vendor {
        TeeVendor::IntelTdx => Some(INTEL_SGX_ROOT_CA_PEM),
        TeeVendor::AmdSevSnp => Some(AMD_ARK_MILAN_PEM),
        TeeVendor::AwsNitro => Some(AWS_NITRO_ROOT_CA_PEM),
        TeeVendor::NvidiaGpu => None, // Verification via NRAS API
        _ => None,
    }
}

/// Returns the AMD ARK (root) certificate for a given processor family.
///
/// Supported families: "Milan" (EPYC 7003), "Genoa" (EPYC 9004)
pub fn get_amd_ark_for_product(product: &str) -> Option<&'static str> {
    match product {
        "Milan" => Some(AMD_ARK_MILAN_PEM),
        "Genoa" => Some(AMD_ARK_GENOA_PEM),
        _ => None,
    }
}

/// Returns the AMD ASK (intermediate) certificate for a given processor family.
pub fn get_amd_ask_for_product(product: &str) -> Option<&'static str> {
    match product {
        "Milan" => Some(AMD_ASK_MILAN_PEM),
        "Genoa" => Some(AMD_ASK_GENOA_PEM),
        _ => None,
    }
}

/// AMD VCEK Certificate OIDs for TCB version parsing
pub mod amd_oids {
    /// OID prefix for AMD SEV-SNP TCB components: 1.3.6.1.4.1.3704.1
    pub const AMD_SEV_OID_PREFIX: &str = "1.3.6.1.4.1.3704.1";

    /// Bootloader firmware version: 1.3.6.1.4.1.3704.1.3.1
    pub const BOOTLOADER_SVN: &str = "1.3.6.1.4.1.3704.1.3.1";
    /// TEE firmware version: 1.3.6.1.4.1.3704.1.3.2
    pub const TEE_SVN: &str = "1.3.6.1.4.1.3704.1.3.2";
    /// SNP firmware version: 1.3.6.1.4.1.3704.1.3.3
    pub const SNP_SVN: &str = "1.3.6.1.4.1.3704.1.3.3";
    /// CPU microcode version: 1.3.6.1.4.1.3704.1.3.4
    pub const MICROCODE_SVN: &str = "1.3.6.1.4.1.3704.1.3.4";
    /// Hardware ID: 1.3.6.1.4.1.3704.1.4
    pub const HWID: &str = "1.3.6.1.4.1.3704.1.4";
}

/// Intel SGX PCK Certificate OIDs for TCB version parsing
pub mod intel_oids {
    /// OID prefix for Intel SGX extensions: 1.2.840.113741.1.13.1
    pub const SGX_EXTENSIONS_OID: &str = "1.2.840.113741.1.13.1";

    /// Platform Provisioning ID (PPID): 1.2.840.113741.1.13.1.1
    pub const PPID: &str = "1.2.840.113741.1.13.1.1";
    /// TCB structure: 1.2.840.113741.1.13.1.2
    pub const TCB: &str = "1.2.840.113741.1.13.1.2";
    /// PCE Security Version Number: 1.2.840.113741.1.13.1.2.17
    pub const PCESVN: &str = "1.2.840.113741.1.13.1.2.17";
    /// CPU Security Version Number: 1.2.840.113741.1.13.1.2.18
    pub const CPUSVN: &str = "1.2.840.113741.1.13.1.2.18";
    /// PCE-ID: 1.2.840.113741.1.13.1.3
    pub const PCE_ID: &str = "1.2.840.113741.1.13.1.3";
    /// FMSPC (Family-Model-Stepping-Platform-CustomSKU): 1.2.840.113741.1.13.1.4
    pub const FMSPC: &str = "1.2.840.113741.1.13.1.4";
}

/// Decodes a PEM certificate to DER bytes.
///
/// Strips the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`
/// markers and base64-decodes the content.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("");

    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
        .map_err(|e| format!("Failed to decode PEM: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intel_root_ca_pem_decodes() {
        let der = pem_to_der(INTEL_SGX_ROOT_CA_PEM);
        assert!(
            der.is_ok(),
            "Intel SGX Root CA PEM should decode: {:?}",
            der.err()
        );
        let der = der.unwrap();
        // X.509 certificates start with ASN.1 SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30, "DER should start with SEQUENCE tag");
        assert!(
            der.len() > 100,
            "Certificate should be substantial: {} bytes",
            der.len()
        );
    }

    #[test]
    fn test_amd_ark_milan_pem_decodes() {
        let der = pem_to_der(AMD_ARK_MILAN_PEM);
        assert!(
            der.is_ok(),
            "AMD ARK Milan PEM should decode: {:?}",
            der.err()
        );
        let der = der.unwrap();
        assert_eq!(der[0], 0x30);
        assert!(
            der.len() > 500,
            "RSA-4096 cert should be large: {} bytes",
            der.len()
        );
    }

    #[test]
    fn test_amd_ask_milan_pem_decodes() {
        let der = pem_to_der(AMD_ASK_MILAN_PEM);
        assert!(
            der.is_ok(),
            "AMD ASK Milan PEM should decode: {:?}",
            der.err()
        );
    }

    #[test]
    fn test_amd_ark_genoa_pem_decodes() {
        let der = pem_to_der(AMD_ARK_GENOA_PEM);
        assert!(
            der.is_ok(),
            "AMD ARK Genoa PEM should decode: {:?}",
            der.err()
        );
    }

    #[test]
    fn test_amd_ask_genoa_pem_decodes() {
        let der = pem_to_der(AMD_ASK_GENOA_PEM);
        assert!(
            der.is_ok(),
            "AMD ASK Genoa PEM should decode: {:?}",
            der.err()
        );
    }

    #[test]
    fn test_aws_nitro_root_ca_pem_decodes() {
        let der = pem_to_der(AWS_NITRO_ROOT_CA_PEM);
        assert!(
            der.is_ok(),
            "AWS Nitro Root CA PEM should decode: {:?}",
            der.err()
        );
        let der = der.unwrap();
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_get_root_ca_pem() {
        assert!(get_root_ca_pem(TeeVendor::IntelTdx).is_some());
        assert!(get_root_ca_pem(TeeVendor::AmdSevSnp).is_some());
        assert!(get_root_ca_pem(TeeVendor::AwsNitro).is_some());
        assert!(get_root_ca_pem(TeeVendor::NvidiaGpu).is_none());
    }

    #[test]
    fn test_get_amd_ark_for_product() {
        assert!(get_amd_ark_for_product("Milan").is_some());
        assert!(get_amd_ark_for_product("Genoa").is_some());
        assert!(get_amd_ark_for_product("Unknown").is_none());
    }

    #[test]
    fn test_aws_nitro_fingerprint() {
        let der = pem_to_der(AWS_NITRO_ROOT_CA_PEM).unwrap();
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&der);
        let fingerprint = hash
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(":");
        assert_eq!(
            fingerprint, AWS_NITRO_ROOT_CA_SHA256_FINGERPRINT,
            "AWS Nitro Root CA fingerprint mismatch"
        );
    }

    #[test]
    fn test_intel_sgx_fingerprint() {
        let der = pem_to_der(INTEL_SGX_ROOT_CA_PEM).unwrap();
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&der);
        let fingerprint = hash
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(":");
        assert_eq!(
            fingerprint, INTEL_SGX_ROOT_CA_SHA256_FINGERPRINT,
            "Intel SGX Root CA fingerprint mismatch"
        );
    }
}
