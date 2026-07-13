//! Travel Rule data envelope per IVMS101.
//!
//! IVMS101 = "InterVASP Messaging Standard 101", the canonical FATF
//! Travel Rule data schema every VASP/CASP protocol carries. EEA/UK
//! CASP infrastructure standardises on TRP (Travel Rule Protocol) as
//! the open HTTPS envelope; the wire payload inside that envelope is
//! IVMS101. MiCA-regulated venues require an IVMS101 transfer-data
//! payload bound to every >€1000 transfer (lower thresholds in some
//! jurisdictions).
//!
//! # Scope of this module
//!
//! Tenzro is the L1 — we expose the IVMS101 envelope as a typed
//! payload binding payments/settlements to originator/beneficiary
//! identity records. The actual VASP-to-VASP TRP wire transport is
//! the next layer up (handled by integration partners or by the
//! tenzro-payments HTTP middleware in a follow-up).
//!
//! Our job here:
//! 1. Provide the canonical Rust types matching the IVMS101 v1.1.0
//!    JSON schema (the live FATF version as of 2024).
//! 2. Bind an `Ivms101Envelope` to a Tenzro receipt envelope so audit
//!    can trace `tenzro_payments::receipt -> ivms101 originator+benef
//!    -> originating VASP DID -> KYC tier`.
//! 3. Surface CAIP-10 wallet identifiers natively (the wire shape
//!    Tenzro consumes) alongside the legal-entity identifiers the
//!    Travel Rule itself names.
//!
//! # Compliance posture
//!
//! IVMS101 fields use the exact wire labels from the standard so
//! external compliance tooling can ingest the JSON form without
//! Tenzro-specific transforms. We use `serde(rename = "camelCase")`
//! at the top level to match the FATF JSON spec; nested types follow
//! the same convention.

use serde::{Deserialize, Serialize};

/// IVMS101 Travel Rule envelope.
///
/// `originator` = the natural/legal person initiating the transfer.
/// `beneficiary` = the natural/legal person receiving it.
/// `transfer` = the transaction data binding the two.
///
/// The envelope is intended to be carried alongside the on-chain
/// transaction (typically via TRP). Tenzro attaches it to receipts
/// via [`Ivms101Binding`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101Envelope {
    /// IVMS101 specification version. Hard-coded "101.2023" (the
    /// version pinned by FATF guidance as of 2024).
    pub spec_version: String,
    pub originator: Ivms101Originator,
    pub beneficiary: Ivms101Beneficiary,
    pub originating_vasp: Ivms101Vasp,
    pub beneficiary_vasp: Ivms101Vasp,
    pub transfer: Ivms101TransferData,
}

impl Ivms101Envelope {
    pub const CURRENT_SPEC_VERSION: &'static str = "101.2023";

    pub fn new(
        originator: Ivms101Originator,
        beneficiary: Ivms101Beneficiary,
        originating_vasp: Ivms101Vasp,
        beneficiary_vasp: Ivms101Vasp,
        transfer: Ivms101TransferData,
    ) -> Self {
        Self {
            spec_version: Self::CURRENT_SPEC_VERSION.to_string(),
            originator,
            beneficiary,
            originating_vasp,
            beneficiary_vasp,
            transfer,
        }
    }

    /// Canonical-bytes hash used to bind this envelope to a payment
    /// receipt. SHA-256 over the canonical JSON form (sorted keys,
    /// no whitespace). The relying party recomputes and verifies.
    pub fn canonical_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let json = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        let canonical = canonical_json(&json);
        let mut h = Sha256::new();
        h.update(b"tenzro/ivms101/v1");
        h.update(canonical.as_bytes());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }
}

/// Natural-person initiator. See IVMS101 §5.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101Originator {
    pub originator_persons: Vec<Ivms101Person>,
    /// CAIP-10 wallet identifier(s) (e.g. `eip155:1:0xabc…`) or
    /// chain-native account-id strings. Tenzro's preferred form.
    pub account_number: Vec<String>,
}

/// Natural-person beneficiary. See IVMS101 §5.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101Beneficiary {
    pub beneficiary_persons: Vec<Ivms101Person>,
    pub account_number: Vec<String>,
}

/// Natural or legal person record per IVMS101.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101Person {
    pub natural_person: Option<Ivms101NaturalPerson>,
    pub legal_person: Option<Ivms101LegalPerson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101NaturalPerson {
    pub name: Ivms101NaturalPersonName,
    pub geographic_address: Vec<Ivms101Address>,
    pub national_identification: Option<Ivms101NationalIdentification>,
    pub customer_identification: Option<String>,
    pub date_and_place_of_birth: Option<Ivms101DateAndPlaceOfBirth>,
    pub country_of_residence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101LegalPerson {
    pub name: Ivms101LegalPersonName,
    pub geographic_address: Vec<Ivms101Address>,
    pub customer_number: Option<String>,
    pub national_identification: Option<Ivms101NationalIdentification>,
    pub country_of_registration: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101NaturalPersonName {
    pub primary_identifier: String,
    pub secondary_identifier: Option<String>,
    /// Latin / Cyrillic / etc. — ISO 15924 four-letter script code.
    pub name_identifier_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101LegalPersonName {
    pub legal_person_name: String,
    pub legal_person_name_identifier_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101Address {
    pub address_type: String,
    pub street_name: Option<String>,
    pub building_number: Option<String>,
    pub post_code: Option<String>,
    pub town_name: Option<String>,
    pub country_sub_division: Option<String>,
    pub country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101NationalIdentification {
    pub national_identifier: String,
    pub national_identifier_type: String,
    pub country_of_issue: Option<String>,
    pub registration_authority: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101DateAndPlaceOfBirth {
    pub date_of_birth: String,
    pub place_of_birth: String,
}

/// Originating or beneficiary VASP record. The legal entity that
/// custodies the originator/beneficiary funds, identified by LEI
/// where available, and a country code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101Vasp {
    pub legal_name: String,
    pub lei: Option<String>,
    pub country: String,
    pub tenzro_did: Option<String>,
}

/// Transfer record binding origin + beneficiary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ivms101TransferData {
    /// CAIP-19 token identifier (e.g. `eip155:1/erc20:0x...`) OR
    /// the native asset string (`TNZO`, `USDC`, …).
    pub asset_caip19: String,
    /// Decimal-string amount in the token's smallest unit.
    pub amount_smallest_unit: String,
    /// ISO 8601 timestamp.
    pub timestamp_iso8601: String,
    /// On-chain transaction hash (hex).
    pub transaction_hash_hex: String,
    /// Bound ISO 20022 message identifier (`GrpHdr.MsgId` of the
    /// pacs.008 built by [`crate::iso20022::Pacs008Document`]) if the
    /// transfer was initiated through a SWIFT-class message.
    pub iso20022_message_id: Option<String>,
}

/// Binding between a Tenzro payment/settlement receipt and an
/// IVMS101 envelope. The envelope itself is stored off-chain (the
/// receipt records only the canonical hash); the binding lets
/// auditors retrieve the full envelope from the issuing VASP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ivms101Binding {
    pub envelope_hash: [u8; 32],
    pub originating_vasp_did: String,
    pub beneficiary_vasp_did: Option<String>,
    pub asset_caip19: String,
    pub amount_smallest_unit: String,
    /// HTTPS URL (typically TRP-compliant) where the originating VASP
    /// serves the full envelope to authenticated peers. Optional —
    /// some flows carry the envelope inline via the off-chain channel.
    pub envelope_url: Option<String>,
}

/// Canonical JSON serialization for hash stability.
fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> Ivms101Envelope {
        Ivms101Envelope::new(
            Ivms101Originator {
                originator_persons: vec![Ivms101Person {
                    natural_person: Some(Ivms101NaturalPerson {
                        name: Ivms101NaturalPersonName {
                            primary_identifier: "Doe".into(),
                            secondary_identifier: Some("Jane".into()),
                            name_identifier_type: "LEGL".into(),
                        },
                        geographic_address: vec![],
                        national_identification: None,
                        customer_identification: Some("did:tn:human:abc".into()),
                        date_and_place_of_birth: None,
                        country_of_residence: Some("US".into()),
                    }),
                    legal_person: None,
                }],
                account_number: vec!["eip155:1:0xabc".into()],
            },
            Ivms101Beneficiary {
                beneficiary_persons: vec![Ivms101Person {
                    natural_person: Some(Ivms101NaturalPerson {
                        name: Ivms101NaturalPersonName {
                            primary_identifier: "Smith".into(),
                            secondary_identifier: Some("John".into()),
                            name_identifier_type: "LEGL".into(),
                        },
                        geographic_address: vec![],
                        national_identification: None,
                        customer_identification: Some("did:tn:human:xyz".into()),
                        date_and_place_of_birth: None,
                        country_of_residence: Some("US".into()),
                    }),
                    legal_person: None,
                }],
                account_number: vec!["eip155:1:0xdef".into()],
            },
            Ivms101Vasp {
                legal_name: "Example VASP A".into(),
                lei: Some("353800GDOIZJBCHQH482".into()),
                country: "US".into(),
                tenzro_did: Some("did:tn:vasp:a".into()),
            },
            Ivms101Vasp {
                legal_name: "Example VASP B".into(),
                lei: Some("549300LGDDJKR6SQYJ86".into()),
                country: "DE".into(),
                tenzro_did: Some("did:tn:vasp:b".into()),
            },
            Ivms101TransferData {
                asset_caip19: "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
                amount_smallest_unit: "1500000000".into(),
                timestamp_iso8601: "2026-06-09T12:00:00Z".into(),
                transaction_hash_hex: "deadbeef".into(),
                iso20022_message_id: None,
            },
        )
    }

    #[test]
    fn envelope_round_trips() {
        let env = sample_envelope();
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Ivms101Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.spec_version, Ivms101Envelope::CURRENT_SPEC_VERSION);
        assert_eq!(parsed.originating_vasp.country, "US");
        assert_eq!(parsed.beneficiary_vasp.country, "DE");
    }

    #[test]
    fn canonical_hash_is_deterministic() {
        let env1 = sample_envelope();
        let env2 = sample_envelope();
        assert_eq!(env1.canonical_hash(), env2.canonical_hash());
    }

    #[test]
    fn canonical_hash_changes_on_amount_change() {
        let env1 = sample_envelope();
        let mut env2 = sample_envelope();
        env2.transfer.amount_smallest_unit = "9999".into();
        assert_ne!(env1.canonical_hash(), env2.canonical_hash());
    }

    #[test]
    fn binding_serializes_envelope_hash_as_byte_array() {
        let env = sample_envelope();
        let b = Ivms101Binding {
            envelope_hash: env.canonical_hash(),
            originating_vasp_did: "did:tn:vasp:a".into(),
            beneficiary_vasp_did: Some("did:tn:vasp:b".into()),
            asset_caip19: env.transfer.asset_caip19.clone(),
            amount_smallest_unit: env.transfer.amount_smallest_unit.clone(),
            envelope_url: Some("https://vasp-a.example/trp/envelope/123".into()),
        };
        let json = serde_json::to_string(&b).unwrap();
        let parsed: Ivms101Binding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.envelope_hash, env.canonical_hash());
    }
}
