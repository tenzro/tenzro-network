//! ISO 20022 pacs.008 (FIToFICustomerCreditTransfer) codec.
//!
//! Typed model for pacs.008.001.08 — the widely-deployed version of
//! the interbank customer credit transfer message — with XML
//! serialization/parsing via quick-xml and a bidirectional mapping to
//! the IVMS101 Travel Rule envelope in [`crate::ivms101`].
//!
//! The model covers the subset of the XSD that binds a SWIFT-class
//! instruction to a Tenzro settlement: group header, payment
//! identification (including UETR), interbank settlement amount,
//! debtor/creditor parties with postal addresses and accounts, and
//! agent BICs. Amounts are decimal strings — never floats.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ivms101::{
    Ivms101Address, Ivms101Beneficiary, Ivms101Envelope, Ivms101NaturalPerson,
    Ivms101NaturalPersonName, Ivms101Originator, Ivms101Person, Ivms101TransferData,
};

/// XML namespace for pacs.008.001.08.
pub const PACS008_NAMESPACE: &str = "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08";

/// ISO 20022 ChargeBearerType1Code values.
const CHARGE_BEARER_CODES: [&str; 4] = ["DEBT", "CRED", "SHAR", "SLEV"];

#[derive(Debug, Error)]
pub enum Iso20022Error {
    #[error("xml serialization failed: {0}")]
    Serialize(String),
    #[error("xml parse failed: {0}")]
    Parse(String),
    #[error("unexpected namespace `{found}`, expected `{expected}`")]
    Namespace { expected: &'static str, found: String },
    #[error("missing or empty mandatory field: {0}")]
    MissingField(&'static str),
    #[error("field {field} exceeds {max} characters")]
    FieldTooLong { field: &'static str, max: usize },
    #[error("invalid amount `{amount}`: {reason}")]
    InvalidAmount { amount: String, reason: &'static str },
    #[error("invalid currency code `{0}` (expected 3 uppercase ASCII letters)")]
    InvalidCurrency(String),
    #[error("invalid charge bearer `{0}` (expected DEBT|CRED|SHAR|SLEV)")]
    InvalidChargeBearer(String),
    #[error("NbOfTxs `{declared}` does not match transaction count {actual}")]
    TransactionCountMismatch { declared: String, actual: usize },
    #[error("account identification must carry exactly one of IBAN or Othr")]
    AmbiguousAccountId,
    #[error("ivms101 mapping failed: {0}")]
    Mapping(String),
}

/// Interbank settlement amount value. Decimal string per ISO
/// `ActiveCurrencyAndAmount`: digits with an optional single decimal
/// point, at most 5 fraction digits, at most 18 total digits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DecimalAmount {
    pub units: String,
}

impl DecimalAmount {
    pub fn new(units: impl Into<String>) -> Result<Self, Iso20022Error> {
        let units = units.into();
        Self::validate_str(&units)?;
        Ok(Self { units })
    }

    fn validate_str(s: &str) -> Result<(), Iso20022Error> {
        let err = |reason: &'static str| Iso20022Error::InvalidAmount {
            amount: s.to_string(),
            reason,
        };
        if s.is_empty() {
            return Err(err("empty"));
        }
        let mut dot_seen = false;
        let mut int_digits = 0usize;
        let mut frac_digits = 0usize;
        for c in s.chars() {
            match c {
                '0'..='9' => {
                    if dot_seen {
                        frac_digits += 1;
                    } else {
                        int_digits += 1;
                    }
                }
                '.' => {
                    if dot_seen {
                        return Err(err("more than one decimal point"));
                    }
                    dot_seen = true;
                }
                _ => return Err(err("non-digit character")),
            }
        }
        if int_digits == 0 {
            return Err(err("no digits before decimal point"));
        }
        if dot_seen && frac_digits == 0 {
            return Err(err("decimal point with no fraction digits"));
        }
        if frac_digits > 5 {
            return Err(err("more than 5 fraction digits"));
        }
        if int_digits + frac_digits > 18 {
            return Err(err("more than 18 total digits"));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), Iso20022Error> {
        Self::validate_str(&self.units)
    }
}

/// `<Document>` root of a pacs.008.001.08 message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "Document")]
pub struct Pacs008Document {
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "FIToFICstmrCdtTrf")]
    pub fi_to_fi_customer_credit_transfer: FiToFiCustomerCreditTransfer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiToFiCustomerCreditTransfer {
    #[serde(rename = "GrpHdr")]
    pub group_header: GroupHeader,
    #[serde(rename = "CdtTrfTxInf")]
    pub credit_transfer_transactions: Vec<CreditTransferTransaction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupHeader {
    #[serde(rename = "MsgId")]
    pub message_id: String,
    /// ISO 8601 creation timestamp.
    #[serde(rename = "CreDtTm")]
    pub creation_date_time: String,
    #[serde(rename = "NbOfTxs")]
    pub number_of_transactions: String,
    #[serde(rename = "SttlmInf")]
    pub settlement_information: SettlementInformation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementInformation {
    /// SettlementMethod1Code: INDA, INGA, COVE, CLRG.
    #[serde(rename = "SttlmMtd")]
    pub settlement_method: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditTransferTransaction {
    #[serde(rename = "PmtId")]
    pub payment_identification: PaymentIdentification,
    #[serde(rename = "IntrBkSttlmAmt")]
    pub interbank_settlement_amount: ActiveCurrencyAmount,
    #[serde(rename = "ChrgBr")]
    pub charge_bearer: String,
    #[serde(rename = "Dbtr")]
    pub debtor: PartyIdentification,
    #[serde(rename = "DbtrAcct", skip_serializing_if = "Option::is_none")]
    pub debtor_account: Option<CashAccount>,
    #[serde(rename = "DbtrAgt")]
    pub debtor_agent: FinancialInstitution,
    #[serde(rename = "CdtrAgt")]
    pub creditor_agent: FinancialInstitution,
    #[serde(rename = "Cdtr")]
    pub creditor: PartyIdentification,
    #[serde(rename = "CdtrAcct", skip_serializing_if = "Option::is_none")]
    pub creditor_account: Option<CashAccount>,
    #[serde(rename = "RmtInf", skip_serializing_if = "Option::is_none")]
    pub remittance_information: Option<RemittanceInformation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentIdentification {
    #[serde(rename = "InstrId", skip_serializing_if = "Option::is_none")]
    pub instruction_id: Option<String>,
    /// ISO element name `EndToEndId` — the originator-assigned
    /// identifier carried unchanged along the whole payment chain.
    #[serde(rename = "EndToEndId")]
    pub end_to_end_id: String,
    /// SWIFT gpi Unique End-to-end Transaction Reference (UUID v4).
    #[serde(rename = "UETR", skip_serializing_if = "Option::is_none")]
    pub uetr: Option<String>,
}

/// `<IntrBkSttlmAmt Ccy="EUR">1500.00</IntrBkSttlmAmt>`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveCurrencyAmount {
    #[serde(rename = "@Ccy")]
    pub currency: String,
    #[serde(rename = "$text")]
    pub value: DecimalAmount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyIdentification {
    #[serde(rename = "Nm")]
    pub name: String,
    #[serde(rename = "PstlAdr", skip_serializing_if = "Option::is_none")]
    pub postal_address: Option<PostalAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostalAddress {
    #[serde(rename = "StrtNm", skip_serializing_if = "Option::is_none")]
    pub street_name: Option<String>,
    #[serde(rename = "BldgNb", skip_serializing_if = "Option::is_none")]
    pub building_number: Option<String>,
    #[serde(rename = "PstCd", skip_serializing_if = "Option::is_none")]
    pub post_code: Option<String>,
    #[serde(rename = "TwnNm", skip_serializing_if = "Option::is_none")]
    pub town_name: Option<String>,
    #[serde(rename = "CtrySubDvsn", skip_serializing_if = "Option::is_none")]
    pub country_sub_division: Option<String>,
    #[serde(rename = "Ctry", skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashAccount {
    #[serde(rename = "Id")]
    pub id: AccountIdentification,
}

/// ISO choice: exactly one of IBAN or Othr.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountIdentification {
    #[serde(rename = "IBAN", skip_serializing_if = "Option::is_none")]
    pub iban: Option<String>,
    #[serde(rename = "Othr", skip_serializing_if = "Option::is_none")]
    pub other: Option<GenericAccountIdentification>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericAccountIdentification {
    #[serde(rename = "Id")]
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinancialInstitution {
    #[serde(rename = "FinInstnId")]
    pub financial_institution_id: FinancialInstitutionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinancialInstitutionId {
    #[serde(rename = "BICFI", skip_serializing_if = "Option::is_none")]
    pub bicfi: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemittanceInformation {
    #[serde(rename = "Ustrd", skip_serializing_if = "Vec::is_empty", default)]
    pub unstructured: Vec<String>,
}

/// Settlement-rail parameters not carried by the IVMS101 envelope,
/// supplied by the caller when building a pacs.008 from Travel Rule
/// data. Currency + amount are the fiat interbank leg (the IVMS
/// envelope carries the crypto-asset smallest-unit amount instead).
#[derive(Debug, Clone)]
pub struct TransferDetails {
    pub message_id: String,
    /// ISO 8601 creation timestamp.
    pub creation_date_time: String,
    pub end_to_end_id: String,
    pub instruction_id: Option<String>,
    pub uetr: Option<String>,
    /// SettlementMethod1Code: INDA, INGA, COVE, CLRG.
    pub settlement_method: String,
    /// ChargeBearerType1Code: DEBT, CRED, SHAR, SLEV.
    pub charge_bearer: String,
    /// ISO 4217 currency code.
    pub currency: String,
    pub amount: DecimalAmount,
    pub debtor_agent_bic: Option<String>,
    pub creditor_agent_bic: Option<String>,
    pub remittance: Option<String>,
}

/// Result of mapping a pacs.008 back into IVMS101 records. The
/// VASP records and the on-chain transaction hash are not derivable
/// from the ISO message: the caller assembles the full
/// [`Ivms101Envelope`] and fills `transaction_hash_hex` after the
/// on-chain settlement executes.
#[derive(Debug, Clone)]
pub struct Ivms101Mapping {
    pub originator: Ivms101Originator,
    pub beneficiary: Ivms101Beneficiary,
    pub transfer: Ivms101TransferData,
}

impl Pacs008Document {
    /// Serialize to pacs.008.001.08 XML. Validates before writing.
    pub fn to_xml(&self) -> Result<String, Iso20022Error> {
        self.validate()?;
        let body = quick_xml::se::to_string(self)
            .map_err(|e| Iso20022Error::Serialize(e.to_string()))?;
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{body}"))
    }

    /// Parse pacs.008.001.08 XML. Fails closed on wrong namespace,
    /// missing mandatory elements, and invalid amounts.
    pub fn from_xml(xml: &str) -> Result<Self, Iso20022Error> {
        let doc: Self =
            quick_xml::de::from_str(xml).map_err(|e| Iso20022Error::Parse(e.to_string()))?;
        if doc.xmlns != PACS008_NAMESPACE {
            return Err(Iso20022Error::Namespace {
                expected: PACS008_NAMESPACE,
                found: doc.xmlns,
            });
        }
        doc.validate()?;
        Ok(doc)
    }

    pub fn validate(&self) -> Result<(), Iso20022Error> {
        let cct = &self.fi_to_fi_customer_credit_transfer;
        let hdr = &cct.group_header;
        require(&hdr.message_id, "GrpHdr.MsgId")?;
        if hdr.message_id.len() > 35 {
            return Err(Iso20022Error::FieldTooLong {
                field: "GrpHdr.MsgId",
                max: 35,
            });
        }
        require(&hdr.creation_date_time, "GrpHdr.CreDtTm")?;
        require(
            &hdr.settlement_information.settlement_method,
            "GrpHdr.SttlmInf.SttlmMtd",
        )?;
        if cct.credit_transfer_transactions.is_empty() {
            return Err(Iso20022Error::MissingField("CdtTrfTxInf"));
        }
        let declared: usize = hdr.number_of_transactions.parse().map_err(|_| {
            Iso20022Error::TransactionCountMismatch {
                declared: hdr.number_of_transactions.clone(),
                actual: cct.credit_transfer_transactions.len(),
            }
        })?;
        if declared != cct.credit_transfer_transactions.len() {
            return Err(Iso20022Error::TransactionCountMismatch {
                declared: hdr.number_of_transactions.clone(),
                actual: cct.credit_transfer_transactions.len(),
            });
        }
        for tx in &cct.credit_transfer_transactions {
            require(
                &tx.payment_identification.end_to_end_id,
                "CdtTrfTxInf.PmtId.EndToEndId",
            )?;
            if tx.payment_identification.end_to_end_id.len() > 35 {
                return Err(Iso20022Error::FieldTooLong {
                    field: "CdtTrfTxInf.PmtId.EndToEndId",
                    max: 35,
                });
            }
            tx.interbank_settlement_amount.value.validate()?;
            validate_currency(&tx.interbank_settlement_amount.currency)?;
            if !CHARGE_BEARER_CODES.contains(&tx.charge_bearer.as_str()) {
                return Err(Iso20022Error::InvalidChargeBearer(tx.charge_bearer.clone()));
            }
            require(&tx.debtor.name, "CdtTrfTxInf.Dbtr.Nm")?;
            require(&tx.creditor.name, "CdtTrfTxInf.Cdtr.Nm")?;
            for acct in [&tx.debtor_account, &tx.creditor_account].into_iter().flatten() {
                if acct.id.iban.is_some() == acct.id.other.is_some() {
                    return Err(Iso20022Error::AmbiguousAccountId);
                }
            }
        }
        Ok(())
    }

    /// Build a pacs.008 from an IVMS101 Travel Rule envelope plus the
    /// settlement-rail parameters. Originator maps to Dbtr, beneficiary
    /// to Cdtr. Fails closed if the envelope already carries a bound
    /// ISO message id that differs from `details.message_id`.
    pub fn from_ivms101(
        envelope: &Ivms101Envelope,
        details: TransferDetails,
    ) -> Result<Self, Iso20022Error> {
        if let Some(bound) = &envelope.transfer.iso20022_message_id
            && bound != &details.message_id
        {
            return Err(Iso20022Error::Mapping(format!(
                "envelope already bound to ISO message id `{bound}`, got `{}`",
                details.message_id
            )));
        }
        let originator_person = envelope
            .originator
            .originator_persons
            .first()
            .ok_or_else(|| Iso20022Error::Mapping("envelope has no originator person".into()))?;
        let beneficiary_person = envelope
            .beneficiary
            .beneficiary_persons
            .first()
            .ok_or_else(|| Iso20022Error::Mapping("envelope has no beneficiary person".into()))?;

        let doc = Self {
            xmlns: PACS008_NAMESPACE.to_string(),
            fi_to_fi_customer_credit_transfer: FiToFiCustomerCreditTransfer {
                group_header: GroupHeader {
                    message_id: details.message_id,
                    creation_date_time: details.creation_date_time,
                    number_of_transactions: "1".to_string(),
                    settlement_information: SettlementInformation {
                        settlement_method: details.settlement_method,
                    },
                },
                credit_transfer_transactions: vec![CreditTransferTransaction {
                    payment_identification: PaymentIdentification {
                        instruction_id: details.instruction_id,
                        end_to_end_id: details.end_to_end_id,
                        uetr: details.uetr,
                    },
                    interbank_settlement_amount: ActiveCurrencyAmount {
                        currency: details.currency,
                        value: details.amount,
                    },
                    charge_bearer: details.charge_bearer,
                    debtor: party_from_person(originator_person)?,
                    debtor_account: account_from_numbers(&envelope.originator.account_number),
                    debtor_agent: FinancialInstitution {
                        financial_institution_id: FinancialInstitutionId {
                            bicfi: details.debtor_agent_bic,
                        },
                    },
                    creditor_agent: FinancialInstitution {
                        financial_institution_id: FinancialInstitutionId {
                            bicfi: details.creditor_agent_bic,
                        },
                    },
                    creditor: party_from_person(beneficiary_person)?,
                    creditor_account: account_from_numbers(&envelope.beneficiary.account_number),
                    remittance_information: details.remittance.map(|r| RemittanceInformation {
                        unstructured: vec![r],
                    }),
                }],
            },
        };
        doc.validate()?;
        Ok(doc)
    }

    /// Map back into IVMS101 records. Dbtr maps to originator, Cdtr to
    /// beneficiary. The transfer record carries the ISO currency code
    /// as the asset identifier and the interbank decimal amount; the
    /// on-chain transaction hash is left empty for the caller to fill
    /// after settlement.
    pub fn to_ivms101(&self) -> Result<Ivms101Mapping, Iso20022Error> {
        self.validate()?;
        let cct = &self.fi_to_fi_customer_credit_transfer;
        let tx = cct
            .credit_transfer_transactions
            .first()
            .ok_or(Iso20022Error::MissingField("CdtTrfTxInf"))?;

        Ok(Ivms101Mapping {
            originator: Ivms101Originator {
                originator_persons: vec![person_from_party(&tx.debtor)],
                account_number: account_numbers(&tx.debtor_account),
            },
            beneficiary: Ivms101Beneficiary {
                beneficiary_persons: vec![person_from_party(&tx.creditor)],
                account_number: account_numbers(&tx.creditor_account),
            },
            transfer: Ivms101TransferData {
                asset_caip19: tx.interbank_settlement_amount.currency.clone(),
                amount_smallest_unit: tx.interbank_settlement_amount.value.units.clone(),
                timestamp_iso8601: cct.group_header.creation_date_time.clone(),
                transaction_hash_hex: String::new(),
                iso20022_message_id: Some(cct.group_header.message_id.clone()),
            },
        })
    }
}

fn require(value: &str, field: &'static str) -> Result<(), Iso20022Error> {
    if value.trim().is_empty() {
        return Err(Iso20022Error::MissingField(field));
    }
    Ok(())
}

fn validate_currency(ccy: &str) -> Result<(), Iso20022Error> {
    if ccy.len() != 3 || !ccy.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(Iso20022Error::InvalidCurrency(ccy.to_string()));
    }
    Ok(())
}

fn is_iban_like(s: &str) -> bool {
    let b = s.as_bytes();
    (15..=34).contains(&b.len())
        && b[0].is_ascii_uppercase()
        && b[1].is_ascii_uppercase()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[4..].iter().all(|c| c.is_ascii_alphanumeric())
}

fn party_from_person(person: &Ivms101Person) -> Result<PartyIdentification, Iso20022Error> {
    let (name, address) = if let Some(np) = &person.natural_person {
        let name = match &np.name.secondary_identifier {
            Some(s) if !s.is_empty() => format!("{s} {}", np.name.primary_identifier),
            _ => np.name.primary_identifier.clone(),
        };
        (name, np.geographic_address.first())
    } else if let Some(lp) = &person.legal_person {
        (lp.name.legal_person_name.clone(), lp.geographic_address.first())
    } else {
        return Err(Iso20022Error::Mapping(
            "person record has neither naturalPerson nor legalPerson".into(),
        ));
    };
    Ok(PartyIdentification {
        name,
        postal_address: address.map(|a| PostalAddress {
            street_name: a.street_name.clone(),
            building_number: a.building_number.clone(),
            post_code: a.post_code.clone(),
            town_name: a.town_name.clone(),
            country_sub_division: a.country_sub_division.clone(),
            country: Some(a.country.clone()),
        }),
    })
}

fn person_from_party(party: &PartyIdentification) -> Ivms101Person {
    let geographic_address = party
        .postal_address
        .as_ref()
        .and_then(|a| {
            a.country.as_ref().map(|country| Ivms101Address {
                address_type: "GEOG".to_string(),
                street_name: a.street_name.clone(),
                building_number: a.building_number.clone(),
                post_code: a.post_code.clone(),
                town_name: a.town_name.clone(),
                country_sub_division: a.country_sub_division.clone(),
                country: country.clone(),
            })
        })
        .into_iter()
        .collect();
    Ivms101Person {
        natural_person: Some(Ivms101NaturalPerson {
            name: Ivms101NaturalPersonName {
                primary_identifier: party.name.clone(),
                secondary_identifier: None,
                name_identifier_type: "LEGL".to_string(),
            },
            geographic_address,
            national_identification: None,
            customer_identification: None,
            date_and_place_of_birth: None,
            country_of_residence: party
                .postal_address
                .as_ref()
                .and_then(|a| a.country.clone()),
        }),
        legal_person: None,
    }
}

fn account_from_numbers(numbers: &[String]) -> Option<CashAccount> {
    let first = numbers.first()?;
    let id = if is_iban_like(first) {
        AccountIdentification {
            iban: Some(first.clone()),
            other: None,
        }
    } else {
        AccountIdentification {
            iban: None,
            other: Some(GenericAccountIdentification { id: first.clone() }),
        }
    };
    Some(CashAccount { id })
}

fn account_numbers(account: &Option<CashAccount>) -> Vec<String> {
    account
        .as_ref()
        .and_then(|a| {
            a.id.iban
                .clone()
                .or_else(|| a.id.other.as_ref().map(|o| o.id.clone()))
        })
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ivms101::Ivms101Vasp;

    fn sample_details() -> TransferDetails {
        TransferDetails {
            message_id: "MSG-2026-07-12-0001".into(),
            creation_date_time: "2026-07-12T09:00:00Z".into(),
            end_to_end_id: "E2E-0001".into(),
            instruction_id: Some("INSTR-0001".into()),
            uetr: Some("eb6305c9-1f7f-49de-aed0-16487c27b42d".into()),
            settlement_method: "CLRG".into(),
            charge_bearer: "SLEV".into(),
            currency: "EUR".into(),
            amount: DecimalAmount::new("1500.00").unwrap(),
            debtor_agent_bic: Some("DEUTDEFF".into()),
            creditor_agent_bic: Some("BNPAFRPP".into()),
            remittance: Some("Invoice 42".into()),
        }
    }

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
                        geographic_address: vec![Ivms101Address {
                            address_type: "GEOG".into(),
                            street_name: Some("Unter den Linden".into()),
                            building_number: Some("1".into()),
                            post_code: Some("10117".into()),
                            town_name: Some("Berlin".into()),
                            country_sub_division: None,
                            country: "DE".into(),
                        }],
                        national_identification: None,
                        customer_identification: Some("did:tn:human:abc".into()),
                        date_and_place_of_birth: None,
                        country_of_residence: Some("DE".into()),
                    }),
                    legal_person: None,
                }],
                account_number: vec!["DE89370400440532013000".into()],
            },
            Ivms101Beneficiary {
                beneficiary_persons: vec![Ivms101Person {
                    natural_person: Some(Ivms101NaturalPerson {
                        name: Ivms101NaturalPersonName {
                            primary_identifier: "Smith".into(),
                            secondary_identifier: None,
                            name_identifier_type: "LEGL".into(),
                        },
                        geographic_address: vec![],
                        national_identification: None,
                        customer_identification: None,
                        date_and_place_of_birth: None,
                        country_of_residence: Some("FR".into()),
                    }),
                    legal_person: None,
                }],
                account_number: vec!["eip155:1:0xdef".into()],
            },
            Ivms101Vasp {
                legal_name: "Example VASP A".into(),
                lei: None,
                country: "DE".into(),
                tenzro_did: Some("did:tn:vasp:a".into()),
            },
            Ivms101Vasp {
                legal_name: "Example VASP B".into(),
                lei: None,
                country: "FR".into(),
                tenzro_did: Some("did:tn:vasp:b".into()),
            },
            Ivms101TransferData {
                asset_caip19: "EUR".into(),
                amount_smallest_unit: "150000".into(),
                timestamp_iso8601: "2026-07-12T09:00:00Z".into(),
                transaction_hash_hex: "deadbeef".into(),
                iso20022_message_id: None,
            },
        )
    }

    const SAMPLE_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Document xmlns=\"urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08\">\
<FIToFICstmrCdtTrf>\
<GrpHdr>\
<MsgId>MSG-1</MsgId>\
<CreDtTm>2026-07-12T09:00:00Z</CreDtTm>\
<NbOfTxs>1</NbOfTxs>\
<SttlmInf><SttlmMtd>CLRG</SttlmMtd></SttlmInf>\
</GrpHdr>\
<CdtTrfTxInf>\
<PmtId>\
<InstrId>INSTR-1</InstrId>\
<EndToEndId>E2E-1</EndToEndId>\
<UETR>eb6305c9-1f7f-49de-aed0-16487c27b42d</UETR>\
</PmtId>\
<IntrBkSttlmAmt Ccy=\"EUR\">1500.00</IntrBkSttlmAmt>\
<ChrgBr>SLEV</ChrgBr>\
<Dbtr><Nm>Jane Doe</Nm><PstlAdr><TwnNm>Berlin</TwnNm><Ctry>DE</Ctry></PstlAdr></Dbtr>\
<DbtrAcct><Id><IBAN>DE89370400440532013000</IBAN></Id></DbtrAcct>\
<DbtrAgt><FinInstnId><BICFI>DEUTDEFF</BICFI></FinInstnId></DbtrAgt>\
<CdtrAgt><FinInstnId><BICFI>BNPAFRPP</BICFI></FinInstnId></CdtrAgt>\
<Cdtr><Nm>John Smith</Nm></Cdtr>\
<CdtrAcct><Id><Othr><Id>eip155:1:0xdef</Id></Othr></Id></CdtrAcct>\
<RmtInf><Ustrd>Invoice 42</Ustrd></RmtInf>\
</CdtTrfTxInf>\
</FIToFICstmrCdtTrf>\
</Document>";

    #[test]
    fn parses_handwritten_xml() {
        let doc = Pacs008Document::from_xml(SAMPLE_XML).unwrap();
        let cct = &doc.fi_to_fi_customer_credit_transfer;
        assert_eq!(cct.group_header.message_id, "MSG-1");
        let tx = &cct.credit_transfer_transactions[0];
        assert_eq!(tx.payment_identification.end_to_end_id, "E2E-1");
        assert_eq!(tx.interbank_settlement_amount.currency, "EUR");
        assert_eq!(tx.interbank_settlement_amount.value.units, "1500.00");
        assert_eq!(tx.debtor.name, "Jane Doe");
        assert_eq!(
            tx.debtor_account.as_ref().unwrap().id.iban.as_deref(),
            Some("DE89370400440532013000")
        );
        assert_eq!(
            tx.creditor_account
                .as_ref()
                .unwrap()
                .id
                .other
                .as_ref()
                .unwrap()
                .id,
            "eip155:1:0xdef"
        );
        assert_eq!(
            tx.remittance_information.as_ref().unwrap().unstructured,
            vec!["Invoice 42".to_string()]
        );
    }

    #[test]
    fn xml_round_trip_preserves_document() {
        let doc = Pacs008Document::from_xml(SAMPLE_XML).unwrap();
        let xml = doc.to_xml().unwrap();
        let reparsed = Pacs008Document::from_xml(&xml).unwrap();
        assert_eq!(doc, reparsed);
    }

    #[test]
    fn rejects_missing_msg_id() {
        let xml = SAMPLE_XML.replace("<MsgId>MSG-1</MsgId>", "");
        assert!(Pacs008Document::from_xml(&xml).is_err());
    }

    #[test]
    fn rejects_empty_debtor_name() {
        let xml = SAMPLE_XML.replace("<Nm>Jane Doe</Nm>", "<Nm></Nm>");
        let err = Pacs008Document::from_xml(&xml).unwrap_err();
        assert!(matches!(err, Iso20022Error::MissingField(_)));
    }

    #[test]
    fn rejects_missing_currency_attribute() {
        let xml = SAMPLE_XML.replace(" Ccy=\"EUR\"", "");
        assert!(Pacs008Document::from_xml(&xml).is_err());
    }

    #[test]
    fn rejects_wrong_namespace() {
        let xml = SAMPLE_XML.replace("pacs.008.001.08", "pacs.009.001.08");
        assert!(matches!(
            Pacs008Document::from_xml(&xml).unwrap_err(),
            Iso20022Error::Namespace { .. }
        ));
    }

    #[test]
    fn rejects_transaction_count_mismatch() {
        let xml = SAMPLE_XML.replace("<NbOfTxs>1</NbOfTxs>", "<NbOfTxs>2</NbOfTxs>");
        assert!(matches!(
            Pacs008Document::from_xml(&xml).unwrap_err(),
            Iso20022Error::TransactionCountMismatch { .. }
        ));
    }

    #[test]
    fn amount_validation() {
        assert!(DecimalAmount::new("1500").is_ok());
        assert!(DecimalAmount::new("0.5").is_ok());
        assert!(DecimalAmount::new("123456789012345.678").is_ok());
        assert!(DecimalAmount::new("").is_err());
        assert!(DecimalAmount::new("1.").is_err());
        assert!(DecimalAmount::new(".5").is_err());
        assert!(DecimalAmount::new("1..2").is_err());
        assert!(DecimalAmount::new("12a").is_err());
        assert!(DecimalAmount::new("1.123456").is_err());
        assert!(DecimalAmount::new("1234567890123456789").is_err());
    }

    #[test]
    fn ivms101_to_pacs008_and_back() {
        let envelope = sample_envelope();
        let doc = Pacs008Document::from_ivms101(&envelope, sample_details()).unwrap();

        let tx = &doc.fi_to_fi_customer_credit_transfer.credit_transfer_transactions[0];
        assert_eq!(tx.debtor.name, "Jane Doe");
        assert_eq!(tx.creditor.name, "Smith");
        assert_eq!(
            tx.debtor_account.as_ref().unwrap().id.iban.as_deref(),
            Some("DE89370400440532013000")
        );
        assert_eq!(
            tx.creditor_account
                .as_ref()
                .unwrap()
                .id
                .other
                .as_ref()
                .unwrap()
                .id,
            "eip155:1:0xdef"
        );
        assert_eq!(
            tx.debtor.postal_address.as_ref().unwrap().country.as_deref(),
            Some("DE")
        );

        let mapped = doc.to_ivms101().unwrap();
        assert_eq!(
            mapped.transfer.iso20022_message_id.as_deref(),
            Some("MSG-2026-07-12-0001")
        );
        assert_eq!(mapped.transfer.asset_caip19, "EUR");
        assert_eq!(mapped.transfer.amount_smallest_unit, "1500.00");
        assert_eq!(
            mapped.originator.account_number,
            vec!["DE89370400440532013000".to_string()]
        );
        assert_eq!(
            mapped.beneficiary.account_number,
            vec!["eip155:1:0xdef".to_string()]
        );
        let orig_name = mapped.originator.originator_persons[0]
            .natural_person
            .as_ref()
            .unwrap();
        assert_eq!(orig_name.name.primary_identifier, "Jane Doe");
        assert_eq!(orig_name.geographic_address[0].country, "DE");
    }

    #[test]
    fn from_ivms101_rejects_conflicting_bound_message_id() {
        let mut envelope = sample_envelope();
        envelope.transfer.iso20022_message_id = Some("MSG-OTHER".into());
        assert!(matches!(
            Pacs008Document::from_ivms101(&envelope, sample_details()).unwrap_err(),
            Iso20022Error::Mapping(_)
        ));
    }
}
