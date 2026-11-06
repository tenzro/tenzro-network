//! The keystore of a passkey account, held in consensus state.
//!
//! A passkey account is the user's devices plus this record on the ledger:
//! which passkeys may act for the account and how it recovers when they are
//! lost. Every node holds the same record under the state root, so any linked
//! device can act through any node, and the account survives every site and
//! every node that ever served it.
//!
//! # Address and genesis
//!
//! The account address commits to its first passkey, its identity and a
//! salt (see [`smart_account_address`]); it never changes when devices
//! change. Until the first [`KeystoreUpdate`] the record is implied: the
//! first passkey alone ([`KeystoreRecord::genesis`]). The first update names
//! that passkey in its [`KeystoreAnchor`], and the anchor is accepted only
//! when it derives the account, so nobody can claim an address their key
//! does not derive.
//!
//! # Authority
//!
//! Every change is approved by a passkey already in the record, over a
//! digest that names the chain, the account, the commitment of the record
//! being changed and the change ([`keystore_digest`]). The same passkey
//! derives the same account on every chain, so the chain id keeps an
//! approval made on one chain from applying on another. The commitment moves
//! with every change, so an approval applies once. Any one linked passkey may
//! approve; a passkey added while the account holds fewer than
//! [`SPEND_MIN_INDEPENDENT_ROOTS`] independent roots signs at once but counts
//! as a root only after [`ADD_DEVICE_WAIT_MS`], during which any other
//! passkey can remove it. Recovery is approved by the account's recovery
//! signers and completes after a wait any passkey can cancel.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::account_signature::CompositeSignature;
use crate::device_binding::{Aaguid, CredentialProvenance, CustodyCredential, independent_roots};
use crate::remote_grant::hex_bytes;

/// The account factory every passkey account's address is derived under.
pub const FACTORY_ADDRESS: [u8; 20] = {
    let mut a = [0u8; 20];
    a[18] = 0x04;
    a
};

/// Longest relying party id (a DNS name).
pub const MAX_RP_ID_LEN: usize = 253;

/// Whether `rp_id` is a relying party id a keystore accepts, and the domain
/// a wallet provider bonds for: a lowercase DNS name of letters, digits,
/// hyphens and dots, with no empty label.
pub fn valid_rp_id(rp_id: &str) -> bool {
    !rp_id.is_empty()
        && rp_id.len() <= MAX_RP_ID_LEN
        && rp_id.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Independent roots of control an account needs before its passkeys may
/// spend from it.
pub const SPEND_MIN_INDEPENDENT_ROOTS: usize = 2;

/// How long a passkey added below [`SPEND_MIN_INDEPENDENT_ROOTS`] waits
/// before it counts as a root, at genesis: the governed
/// `keystore.add_device_wait_ms` starts here.
pub const ADD_DEVICE_WAIT_MS: u64 = 48 * 60 * 60 * 1000;

/// Recovery wait when a recovery key and an email verifier both approved,
/// at genesis (`keystore.recovery_wait_key_and_email_ms`).
pub const RECOVERY_WAIT_KEY_AND_EMAIL_MS: u64 = 60 * 60 * 1000;
/// Recovery wait when only a recovery key approved, at genesis
/// (`keystore.recovery_wait_key_ms`).
pub const RECOVERY_WAIT_KEY_MS: u64 = 48 * 60 * 60 * 1000;
/// Recovery wait for any other approval, at genesis
/// (`keystore.recovery_wait_other_ms`): the longest.
pub const RECOVERY_WAIT_EMAIL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Most passkeys one account holds.
pub const MAX_CREDENTIALS: usize = 16;
/// Most recovery signers one account holds.
pub const MAX_RECOVERY_SIGNERS: usize = 8;
/// Longest WebAuthn credential id.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// Longest label, in bytes.
pub const MAX_LABEL_LEN: usize = 64;

const RECORD_DOMAIN: &[u8] = b"tenzro/keystore-record/v1";
const UPDATE_DOMAIN: &[u8] = b"tenzro/keystore-update/v1";

/// The human DID a passkey's P-256 key (`x || y`) derives.
pub fn human_did(public_key: &[u8]) -> String {
    format!(
        "did:tenzro:human:{}",
        crate::did_derivation::human_id(public_key)
    )
}

/// The address of the passkey account whose first passkey is
/// `credential_id` with key `public_key`, as wallet number `salt` of its
/// identity: the first 20 bytes of
/// `SHA-256(factory ‖ SHA-256(key ‖ credential id ‖ DID) ‖ salt)`.
pub fn smart_account_address(public_key: &[u8], credential_id: &[u8], salt: u64) -> [u8; 20] {
    let did = human_did(public_key);
    let owner: [u8; 32] = Sha256::new()
        .chain_update(public_key)
        .chain_update(credential_id)
        .chain_update(did.as_bytes())
        .finalize()
        .into();
    let hash = Sha256::new()
        .chain_update(FACTORY_ADDRESS)
        .chain_update(owner)
        .chain_update(salt.to_le_bytes())
        .finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[..20]);
    out
}

/// Key of the credential index: `SHA-256(SHA-256(rp id) ‖ credential id)`.
pub fn credential_index_key(rp_id: &str, credential_id: &[u8]) -> [u8; 32] {
    let rp: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    Sha256::new()
        .chain_update(rp)
        .chain_update(credential_id)
        .finalize()
        .into()
}

/// One passkey that may act for the account. Public material only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreCredential {
    /// The relying party the passkey is registered on: any wallet
    /// provider's domain. Its assertions must carry this RP's `rpIdHash` and
    /// come from this domain or a subdomain of it.
    pub rp_id: String,
    /// WebAuthn credential id.
    #[serde(with = "hex_bytes")]
    pub credential_id: Vec<u8>,
    /// P-256 public key, `x || y`.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Authenticator model, or sync provider for a synced passkey.
    #[serde(with = "hex_bytes")]
    pub aaguid: Vec<u8>,
    /// BE: the key may be replicated by a sync provider.
    pub backup_eligible: bool,
    /// BS: the key was replicated when it was added.
    pub backup_state: bool,
    /// Block time (ms) from which the passkey counts as a root of control.
    /// Zero: at once. Set by the chain, never by the request.
    pub counts_as_root_from_ms: u64,
    /// The holder's name for the device. Carries no authority.
    pub label: String,
    /// Block time (ms) the passkey joined the keystore on chain: the
    /// account's first change for the passkey it derives from. Set by the
    /// chain, never by the request; zero until then.
    #[serde(default)]
    pub added_at_ms: u64,
}

impl KeystoreCredential {
    /// Where the key lives.
    pub fn provenance_at(&self) -> CredentialProvenance {
        let mut aaguid = [0u8; 16];
        if self.aaguid.len() == 16 {
            aaguid.copy_from_slice(&self.aaguid);
        }
        CredentialProvenance {
            aaguid: Aaguid(aaguid),
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
        }
    }

    /// Whether the passkey counts as a root of control at `now_ms`.
    pub fn counts_at(&self, now_ms: u64) -> bool {
        self.counts_as_root_from_ms <= now_ms
    }

    fn check(&self) -> Result<(), &'static str> {
        if !valid_rp_id(&self.rp_id) {
            return Err("a passkey names its relying party as a lowercase DNS name");
        }
        if self.credential_id.is_empty() || self.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return Err("a credential id is 1 to 1023 bytes");
        }
        if self.public_key.len() != 64 {
            return Err("a passkey's P-256 key is 64 bytes, x || y");
        }
        if self.aaguid.len() != 16 {
            return Err("an AAGUID is 16 bytes");
        }
        if self.backup_state && !self.backup_eligible {
            return Err("a passkey cannot be backed up without being backup eligible");
        }
        if self.label.len() > MAX_LABEL_LEN {
            return Err("a label is at most 64 bytes");
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>) {
        field(out, self.rp_id.as_bytes());
        field(out, &self.credential_id);
        field(out, &self.public_key);
        field(out, &self.aaguid);
        out.push(u8::from(self.backup_eligible));
        out.push(u8::from(self.backup_state));
        field(out, self.label.as_bytes());
    }
}

impl CustodyCredential for KeystoreCredential {
    fn credential_id_bytes(&self) -> Vec<u8> {
        self.credential_id.clone()
    }
    fn provenance(&self) -> CredentialProvenance {
        self.provenance_at()
    }
}

/// How many of the account's passkeys must approve a change to its
/// keystore. Under [`SecondFactorPolicy::TwoCredentials`] one passkey alone
/// cannot act for the account at all: its transactions and its approvals as
/// an agent root are refused, and it spends only through user operations
/// both passkeys sign.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecondFactorPolicy {
    /// Any one passkey approves (default).
    #[default]
    SingleCredential,
    /// Two different passkeys approve.
    TwoCredentials,
}

impl SecondFactorPolicy {
    /// Passkeys that must approve.
    pub fn required_signatures(&self) -> usize {
        match self {
            Self::SingleCredential => 1,
            Self::TwoCredentials => 2,
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::SingleCredential => 1,
            Self::TwoCredentials => 2,
        }
    }
}

/// What a recovery signer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRole {
    /// A hardware key the holder keeps apart from their devices.
    RecoveryKey,
    /// A verifier attesting that the holder proved control of the email
    /// whose commitment the account carries.
    EmailVerifier,
    /// Another device the holder keeps.
    Device,
}

impl RecoveryRole {
    fn tag(self) -> u8 {
        match self {
            Self::RecoveryKey => 1,
            Self::EmailVerifier => 2,
            Self::Device => 3,
        }
    }
}

/// One key that may approve the account's recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySigner {
    /// For a passkey, the relying party it is registered on; empty for a TPM
    /// or Secure Enclave key, which signs in raw form.
    pub rp_id: String,
    /// P-256 key, `x || y`: a passkey, or a TPM or Secure Enclave key.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// AAGUID of a passkey; zeros for a TPM or Secure Enclave key.
    #[serde(with = "hex_bytes")]
    pub aaguid: Vec<u8>,
    /// BE of a passkey.
    pub backup_eligible: bool,
    /// BS of a passkey.
    pub backup_state: bool,
    /// What the signer is.
    pub role: RecoveryRole,
    /// The holder's name for it. Carries no authority.
    pub label: String,
}

impl RecoverySigner {
    fn check(&self) -> Result<(), &'static str> {
        if !self.rp_id.is_empty() && !valid_rp_id(&self.rp_id) {
            return Err("a recovery passkey names its relying party as a lowercase DNS name");
        }
        if self.public_key.len() != 64 {
            return Err("a recovery signer's P-256 key is 64 bytes, x || y");
        }
        if self.aaguid.len() != 16 {
            return Err("an AAGUID is 16 bytes");
        }
        if self.backup_state && !self.backup_eligible {
            return Err("a key cannot be backed up without being backup eligible");
        }
        if self.label.len() > MAX_LABEL_LEN {
            return Err("a label is at most 64 bytes");
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>) {
        field(out, self.rp_id.as_bytes());
        field(out, &self.public_key);
        field(out, &self.aaguid);
        out.push(u8::from(self.backup_eligible));
        out.push(u8::from(self.backup_state));
        out.push(self.role.tag());
        field(out, self.label.as_bytes());
    }
}

impl CustodyCredential for RecoverySigner {
    fn credential_id_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    fn provenance(&self) -> CredentialProvenance {
        let mut aaguid = [0u8; 16];
        if self.aaguid.len() == 16 {
            aaguid.copy_from_slice(&self.aaguid);
        }
        CredentialProvenance {
            aaguid: Aaguid(aaguid),
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
        }
    }
}

/// The account's one-time recovery code: only a commitment to it is on
/// chain ([`recovery_code_commitment`]); the code itself is a 32-byte
/// secret the holder keeps, downloaded or written down. It is off until the
/// account's passkeys set it. Using it takes two steps so nobody who sees it
/// can use it first: a claim binding the code to the passkey that will join
/// ([`recovery_code_claim`]), sent and paid by another account, then, after
/// the governed reveal delay and before the claim expires, the code and that
/// passkey. That starts a recovery any linked passkey can cancel during its
/// wait, and spends the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCode {
    /// `SHA-256(domain ‖ chain id ‖ account ‖ code)`.
    #[serde(with = "hex_bytes")]
    pub commitment: Vec<u8>,
}

const RECOVERY_CODE_DOMAIN: &[u8] = b"tenzro/keystore/recovery-code/v1";
const RECOVERY_CLAIM_DOMAIN: &[u8] = b"tenzro/keystore/recovery-claim/v1";

/// The commitment the account holds on chain `chain_id` for recovery code
/// `code`.
pub fn recovery_code_commitment(chain_id: u64, account: &[u8], code: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(RECOVERY_CODE_DOMAIN)
        .chain_update(chain_id.to_le_bytes())
        .chain_update(account)
        .chain_update(code)
        .finalize()
        .into()
}

/// The claim on chain `chain_id` that binds recovery code `code` to the
/// passkey `credential`.
pub fn recovery_code_claim(
    chain_id: u64,
    account: &[u8],
    code: &[u8],
    credential: &KeystoreCredential,
) -> [u8; 32] {
    let mut c = Vec::new();
    credential.encode(&mut c);
    Sha256::new()
        .chain_update(RECOVERY_CLAIM_DOMAIN)
        .chain_update(chain_id.to_le_bytes())
        .chain_update(account)
        .chain_update(code)
        .chain_update(&c)
        .finalize()
        .into()
}

/// A recovery the recovery signers approved, waiting out its delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecovery {
    /// The passkey that joins the account when the recovery completes.
    pub credential: KeystoreCredential,
    /// Indices into the recovery signers of those who approved.
    pub approvers: Vec<u32>,
    /// Block time (ms) the recovery started.
    pub started_at_ms: u64,
    /// Block time (ms) from which it may complete.
    pub ready_at_ms: u64,
}

/// An account's keystore as consensus state holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreRecord {
    /// The account address, 20 bytes.
    #[serde(with = "hex_bytes")]
    pub account: Vec<u8>,
    /// The identity that owns it: the human DID of its first passkey.
    pub owner_did: String,
    /// Which wallet of that identity this is.
    pub salt: u64,
    /// Zero for the implied genesis record; one more per change.
    pub version: u64,
    /// The passkeys that may act for the account, ordered by credential id.
    pub credentials: Vec<KeystoreCredential>,
    /// How many passkeys approve a change.
    pub policy: SecondFactorPolicy,
    /// The keys that may approve a recovery.
    pub recovery_signers: Vec<RecoverySigner>,
    /// Independent roots among the recovery signers a recovery needs.
    pub recovery_threshold: u32,
    /// The recovery in progress, if any.
    pub pending_recovery: Option<PendingRecovery>,
    /// The one-time recovery code, when the account set one.
    pub recovery_code: Option<RecoveryCode>,
}

impl KeystoreRecord {
    /// The implied record of an account before its first change: the
    /// anchor's passkey alone.
    pub fn genesis(anchor: &KeystoreAnchor) -> Self {
        let address = smart_account_address(&anchor.public_key, &anchor.credential_id, anchor.salt);
        Self {
            account: address.to_vec(),
            owner_did: human_did(&anchor.public_key),
            salt: anchor.salt,
            version: 0,
            credentials: vec![KeystoreCredential {
                rp_id: anchor.rp_id.clone(),
                credential_id: anchor.credential_id.clone(),
                public_key: anchor.public_key.clone(),
                aaguid: anchor.aaguid.clone(),
                backup_eligible: anchor.backup_eligible,
                backup_state: anchor.backup_state,
                counts_as_root_from_ms: 0,
                label: String::new(),
                added_at_ms: 0,
            }],
            policy: SecondFactorPolicy::SingleCredential,
            recovery_signers: Vec::new(),
            recovery_threshold: 0,
            pending_recovery: None,
            recovery_code: None,
        }
    }

    /// The 32-byte commitment over the record. A change names it, so an
    /// approval applies to exactly one version.
    pub fn commitment(&self) -> [u8; 32] {
        let body = serde_json::to_vec(self).unwrap_or_default();
        Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update(body)
            .finalize()
            .into()
    }

    /// The passkey with P-256 key `public_key`.
    pub fn credential_by_key(&self, public_key: &[u8]) -> Option<&KeystoreCredential> {
        self.credentials.iter().find(|c| c.public_key == public_key)
    }

    /// The passkey with id `credential_id`.
    pub fn credential_by_id(&self, credential_id: &[u8]) -> Option<&KeystoreCredential> {
        self.credentials
            .iter()
            .find(|c| c.credential_id == credential_id)
    }

    /// Independent roots among the passkeys that count at `now_ms`.
    pub fn independent_roots_at(&self, now_ms: u64) -> usize {
        let counting: Vec<&KeystoreCredential> = self
            .credentials
            .iter()
            .filter(|c| c.counts_at(now_ms))
            .collect();
        independent_roots(&counting)
    }

    /// Whether the account's passkeys may spend at `now_ms`.
    pub fn may_spend(&self, now_ms: u64) -> bool {
        self.independent_roots_at(now_ms) >= SPEND_MIN_INDEPENDENT_ROOTS
    }
}

/// The first passkey of an account, named by the account's first change so
/// the chain can check that it derives the account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreAnchor {
    /// The relying party the passkey is registered on.
    pub rp_id: String,
    /// WebAuthn credential id.
    #[serde(with = "hex_bytes")]
    pub credential_id: Vec<u8>,
    /// P-256 public key, `x || y`.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// AAGUID from its registration.
    #[serde(with = "hex_bytes")]
    pub aaguid: Vec<u8>,
    /// BE from its registration.
    pub backup_eligible: bool,
    /// BS from its registration.
    pub backup_state: bool,
    /// Which wallet of the identity.
    pub salt: u64,
}

/// One change to an account's keystore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeystoreOp {
    /// Link a passkey. The update carries its proof of possession.
    AddCredential {
        /// The passkey; `counts_as_root_from_ms` is set by the chain.
        credential: KeystoreCredential,
    },
    /// Unlink a passkey. At least one stays.
    RemoveCredential {
        /// Its credential id.
        #[serde(with = "hex_bytes")]
        credential_id: Vec<u8>,
    },
    /// Set how many passkeys approve a change. Two needs two passkeys.
    SetPolicy {
        /// The policy.
        policy: SecondFactorPolicy,
    },
    /// Replace the recovery signers and threshold. No signers and threshold
    /// zero turns recovery off.
    SetRecovery {
        /// The signers.
        signers: Vec<RecoverySigner>,
        /// Independent roots among them a recovery needs.
        threshold: u32,
    },
    /// Start a recovery approved by the recovery signers, adding
    /// `credential` once its wait has passed. The update carries the new
    /// passkey's proof of possession.
    StartRecovery {
        /// The passkey to add.
        credential: KeystoreCredential,
    },
    /// Cancel the pending recovery.
    CancelRecovery,
    /// Complete the pending recovery after its wait.
    FinishRecovery,
    /// Set the one-time recovery code's commitment, or turn it off with
    /// none.
    SetRecoveryCode {
        /// [`recovery_code_commitment`] of the new code.
        commitment: Option<RecoveryCodeCommitment>,
    },
    /// Claim the recovery code for a passkey without revealing either:
    /// [`recovery_code_claim`]. Sent and paid by another account; needs no
    /// approval and changes nothing in the record.
    ClaimRecoveryCode {
        /// The claim.
        #[serde(with = "hex_bytes")]
        claim: Vec<u8>,
    },
    /// Reveal the recovery code and the passkey it was claimed for, starting
    /// a recovery that adds that passkey after its wait. The update carries
    /// the passkey's proof of possession.
    RecoverWithCode {
        /// The code.
        #[serde(with = "hex_bytes")]
        code: Vec<u8>,
        /// The passkey to add.
        credential: KeystoreCredential,
    },
}

/// A recovery code commitment, 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCodeCommitment(#[serde(with = "hex_bytes")] pub Vec<u8>);

impl KeystoreOp {
    /// The canonical bytes an approval signs.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::AddCredential { credential } => {
                out.push(1);
                credential.encode(&mut out);
            }
            Self::RemoveCredential { credential_id } => {
                out.push(2);
                field(&mut out, credential_id);
            }
            Self::SetRecovery { signers, threshold } => {
                out.push(3);
                out.extend_from_slice(&threshold.to_be_bytes());
                out.extend_from_slice(&(signers.len() as u32).to_be_bytes());
                for s in signers {
                    s.encode(&mut out);
                }
            }
            Self::StartRecovery { credential } => {
                out.push(4);
                credential.encode(&mut out);
            }
            Self::CancelRecovery => out.push(5),
            Self::FinishRecovery => out.push(6),
            Self::SetPolicy { policy } => {
                out.push(7);
                out.push(policy.tag());
            }
            Self::SetRecoveryCode { commitment } => {
                out.push(8);
                match commitment {
                    Some(c) => field(&mut out, &c.0),
                    None => field(&mut out, &[]),
                }
            }
            Self::ClaimRecoveryCode { claim } => {
                out.push(9);
                field(&mut out, claim);
            }
            Self::RecoverWithCode { code, credential } => {
                out.push(10);
                field(&mut out, code);
                credential.encode(&mut out);
            }
        }
        out
    }

    /// The passkey the change adds, which must prove possession.
    pub fn new_credential(&self) -> Option<&KeystoreCredential> {
        match self {
            Self::AddCredential { credential }
            | Self::StartRecovery { credential }
            | Self::RecoverWithCode { credential, .. } => Some(credential),
            _ => None,
        }
    }
}

/// One signature approving a change: by a passkey of the account, or for a
/// recovery by a recovery signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreApproval {
    /// The signer's P-256 key, `x || y`.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Its signature over [`KeystoreUpdate::digest`]: a passkey signs a
    /// WebAuthn assertion with user verification under the account-owner
    /// context; a recovery signer signs under the recovery-approval context.
    pub signature: CompositeSignature,
}

/// A change to an account's keystore, carried by a transaction any account
/// may send and pay for: the authority is in the approvals, never in the
/// sender. A transaction the account itself sends, signed by one of its
/// passkeys, counts as that passkey's approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreUpdate {
    /// The chain the change is for. A chain refuses a change made for
    /// another.
    pub chain_id: u64,
    /// The account, 20 bytes.
    #[serde(with = "hex_bytes")]
    pub account: Vec<u8>,
    /// The first passkey, required exactly when the account has no record
    /// on chain yet.
    pub anchor: Option<KeystoreAnchor>,
    /// Commitment of the record being changed; for an account with no
    /// record on chain, of its genesis record.
    #[serde(with = "hex_bytes")]
    pub previous_commitment: Vec<u8>,
    /// The change.
    pub op: KeystoreOp,
    /// Signatures over [`Self::digest`].
    pub approvals: Vec<KeystoreApproval>,
    /// For a change that adds a passkey: that passkey's WebAuthn assertion
    /// with user verification over [`Self::digest`] under the account-owner
    /// context.
    pub possession: Option<CompositeSignature>,
}

impl KeystoreUpdate {
    /// What every approval signs.
    pub fn digest(&self) -> [u8; 32] {
        keystore_digest(
            self.chain_id,
            &self.account,
            &self.previous_commitment,
            &self.op,
        )
    }

    /// Stateless checks.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.account.len() != 20 {
            return Err("a keystore account is 20 bytes");
        }
        if self.previous_commitment.len() != 32 {
            return Err("a keystore commitment is 32 bytes");
        }
        if self.approvals.len() > MAX_RECOVERY_SIGNERS + MAX_CREDENTIALS {
            return Err("too many approvals");
        }
        if let Some(anchor) = &self.anchor
            && (!valid_rp_id(&anchor.rp_id)
                || anchor.public_key.len() != 64
                || anchor.aaguid.len() != 16
                || anchor.credential_id.is_empty()
                || anchor.credential_id.len() > MAX_CREDENTIAL_ID_LEN
                || (anchor.backup_state && !anchor.backup_eligible))
        {
            return Err("a malformed keystore anchor");
        }
        for a in &self.approvals {
            if a.public_key.len() != 64 {
                return Err("an approval names a 64-byte P-256 key");
            }
        }
        match &self.op {
            KeystoreOp::AddCredential { credential } | KeystoreOp::StartRecovery { credential } => {
                credential.check()?;
                if self.possession.is_none() {
                    return Err("adding a passkey needs its proof of possession");
                }
            }
            KeystoreOp::RemoveCredential { credential_id } => {
                if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_LEN {
                    return Err("a credential id is 1 to 1023 bytes");
                }
            }
            KeystoreOp::SetRecovery { signers, threshold } => {
                if signers.len() > MAX_RECOVERY_SIGNERS {
                    return Err("an account holds at most 8 recovery signers");
                }
                for s in signers {
                    s.check()?;
                }
                if signers.is_empty() != (*threshold == 0) {
                    return Err("recovery needs a threshold exactly when it has signers");
                }
            }
            KeystoreOp::SetRecoveryCode { commitment } => {
                if commitment.as_ref().is_some_and(|c| c.0.len() != 32) {
                    return Err("a recovery code commitment is 32 bytes");
                }
            }
            KeystoreOp::ClaimRecoveryCode { claim } => {
                if claim.len() != 32 || !self.approvals.is_empty() {
                    return Err("a recovery code claim is 32 bytes and carries no approval");
                }
            }
            KeystoreOp::RecoverWithCode { code, credential } => {
                if code.len() != 32 {
                    return Err("a recovery code is 32 bytes");
                }
                credential.check()?;
                if self.possession.is_none() {
                    return Err("adding a passkey needs its proof of possession");
                }
            }
            KeystoreOp::SetPolicy { .. }
            | KeystoreOp::CancelRecovery
            | KeystoreOp::FinishRecovery => {}
        }
        if self.op.new_credential().is_none() && self.possession.is_some() {
            return Err("a proof of possession belongs only to a change that adds a passkey");
        }
        Ok(())
    }
}

/// The digest an approval of `op` on `account` on chain `chain_id` signs,
/// given the commitment of the record it changes:
/// `SHA-256(domain ‖ chain id ‖ account ‖ commitment ‖ op)`, the chain id
/// as 8 bytes little-endian like a transaction's.
pub fn keystore_digest(
    chain_id: u64,
    account: &[u8],
    previous_commitment: &[u8],
    op: &KeystoreOp,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(UPDATE_DOMAIN);
    h.update(chain_id.to_le_bytes());
    h.update((account.len() as u32).to_be_bytes());
    h.update(account);
    h.update((previous_commitment.len() as u32).to_be_bytes());
    h.update(previous_commitment);
    h.update(op.encode());
    h.finalize().into()
}

/// Which recovery wait a recovery approved by signers in `roles` serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryWait {
    /// A recovery key and an email verifier approved.
    KeyAndEmail,
    /// A recovery key approved, without an email verifier.
    Key,
    /// Anything else: the longest wait.
    Other,
}

/// The wait a recovery approved by signers in `roles` serves.
pub fn recovery_wait(roles: &[RecoveryRole]) -> RecoveryWait {
    let key = roles.contains(&RecoveryRole::RecoveryKey);
    let email = roles.contains(&RecoveryRole::EmailVerifier);
    match (key, email) {
        (true, true) => RecoveryWait::KeyAndEmail,
        (true, false) => RecoveryWait::Key,
        _ => RecoveryWait::Other,
    }
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> KeystoreAnchor {
        KeystoreAnchor {
            rp_id: "tenzro.com".to_string(),
            credential_id: vec![7; 16],
            public_key: vec![9; 64],
            aaguid: vec![0; 16],
            backup_eligible: true,
            backup_state: true,
            salt: 0,
        }
    }

    #[test]
    fn the_genesis_record_is_the_first_passkey_at_its_derived_address() {
        let a = anchor();
        let g = KeystoreRecord::genesis(&a);
        assert_eq!(
            g.account,
            smart_account_address(&a.public_key, &a.credential_id, 0).to_vec()
        );
        assert_eq!(g.owner_did, human_did(&a.public_key));
        assert_eq!(g.credentials.len(), 1);
        assert_ne!(
            KeystoreRecord::genesis(&KeystoreAnchor { salt: 1, ..a }).account,
            g.account,
            "each wallet of an identity has its own address"
        );
    }

    /// The vector wallets check their own derivation against.
    #[test]
    fn the_address_and_identity_match_the_shared_vector() {
        let key = [0x11u8; 64];
        let credential = [0x22u8; 16];
        assert_eq!(
            human_did(&key),
            "did:tenzro:human:f7ee7b699f1ecc0948fc09b1f084f3b1740e645c242e245442f6b8899f0d8360"
        );
        assert_eq!(
            hex::encode(smart_account_address(&key, &credential, 0)),
            "584cea8771076642829ddfab5ef731a3c3df9a92"
        );
        assert_eq!(
            hex::encode(smart_account_address(&key, &credential, 1)),
            "3727a36a5d0491d76eb580c9c6307e6d65764f19"
        );
    }

    #[test]
    fn the_digest_binds_chain_account_commitment_and_change() {
        let op = KeystoreOp::RemoveCredential {
            credential_id: vec![1],
        };
        let d = keystore_digest(1337, &[1; 20], &[2; 32], &op);
        assert_ne!(d, keystore_digest(1338, &[1; 20], &[2; 32], &op));
        assert_ne!(d, keystore_digest(1337, &[3; 20], &[2; 32], &op));
        assert_ne!(d, keystore_digest(1337, &[1; 20], &[4; 32], &op));
        assert_ne!(
            d,
            keystore_digest(
                1337,
                &[1; 20],
                &[2; 32],
                &KeystoreOp::RemoveCredential {
                    credential_id: vec![2]
                }
            )
        );
        assert_ne!(
            d,
            keystore_digest(1337, &[1; 20], &[2; 32], &KeystoreOp::CancelRecovery)
        );
    }

    #[test]
    fn synced_passkeys_of_one_provider_are_one_root_and_waiting_ones_none() {
        let mut g = KeystoreRecord::genesis(&anchor());
        let mut second = g.credentials[0].clone();
        second.credential_id = vec![8; 16];
        second.public_key = vec![10; 64];
        g.credentials.push(second.clone());
        assert_eq!(g.independent_roots_at(0), 1);
        let mut bound = second;
        bound.credential_id = vec![11; 16];
        bound.backup_eligible = false;
        bound.backup_state = false;
        bound.counts_as_root_from_ms = 100;
        g.credentials.push(bound);
        assert!(!g.may_spend(99));
        assert!(g.may_spend(100));
    }

    #[test]
    fn an_update_round_trips_through_json_and_validates() {
        let u = KeystoreUpdate {
            chain_id: 1337,
            account: vec![1; 20],
            anchor: Some(anchor()),
            previous_commitment: vec![0; 32],
            op: KeystoreOp::SetRecovery {
                signers: Vec::new(),
                threshold: 0,
            },
            approvals: Vec::new(),
            possession: None,
        };
        u.validate().unwrap();
        let back: KeystoreUpdate =
            serde_json::from_slice(&serde_json::to_vec(&u).unwrap()).unwrap();
        assert_eq!(back, u);
        let bad = KeystoreUpdate {
            op: KeystoreOp::SetRecovery {
                signers: Vec::new(),
                threshold: 1,
            },
            ..u
        };
        assert!(bad.validate().is_err());
    }

    /// The digest every SDK computes for the same change, from the shared
    /// vector in `sdk/fixtures/keystore/digest.json`.
    #[test]
    fn the_digest_matches_the_shared_vector() {
        let raw = include_str!("../../../sdk/fixtures/keystore/digest.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let chain_id = v["chain_id"].as_u64().unwrap();
        let account = hex::decode(v["account"].as_str().unwrap()).unwrap();
        let previous = hex::decode(v["previous_commitment"].as_str().unwrap()).unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 11);
        for case in cases {
            let op: KeystoreOp = serde_json::from_value(case["op"].clone()).unwrap();
            assert_eq!(
                hex::encode(keystore_digest(chain_id, &account, &previous, &op)),
                case["digest"].as_str().unwrap(),
                "{op:?}"
            );
        }
        // The recovery code helpers every SDK computes the same way.
        let code = [0x77u8; 32];
        let op =
            |i: usize| -> KeystoreOp { serde_json::from_value(cases[i]["op"].clone()).unwrap() };
        let KeystoreOp::SetRecoveryCode {
            commitment: Some(c),
        } = op(8)
        else {
            panic!()
        };
        assert_eq!(c.0, recovery_code_commitment(chain_id, &account, &code));
        let KeystoreOp::RecoverWithCode { credential, .. } = op(10) else {
            panic!()
        };
        let KeystoreOp::ClaimRecoveryCode { claim } = op(9) else {
            panic!()
        };
        assert_eq!(
            claim,
            recovery_code_claim(chain_id, &account, &code, &credential)
        );
    }

    /// A change as a client builds it decodes and encodes as the node puts it
    /// in a signing payload, from `sdk/fixtures/keystore/encoding.json`.
    #[test]
    fn a_client_change_encodes_as_the_shared_vector() {
        let raw = include_str!("../../../sdk/fixtures/keystore/encoding.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        for case in v["cases"].as_array().unwrap() {
            let update: KeystoreUpdate = serde_json::from_value(case["update"].clone()).unwrap();
            assert_eq!(serde_json::to_value(&update).unwrap(), case["encoded"]);
        }
    }

    #[test]
    fn recovery_waits_by_who_approved() {
        assert_eq!(
            recovery_wait(&[RecoveryRole::RecoveryKey, RecoveryRole::EmailVerifier]),
            RecoveryWait::KeyAndEmail
        );
        assert_eq!(
            recovery_wait(&[RecoveryRole::RecoveryKey]),
            RecoveryWait::Key
        );
        assert_eq!(recovery_wait(&[RecoveryRole::Device]), RecoveryWait::Other);
        assert_eq!(
            recovery_wait(&[RecoveryRole::EmailVerifier]),
            RecoveryWait::Other
        );
    }
}
