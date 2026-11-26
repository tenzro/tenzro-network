//! Encrypted file sharing (preview, feature `files`): one file sealed for
//! several recipients and handed over through their mailboxes.
//!
//! The sealed file is an age v1 file (age-encryption.org/v1): one random
//! file key, the content in age's chunked AEAD, and one stanza per recipient
//! wrapping the file key with the hybrid X25519 + ML-KEM-768 seal of
//! [`tenzro_crypto::hybrid_seal`], so reading it needs both key exchanges
//! broken. Each recipient's key comes with a [`RecipientCard`] signed by a key
//! of its DID, checked against the DID document before anything is sealed to
//! it; the recipient's private half may be derived on demand from its TPM or
//! Secure Enclave ([`HybridRecipient`]).
//!
//! A [`ShareManifest`], signed by the sharer's DID key, names the recipients
//! and the digest of the sealed file, so a recipient can check who else was
//! given it. Taking a recipient off is [`reshare`]: a new file key, sealed to
//! the others. A copy the removed recipient already holds cannot be recalled.
//!
//! What a mailbox carries is [`SharedFile::sealed`]: the age file after its
//! length, so the depositor may pad it to a size class.

use std::collections::HashSet;
use std::io::{Read as _, Write as _};

use age_core::format::{FileKey, Stanza};
use age_core::secrecy::ExposeSecret as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::hybrid_seal::{self, HybridPublicKey, HybridRecipient, HybridSealed};
use tenzro_crypto::{CompositeSignature, HybridSigner, PqPolicy, SignatureContext};
use zeroize::Zeroizing;

use crate::error::MailboxError;
use crate::service::{Ledger, verify};
use crate::wire::{base64_bytes, hex_bytes, push_prefixed, tagged};

/// The age stanza type that wraps a file key with the hybrid seal.
pub const FILE_STANZA_TAG: &str = "tenzro-hybrid";

/// The context every file key is sealed under.
const SEAL_CONTEXT: &[u8] = b"tenzro/mailbox/v1/file-key";

/// Bytes of an ML-KEM-768 ciphertext, at the start of a stanza's body.
const ML_KEM_768_CT_LEN: usize = 1088;

/// Bytes of an age file key.
const FILE_KEY_LEN: usize = 16;

fn files_error(e: impl std::fmt::Display) -> MailboxError {
    MailboxError::Files(e.to_string())
}

/// The bytes a DID's key signs to vouch for its file key.
pub fn recipient_card_preimage(did: &str, key: &HybridPublicKey) -> Vec<u8> {
    let mut m = tagged(b"/file-recipient");
    push_prefixed(&mut m, did.as_bytes());
    push_prefixed(&mut m, &key.encode());
    m
}

/// The bytes a sharer's DID key signs for a shared file.
pub fn share_manifest_preimage(
    sharer: &str,
    recipients: &[String],
    file_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut m = tagged(b"/file-manifest");
    push_prefixed(&mut m, sharer.as_bytes());
    m.extend_from_slice(&(recipients.len() as u32).to_be_bytes());
    for did in recipients {
        push_prefixed(&mut m, did.as_bytes());
    }
    m.extend_from_slice(file_sha256);
    m
}

/// A recipient's hybrid file key, vouched for by a key of its DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientCard {
    /// The recipient's DID.
    pub did: String,
    /// The hybrid key ([`HybridPublicKey::encode`]), base64 in JSON.
    #[serde(with = "base64_bytes")]
    pub key: Vec<u8>,
    /// The P-256 key (`x || y`) that signed, hex in JSON.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Signature over [`recipient_card_preimage`] under
    /// [`SignatureContext::Mailbox`].
    pub signature: CompositeSignature,
}

/// A recipient whose card held.
#[derive(Debug, Clone)]
pub struct VerifiedRecipient {
    did: String,
    key: HybridPublicKey,
}

impl VerifiedRecipient {
    /// The recipient's DID.
    pub fn did(&self) -> &str {
        &self.did
    }
}

async fn signed_by(
    ledger: &dyn Ledger,
    did: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &CompositeSignature,
) -> Result<bool, MailboxError> {
    Ok(ledger.did_key(did, public_key).await?.is_some_and(|k| {
        verify(
            &k.key,
            k.rp_id.as_deref(),
            SignatureContext::Mailbox,
            message,
            signature,
            PqPolicy::WhenPresent,
        )
    }))
}

impl RecipientCard {
    /// `did`'s card for `key`, signed by `identity`, a key of that DID.
    pub fn new(
        did: &str,
        key: &HybridPublicKey,
        identity: &dyn HybridSigner,
    ) -> Result<Self, MailboxError> {
        let signature = identity
            .sign(
                SignatureContext::Mailbox,
                &recipient_card_preimage(did, key),
            )
            .map_err(|e| MailboxError::Signing(e.to_string()))?;
        Ok(Self {
            did: did.to_string(),
            key: key.encode(),
            public_key: identity.public_key().p256.clone(),
            signature,
        })
    }

    /// Checks the card against `ledger`: the key that signed must act for
    /// the DID, and sign with its ML-DSA key when the DID has one.
    pub async fn verify(&self, ledger: &dyn Ledger) -> Result<VerifiedRecipient, MailboxError> {
        let key = HybridPublicKey::decode(&self.key)
            .ok_or_else(|| files_error("the card's key is not a hybrid key"))?;
        let message = recipient_card_preimage(&self.did, &key);
        if !signed_by(
            ledger,
            &self.did,
            &self.public_key,
            &message,
            &self.signature,
        )
        .await?
        {
            return Err(MailboxError::Unauthorized(format!(
                "the file key is not signed by a key of {}",
                self.did
            )));
        }
        Ok(VerifiedRecipient {
            did: self.did.clone(),
            key,
        })
    }
}

/// Who a file was shared with, signed by the sharer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareManifest {
    /// The sharer's DID.
    pub sharer: String,
    /// The recipients' DIDs, sorted.
    pub recipients: Vec<String>,
    /// SHA-256 of the age file, hex in JSON.
    #[serde(with = "hex_bytes")]
    pub file_sha256: Vec<u8>,
    /// The P-256 key (`x || y`) that signed, hex in JSON.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Signature over [`share_manifest_preimage`] under
    /// [`SignatureContext::Mailbox`].
    pub signature: CompositeSignature,
}

impl ShareManifest {
    /// Checks that the sharer's DID signed this manifest and that `sealed`
    /// is the file it names.
    pub async fn verify(&self, sealed: &[u8], ledger: &dyn Ledger) -> Result<(), MailboxError> {
        let file = age_file(sealed)?;
        let digest: [u8; 32] = Sha256::digest(file).into();
        if self.file_sha256 != digest {
            return Err(files_error("the manifest names another file"));
        }
        let message = share_manifest_preimage(&self.sharer, &self.recipients, &digest);
        if !signed_by(
            ledger,
            &self.sharer,
            &self.public_key,
            &message,
            &self.signature,
        )
        .await?
        {
            return Err(MailboxError::Unauthorized(format!(
                "the manifest is not signed by a key of {}",
                self.sharer
            )));
        }
        Ok(())
    }
}

/// A sealed file and its manifest.
#[derive(Debug, Clone)]
pub struct SharedFile {
    /// The age file after its length (4 bytes, big-endian); anything after
    /// the file is padding.
    pub sealed: Vec<u8>,
    /// Who it was shared with, signed by the sharer.
    pub manifest: ShareManifest,
}

fn age_file(sealed: &[u8]) -> Result<&[u8], MailboxError> {
    let (len, rest) = sealed
        .split_first_chunk::<4>()
        .ok_or_else(|| files_error("too short for a sealed file"))?;
    rest.get(..u32::from_be_bytes(*len) as usize)
        .ok_or_else(|| files_error("the sealed file is cut short"))
}

struct SealTo<'a>(&'a HybridPublicKey);

impl age::Recipient for SealTo<'_> {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let sealed = hybrid_seal::seal(self.0, SEAL_CONTEXT, file_key.expose_secret())
            .map_err(|e| age::EncryptError::Io(std::io::Error::other(e.to_string())))?;
        let mut body = sealed.ml_kem_ciphertext;
        body.extend_from_slice(&sealed.ciphertext);
        Ok((
            vec![Stanza {
                tag: FILE_STANZA_TAG.to_string(),
                args: vec![STANDARD_NO_PAD.encode(sealed.x25519_share)],
                body,
            }],
            // A file sealed to post-quantum recipients is never also sealed
            // to a classical one, which would undo the point.
            HashSet::from(["postquantum".to_string()]),
        ))
    }
}

struct OpenWith<'a>(&'a dyn HybridRecipient);

impl age::Identity for OpenWith<'_> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != FILE_STANZA_TAG {
            return None;
        }
        let share: Option<[u8; 32]> = match &stanza.args[..] {
            [arg] => STANDARD_NO_PAD
                .decode(arg)
                .ok()
                .and_then(|b| b.try_into().ok()),
            _ => None,
        };
        let (Some(x25519_share), true) = (share, stanza.body.len() > ML_KEM_768_CT_LEN) else {
            return Some(Err(age::DecryptError::InvalidHeader));
        };
        let (ml_kem_ciphertext, ciphertext) = stanza.body.split_at(ML_KEM_768_CT_LEN);
        let sealed = HybridSealed {
            x25519_share,
            ml_kem_ciphertext: ml_kem_ciphertext.to_vec(),
            ciphertext: ciphertext.to_vec(),
        };
        // A stanza sealed to another recipient does not open: try the next.
        let key = hybrid_seal::open_with(self.0, &sealed, SEAL_CONTEXT).ok()?;
        if key.len() != FILE_KEY_LEN {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        Some(Ok(FileKey::init_with_mut(|file_key| {
            file_key.copy_from_slice(&key)
        })))
    }
}

/// Seals `content` for `recipients` and signs the manifest as `sharer`
/// with `identity`, a key of the sharer's DID.
pub fn share(
    content: &[u8],
    recipients: &[VerifiedRecipient],
    sharer: &str,
    identity: &dyn HybridSigner,
) -> Result<SharedFile, MailboxError> {
    if recipients.is_empty() {
        return Err(files_error("a file is shared with at least one recipient"));
    }
    let seals: Vec<SealTo<'_>> = recipients.iter().map(|r| SealTo(&r.key)).collect();
    let encryptor = age::Encryptor::with_recipients(seals.iter().map(|s| s as &dyn age::Recipient))
        .map_err(files_error)?;
    let mut file = Vec::new();
    let mut writer = encryptor.wrap_output(&mut file).map_err(files_error)?;
    writer.write_all(content).map_err(files_error)?;
    writer.finish().map_err(files_error)?;

    let digest: [u8; 32] = Sha256::digest(&file).into();
    let mut dids: Vec<String> = recipients.iter().map(|r| r.did.clone()).collect();
    dids.sort();
    dids.dedup();
    let signature = identity
        .sign(
            SignatureContext::Mailbox,
            &share_manifest_preimage(sharer, &dids, &digest),
        )
        .map_err(|e| MailboxError::Signing(e.to_string()))?;
    let len = u32::try_from(file.len()).map_err(|_| files_error("the file is too large"))?;
    let mut sealed = len.to_be_bytes().to_vec();
    sealed.extend_from_slice(&file);
    Ok(SharedFile {
        sealed,
        manifest: ShareManifest {
            sharer: sharer.to_string(),
            recipients: dids,
            file_sha256: digest.to_vec(),
            public_key: identity.public_key().p256.clone(),
            signature,
        },
    })
}

/// Opens a sealed file with `key`, the recipient's hybrid key, once the
/// sharer's DID has been found to have signed `manifest` for this file.
pub async fn open(
    sealed: &[u8],
    manifest: &ShareManifest,
    key: &dyn HybridRecipient,
    ledger: &dyn Ledger,
) -> Result<Zeroizing<Vec<u8>>, MailboxError> {
    manifest.verify(sealed, ledger).await?;
    let decryptor = age::Decryptor::new(age_file(sealed)?).map_err(files_error)?;
    let identity = OpenWith(key);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(files_error)?;
    let mut content = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut content).map_err(files_error)?;
    Ok(content)
}

/// Shares a file again with `remaining` only, under a new file key: how a
/// recipient is taken off. Whoever held the old file keeps that copy.
pub async fn reshare(
    shared: &SharedFile,
    key: &dyn HybridRecipient,
    remaining: &[VerifiedRecipient],
    sharer: &str,
    identity: &dyn HybridSigner,
    ledger: &dyn Ledger,
) -> Result<SharedFile, MailboxError> {
    let content = open(&shared.sealed, &shared.manifest, key, ledger).await?;
    share(&content, remaining, sharer, identity)
}
