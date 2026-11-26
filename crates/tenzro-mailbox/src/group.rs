//! Group sessions (preview, feature `mls`): end-to-end keys for many members
//! with MLS (RFC 9420), carried through mailboxes.
//!
//! Each member keeps a [`GroupMember`]: an MLS signature key made in memory
//! for this member, and the groups it is in. A member publishes key packages
//! signed by its DID's own key ([`GroupMember::package`]), in its mailbox as
//! key packages ([`crate::MailboxClient::upload_prekeys`]); whoever adds it
//! checks that signature against the DID document first
//! ([`MemberPackage::verify`]), so a mailbox cannot hand out a key package of
//! its own. The others trust the adding member's check, as MLS trusts its
//! authentication service.
//!
//! Commits, welcomes and messages are MLS messages: the sender deposits each
//! one in every other member's mailbox, padded to a size class like any
//! sealed message, and the mailbox learns no more than it does of one.
//! Members apply commits in the order the group made them; a commit that
//! arrives out of order is refused and fetched again later.
//!
//! The cipher suite is [`GROUP_CIPHERSUITE`]: X25519 with ML-KEM-768 for the
//! keys, so a recording of the group's traffic stays sealed against a
//! quantum computer, and Ed25519 for the in-group signatures. Group state is
//! held in memory: a member that restarts joins again.

use std::collections::HashMap;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::{CompositeSignature, HybridSigner, PqPolicy, SignatureContext};

use crate::error::MailboxError;
use crate::service::{Ledger, verify};
use crate::wire::{base64_bytes, hex_bytes, push_prefixed, tagged};

/// The cipher suite of every group: hybrid X25519 + ML-KEM-768 keys,
/// AES-128-GCM, SHA-256, Ed25519.
pub const GROUP_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;

/// Application messages are padded to a multiple of this many bytes inside
/// the group's encryption.
const PADDING: usize = 256;

fn group_error(e: impl std::fmt::Display) -> MailboxError {
    MailboxError::Group(e.to_string())
}

/// The bytes a DID's key signs to vouch for one of its key packages.
pub fn member_package_preimage(did: &str, key_package: &[u8]) -> Vec<u8> {
    let mut m = tagged(b"/mls-key-package");
    push_prefixed(&mut m, did.as_bytes());
    m.extend_from_slice(&Sha256::digest(key_package));
    m
}

/// A member's MLS key package, vouched for by its DID's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberPackage {
    /// The member's DID, which its MLS credential names too.
    pub did: String,
    /// The TLS-encoded MLS key package, base64 in JSON.
    #[serde(with = "base64_bytes")]
    pub key_package: Vec<u8>,
    /// The P-256 key (`x || y`) that signed, hex in JSON: the key the DID
    /// resolves to, or one its account's keystore links.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Signature over [`member_package_preimage`] under
    /// [`SignatureContext::Mailbox`].
    pub signature: CompositeSignature,
}

/// A key package whose DID signature and MLS signature both held.
#[derive(Debug, Clone)]
pub struct VerifiedPackage {
    did: String,
    key_package: KeyPackage,
}

impl VerifiedPackage {
    /// The member it adds.
    pub fn did(&self) -> &str {
        &self.did
    }
}

impl MemberPackage {
    /// The bytes a mailbox keeps for it.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MailboxError> {
        serde_json::to_vec(self).map_err(group_error)
    }

    /// Read one a mailbox served.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MailboxError> {
        serde_json::from_slice(bytes).map_err(group_error)
    }

    /// Checks the package against `ledger`: the key that signed must act
    /// for the DID (and sign with its ML-DSA key when the DID has one), and
    /// the MLS key package must be well signed, of [`GROUP_CIPHERSUITE`],
    /// and name the same DID.
    pub async fn verify(&self, ledger: &dyn Ledger) -> Result<VerifiedPackage, MailboxError> {
        let signed = ledger
            .did_key(&self.did, &self.public_key)
            .await?
            .is_some_and(|k| {
                verify(
                    &k.key,
                    k.rp_id.as_deref(),
                    SignatureContext::Mailbox,
                    &member_package_preimage(&self.did, &self.key_package),
                    &self.signature,
                    PqPolicy::WhenPresent,
                )
            });
        if !signed {
            return Err(MailboxError::Unauthorized(format!(
                "the key package is not signed by a key of {}",
                self.did
            )));
        }
        let key_package = KeyPackageIn::tls_deserialize_exact(&self.key_package)
            .map_err(group_error)?
            .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
            .map_err(group_error)?;
        if key_package.ciphersuite() != GROUP_CIPHERSUITE {
            return Err(group_error("the key package is of another cipher suite"));
        }
        if did_of(key_package.leaf_node().credential()).as_deref() != Some(self.did.as_str()) {
            return Err(group_error("the key package names another member"));
        }
        Ok(VerifiedPackage {
            did: self.did.clone(),
            key_package,
        })
    }
}

fn did_of(credential: &Credential) -> Option<String> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    String::from_utf8(basic.identity().to_vec()).ok()
}

/// A change to a group, to deposit with each member.
#[derive(Debug, Clone)]
pub struct Commit {
    /// The commit, for every member that was in the group before it.
    pub commit: Vec<u8>,
    /// The welcome, for the members it adds.
    pub welcome: Option<Vec<u8>>,
}

/// What an MLS message held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// A member's message to the group.
    Message {
        /// The group's id.
        group: Vec<u8>,
        /// The sending member's DID.
        sender: String,
        /// The message.
        bytes: Vec<u8>,
    },
    /// A commit, now applied: the group is at `epoch`.
    Changed {
        /// The group's id.
        group: Vec<u8>,
        /// The group's epoch after the commit.
        epoch: u64,
    },
    /// A commit that removed this member; the group is forgotten.
    Removed {
        /// The group's id.
        group: Vec<u8>,
    },
}

/// One member's side of its groups.
pub struct GroupMember {
    did: String,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    groups: HashMap<Vec<u8>, MlsGroup>,
}

impl GroupMember {
    /// A member for `did`, with an MLS signature key made now.
    pub fn new(did: &str) -> Result<Self, MailboxError> {
        let provider = OpenMlsRustCrypto::default();
        let signer =
            SignatureKeyPair::new(GROUP_CIPHERSUITE.signature_algorithm()).map_err(group_error)?;
        signer.store(provider.storage()).map_err(group_error)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(did.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            did: did.to_string(),
            provider,
            signer,
            credential,
            groups: HashMap::new(),
        })
    }

    /// The member's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// A fresh key package, signed by `identity`, a key of the member's DID.
    /// Each one adds the member to one group.
    pub fn package(&self, identity: &dyn HybridSigner) -> Result<MemberPackage, MailboxError> {
        let bundle = KeyPackage::builder()
            .build(
                GROUP_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(group_error)?;
        let key_package = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(group_error)?;
        let signature = identity
            .sign(
                SignatureContext::Mailbox,
                &member_package_preimage(&self.did, &key_package),
            )
            .map_err(|e| MailboxError::Signing(e.to_string()))?;
        Ok(MemberPackage {
            did: self.did.clone(),
            key_package,
            public_key: identity.public_key().p256.clone(),
            signature,
        })
    }

    /// A new group with this member alone in it; returns its id.
    pub fn create(&mut self) -> Result<Vec<u8>, MailboxError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(GROUP_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .padding_size(PADDING)
            .build();
        let group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential.clone(),
        )
        .map_err(group_error)?;
        let id = group.group_id().as_slice().to_vec();
        self.groups.insert(id.clone(), group);
        Ok(id)
    }

    /// Joins the group a welcome is for; returns its id.
    pub fn join(&mut self, welcome: &[u8]) -> Result<Vec<u8>, MailboxError> {
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(group_error)?
            .extract()
        else {
            return Err(group_error("not a welcome"));
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .padding_size(PADDING)
            .build();
        let group = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(group_error)?
            .into_group(&self.provider)
            .map_err(group_error)?;
        let id = group.group_id().as_slice().to_vec();
        self.groups.insert(id.clone(), group);
        Ok(id)
    }

    fn group(&self, id: &[u8]) -> Result<&MlsGroup, MailboxError> {
        self.groups
            .get(id)
            .ok_or_else(|| group_error("this member is not in that group"))
    }

    /// Adds the members `packages` vouch for.
    pub fn add(&mut self, id: &[u8], packages: &[VerifiedPackage]) -> Result<Commit, MailboxError> {
        let key_packages: Vec<KeyPackage> =
            packages.iter().map(|p| p.key_package.clone()).collect();
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self
            .groups
            .get_mut(id)
            .ok_or_else(|| group_error("this member is not in that group"))?;
        let (commit, welcome, _) = group
            .add_members(provider, signer, &key_packages)
            .map_err(group_error)?;
        group.merge_pending_commit(provider).map_err(group_error)?;
        Ok(Commit {
            commit: commit.tls_serialize_detached().map_err(group_error)?,
            welcome: Some(welcome.tls_serialize_detached().map_err(group_error)?),
        })
    }

    /// Removes every member whose credential names one of `dids`.
    pub fn remove(&mut self, id: &[u8], dids: &[&str]) -> Result<Commit, MailboxError> {
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self
            .groups
            .get_mut(id)
            .ok_or_else(|| group_error("this member is not in that group"))?;
        let leaves: Vec<LeafNodeIndex> = group
            .members()
            .filter(|m| did_of(&m.credential).is_some_and(|d| dids.contains(&d.as_str())))
            .map(|m| m.index)
            .collect();
        if leaves.is_empty() {
            return Err(group_error("none of those DIDs is a member"));
        }
        let (commit, _, _) = group
            .remove_members(provider, signer, &leaves)
            .map_err(group_error)?;
        group.merge_pending_commit(provider).map_err(group_error)?;
        Ok(Commit {
            commit: commit.tls_serialize_detached().map_err(group_error)?,
            welcome: None,
        })
    }

    /// Replaces this member's keys in the group: what was sealed before
    /// stays out of reach of anyone who later takes the new keys, and what
    /// is sealed after, of anyone who took the old ones.
    pub fn update(&mut self, id: &[u8]) -> Result<Commit, MailboxError> {
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self
            .groups
            .get_mut(id)
            .ok_or_else(|| group_error("this member is not in that group"))?;
        let (commit, _, _) = group
            .self_update(provider, signer, LeafNodeParameters::default())
            .map_err(group_error)?
            .into_messages();
        group.merge_pending_commit(provider).map_err(group_error)?;
        Ok(Commit {
            commit: commit.tls_serialize_detached().map_err(group_error)?,
            welcome: None,
        })
    }

    /// Seals `message` for every member of the group.
    pub fn seal(&mut self, id: &[u8], message: &[u8]) -> Result<Vec<u8>, MailboxError> {
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self
            .groups
            .get_mut(id)
            .ok_or_else(|| group_error("this member is not in that group"))?;
        group
            .create_message(provider, signer, message)
            .map_err(group_error)?
            .tls_serialize_detached()
            .map_err(group_error)
    }

    /// Opens an MLS message of one of this member's groups: a member's
    /// message, or a commit, which is applied.
    pub fn open(&mut self, message: &[u8]) -> Result<Opened, MailboxError> {
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(group_error)?
            .try_into_protocol_message()
            .map_err(group_error)?;
        let id = message.group_id().as_slice().to_vec();
        let provider = &self.provider;
        let group = self
            .groups
            .get_mut(&id)
            .ok_or_else(|| group_error("this member is not in that group"))?;
        let processed = group
            .process_message(provider, message)
            .map_err(group_error)?;
        let sender = did_of(processed.credential());
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok(Opened::Message {
                group: id,
                sender: sender.ok_or_else(|| group_error("the sender names no DID"))?,
                bytes: m.into_bytes(),
            }),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let removed = staged.self_removed();
                group
                    .merge_staged_commit(provider, *staged)
                    .map_err(group_error)?;
                if removed {
                    self.groups.remove(&id);
                    return Ok(Opened::Removed { group: id });
                }
                Ok(Opened::Changed {
                    group: id,
                    epoch: group.epoch().as_u64(),
                })
            }
            _ => Err(group_error("only commits and messages are taken")),
        }
    }

    /// The DIDs in the group, this member's included.
    pub fn members(&self, id: &[u8]) -> Result<Vec<String>, MailboxError> {
        Ok(self
            .group(id)?
            .members()
            .filter_map(|m| did_of(&m.credential))
            .collect())
    }

    /// The group's epoch: it moves on with every commit.
    pub fn epoch(&self, id: &[u8]) -> Result<u64, MailboxError> {
        Ok(self.group(id)?.epoch().as_u64())
    }
}
