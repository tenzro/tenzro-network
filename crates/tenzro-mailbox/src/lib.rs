//! Store-and-forward mailbox for Tenzro Network.
//!
//! Preview: the interface and the stored format may change before the stable
//! release.
//!
//! A sender hands a sealed message to a mailbox for a recipient who is
//! offline; the recipient collects it later from any of its devices. An
//! operator runs the mailbox beside its node, as its own process: a node
//! links none of this crate and carries no mailbox state.
//!
//! - **Who may collect.** The recipient: a request signed by the key its DID
//!   resolves to, or by a passkey its account's keystore links. Collecting leaves the message
//!   in place; only the recipient's acknowledgement, or the end of the
//!   lifetime the sender paid for, drops it.
//! - **Which signatures count.** A recipient's list, collect and
//!   acknowledge requests, and the operator's receipts, are checked against
//!   the signer's keys as the ledger records them: a key with an ML-DSA-65
//!   key enrolled must sign with both its P-256 and its ML-DSA-65 key, and a
//!   key with none enrolled is accepted on its P-256 signature alone. A
//!   payer's voucher always carries both signatures, as the ledger requires
//!   of every voucher it pays.
//! - **Who may deposit.** Whoever pays, unless the recipient named the DIDs
//!   it takes mail from ([`DepositPolicy`]); then a deposit also proves it
//!   comes from one of them ([`SenderProof`]), or carries the recipient's
//!   signed leave for its holder or for a named depositor ([`Capability`]).
//!   Every deposit carries a voucher on an
//!   escrow the payer funded on the ledger for the mailbox's account; the
//!   mailbox checks the voucher against the escrow and claims what its
//!   deposits cost. The price is the operator's rate per byte per hour.
//!   Each voucher is bound to one deposit, so a voucher someone else sees
//!   pays for nothing else. A voucher promises a total: a payer who signs
//!   for more than its deposits cost can be claimed against for that
//!   difference, as on any escrow, so it signs for the exact running total.
//! - **What the operator holds.** The sealed bytes and one receipt per
//!   message, in one directory. Nothing is in consensus state.
//! - **What the operator learns.** The payer's account, the recipient's DID,
//!   the size class of each message and when it was deposited, collected and
//!   acknowledged. It does not learn the content, and it learns the sender
//!   only as far as the paying account names one. Sender anonymity is not
//!   promised: a sender who wants its deposits unlinked pays each
//!   conversation from a fresh funded account.
//!
//! A recipient names its mailboxes in its DID document as services of type
//! [`MAILBOX_SERVICE_TYPE`], each endpoint pinning the digest of the operator
//! key that signs the mailbox's receipts ([`mailbox_endpoint`],
//! [`mailboxes_in`], [`MailboxClient::connect`], [`Receipt::verify`]).

mod client;
mod discovery;
mod error;
#[cfg(feature = "files")]
mod files;
#[cfg(feature = "mls")]
mod group;
mod http;
mod prekeys;
mod rpc_ledger;
mod service;
mod store;
mod wire;

pub use client::{Collected, DepositRequest, MailboxClient, Terms, sign_voucher, size_class_for};
pub use discovery::{
    MAILBOX_SERVICE_TYPE, MailboxEntry, mailbox_endpoint, mailboxes_in, operator_key_digest,
};
pub use error::MailboxError;
#[cfg(feature = "files")]
pub use files::{
    FILE_STANZA_TAG, RecipientCard, ShareManifest, SharedFile, VerifiedRecipient,
    open as open_file, recipient_card_preimage, reshare, share, share_manifest_preimage,
};
#[cfg(feature = "mls")]
pub use group::{
    Commit, GROUP_CIPHERSUITE, GroupMember, MemberPackage, Opened, VerifiedPackage,
    member_package_preimage,
};
pub use http::{HttpLimits, router, serve};
pub use prekeys::Prekey;
pub use rpc_ledger::RpcLedger;
pub use service::{
    CLAIM_GAS_PER_VOUCHER, EscrowView, Ledger, Mailbox, MailboxConfig, MailboxInfo, SigningKey,
    claim_gas,
};
pub use store::EscrowAccount;
pub use wire::{
    Action, Auth, Capability, Deposit, DepositPolicy, PrekeyFetch, Receipt, SenderProof,
    TAG_PREFIX, auth_preimage, deposit_binding, fetch_binding, prekeys_digest, recipient_tag,
    sender_preimage, tag_key_bytes,
};

#[cfg(test)]
mod tests;
