//! Why the mailbox refused or could not serve a request.

use thiserror::Error;

/// A refused or failed mailbox request.
#[derive(Debug, Error)]
pub enum MailboxError {
    /// The sealed message is not padded to one of the sizes the operator
    /// takes.
    #[error("the sealed message is {size} bytes; pad it to one of {classes:?}")]
    SizeClass {
        /// Size offered.
        size: u64,
        /// The sizes the operator takes.
        classes: Vec<u64>,
    },
    /// The lifetime is zero or longer than the operator keeps mail.
    #[error("the lifetime is {lifetime_s} s; it must be 1..={max_s} s")]
    Lifetime {
        /// Lifetime asked for.
        lifetime_s: u64,
        /// The operator's limit.
        max_s: u64,
    },
    /// The recipient is not a DID the mailbox can hold mail for.
    #[error("the recipient is not a DID of 1..={max} bytes")]
    Recipient {
        /// Longest DID taken.
        max: usize,
    },
    /// The mailbox is serving as many requests as it takes at once.
    #[error("the mailbox is busy; retry later")]
    Busy,
    /// A mailbox this client asked could not be reached or did not answer
    /// as a mailbox does.
    #[error("the mailbox: {0}")]
    Remote(String),
    /// Key packages the mailbox cannot keep.
    #[error("key packages: {0}")]
    Prekeys(String),
    /// A depositor policy the mailbox cannot keep.
    #[error("policy: {0}")]
    Policy(String),
    /// A group session that could not be made, changed or read.
    #[cfg(feature = "mls")]
    #[error("group: {0}")]
    Group(String),
    /// A shared file that could not be sealed, opened or checked.
    #[cfg(feature = "files")]
    #[error("file: {0}")]
    Files(String),
    /// The recipient takes mail only from DIDs it named, and this deposit
    /// does not show it may.
    #[error("the recipient does not take mail from this depositor: {0}")]
    NotAllowed(String),
    /// The recipient already has as many messages waiting as the operator
    /// keeps for one recipient.
    #[error("the recipient's mailbox is full")]
    RecipientFull,
    /// The escrow already paid for this deposit, and the message was
    /// delivered or its lifetime ended.
    #[error("this deposit was already taken under its voucher")]
    Spent,
    /// The mailbox lost part of its record of recent requests and takes
    /// none of this kind until the window those records covered has passed.
    #[error("the mailbox is recovering its records; retry later")]
    Recovering,
    /// The operator's settings cannot be used.
    #[error("configuration: {0}")]
    Config(String),
    /// The operator's disk allowance for mail is used up.
    #[error("the mailbox is full")]
    Full,
    /// The payer deposited too often.
    #[error("too many deposits from this payer; retry later")]
    RateLimited,
    /// The voucher does not pay for the deposit.
    #[error("payment refused: {0}")]
    Unpaid(String),
    /// The caller did not prove it is the recipient.
    #[error("not authorized: {0}")]
    Unauthorized(String),
    /// The recipient has no such message.
    #[error("no such message")]
    NotFound,
    /// The ledger could not be read.
    #[error("ledger: {0}")]
    Ledger(String),
    /// The receipt could not be signed.
    #[error("signing: {0}")]
    Signing(String),
    /// The mailbox directory could not be read or written.
    #[error("store: {0}")]
    Store(String),
}

impl From<std::io::Error> for MailboxError {
    fn from(e: std::io::Error) -> Self {
        Self::Store(e.to_string())
    }
}
