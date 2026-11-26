//! The mailbox directory: the only state the service keeps.
//!
//! ```text
//! mail/<sha256(recipient did)>/<id>.bin    the sealed bytes
//! mail/<sha256(recipient did)>/<id>.json   the receipt; the message exists once this does
//! escrows/<escrow id>.json                 what the escrow owes, its highest voucher, the ids it paid for
//! policies/<sha256(recipient did)>.json    who may deposit for the recipient, when it set that
//! prekeys/<sha256(recipient did)>/<n>.bin  key packages, handed out oldest first
//! prekeys/<sha256(recipient did)>/last.bin the last-resort package, handed out when none is left
//! prekeys/<sha256(recipient did)>/served/  packages already paid for, kept an hour
//! recent.log                               nonces and deposit times still inside their windows
//! ```
//!
//! Every file is written under a temporary name, synced and renamed, and the
//! directory is synced after the rename, so a file that exists is whole and
//! stays after a power loss.
//!
//! A deposit is charged before its message is written: the escrow record
//! first names the deposit as pending, then the message is written, then the
//! mark is cleared. A mark that is still set when the escrow is next used, or
//! when the directory is opened, is settled first: if the deposit's receipt
//! exists the mark is cleared, and if it does not the charge is taken back.
//! A message whose deposit is still marked pending is unmarked before it is
//! dropped, so a missing receipt always means the deposit never completed.
//!
//! An escrow record keeps the id of every deposit it paid for, so a deposit
//! that was delivered or expired cannot be offered again under the same
//! voucher. The record is dropped once the escrow's lifetime has passed: no
//! voucher on it pays for a deposit after that, so nothing can be replayed.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tenzro_types::payment_authorization::EscrowVoucher;

use crate::error::MailboxError;
use crate::service::HOUR_MS;
use crate::wire::{DepositPolicy, Receipt};

/// A deposit that is charged and whose message may not be written yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Pending {
    id: String,
    recipient_did: String,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    charge: u128,
}

/// A recipient's depositor policy and the epoch it was set at.
#[derive(Debug, Serialize, Deserialize)]
struct PolicyRecord {
    policy: DepositPolicy,
    epoch: u64,
}

/// What one escrow owes the mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowAccount {
    /// The highest voucher the payer signed.
    pub voucher: EscrowVoucher,
    /// Total charged for deposits, in wei: the cumulative amount the mailbox
    /// claims under `voucher`.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub charged: u128,
    pub(crate) pending: Option<Pending>,
    /// The id of every deposit the escrow paid for, held or since dropped.
    pub(crate) taken: BTreeSet<String>,
    /// Unix milliseconds the escrow ends, as the ledger had it.
    pub expires_at_ms: u64,
}

impl EscrowAccount {
    /// Whether the escrow already paid for the deposit `id`.
    pub(crate) fn took(&self, id: &str) -> bool {
        self.taken.contains(id)
    }
}

/// What the mailbox remembers of recent requests.
#[derive(Debug, Default)]
pub(crate) struct Recent {
    /// Nonces accepted, with the time each was signed.
    pub(crate) nonces: HashMap<[u8; 16], u64>,
    /// When each payer account deposited or fetched a key package.
    pub(crate) deposits: HashMap<[u8; 32], VecDeque<u64>>,
    /// When a key package of each recipient (by the SHA-256 of its DID) was
    /// handed out.
    pub(crate) fetches: HashMap<[u8; 32], VecDeque<u64>>,
    /// Recipients' requests are refused until this time: part of the record
    /// of accepted nonces was lost, so a replay could not be told apart.
    pub(crate) auth_closed_until_ms: u64,
    /// Deposits are refused until this time: part of the record of deposit
    /// times was lost, so the hourly counts cannot be trusted.
    pub(crate) deposits_closed_until_ms: u64,
}

impl Recent {
    /// How many times `payer` deposited in the hour before `now_ms`.
    pub(crate) fn count(&self, payer: &[u8; 32], now_ms: u64) -> usize {
        self.deposits.get(payer).map_or(0, |times| {
            times.iter().filter(|t| *t + HOUR_MS > now_ms).count()
        })
    }

    /// How many records it holds.
    pub(crate) fn len(&self) -> usize {
        self.nonces.len()
            + self.deposits.values().map(VecDeque::len).sum::<usize>()
            + self.fetches.values().map(VecDeque::len).sum::<usize>()
    }
}

/// The mailbox directory.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    total_bytes: u64,
    /// Bytes of key packages and depositor policies held, whoever they are
    /// for.
    key_bytes: AtomicU64,
    recent: fs::File,
    recent_lines: usize,
}

/// Makes a rename or removal inside `dir` durable. Only Unix lets a
/// directory be synced; elsewhere the rename is as durable as the file
/// system makes it.
fn sync_dir(dir: &Path) -> Result<(), MailboxError> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn parent(path: &Path) -> &Path {
    path.parent().unwrap_or(Path::new("."))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), MailboxError> {
    #[cfg(test)]
    if faults::next_write_fails() {
        return Err(MailboxError::Store(format!(
            "{}: write made to fail",
            path.display()
        )));
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let written = fs::File::create(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    });
    if let Err(e) = written {
        // Best effort: whatever stays is removed when the directory is opened.
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    sync_dir(parent(path))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, MailboxError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| MailboxError::Store(format!("{}: {e}", path.display())))
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, MailboxError> {
    serde_json::to_vec(value).map_err(|e| MailboxError::Store(e.to_string()))
}

/// Removes `path` if it is there and returns how many bytes it held.
fn remove_if_present(path: &Path) -> Result<u64, MailboxError> {
    let size = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    fs::remove_file(path)?;
    sync_dir(parent(path))?;
    Ok(size)
}

fn has_extension(path: &Path, extension: &str) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some(extension)
}

/// Whether `id` is a message id: 32 lowercase hex characters, so it names a
/// file and nothing else.
fn is_entry_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn open_recent(root: &Path) -> Result<fs::File, MailboxError> {
    Ok(fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("recent.log"))?)
}

impl Store {
    /// Opens the directory at `root`, creating it if absent, and finishes
    /// what an interrupted deposit left behind.
    pub fn open(root: &Path) -> Result<Self, MailboxError> {
        fs::create_dir_all(root.join("mail"))?;
        fs::create_dir_all(root.join("escrows"))?;
        fs::create_dir_all(root.join("policies"))?;
        fs::create_dir_all(root.join("prekeys"))?;
        remove_if_present(&root.join("recent.log.tmp"))?;
        let mut store = Self {
            root: root.to_path_buf(),
            total_bytes: 0,
            key_bytes: AtomicU64::new(0),
            recent: open_recent(root)?,
            recent_lines: 0,
        };
        for dir in store.recipient_dirs()? {
            for file in fs::read_dir(&dir)? {
                let path = file?.path();
                let whole_message = (has_extension(&path, "bin")
                    && path.with_extension("json").exists())
                    || (has_extension(&path, "json") && path.with_extension("bin").exists());
                if whole_message {
                    store.total_bytes += fs::metadata(&path)?.len();
                } else if has_extension(&path, "bin") || has_extension(&path, "tmp") {
                    fs::remove_file(&path)?;
                }
            }
            // Fails, as it should, for a directory that still holds mail.
            let _ = fs::remove_dir(&dir);
        }
        for file in fs::read_dir(root.join("escrows"))? {
            let path = file?.path();
            if has_extension(&path, "tmp") {
                fs::remove_file(&path)?;
            }
        }
        store.accounts()?;
        store.key_bytes = AtomicU64::new(store.scan_key_bytes()?);
        Ok(store)
    }

    /// Adds up the key packages and policies on disk. A package that was
    /// handed out waits aside for its fetch to be repeated and is not counted.
    fn scan_key_bytes(&self) -> Result<u64, MailboxError> {
        let mut total = 0;
        for dir in fs::read_dir(self.root.join("prekeys"))? {
            let dir = dir?.path();
            if dir.is_dir() {
                for file in fs::read_dir(&dir)? {
                    let path = file?.path();
                    if path.is_file() {
                        total += fs::metadata(&path)?.len();
                    }
                }
            }
        }
        for file in fs::read_dir(self.root.join("policies"))? {
            total += fs::metadata(file?.path())?.len();
        }
        Ok(total)
    }

    /// Refuses `incoming` more bytes of keys or policies when they would
    /// take those held past `max_key_bytes`.
    fn room_for_keys(&self, incoming: u64, max_key_bytes: u64) -> Result<(), MailboxError> {
        if self
            .key_bytes
            .load(Ordering::Relaxed)
            .saturating_add(incoming)
            > max_key_bytes
        {
            return Err(MailboxError::Full);
        }
        Ok(())
    }

    /// The directories that hold recipients' mail. Anything else found
    /// beside them is left alone.
    fn recipient_dirs(&self) -> Result<Vec<PathBuf>, MailboxError> {
        let mut dirs = Vec::new();
        for entry in fs::read_dir(self.root.join("mail"))? {
            let path = entry?.path();
            if path.is_dir() {
                dirs.push(path);
            }
        }
        Ok(dirs)
    }

    fn recipient_dir(&self, recipient_did: &str) -> PathBuf {
        self.root
            .join("mail")
            .join(hex::encode(Sha256::digest(recipient_did.as_bytes())))
    }

    fn policy_path(&self, recipient_did: &str) -> PathBuf {
        self.root.join("policies").join(format!(
            "{}.json",
            hex::encode(Sha256::digest(recipient_did.as_bytes()))
        ))
    }

    /// Who may deposit for `recipient_did`, and the epoch of that policy:
    /// anyone who pays at epoch 0, unless it set otherwise.
    pub fn policy(&self, recipient_did: &str) -> Result<(DepositPolicy, u64), MailboxError> {
        let kept: Option<PolicyRecord> = read_json(&self.policy_path(recipient_did))?;
        Ok(kept.map_or((DepositPolicy::Anyone, 0), |k| (k.policy, k.epoch)))
    }

    /// Records who may deposit for `recipient_did`, under the next epoch,
    /// and returns that epoch.
    pub fn set_policy(
        &self,
        recipient_did: &str,
        policy: &DepositPolicy,
        max_key_bytes: u64,
    ) -> Result<u64, MailboxError> {
        let (_, epoch) = self.policy(recipient_did)?;
        let record = PolicyRecord {
            policy: policy.clone(),
            epoch: epoch + 1,
        };
        let path = self.policy_path(recipient_did);
        let json = to_json(&record)?;
        let before = fs::metadata(&path).map_or(0, |m| m.len());
        self.room_for_keys((json.len() as u64).saturating_sub(before), max_key_bytes)?;
        write_atomic(&path, &json)?;
        self.key_bytes
            .fetch_add(json.len() as u64, Ordering::Relaxed);
        self.key_bytes.fetch_sub(before, Ordering::Relaxed);
        Ok(record.epoch)
    }

    fn prekey_dir(&self, recipient_did: &str) -> PathBuf {
        self.root
            .join("prekeys")
            .join(hex::encode(Sha256::digest(recipient_did.as_bytes())))
    }

    /// The numbered key packages held in `dir`, oldest first.
    fn prekey_files(dir: &Path) -> Result<Vec<(u64, PathBuf)>, MailboxError> {
        let mut files = Vec::new();
        if !dir.exists() {
            return Ok(files);
        }
        for file in fs::read_dir(dir)? {
            let path = file?.path();
            if has_extension(&path, "bin")
                && let Some(n) = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            {
                files.push((n, path));
            }
        }
        files.sort();
        Ok(files)
    }

    /// How many key packages are held for `recipient_did`, the last-resort
    /// one aside.
    pub fn prekey_count(&self, recipient_did: &str) -> Result<usize, MailboxError> {
        Ok(Self::prekey_files(&self.prekey_dir(recipient_did))?.len())
    }

    /// Adds `packages` after those held for `recipient_did`, and replaces
    /// its last-resort package when one is given.
    pub fn add_prekeys(
        &self,
        recipient_did: &str,
        packages: &[Vec<u8>],
        last_resort: Option<&[u8]>,
        max_key_bytes: u64,
    ) -> Result<(), MailboxError> {
        let dir = self.prekey_dir(recipient_did);
        let last_before = fs::metadata(dir.join("last.bin")).map_or(0, |m| m.len());
        let incoming = packages.iter().map(|p| p.len() as u64).sum::<u64>()
            + last_resort.map_or(0, |l| (l.len() as u64).saturating_sub(last_before));
        self.room_for_keys(incoming, max_key_bytes)?;
        fs::create_dir_all(dir.join("served"))?;
        let first = Self::prekey_files(&dir)?.last().map_or(0, |(n, _)| n + 1);
        for (n, package) in (first..).zip(packages) {
            write_atomic(&dir.join(format!("{n:020}.bin")), package)?;
            self.key_bytes
                .fetch_add(package.len() as u64, Ordering::Relaxed);
        }
        if let Some(last) = last_resort {
            write_atomic(&dir.join("last.bin"), last)?;
            self.key_bytes
                .fetch_add(last.len() as u64, Ordering::Relaxed);
            self.key_bytes.fetch_sub(last_before, Ordering::Relaxed);
        }
        Ok(())
    }

    /// The package already handed out for `fetch_id`, and whether it is the
    /// last-resort one, if it was handed out.
    pub fn served_prekey(
        &self,
        recipient_did: &str,
        fetch_id: &str,
    ) -> Result<Option<(Vec<u8>, bool)>, MailboxError> {
        if !is_entry_id(fetch_id) {
            return Ok(None);
        }
        let served = self.prekey_dir(recipient_did).join("served");
        for (extension, last_resort) in [("bin", false), ("last", true)] {
            match fs::read(served.join(format!("{fetch_id}.{extension}"))) {
                Ok(bytes) => return Ok(Some((bytes, last_resort))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }

    /// Hands out one key package of `recipient_did` for `fetch_id`: the
    /// oldest one, moved aside so nobody else gets it, or a copy of the
    /// last-resort one when none is left. Returns the package and whether it
    /// is the last-resort one, or `None` when the recipient has neither.
    pub fn take_prekey(
        &self,
        recipient_did: &str,
        fetch_id: &str,
    ) -> Result<Option<(Vec<u8>, bool)>, MailboxError> {
        if !is_entry_id(fetch_id) {
            return Ok(None);
        }
        let dir = self.prekey_dir(recipient_did);
        let served = dir.join("served");
        fs::create_dir_all(&served)?;
        if let Some((_, oldest)) = Self::prekey_files(&dir)?.into_iter().next() {
            let to = served.join(format!("{fetch_id}.bin"));
            let len = fs::metadata(&oldest)?.len();
            fs::rename(&oldest, &to)?;
            self.key_bytes.fetch_sub(len, Ordering::Relaxed);
            sync_dir(&dir)?;
            sync_dir(&served)?;
            return Ok(Some((fs::read(&to)?, false)));
        }
        match fs::read(dir.join("last.bin")) {
            Ok(bytes) => {
                write_atomic(&served.join(format!("{fetch_id}.last")), &bytes)?;
                Ok(Some((bytes, true)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Charges the escrow `charged` in total under `voucher` for the request
    /// `id`, which it then counts as taken.
    pub fn charge(
        &self,
        previous: Option<&EscrowAccount>,
        voucher: EscrowVoucher,
        charged: u128,
        id: &str,
        escrow_expires_at_ms: u64,
    ) -> Result<(), MailboxError> {
        let mut taken = previous.map(|p| p.taken.clone()).unwrap_or_default();
        taken.insert(id.to_string());
        self.write_account(&EscrowAccount {
            voucher,
            charged,
            pending: None,
            taken,
            expires_at_ms: escrow_expires_at_ms,
        })
    }

    /// Drops key packages handed out more than an hour before `now_ms`, by
    /// the time their file was written.
    fn sweep_served(&self, now_ms: u64) -> Result<(), MailboxError> {
        for dir in fs::read_dir(self.root.join("prekeys"))? {
            let served = dir?.path().join("served");
            if !served.is_dir() {
                continue;
            }
            for file in fs::read_dir(&served)? {
                let path = file?.path();
                let written_ms = fs::metadata(&path)?
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as u64);
                if written_ms + HOUR_MS <= now_ms
                    && let Err(e) = remove_if_present(&path)
                {
                    tracing::warn!("{} could not be dropped: {e}", path.display());
                }
            }
        }
        Ok(())
    }

    fn receipt_path(&self, recipient_did: &str, id: &str) -> PathBuf {
        self.recipient_dir(recipient_did).join(format!("{id}.json"))
    }

    fn account_path(&self, escrow_id: &str) -> PathBuf {
        self.root.join("escrows").join(format!("{escrow_id}.json"))
    }

    /// Writes an escrow's record.
    fn write_account(&self, account: &EscrowAccount) -> Result<(), MailboxError> {
        let path = self.account_path(&hex::encode(account.voucher.escrow_id));
        write_atomic(&path, &to_json(account)?)
    }

    /// Settles a pending mark left on `account`: cleared if the deposit's
    /// receipt exists, and the charge taken back if it does not. The record
    /// is written back before anything else is done with it.
    fn settle(&self, mut account: EscrowAccount) -> Result<EscrowAccount, MailboxError> {
        let Some(pending) = account.pending.take() else {
            return Ok(account);
        };
        if !self
            .receipt_path(&pending.recipient_did, &pending.id)
            .exists()
        {
            account.charged = account.charged.saturating_sub(pending.charge);
            account.taken.remove(&pending.id);
        }
        self.write_account(&account)?;
        Ok(account)
    }

    /// The receipt of `recipient_did`'s message `id`, if held.
    pub fn entry(&self, recipient_did: &str, id: &str) -> Result<Option<Receipt>, MailboxError> {
        if !is_entry_id(id) {
            return Ok(None);
        }
        read_json(&self.receipt_path(recipient_did, id))
    }

    /// The receipt files in `dir`.
    fn receipt_files(dir: &Path) -> Result<Vec<PathBuf>, MailboxError> {
        let mut files = Vec::new();
        for file in fs::read_dir(dir)? {
            let path = file?.path();
            if has_extension(&path, "json") {
                files.push(path);
            }
        }
        Ok(files)
    }

    /// How many messages are held for `recipient_did`.
    pub fn count(&self, recipient_did: &str) -> Result<usize, MailboxError> {
        let dir = self.recipient_dir(recipient_did);
        if !dir.exists() {
            return Ok(0);
        }
        Ok(Self::receipt_files(&dir)?.len())
    }

    /// The receipts of every message held for `recipient_did`, oldest first.
    /// A receipt that cannot be read is skipped and logged, so one damaged
    /// file does not hide a recipient's other mail.
    pub fn entries(&self, recipient_did: &str) -> Result<Vec<Receipt>, MailboxError> {
        let dir = self.recipient_dir(recipient_did);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries: Vec<Receipt> = Vec::new();
        for path in Self::receipt_files(&dir)? {
            match read_json(&path) {
                Ok(Some(receipt)) => entries.push(receipt),
                Ok(None) => {}
                Err(e) => tracing::warn!("skipping an unreadable receipt: {e}"),
            }
        }
        entries.sort_by(|a, b| (a.deposited_at_ms, &a.id).cmp(&(b.deposited_at_ms, &b.id)));
        Ok(entries)
    }

    /// The sealed bytes of the message `receipt` names.
    pub fn sealed(&self, receipt: &Receipt) -> Result<Vec<u8>, MailboxError> {
        let path = self
            .receipt_path(&receipt.recipient_did, &receipt.id)
            .with_extension("bin");
        Ok(fs::read(path)?)
    }

    /// Removes the two files of a message and returns the bytes they held.
    /// Both removals are tried even if the first fails.
    fn remove_message(&self, receipt_path: &Path) -> Result<u64, MailboxError> {
        let receipt = remove_if_present(receipt_path);
        let sealed = remove_if_present(&receipt_path.with_extension("bin"));
        // Fails, as it should, while the recipient has other mail.
        let _ = fs::remove_dir(parent(receipt_path));
        Ok(receipt? + sealed?)
    }

    /// What the escrow `escrow_id` (hex) owes, if it paid for anything, with
    /// any pending mark settled.
    pub fn account(&self, escrow_id: &str) -> Result<Option<EscrowAccount>, MailboxError> {
        read_json::<EscrowAccount>(&self.account_path(escrow_id))?
            .map(|account| self.settle(account))
            .transpose()
    }

    /// Every escrow that paid for a deposit, with any pending mark settled.
    pub fn accounts(&self) -> Result<Vec<EscrowAccount>, MailboxError> {
        let mut accounts = Vec::new();
        for file in fs::read_dir(self.root.join("escrows"))? {
            let path = file?.path();
            if has_extension(&path, "json")
                && let Some(account) = read_json::<EscrowAccount>(&path)?
            {
                accounts.push(self.settle(account)?);
            }
        }
        Ok(accounts)
    }

    /// Charges the escrow `charged` in total under `voucher` and keeps the
    /// message, unless that would take the mail held past `max_total_bytes`.
    /// `previous` is the escrow's settled record before this deposit; it is
    /// put back if the message cannot be written. If putting it back fails
    /// too, the pending mark stays and is settled when the escrow is next
    /// used.
    pub fn insert(
        &mut self,
        receipt: &Receipt,
        sealed: &[u8],
        previous: Option<&EscrowAccount>,
        voucher: EscrowVoucher,
        charged: u128,
        escrow_expires_at_ms: u64,
        max_total_bytes: u64,
    ) -> Result<(), MailboxError> {
        let receipt_json = to_json(receipt)?;
        let size = (sealed.len() + receipt_json.len()) as u64;
        if self.total_bytes + size > max_total_bytes {
            return Err(MailboxError::Full);
        }
        let mut taken = previous.map(|p| p.taken.clone()).unwrap_or_default();
        taken.insert(receipt.id.clone());
        let mut account = EscrowAccount {
            voucher,
            charged,
            pending: Some(Pending {
                id: receipt.id.clone(),
                recipient_did: receipt.recipient_did.clone(),
                charge: receipt.charge,
            }),
            taken,
            expires_at_ms: escrow_expires_at_ms,
        };
        self.write_account(&account)?;
        let receipt_path = self.receipt_path(&receipt.recipient_did, &receipt.id);
        let written = fs::create_dir_all(parent(&receipt_path))
            .map_err(MailboxError::from)
            .and_then(|()| write_atomic(&receipt_path.with_extension("bin"), sealed))
            .and_then(|()| write_atomic(&receipt_path, &receipt_json));
        if let Err(e) = written {
            let message_gone = self.remove_message(&receipt_path).map(|_| ());
            let charge_undone = match previous {
                Some(previous) => self.write_account(previous),
                None => remove_if_present(&self.account_path(&receipt.escrow_id)).map(|_| ()),
            };
            if let Err(undo) = message_gone.and(charge_undone) {
                tracing::warn!(
                    "deposit {} failed and its charge stays marked pending until its escrow is next used: {undo}",
                    receipt.id
                );
            }
            return Err(e);
        }
        self.total_bytes += size;
        account.pending = None;
        if let Err(e) = self.write_account(&account) {
            tracing::warn!(
                "deposit {} is held and charged; its pending mark is cleared when its escrow is next used: {e}",
                receipt.id
            );
        }
        Ok(())
    }

    /// Drops the message `receipt` names. Its escrow keeps the message's id.
    pub fn remove(&mut self, receipt: &Receipt) -> Result<(), MailboxError> {
        // Reading the record settles a pending mark, this message's included.
        self.account(&receipt.escrow_id)?;
        let freed = self.remove_message(&self.receipt_path(&receipt.recipient_did, &receipt.id))?;
        self.total_bytes = self.total_bytes.saturating_sub(freed);
        Ok(())
    }

    /// Drops every message whose lifetime ended by `now_ms`, every receipt
    /// that cannot be read together with its sealed bytes, and the record of
    /// every escrow that ended by `now_ms`. Returns how many messages were
    /// dropped. A message that cannot be dropped is logged and left for the
    /// next sweep.
    pub fn sweep(&mut self, now_ms: u64) -> Result<usize, MailboxError> {
        // Every pending mark is settled first, while each message it names
        // is still there to show it was written.
        for account in self.accounts()? {
            if account.expires_at_ms <= now_ms {
                let path = self.account_path(&hex::encode(account.voucher.escrow_id));
                if let Err(e) = remove_if_present(&path) {
                    tracing::warn!("{} could not be dropped: {e}", path.display());
                }
            }
        }
        self.sweep_served(now_ms)?;
        let mut dropped = 0;
        for dir in self.recipient_dirs()? {
            for path in Self::receipt_files(&dir)? {
                let removed = match read_json::<Receipt>(&path) {
                    Ok(Some(receipt)) if receipt.expires_at_ms <= now_ms => self.remove(&receipt),
                    Ok(_) => continue,
                    Err(e) => {
                        tracing::warn!("dropping an unreadable receipt and its message: {e}");
                        self.remove_message(&path).map(|freed| {
                            self.total_bytes = self.total_bytes.saturating_sub(freed);
                        })
                    }
                };
                match removed {
                    Ok(()) => dropped += 1,
                    Err(e) => tracing::warn!("{} could not be dropped: {e}", path.display()),
                }
            }
        }
        Ok(dropped)
    }

    fn record(&mut self, line: &str) -> Result<(), MailboxError> {
        self.recent.write_all(line.as_bytes())?;
        self.recent.sync_data()?;
        self.recent_lines += 1;
        Ok(())
    }

    /// Records that `nonce`, signed at `signed_at_ms`, was accepted.
    pub(crate) fn record_nonce(
        &mut self,
        nonce: &[u8; 16],
        signed_at_ms: u64,
    ) -> Result<(), MailboxError> {
        self.record(&format!("n {} {signed_at_ms}\n", hex::encode(nonce)))
    }

    /// Records that the account `payer` deposited at `at_ms`.
    pub(crate) fn record_deposit(
        &mut self,
        payer: &[u8; 32],
        at_ms: u64,
    ) -> Result<(), MailboxError> {
        self.record(&format!("d {} {at_ms}\n", hex::encode(payer)))
    }

    /// Records that a key package of the recipient whose DID hashes to
    /// `recipient` was handed out at `at_ms`.
    pub(crate) fn record_fetch(
        &mut self,
        recipient: &[u8; 32],
        at_ms: u64,
    ) -> Result<(), MailboxError> {
        self.record(&format!("f {} {at_ms}\n", hex::encode(recipient)))
    }

    /// What the log of recent requests holds, and how many of its lines
    /// could not be read: each of those is a record that is lost.
    pub(crate) fn recent(&self) -> Result<(Recent, usize), MailboxError> {
        let mut recent = Recent::default();
        let mut damaged = 0;
        let bytes = fs::read(self.root.join("recent.log"))?;
        for line in String::from_utf8_lossy(&bytes).lines() {
            let mut parts = line.split(' ');
            let fields = (parts.next(), parts.next(), parts.next(), parts.next());
            let (Some(kind), Some(key), Some(Ok(at)), None) = (
                fields.0,
                fields.1,
                fields.2.map(str::parse::<u64>),
                fields.3,
            ) else {
                damaged += 1;
                continue;
            };
            match (kind, hex::decode(key)) {
                ("n", Ok(nonce)) if nonce.len() == 16 => {
                    recent
                        .nonces
                        .insert(nonce.try_into().expect("16 bytes"), at);
                }
                ("d", Ok(payer)) if payer.len() == 32 => recent
                    .deposits
                    .entry(payer.try_into().expect("32 bytes"))
                    .or_default()
                    .push_back(at),
                ("f", Ok(recipient)) if recipient.len() == 32 => recent
                    .fetches
                    .entry(recipient.try_into().expect("32 bytes"))
                    .or_default()
                    .push_back(at),
                ("c", _) if key == "auth" => recent.auth_closed_until_ms = at,
                ("c", _) if key == "deposits" => recent.deposits_closed_until_ms = at,
                _ => damaged += 1,
            }
        }
        Ok((recent, damaged))
    }

    /// How many records the log holds, live or not.
    pub(crate) fn recent_lines(&self) -> usize {
        self.recent_lines
    }

    /// Rewrites the log to hold exactly `recent`.
    pub(crate) fn compact_recent(&mut self, recent: &Recent) -> Result<(), MailboxError> {
        let mut text = format!(
            "c auth {}\nc deposits {}\n",
            recent.auth_closed_until_ms, recent.deposits_closed_until_ms
        );
        for (nonce, at) in &recent.nonces {
            text.push_str(&format!("n {} {at}\n", hex::encode(nonce)));
        }
        for (kind, times) in [("d", &recent.deposits), ("f", &recent.fetches)] {
            for (key, times) in times {
                for at in times {
                    text.push_str(&format!("{kind} {} {at}\n", hex::encode(key)));
                }
            }
        }
        write_atomic(&self.root.join("recent.log"), text.as_bytes())?;
        self.recent = open_recent(&self.root)?;
        self.recent_lines = text.lines().count();
        Ok(())
    }
}

/// Lets a test make chosen writes fail: `fail_writes(&[0, 2])` fails the
/// next write and the third one from now on this thread.
#[cfg(test)]
pub(crate) mod faults {
    use std::cell::{Cell, RefCell};

    thread_local! {
        static WRITES: Cell<u64> = const { Cell::new(0) };
        static FAILING: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn fail_writes(offsets: &[u64]) {
        let now = WRITES.with(Cell::get);
        FAILING.with(|f| *f.borrow_mut() = offsets.iter().map(|o| now + o).collect());
    }

    pub(super) fn next_write_fails() -> bool {
        let index = WRITES.with(|w| w.replace(w.get() + 1));
        FAILING.with(|f| f.borrow().contains(&index))
    }
}
