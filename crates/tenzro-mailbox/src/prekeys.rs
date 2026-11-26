//! Key packages: what lets a sender start an end-to-end session with a
//! recipient that is offline.
//!
//! A recipient uploads a batch of signed, opaque key packages and one
//! last-resort package. A sender pays for one package at a time: it gets the
//! oldest one, which nobody else gets, or the last-resort one once none is
//! left. The mailbox never reads a package. So that nobody can use up a
//! recipient's packages to leave it on the reusable last-resort one, each
//! fetch is paid, counts against its payer's hourly allowance, and the
//! packages of one recipient are handed out at most so many times an hour,
//! whoever pays.

use sha2::{Digest, Sha256};
use tenzro_types::did_services::MAX_DID_LEN;

use crate::error::MailboxError;
use crate::service::{HOUR_MS, Mailbox, highest, total_after};
use crate::wire::{Action, Auth, PrekeyFetch, fetch_binding, prekeys_digest};

/// One handed-out key package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prekey {
    /// The package as the recipient uploaded it.
    pub package: Vec<u8>,
    /// Whether it is the recipient's last-resort package, which others may
    /// have received too.
    pub last_resort: bool,
}

/// The id a fetch is known by: its escrow and its binding.
fn fetch_id(escrow_id: &[u8; 32], binding: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"tenzro/mailbox/v1/fetch-id");
    h.update(escrow_id);
    h.update(binding);
    hex::encode(&h.finalize()[..16])
}

impl Mailbox {
    /// Adds the recipient's `packages` after those held, and replaces its
    /// last-resort package when one is given. Returns how many packages are
    /// held.
    pub async fn upload_prekeys(
        &self,
        auth: &Auth,
        packages: &[Vec<u8>],
        last_resort: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<usize, MailboxError> {
        let max = self.config.max_prekey_bytes;
        if packages
            .iter()
            .map(Vec::as_slice)
            .chain(last_resort)
            .any(|p| p.is_empty() || p.len() > max)
        {
            return Err(MailboxError::Prekeys(format!(
                "a package must be 1..={max} bytes"
            )));
        }
        let held = self.state.lock().store.prekey_count(&auth.did)?;
        if held + packages.len() > self.config.max_prekeys_per_recipient {
            return Err(MailboxError::Prekeys(format!(
                "at most {} packages are kept for a recipient, and {held} are held",
                self.config.max_prekeys_per_recipient
            )));
        }
        self.authorize(
            Action::Prekeys,
            auth,
            &prekeys_digest(packages, last_resort),
            now_ms,
        )
        .await?;
        let state = self.state.lock();
        state.store.add_prekeys(
            &auth.did,
            packages,
            last_resort,
            self.config.max_key_bytes_total,
        )?;
        state.store.prekey_count(&auth.did)
    }

    /// Hands out one of the recipient's key packages for the request
    /// `fetch`, once its voucher pays for it. The same request again returns
    /// the same package and charges nothing.
    pub async fn fetch_prekey(
        &self,
        fetch: &PrekeyFetch,
        now_ms: u64,
    ) -> Result<Prekey, MailboxError> {
        let recipient = &fetch.recipient_did;
        if recipient.is_empty() || recipient.len() > MAX_DID_LEN {
            return Err(MailboxError::Recipient { max: MAX_DID_LEN });
        }
        let voucher = &fetch.voucher;
        let binding = fetch_binding(&self.signer.public_key().p256, recipient, &fetch.nonce);
        let escrow = self.check_voucher(voucher, &binding, now_ms).await?;
        let id = fetch_id(&voucher.escrow_id, &binding);
        let recipient_key: [u8; 32] = Sha256::digest(recipient.as_bytes()).into();

        let mut state = self.state.lock();
        let account = state.store.account(&hex::encode(voucher.escrow_id))?;
        if account.as_ref().is_some_and(|a| a.took(&id)) {
            return match state.store.served_prekey(recipient, &id)? {
                Some((package, last_resort)) => Ok(Prekey {
                    package,
                    last_resort,
                }),
                None => Err(MailboxError::Spent),
            };
        }
        if now_ms < state.recent.deposits_closed_until_ms {
            return Err(MailboxError::Recovering);
        }
        if state.recent.count(&escrow.payer, now_ms) >= self.config.max_deposits_per_payer_per_hour
        {
            return Err(MailboxError::RateLimited);
        }
        let handed_out = state.recent.fetches.get(&recipient_key).map_or(0, |times| {
            times.iter().filter(|t| *t + HOUR_MS > now_ms).count()
        });
        if handed_out >= self.config.max_fetches_per_recipient_per_hour {
            return Err(MailboxError::RateLimited);
        }
        let charged = total_after(account.as_ref(), &escrow, voucher, self.config.prekey_price)?;
        // A package moved aside by an earlier attempt of this request that
        // was not charged is handed out again rather than a new one.
        let (package, last_resort) = match state.store.served_prekey(recipient, &id)? {
            Some(served) => served,
            None => state
                .store
                .take_prekey(recipient, &id)?
                .ok_or(MailboxError::NotFound)?,
        };
        state.store.charge(
            account.as_ref(),
            highest(account.as_ref(), voucher),
            charged,
            &id,
            escrow.expires_at_ms,
        )?;
        state
            .recent
            .deposits
            .entry(escrow.payer)
            .or_default()
            .push_back(now_ms);
        state.store.record_deposit(&escrow.payer, now_ms)?;
        state
            .recent
            .fetches
            .entry(recipient_key)
            .or_default()
            .push_back(now_ms);
        state.store.record_fetch(&recipient_key, now_ms)?;
        state.compact(self.config.auth_window_ms, now_ms)?;
        Ok(Prekey {
            package,
            last_resort,
        })
    }
}
