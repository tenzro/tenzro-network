//! The mailbox service (preview): what the binary runs, kept here so it can
//! be tested without hardware.
//!
//! The service holds sealed messages for offline recipients
//! ([`tenzro_mailbox`]), and claims on the ledger what its deposits cost:
//! each escrow that paid is claimed up to what was charged under the highest
//! voucher its payer signed, with a `ClaimEscrow` transaction the service's
//! own key signs and submits through the node's public interface.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tenzro_crypto::HybridSigner as _;
use tenzro_mailbox::{EscrowAccount, Ledger, MailboxError, claim_gas};
use tenzro_sdk::error::{SdkError, SdkResult};
use tenzro_sdk::typed_tx::{TxKind, TypedTransaction};
use tenzro_types::payment_authorization::{EscrowClaim, MAX_VOUCHERS_PER_CLAIM};

/// What the ledger still owes the mailbox: one claim for every escrow whose
/// charges pass what was already claimed on it. An escrow the ledger no
/// longer holds open is left out, and so is one that ends within `margin_ms`
/// of `now_ms`: a claim of it could fail, and a claim fails together with
/// every other claim of its transaction.
pub async fn due_claims(
    due: Vec<EscrowAccount>,
    ledger: &dyn Ledger,
    now_ms: u64,
    margin_ms: u64,
) -> Result<Vec<EscrowClaim>, MailboxError> {
    let mut claims = Vec::new();
    for account in due {
        let Some(escrow) = ledger.escrow(&account.voucher.escrow_id).await? else {
            continue;
        };
        if escrow.expires_at_ms <= now_ms.saturating_add(margin_ms) {
            continue;
        }
        if account.charged > escrow.claimed {
            claims.push(EscrowClaim {
                amount: account.charged,
                voucher: account.voucher,
            });
        }
    }
    claims.sort_by_key(|c| c.voucher.escrow_id);
    Ok(claims)
}

/// The `ClaimEscrow` transaction that claims `claims`, which must be at most
/// as many as the ledger takes in one.
pub fn claim_transaction(claims: &[EscrowClaim]) -> SdkResult<TypedTransaction> {
    let fields = serde_json::json!({ "claims": claims });
    Ok(TypedTransaction::new(TxKind::ClaimEscrow, fields)?.gas_limit(claim_gas(claims.len())))
}

/// Submits a claim transaction.
pub trait Submit: Send + Sync {
    /// Signs and submits `tx`; an error when the node refuses it.
    fn submit(&self, tx: &TypedTransaction) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// Claims what the escrows owe, as many claims per transaction as the
/// ledger takes. When a transaction is refused, each of its claims is sent
/// alone, so one claim that cannot succeed does not hold back the others;
/// a claim refused alone waits before it is tried again, twice as long after
/// each refusal, up to a day.
#[derive(Default)]
pub struct Claimer {
    /// For each escrow refused alone: how many times, and when it may be
    /// tried again.
    backoff: HashMap<[u8; 32], (u32, u64)>,
}

/// The first wait after a claim is refused alone.
const FIRST_BACKOFF_MS: u64 = 10 * 60 * 1000;
/// The longest wait.
const MAX_BACKOFF_MS: u64 = 24 * 60 * 60 * 1000;

impl Claimer {
    /// Submits `claims`, leaving out escrows still waiting after a refusal.
    /// Returns how many claims were accepted.
    pub async fn claim(
        &mut self,
        claims: Vec<EscrowClaim>,
        submit: &impl Submit,
        now_ms: u64,
    ) -> usize {
        let ready: Vec<EscrowClaim> = claims
            .into_iter()
            .filter(|c| {
                self.backoff
                    .get(&c.voucher.escrow_id)
                    .is_none_or(|(_, after)| *after <= now_ms)
            })
            .collect();
        let mut accepted = 0;
        for batch in ready.chunks(MAX_VOUCHERS_PER_CLAIM) {
            if self.send(batch, submit).await {
                accepted += batch.len();
                continue;
            }
            for claim in batch {
                let id = claim.voucher.escrow_id;
                if batch.len() > 1 && self.send(std::slice::from_ref(claim), submit).await {
                    accepted += 1;
                    self.backoff.remove(&id);
                    continue;
                }
                let (refusals, _) = self.backoff.get(&id).copied().unwrap_or((0, 0));
                let wait = FIRST_BACKOFF_MS
                    .saturating_mul(1u64 << refusals.min(16))
                    .min(MAX_BACKOFF_MS);
                self.backoff
                    .insert(id, (refusals + 1, now_ms.saturating_add(wait)));
            }
        }
        accepted
    }

    async fn send(&mut self, claims: &[EscrowClaim], submit: &impl Submit) -> bool {
        let sent = match claim_transaction(claims) {
            Ok(tx) => submit.submit(&tx).await,
            Err(e) => Err(anyhow::anyhow!("{e}")),
        };
        match sent {
            Ok(()) => {
                for claim in claims {
                    self.backoff.remove(&claim.voucher.escrow_id);
                }
                true
            }
            Err(e) => {
                tracing::warn!("a claim of {} voucher(s) was refused: {e:#}", claims.len());
                false
            }
        }
    }
}

/// The service's key as the SDK signs transactions with it: the P-256 key
/// and the ML-DSA-65 key of the machine's hardware.
pub struct ServiceKey(pub Arc<tenzro_device_key::signer::HardwareHybridSigner>);

#[async_trait]
impl tenzro_sdk::wallet::HybridSigner for ServiceKey {
    fn p256_public_key(&self) -> [u8; 64] {
        let mut key = [0u8; 64];
        key.copy_from_slice(&self.0.public_key().p256);
        key
    }

    fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
        self.0.public_key().pq.clone()
    }

    async fn sign_composite(&self, m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
        self.0
            .sign_representative(m_prime)
            .map_err(|e| SdkError::InvalidParameter(format!("the service key: {e}")))
    }

    async fn sign_ml_dsa_leg(&self, m_prime: &[u8]) -> SdkResult<Vec<u8>> {
        // The service's key is a TPM or Secure Enclave key that signs without a prompt, so the
        // P-256 leg made alongside costs nothing the caller would see.
        let (_, pq) = self.sign_composite(m_prime).await?;
        pq.ok_or_else(|| SdkError::InvalidParameter("the service key: no ML-DSA-65 key".into()))
    }

    async fn sign_p256(&self, message: &[u8]) -> SdkResult<[u8; 64]> {
        let rs = self
            .0
            .sign_external(message)
            .map_err(|e| SdkError::InvalidParameter(format!("the service key: {e}")))?;
        rs.try_into()
            .map_err(|_| SdkError::InvalidParameter("the service key: a short signature".into()))
    }
}

#[cfg(test)]
mod tests;
