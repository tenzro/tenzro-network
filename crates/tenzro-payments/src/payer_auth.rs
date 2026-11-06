//! Binding a payment credential to the account it debits.
//!
//! Every Tenzro-native credential (x402 `tenzro-hybrid` and `upto`, MPP) is
//! signed over one canonical preimage,
//! [`tenzro_types::payment_authorization::payment_authorization_preimage`].
//! That preimage names the chain, the challenge id, the payer address, the
//! payee address, the ceiling and the asset. The debited account is the one
//! the signing key controls; a credential that names a different
//! `payer_address` is refused. The same signature travels on the settlement
//! transaction and is verified again by every validator, so the node's view
//! of who authorized the payment is never the only check.
//!
//! When a payer DID is named, a [`PayerKeyResolver`] must confirm the DID
//! lists the signing key or registers the account it controls, otherwise any
//! key could claim any DID.

use std::collections::HashMap;

use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, PqPolicy, SignatureContext, verify_composite,
};
use tenzro_types::Address;
use tenzro_types::payment_authorization::{
    AppMargin, P256_PUBLIC_KEY_LEN, PaymentAuthorization, PaymentBinding,
    payment_authorization_preimage,
};

use crate::error::{PaymentError, Result};
use crate::types::{PaymentChallenge, PaymentCredential};

/// The ledger account a payer's P-256 key (`x || y`) derives, in the 32-byte
/// account slot.
pub fn payer_account(public_key: &[u8]) -> Address {
    Address::new(tenzro_crypto::account_slot(public_key))
}

/// Reads the ML-DSA-65 key an account has enrolled in chain state.
///
/// The enrolled key is the only source of a payer's post-quantum key: a key
/// carried on the credential itself could be swapped or stripped by whoever
/// relays it.
pub trait EnrolledKeys: Send + Sync {
    /// The ML-DSA-65 key enrolled for the account `p256_xy` controls, or
    /// `None` when the account has enrolled none.
    fn enrolled_pq_key(&self, p256_xy: &[u8]) -> Result<Option<Vec<u8>>>;

    /// When the passkey `p256_xy` may pay alone for `account`, a passkey
    /// account whose keystore on chain links it: the relying party the
    /// keystore records it under. A reader with no chain state knows of no
    /// keystore.
    fn keystore_rp_id(&self, _p256_xy: &[u8], _account: &Address) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Verify a payer's composite signature against its P-256 key and the
/// ML-DSA-65 key its account enrolled; an enrolled key makes its leg
/// mandatory.
pub fn verify_payer_signature(
    keys: &dyn EnrolledKeys,
    public_key: &[u8],
    context: SignatureContext,
    message: &[u8],
    signature: &CompositeSignature,
) -> std::result::Result<(), String> {
    verify_payer_signature_for(keys, None, public_key, context, message, signature)
}

/// [`verify_payer_signature`] with a passkey leg made for the relying party
/// `rp_id`, the one a keystore records the payer's passkey under; `None` for
/// a passkey no keystore pins, checked against the relying party its
/// assertion names. No relying party is fixed for the network.
pub fn verify_payer_signature_for(
    keys: &dyn EnrolledKeys,
    rp_id: Option<&str>,
    public_key: &[u8],
    context: SignatureContext,
    message: &[u8],
    signature: &CompositeSignature,
) -> std::result::Result<(), String> {
    let pq = keys
        .enrolled_pq_key(public_key)
        .map_err(|e| e.to_string())?;
    let key = CompositePublicKey::new(public_key.to_vec(), pq).map_err(|e| e.to_string())?;
    match rp_id {
        Some(rp_id) => tenzro_crypto::composite::verify_composite_for(
            rp_id,
            &key,
            context,
            message,
            signature,
            PqPolicy::Required,
        ),
        None => verify_composite(&key, context, message, signature, PqPolicy::Required),
    }
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// The account a voucher draws for: an agent's wallet when a serving node
/// signed it for the agent, otherwise the account its keys derive.
pub fn voucher_payer(voucher: &tenzro_types::payment_authorization::EscrowVoucher) -> Address {
    match &voucher.agent {
        Some(agent) => Address::new(tenzro_types::agent_terms::agent_wallet(&agent.agent_did)),
        None => payer_account(&voucher.public_key),
    }
}

/// Whether `account` is the one a payer's keys derive.
pub fn keys_control_account(public_key: &[u8], account: &Address) -> bool {
    tenzro_crypto::controls_account(public_key, account.as_bytes())
}

/// Key in `challenge.extra` carrying the chain id the challenge settles on.
pub const CHAIN_ID_KEY: &str = "chain_id";

/// Key in `credential.extra` carrying the payer's P-256 public key, `x || y` (hex).
pub const PUBLIC_KEY_KEY: &str = "public_key";

/// Key in `credential.extra` carrying a metered ceiling (decimal string).
pub const UPTO_MAX_KEY: &str = "upto_max";

/// Resolves whether a payer DID stands behind a signing key and account.
///
/// Implemented over the TDIP identity registry. A payer that names no DID is
/// bound by its key alone.
pub trait PayerKeyResolver: Send + Sync {
    /// `Ok(true)` if `did` lists `public_key` as an authentication or
    /// assertion key, or registers `payer` (the account that key controls) as
    /// its wallet. `Ok(false)` if the DID resolves but binds neither. `Err`
    /// if the DID cannot be resolved.
    fn did_binds_payer(&self, did: &str, public_key: &[u8], payer: &Address) -> Result<bool>;
}

impl PayerKeyResolver for tenzro_identity::IdentityRegistry {
    fn did_binds_payer(&self, did: &str, public_key: &[u8], payer: &Address) -> Result<bool> {
        use subtle::ConstantTimeEq;
        let identity = self
            .resolve(did)
            .map_err(|e| PaymentError::IdentityError(format!("payer DID {did}: {e}")))?;
        if !identity.is_active() {
            return Err(PaymentError::IdentityError(format!(
                "payer DID {did} is not active"
            )));
        }
        let lists_key = identity
            .public_keys
            .iter()
            .filter(|k| {
                k.purposes
                    .contains(&tenzro_identity::KeyPurpose::Authentication)
                    || k.purposes
                        .contains(&tenzro_identity::KeyPurpose::AssertionMethod)
            })
            .any(|k| {
                k.public_key.len() == public_key.len()
                    && bool::from(k.public_key.as_slice().ct_eq(public_key))
            });
        Ok(lists_key || identity.wallet_address == *payer)
    }
}

/// A payer whose signature over the payment authorization has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayer {
    /// The account debited: the one the signing key controls.
    pub address: Address,
    /// The DID the payer presented, once [`bind_payer_did`] confirmed it.
    pub did: Option<String>,
    /// The authorization to carry on the settlement transaction.
    pub authorization: PaymentAuthorization,
}

/// Parse a Tenzro address from hex.
///
/// A 20-byte address occupies the first 20 bytes of the 32-byte form, the
/// layout transaction admission derives from a key. A 32-byte value is taken
/// as-is. Anything else is refused rather than padded into some account.
pub fn parse_tenzro_address(s: &str) -> Result<Address> {
    let clean = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(clean)
        .map_err(|e| PaymentError::CredentialError(format!("address '{s}' is not hex: {e}")))?;
    let mut out = [0u8; 32];
    match bytes.len() {
        20 => out[..20].copy_from_slice(&bytes),
        32 => out.copy_from_slice(&bytes),
        n => {
            return Err(PaymentError::CredentialError(format!(
                "address '{s}' is {n} bytes; a Tenzro address is 20 or 32 bytes"
            )));
        }
    }
    Ok(Address::new(out))
}

/// The chain id a challenge settles on, stamped by the gateway at mint time.
pub fn challenge_chain_id(challenge: &PaymentChallenge) -> Result<u64> {
    challenge
        .extra
        .get(CHAIN_ID_KEY)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            PaymentError::ChallengeError(format!(
                "challenge {} carries no chain_id; it was not minted by this gateway",
                challenge.challenge_id
            ))
        })
}

/// The ceiling a credential authorizes: its `upto_max` for a metered
/// credential, otherwise its amount.
pub fn authorized_ceiling(credential: &PaymentCredential) -> Result<u128> {
    match credential.extra.get(UPTO_MAX_KEY) {
        None => Ok(credential.amount),
        Some(v) => {
            let raw = v.as_str().ok_or_else(|| {
                PaymentError::CredentialError("upto_max must be a decimal string".to_string())
            })?;
            raw.parse::<u128>().map_err(|_| {
                PaymentError::CredentialError(format!("upto_max '{raw}' is not a valid u128"))
            })
        }
    }
}

/// Domain of a request digest.
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"tenzro/request";

/// Key in `challenge.extra` carrying the payee's quote digest (hex).
pub const QUOTE_DIGEST_KEY: &str = "quote_digest";
/// Key in `challenge.extra` carrying the quoted USD price in micro-units.
pub const USD_E6_KEY: &str = "usd_e6";
/// Key in `challenge.extra` carrying the wallet an application's developer
/// margin is paid to (hex address).
pub const APP_WALLET_KEY: &str = "app_wallet";
/// Key in `challenge.extra` carrying the developer margin in basis points.
pub const MARGIN_BPS_KEY: &str = "margin_bps";

/// What a payment against `challenge` pays for: the digest of the requested
/// resource, and the payee's quote, USD price and application margin when
/// the challenge carries them. A challenge without a quote binds the request
/// alone. A margin is a non-zero `margin_bps` together with an `app_wallet`;
/// one without the other is refused, so the payer always signs the exact
/// margin and wallet a settlement will pay.
pub fn challenge_binding(challenge: &PaymentChallenge) -> Result<PaymentBinding> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(REQUEST_DIGEST_DOMAIN);
    h.update(challenge.resource.as_bytes());
    let quote_digest = match challenge.extra.get(QUOTE_DIGEST_KEY) {
        None => [0u8; 32],
        Some(v) => {
            let raw = v.as_str().ok_or_else(|| {
                PaymentError::CredentialError("quote_digest must be a hex string".to_string())
            })?;
            hex::decode(raw.trim_start_matches("0x"))
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| {
                    PaymentError::CredentialError("quote_digest is 32 bytes of hex".to_string())
                })?
        }
    };
    let usd_e6 = match challenge.extra.get(USD_E6_KEY) {
        None => 0,
        Some(v) => v.as_u64().ok_or_else(|| {
            PaymentError::CredentialError("usd_e6 must be an unsigned integer".to_string())
        })?,
    };
    Ok(PaymentBinding {
        request_digest: h.finalize().into(),
        quote_digest,
        usd_e6,
        app_margin: challenge_app_margin(challenge)?,
    })
}

/// The application margin `challenge` asks the payer to sign, if any.
pub fn challenge_app_margin(challenge: &PaymentChallenge) -> Result<Option<AppMargin>> {
    let margin_bps = match challenge.extra.get(MARGIN_BPS_KEY) {
        None => 0,
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| PaymentError::ChallengeError("margin_bps must be a u32".to_string()))?,
    };
    let app_wallet = match challenge.extra.get(APP_WALLET_KEY) {
        None => None,
        Some(v) => Some(parse_tenzro_address(v.as_str().ok_or_else(|| {
            PaymentError::ChallengeError("app_wallet must be a hex string".to_string())
        })?)?),
    };
    match (app_wallet, margin_bps) {
        (None, 0) => Ok(None),
        (Some(app_wallet), bps) if bps > 0 => Ok(Some(AppMargin {
            app_wallet,
            margin_bps: bps,
        })),
        _ => Err(PaymentError::ChallengeError(
            "a developer margin names both a non-zero margin_bps and an app_wallet".to_string(),
        )),
    }
}

/// The message a payer signs to authorize `max_amount` of `asset` against
/// `challenge`.
pub fn authorization_message(
    challenge: &PaymentChallenge,
    payer: &Address,
    max_amount: u128,
    asset: &str,
) -> Result<Vec<u8>> {
    let chain_id = challenge_chain_id(challenge)?;
    let payee = parse_tenzro_address(&challenge.recipient)?;
    Ok(payment_authorization_preimage(
        chain_id,
        &challenge.challenge_id,
        payer,
        &payee,
        max_amount,
        asset,
        &challenge_binding(challenge)?,
    ))
}

/// Assemble a signed credential from a payer's signature legs.
///
/// `amount` is the charge; `max_amount` is what the payer signed. They are
/// equal for an exact payment. For a metered payment the ceiling is recorded
/// under `upto_max` and the charge is chosen at capture time.
#[allow(clippy::too_many_arguments)]
pub fn assemble_credential(
    challenge: &PaymentChallenge,
    protocol: &str,
    payer_did: &str,
    payer: &Address,
    public_key: &[u8],
    signature: CompositeSignature,
    amount: u128,
    max_amount: u128,
) -> PaymentCredential {
    let mut extra = HashMap::new();
    extra.insert(
        PUBLIC_KEY_KEY.to_string(),
        serde_json::json!(hex::encode(public_key)),
    );
    if max_amount != amount {
        extra.insert(
            UPTO_MAX_KEY.to_string(),
            serde_json::json!(max_amount.to_string()),
        );
    }
    PaymentCredential {
        credential_id: uuid::Uuid::new_v4().to_string(),
        challenge_id: challenge.challenge_id.clone(),
        protocol: protocol.to_string(),
        payer_did: payer_did.to_string(),
        payer_address: hex::encode(payer.as_bytes()),
        amount,
        asset: challenge.asset.clone(),
        signature: Some(signature),
        extra,
    }
}

/// Sign a credential with a hybrid signer the payer controls, paying from
/// the account its P-256 key names.
pub fn sign_credential(
    challenge: &PaymentChallenge,
    protocol: &str,
    payer_did: &str,
    signer: &dyn tenzro_crypto::composite::HybridSigner,
    amount: u128,
    max_amount: u128,
) -> Result<PaymentCredential> {
    let payer = payer_account(&signer.public_key().p256);
    sign_credential_from(
        challenge, protocol, payer_did, signer, &payer, amount, max_amount,
    )
}

/// Sign a credential paying from `payer`: the account the signer's P-256
/// key names, or a passkey account whose keystore on chain links the signer.
#[allow(clippy::too_many_arguments)]
pub fn sign_credential_from(
    challenge: &PaymentChallenge,
    protocol: &str,
    payer_did: &str,
    signer: &dyn tenzro_crypto::composite::HybridSigner,
    payer: &Address,
    amount: u128,
    max_amount: u128,
) -> Result<PaymentCredential> {
    let public_key = signer.public_key().p256.clone();
    let payer = *payer;
    let message = authorization_message(challenge, &payer, max_amount, &challenge.asset)?;
    let sig = signer
        .sign(SignatureContext::PaymentAuthorization, &message)
        .map_err(|e| PaymentError::CredentialError(format!("signing failed: {e}")))?;
    Ok(assemble_credential(
        challenge,
        protocol,
        payer_did,
        &payer,
        &public_key,
        sig,
        amount,
        max_amount,
    ))
}

/// Verify a credential's authorization and bind it to the account it debits.
///
/// Checks, in order: the challenge id matches; the asset matches; the charge
/// fits under the signed ceiling and the ceiling under the challenge amount;
/// the signing key controls `payer_address` (or `payer_address` is derived
/// from it when absent); and the signatures verify over the canonical
/// preimage. A named payer DID is bound separately by [`bind_payer_did`].
pub fn verify_payer(
    keys: &dyn EnrolledKeys,
    challenge: &PaymentChallenge,
    credential: &PaymentCredential,
) -> Result<VerifiedPayer> {
    if credential.challenge_id != challenge.challenge_id {
        return Err(PaymentError::VerificationFailed(
            "credential challenge_id does not match the challenge".to_string(),
        ));
    }
    if !credential.asset.eq_ignore_ascii_case(&challenge.asset) {
        return Err(PaymentError::VerificationFailed(format!(
            "credential asset {} does not match challenge asset {}",
            credential.asset, challenge.asset
        )));
    }
    let max_amount = authorized_ceiling(credential)?;
    if credential.amount > max_amount {
        return Err(PaymentError::VerificationFailed(format!(
            "charge {} exceeds the authorized ceiling {}",
            credential.amount, max_amount
        )));
    }
    if max_amount > challenge.amount {
        return Err(PaymentError::VerificationFailed(format!(
            "authorized ceiling {} exceeds the challenge amount {}",
            max_amount, challenge.amount
        )));
    }

    let pk_hex = credential
        .extra
        .get(PUBLIC_KEY_KEY)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PaymentError::CredentialError("credential carries no extra.public_key".to_string())
        })?;
    let public_key = hex::decode(pk_hex.trim_start_matches("0x"))
        .map_err(|e| PaymentError::CredentialError(format!("public_key is not hex: {e}")))?;
    if public_key.len() != P256_PUBLIC_KEY_LEN {
        return Err(PaymentError::CredentialError(format!(
            "public_key is {} bytes; a P-256 key (x || y) is {}",
            public_key.len(),
            P256_PUBLIC_KEY_LEN
        )));
    }
    let signature = credential.signature.clone().ok_or_else(|| {
        PaymentError::CredentialError("credential carries no signature".to_string())
    })?;

    let (payer, rp_id) = if credential.payer_address.is_empty() {
        (payer_account(&public_key), None)
    } else {
        let named = parse_tenzro_address(&credential.payer_address)?;
        let rp_id = if keys_control_account(&public_key, &named) {
            None
        } else {
            Some(keys.keystore_rp_id(&public_key, &named)?.ok_or_else(|| {
                PaymentError::VerificationFailed(
                    "payer_address is not the account of the signing keys, nor a passkey account whose \
                     keystore lets them pay"
                        .to_string(),
                )
            })?)
        };
        (named, rp_id)
    };

    let message = authorization_message(challenge, &payer, max_amount, &credential.asset)?;
    verify_payer_signature_for(
        keys,
        rp_id.as_deref(),
        &public_key,
        SignatureContext::PaymentAuthorization,
        &message,
        &signature,
    )
    .map_err(|e| PaymentError::VerificationFailed(format!("payer signature invalid: {e}")))?;

    Ok(VerifiedPayer {
        address: payer,
        did: None,
        authorization: PaymentAuthorization {
            resellers: Vec::new(),
            public_key,
            signature,
            max_amount,
            asset: credential.asset.clone(),
            binding: challenge_binding(challenge)?,
        },
    })
}

/// Key in `credential.extra` naming the escrow a voucher draws on (hex).
pub const ESCROW_ID_KEY: &str = "escrow_id";

/// Key in `credential.extra` carrying a voucher's cumulative amount.
pub const CUMULATIVE_AMOUNT_KEY: &str = "cumulative_amount";

/// Credential `extra` key: the paying agent of a voucher a serving node
/// signed for it.
pub const AGENT_DID_KEY: &str = "agent_did";

/// Credential `extra` key: the serving node that signed an agent's voucher.
pub const MACHINE_DID_KEY: &str = "machine_did";

/// Credential `extra` key: when the serving node signed, unix ms.
pub const AS_OF_MS_KEY: &str = "as_of_ms";
/// Credential `extra` key of a voucher's receipt binding (hex of 32 bytes):
/// the head of the hash chain of the receipts the payer is paying for.
/// Absent for a voucher signed ahead of delivery.
pub const BINDING_KEY: &str = "binding";

/// Verify a credential that pays with a cumulative escrow voucher.
///
/// The credential's `amount` is this request's charge; the voucher's
/// cumulative total must cover it. A payer's own signature is checked here;
/// whether the escrow on the ledger can honour the voucher, and for an
/// agent's voucher whether a node its terms assign signed it, is the voucher
/// rail's check against chain state.
pub fn verify_escrow_voucher(
    keys: &dyn EnrolledKeys,
    challenge: &PaymentChallenge,
    credential: &PaymentCredential,
) -> Result<tenzro_types::payment_authorization::EscrowVoucher> {
    use tenzro_types::payment_authorization::EscrowVoucher;
    if credential.challenge_id != challenge.challenge_id {
        return Err(PaymentError::VerificationFailed(
            "credential challenge_id does not match the challenge".to_string(),
        ));
    }
    let field = |key: &str| {
        credential
            .extra
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| PaymentError::CredentialError(format!("voucher is missing extra.{key}")))
    };
    let escrow_id: [u8; 32] = hex::decode(field(ESCROW_ID_KEY)?.trim_start_matches("0x"))
        .map_err(|e| PaymentError::CredentialError(format!("escrow_id is not hex: {e}")))?
        .try_into()
        .map_err(|_| PaymentError::CredentialError("escrow_id must be 32 bytes".to_string()))?;
    let cumulative: u128 = field(CUMULATIVE_AMOUNT_KEY)?.parse().map_err(|_| {
        PaymentError::CredentialError("cumulative_amount is not a valid u128".to_string())
    })?;
    let binding: [u8; 32] = match credential.extra.get(BINDING_KEY).and_then(|v| v.as_str()) {
        None => [0u8; 32],
        Some(h) => hex::decode(h.trim_start_matches("0x"))
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                PaymentError::CredentialError("binding must be 32 bytes of hex".into())
            })?,
    };
    if credential.amount == 0 || credential.amount > cumulative {
        return Err(PaymentError::VerificationFailed(format!(
            "voucher charge {} must be non-zero and within its cumulative total {}",
            credential.amount, cumulative
        )));
    }
    if credential.amount > challenge.amount {
        return Err(PaymentError::VerificationFailed(format!(
            "voucher charge {} exceeds the challenge amount {}",
            credential.amount, challenge.amount
        )));
    }
    if let Some(agent_did) = credential.extra.get(AGENT_DID_KEY).and_then(|v| v.as_str()) {
        // A serving node signed for the agent with its hardware key; only
        // the agent's terms in chain state say which node may, so the voucher
        // rail's ledger check is the signature check.
        let as_of_ms = field(AS_OF_MS_KEY)?.parse().map_err(|_| {
            PaymentError::CredentialError("as_of_ms is not a valid u64".to_string())
        })?;
        let signature = match &credential.signature {
            Some(
                sig @ CompositeSignature {
                    classical: tenzro_crypto::composite::ClassicalProof::Raw { signature },
                    pq: None,
                },
            ) if signature.len() == 64 => sig.clone(),
            _ => {
                return Err(PaymentError::CredentialError(
                    "an agent voucher carries the serving node's raw 64-byte P-256 signature"
                        .to_string(),
                ));
            }
        };
        return Ok(EscrowVoucher {
            binding,
            escrow_id,
            cumulative_amount: cumulative,
            public_key: Vec::new(),
            signature,
            agent: Some(tenzro_types::payment_authorization::AgentVoucherSigner {
                agent_did: agent_did.to_string(),
                machine_did: field(MACHINE_DID_KEY)?.to_string(),
                as_of_ms,
            }),
            attribution: None,
        });
    }
    let public_key = hex::decode(field(PUBLIC_KEY_KEY)?.trim_start_matches("0x"))
        .map_err(|e| PaymentError::CredentialError(format!("public_key is not hex: {e}")))?;
    let voucher = EscrowVoucher {
        binding,
        escrow_id,
        cumulative_amount: cumulative,
        public_key,
        signature: credential.signature.clone().ok_or_else(|| {
            PaymentError::CredentialError("credential carries no signature".to_string())
        })?,
        agent: None,
        attribution: None,
    };
    verify_voucher_signature(keys, challenge_chain_id(challenge)?, &voucher)?;
    Ok(voucher)
}

/// Check a voucher's signature over its canonical preimage on `chain_id`,
/// with its attribution when it carries one. Whether its keys own the escrow
/// is the escrow reader's check.
pub fn verify_voucher_signature(
    keys: &dyn EnrolledKeys,
    chain_id: u64,
    voucher: &tenzro_types::payment_authorization::EscrowVoucher,
) -> Result<()> {
    use tenzro_types::payment_authorization::{
        attributed_voucher_preimage, escrow_voucher_preimage,
    };
    if voucher.public_key.len() != P256_PUBLIC_KEY_LEN {
        return Err(PaymentError::CredentialError(
            "voucher public_key must be a P-256 key (x || y)".to_string(),
        ));
    }
    let message = attributed_voucher_preimage(
        escrow_voucher_preimage(
            chain_id,
            &voucher.escrow_id,
            voucher.cumulative_amount,
            &voucher.binding,
        ),
        voucher.attribution.as_ref(),
    );
    verify_payer_signature(
        keys,
        &voucher.public_key,
        SignatureContext::EscrowVoucher,
        &message,
        &voucher.signature,
    )
    .map_err(|e| PaymentError::VerificationFailed(format!("voucher signature invalid: {e}")))
}

/// Bind the DID a credential names to its verified payer.
///
/// A credential naming no DID pays by key alone. A named DID must resolve and
/// stand behind the signing key or its account; otherwise any key could
/// claim any DID's delegation scope and reputation.
pub fn bind_payer_did(
    payer: &mut VerifiedPayer,
    did: &str,
    resolver: Option<&dyn PayerKeyResolver>,
) -> Result<()> {
    if did.is_empty() {
        return Ok(());
    }
    let resolver = resolver.ok_or_else(|| {
        PaymentError::VerificationFailed(format!(
            "credential names payer DID {did} but this gateway cannot resolve DIDs; omit the \
             DID to pay by key alone"
        ))
    })?;
    if !resolver.did_binds_payer(did, &payer.authorization.public_key, &payer.address)? {
        return Err(PaymentError::VerificationFailed(format!(
            "payer DID {did} lists neither the signing key nor the account it controls"
        )));
    }
    payer.did = Some(did.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tenzro_crypto::composite::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;

    fn signer() -> TestHybridSigner {
        static SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
        TestHybridSigner::hybrid(SEED.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    fn challenge(amount: u128) -> PaymentChallenge {
        let mut extra = HashMap::new();
        extra.insert(CHAIN_ID_KEY.to_string(), serde_json::json!(1337u64));
        PaymentChallenge {
            challenge_id: "ch-1".to_string(),
            protocol: "x402".to_string(),
            resource: "/r".to_string(),
            amount,
            asset: "TNZO".to_string(),
            recipient: hex::encode([9u8; 20]),
            chain: "tenzro".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            extra,
        }
    }

    fn keys() -> crate::test_support::SeedKeys {
        crate::test_support::SeedKeys
    }

    struct Lists(bool);
    impl PayerKeyResolver for Lists {
        fn did_binds_payer(&self, _did: &str, _pk: &[u8], _payer: &Address) -> Result<bool> {
            Ok(self.0)
        }
    }

    #[test]
    fn a_signed_credential_binds_to_the_signing_key_account() {
        let s = signer();
        let ch = challenge(100);
        let cred = sign_credential(&ch, "x402", "", &s, 100, 100).unwrap();
        let v = verify_payer(&keys(), &ch, &cred).unwrap();
        let pk = s.public_key();
        assert_eq!(v.address, payer_account(&pk.p256));
        assert!(pk.pq.is_some());
    }

    #[test]
    fn a_stripped_ml_dsa_leg_is_refused() {
        let s = signer();
        let ch = challenge(100);
        let mut cred = sign_credential(&ch, "x402", "", &s, 100, 100).unwrap();
        // The account enrolled an ML-DSA-65 key, so its leg is mandatory.
        cred.signature.as_mut().unwrap().pq = None;
        assert!(verify_payer(&keys(), &ch, &cred).is_err());
    }

    #[test]
    fn a_challenge_margin_is_bound_into_what_the_payer_signs() {
        let plain = challenge(100);
        assert_eq!(challenge_binding(&plain).unwrap().app_margin, None);
        let mut ch = challenge(100);
        ch.extra.insert(
            APP_WALLET_KEY.to_string(),
            serde_json::json!(hex::encode([7u8; 32])),
        );
        ch.extra
            .insert(MARGIN_BPS_KEY.to_string(), serde_json::json!(150u64));
        assert_eq!(
            challenge_binding(&ch).unwrap().app_margin,
            Some(AppMargin {
                app_wallet: Address::new([7u8; 32]),
                margin_bps: 150,
            })
        );
        let payer = Address::new([1u8; 32]);
        assert_ne!(
            authorization_message(&ch, &payer, 100, "TNZO").unwrap(),
            authorization_message(&plain, &payer, 100, "TNZO").unwrap()
        );
        let mut wallet_only = ch.clone();
        wallet_only.extra.remove(MARGIN_BPS_KEY);
        assert!(challenge_binding(&wallet_only).is_err());
        let mut margin_only = ch.clone();
        margin_only.extra.remove(APP_WALLET_KEY);
        assert!(challenge_binding(&margin_only).is_err());
    }

    #[test]
    fn a_key_signing_for_a_victim_account_is_refused() {
        // The attacker signs a well-formed authorization naming the victim as
        // payer with its own key; only the key-to-account binding stops it.
        let attacker = signer();
        let ch = challenge(100);
        let victim = Address::new({
            let mut b = [0u8; 32];
            b[..20].copy_from_slice(&[0x42u8; 20]);
            b
        });
        let pk = attacker.public_key().p256.clone();
        let msg = authorization_message(&ch, &victim, 100, "TNZO").unwrap();
        let sig = attacker
            .sign(
                tenzro_crypto::composite::SignatureContext::PaymentAuthorization,
                &msg,
            )
            .unwrap();
        let mut cred =
            assemble_credential(&ch, "x402", "", &payer_account(&pk), &pk, sig, 100, 100);
        cred.payer_address = hex::encode(&victim.as_bytes()[..20]);
        let err = verify_payer(&keys(), &ch, &cred).unwrap_err();
        assert!(err.to_string().contains("not the account"), "{err}");
    }

    #[test]
    fn naming_a_victim_payer_address_is_refused() {
        let s = signer();
        let ch = challenge(100);
        let mut cred = sign_credential(&ch, "x402", "", &s, 100, 100).unwrap();
        cred.payer_address = hex::encode([0x42u8; 20]);
        let err = verify_payer(&keys(), &ch, &cred).unwrap_err();
        assert!(err.to_string().contains("not the account"), "{err}");
    }

    #[test]
    fn swapping_in_another_key_breaks_the_signature() {
        let victim = signer();
        let attacker = signer();
        let ch = challenge(100);
        let mut cred = sign_credential(&ch, "x402", "", &attacker, 100, 100).unwrap();
        // Present the victim's key and address with the attacker's signature.
        let vpk = victim.public_key().p256.clone();
        cred.extra.insert(
            PUBLIC_KEY_KEY.to_string(),
            serde_json::json!(hex::encode(&vpk)),
        );
        cred.payer_address = hex::encode(payer_account(&vpk).as_bytes());
        assert!(verify_payer(&keys(), &ch, &cred).is_err());
    }

    #[test]
    fn a_signature_for_one_payee_does_not_pay_another() {
        let s = signer();
        let ch = challenge(100);
        let cred = sign_credential(&ch, "x402", "", &s, 100, 100).unwrap();
        let mut other = ch.clone();
        other.recipient = hex::encode([7u8; 20]);
        assert!(verify_payer(&keys(), &other, &cred).is_err());
    }

    #[test]
    fn a_charge_above_the_signed_ceiling_is_refused() {
        let s = signer();
        let ch = challenge(100);
        let mut cred = sign_credential(&ch, "x402", "", &s, 40, 50).unwrap();
        assert!(verify_payer(&keys(), &ch, &cred).is_ok());
        cred.amount = 51;
        assert!(verify_payer(&keys(), &ch, &cred).is_err());
    }

    #[test]
    fn a_named_did_must_bind_the_key() {
        let s = signer();
        let ch = challenge(100);
        let cred = sign_credential(&ch, "x402", "did:tenzro:human:x", &s, 100, 100).unwrap();
        let payer = verify_payer(&keys(), &ch, &cred).unwrap();
        let mut bound = payer.clone();
        bind_payer_did(&mut bound, &cred.payer_did, Some(&Lists(true))).unwrap();
        assert_eq!(bound.did.as_deref(), Some("did:tenzro:human:x"));
        let mut refused = payer.clone();
        assert!(bind_payer_did(&mut refused, &cred.payer_did, Some(&Lists(false))).is_err());
        let mut unresolvable = payer;
        assert!(bind_payer_did(&mut unresolvable, &cred.payer_did, None).is_err());
    }

    #[test]
    fn a_short_address_is_left_aligned_and_odd_lengths_are_refused() {
        let a = parse_tenzro_address(&hex::encode([1u8; 20])).unwrap();
        assert_eq!(&a.as_bytes()[..20], &[1u8; 20]);
        assert_eq!(&a.as_bytes()[20..], &[0u8; 12]);
        assert!(parse_tenzro_address("0x0102").is_err());
    }
}
