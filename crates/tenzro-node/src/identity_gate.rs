//! The node side of the identity gate: the registry views the gate
//! reads, the wiring of its layers, and the onboarding service that sponsors
//! a machine's first registration.
//!
//! Tenzro has no participants without a registered identity. The layers, in
//! the order a stranger meets them:
//!
//! 1. Peer admission ([`tenzro_iroh::identity_gate`]): an unregistered peer
//!    gets an onboarding session (sync, discovery, gossip, the registration
//!    request) and nothing else, for [`OnboardingPolicy::window`].
//! 2. Gossip ([`tenzro_network::GossipGuard::set_registered_only`]): an
//!    unregistered neighbour delivers nothing but a verified validator
//!    announcement.
//! 3. The mempool ([`tenzro_consensus::SenderRegistry`]): a transaction from
//!    an account with no registered identity is not pooled, except the ones
//!    that are how an identity is registered.
//! 4. The edge: [`require_registered_caller`], for the RPC, MCP and A2A write
//!    calls whose actor is a wallet address.
//! 5. The standing sweep ([`IdentityGate::sweep`]) closes the connections of
//!    identities that were revoked, or never registered.
//!
//! Each layer runs in the node's own `[onboarding]` mode while the governed
//! mode on chain (`feature.identity_required.mode`, see
//! [`tenzro_vm::identity_required::Mode`]) is enforce. When governance relaxes
//! the rule to audit or off, every node admits what it would refuse at its
//! next read of chain state, logging it under audit, with no restart and no
//! config change.
//!
//! All of it is node-local policy. What the VM does with a transaction from
//! an unregistered account is unchanged by this module; that is a consensus
//! rule and needs a protocol version and an activation epoch (the `feature.<name>.activation_epoch` gates of `tenzro_vm::feature_gate`).
//!
//! The registry both views read is consensus chain state, the same state the
//! mirrored [`tenzro_identity::IdentityRegistry`] is built from: a DID is
//! registered when `RegisterIdentity` wrote its record, and a wallet when the
//! wallet-to-identity index names it.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tenzro_consensus::SenderRegistry;
use tenzro_iroh::identity_gate::IdentityGate;
use tenzro_iroh::{DiscoveryStore, EndpointId, RegistryView, Reply, RequestHandler};
use tenzro_onboarding_types::onboarding::{
    ApprovalBook, ApprovalChallenge, GateMode, OnboardingPolicy, SponsorAsk, SponsorLedger,
    SponsorPolicy, Standing,
};
use tenzro_storage::KvStore;
use tenzro_types::primitives::Address;
use tenzro_types::transaction::TransactionType;
use tenzro_vm::StateAdapter;
use tenzro_vm::traits::VmState;

/// The `[onboarding]` table of the node config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OnboardingConfig {
    /// The gate's mode and its window, back-off and session limits.
    #[serde(flatten)]
    pub policy: OnboardingPolicy,
    /// Whether and how this node pays a machine's first registration.
    pub sponsor: SponsorPolicy,
    /// Seconds between standing sweeps.
    pub sweep_secs: u64,
}

impl Default for OnboardingConfig {
    fn default() -> Self {
        Self {
            policy: OnboardingPolicy::default(),
            sponsor: SponsorPolicy::default(),
            sweep_secs: 30,
        }
    }
}

// ---------------------------------------------------------------------------
// Registry views over consensus chain state
// ---------------------------------------------------------------------------

/// The identity registry as the peer gate reads it: machine identities
/// registered on chain, minus the revoked.
pub struct ChainRegistry {
    chain: Arc<dyn KvStore>,
    ready: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl ChainRegistry {
    /// A view over `chain`. `ready` says whether the node's chain state has
    /// caught up far enough to be believed.
    pub fn new(chain: Arc<dyn KvStore>, ready: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        Self { chain, ready }
    }
}

impl RegistryView for ChainRegistry {
    fn standing(&self, did: &str) -> Standing {
        let state = StateAdapter::with_storage(self.chain.clone());
        governed(&state, did_standing(&state, did), "peer", did)
    }

    fn ready(&self) -> bool {
        (self.ready)()
    }
}

/// The standing of the machine or human identity `did` in `state`.
pub fn did_standing(state: &dyn VmState, did: &str) -> Standing {
    if tenzro_vm::native::is_identity_revoked(state, did) {
        return Standing::Revoked;
    }
    let slot = tenzro_types::identity::identity_slot(did);
    match state.get_storage(&tenzro_vm::native::SYSTEM_ADDRESS, slot.as_bytes()) {
        Some(record) if !record.is_empty() => Standing::Registered,
        _ => Standing::Unregistered,
    }
}

/// The standing of the account `address` in `state`: registered when the
/// wallet index names an identity that is not revoked.
///
/// One carve-out keeps the chain live: an account that already holds a
/// validator bond is admitted as registered. Validators are in the genesis
/// set or bonded before this rule, and their records, votes and exits are
/// what the chain runs on; whether a validator must also hold an identity is
/// a consensus rule (RegisterValidator), not a mempool one.
pub fn account_standing(state: &dyn VmState, address: &[u8]) -> Standing {
    match tenzro_vm::native::identity_of_wallet(state, address) {
        Some(did) => {
            if tenzro_vm::native::is_identity_revoked(state, &did) {
                Standing::Revoked
            } else {
                Standing::Registered
            }
        }
        None if tenzro_vm::native::bonded_stake_of(state, address) > 0 => Standing::Registered,
        None => Standing::Unregistered,
    }
}

/// `standing` as the governed mode of the identity rule leaves it: unchanged
/// under enforce; under audit or off a refusal is admitted, logged under
/// audit with the `layer` and `who` it concerns.
pub fn governed(state: &dyn VmState, standing: Standing, layer: &str, who: &str) -> Standing {
    use tenzro_vm::identity_required::Mode;
    if standing.is_registered() {
        return standing;
    }
    match tenzro_vm::identity_required::mode(state) {
        Mode::Enforce => standing,
        Mode::Off => Standing::Registered,
        Mode::Audit => {
            tracing::warn!(
                target: "tenzro_node::identity_gate",
                layer,
                who,
                reason = standing.refusal(),
                action = "audit",
                "governed audit mode: admitted a party with no registered identity"
            );
            Standing::Registered
        }
    }
}

/// The mempool's registry: accounts by the wallet index.
pub struct ChainSenders {
    chain: Arc<dyn KvStore>,
}

impl ChainSenders {
    /// A view over `chain`.
    pub fn new(chain: Arc<dyn KvStore>) -> Self {
        Self { chain }
    }
}

impl SenderRegistry for ChainSenders {
    fn sender_standing(&self, sender: &Address) -> Standing {
        let state = StateAdapter::with_storage(self.chain.clone());
        let standing = account_standing(&state, sender.as_bytes());
        governed(&state, standing, "mempool", &sender.to_string())
    }
}

/// The mempool's registry in audit mode: says what it would refuse, refuses
/// nothing.
pub struct AuditSenders(pub ChainSenders);

impl SenderRegistry for AuditSenders {
    fn sender_standing(&self, sender: &Address) -> Standing {
        let standing = self.0.sender_standing(sender);
        if !standing.is_registered() {
            tracing::warn!(
                target: "tenzro_node::identity_gate",
                %sender,
                reason = standing.refusal(),
                action = "audit",
                "mempool: would refuse a transaction from a sender with no registered identity"
            );
        }
        Standing::Registered
    }
}

/// Refuses a caller whose wallet address has no registered identity. For the
/// RPC, MCP and A2A write calls whose actor is a wallet address; the refusal
/// names its reason.
pub fn require_registered_caller(
    chain: &Arc<dyn KvStore>,
    caller: &Address,
) -> std::result::Result<(), String> {
    let state = StateAdapter::with_storage(chain.clone());
    let standing = account_standing(&state, caller.as_bytes());
    let standing = governed(&state, standing, "edge", &caller.to_string());
    if standing.is_registered() {
        Ok(())
    } else {
        Err(format!(
            "{caller}: {}; register an identity first (tenzro identity register, or the onboarding \
             request on the {} protocol)",
            standing.refusal(),
            String::from_utf8_lossy(tenzro_iroh::ALPN_ONBOARD)
        ))
    }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

/// Turns the peer gate on: installs the registry, the protected identities
/// and the sweeper. `protected` is the boot list and the validator set's
/// machine identities.
pub fn install_peer_gate(
    cfg: &OnboardingConfig,
    gate: &IdentityGate,
    registry: Arc<dyn RegistryView>,
    protected: HashSet<String>,
) -> Option<tokio::task::JoinHandle<()>> {
    if cfg.policy.mode == GateMode::Off {
        return None;
    }
    gate.set_policy(cfg.policy);
    gate.protect(protected);
    gate.install_registry(registry);
    tracing::info!(
        target: "tenzro_node::identity_gate",
        mode = ?cfg.policy.mode,
        window_secs = cfg.policy.window.as_secs(),
        "identity gate on: peers without a registered identity get an onboarding session only"
    );
    Some(gate.spawn_sweeper(Duration::from_secs(cfg.sweep_secs.max(1))))
}

/// Wires the identity registry into the mempool, in the gate's mode.
pub fn install_mempool_gate(
    cfg: &OnboardingConfig,
    mempool: &tenzro_consensus::Mempool,
    chain: Arc<dyn KvStore>,
) {
    let senders = ChainSenders::new(chain);
    let registry: Arc<dyn SenderRegistry> = match cfg.policy.mode {
        GateMode::Off => return,
        GateMode::Audit => Arc::new(AuditSenders(senders)),
        GateMode::Enforce => Arc::new(senders),
    };
    if let Err(e) = mempool.set_sender_registry(registry) {
        tracing::warn!(error = %e, "mempool identity gate already wired");
    }
}

// ---------------------------------------------------------------------------
// The onboarding service: status, challenge, sponsored registration
// ---------------------------------------------------------------------------

/// Gas a sponsored registration is sent with (what the CLI sends).
pub const SPONSOR_REGISTER_GAS: u64 = 200_000;

/// The sponsor's own ledger account, as the registration sink.
pub struct LedgerSink(pub Arc<crate::payment_rails::LedgerSubmitter>);

#[async_trait]
impl RegistrationSink for LedgerSink {
    async fn submit(&self, tx: TransactionType) -> std::result::Result<String, String> {
        self.0
            .submit_with_gas(Address::new([0u8; 32]), tx, SPONSOR_REGISTER_GAS)
            .await
    }

    fn fee_cap(&self) -> u128 {
        self.0.fee_for(SPONSOR_REGISTER_GAS)
    }
}

/// The machine identities the gate admits in full without a registry entry:
/// the boot list (operator's, genesis validators', remembered relays) and
/// the current validator set's machines.
pub fn protected_identities(
    config: &crate::config::NodeConfig,
    consensus: Option<&crate::consensus_driver::ConsensusHandle>,
    chain: Option<&Arc<dyn KvStore>>,
) -> HashSet<String> {
    let mut out: HashSet<String> = crate::identity_bootstrap::boot_entries(config)
        .map(|entries| entries.into_iter().map(|e| e.did).collect())
        .unwrap_or_default();
    if let Some(consensus) = consensus {
        let set = consensus.validator_set();
        let state = chain.map(|c| StateAdapter::with_storage(c.clone()));
        for v in set.active_validators() {
            out.insert(tenzro_types::did_derivation::machine_did(
                &v.public_key.p256,
            ));
            if let Some(state) = &state
                && let Some(m) =
                    tenzro_vm::native::validator_machine::machine_of(state, v.address.as_bytes())
            {
                out.insert(m.did());
            }
        }
    }
    out
}

/// Largest label a machine may carry.
const MAX_LABEL: usize = 64;

/// A request on the onboarding protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum OnboardRequest {
    /// Where does my identity stand?
    Status,
    /// A challenge an owner approval answers, for this machine and label.
    Challenge {
        /// The label the machine will carry.
        label: String,
    },
    /// Register my machine identity; pay the fee from the sponsor's account.
    Register {
        /// The `RegisterIdentity` transaction body the machine's hardware
        /// signed.
        tx: TransactionType,
        /// The label the approval named.
        label: String,
        /// The owner's approval of this machine, when one was given.
        approval: Option<OwnerApproval>,
    },
}

/// An owner's approval of a machine, answering an [`ApprovalChallenge`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerApproval {
    /// The challenge nonce.
    pub nonce: [u8; 16],
    /// The owner identity approving.
    pub owner_did: String,
    /// The owner's assertion over the challenge statement (a passkey
    /// assertion, verified by the node's [`OwnerApprovalVerifier`]).
    pub assertion: Vec<u8>,
}

/// A reply on the onboarding protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum OnboardReply {
    /// The peer's standing.
    Status {
        /// What the registry says.
        standing: Standing,
        /// The machine identity the peer's record names, if any.
        machine_did: Option<String>,
    },
    /// A challenge for the owner to approve.
    Challenge {
        /// The challenge.
        challenge: ApprovalChallenge,
        /// The statement the owner signs, hex.
        statement_hex: String,
    },
    /// The registration was admitted to the sponsor's mempool.
    Submitted {
        /// The transaction hash.
        tx_hash: String,
    },
    /// The registration chain state already holds.
    AlreadyRegistered,
    /// Refused, with the reason.
    Refused {
        /// Why.
        reason: String,
    },
}

/// Verifies an owner's approval of a machine: that `assertion` is the
/// owner's passkey assertion over `challenge.statement()`, and that
/// `owner_did` is a registered identity that owns the passkey. Returns the
/// owner identity on success.
///
/// The production verifier is the wallet-RP passkey assertion check (R31 and
/// R32); until it is wired, a node has none and a sponsored registration is
/// refused for want of a verifiable owner approval.
pub trait OwnerApprovalVerifier: Send + Sync {
    /// Checks the approval.
    fn verify(
        &self,
        challenge: &ApprovalChallenge,
        owner_did: &str,
        assertion: &[u8],
    ) -> std::result::Result<(), String>;
}

/// Where a sponsored registration is sent: the sponsor's own ledger account.
#[async_trait]
pub trait RegistrationSink: Send + Sync {
    /// Signs `tx` from the sponsor's account and admits it to the mempool,
    /// returning the transaction hash.
    async fn submit(&self, tx: TransactionType) -> std::result::Result<String, String>;
    /// The most the registration can cost the sponsor, in the smallest unit.
    fn fee_cap(&self) -> u128;
}

/// Answers the onboarding protocol.
pub struct OnboardServer {
    names: PeerNames,
    chain: Arc<dyn KvStore>,
    gate: IdentityGate,
    sink: RwLock<Option<Arc<dyn RegistrationSink>>>,
    verifier: Option<Arc<dyn OwnerApprovalVerifier>>,
    sponsor: Mutex<SponsorLedger>,
    approvals: Mutex<ApprovalBook>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    nonce: fn() -> [u8; 16],
}

/// The machine identity the transport-verified endpoint record of a
/// connection names.
pub type PeerNames = Arc<dyn Fn(EndpointId) -> Option<String> + Send + Sync>;

/// The names `discovery` holds: the machine identity of each verified,
/// unexpired endpoint record.
pub fn names_from(discovery: Arc<DiscoveryStore>) -> PeerNames {
    Arc::new(move |endpoint| discovery.naming(endpoint).map(|r| r.machine_did()))
}

impl std::fmt::Debug for OnboardServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnboardServer")
            .field("sponsors", &self.sink.read().is_some())
            .finish_non_exhaustive()
    }
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn random_nonce() -> [u8; 16] {
    rand::random()
}

impl OnboardServer {
    /// A server answering for `chain`, naming peers with `names`.
    /// `sink` is the sponsor's account (none: this node does not pay for
    /// anyone), `verifier` checks owner approvals (none: none verifies).
    pub fn new(
        cfg: &OnboardingConfig,
        names: PeerNames,
        chain: Arc<dyn KvStore>,
        gate: IdentityGate,
        sink: Option<Arc<dyn RegistrationSink>>,
        verifier: Option<Arc<dyn OwnerApprovalVerifier>>,
    ) -> Self {
        Self {
            names,
            chain,
            gate,
            sink: RwLock::new(sink),
            verifier,
            sponsor: Mutex::new(SponsorLedger::new(cfg.sponsor)),
            approvals: Mutex::new(ApprovalBook::new(cfg.policy.challenge_ttl, 1024)),
            clock: Arc::new(wall_ms),
            nonce: random_nonce,
        }
    }

    /// Installs the account that pays sponsored registrations. The ledger
    /// rail comes up after the endpoint, so the server starts without one.
    pub fn set_sink(&self, sink: Arc<dyn RegistrationSink>) {
        *self.sink.write() = Some(sink);
    }

    fn refused(reason: impl Into<String>) -> Reply {
        let reason = reason.into();
        tracing::warn!(target: "tenzro_node::identity_gate", %reason, "onboarding request refused");
        Self::reply(&OnboardReply::Refused { reason })
    }

    fn reply(reply: &OnboardReply) -> Reply {
        Reply::full(200, serde_json::to_vec(reply).unwrap_or_default())
    }

    fn standing_of(&self, did: &str) -> Standing {
        let state = StateAdapter::with_storage(self.chain.clone());
        did_standing(&state, did)
    }

    async fn register(
        &self,
        remote: EndpointId,
        did: &str,
        tx: TransactionType,
        label: &str,
        approval: Option<OwnerApproval>,
    ) -> OnboardReply {
        let refuse = |reason: String| {
            tracing::warn!(target: "tenzro_node::identity_gate", %did, %reason, "sponsored registration refused");
            OnboardReply::Refused { reason }
        };
        let Some(sink) = self.sink.read().clone() else {
            return refuse("this node does not sponsor registrations".into());
        };
        let TransactionType::RegisterIdentity {
            did: tx_did,
            identity_type,
            display_name,
            controller_pubkey,
            key_type,
            wallet_id,
            wallet_address,
            pq_verifying_key,
            metadata,
            proof,
        } = tx.clone()
        else {
            return refuse("the sponsored transaction is a RegisterIdentity".into());
        };
        // Only the peer's own hardware root: the DID the transport-verified
        // record names is the DID registered.
        if tx_did != did {
            return refuse(format!(
                "this connection is machine {did}; the registration names {tx_did}"
            ));
        }
        if identity_type != "machine" {
            return refuse(
                "only a machine identity is sponsored; a person registers with their wallet passkey"
                    .into(),
            );
        }
        match self.standing_of(did) {
            Standing::Registered => return OnboardReply::AlreadyRegistered,
            Standing::Revoked => return refuse("this identity was revoked".into()),
            Standing::Unregistered => {}
        }
        // The registration must be one the VM would accept: the DID derives
        // from the key it names, and the hardware key signed every field.
        let payload = tenzro_types::identity::RegisterIdentityPayload {
            did: tx_did,
            identity_type,
            display_name,
            controller_pubkey,
            key_type,
            wallet_id,
            wallet_address,
            pq_verifying_key,
            metadata,
            proof,
        };
        let controller_xy = match payload.controller_pubkey.as_slice() {
            [0x04, xy @ ..] if xy.len() == 64 => xy.to_vec(),
            other => other.to_vec(),
        };
        let enrolled = {
            let state = StateAdapter::with_storage(self.chain.clone());
            tenzro_vm::account_keys::enrolled_pq_key(&state, &controller_xy)
        };
        if !tenzro_tee::identity_evidence::registration_is_authorized(&payload, enrolled.as_deref())
        {
            return refuse("the registration is not authorized by its hardware key".into());
        }
        if label.is_empty() || label.len() > MAX_LABEL {
            return refuse(format!("the label is 1 to {MAX_LABEL} bytes"));
        }

        // The owner's approval, bound to this machine, endpoint and label.
        let now = (self.clock)();
        let mut owner = None;
        if let Some(a) = approval {
            let challenge =
                match self
                    .approvals
                    .lock()
                    .redeem(now, &a.nonce, did, &remote.to_string(), label)
                {
                    Ok(c) => c,
                    Err(e) => return refuse(e.reason().into()),
                };
            let Some(verifier) = &self.verifier else {
                return refuse("this node cannot verify owner approvals".into());
            };
            if let Err(e) = verifier.verify(&challenge, &a.owner_did, &a.assertion) {
                return refuse(format!("the owner approval did not verify: {e}"));
            }
            // The owner must exist and be resolvable on chain: no machine
            // is sponsored into the world without a traceable accountable
            // root (charter 20).
            match self.standing_of(&a.owner_did) {
                Standing::Registered => {}
                other => {
                    return refuse(format!(
                        "the approving owner {} is not accepted: {}",
                        a.owner_did,
                        other.refusal()
                    ));
                }
            }
            owner = Some(a.owner_did);
        }

        let ask = SponsorAsk {
            root: did.to_string(),
            provider: None,
            owner,
            source: self.gate.source_for(remote),
            fee: sink.fee_cap(),
        };
        let grant = match self.sponsor.lock().authorise(now, &ask) {
            Ok(g) => g,
            Err(e) => return refuse(e.reason().into()),
        };
        match sink.submit(tx).await {
            Ok(tx_hash) => {
                tracing::info!(target: "tenzro_node::identity_gate", %did, %tx_hash, "sponsored a machine's first registration");
                OnboardReply::Submitted { tx_hash }
            }
            Err(e) => {
                self.sponsor.lock().release(grant);
                refuse(format!("the registration was not admitted: {e}"))
            }
        }
    }
}

#[async_trait]
impl RequestHandler for OnboardServer {
    async fn handle(&self, remote: EndpointId, request: Bytes) -> Reply {
        let request: OnboardRequest = match serde_json::from_slice(&request) {
            Ok(r) => r,
            Err(e) => return Self::refused(format!("unreadable onboarding request: {e}")),
        };
        // The peer is the machine the transport-verified record names.
        let Some(did) = (self.names)(remote) else {
            return Self::refused(
                "no verified endpoint record names this connection; publish it on tenzro/discovery first",
            );
        };
        let reply = match request {
            OnboardRequest::Status => OnboardReply::Status {
                standing: self.standing_of(&did),
                machine_did: Some(did),
            },
            OnboardRequest::Challenge { label } => {
                if label.is_empty() || label.len() > MAX_LABEL {
                    return Self::refused(format!("the label is 1 to {MAX_LABEL} bytes"));
                }
                let now = (self.clock)();
                let challenge = self.approvals.lock().issue(
                    now,
                    (self.nonce)(),
                    &did,
                    &remote.to_string(),
                    &label,
                );
                // An approval is now visibly in progress: the onboarding
                // window may be extended once while it is.
                self.gate.approval_in_progress(
                    &remote.to_string(),
                    Some(&did),
                    challenge.expires_ms,
                );
                OnboardReply::Challenge {
                    statement_hex: hex::encode(challenge.statement()),
                    challenge,
                }
            }
            OnboardRequest::Register {
                tx,
                label,
                approval,
            } => self.register(remote, &did, tx, &label, approval).await,
        };
        Self::reply(&reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};

    fn endpoint(n: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[n; 32]).public()
    }

    #[derive(Default)]
    struct Sink {
        sent: Mutex<Vec<TransactionType>>,
        fail: AtomicBool,
    }

    #[async_trait]
    impl RegistrationSink for Sink {
        async fn submit(&self, tx: TransactionType) -> std::result::Result<String, String> {
            if self.fail.load(Ordering::SeqCst) {
                return Err("mempool full".into());
            }
            self.sent.lock().push(tx);
            Ok("0xabc".into())
        }
        fn fee_cap(&self) -> u128 {
            1_600_000_000_000_000
        }
    }

    /// A verifier standing in for the owner's passkey: accepts the assertion
    /// `owner-ok:<statement hex>` (a simulated owner approval).
    struct SimulatedOwner;

    impl OwnerApprovalVerifier for SimulatedOwner {
        fn verify(
            &self,
            challenge: &ApprovalChallenge,
            _owner_did: &str,
            assertion: &[u8],
        ) -> std::result::Result<(), String> {
            let expected = format!("owner-ok:{}", hex::encode(challenge.statement()));
            if assertion == expected.as_bytes() {
                Ok(())
            } else {
                Err("assertion does not cover this challenge".into())
            }
        }
    }

    fn nonce() -> [u8; 16] {
        static N: AtomicU64 = AtomicU64::new(1);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&N.fetch_add(1, Ordering::SeqCst).to_le_bytes());
        out
    }

    /// The `RegisterIdentity` a machine's hardware signs: the DID its key
    /// derives, the wallet it pays to, the statement signed by that key.
    fn registration(signer: &dyn HybridSigner, wallet: [u8; 32]) -> (String, TransactionType) {
        use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
        use tenzro_types::identity::{RegisterIdentityPayload, RegistrationProof};
        let public = signer.public_key().clone();
        let sec1 = [&[0x04u8][..], &public.p256].concat();
        let did = tenzro_types::did_derivation::machine_did(&sec1);
        let mut payload = RegisterIdentityPayload {
            did: did.clone(),
            identity_type: "machine".into(),
            display_name: "machine root".into(),
            controller_pubkey: sec1,
            key_type: "P-256".into(),
            wallet_id: format!("0x{}", hex::encode(wallet)),
            wallet_address: Address::new(wallet),
            pq_verifying_key: public.pq.clone().unwrap_or_default(),
            metadata: BTreeMap::new(),
            proof: RegistrationProof::Hardware {
                signature: CompositeSignature::classical(ClassicalProof::Raw {
                    signature: Vec::new(),
                }),
            },
        };
        let statement = tenzro_types::identity::registration_statement(&payload);
        let signature = signer
            .sign(SignatureContext::IdentityRegistration, &statement)
            .unwrap();
        payload.proof = RegistrationProof::Hardware {
            signature: serde_json::from_value(serde_json::to_value(&signature).unwrap()).unwrap(),
        };
        (
            did,
            TransactionType::RegisterIdentity {
                did: payload.did,
                identity_type: payload.identity_type,
                display_name: payload.display_name,
                controller_pubkey: payload.controller_pubkey,
                key_type: payload.key_type,
                wallet_id: payload.wallet_id,
                wallet_address: payload.wallet_address,
                pq_verifying_key: payload.pq_verifying_key,
                metadata: payload.metadata,
                proof: payload.proof,
            },
        )
    }

    struct Rig {
        server: OnboardServer,
        now: Arc<AtomicU64>,
        sink: Arc<Sink>,
        chain: Arc<dyn KvStore>,
        did: String,
        tx: TransactionType,
        remote: EndpointId,
    }

    /// Writes the identity record of `did` to the chain store the views read.
    fn put_identity_record(chain: &Arc<dyn KvStore>, did: &str) {
        let key = format!(
            "storage:{}:{}",
            hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
            hex::encode(tenzro_types::identity::identity_slot(did))
        );
        chain
            .put(tenzro_storage::CF_STATE, key.as_bytes(), b"{}")
            .unwrap();
    }

    fn register_owner(chain: &Arc<dyn KvStore>) {
        put_identity_record(chain, "did:tenzro:human:owner");
    }

    fn rig(sponsor_on: bool) -> Rig {
        let chain: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        register_owner(&chain);
        let sink = Arc::new(Sink::default());
        let mut cfg = OnboardingConfig::default();
        cfg.sponsor.enabled = sponsor_on;
        let signer = TestHybridSigner::hybrid(41);
        let (did, tx) = registration(&signer, [9; 32]);
        let remote = endpoint(9);
        let named = did.clone();
        let names: PeerNames = Arc::new(move |e| (e == remote).then(|| named.clone()));
        let gate = IdentityGate::new(cfg.policy, None);
        let mut server = OnboardServer::new(
            &cfg,
            names,
            chain.clone(),
            gate,
            Some(sink.clone()),
            Some(Arc::new(SimulatedOwner)),
        );
        let now = Arc::new(AtomicU64::new(1_000_000));
        let ticking = now.clone();
        server.clock = Arc::new(move || ticking.load(Ordering::SeqCst));
        server.nonce = nonce;
        Rig {
            server,
            now,
            sink,
            chain,
            did,
            tx,
            remote,
        }
    }

    async fn ask(r: &Rig, from: EndpointId, req: &OnboardRequest) -> OnboardReply {
        let reply = r
            .server
            .handle(from, Bytes::from(serde_json::to_vec(req).unwrap()))
            .await;
        let tenzro_iroh::ReplyBody::Full(body) = reply.body else {
            panic!("streamed")
        };
        serde_json::from_slice(&body).unwrap()
    }

    async fn challenge(r: &Rig, label: &str) -> ApprovalChallenge {
        match ask(
            r,
            r.remote,
            &OnboardRequest::Challenge {
                label: label.into(),
            },
        )
        .await
        {
            OnboardReply::Challenge { challenge, .. } => challenge,
            other => panic!("{other:?}"),
        }
    }

    fn approval(c: &ApprovalChallenge) -> OwnerApproval {
        OwnerApproval {
            nonce: c.nonce,
            owner_did: "did:tenzro:human:owner".into(),
            assertion: format!("owner-ok:{}", hex::encode(c.statement())).into_bytes(),
        }
    }

    fn register_req(r: &Rig, label: &str, a: Option<OwnerApproval>) -> OnboardRequest {
        OnboardRequest::Register {
            tx: r.tx.clone(),
            label: label.into(),
            approval: a,
        }
    }

    fn refused(reply: OnboardReply) -> String {
        match reply {
            OnboardReply::Refused { reason } => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_defaults_audit_and_do_not_sponsor() {
        let cfg = OnboardingConfig::default();
        assert_eq!(cfg.policy.mode, GateMode::Audit);
        assert!(!cfg.sponsor.enabled);
        assert!(cfg.sponsor.require_owner_approval);
    }

    #[test]
    fn the_config_reads_as_one_table() {
        let cfg: OnboardingConfig = toml::from_str(
            "mode = \"audit\"\nwindow = 600\n[sponsor]\nenabled = true\nmax_per_day = 5\n",
        )
        .unwrap();
        assert_eq!(cfg.policy.mode, GateMode::Audit);
        assert_eq!(cfg.policy.window, Duration::from_secs(600));
        assert!(cfg.sponsor.enabled);
        assert_eq!(cfg.sponsor.max_per_day, 5);
        let empty: OnboardingConfig = toml::from_str("").unwrap();
        assert_eq!(empty.policy.mode, GateMode::Audit);
    }

    #[test]
    fn an_account_is_registered_by_the_wallet_index_and_revoked_by_the_marker() {
        let chain: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let senders = ChainSenders::new(chain.clone());
        let a = Address::new([5; 32]);
        assert_eq!(senders.sender_standing(&a), Standing::Unregistered);
        // What RegisterIdentity writes, in the chain store each view reads.
        let key = format!(
            "storage:{}:{}",
            hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
            hex::encode(format!("identity_wallet:{}", hex::encode(a.as_bytes())))
        );
        chain
            .put(
                tenzro_storage::CF_STATE,
                key.as_bytes(),
                b"did:tenzro:machine:aa",
            )
            .unwrap();
        assert_eq!(senders.sender_standing(&a), Standing::Registered);
        assert!(require_registered_caller(&chain, &a).is_ok());
        let b = Address::new([6; 32]);
        let err = require_registered_caller(&chain, &b).unwrap_err();
        assert!(err.contains("no registered identity"), "{err}");
    }

    #[test]
    fn the_governed_mode_relaxes_every_node_layer_with_no_config_change() {
        use tenzro_vm::identity_required::{MODE_KEY, Mode};
        let chain: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let senders = ChainSenders::new(chain.clone());
        let peers = ChainRegistry::new(chain.clone(), Arc::new(|| true));
        let stranger = Address::new([7; 32]);
        let did = "did:tenzro:machine:bb";
        // Where an enacted parameter change lands in chain state, written
        // straight to the store each view reads.
        let set_mode = |mode: Mode| {
            let key = format!(
                "storage:{}:{}",
                hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
                hex::encode(tenzro_vm::native::governed_param_key(MODE_KEY))
            );
            chain
                .put(
                    tenzro_storage::CF_STATE,
                    key.as_bytes(),
                    &(mode as u64).to_le_bytes(),
                )
                .unwrap();
        };
        // No vote: enforce.
        assert_eq!(senders.sender_standing(&stranger), Standing::Unregistered);
        assert!(require_registered_caller(&chain, &stranger).is_err());
        assert_eq!(peers.standing(did), Standing::Unregistered);

        for relaxed in [Mode::Audit, Mode::Off] {
            set_mode(relaxed);
            assert_eq!(senders.sender_standing(&stranger), Standing::Registered);
            assert!(require_registered_caller(&chain, &stranger).is_ok());
            assert_eq!(peers.standing(did), Standing::Registered);
        }

        set_mode(Mode::Enforce);
        assert_eq!(senders.sender_standing(&stranger), Standing::Unregistered);
        assert_eq!(peers.standing(did), Standing::Unregistered);
    }

    #[tokio::test]
    async fn a_connection_no_record_names_gets_nothing_from_the_onboarding_service() {
        let r = rig(true);
        let reason = refused(ask(&r, endpoint(77), &OnboardRequest::Status).await);
        assert!(reason.contains("no verified endpoint record"), "{reason}");
    }

    #[tokio::test]
    async fn acceptance_a_fresh_machine_registers_with_one_simulated_owner_approval() {
        let r = rig(true);
        // From empty: the chain knows nothing of the machine.
        let OnboardReply::Status {
            standing,
            machine_did,
        } = ask(&r, r.remote, &OnboardRequest::Status).await
        else {
            panic!()
        };
        assert_eq!(standing, Standing::Unregistered);
        assert_eq!(machine_did.as_deref(), Some(r.did.as_str()));

        // One owner approval, of this machine, endpoint and label.
        let c = challenge(&r, "pi").await;
        let reply = ask(&r, r.remote, &register_req(&r, "pi", Some(approval(&c)))).await;
        assert!(matches!(reply, OnboardReply::Submitted { .. }), "{reply:?}");
        // The sponsor's account sent the machine's own signed registration.
        let sent = r.sink.sent.lock();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], r.tx);
    }

    #[tokio::test]
    async fn a_registration_without_an_owner_approval_is_not_sponsored() {
        let r = rig(true);
        let reason = refused(ask(&r, r.remote, &register_req(&r, "pi", None)).await);
        assert!(reason.contains("owner approval"), "{reason}");
        assert!(r.sink.sent.lock().is_empty());
    }

    #[tokio::test]
    async fn an_owner_the_chain_does_not_hold_cannot_back_a_machine() {
        let r = rig(true);
        let c = challenge(&r, "pi").await;
        let mut a = approval(&c);
        a.owner_did = "did:tenzro:human:nobody".into();
        let reason = refused(ask(&r, r.remote, &register_req(&r, "pi", Some(a))).await);
        assert!(reason.contains("is not accepted"), "{reason}");
        assert!(r.sink.sent.lock().is_empty());
    }

    #[tokio::test]
    async fn a_node_that_does_not_sponsor_refuses() {
        let r = rig(false);
        let c = challenge(&r, "pi").await;
        let reason = refused(ask(&r, r.remote, &register_req(&r, "pi", Some(approval(&c)))).await);
        assert!(reason.contains("does not sponsor"), "{reason}");
    }

    #[tokio::test]
    async fn a_stale_approval_cannot_be_replayed() {
        let r = rig(true);
        let c = challenge(&r, "pi").await;
        let a = approval(&c);
        assert!(matches!(
            ask(&r, r.remote, &register_req(&r, "pi", Some(a.clone()))).await,
            OnboardReply::Submitted { .. }
        ));
        // Same approval, again: the challenge is spent.
        let reason = refused(ask(&r, r.remote, &register_req(&r, "pi", Some(a))).await);
        assert!(reason.contains("already used"), "{reason}");

        // An approval that outlives its five minutes.
        let r = rig(true);
        let c = challenge(&r, "pi").await;
        r.now.fetch_add(6 * 60_000, Ordering::SeqCst);
        let reason = refused(ask(&r, r.remote, &register_req(&r, "pi", Some(approval(&c)))).await);
        assert!(reason.contains("expired"), "{reason}");
    }

    #[tokio::test]
    async fn an_approval_for_another_label_or_another_machine_is_refused() {
        let r = rig(true);
        let c = challenge(&r, "pi").await;
        let reason =
            refused(ask(&r, r.remote, &register_req(&r, "other", Some(approval(&c)))).await);
        assert!(
            reason.contains("another machine, endpoint or label"),
            "{reason}"
        );

        // An assertion that does not cover the challenge the machine was given.
        let c = challenge(&r, "pi").await;
        let reason = refused(
            ask(
                &r,
                r.remote,
                &register_req(
                    &r,
                    "pi",
                    Some(OwnerApproval {
                        assertion: b"owner-ok:forged".to_vec(),
                        ..approval(&c)
                    }),
                ),
            )
            .await,
        );
        assert!(reason.contains("did not verify"), "{reason}");
        assert!(r.sink.sent.lock().is_empty());
    }

    #[tokio::test]
    async fn a_machine_can_only_register_its_own_hardware_root() {
        let r = rig(true);
        let c = challenge(&r, "pi").await;
        let (_, someone_elses) = registration(&TestHybridSigner::hybrid(42), [8; 32]);
        let reply = ask(
            &r,
            r.remote,
            &OnboardRequest::Register {
                tx: someone_elses,
                label: "pi".into(),
                approval: Some(approval(&c)),
            },
        )
        .await;
        assert!(refused(reply).contains("this connection is machine"));
        assert!(r.sink.sent.lock().is_empty());
    }

    #[tokio::test]
    async fn a_registration_the_vm_would_reject_is_not_paid_for() {
        let r = rig(true);
        let c = challenge(&r, "pi").await;
        let mut tx = r.tx.clone();
        if let TransactionType::RegisterIdentity { display_name, .. } = &mut tx {
            *display_name = "tampered after signing".into();
        }
        let reply = ask(
            &r,
            r.remote,
            &OnboardRequest::Register {
                tx,
                label: "pi".into(),
                approval: Some(approval(&c)),
            },
        )
        .await;
        assert!(refused(reply).contains("not authorized by its hardware key"));
        assert!(r.sink.sent.lock().is_empty());
    }

    #[tokio::test]
    async fn one_hardware_root_is_sponsored_once_and_a_failed_submission_gives_the_turn_back() {
        let r = rig(true);
        r.sink.fail.store(true, Ordering::SeqCst);
        let c = challenge(&r, "pi").await;
        let reason = refused(ask(&r, r.remote, &register_req(&r, "pi", Some(approval(&c)))).await);
        assert!(reason.contains("was not admitted"), "{reason}");
        r.sink.fail.store(false, Ordering::SeqCst);

        let c = challenge(&r, "pi").await;
        assert!(matches!(
            ask(&r, r.remote, &register_req(&r, "pi", Some(approval(&c)))).await,
            OnboardReply::Submitted { .. }
        ));
        // The transaction has not executed yet; the root has had its turn.
        let c = challenge(&r, "pi").await;
        let reason = refused(ask(&r, r.remote, &register_req(&r, "pi", Some(approval(&c)))).await);
        assert!(
            reason.contains("already had its sponsored registration"),
            "{reason}"
        );
        assert_eq!(r.sink.sent.lock().len(), 1);
    }

    #[tokio::test]
    async fn a_machine_the_chain_already_holds_is_told_so_and_not_paid_for() {
        let r = rig(true);
        put_identity_record(&r.chain, &r.did);
        let c = challenge(&r, "pi").await;
        assert!(matches!(
            ask(&r, r.remote, &register_req(&r, "pi", Some(approval(&c)))).await,
            OnboardReply::AlreadyRegistered
        ));
        assert!(r.sink.sent.lock().is_empty());
    }
}
