//! Joining the network by machine identity.
//!
//! A node's boot list names machine identities, never network addresses:
//! the entries the operator gives (`--boot-nodes`, `TENZRO_BOOT_NODES`,
//! `[iroh] boot`) and the genesis validators, whose consensus keys carry the
//! P-256 key their machine identities derive from. [`start`] admits the
//! relays those entries name, each verified by its operator's signed record,
//! and starts this node's own relay when it serves the role; [`announce`]
//! then keeps this machine's endpoint record published and the boot
//! identities resolved.
//!
//! Both lists are only a way in. A running node remembers the relay
//! operators it met through the discovery network ([`remember`]) and joins
//! through them too after a restart, so it never depends on the operator's
//! list or the genesis validators still being reachable.

use std::sync::{Arc, OnceLock};

use tenzro_device_key::HardwareSigner;
use tenzro_iroh::{BootIdentity, IdentityTransport};
use tenzro_types::Visibility;
use tenzro_types::did_derivation::{MACHINE_KEY_LABEL, machine_did as did_of_key};

use crate::config::{GenesisConfig, NodeConfig};
use crate::error::{NodeError, Result};

/// This machine's identity key once opened, or why it did not open.
static MACHINE_SIGNER: OnceLock<std::result::Result<Box<dyn HardwareSigner>, String>> =
    OnceLock::new();

/// This machine's identity key, opened once, or why it did not open.
fn opened_machine_signer() -> &'static std::result::Result<Box<dyn HardwareSigner>, String> {
    MACHINE_SIGNER.get_or_init(|| {
        // Opening the key can take minutes on a TPM that is busy or slow; say so before waiting.
        tracing::info!(
            "Opening this machine's identity key in its TPM or Secure Enclave; a first start can take up to three minutes"
        );
        let started = std::time::Instant::now();
        let opened =
            tenzro_device_key::signer::open_or_create(MACHINE_KEY_LABEL).map_err(|e| e.to_string());
        match &opened {
            Ok(_) => tracing::info!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                "machine identity key is open"
            ),
            Err(e) => tracing::warn!(error = %e, "machine identity key did not open"),
        }
        opened
    })
}

/// The machine identities behind gossip neighbours, read from the verified,
/// unexpired endpoint records the discovery store holds. A record names an
/// endpoint only after it verified against the machine identity it claims.
pub struct RecordedPeers {
    /// The discovery store the records are read from.
    pub store: Arc<tenzro_iroh::DiscoveryStore>,
    /// The consensus that knows the validators' keys, which checks the
    /// endpoint announcements a neighbour no record names delivers. Without
    /// it no such neighbour is heard.
    pub consensus: Option<Arc<crate::consensus_driver::ConsensusHandle>>,
    /// The identity registry (consensus chain state) the identity gate reads
    /// to tell a registered neighbour from one that is merely named.
    pub registry: Option<Arc<dyn tenzro_iroh::RegistryView>>,
    /// The peer gate, whose protected identities (the boot list and the
    /// validators' machines) stand as registered here as they do there.
    pub gate: Option<tenzro_iroh::IdentityGate>,
}

impl tenzro_network::PeerIdentities for RecordedPeers {
    fn machine_did(&self, endpoint: tenzro_iroh::EndpointId) -> Option<String> {
        self.store
            .naming(endpoint)
            .map(|record| record.machine_did())
    }

    fn vouches_for_announcement(&self, announcement: &[u8]) -> bool {
        self.consensus
            .as_ref()
            .is_some_and(|c| c.vouches_for_announcement(announcement))
    }

    fn registry_standing(&self, did: &str) -> tenzro_onboarding_types::onboarding::Standing {
        use tenzro_onboarding_types::onboarding::Standing;
        // A machine the peer gate admits whatever the registry says is heard
        // on gossip as well: a validator's machine need not be registered.
        if self.gate.as_ref().is_some_and(|g| g.protects(did)) {
            return Standing::Registered;
        }
        match &self.registry {
            // A registry that cannot be believed yet (the node is syncing)
            // vouches for no one the gate does not protect.
            Some(r) if r.ready() => r.standing(did),
            Some(_) => Standing::Unregistered,
            // No registry wired: the identity gate is not in play.
            None => Standing::Registered,
        }
    }
}

/// This machine's identity, when this process has already opened its
/// identity key. Never opens the key itself, so a record written before the
/// node checked its hardware names no machine rather than touching it.
pub fn opened_machine_did() -> Option<String> {
    static DID: OnceLock<String> = OnceLock::new();
    if let Some(did) = DID.get() {
        return Some(did.clone());
    }
    let signer = MACHINE_SIGNER.get()?.as_deref().ok()?;
    let did = did_of_key(&signer.public_key_sec1().ok()?);
    Some(DID.get_or_init(|| did).clone())
}

/// Where this machine's identity key lives when the machine has no TPM of
/// its own: a TPM in another machine the operator owns. Set once, before the
/// key is first opened.
static REMOTE: OnceLock<crate::remote_tpm::RemoteConfig> = OnceLock::new();

/// Uses the identity key held by a provider instead of a local TPM.
pub fn use_remote_tpm(config: crate::remote_tpm::RemoteConfig) -> std::result::Result<(), String> {
    crate::remote_tpm::install(&config).map_err(|e| e.to_string())?;
    REMOTE
        .set(config)
        .map_err(|_| "the remote TPM is already configured".to_string())
}

/// Whether the identity key is held by a provider.
pub fn remote_tpm_configured() -> bool {
    REMOTE.get().is_some()
}

/// This machine's identity key, opened once. `None` when the machine has no
/// TPM 2.0 or Secure Enclave. A node process never runs in that state: it
/// refuses to start ([`require_hardware_identity`]).
pub fn machine_signer() -> Option<&'static dyn HardwareSigner> {
    opened_machine_signer().as_deref().ok()
}

/// Why a node refuses to start on a machine with no hardware key store.
pub const NO_HARDWARE_IDENTITY: &str = "this machine has no TPM 2.0 (Linux /dev/tpmrm0, Windows TPM \
     Base Services) or Secure Enclave (macOS), so it has no machine identity key. A Tenzro node runs \
     only with its identity key in hardware; there is no keyless or software-key mode. If the \
     machine has a TPM, turn it on in the firmware settings (it may be called fTPM, PTT or Security \
     Device), run `tenzro-node tpm provision` as the node user, and start again. If it has none (a \
     Raspberry Pi, for example), keep the key in another machine's TPM: run `tenzro-node tpm \
     key-holder` and start with --tpm-key-holder (docs/NODE.md, Raspberry Pi and other edge \
     devices), or use the network with a passkey instead: tenzro setup --path network.";

/// Refuses on a machine with no TPM 2.0 or Secure Enclave. Needs no
/// configuration, so a node checks it before anything else.
pub fn require_hardware_key_store() -> std::result::Result<(), String> {
    hardware_identity_verdict(
        tenzro_device_key::signer::platform_backend().is_some() || remote_tpm_configured(),
        || Ok(()),
    )
}

/// Refuses unless this machine holds its identity key in a TPM 2.0 or a
/// Secure Enclave and the key opens. Checked at node start, before any
/// state is opened, so a node never runs without an identity.
pub fn require_hardware_identity() -> std::result::Result<(), String> {
    hardware_identity_verdict(
        tenzro_device_key::signer::platform_backend().is_some() || remote_tpm_configured(),
        || {
            opened_machine_signer()
                .as_ref()
                .map(|_| ())
                .map_err(Clone::clone)
        },
    )
}

/// The start verdict for a machine that has (`has_backend`) or lacks a
/// hardware key store, whose identity key opens as `open` reports.
fn hardware_identity_verdict(
    has_backend: bool,
    open: impl FnOnce() -> std::result::Result<(), String>,
) -> std::result::Result<(), String> {
    if !has_backend {
        return Err(NO_HARDWARE_IDENTITY.to_string());
    }
    open().map_err(|e| {
        format!(
            "the machine identity key in this machine's TPM 2.0 or Secure Enclave does not open \
             ({e}); a node does not start without it. Run `tenzro-node tpm provision` as the node \
             user and check that it can open /dev/tpmrm0."
        )
    })
}

/// This machine's identity, `did:tenzro:machine:{id}`, when it has one.
pub fn machine_did() -> Option<String> {
    machine_signer()?
        .public_key_sec1()
        .ok()
        .map(|pk| did_of_key(&pk))
}

/// This machine's ML-DSA-65 verifying key, the one its derivation root
/// derives under the machine key label, read once. `None` when the root does
/// not open.
pub fn machine_ml_dsa_public() -> Option<Vec<u8>> {
    static KEY: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    KEY.get_or_init(|| {
        tenzro_device_key::DerivationRoot::open_or_create()
            .ok()?
            .ml_dsa65_public(MACHINE_KEY_LABEL)
            .ok()
    })
    .clone()
}

/// The registry slot a node fills once its identity registry is up.
pub type RegistrySlot = Arc<parking_lot::RwLock<Option<Arc<tenzro_identity::IdentityRegistry>>>>;

/// The composite key registered for the machine identity of a validator
/// whose consensus key has P-256 leg `consensus_p256` (SEC1). `None` when the
/// registry is not up yet or the machine identity has no registered key: a
/// validator in that state cannot attest.
pub fn registered_machine_key(
    registry: &RegistrySlot,
    consensus_p256: &[u8],
) -> Option<tenzro_crypto::composite::CompositePublicKey> {
    registered_identity_key(registry, &did_of_key(consensus_p256))
}

/// The hardware identity key registered for `did`. `None` when the registry
/// is not up yet or the identity has no registered key.
pub fn registered_identity_key(
    registry: &RegistrySlot,
    did: &str,
) -> Option<tenzro_crypto::composite::CompositePublicKey> {
    let registry = registry.read().clone()?;
    tenzro_identity::identity_key(&registry.resolve(did).ok()?)
}

/// The genesis validators as boot identities: each validator's machine
/// identity, from the P-256 leg of its consensus key, with the relay its
/// entry names.
pub fn genesis_boot(genesis: &GenesisConfig) -> Result<Vec<BootIdentity>> {
    genesis
        .validators
        .iter()
        .map(|v| {
            let key =
                hex::decode(v.p256_public_key.trim().trim_start_matches("0x")).map_err(|e| {
                    NodeError::Config(format!("genesis validator p256_public_key: {e}"))
                })?;
            let did = did_of_key(&key);
            let entry = match &v.relay {
                Some(relay) => format!("{did}@{relay}"),
                None => did,
            };
            entry.parse().map_err(NodeError::Config)
        })
        .collect()
}

/// Every boot identity this node joins through: the operator's, then the
/// genesis validators', then the relay operators it remembered from its last
/// run, without repeats.
pub fn boot_entries(config: &NodeConfig) -> Result<Vec<BootIdentity>> {
    let mut entries = config.iroh.boot.clone();
    let add = |entries: &mut Vec<BootIdentity>, entry: BootIdentity| {
        if !entries.iter().any(|e| e.did == entry.did) {
            entries.push(entry);
        }
    };
    if let Some(genesis) = &config.genesis {
        for entry in genesis_boot(genesis)? {
            add(&mut entries, entry);
        }
    }
    for entry in remembered(&config.data_dir) {
        add(&mut entries, entry);
    }
    Ok(entries)
}

/// Most relay operators a node remembers between runs.
pub const MAX_REMEMBERED: usize = 16;

/// How often the remembered relay operators are refreshed.
const REMEMBER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// How often the relay operators are looked for until the first are found.
const REMEMBER_FIRST: std::time::Duration = std::time::Duration::from_secs(30);

fn remembered_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("iroh").join("known-relays.json")
}

/// The relay operators this node remembered from its last run. A missing or
/// unreadable file, or an entry that no longer parses, is skipped: the list
/// is a hint, never a requirement.
pub fn remembered(data_dir: &std::path::Path) -> Vec<BootIdentity> {
    let Ok(bytes) = std::fs::read(remembered_path(data_dir)) else {
        return Vec::new();
    };
    let entries: Vec<String> = serde_json::from_slice(&bytes).unwrap_or_default();
    entries
        .iter()
        .filter_map(|e| e.parse().ok())
        .take(MAX_REMEMBERED)
        .collect()
}

/// The relay operators to remember from the records this node holds: the
/// network-wide records of machines that serve the relay role, newest first.
pub fn relay_operators(records: &[tenzro_iroh::EndpointRecord]) -> Vec<BootIdentity> {
    let mut serving: Vec<&tenzro_iroh::EndpointRecord> = records
        .iter()
        .filter(|r| r.scope == tenzro_iroh::RecordScope::Network && r.serves_relay.is_some())
        .collect();
    serving.sort_by_key(|s| std::cmp::Reverse(s.issued_ms));
    serving
        .into_iter()
        .filter_map(|r| {
            format!("{}@{}", r.machine_did(), r.serves_relay.as_ref()?)
                .parse()
                .ok()
        })
        .take(MAX_REMEMBERED)
        .collect()
}

/// Keeps the relay operators this node meets written under its data
/// directory, so the next start can join through them.
pub fn remember(transport: &Arc<IdentityTransport>, data_dir: std::path::PathBuf) {
    let transport = transport.clone();
    tokio::spawn(async move {
        let mut wait = REMEMBER_FIRST;
        loop {
            tokio::time::sleep(wait).await;
            let operators = relay_operators(&transport.store().records());
            if operators.is_empty() {
                continue;
            }
            wait = REMEMBER_INTERVAL;
            let path = remembered_path(&data_dir);
            let list: Vec<String> = operators.iter().map(ToString::to_string).collect();
            let tmp = path.with_extension("json.tmp");
            let written = serde_json::to_vec(&list)
                .map_err(std::io::Error::other)
                .and_then(|bytes| {
                    std::fs::create_dir_all(path.parent().unwrap_or(&data_dir))?;
                    std::fs::write(&tmp, bytes)
                })
                .and_then(|()| std::fs::rename(&tmp, &path));
            if let Err(e) = written {
                tracing::debug!(error = %e, "could not remember relay operators");
            }
        }
    });
}

/// Whether the node is private: its node-wide visibility announces nothing.
pub fn is_private(visibility: &Visibility) -> bool {
    !visibility.is_announced()
}

/// A private node's counterparties: its boot identities and the identities
/// its operator lists in `[iroh] counterparties`.
pub fn counterparties(config: &NodeConfig) -> Vec<String> {
    let mut list: Vec<String> = boot_entries(config)
        .unwrap_or_default()
        .into_iter()
        .map(|b| b.did)
        .collect();
    list.extend(config.iroh.counterparties.iter().cloned());
    list
}

/// The relay URLs staked edge operators publish in `chain`, most bonded
/// first. Relaying is part of the edge role: an edge operator serves the
/// relay at the URL its bond publishes, and any node can find it there.
pub fn staked_relays(chain: &dyn tenzro_vm::VmState) -> Vec<url::Url> {
    tenzro_vm::native::role_endpoints(chain, tenzro_types::NetworkRole::Edge)
        .into_iter()
        .filter_map(|e| url::Url::parse(&e.url).ok())
        .filter(|u| matches!(u.scheme(), "https" | "http"))
        .collect()
}

/// Admits the boot relays and the relays of staked edge operators
/// (`staked`, see [`staked_relays`]) and starts this node's relay role when
/// configured.
pub async fn start(config: &NodeConfig, staked: &[url::Url]) -> Result<Arc<IdentityTransport>> {
    let boot = boot_entries(config)?;
    if boot.is_empty() && staked.is_empty() && config.iroh.relay.is_none() {
        tracing::warn!(
            "No boot identities: this node reaches no one by identity. Pass --boot-nodes \
             did:tenzro:machine:<id>@<relay url>, or a genesis whose validators name relays."
        );
    }
    // A relay the boot list names is admitted when its operator's signed
    // record can be fetched, and the transport waits a minute for that. A
    // relay that was not up in that minute is kept as a candidate, is in the
    // endpoint's relay map from the start, and is asked again every round of
    // the record loop (see `IdentityTransport::admit_pending`), so the node
    // starts after one ask and recovers its relay without a restart.
    // (A node serving the relay itself starts once: starting it binds the
    // relay listener.)
    let wants_relay = config.iroh.relay.is_none() && boot.iter().any(|b| b.relay.is_some());
    let own_did = machine_did();
    let transport = admit_boot_relays(
        wants_relay,
        START_ADMISSION_ROUNDS,
        || {
            let (boot, own_did) = (boot.clone(), own_did.clone());
            async move {
                IdentityTransport::start_with_limits(
                    boot,
                    staked,
                    config.iroh.relay.as_ref(),
                    own_did,
                    config.iroh.relay_limits.limits(),
                )
                .await
                .map_err(|e| NodeError::Config(format!("identity transport: {e}")))
            }
        },
        |t| !t.relays().is_empty(),
    )
    .await?;
    // Relays the config names beside the boot list's, and the direct
    // addresses it fixes for peers. A relay that does not answer now is asked
    // again every round and joins the running endpoint when it does.
    let mut extra = Vec::new();
    for url in &config.iroh.relay_urls {
        tenzro_iroh::identity_record::check_relay_url(url)
            .map_err(|e| NodeError::Config(format!("[iroh] relay_urls {url}: {e}")))?;
        extra.push(url.clone());
    }
    transport.add_relay_candidates(&extra);
    transport.set_static_addrs(config.iroh.peer_addrs.clone());
    transport.keep_direct_addrs(config.data_dir.join("iroh").join("direct-addrs.json"));
    // Providers of weights gated behind a licence serve them to this machine
    // only when its record states its operator accepted that licence.
    transport
        .declare_accepted_licences(&config.model_licensing.accepted_license_ids)
        .map_err(|e| NodeError::Config(format!("--accept-license: {e}")))?;
    if machine_did().is_some() {
        bind_records(&transport);
    }
    keep_pq_pins(&transport, config.data_dir.clone());
    crate::update_advert::keep(&transport, config.data_dir.clone());
    Ok(transport)
}

/// The asks [`start`] makes before going on: the record loop keeps asking.
const START_ADMISSION_ROUNDS: u32 = 1;

/// How many times a start asks for the boot relays' records, each ask
/// waiting up to the transport's own admission window (a minute).
pub const RELAY_ADMISSION_ROUNDS: u32 = 5;

/// Starts the transport with `start`, again when `wants_relay` and it
/// admitted no relay, up to `rounds` times in all. The last transport is
/// returned either way: a node whose relay never answers still starts, and
/// says so.
async fn admit_boot_relays<T, Fut>(
    wants_relay: bool,
    rounds: u32,
    mut start: impl FnMut() -> Fut,
    has_relay: impl Fn(&T) -> bool,
) -> Result<T>
where
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut round = 1;
    loop {
        let transport = start().await?;
        if !wants_relay || has_relay(&transport) {
            return Ok(transport);
        }
        if round >= rounds {
            tracing::error!(
                rounds,
                "no boot relay answered: this node starts with its relays unadmitted and asks \
                 again every few seconds; peers are reached when one answers"
            );
            return Ok(transport);
        }
        tracing::warn!(round, rounds, "no boot relay admitted yet; asking again");
        round += 1;
    }
}

/// Where the ML-DSA pins of the identities this node has met are saved.
fn pq_pins_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("iroh").join("pq-pins.json")
}

/// How often changed ML-DSA pins are saved.
const PQ_PINS_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Takes back the ML-DSA pins the last run saved, so an identity that bound
/// its records before the restart cannot have the binding stripped after
/// it, and keeps them saved while the node runs.
fn keep_pq_pins(transport: &Arc<IdentityTransport>, data_dir: std::path::PathBuf) {
    let path = pq_pins_path(&data_dir);
    let mut saved = match transport.store().restore_pq_pins(&path) {
        Ok(n) => {
            if n > 0 {
                tracing::info!(
                    pins = n,
                    "took back the ML-DSA pins of identities met before"
                );
            }
            transport
                .store()
                .save_pq_pins(&path, u64::MAX)
                .unwrap_or(u64::MAX)
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "could not read the saved ML-DSA pins");
            u64::MAX
        }
    };
    let transport = transport.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(PQ_PINS_SAVE_INTERVAL).await;
            match transport.store().save_pq_pins(&path, saved) {
                Ok(changes) => saved = changes,
                Err(e) => tracing::warn!(error = %e, "could not save the ML-DSA pins"),
            }
        }
    });
}

/// Holds each validator in `validators` to the ML-DSA key its machine
/// identity registered. A validator whose consensus key is ML-DSA-65 /
/// P-256 names its machine by that key: its P-256 leg is the machine key its
/// identity derives from, and the node binds its endpoint records with the
/// ML-DSA-65 key the same root derives under the same label. A validator of
/// another scheme (ML-DSA-87 / P-384) names its machine identity on chain
/// apart from its consensus key; `registered` returns it (see
/// [`tenzro_vm::native::validator_machine::machine_of`]). A validator that
/// names none is not pinned. Returns how many were pinned.
pub fn pin_validator_pq_keys(
    identity: &IdentityTransport,
    validators: &[tenzro_consensus::ValidatorInfo],
    registered: impl Fn(&tenzro_types::primitives::Address) -> Option<(String, Vec<u8>)>,
) -> usize {
    let mut pinned = 0;
    for v in validators {
        if v.public_key.scheme() == tenzro_types::signature_scheme::SignatureScheme::MlDsa65P256 {
            identity.pin_pq_key(&did_of_key(&v.public_key.p256), v.public_key.ml_dsa.clone());
            pinned += 1;
        } else if let Some((did, machine_pq_key)) = registered(&v.address) {
            identity.pin_pq_key(&did, machine_pq_key);
            pinned += 1;
        }
    }
    pinned
}

/// Keeps the validators of the current epoch pinned (see
/// [`pin_validator_pq_keys`]) for as long as the node runs, so joins, key
/// rotations and machine registrations are followed within a minute.
/// `chain` reads the machine identities registered on chain.
pub fn keep_validators_pinned(
    identity: Arc<IdentityTransport>,
    epochs: Arc<tenzro_consensus::EpochManager>,
    chain: Option<Arc<dyn tenzro_storage::KvStore>>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            let set = epochs.current_validator_set();
            let state = chain.clone().map(tenzro_vm::StateAdapter::with_storage);
            pin_validator_pq_keys(&identity, set.active_validators(), |address| {
                let state = state.as_ref()?;
                tenzro_vm::native::validator_machine::machine_of(state, address.as_bytes())
                    .map(|m| (m.did(), m.tagged_ml_dsa()))
            });
        }
    });
}

/// How often the node follows the chain's post-quantum policies.
const CHAIN_POLICY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Follows, for as long as the node runs, what governance has put in force
/// on chain:
/// - hybrid stored records: the moment from which this node signs stored
///   records with hybrid session keys and requires them of others (see
///   [`tenzro_crypto::session::set_hybrid_records_from_ms`]);
/// - machine registration: a validator whose consensus key does not name its
///   machine (ML-DSA-87 / P-384) registers its machine identity, so peers
///   hold its endpoint records to the machine's ML-DSA key from the first.
pub fn keep_chain_policies(node: Arc<crate::node::TenzroNode>) {
    // Every node registers its own machine identity once the chain has
    // finalized, and keeps trying until it is on chain.
    crate::machine_registration::spawn(node.clone());
    tokio::spawn(async move {
        loop {
            if let Some(chain) = crate::rpc::chain_state_of(&node) {
                tenzro_crypto::session::set_hybrid_records_from_ms(
                    tenzro_vm::native::network_param(
                        &chain,
                        tenzro_vm::governance::HYBRID_RECORDS_FROM_PARAM,
                    ),
                );
                tenzro_crypto::batch::set_pq_leg_required_from_ms(
                    tenzro_vm::native::network_param(
                        &chain,
                        tenzro_vm::governance::PQ_LEG_REQUIRED_FROM_PARAM,
                    ),
                );
                if let Err(e) = maybe_register_machine(&node, &chain).await {
                    tracing::warn!(error = %e, "validator machine not registered this round");
                }
            }
            tokio::time::sleep(CHAIN_POLICY_INTERVAL).await;
        }
    });
}

/// Registers this machine as the validator's machine when governance has
/// enabled it, the validator's consensus key does not name it, and the chain
/// does not name it already.
async fn maybe_register_machine(
    node: &Arc<crate::node::TenzroNode>,
    chain: &tenzro_vm::StateAdapter,
) -> std::result::Result<bool, String> {
    use tenzro_vm::native::validator_machine as vm;
    if !matches!(
        tenzro_vm::native::lever_status(chain, vm::MACHINE_IDENTITY_STATUS),
        tenzro_vm::governance::LeverStatus::Enabled
    ) {
        return Ok(false);
    }
    let Some(key) = node.validator_signer() else {
        return Ok(false);
    };
    if key.public_key().scheme() == tenzro_types::signature_scheme::SignatureScheme::MlDsa65P256 {
        return Ok(false);
    }
    let Some(submitter) = node.ledger_submitter() else {
        return Ok(false);
    };
    let account = submitter.address();
    let Some(machine) = machine_signer() else {
        return Ok(false);
    };
    let p256 = machine
        .public_key_sec1()
        .map_err(|e| e.to_string())?
        .to_vec();
    let registered = vm::machine_of(chain, account.as_bytes());
    if registered.as_ref().is_some_and(|m| m.p256 == p256) {
        return Ok(false);
    }
    let validator = account.as_bytes().to_vec();
    let registration =
        tokio::task::spawn_blocking(move || machine_registration(machine, &validator, p256))
            .await
            .map_err(|e| e.to_string())??;
    let tx = tenzro_types::TransactionType::RegisterValidatorMachine {
        machine_p256: registration.machine.p256,
        machine_ml_dsa: registration.machine.ml_dsa,
        p256_signature: registration.p256_signature,
        ml_dsa_signature: registration.ml_dsa_signature,
    };
    crate::rpc::submit_as_validator(node, tx, vm::GAS_VALIDATOR_MACHINE)
        .await
        .map_err(|e| e.message)?;
    tracing::info!(%account, "registered this machine as the validator's machine identity");
    Ok(true)
}

/// Both machine keys' signatures naming `validator`: the hardware P-256 key
/// and the ML-DSA-65 key the derivation root derives under the machine
/// label. A classical root has no post-quantum key to register.
fn machine_registration(
    machine: &dyn HardwareSigner,
    validator: &[u8],
    p256: Vec<u8>,
) -> std::result::Result<tenzro_vm::native::validator_machine::MachineRegistration, String> {
    use sha2::Digest;
    use tenzro_vm::native::validator_machine as vm;
    let root = tenzro_device_key::DerivationRoot::open_or_create().map_err(|e| e.to_string())?;
    let ml_dsa = root
        .ml_dsa65_public(MACHINE_KEY_LABEL)
        .map_err(|e| e.to_string())?;
    let message = vm::proof_message(validator, &p256, &ml_dsa);
    let digest: [u8; 32] = sha2::Sha256::digest(&message).into();
    let p256_signature = machine.sign_prehash(&digest).map_err(|e| e.to_string())?;
    let ml_dsa_signature = root
        .ml_dsa65_sign(MACHINE_KEY_LABEL, vm::MACHINE_PROOF_CONTEXT, &message)
        .map_err(|e| e.to_string())?;
    Ok(vm::MachineRegistration {
        machine: vm::ValidatorMachine { p256, ml_dsa },
        p256_signature: p256_signature.to_vec(),
        ml_dsa_signature,
    })
}

/// The machine's ML-DSA-65 key that its derivation root derives under the
/// machine key label: the ML-DSA leg of its consensus key when it validates.
struct DerivedMachinePq {
    root: tenzro_device_key::DerivationRoot,
}

impl tenzro_iroh::MachinePqKey for DerivedMachinePq {
    fn public_key(&self) -> tenzro_iroh::IrohResult<Vec<u8>> {
        self.root
            .ml_dsa65_public(MACHINE_KEY_LABEL)
            .map(|k| tenzro_types::signature_scheme::SignatureScheme::MlDsa65P256.tag(&k))
            .map_err(|e| tenzro_iroh::IrohError::Backend(format!("machine ML-DSA-65 key: {e}")))
    }

    fn sign_binding(&self, message: &[u8]) -> tenzro_iroh::IrohResult<Vec<u8>> {
        self.root
            .ml_dsa65_sign(
                MACHINE_KEY_LABEL,
                tenzro_iroh::pq_endpoint::PQ_BINDING_CONTEXT,
                message,
            )
            .map_err(|e| tenzro_iroh::IrohError::Backend(format!("machine ML-DSA-65 key: {e}")))
    }

    fn sign_channel(&self, message: &[u8]) -> tenzro_iroh::IrohResult<Vec<u8>> {
        self.root
            .ml_dsa65_sign(
                MACHINE_KEY_LABEL,
                tenzro_iroh::pq_endpoint::PQ_CHANNEL_CONTEXT,
                message,
            )
            .map_err(|e| tenzro_iroh::IrohError::Backend(format!("machine ML-DSA-65 key: {e}")))
    }
}

/// The machine's hardware P-256 identity key as the channel signer: each
/// connection's proof is a TPM or Secure Enclave signature, so no key that
/// can sign is held in this process.
struct MachineChannelSigner;

impl tenzro_device_key::signer::HardwareSigner for MachineChannelSigner {
    fn backend(&self) -> tenzro_device_key::signer::HardwareBackend {
        machine_signer().map_or(tenzro_device_key::signer::HardwareBackend::Tpm, |s| {
            s.backend()
        })
    }
    fn label(&self) -> &str {
        machine_signer().map_or("", |s| s.label())
    }
    fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
        machine_signer()
            .ok_or_else(|| tenzro_device_key::DeviceKeyError::NotFound("machine key".into()))?
            .public_key_sec1()
    }
    fn sign_prehash(
        &self,
        digest: &[u8; 32],
    ) -> tenzro_device_key::Result<tenzro_device_key::DeviceSignature> {
        machine_signer()
            .ok_or_else(|| tenzro_device_key::DeviceKeyError::NotFound("machine key".into()))?
            .sign_prehash(digest)
    }
}

/// Binds this node's endpoint records with the machine's ML-DSA-65 key.
fn bind_records(transport: &IdentityTransport) {
    match tenzro_device_key::DerivationRoot::open_or_create() {
        Ok(root) => {
            transport.enable_pq_binding(
                Arc::new(DerivedMachinePq { root }),
                Arc::new(MachineChannelSigner),
            );
            tracing::info!("endpoint records carry the machine's ML-DSA-65 binding");
        }
        Err(e) => tracing::warn!(
            error = %e,
            "no derivation root; endpoint records carry no ML-DSA binding"
        ),
    }
}

/// Keeps this machine's endpoint record for `endpoint` published and the
/// boot identities resolved, for as long as the endpoint runs.
///
/// A private node (see [`is_private`]) shares its record only with its
/// counterparties: its boot identities and `[iroh] counterparties`.
pub fn announce(
    transport: &Arc<IdentityTransport>,
    endpoint: tenzro_iroh::Endpoint,
    config: &NodeConfig,
    visibility: &Visibility,
) {
    if is_private(visibility) {
        let counterparties = counterparties(config);
        tracing::info!(
            count = counterparties.len(),
            "private node: endpoint record shared with counterparties only"
        );
        transport.share_with_counterparties(counterparties);
    }
    tokio::spawn(transport.clone().run(endpoint, machine_signer()));
    remember(transport, config.data_dir.clone());
}

/// How often the resolved boot identities are checked for gossip neighbours
/// not added yet.
const GOSSIP_SEED_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Makes every boot identity this node has resolved a gossip neighbour, as
/// soon as its signed record resolves and whenever it moves to a new
/// endpoint: the genesis validators (and the operator's boot entries) are a
/// fresh network's first gossip links, from which the rest of the mesh and
/// every announcement travel. Runs until `endpoint` closes.
pub fn seed_gossip(
    transport: &Arc<IdentityTransport>,
    network: Arc<tenzro_network::TenzroNetworkService>,
    endpoint: tenzro_iroh::Endpoint,
) {
    let transport = transport.clone();
    tokio::spawn(async move {
        // Each neighbour with the way to reach it last joined: a peer whose
        // record changes (a new endpoint, or relays it names now) is joined
        // again, so a first dial made before it was reachable is not final.
        let mut seeded: std::collections::HashMap<
            tenzro_iroh::EndpointId,
            tenzro_iroh::EndpointAddr,
        > = std::collections::HashMap::new();
        loop {
            let changed: Vec<tenzro_iroh::EndpointAddr> = transport
                .peer_addrs()
                .into_iter()
                .map(|(_, addr)| addr)
                .filter(|addr| addr.id != endpoint.id() && seeded.get(&addr.id) != Some(addr))
                .collect();
            let fresh: Vec<tenzro_iroh::EndpointId> = changed.iter().map(|a| a.id).collect();
            seeded.extend(changed.into_iter().map(|a| (a.id, a)));
            if !fresh.is_empty() {
                tracing::info!(
                    count = fresh.len(),
                    "boot identities resolved; joining them as gossip neighbours"
                );
                network.add_gossip_peers(&fresh).await;
            }
            tokio::select! {
                _ = endpoint.closed() => return,
                _ = tokio::time::sleep(GOSSIP_SEED_INTERVAL) => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GenesisValidator;

    /// Each ML-DSA-65 / P-256 validator's records are held to the ML-DSA-65
    /// key it registered, under the machine identity its P-256 leg derives;
    /// a validator of another scheme names no machine identity and is not
    /// pinned.
    #[tokio::test]
    async fn validators_are_pinned_to_their_registered_ml_dsa_keys() {
        use tenzro_consensus::validator_key::test_signer::SoftwareTestSigner;
        use tenzro_consensus::{ValidatorInfo, ValidatorSigner};
        use tenzro_types::signature_scheme::SignatureScheme;
        let transport = IdentityTransport::start(vec![], &[], None, None)
            .await
            .unwrap();
        let a = SoftwareTestSigner::from_seed(1).public_key().clone();
        let b = SoftwareTestSigner::from_seed_with_scheme(2, SignatureScheme::MlDsa87P384)
            .public_key()
            .clone();
        let validators = vec![
            ValidatorInfo::new(
                tenzro_types::primitives::Address::new([1; 32]),
                a.clone(),
                [1; 32],
                1,
            ),
            ValidatorInfo::new(
                tenzro_types::primitives::Address::new([2; 32]),
                b.clone(),
                [2; 32],
                1,
            ),
        ];
        assert_eq!(pin_validator_pq_keys(&transport, &validators, |_| None), 1);
        assert_eq!(
            transport.store().pinned_pq_key(&did_of_key(&a.p256)),
            Some(a.ml_dsa.clone())
        );
        assert_eq!(transport.store().pinned_pq_key(&did_of_key(&b.p256)), None);
    }

    /// An ML-DSA-87 / P-384 validator that registered its machine identity
    /// on chain is held to that machine's ML-DSA key under the machine's own
    /// DID, from its first record, instead of the first key it presents.
    #[tokio::test]
    async fn an_ml_dsa_87_validator_is_pinned_to_its_registered_machine() {
        use tenzro_consensus::validator_key::test_signer::SoftwareTestSigner;
        use tenzro_consensus::{ValidatorInfo, ValidatorSigner};
        use tenzro_types::signature_scheme::SignatureScheme;
        let transport = IdentityTransport::start(vec![], &[], None, None)
            .await
            .unwrap();
        let b = SoftwareTestSigner::from_seed_with_scheme(3, SignatureScheme::MlDsa87P384)
            .public_key()
            .clone();
        let address = tenzro_types::primitives::Address::new([3; 32]);
        let validators = vec![ValidatorInfo::new(address, b, [3; 32], 1)];
        let machine_did = "did:tenzro:machine:registered".to_string();
        let machine_key = vec![7u8; 1953];
        let registered = |a: &tenzro_types::primitives::Address| {
            (*a == address).then(|| (machine_did.clone(), machine_key.clone()))
        };
        assert_eq!(
            pin_validator_pq_keys(&transport, &validators, registered),
            1
        );
        assert_eq!(
            transport.store().pinned_pq_key(&machine_did),
            Some(machine_key.clone())
        );
    }

    /// The pins of identities met before are read back at start and saved
    /// when they change.
    #[tokio::test]
    async fn the_node_keeps_its_ml_dsa_pins_across_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let path = pq_pins_path(tmp.path());
        let did = "did:tenzro:machine:met-before";
        tenzro_iroh::pq_endpoint::save_pins(
            &path,
            &[tenzro_iroh::pq_endpoint::SavedPin {
                did: did.to_string(),
                key: vec![9; 1953],
                required: true,
            }],
        )
        .unwrap();
        let transport = IdentityTransport::start(vec![], &[], None, None)
            .await
            .unwrap();
        keep_pq_pins(&transport, tmp.path().to_path_buf());
        assert_eq!(transport.store().pinned_pq_key(did), Some(vec![9; 1953]));
        transport.pin_pq_key("did:tenzro:machine:new", vec![1; 1953]);
        let saved = transport.store().save_pq_pins(&path, 0).unwrap();
        assert!(saved > 0);
        let back = tenzro_iroh::pq_endpoint::load_pins(&path).unwrap();
        assert_eq!(back.len(), 2);
    }

    /// A machine with no TPM 2.0 or Secure Enclave is refused, naming what
    /// is missing; no key is tried.
    #[test]
    fn a_machine_without_a_tpm_is_refused() {
        let err = hardware_identity_verdict(false, || panic!("no key store to open")).unwrap_err();
        assert_eq!(err, NO_HARDWARE_IDENTITY);
        assert!(err.contains("no TPM 2.0"), "{err}");
        assert!(err.contains("no keyless"), "{err}");
    }

    /// A TPM whose identity key does not open is refused with the reason.
    #[test]
    fn a_tpm_whose_identity_key_does_not_open_is_refused() {
        let err = hardware_identity_verdict(true, || Err("TPM_RC_HANDLE".into())).unwrap_err();
        assert!(err.contains("TPM_RC_HANDLE"), "{err}");
        assert!(err.contains("does not start"), "{err}");
    }

    /// A TPM (a private test network's software TPM included) whose
    /// identity key opens starts.
    #[test]
    fn a_tpm_whose_identity_key_opens_starts() {
        assert_eq!(hardware_identity_verdict(true, || Ok(())), Ok(()));
    }

    /// The node checks for a hardware identity before it starts, and the
    /// path that let a machine without one run with only a warning stays
    /// gone.
    #[test]
    fn no_fallback_runs_a_node_without_a_hardware_identity() {
        let main = include_str!("main.rs");
        let this = include_str!("identity_bootstrap.rs");
        for check in ["require_hardware_key_store", "require_hardware_identity"] {
            assert!(
                main.contains(&format!("identity_bootstrap::{check}")),
                "node start no longer refuses a machine without a TPM ({check})"
            );
        }
        for removed in [
            ["publishes no endpoint", " record and"].concat(),
            ["it can reach identities but has", " none of its"].concat(),
        ] {
            assert!(
                !this.contains(&removed),
                "the no-TPM fallback is back: {removed}"
            );
            assert!(
                !main.contains(&removed),
                "the no-TPM fallback is back: {removed}"
            );
        }
    }

    /// The machine identity is the key the TPM holds at its persistent
    /// identity handle.
    #[test]
    fn the_machine_key_is_the_persistent_tpm_identity() {
        assert_eq!(MACHINE_KEY_LABEL, tenzro_device_key::IDENTITY_KEY_LABEL);
    }

    fn validator(p256: [u8; 65], relay: Option<&str>) -> GenesisValidator {
        GenesisValidator {
            address: String::new(),
            ml_dsa_public_key: String::new(),
            p256_public_key: hex::encode(p256),
            node_key: String::new(),
            proof_of_possession: String::new(),
            node_key_proof: String::new(),
            vrf_key: String::new(),
            vrf_key_proof: String::new(),
            stake: 1,
            relay: relay.map(str::to_string),
        }
    }

    #[test]
    fn remembered_relay_operators_join_the_boot_list_after_the_configured_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            genesis: None,
            ..Default::default()
        };
        assert!(remembered(tmp.path()).is_empty());
        let did = |b: u8| format!("did:tenzro:machine:{}", hex::encode([b; 32]));
        std::fs::create_dir_all(tmp.path().join("iroh")).unwrap();
        std::fs::write(
            remembered_path(tmp.path()),
            serde_json::to_vec(&vec![
                format!("{}@https://relay.operator.example/", did(1)),
                "not an identity".into(),
            ])
            .unwrap(),
        )
        .unwrap();
        let entries = boot_entries(&config).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].did, did(1));
    }

    #[test]
    fn a_node_is_private_only_when_it_announces_nothing() {
        assert!(!is_private(&Visibility::Public));
        assert!(!is_private(&Visibility::Gated));
        assert!(is_private(&Visibility::Private));
    }

    #[test]
    fn genesis_validators_are_booted_by_machine_identity() {
        let mut key = [7u8; 65];
        key[0] = 0x04;
        let mut genesis = GenesisConfig::default_testnet();
        genesis.validators = vec![
            validator(key, Some("https://relay.example.org")),
            validator([4u8; 65], None),
        ];
        let boot = genesis_boot(&genesis).unwrap();
        assert_eq!(boot[0].did, did_of_key(&key));
        assert_eq!(
            boot[0].relay.as_ref().unwrap().as_str(),
            "https://relay.example.org/"
        );
        assert_eq!(boot[1].relay, None);

        genesis.validators = vec![validator(key, Some("/ip4/192.0.2.10/tcp/9000"))];
        assert!(
            genesis_boot(&genesis).is_err(),
            "a genesis relay must be a URL, not a transport path"
        );
    }
    #[tokio::test]
    async fn boot_relays_are_asked_for_again_until_one_answers() {
        // The relay is down for the first two asks (each of which the real
        // transport spends a minute on), then up.
        let asks = std::cell::Cell::new(0u32);
        let got = admit_boot_relays(
            true,
            RELAY_ADMISSION_ROUNDS,
            || {
                asks.set(asks.get() + 1);
                let relays = if asks.get() >= 3 { 1 } else { 0 };
                async move { Ok::<_, NodeError>(relays) }
            },
            |relays| *relays > 0,
        )
        .await
        .unwrap();
        assert_eq!((got, asks.get()), (1, 3));
    }

    #[tokio::test]
    async fn a_relay_that_never_answers_still_lets_the_node_start_after_the_rounds() {
        let asks = std::cell::Cell::new(0u32);
        let got = admit_boot_relays(
            true,
            RELAY_ADMISSION_ROUNDS,
            || {
                asks.set(asks.get() + 1);
                async { Ok::<_, NodeError>(0) }
            },
            |relays| *relays > 0,
        )
        .await
        .unwrap();
        assert_eq!((got, asks.get()), (0, RELAY_ADMISSION_ROUNDS));
    }

    #[tokio::test]
    async fn a_node_that_names_no_relay_starts_once() {
        let asks = std::cell::Cell::new(0u32);
        admit_boot_relays(
            false,
            RELAY_ADMISSION_ROUNDS,
            || {
                asks.set(asks.get() + 1);
                async { Ok::<_, NodeError>(0) }
            },
            |relays| *relays > 0,
        )
        .await
        .unwrap();
        assert_eq!(asks.get(), 1);
    }
}
