//! A network of validators in one process, each with its own storage, iroh
//! endpoint, machine identity, validator key, consensus and event loop. They
//! find each other through a relay a separate machine serves, publish their
//! endpoint announcements and certificates to one another as gossip would,
//! and catch up over block sync, as nodes do.
//!
//! The keys are software test keys handed to each node: the machine key the
//! node's endpoint record is signed with, and the validator key its
//! consensus signs with. Nothing here reaches a TPM.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tempfile::TempDir;
use tokio::sync::mpsc;

use tenzro_consensus::session::SessionKey;
use tenzro_consensus::validator::ValidatorInfo;
use tenzro_consensus::{
    Certificate, ConsensusConfig, EpochManager, EpochStart, PublishedCertificate, TimeRules,
    ValidatorSigner,
};
use tenzro_device_key::HardwareSigner;
use tenzro_iroh::{BootIdentity, IdentityTransport, IrohBackedResolver, RelayRoleConfig};
use tenzro_storage::traits::BlockStore;
use tenzro_storage::{BlockStoreImpl, KvStore, RocksDbStore};
use tenzro_types::primitives::{Address, BlockHeight, Hash};
use tenzro_vm::{MultiVmRuntime, VmConfig};

use tenzro_node::consensus_driver::{ConsensusHandle, Launcher};
use tenzro_node::event_loop::{EventLoop, NodeEvent};
use tenzro_node::metrics::MetricsCollector;

const CHAIN_ID: u64 = 1337;

/// A software stand-in for a machine's TPM key.
struct TestSigner(p256::ecdsa::SigningKey);

impl HardwareSigner for TestSigner {
    fn backend(&self) -> tenzro_device_key::HardwareBackend {
        tenzro_device_key::HardwareBackend::Tpm
    }
    fn label(&self) -> &str {
        "test"
    }
    fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
        let mut out = [0u8; 65];
        out.copy_from_slice(self.0.verifying_key().to_sec1_point(false).as_bytes());
        Ok(out)
    }
    fn sign_prehash(
        &self,
        digest: &[u8; 32],
    ) -> tenzro_device_key::Result<tenzro_device_key::DeviceSignature> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
        Ok(sig.to_bytes().into())
    }
}

/// The limit a validator's refusal of a transaction names, when it is
/// backpressure: an admission rate, a capacity limit or a sender running too
/// far ahead of execution. A load test may meet these; it must meet no
/// other refusal.
fn backpressure(why: &str) -> Option<&'static str> {
    [
        "Rate limit exceeded for lane",
        "pending transactions (cap",
        "Nonce gap too large",
        "Mempool full",
        "Mempool size limit exceeded",
    ]
    .into_iter()
    .find(|limit| why.contains(limit))
}

fn test_signer(seed: u8) -> TestSigner {
    TestSigner(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
}

/// The governed parameters the launch genesis sets apart from the
/// production genesis.
fn launch_switches() -> std::collections::BTreeMap<String, u64> {
    let prod: tenzro_node::config::GenesisConfig =
        toml::from_str(include_str!("../../../config/genesis-prod.toml")).unwrap();
    let launch: tenzro_node::config::GenesisConfig =
        toml::from_str(include_str!("../../../config/genesis-launch.toml")).unwrap();
    launch
        .network_params
        .into_iter()
        .filter(|(k, v)| prod.network_params.get(k) != Some(v))
        .collect()
}

/// The in-process networks run one at a time: two at once on a loaded host
/// starve each other's timers.
static ONE_NETWORK_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Threads of the compact-certificate pool the test networks' validators
/// share.
const NET_COMPACT_THREADS: usize = 4;

/// Waits until the test networks' compact pool has no job left by an
/// earlier network. A proof runs on a blocking thread that the runtime's
/// teardown leaves behind, and running on into the next network it would
/// take that network's cores and its turn at the pool.
fn await_compact_pool_idle() {
    let pool = tenzro_node::consensus_driver::shared_compact_work(NET_COMPACT_THREADS);
    let deadline = Instant::now() + Duration::from_secs(600);
    while Instant::now() < deadline {
        if pool.try_run(|| ()).is_some() {
            // A proof queued behind the one that ended takes the pool at
            // once; idle twice over half a second means none is queued.
            std::thread::sleep(Duration::from_millis(500));
            if pool.try_run(|| ()).is_some() {
                return;
            }
        } else {
            pool.run(|| ());
        }
    }
}

/// Runs a network test on a runtime of its own, one network at a time.
/// However the test ends, its teardown ends: what still runs on the
/// runtime's blocking threads is given a few seconds and then left behind,
/// where dropping the runtime would wait on it for good, and a failure is
/// then reported as the failure it is.
fn network_test(test: impl std::future::Future<Output = ()>) {
    let _one_at_a_time = ONE_NETWORK_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    await_compact_pool_idle();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("test runtime");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(test)));
    runtime.shutdown_timeout(Duration::from_secs(10));
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// Ten-second epochs, as the local test genesis has.
fn time_rules() -> TimeRules {
    TimeRules {
        checkpoint_interval_ms: 500,
        epoch_checkpoints: 20,
        handover_confirmations: 2,
        idle_round_interval_ms: 1_000,
        ..TimeRules::default()
    }
}

/// What a validator keeps across a restart: its keys and its storage.
struct Machine {
    validator: Arc<SessionKey>,
    machine: &'static dyn HardwareSigner,
    did: String,
    storage: Arc<RocksDbStore>,
    dir: TempDir,
    /// The key of the validator's ledger account, when it records the
    /// signers of the checkpoints it is designated for, as a node does.
    account: Option<Arc<tenzro_crypto::composite::testing::TestHybridSigner>>,
}

/// How the validators' ledger accounts take part.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Accounts {
    /// No validator sends anything.
    Silent,
    /// Each records checkpoint signers from an account that holds nothing
    /// and has no bond.
    RecordUnbonded,
    /// Each records checkpoint signers from an account bonded at genesis
    /// that holds nothing to spend.
    RecordBonded,
}

/// A validator's signer with a stall switch: while the switch holds a future
/// instant the signer answers like a TPM that stopped answering, with the
/// executor's own error after the wait, and signs normally again once the
/// instant passes.
struct StallingSigner {
    inner: Arc<SessionKey>,
    until: Arc<Mutex<Option<Instant>>>,
}

impl ValidatorSigner for StallingSigner {
    fn public_key(&self) -> &tenzro_consensus::ValidatorPublicKey {
        ValidatorSigner::public_key(self.inner.as_ref())
    }

    fn sign(
        &self,
        domain: &[u8],
        message: &[u8],
    ) -> tenzro_consensus::error::Result<tenzro_consensus::CompositeSignature> {
        let stalled = self.until.lock().is_some_and(|at| Instant::now() < at);
        if stalled {
            std::thread::sleep(Duration::from_millis(500));
            return Err(tenzro_consensus::error::ConsensusError::Crypto(
                "sign: the TPM did not answer within 0.5s".into(),
            ));
        }
        self.inner.sign(domain, message)
    }
}

/// A running validator.
struct Running {
    consensus: Arc<ConsensusHandle>,
    resolver: Arc<IrohBackedResolver>,
    transport: Arc<IdentityTransport>,
    events: mpsc::Sender<NodeEvent>,
    tip: Arc<AtomicU64>,
}

/// What the network carries between running validators: their endpoint
/// announcements and the certificates they form.
#[derive(Default)]
struct Gossip {
    nodes: HashMap<usize, (Arc<ConsensusHandle>, mpsc::Sender<NodeEvent>)>,
    /// Validators that hear no announcement until the instant given: a
    /// restarted validator whose gossip mesh has not formed yet.
    deaf: HashMap<usize, Instant>,
    /// The latest announcement each validator published.
    published: HashMap<usize, tenzro_consensus::announce::PublishedAnnouncement>,
    /// Publications that asked for sealed endpoints.
    requests: usize,
}

struct Net {
    machines: Vec<Machine>,
    running: Vec<Option<Running>>,
    validators: Vec<ValidatorInfo>,
    gossip: Arc<Mutex<Gossip>>,
    /// Signers of every certificate any validator formed, by epoch, as
    /// committee positions.
    signed: Arc<Mutex<Vec<(u64, u64, Vec<u16>)>>>,
    /// Checkpoint-signers records a validator submitted, and why any it
    /// tried was not admitted.
    stats: Arc<tenzro_node::checkpoint_recorder::RecorderStats>,
    /// How long each recorder rank behind the first waits.
    fallback: Duration,
    boot: Vec<BootIdentity>,
    genesis: tenzro_node::config::GenesisConfig,
    /// How many of the machines are in the genesis validator set; the rest
    /// are spares that follow until a recovery manifest seats them.
    founding: usize,
    /// Recovery manifests to apply when machine `i` starts.
    recovery: HashMap<usize, tenzro_node::recovery::RecoveryRequest>,
    /// Validators a starting machine syncs from, as `--state-sync-from`
    /// names them to a node.
    sync_from: Vec<usize>,
    /// The relays, in the order the boot list names them: each with the
    /// task that runs its record loop and serves its listener.
    relays: Vec<Option<(iroh::protocol::Router, TempDir, tokio::task::JoinHandle<()>)>>,
    /// Validators take no direct path: every packet goes through a relay,
    /// as for a validator behind a NAT that lets nothing in.
    relay_only: bool,
    /// Each machine's TPM stall switch.
    stalls: Vec<Arc<Mutex<Option<Instant>>>>,
}

impl Net {
    async fn start(n: usize) -> Self {
        Self::start_with(n, Vec::new(), time_rules()).await
    }

    /// A network of `n` validators whose genesis funds `accounts`, running
    /// under `rules`.
    async fn start_with(n: usize, accounts: Vec<Address>, rules: TimeRules) -> Self {
        Self::start_full(n, accounts, rules, Accounts::Silent).await
    }

    /// A network of `n` validators whose genesis funds `accounts`, running
    /// under `rules`, the validators' own accounts taking part as `own`.
    async fn start_full(n: usize, accounts: Vec<Address>, rules: TimeRules, own: Accounts) -> Self {
        Self::start_configured(n, 0, accounts, rules, own, Default::default()).await
    }

    /// [`Net::start_full`] with genesis network parameters `params`.
    async fn start_configured(
        founding: usize,
        spares: usize,
        accounts: Vec<Address>,
        rules: TimeRules,
        own: Accounts,
        params: std::collections::BTreeMap<String, u64>,
    ) -> Self {
        Self::start_recording(
            founding,
            spares,
            accounts,
            rules,
            own,
            params,
            Duration::from_secs(120),
        )
        .await
    }

    /// [`Net::start_configured`] with the recorders' fallback interval.
    async fn start_recording(
        founding: usize,
        spares: usize,
        accounts: Vec<Address>,
        rules: TimeRules,
        own: Accounts,
        params: std::collections::BTreeMap<String, u64>,
        fallback: Duration,
    ) -> Self {
        Self::start_relayed(
            founding, spares, accounts, rules, own, params, fallback, 1, false,
        )
        .await
    }

    /// [`Net::start_recording`] with `relay_count` relays, each on a machine
    /// of its own and all named in the boot list, and with the validators on
    /// relay-only paths when `relay_only`.
    #[allow(clippy::too_many_arguments)]
    async fn start_relayed(
        founding: usize,
        spares: usize,
        accounts: Vec<Address>,
        rules: TimeRules,
        own: Accounts,
        params: std::collections::BTreeMap<String, u64>,
        fallback: Duration,
        relay_count: usize,
        relay_only: bool,
    ) -> Self {
        let n = founding + spares;
        // The relays every machine boots through.
        let mut relays = Vec::new();
        let mut boot: Vec<BootIdentity> = Vec::new();
        for r in 0..relay_count {
            let relay_key: &'static dyn HardwareSigner =
                Box::leak(Box::new(test_signer(200 + r as u8)));
            let relay_did = did_of(relay_key);
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let url = url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
            let role = RelayRoleConfig {
                bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
                public_url: url.clone(),
            };
            let relay_dir = tempfile::tempdir().unwrap();
            let transport =
                IdentityTransport::start(vec![], &[], Some(&role), Some(relay_did.clone()))
                    .await
                    .expect("relay transport");
            let relay = relay_endpoint(&transport).await;
            let task = tokio::spawn(transport.run(relay.endpoint().clone(), Some(relay_key)));
            boot.push(format!("{relay_did}@{url}").parse().unwrap());
            relays.push(Some((relay, relay_dir, task)));
        }

        let mut machines = Vec::new();
        let mut validators = Vec::new();
        let mut genesis_validators = Vec::new();
        for i in 0..n {
            let validator = Arc::new(SessionKey::generate().expect("validator key"));
            let machine: &'static dyn HardwareSigner =
                Box::leak(Box::new(test_signer(i as u8 + 1)));
            let did = did_of(machine);
            let dir = tempfile::tempdir().unwrap();
            let storage = Arc::new(RocksDbStore::open_default(dir.path().join("db")).unwrap());
            let account = (own != Accounts::Silent).then(|| {
                Arc::new(tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
                    0x80 + i as u8,
                ))
            });
            let address = account
                .as_ref()
                .map_or(Address::new([i as u8 + 1; 32]), |a| a.address());
            if own == Accounts::RecordBonded {
                genesis_validators.push(bonded_at_genesis(&validator, address, i as u8));
            }
            validators.push(ValidatorInfo::new(
                address,
                validator.public_key().clone(),
                [i as u8 + 1; 32],
                1 << 80,
            ));
            machines.push(Machine {
                validator,
                machine,
                did,
                storage,
                dir,
                account,
            });
        }
        let genesis = tenzro_node::config::GenesisConfig {
            protocol: None,
            consensus: Default::default(),
            validator_registry: Default::default(),
            version: tenzro_node::config::GENESIS_SCHEMA_VERSION,
            chain_id: CHAIN_ID,
            timestamp: (chrono::Utc::now().timestamp() as u64).max(1),
            validators: genesis_validators,
            // A validator account holds what its one enrolment costs; its
            // records pay no fee.
            accounts: accounts
                .iter()
                .copied()
                .chain(
                    machines
                        .iter()
                        .filter_map(|m| m.account.as_ref().map(|a| a.address())),
                )
                .map(|a| tenzro_node::config::GenesisAccount {
                    address: hex::encode(a.as_bytes()),
                    balance: 1_000_000,
                })
                .collect(),
            weak_subjectivity: None,
            time: rules,
            network_params: params,
            economy: Default::default(),
            role_stakes: Vec::new(),
        };
        let mut net = Net {
            running: (0..n).map(|_| None).collect(),
            machines,
            validators,
            gossip: Arc::new(Mutex::new(Gossip::default())),
            signed: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::default(),
            fallback,
            boot,
            genesis,
            founding,
            recovery: HashMap::new(),
            sync_from: Vec::new(),
            relays,
            relay_only,
            stalls: (0..n).map(|_| Arc::new(Mutex::new(None))).collect(),
        };
        for i in 0..founding {
            net.up(i).await;
        }
        net
    }

    /// Starts validator `i` from what its storage holds: at genesis on a
    /// fresh chain, otherwise as a node restarting does.
    async fn up(&mut self, i: usize) {
        self.try_up(i).await.expect("validator starts");
    }

    /// [`Net::up`], reporting a refusal to start (a recovery manifest the
    /// node does not apply).
    async fn try_up(&mut self, i: usize) -> tenzro_node::error::Result<()> {
        let m = &self.machines[i];
        let genesis_block = tenzro_node::genesis::initialize_genesis(&m.storage, &self.genesis)
            .await
            .expect("genesis");
        let genesis_hash = genesis_block.hash().0;

        let transport = IdentityTransport::start(self.boot.clone(), &[], None, Some(m.did.clone()))
            .await
            .expect("identity transport");
        let iroh_dir = m.dir.path().join(format!("iroh-{}", unique()));
        let resolver = bind(&transport, &iroh_dir, self.relay_only).await;
        tokio::spawn(
            transport
                .clone()
                .run(resolver.endpoint().clone(), Some(m.machine)),
        );

        // `--state-sync-from <id>@<ip:port>`: the node is told where to find
        // the validators it syncs from, as no discovery service runs here.
        for j in self.sync_from.iter().filter(|j| **j != i) {
            if let Some(r) = self.running[*j].as_ref() {
                resolver
                    .remember_addr(r.resolver.endpoint().addr())
                    .expect("the sync source's address is remembered");
            }
        }

        let epoch_store = Arc::new(tenzro_node::epoch_state_store::RocksDbEpochStateStore::new(
            m.storage.clone(),
        ));
        let em = Arc::new(
            EpochManager::with_store(
                self.validators[..self.founding].to_vec(),
                10_000,
                epoch_store,
            )
            .expect("epoch manager"),
        );
        let kv: Arc<dyn KvStore> = m.storage.clone();
        // Validators of one process share one proving pool; it leaves the
        // cores to the validators' own work, as separate machines would.
        let consensus = ConsensusHandle::new(
            ConsensusConfig {
                compact_pool_threads: NET_COMPACT_THREADS,
                ..ConsensusConfig::default()
            },
            self.genesis.time.clone(),
            CHAIN_ID,
            genesis_hash,
            em,
            Some(kv.clone()),
            Some(kv.clone()),
        )
        .expect("consensus handle");
        // The mempool admits and selects by the executed nonce, as a node's.
        consensus
            .set_state_reader(Arc::new(
                tenzro_node::lane_resolver::NodeAccountStateReader::new(kv.clone()),
            ))
            .expect("state reader");

        if let Some(request) = self.recovery.get(&i) {
            tenzro_node::recovery::apply(request, &m.storage, &consensus, None, CHAIN_ID).await?;
        }

        let (segments_tx, segments_rx) = mpsc::channel(1024);
        let (certificates_tx, certificates_rx) = mpsc::unbounded_channel();
        let (formed_tx, mut formed_rx) = mpsc::unbounded_channel::<Certificate>();
        let (compact_tx, mut compact_rx) =
            mpsc::unbounded_channel::<tenzro_light::compact::CompactCertificate>();
        let (evidence_tx, _evidence_rx) = mpsc::unbounded_channel();
        let (announce_tx, mut announce_rx) =
            mpsc::unbounded_channel::<tenzro_consensus::announce::Publication>();

        let vm = Arc::new(MultiVmRuntime::new(VmConfig::default()).await.unwrap());
        let tip = Arc::new(AtomicU64::new(0));
        let event_loop = EventLoop::new(
            m.storage.clone(),
            vm,
            Some(consensus.clone()),
            None,
            tip.clone(),
            Arc::new(MetricsCollector::new()),
        )
        .with_ordered_segments(segments_rx)
        .with_certificates(certificates_rx)
        .with_iroh_resolver(resolver.clone())
        .with_sync_peers(
            self.sync_from
                .iter()
                .filter(|j| **j != i)
                .filter_map(|j| self.running[*j].as_ref())
                .map(|r| *r.resolver.endpoint().id().as_bytes())
                .collect(),
        )
        .with_block_sync(tenzro_node::config::BlockSyncConfig {
            tip_probe_interval_ms: 2_000,
            ..Default::default()
        });
        let events = event_loop.event_sender();

        // Formed certificates go to this node's event loop and, as on the
        // network, to every other running node. A validator with an account
        // records the signers of the ones it is designated for, as a node
        // does.
        {
            let gossip = self.gossip.clone();
            let signed = self.signed.clone();
            let publisher = consensus.clone();
            // The validator's own transactions reach every other running
            // node's pool, as the transactions topic carries them.
            let tx_gossip: tenzro_node::payment_rails::GossipSlot = Arc::default();
            {
                let (sender, mut admitted) = mpsc::channel::<NodeEvent>(1024);
                *tx_gossip.lock() = Some(sender);
                let gossip = self.gossip.clone();
                tokio::spawn(async move {
                    while let Some(event) = admitted.recv().await {
                        let NodeEvent::LocallyAdmittedTransaction(tx) = event else {
                            continue;
                        };
                        let peers: Vec<_> = gossip
                            .lock()
                            .nodes
                            .iter()
                            .filter(|(j, _)| **j != i)
                            .map(|(_, (c, _))| c.clone())
                            .collect();
                        for c in peers {
                            let _ = c.submit_transaction(tx.clone());
                        }
                    }
                });
            }
            let recorder = m
                .account
                .clone()
                .map(|a| a as Arc<dyn tenzro_crypto::composite::HybridSigner>);
            let recorder = recorder.map(|signer| {
                tenzro_node::checkpoint_recorder::CheckpointRecorder::new(
                    publisher.clone(),
                    signer,
                    m.storage.clone(),
                    CHAIN_ID,
                    Arc::default(),
                    tx_gossip,
                    self.fallback,
                    self.stats.clone(),
                )
            });
            tokio::spawn(async move {
                while let Some(cert) = formed_rx.recv().await {
                    signed.lock().push((
                        cert.checkpoint.epoch,
                        cert.checkpoint.index,
                        cert.signers.to_vec(),
                    ));
                    if let Some(recorder) = recorder.as_ref() {
                        recorder.on_certificate(&cert);
                    }
                    let published: PublishedCertificate = publisher.publication(cert.clone());
                    let peers: Vec<_> = gossip
                        .lock()
                        .nodes
                        .iter()
                        .filter(|(j, _)| **j != i)
                        .map(|(_, (_, tx))| tx.clone())
                        .collect();
                    for tx in peers {
                        let _ = tx
                            .send(NodeEvent::NetworkCertificate(Box::new(published.clone())))
                            .await;
                    }
                    if certificates_tx.send(cert).is_err() {
                        return;
                    }
                }
            });
        }
        // Endpoint announcements, to every other running node.
        {
            let gossip = self.gossip.clone();
            tokio::spawn(async move {
                while let Some(a) = announce_rx.recv().await {
                    let peers: Vec<_> = {
                        let mut g = gossip.lock();
                        g.published.insert(i, a.published.clone());
                        g.requests += usize::from(!a.wanted.is_empty());
                        let now = Instant::now();
                        g.nodes
                            .iter()
                            .filter(|(j, _)| **j != i)
                            .filter(|(j, _)| g.deaf.get(*j).is_none_or(|until| now >= *until))
                            .map(|(_, (c, _))| c.clone())
                            .collect()
                    };
                    for c in peers {
                        c.offer_publication(a.clone());
                    }
                }
            });
        }

        // Compact certificates reach every other running validator, as
        // gossip carries them, and each checks them off the runtime, one
        // after another as separate machines would without sharing cores. A
        // member holding a verified one does not prove it again.
        {
            let gossip = self.gossip.clone();
            tokio::spawn(async move {
                while let Some(cc) = compact_rx.recv().await {
                    let peers: Vec<_> = gossip
                        .lock()
                        .nodes
                        .iter()
                        .filter(|(j, _)| **j != i)
                        .map(|(_, (c, _))| c.clone())
                        .collect();
                    let _ = tokio::task::spawn_blocking(move || {
                        for c in peers {
                            if let Err(e) = c.accept_compact_certificate(&cc) {
                                tracing::debug!(error = %e, "compact certificate refused");
                            }
                        }
                    })
                    .await;
                }
            });
        }

        // On the network a node joins gossip before it publishes: the
        // others answer its new endpoint announcement with their endpoints
        // sealed to it, once, and it must be there to receive them.
        self.gossip
            .lock()
            .nodes
            .insert(i, (consensus.clone(), events.clone()));
        consensus.set_launcher(Launcher {
            signer: Arc::new(StallingSigner {
                inner: m.validator.clone(),
                until: self.stalls[i].clone(),
            }) as Arc<dyn ValidatorSigner>,
            high_water: Arc::new(tenzro_consensus::KvVoteHighWater::new(kv)),
            endpoint: resolver.endpoint().clone(),
            identity: Some(transport.clone()),
            machine: Some(m.did.clone()),
            handler: resolver.consensus_handler().clone(),
            segments: segments_tx,
            certificates: formed_tx,
            compact: compact_tx,
            evidence: evidence_tx,
            announcements: announce_tx,
        });
        let local_tip = BlockStoreImpl::new(m.storage.clone())
            .unwrap()
            .latest_height()
            .await
            .unwrap()
            .map_or(0, |h| h.0);
        if !consensus.resume(local_tip).unwrap() {
            if let Some(recovery) =
                tenzro_node::recovery::pending_start(&m.storage, local_tip).unwrap()
            {
                consensus
                    .launch(recovery.epoch, recovery.start)
                    .expect("launch");
            } else if consensus.latest_certificate().is_none() && local_tip == 0 {
                consensus
                    .launch(0, genesis_start(&m.storage, &genesis_block))
                    .expect("launch");
            }
        }
        tokio::spawn(async move {
            if let Err(e) = event_loop.run().await {
                tracing::warn!(error = %e, "event loop ended");
            }
        });
        self.running[i] = Some(Running {
            consensus,
            resolver,
            transport,
            events,
            tip,
        });
        Ok(())
    }

    /// Stops validator `i` as its process ending would: consensus, the
    /// event loop and the endpoint go; storage stays.
    async fn down(&mut self, i: usize) {
        self.gossip.lock().nodes.remove(&i);
        let r = self.running[i].take().expect("running");
        r.consensus.stop();
        let _ = r.events.send(NodeEvent::Shutdown).await;
        let _ = r.resolver.shutdown().await;
    }

    fn node(&self, i: usize) -> &Running {
        self.running[i].as_ref().expect("running")
    }

    fn height(&self, i: usize) -> u64 {
        self.node(i).tip.load(Ordering::Acquire)
    }

    /// The latest certified checkpoint `i` holds: (epoch, index).
    fn certified(&self, i: usize) -> (u64, u64) {
        self.node(i)
            .consensus
            .latest_certificate()
            .map_or((0, 0), |c| (c.checkpoint.epoch, c.checkpoint.index))
    }

    /// The committee position of validator `i` in `epoch`.
    fn position(&self, i: usize, epoch: u64) -> Option<u16> {
        let c = self
            .running
            .iter()
            .flatten()
            .next()?
            .consensus
            .committee(epoch)?;
        c.members()
            .iter()
            .position(|m| &m.public_key == self.machines[i].validator.public_key())
            .map(|p| p as u16)
    }

    /// Waits until `done`. `limit` is how long the network may go without any
    /// validator's tip or certified checkpoint moving, not how long the wait
    /// may take: a host running other work slows the validators down without
    /// stopping them, and a network that has stopped still fails after `limit`.
    /// A wait never runs past ten times `limit`.
    async fn wait_for(&self, what: &str, limit: Duration, mut done: impl FnMut(&Self) -> bool) {
        let start = Instant::now();
        let mut seen = self.progress();
        let mut moved = Instant::now();
        while !done(self) {
            let now = self.progress();
            if now != seen {
                seen = now;
                moved = Instant::now();
            }
            assert!(
                moved.elapsed() < limit && start.elapsed() < limit * 10,
                "{what}: no progress for {:?} (waited {:?}); heights {:?}, certified {:?}",
                moved.elapsed(),
                start.elapsed(),
                self.heights(),
                (0..self.running.len())
                    .filter(|i| self.running[*i].is_some())
                    .map(|i| self.certified(i))
                    .collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Every running validator's tip and certified checkpoint.
    fn progress(&self) -> Vec<(Option<u64>, (u64, u64))> {
        self.heights()
            .into_iter()
            .enumerate()
            .map(|(i, tip)| {
                (
                    tip,
                    if self.running[i].is_some() {
                        self.certified(i)
                    } else {
                        (0, 0)
                    },
                )
            })
            .collect()
    }

    fn heights(&self) -> Vec<Option<u64>> {
        (0..self.running.len())
            .map(|i| {
                self.running[i]
                    .as_ref()
                    .map(|r| r.tip.load(Ordering::Acquire))
            })
            .collect()
    }
}

/// The genesis entry that bonds validator `i`'s ledger account `address`,
/// with the proofs of possession a genesis validator carries, from software
/// keys.
fn bonded_at_genesis(
    validator: &SessionKey,
    address: Address,
    i: u8,
) -> tenzro_node::config::GenesisValidator {
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer as _};
    let key = ValidatorSigner::public_key(validator).clone();
    let node = Ed25519SignerImpl::generate().expect("node key");
    let node_key: [u8; 32] = node
        .public_key()
        .as_bytes()
        .try_into()
        .expect("Ed25519 key");
    let proof = tenzro_consensus::validator_key::prove_registration(
        validator,
        address.as_bytes(),
        &node_key,
    )
    .expect("registration proof");
    let node_key_proof = node
        .sign(
            &tenzro_consensus::validator_key::node_key_registration_message(
                address.as_bytes(),
                &key,
                &node_key,
            ),
        )
        .expect("node key proof");
    let vrf = tenzro_crypto::vrf::VrfSecretKey([0x60 + i; 32]);
    let vrf_key = tenzro_crypto::vrf::VrfProver::public_key(&vrf).0;
    let vrf_key_proof = tenzro_crypto::vrf::VrfProver::prove(
        &vrf,
        &tenzro_consensus::validator_key::vrf_key_registration_alpha(
            address.as_bytes(),
            &key,
            &node_key,
            &vrf_key,
        ),
    )
    .expect("VRF key proof");
    tenzro_node::config::GenesisValidator {
        address: hex::encode(address.as_bytes()),
        ml_dsa_public_key: hex::encode(&key.ml_dsa),
        p256_public_key: hex::encode(&key.p256),
        node_key: hex::encode(node_key),
        proof_of_possession: hex::encode(proof),
        node_key_proof: hex::encode(node_key_proof.as_bytes()),
        vrf_key: hex::encode(vrf_key),
        vrf_key_proof: hex::encode(vrf_key_proof.as_bytes()),
        stake: 1_000_000,
        relay: None,
    }
}

/// The relay machine's endpoint, serving its discovery store. A node with
/// the relay role binds UDP 443, which a test cannot; this one keeps an
/// ephemeral port and serves what peers sync records through.
async fn relay_endpoint(transport: &Arc<IdentityTransport>) -> iroh::protocol::Router {
    use tenzro_iroh::identity_transport::{base_builder, on_loopback, with_relays};
    let endpoint = transport
        .paths()
        .install(with_relays(
            on_loopback(base_builder()),
            transport.relays(),
            Some(transport.store().clone()),
        ))
        .bind()
        .await
        .expect("relay endpoint");
    transport.paths().attach(
        &endpoint,
        &tenzro_iroh::connection_limits::ConnectionLimits::default(),
    );
    tokio::time::timeout(Duration::from_secs(20), endpoint.online())
        .await
        .expect("the relay machine reaches its own relay");
    let mut router = iroh::protocol::Router::builder(endpoint).accept(
        tenzro_iroh::ALPN_DISCOVERY,
        tenzro_iroh::discovery::DiscoveryProtocol::new(transport.store().clone()),
    );
    if let Some(service) = transport.peer_relay_service() {
        router = router.accept(tenzro_iroh::paths::ALPN_PEER_RELAY, service);
    }
    router
        .accept(
            tenzro_iroh::paths::ALPN_PUNCH,
            tenzro_iroh::paths::PunchService::new(transport.paths().clone()),
        )
        .spawn()
}

/// An endpoint on a loopback port the operating system picks as it binds.
async fn bind_loopback(
    dir: &std::path::Path,
    identity: Option<&IdentityTransport>,
    port_mapping: bool,
    relay_only: bool,
) -> Arc<IrohBackedResolver> {
    let mut cfg = tenzro_iroh::TenzroIrohConfig::loopback();
    cfg.data_dir = dir.to_path_buf();
    cfg.relay_only = relay_only;
    if !port_mapping {
        cfg.port_mapping = false;
    }
    IrohBackedResolver::bind_with_config(&cfg, identity)
        .await
        .expect("a loopback endpoint")
}

async fn bind(
    transport: &Arc<IdentityTransport>,
    dir: &std::path::Path,
    relay_only: bool,
) -> Arc<IrohBackedResolver> {
    let resolver = bind_loopback(dir, Some(transport.as_ref()), true, relay_only).await;
    if !transport.relays().is_empty() {
        tokio::time::timeout(Duration::from_secs(20), resolver.endpoint().online())
            .await
            .expect("reaches the relay");
    }
    resolver
}

impl Net {
    /// Makes validator `i`'s TPM stop answering for `how_long` from now.
    fn stall_tpm(&self, i: usize, how_long: Duration) {
        *self.stalls[i].lock() = Some(Instant::now() + how_long);
    }

    /// Stops relay `r` as its machine going away would: its listener, its
    /// endpoint and its record loop.
    async fn stop_relay(&mut self, r: usize) {
        let (router, _dir, task) = self.relays[r].take().expect("relay running");
        task.abort();
        let _ = router.shutdown().await;
    }

    /// How many of the other running validators validator `i` reaches now,
    /// by a connection to the endpoint its store holds a record for.
    async fn peers_reached(&self, i: usize) -> usize {
        let me = self.node(i);
        let endpoint = me.resolver.endpoint().clone();
        let mut reached = 0;
        for (j, other) in self.running.iter().enumerate() {
            if j == i || other.is_none() {
                continue;
            }
            let Some(record) = me.transport.store().lookup(&self.machines[j].did) else {
                continue;
            };
            let Ok(addr) = tenzro_iroh::identity_transport::endpoint_addr(&record) else {
                continue;
            };
            let ask = tenzro_iroh::discovery::ask(
                &endpoint,
                addr,
                &tenzro_iroh::discovery::DiscoveryRequest::Snapshot,
            );
            if matches!(
                tokio::time::timeout(Duration::from_secs(5), ask).await,
                Ok(Ok(_))
            ) {
                reached += 1;
            }
        }
        reached
    }
}

fn did_of(key: &dyn HardwareSigner) -> String {
    tenzro_types::did_derivation::machine_did(&key.public_key_sec1().expect("public key"))
}

fn unique() -> u64 {
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// Where the genesis epoch starts, as a node computes it.
fn genesis_start(storage: &Arc<RocksDbStore>, genesis: &tenzro_types::block::Block) -> EpochStart {
    let trie = tenzro_storage::StateTrie::new(storage.clone() as Arc<dyn KvStore>);
    let root = trie.root_at(0).unwrap().expect("genesis state");
    EpochStart {
        first_height: 1,
        first_checkpoint: 0,
        prev_checkpoint: [0; 32],
        timestamp_ms: genesis.header.timestamp.as_millis().max(0) as u64,
        base_blocks: vec![(0, genesis.hash().0, root.0)],
        leader_lookahead_rounds: tenzro_consensus::schedule::LOOKAHEAD_ROUNDS,
    }
}

/// A validator stopped while the others go on for many epochs (far more
/// rounds than the DAG keeps) is restarted. It catches up over block sync,
/// through every epoch end and handover it missed, stands down from the
/// epoch it was running, and signs certificates again once a handover seats
/// it, while the others never stop certifying.
#[test]
fn a_validator_stopped_for_many_epochs_catches_up_and_signs_again() {
    network_test(async {
        const N: usize = 4;
        const LATE: usize = 3;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        let mut net = Net::start(N).await;

        // The network runs, every validator signing.
        net.wait_for(
            "the network certifies two epochs",
            Duration::from_secs(180),
            |n| (0..N).all(|i| n.certified(i).0 >= 2),
        )
        .await;

        net.down(LATE).await;
        let (stopped_epoch, _) = net.certified(0);

        // The other three, still a quorum, certify many more epochs.
        net.wait_for("three validators go on", Duration::from_secs(240), |n| {
            (0..N)
                .filter(|i| *i != LATE)
                .all(|i| n.certified(i).0 >= stopped_epoch + 6)
        })
        .await;
        let (left_epoch, left_index) = net.certified(0);
        let left_height = net.height(0);

        net.up(LATE).await;

        // It catches up to where the others were when it came back.
        net.wait_for(
            "the restarted validator catches up",
            Duration::from_secs(180),
            |n| n.certified(LATE).1 >= left_index && n.height(LATE) >= left_height,
        )
        .await;

        // And signs again: a certificate of a later epoch names it.
        let signed = net.signed.clone();
        net.wait_for(
            "the restarted validator signs again",
            Duration::from_secs(180),
            |n| {
                signed.lock().iter().any(|(epoch, _, signers)| {
                    *epoch > left_epoch
                        && n.position(LATE, *epoch)
                            .is_some_and(|p| signers.contains(&p))
                })
            },
        )
        .await;
        assert!(net.node(LATE).consensus.is_validator());

        // Every validator holds the same chain.
        let h = (0..N).map(|i| net.height(i)).min().unwrap();
        let hash = |i: usize| {
            let storage = net.machines[i].storage.clone();
            async move {
                BlockStoreImpl::new(storage)
                    .unwrap()
                    .get_block_by_height(BlockHeight(h))
                    .await
                    .unwrap()
                    .map(|b| b.hash())
            }
        };
        let reference = hash(0).await;
        assert!(reference.is_some());
        for i in 1..N {
            assert_eq!(hash(i).await, reference, "validator {i} at height {h}");
        }
    });
}

/// Resident memory of this process, MB.
fn rss_mb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map_or(0, |kb| kb / 1024)
}

/// A validator that falls an epoch behind catches up in bounded memory. All
/// validators share this process, so its resident set while the late one
/// syncs, verifies the certificates it missed and rejoins may grow by no
/// more than the network itself used before it stopped, plus 512 MB.
#[test]
fn a_validator_an_epoch_behind_catches_up_in_bounded_memory() {
    network_test(async {
        catches_up_in_bounded_memory(4).await;
    });
}

/// The same with seven validators, the committee the test network runs.
#[test]
fn one_of_seven_validators_an_epoch_behind_catches_up_in_bounded_memory() {
    network_test(async {
        catches_up_in_bounded_memory(7).await;
    });
}

#[allow(non_snake_case)]
async fn catches_up_in_bounded_memory(n_validators: usize) {
    let N = n_validators;
    let LATE = N - 1;
    const ABORT_MB: u64 = 6_144;
    let mut net = Net::start(N).await;
    net.wait_for(
        "the network certifies two epochs",
        Duration::from_secs(180),
        |n| (0..N).all(|i| n.certified(i).0 >= 2),
    )
    .await;
    let before = rss_mb();

    net.down(LATE).await;
    let (stopped_epoch, _) = net.certified(0);
    net.wait_for(
        "the others certify the next epoch",
        Duration::from_secs(240),
        |n| {
            (0..N)
                .filter(|i| *i != LATE)
                .all(|i| n.certified(i).0 > stopped_epoch)
        },
    )
    .await;
    let (_, left_index) = net.certified(0);
    let left_height = net.height(0);

    net.up(LATE).await;
    let mut peak = rss_mb();
    net.wait_for(
        "the late validator catches up",
        Duration::from_secs(240),
        |n| {
            let now = rss_mb();
            peak = peak.max(now);
            assert!(
                now < ABORT_MB,
                "resident memory reached {now} MB while catching up (before: {before} MB)"
            );
            n.certified(LATE).1 >= left_index && n.height(LATE) >= left_height
        },
    )
    .await;
    assert!(
        peak <= 2 * before + 512,
        "catching up an epoch took the process from {before} MB to {peak} MB"
    );
}

/// Transfers offered at `rate` a second, round robin over `senders`
/// accounts funded at genesis, to every validator as gossip would, for
/// `load_for`, while epochs end every few seconds. Every accepted transfer
/// must then execute within `drain`: a sender whose transactions stall
/// behind one that never executes is refused once it has too many pending,
/// and nothing of it is ever included again.
///
/// With `stall` (after, hold), the first two validators stop `after` into
/// the load and start again `hold` later: the network is below quorum
/// meanwhile, and transfers go to the other two only, as to a node that
/// serves RPC.
async fn every_transfer_executes_under_load(
    rate: u32,
    senders: u8,
    load_for: Duration,
    drain: Duration,
    stall: Option<(Duration, Duration)>,
) {
    every_transfer_executes_under_load_on(
        Default::default(),
        rate,
        senders,
        load_for,
        drain,
        stall,
    )
    .await;
}

/// [`every_transfer_executes_under_load`] on a network whose genesis sets
/// `params`; returns the network once every transfer has executed.
async fn every_transfer_executes_under_load_on(
    params: std::collections::BTreeMap<String, u64>,
    rate: u32,
    senders: u8,
    load_for: Duration,
    drain: Duration,
    stall: Option<(Duration, Duration)>,
) -> Net {
    use tenzro_consensus::mempool::AccountStateReader;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    const N: usize = 4;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let signers: Vec<TestHybridSigner> = (1..=senders).map(TestHybridSigner::hybrid).collect();
    let addresses: Vec<Address> = signers.iter().map(|s| s.address()).collect();
    let mut net = Net::start_configured(
        N,
        0,
        addresses.clone(),
        time_rules(),
        Accounts::Silent,
        params,
    )
    .await;
    net.wait_for(
        "the network certifies an epoch",
        Duration::from_secs(180),
        |n| (0..N).all(|i| n.certified(i).0 >= 1),
    )
    .await;

    // Every sender holds a registered identity, as RegisterIdentity leaves
    // it: the wallet index names its identity in each machine's chain store.
    for m in &net.machines {
        let store = m.storage.clone() as Arc<dyn KvStore>;
        for (i, a) in addresses.iter().enumerate() {
            register_in_chain_store(&store, a, &format!("did:tenzro:machine:sender{i}"));
        }
    }

    // Each sender's first transaction enrols its ML-DSA-65 key; the load of
    // transfers starts once every key is enrolled.
    for s in &signers {
        let enrol = signed_transfer(s, 0, 0);
        for i in 0..N {
            net.node(i).consensus.submit_transaction(enrol.clone()).ok();
        }
    }
    let enrolled = tenzro_node::lane_resolver::NodeAccountStateReader::new(
        net.machines[0].storage.clone() as Arc<dyn KvStore>,
    );
    net.wait_for(
        "every sender's key is enrolled",
        Duration::from_secs(180),
        |_| addresses.iter().all(|a| enrolled.account_nonce(a) > 0),
    )
    .await;

    let first = if stall.is_some() { 2 } else { 0 };
    let handles: Vec<Arc<ConsensusHandle>> =
        (first..N).map(|i| net.node(i).consensus.clone()).collect();
    let (start_epoch, _) = net.certified(0);
    let start_height = net.height(0);
    // The clients are not the validators, and not one machine: each worker
    // is a thread with a runtime of its own that signs for its share of the
    // senders and offers its share of the rate. Signing two signatures per
    // transfer is the clients' work, which one thread cannot keep up with
    // at the rate the validators are asked to hold.
    const WORKERS: usize = 8;
    let load: Vec<_> = (0..WORKERS)
        .map(|w| {
            let handles = handles.clone();
            let seeds: Vec<(usize, u8)> = (1..=senders)
                .enumerate()
                .filter(|(i, _)| i % WORKERS == w)
                .collect();
            tokio::task::spawn_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .expect("load runtime")
                    .block_on(async move {
                        let signers: Vec<TestHybridSigner> = seeds
                            .iter()
                            .map(|(_, seed)| TestHybridSigner::hybrid(*seed))
                            .collect();
                        let mut nonces = vec![1u64; signers.len()];
                        // Each sender's accepted transfers by nonce, from 1.
                        let mut hashes: Vec<Vec<Hash>> = vec![Vec::new(); signers.len()];
                        let mut offered = 0u64;
                        let mut refused_offers = 0u64;
                        let mut spent = Duration::ZERO;
                        let mut refused: std::collections::BTreeMap<String, u64> =
                            Default::default();
                        let mut tick = tokio::time::interval(Duration::from_millis(10));
                        let (mut due, mut k) = (0f64, 0usize);
                        let end = Instant::now() + load_for;
                        while !signers.is_empty() && Instant::now() < end {
                            tick.tick().await;
                            due += f64::from(rate) / WORKERS as f64 / 100.0;
                            while due >= 1.0 {
                                due -= 1.0;
                                let i = k % signers.len();
                                k += 1;
                                let signed = signed_transfer(&signers[i], nonces[i], 1);
                                offered += 1;
                                let mut ok = false;
                                let mut why = Vec::new();
                                let began = Instant::now();
                                for h in &handles {
                                    match h.submit_transaction(signed.clone()) {
                                        Ok(()) => ok = true,
                                        Err(e) => why.push(e.to_string()),
                                    }
                                }
                                spent += began.elapsed();
                                // A refused nonce is offered again on the sender's next turn.
                                if ok {
                                    nonces[i] += 1;
                                    hashes[i].push(signed.clone().hash());
                                } else {
                                    // Refused by every validator: each refusal counts
                                    // under its reason.
                                    refused_offers += 1;
                                    for w in why {
                                        let key = match backpressure(&w) {
                                            Some(limit) => limit.to_string(),
                                            None => w,
                                        };
                                        *refused.entry(key).or_default() += 1;
                                    }
                                }
                            }
                        }
                        let senders: Vec<usize> = seeds.iter().map(|(i, _)| *i).collect();
                        (
                            senders,
                            nonces,
                            hashes,
                            offered,
                            refused_offers,
                            spent,
                            refused,
                        )
                    })
            })
        })
        .collect();
    if let Some((after, hold)) = stall {
        tokio::time::sleep(after).await;
        net.down(0).await;
        net.down(1).await;
        tokio::time::sleep(hold).await;
        net.up(0).await;
        net.up(1).await;
    }
    let mut accepted = vec![0u64; addresses.len()];
    let mut accepted_hashes: Vec<Vec<Hash>> = vec![Vec::new(); addresses.len()];
    let mut offered = 0u64;
    let mut refused_offers = 0u64;
    let mut spent = Duration::ZERO;
    let mut refused: std::collections::BTreeMap<String, u64> = Default::default();
    for worker in load {
        let (
            owned,
            nonces,
            hashes,
            worker_offered,
            worker_refused_offers,
            worker_spent,
            worker_refused,
        ) = worker.await.unwrap();
        for ((i, n), h) in owned.into_iter().zip(nonces).zip(hashes) {
            accepted[i] = n;
            accepted_hashes[i] = h;
        }
        offered += worker_offered;
        refused_offers += worker_refused_offers;
        spent += worker_spent;
        for (why, n) in worker_refused {
            *refused.entry(why).or_default() += n;
        }
    }
    let total: u64 = accepted.iter().sum();
    eprintln!(
        "load: {offered} offered ({:.0} a second of the {rate} asked), {total} accepted, \
         {spent:?} spent submitting, refusals {refused:?}",
        offered as f64 / load_for.as_secs_f64()
    );
    // How many transfers the clients manage to sign and offer is the host's:
    // on a loaded machine they fall behind the asked rate, and how many the
    // validators then refuse as backpressure follows from that too. What the
    // test holds the network to is that the load reached it (every sender has
    // transfers accepted past its enrolment) and, below, that every accepted
    // transfer executes. The rate itself is a measurement, printed above.
    let starved = accepted.iter().filter(|n| **n <= 1).count();
    assert_eq!(
        starved, 0,
        "the validators accepted the load: {starved} of {senders} senders had no transfer accepted \
         ({total} of {offered} offered)"
    );
    // The floor: every offered transfer is accepted, or refused by every
    // validator as backpressure (a rate, capacity or nonce-gap limit) with
    // the reason recorded. Any other refusal is a defect, whatever the rate.
    let other: Vec<&String> = refused
        .keys()
        .filter(|w| backpressure(w).is_none())
        .collect();
    assert!(
        other.is_empty(),
        "transfers were refused for something other than backpressure: {other:?}"
    );
    // Each sender's nonce starts at 1, past its enrolment.
    let accepted_offers: u64 = accepted.iter().map(|n| n - 1).sum();
    assert!(
        accepted_offers >= offered - refused_offers,
        "{accepted_offers} transfers accepted of {offered} offered, {refused_offers} refused as \
         backpressure: the rest were neither accepted nor refused"
    );
    // Backpressure sheds load; it does not take most of it. At least half of
    // what the clients offered is accepted, however fast they offered it.
    assert!(
        accepted_offers * 2 >= offered,
        "{accepted_offers} transfers accepted of {offered} offered: backpressure refused most of \
         the load ({refused:?})"
    );
    // A full mempool or a sender too far ahead of execution is a limit this
    // load should seldom reach: the admission rate limits shed it first. A
    // large share of either would hide a mempool that does not drain or
    // nonces that do not advance, so each stays under a tenth of the offers.
    for limit in [
        "Mempool full",
        "Mempool size limit exceeded",
        "Nonce gap too large",
    ] {
        let n: u64 = refused
            .iter()
            .filter(|(why, _)| backpressure(why) == Some(limit))
            .map(|(_, n)| n)
            .sum();
        assert!(
            n * 10 <= offered,
            "{n} of {offered} offered transfers were refused with \"{limit}\": more than \
             backpressure at this load explains"
        );
    }

    let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
        net.machines[0].storage.clone() as Arc<dyn KvStore>,
    );
    let executed = |reader: &tenzro_node::lane_resolver::NodeAccountStateReader| -> u64 {
        addresses
            .iter()
            .zip(&accepted)
            .map(|(a, n)| reader.account_nonce(a).min(*n))
            .sum()
    };
    // How fast transfers execute is the host's: four validators of an
    // unoptimised build in one process, on a machine others share. The
    // backlog the load leaves gets the time it takes at the rate the
    // validators executed during the load, half again as tolerance, never
    // less than `drain` and never more than five times it. Every accepted
    // transfer must still execute: a network that stops executing fails.
    let at_load_end = executed(&reader);
    let executed_rate = at_load_end as f64 / load_for.as_secs_f64();
    let backlog = total.saturating_sub(at_load_end);
    let needed = if executed_rate > 0.0 {
        Duration::from_secs_f64(1.5 * backlog as f64 / executed_rate)
    } else {
        drain * 5
    };
    let drain = needed.clamp(drain, drain * 5);
    eprintln!(
        "executed {at_load_end} of {total} during the load ({executed_rate:.0} a second); \
         draining for up to {drain:?}"
    );
    // The drain time is an estimate from the rate during the load, and
    // execution on a shared host comes in bursts (the executed height can sit
    // still for a minute while ordering goes on, then catch up). So the
    // deadline holds only while the count of executed transfers is still
    // moving: a network that stops executing for `STALLED` fails at the
    // deadline as before, one still working through its backlog is given time
    // up to ten times the estimate.
    const STALLED: Duration = Duration::from_secs(60);
    let started = Instant::now();
    let deadline = started + drain;
    let mut last_count = executed(&reader);
    let mut last_progress = Instant::now();
    let mut report = Instant::now();
    while executed(&reader) < total {
        let now = Instant::now();
        let count = executed(&reader);
        if count > last_count {
            last_count = count;
            last_progress = now;
        }
        if now >= deadline
            && (now.duration_since(last_progress) >= STALLED || now >= started + drain * 10)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        if report.elapsed() >= Duration::from_secs(10) {
            report = Instant::now();
            eprintln!(
                "executed {} of {total}; heights {:?}, executed heights {:?}",
                executed(&reader),
                net.heights(),
                (0..N)
                    .map(|i| net.node(i).consensus.executed_height())
                    .collect::<Vec<_>>()
            );
        }
    }
    let done = executed(&reader);
    let stalled: Vec<usize> = (0..addresses.len())
        .filter(|&i| reader.account_nonce(&addresses[i]) < accepted[i])
        .collect();
    let stuck = stalled.len();
    // Where each stalled sender's next transfer is: its receipt if it
    // executed and failed, which validators' pools hold it, and the lowest
    // nonce each holds of that sender.
    for &s in stalled.iter().take(5) {
        let a = &addresses[s];
        let next = reader.account_nonce(a);
        let receipt = accepted_hashes[s]
            .get((next as usize).wrapping_sub(1))
            .and_then(|h| {
                net.machines[0]
                    .storage
                    .get(
                        tenzro_storage::CF_TRANSACTIONS,
                        format!("receipt:{h}").as_bytes(),
                    )
                    .ok()
                    .flatten()
            })
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .chars()
                    .take(300)
                    .collect::<String>()
            });
        eprintln!("stalled sender at nonce {next}: receipt {receipt:?}");
        let pools: Vec<(bool, Option<u64>)> = (0..N)
            .map(|i| {
                let pool = net.node(i).consensus.mempool();
                let held = pool.has_pending_from(a, |t| t.transaction.nonce.0 == next);
                let lowest = (next..next + 64)
                    .find(|&k| pool.has_pending_from(a, |t| t.transaction.nonce.0 == k));
                (held, lowest)
            })
            .collect();
        eprintln!("stalled sender at nonce {next}: (held, lowest pooled) per validator {pools:?}");
    }
    assert_eq!(
        done, total,
        "{done} of {total} accepted transfers executed within {drain:?} of the load ending; \
         {stuck} of {senders} senders stalled"
    );
    // Certificates follow execution: they are given what is left of the
    // same deadline to reach the epochs the load ran through.
    net.wait_for(
        "blocks were ordered and epochs certified under load",
        deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_secs(60)),
        |n| n.height(0) > start_height + 8 && n.certified(0).0 > start_epoch + 2,
    )
    .await;
    net
}

#[test]
fn every_transfer_executes_at_60_a_second() {
    network_test(async {
        every_transfer_executes_under_load(
            60,
            120,
            Duration::from_secs(90),
            Duration::from_secs(60),
            None,
        )
        .await;
    });
}

#[test]
fn every_transfer_executes_at_200_a_second() {
    network_test(async {
        every_transfer_executes_under_load(
            200,
            240,
            Duration::from_secs(90),
            Duration::from_secs(60),
            None,
        )
        .await;
    });
}

/// Half the validators stop under load and start again three minutes
/// later: every transfer accepted meanwhile, and after, still executes.
#[test]
fn every_transfer_executes_through_a_stall() {
    network_test(async {
        every_transfer_executes_under_load(
            20,
            240,
            Duration::from_secs(300),
            Duration::from_secs(120),
            Some((Duration::from_secs(30), Duration::from_secs(180))),
        )
        .await;
    });
}

/// A validator stopped for far more rounds than the DAG keeps, but for much
/// less than an epoch, is restarted. It fast-forwards to a certified
/// checkpoint of the running epoch and signs that epoch's certificates
/// again, long before the next handover.
#[test]
fn a_validator_stopped_mid_epoch_rejoins_the_same_epoch() {
    network_test(async {
        const N: usize = 4;
        const LATE: usize = 3;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        // Twenty-minute epochs; rounds every 100 ms while idle, so the DAG's
        // 50 rounds last about five seconds.
        let rules = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 2_400,
            handover_confirmations: 2,
            idle_round_interval_ms: 100,
            ..TimeRules::default()
        };
        use tenzro_crypto::composite::testing::TestHybridSigner;
        let signers: Vec<TestHybridSigner> = (1..=40u8).map(TestHybridSigner::hybrid).collect();
        let addresses: Vec<Address> = signers.iter().map(|s| s.address()).collect();
        let mut net = Net::start_with(N, addresses, rules).await;
        // Checkpoints come with blocks: keep funded transfers flowing into every
        // running validator's mempool, about 20 a second.
        let gossip = net.gossip.clone();
        let load = tokio::spawn(async move {
            let mut nonces = vec![0u64; signers.len()];
            let mut k = 0usize;
            loop {
                let i = k % signers.len();
                k += 1;
                let s = &signers[i];
                let signed = signed_transfer(s, nonces[i], 1);
                let handles: Vec<Arc<ConsensusHandle>> = gossip
                    .lock()
                    .nodes
                    .values()
                    .map(|(h, _)| h.clone())
                    .collect();
                let mut ok = false;
                for h in handles {
                    ok |= h.submit_transaction(signed.clone()).is_ok();
                }
                // A refused nonce is offered again on the sender's next turn.
                if ok {
                    nonces[i] += 1;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        net.wait_for("the network certifies", Duration::from_secs(120), |n| {
            (0..N).all(|i| n.certified(i).1 >= 2)
        })
        .await;
        let (epoch, _) = net.certified(0);

        net.down(LATE).await;
        let (_, stopped_index) = net.certified(0);
        // The others go on for many times the rounds the DAG keeps.
        net.wait_for("three validators go on", Duration::from_secs(120), |n| {
            (0..N)
                .filter(|i| *i != LATE)
                .all(|i| n.certified(i).1 >= stopped_index + 30)
        })
        .await;
        let (_, left_index) = net.certified(0);
        let left_height = net.height(0);

        let back = Instant::now();
        net.up(LATE).await;

        net.wait_for(
            "the restarted validator catches up",
            Duration::from_secs(120),
            |n| n.certified(LATE).1 >= left_index && n.height(LATE) >= left_height,
        )
        .await;

        // It signs again in the same epoch.
        let signed = net.signed.clone();
        let position = net.position(LATE, epoch).expect("seated");
        net.wait_for(
            "the restarted validator signs in its epoch",
            Duration::from_secs(120),
            |_| {
                signed.lock().iter().any(|(e, index, signers)| {
                    *e == epoch && *index > left_index && signers.contains(&position)
                })
            },
        )
        .await;
        let took = back.elapsed();
        assert_eq!(
            net.certified(0).0,
            epoch,
            "the epoch ended before the validator rejoined"
        );
        assert!(net.node(LATE).consensus.is_validator());
        eprintln!(
            "rejoined its epoch {:.1} s after restarting",
            took.as_secs_f64()
        );

        // Every validator holds the same chain.
        let h = (0..N).map(|i| net.height(i)).min().unwrap();
        let hash = |i: usize| {
            let storage = net.machines[i].storage.clone();
            async move {
                BlockStoreImpl::new(storage)
                    .unwrap()
                    .get_block_by_height(BlockHeight(h))
                    .await
                    .unwrap()
                    .map(|b| b.hash())
            }
        };
        let reference = hash(0).await;
        for i in 1..N {
            assert_eq!(hash(i).await, reference, "validator {i} at height {h}");
        }
        load.abort();
    });
}

/// A validator that restarts while its gossip mesh is still forming loses the
/// sealed endpoints its peers publish at once. Its peers publish the set
/// again within seconds, so every validator holds every other's endpoint soon
/// after the mesh forms, not at a periodic announcement minutes later.
#[test]
fn a_restarted_validator_learns_its_peers_endpoints_soon_after_its_mesh_forms() {
    network_test(async {
        const N: usize = 4;
        const LATE: usize = 3;
        let mut net = Net::start(N).await;
        let meshed = |n: &Net| {
            (0..N).all(|i| {
                (0..N).filter(|j| *j != i).all(|j| {
                    n.node(i)
                        .consensus
                        .announced_endpoint(n.machines[j].validator.public_key())
                        .is_some()
                })
            })
        };
        net.wait_for(
            "the validators know each other",
            Duration::from_secs(90),
            meshed,
        )
        .await;
        net.down(LATE).await;
        let deaf = Duration::from_secs(10);
        net.gossip
            .lock()
            .deaf
            .insert(LATE, Instant::now() + deaf + Duration::from_secs(5));
        let back = Instant::now();
        net.up(LATE).await;
        net.wait_for(
            "the restarted validator knows its peers again",
            Duration::from_secs(60),
            meshed,
        )
        .await;
        let took = back.elapsed();
        eprintln!("meshed {:.1} s after restarting", took.as_secs_f64());
        assert!(
            took < Duration::from_secs(40),
            "meshed only {took:?} after restarting"
        );
    });
}

/// A validator that restarts and hears nothing for longer than its peers
/// keep repeating their sealed endpoints has missed every copy sealed to
/// it. With the pull gate live it asks in its own announcement, and the
/// peers publish the set again at once: it holds every endpoint within one
/// announcement interval of hearing again, where the peers' next unprompted
/// publication of the set is minutes away.
#[test]
fn a_restarted_validator_that_missed_the_sealed_endpoints_asks_for_them() {
    network_test(async {
        const N: usize = 4;
        const LATE: usize = 3;
        let live = [(
            tenzro_vm::governance::SEALED_ENDPOINT_PULL_GATE.to_string(),
            0,
        )];
        let mut net = Net::start_configured(
            N,
            0,
            Vec::new(),
            time_rules(),
            Accounts::Silent,
            live.into_iter().collect(),
        )
        .await;
        let meshed = |n: &Net| {
            (0..N).all(|i| {
                (0..N).filter(|j| *j != i).all(|j| {
                    n.node(i)
                        .consensus
                        .announced_endpoint(n.machines[j].validator.public_key())
                        .is_some()
                })
            })
        };
        net.wait_for(
            "the validators know each other",
            Duration::from_secs(90),
            meshed,
        )
        .await;
        net.down(LATE).await;
        // Past the peers' quick repeats and the periodic announcements that
        // still carry the set after a change.
        let deaf = Duration::from_secs(100);
        net.gossip.lock().deaf.insert(LATE, Instant::now() + deaf);
        let back = Instant::now();
        net.up(LATE).await;
        net.wait_for(
            "the restarted validator knows its peers again",
            deaf + Duration::from_secs(120),
            meshed,
        )
        .await;
        let took = back.elapsed();
        eprintln!("meshed {:.1} s after restarting", took.as_secs_f64());
        assert!(
            took < deaf + Duration::from_secs(35),
            "meshed only {took:?} after restarting, {deaf:?} of it unable to hear"
        );
        assert!(net.gossip.lock().requests > 0, "nothing was asked");
    });
}

/// While the pull gate is dormant a validator that lacks its peers'
/// endpoints asks for nothing: every publication is an announcement and its
/// sealed endpoints, as before the gate existed.
#[test]
fn a_validator_asks_for_no_endpoints_while_the_gate_is_dormant() {
    network_test(async {
        const N: usize = 4;
        const LATE: usize = 3;
        let mut net = Net::start(N).await;
        net.wait_for(
            "every validator published its announcement",
            Duration::from_secs(90),
            |n| n.gossip.lock().published.len() == N,
        )
        .await;
        net.down(LATE).await;
        // Unable to hear for several of the waits after which a live gate
        // would have it ask.
        let deaf = Duration::from_secs(20);
        net.gossip.lock().deaf.insert(LATE, Instant::now() + deaf);
        net.up(LATE).await;
        tokio::time::sleep(deaf).await;
        assert_eq!(net.gossip.lock().requests, 0);
    });
}

/// A neighbour no endpoint record names yet is heard on the announcements
/// topic when, and only when, what it delivers is a current announcement
/// signed by a validator of a committee the node holds: gossip admits it on
/// that, since the announcement is what leads to the record that names the
/// neighbour.
#[test]
fn only_a_current_announcement_of_a_known_validator_is_vouched_for() {
    network_test(async {
        const N: usize = 3;
        let net = Net::start(N).await;
        net.wait_for(
            "every validator published its announcement",
            Duration::from_secs(90),
            |n| n.gossip.lock().published.len() == N,
        )
        .await;
        let published = net.gossip.lock().published.get(&1).cloned().unwrap();
        let encode =
            |p: &tenzro_consensus::announce::PublishedAnnouncement| bincode::serialize(p).unwrap();
        let node = &net.node(0).consensus;
        assert!(
            node.vouches_for_announcement(&encode(&published)),
            "a validator's own signed announcement"
        );

        let mut altered = published.clone();
        altered.announcement.not_after_ms += 1;
        assert!(
            !node.vouches_for_announcement(&encode(&altered)),
            "an announcement changed after it was signed"
        );
        let mut unknown = published.clone();
        unknown.announcement.validator = [7; 32];
        assert!(
            !node.vouches_for_announcement(&encode(&unknown)),
            "an announcement naming no validator the node knows"
        );
        let mut elsewhere = published.clone();
        elsewhere.announcement.chain_id ^= 1;
        assert!(
            !node.vouches_for_announcement(&encode(&elsewhere)),
            "an announcement for another chain"
        );
        assert!(!node.vouches_for_announcement(b"not an announcement"));
        assert!(!node.vouches_for_announcement(&[]));
    });
}

/// A network started from the launch genesis, with every post-quantum
/// switch on from block 0, certifies epochs and executes every transfer
/// under load, and its chain state holds every switch on.
#[test]
fn a_network_from_the_launch_genesis_runs_with_every_post_quantum_switch_on() {
    network_test(async {
        // Every launch value applies, the identity rule live from block 0
        // included: the senders hold registered identities.
        let switches = launch_switches();
        let started = Instant::now();
        let net = every_transfer_executes_under_load_on(
            switches.clone(),
            60,
            120,
            Duration::from_secs(60),
            Duration::from_secs(60),
            None,
        )
        .await;
        let state = tenzro_vm::StateAdapter::with_storage(
            net.machines[0].storage.clone() as Arc<dyn KvStore>
        );
        for (key, value) in &switches {
            assert_eq!(
                tenzro_vm::native::network_param(&state, key),
                *value,
                "{key}"
            );
        }
        eprintln!(
            "launch genesis network: height {}, certified epoch {}, {:?} from start",
            net.height(0),
            net.certified(0).0,
            started.elapsed()
        );
    });
}

/// Writes what `RegisterIdentity` leaves in chain state for `account`: the
/// wallet index entry naming `did`.
fn register_in_chain_store(store: &Arc<dyn KvStore>, account: &Address, did: &str) {
    let key = format!(
        "storage:{}:{}",
        hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
        hex::encode(format!(
            "identity_wallet:{}",
            hex::encode(account.as_bytes())
        ))
    );
    store
        .put(tenzro_storage::CF_STATE, key.as_bytes(), did.as_bytes())
        .expect("write the wallet index");
}

/// The sender's transaction at `nonce`: the account's first transaction is
/// the enrolment of its ML-DSA-65 key, every later one a transfer of
/// `amount`.
fn feed_transfers(
    handles: Vec<Arc<ConsensusHandle>>,
    storage: Arc<dyn KvStore>,
) -> tokio::task::JoinHandle<()> {
    use tenzro_consensus::mempool::AccountStateReader;
    tokio::spawn(async move {
        let signer = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(1);
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(storage);
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tick.tick().await;
            let nonce = reader.account_nonce(&signer.address());
            let signed = signed_transfer(&signer, nonce, 1);
            for h in &handles {
                let _ = h.submit_transaction(signed.clone());
            }
        }
    })
}

fn signed_transfer(
    signer: &tenzro_crypto::composite::testing::TestHybridSigner,
    nonce: u64,
    amount: u128,
) -> tenzro_types::transaction::SignedTransaction {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    use tenzro_types::account_signature::{AccountKeysOp, pq_enrollment_message};
    use tenzro_types::primitives::{ChainId, Nonce};
    use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
    let tx_type = if nonce == 0 {
        let key = signer.public_key().pq.clone().expect("a hybrid signer");
        let message = pq_enrollment_message(&signer.public_key().account_slot(), &key);
        let possession = signer
            .sign(SignatureContext::PqKeyEnrollment, &message)
            .unwrap()
            .pq
            .unwrap();
        TransactionType::AccountKeys {
            op: AccountKeysOp::EnrollPqKey {
                ml_dsa_public_key: key,
                possession,
            },
        }
    } else {
        TransactionType::Transfer { amount }
    };
    let tx = Transaction::new(
        ChainId::from(CHAIN_ID),
        signer.address(),
        Address::new([0xee; 32]),
        Nonce::from(nonce),
        tx_type,
        // The enrolment costs more gas than a transfer.
        if nonce == 0 { 200_000 } else { 21_000 },
        10_000_000_000,
    );
    let sig = signer
        .sign(SignatureContext::Transaction, tx.hash().as_bytes())
        .unwrap();
    SignedTransaction::new(tx, signer.public_key().p256.clone(), sig)
}

/// A registration submitted as a transaction, ordered into a block and
/// executed by every validator, leaves the controller's ML-DSA-65 key enrolled
/// in each one's chain state: the path a node's identity registration takes
/// before a later approval by that controller needs both legs.
#[test]
fn a_registration_in_a_block_enrols_the_controllers_key_on_every_validator() {
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        use tenzro_crypto::composite::testing::TestHybridSigner;
        use tenzro_crypto::composite::{HybridSigner, SignatureContext};
        use tenzro_types::primitives::{ChainId, Nonce};
        use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
        const N: usize = 4;
        let sender = TestHybridSigner::hybrid(1);
        let controller = TestHybridSigner::hybrid(7);
        let controller_p256 = controller.public_key().p256.clone();
        let expected_pq = TestHybridSigner::hybrid_pq_key(&controller_p256).expect("a hybrid key");
        let net = Net::start_with(N, vec![sender.address()], time_rules()).await;
        net.wait_for(
            "the network certifies an epoch",
            Duration::from_secs(180),
            |n| (0..N).all(|i| n.certified(i).0 >= 1),
        )
        .await;
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        let submit = |tx: &SignedTransaction| {
            for i in 0..N {
                net.node(i).consensus.submit_transaction(tx.clone()).ok();
            }
        };
        // The sender's first transaction enrols its own key.
        submit(&signed_transfer(&sender, 0, 0));
        net.wait_for(
            "the sender's key is enrolled",
            Duration::from_secs(120),
            |_| reader.account_nonce(&sender.address()) > 0,
        )
        .await;

        let mut payload = tenzro_types::identity::RegisterIdentityPayload {
            did: format!(
                "did:tenzro:human:{}",
                tenzro_types::did_derivation::human_id(&controller_p256)
            ),
            identity_type: "human".to_string(),
            display_name: "Controller".to_string(),
            controller_pubkey: controller_p256.clone(),
            key_type: "P256".to_string(),
            wallet_id: "wallet-1".to_string(),
            wallet_address: Address::new([0x77; 32]),
            pq_verifying_key: controller.public_key().pq.clone().expect("a hybrid key"),
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        let statement = tenzro_types::identity::registration_statement(&payload);
        payload.proof = tenzro_types::identity::RegistrationProof::Hardware {
            signature: controller
                .sign(SignatureContext::IdentityRegistration, &statement)
                .unwrap(),
        };
        let tx = Transaction::new(
            ChainId::from(CHAIN_ID),
            sender.address(),
            Address::new([0u8; 32]),
            Nonce::from(1),
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
            200_000,
            10_000_000_000,
        );
        let sig = sender
            .sign(SignatureContext::Transaction, tx.hash().as_bytes())
            .unwrap();
        submit(&SignedTransaction::new(
            tx,
            sender.public_key().p256.clone(),
            sig,
        ));
        net.wait_for(
            "the registration executes",
            Duration::from_secs(120),
            |_| reader.account_nonce(&sender.address()) > 1,
        )
        .await;

        // Every validator, once it has executed the block, holds the key.
        net.wait_for(
            "every validator holds the controller's enrolled key",
            Duration::from_secs(60),
            |n| {
                (0..N).all(|i| {
                    let state = tenzro_vm::StateAdapter::with_storage(
                        n.machines[i].storage.clone() as Arc<dyn KvStore>,
                    );
                    tenzro_vm::account_keys::enrolled_pq_key(&state, &controller_p256).as_deref()
                        == Some(expected_pq.as_slice())
                })
            },
        )
        .await;
    });
}

/// Four validators; gossip delivers to each, once, a transfer of `amount`
/// from a funded sender at a nonce just past the window a validator holds
/// for it, which every one refuses; then the sender's transactions before it
/// arrive and execute. Returns the network, the sender, the hash of the
/// refused transfer and its nonce.
async fn refused_once_then_earlier_ones_execute(
    amount: u128,
) -> (
    Net,
    tenzro_crypto::composite::testing::TestHybridSigner,
    tenzro_types::primitives::Hash,
    u64,
) {
    use tenzro_consensus::mempool::AccountStateReader;
    const N: usize = 4;
    let signer = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(1);
    let net = Net::start_with(N, vec![signer.address()], time_rules()).await;
    net.wait_for(
        "the network certifies an epoch",
        Duration::from_secs(180),
        |n| (0..N).all(|i| n.certified(i).0 >= 1),
    )
    .await;
    let window = tenzro_consensus::ConsensusConfig::default().mempool_max_per_sender as u64;
    // The sender's first transaction enrols its ML-DSA-65 key; the far one
    // is then refused for its nonce alone.
    let enrol = signed_transfer(&signer, 0, 0);
    for i in 0..N {
        net.node(i).consensus.submit_transaction(enrol.clone()).ok();
    }
    let enrolled = tenzro_node::lane_resolver::NodeAccountStateReader::new(
        net.machines[0].storage.clone() as Arc<dyn KvStore>,
    );
    net.wait_for(
        "the sender's key is enrolled",
        Duration::from_secs(120),
        |_| enrolled.account_nonce(&signer.address()) > 0,
    )
    .await;
    let far = signed_transfer(&signer, window + 2, amount);
    let far_hash = far.transaction.hash();
    for i in 0..N {
        net.node(i)
            .events
            .send(NodeEvent::NewTransaction(far.clone()))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    for i in 0..N {
        assert!(
            net.node(i)
                .consensus
                .mempool()
                .get_transaction(&far_hash)
                .is_none(),
            "validator {i} admitted a transaction past its nonce window"
        );
    }

    let handles: Vec<Arc<ConsensusHandle>> =
        (0..N).map(|i| net.node(i).consensus.clone()).collect();
    let mut next = 1u64;
    let fill = Instant::now() + Duration::from_secs(120);
    while next <= window + 1 {
        assert!(
            Instant::now() < fill,
            "the earlier transactions were admitted"
        );
        let tx = signed_transfer(&signer, next, 1);
        let mut ok = false;
        for h in &handles {
            ok |= h.submit_transaction(tx.clone()).is_ok();
        }
        if ok {
            next += 1;
        } else {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
        net.machines[0].storage.clone() as Arc<dyn KvStore>,
    );
    net.wait_for(
        "the earlier transactions execute",
        Duration::from_secs(120),
        |_| reader.account_nonce(&signer.address()) > window + 1,
    )
    .await;
    (net, signer, far_hash, window + 2)
}

/// A transaction gossip delivers once, at a moment every validator's
/// admission refuses it for a reason that passes (here: its nonce is further
/// ahead of the sender's than a validator holds), still executes once the
/// sender's earlier transactions have. Its origin publishes it only once, so
/// a validator that drops it would leave the sender waiting behind it for
/// good.
#[test]
fn a_gossiped_transaction_refused_for_a_while_still_executes() {
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        let (net, signer, _, nonce) = refused_once_then_earlier_ones_execute(1).await;
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for(
            "the refused transaction executes after the ones before it",
            Duration::from_secs(120),
            |_| reader.account_nonce(&signer.address()) > nonce,
        )
        .await;
    });
}

/// A held transaction that is then refused for good (here: it spends more
/// than the sender holds) is dropped: it never reaches a mempool and never
/// executes, and the sender's next transaction at its nonce does.
#[test]
fn a_held_transaction_refused_for_good_is_dropped() {
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        const N: usize = 4;
        let (net, signer, held, nonce) =
            refused_once_then_earlier_ones_execute(u128::MAX / 2).await;
        let in_any_mempool = |net: &Net| {
            (0..N).any(|i| {
                net.node(i)
                    .consensus
                    .mempool()
                    .get_transaction(&held)
                    .is_some()
            })
        };
        let executed = |net: &Net| {
            (0..N).any(|i| {
                net.machines[i]
                    .storage
                    .get(
                        tenzro_storage::CF_TRANSACTIONS,
                        format!("receipt:{held}").as_bytes(),
                    )
                    .ok()
                    .flatten()
                    .is_some()
            })
        };
        // Offered again several times since its nonce came due.
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            assert!(
                !in_any_mempool(&net),
                "a transaction refused for good was admitted"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let next = signed_transfer(&signer, nonce, 1);
        for i in 0..N {
            let _ = net.node(i).consensus.submit_transaction(next.clone());
        }
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for(
            "the sender's next transaction executes at the dropped one's nonce",
            Duration::from_secs(120),
            |_| reader.account_nonce(&signer.address()) > nonce,
        )
        .await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!in_any_mempool(&net), "the dropped transaction came back");
        assert!(!executed(&net), "the dropped transaction executed");
    });
}

/// The epochs' recorded vote tallies `i` holds in state: (checkpoints'
/// highest index recorded, rounds certified), summed over epochs 0 to `last`.
fn recorded_votes(net: &Net, i: usize, last: u64) -> (usize, u64) {
    let state = tenzro_vm::StateAdapter::with_storage(net.machines[i].storage.clone());
    (0..=last)
        .map(|e| tenzro_vm::native::rewards::read_epoch_votes(&state, e).unwrap())
        .fold((0, 0), |(n, rounds), v| {
            (
                n + usize::from(v.last_index.is_some()),
                rounds + v.certified_rounds,
            )
        })
}

/// Four validators whose ledger accounts are bonded at genesis and hold
/// nothing to spend. Nobody else sends anything: the blocks are the
/// validators' own records of the checkpoints they sign. The chain advances,
/// certifies epochs, and records every validator's vote work, and no account
/// is charged for it.
#[test]
fn validators_with_nothing_to_spend_advance_and_record_their_checkpoints() {
    network_test(async {
        use tenzro_vm::traits::VmState as _;
        const N: usize = 4;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        // A signers record is made only for a checkpoint that certifies
        // real work, so a funded account feeds the chain its transfers: the
        // validators' records of those checkpoints are the rest of the blocks.
        let feeder_account = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(1);
        let net = Net::start_full(
            N,
            vec![feeder_account.address()],
            time_rules(),
            Accounts::RecordBonded,
        )
        .await;
        let feeder = feed_transfers(
            (0..N).map(|i| net.node(i).consensus.clone()).collect(),
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        for m in &net.machines {
            let state = tenzro_vm::StateAdapter::with_storage(m.storage.clone());
            let account = m.account.as_ref().unwrap().address();
            assert!(tenzro_vm::native::bonded_stake_of(&state, account.as_bytes()) > 0);
        }

        net.wait_for(
            "the chain advances and certifies two epochs on its validators' records",
            Duration::from_secs(180),
            |n| (0..N).all(|i| n.height(i) >= 10 && n.certified(i).0 >= 2),
        )
        .await;
        let (epoch, _) = net.certified(0);
        net.wait_for(
            "every validator holds recorded vote tallies",
            Duration::from_secs(60),
            |n| (0..N).all(|i| recorded_votes(n, i, epoch).1 > 0),
        )
        .await;
        assert!(
            net.stats.refusals.lock().is_empty(),
            "records not admitted: {:?}",
            net.stats.refusals.lock()
        );
        assert!(net.stats.submitted.load(Ordering::Acquire) >= 1);
        for m in &net.machines {
            let state = tenzro_vm::StateAdapter::with_storage(m.storage.clone());
            let account = m.account.as_ref().unwrap().address();
            // The account paid for its key enrolment (nonce 0) and nothing
            // after it: the records pay no fee.
            // One member records each checkpoint, so only some accounts
            // have records; every one has its enrolment.
            assert!(
                state.get_nonce(account.as_bytes()) >= 1,
                "no enrolment executed"
            );
            assert!(
                tenzro_vm::account_keys::enrolled_pq_key(
                    &state,
                    &tenzro_crypto::composite::HybridSigner::public_key(
                        m.account.as_ref().unwrap().as_ref()
                    )
                    .p256
                )
                .is_some(),
                "the account enrolled no ML-DSA-65 key"
            );
        }
        feeder.abort();
        {
            let state = tenzro_vm::StateAdapter::with_storage(net.machines[0].storage.clone());
            assert!(
                net.machines
                    .iter()
                    .any(|m| state.get_nonce(m.account.as_ref().unwrap().address().as_bytes()) > 1),
                "no record executed"
            );
        }
        // Every validator signed rounds the records credited.
        let state = tenzro_vm::StateAdapter::with_storage(net.machines[0].storage.clone());
        for m in &net.machines {
            let account = m.account.as_ref().unwrap().address();
            assert!(
                (0..=epoch).any(|e| {
                    tenzro_vm::native::rewards::read_epoch_votes(&state, e)
                        .unwrap()
                        .participation_bps(&account)
                        .is_some_and(|bps| bps > 0)
                }),
                "no vote work recorded for {account}"
            );
        }
    });
}

/// Every signers record in blocks `0..=tip` of `i`'s chain, in block order,
/// as (epoch, index, anchor round, first height, last height of the
/// checkpoint), and the number of other transactions.
/// Whether `t` executed in the block at `height`: its first inclusion, as
/// the transaction index records it. Validators batch what their pools hold,
/// so a transaction can be ordered in more than one block; a later copy is
/// skipped and is not a second transaction.
fn executed_in(
    storage: &RocksDbStore,
    t: &tenzro_types::transaction::SignedTransaction,
    height: u64,
) -> bool {
    storage
        .get(
            tenzro_storage::CF_TRANSACTIONS,
            format!("idx:{}", t.transaction.hash()).as_bytes(),
        )
        .unwrap()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("block_height").and_then(|h| h.as_u64()))
        == Some(height)
}

/// A signers record in a block: where it executed, who sent it and the
/// certificate it carries.
struct RecordAt {
    height: u64,
    from: Address,
    published: PublishedCertificate,
}

/// The positions in `records` of the records the chain refused as the second
/// of their checkpoint. `records` is every signers record in chain order as
/// (block, epoch, index, sender).
///
/// A member sends a record only when neither the chain's tally nor its own
/// pool holds one for that checkpoint, and the members take turns, so a
/// checkpoint usually has one record. A crossing is left, by design: a member
/// whose turn comes before the first record is ordered, or has reached its
/// pool, sends its own. That happens when ordering is slower than the
/// fallback interval, and when a member was kept from its turn because its
/// own key enrolment had not executed. Each node then holds only its own
/// record, both are ordered, the chain takes the first and refuses the
/// second, and the checkpoint is counted once.
///
/// So at most one crossing per checkpoint is accepted, between two different
/// members; a member that records one checkpoint twice, or a third record of
/// one checkpoint, is an error that names the checkpoint.
fn refused_crossings(records: &[(u64, u64, u64, Address)]) -> Result<Vec<usize>, String> {
    let who = |a: &Address| hex::encode(&a.as_bytes()[..2]);
    let mut first_of: HashMap<(u64, u64), usize> = HashMap::new();
    let mut crossed = std::collections::HashSet::new();
    let mut refused = Vec::new();
    for (pos, (_, epoch, index, from)) in records.iter().enumerate() {
        let Some(&at) = first_of.get(&(*epoch, *index)) else {
            first_of.insert((*epoch, *index), pos);
            continue;
        };
        if !crossed.insert((*epoch, *index)) {
            return Err(format!(
                "checkpoint {epoch}/{index} has more than two records"
            ));
        }
        if records[at].3 == *from {
            return Err(format!(
                "checkpoint {epoch}/{index} recorded twice by {}",
                who(from)
            ));
        }
        refused.push(pos);
    }
    Ok(refused)
}

#[test]
fn a_checkpoint_takes_its_first_record_and_refuses_one_crossing() {
    let (a, b, c) = (
        Address::new([1; 32]),
        Address::new([2; 32]),
        Address::new([3; 32]),
    );
    // A second member's record of the same checkpoint is refused.
    let crossed = [(3, 0, 2, a), (3, 0, 2, b), (4, 1, 3, b)];
    assert_eq!(refused_crossings(&crossed), Ok(vec![1]));
    // In the next block as well, and whichever member's came first.
    let later = [(3, 0, 2, b), (4, 0, 2, a), (4, 0, 3, a)];
    assert_eq!(refused_crossings(&later), Ok(vec![1]));
    // One crossing on each of two checkpoints.
    let both = [(3, 0, 2, a), (3, 0, 2, b), (4, 0, 3, a), (4, 0, 3, b)];
    assert_eq!(refused_crossings(&both), Ok(vec![1, 3]));
    // No repeat.
    let none = [(3, 0, 2, a), (4, 0, 3, a), (5, 1, 1, b)];
    assert_eq!(refused_crossings(&none), Ok(vec![]));
    // One member twice.
    let twice = [(3, 0, 2, a), (4, 0, 2, a)];
    assert!(refused_crossings(&twice).is_err());
    // Three records of one checkpoint.
    let three = [(3, 0, 2, a), (3, 0, 2, b), (3, 0, 2, c)];
    assert!(refused_crossings(&three).is_err());
}

/// The signers records in a validator's blocks.
struct ChainRecords {
    /// The records the chain took, in chain order.
    taken: Vec<RecordAt>,
    /// The records it refused as the second of their checkpoint
    /// ([`refused_crossings`]), in chain order.
    refused: Vec<RecordAt>,
    /// Every other transaction.
    others: usize,
}

/// Reads `i`'s blocks through `tip`. Panics when a checkpoint has a second
/// record that [`refused_crossings`] does not accept.
async fn chain_records(net: &Net, i: usize, tip: u64) -> ChainRecords {
    let store = BlockStoreImpl::new(net.machines[i].storage.clone()).unwrap();
    let mut all = Vec::new();
    let mut others = 0;
    for h in 0..=tip {
        let Some(block) = store.get_block_by_height(BlockHeight(h)).await.unwrap() else {
            continue;
        };
        for t in block
            .transactions
            .iter()
            .filter(|t| executed_in(&net.machines[i].storage, t, h))
        {
            match &t.transaction.tx_type {
                tenzro_types::transaction::TransactionType::RecordCheckpointSigners {
                    certificate,
                } => all.push(RecordAt {
                    height: h,
                    from: t.transaction.from,
                    published: bincode::deserialize(certificate).unwrap(),
                }),
                _ => others += 1,
            }
        }
    }
    let keys: Vec<(u64, u64, u64, Address)> = all
        .iter()
        .map(|r| {
            let cp = &r.published.certificate.checkpoint;
            (r.height, cp.epoch, cp.index, r.from)
        })
        .collect();
    let refused = refused_crossings(&keys).unwrap_or_else(|e| {
        let listed: Vec<String> = keys
            .iter()
            .map(|(h, epoch, index, from)| {
                format!(
                    "block {h}: {epoch}/{index} from {}",
                    hex::encode(&from.as_bytes()[..2])
                )
            })
            .collect();
        panic!("{e}; records on chain: {listed:?}")
    });
    // A crossing needs ordering slower than the fallback interval, so it is
    // the exception: crossings on most checkpoints would be members recording
    // over each other as a rule, which one-per-checkpoint tolerance hides.
    let checkpoints = keys.len() - refused.len();
    assert!(
        checkpoints < 4 || refused.len() * 2 <= checkpoints,
        "{} of {checkpoints} checkpoints were recorded twice",
        refused.len()
    );
    let (mut taken, mut crossings) = (Vec::new(), Vec::new());
    for (at, record) in all.into_iter().enumerate() {
        if refused.contains(&at) {
            crossings.push(record);
        } else {
            taken.push(record);
        }
    }
    ChainRecords {
        taken,
        refused: crossings,
        others,
    }
}

/// The signers records the chain took in `i`'s blocks through `tip` as
/// (epoch, index, anchor round, first height, last height), and the count of
/// every other transaction. A record refused as the second of its checkpoint
/// is left out ([`refused_crossings`]); any other repeat panics.
async fn records_on_chain(
    net: &Net,
    i: usize,
    tip: u64,
) -> (Vec<(u64, u64, u64, u64, u64)>, usize) {
    let chain = chain_records(net, i, tip).await;
    let records = chain
        .taken
        .iter()
        .map(|r| {
            let cp = &r.published.certificate.checkpoint;
            (
                cp.epoch,
                cp.index,
                cp.anchor_round,
                cp.first_height,
                cp.last_height,
            )
        })
        .collect();
    (records, chain.others)
}

/// An idle committee goes quiet. Four validators bonded at genesis; one
/// funded account sends a few transactions and stops. Every checkpoint that
/// certified them is recorded exactly once, by one validator each, in an
/// order the VM accepts (no record is refused as stale, and none as a
/// duplicate but the one crossing [`refused_crossings`] accepts), the
/// records of those checkpoints are not themselves recorded, and once the
/// last of them has landed the height stops advancing.
#[test]
fn an_idle_committee_stops_producing_blocks_and_records_each_checkpoint_once() {
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        use tenzro_crypto::composite::testing::TestHybridSigner;
        const N: usize = 4;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        let sender = TestHybridSigner::hybrid(1);
        // The fallback step is the production one, so the test measures the
        // protocol at its real margin.
        let net = Net::start_recording(
            N,
            0,
            vec![sender.address()],
            time_rules(),
            Accounts::RecordBonded,
            Default::default(),
            tenzro_node::checkpoint_recorder::RANK_STEP,
        )
        .await;
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        const TRANSFERS: u64 = 5;
        for nonce in 0..TRANSFERS {
            // The first is the key enrolment; each waits for the one before.
            let tx = signed_transfer(&sender, nonce, 1);
            for i in 0..N {
                net.node(i).consensus.submit_transaction(tx.clone()).ok();
            }
            net.wait_for(
                "the sender's transaction executes",
                Duration::from_secs(120),
                |_| reader.account_nonce(&sender.address()) > nonce,
            )
            .await;
        }

        // Quiet: the height holds still for a long stretch, a good deal
        // longer than a record takes to land.
        let mut last = (net.height(0), Instant::now());
        net.wait_for("the chain goes quiet", Duration::from_secs(240), |n| {
            let h = n.height(0);
            if h != last.0 {
                last = (h, Instant::now());
            }
            last.1.elapsed() >= Duration::from_secs(20) && (0..N).all(|i| n.height(i) == h)
        })
        .await;
        let tip = net.height(0);
        tokio::time::sleep(Duration::from_secs(10)).await;
        for i in 0..N {
            assert_eq!(
                net.height(i),
                tip,
                "validator {i} still made blocks while idle"
            );
        }

        let (records, others) = records_on_chain(&net, 0, tip).await;
        assert!(
            others >= TRANSFERS as usize,
            "the real transactions are on chain"
        );
        assert!(
            !records.is_empty(),
            "the real transactions' checkpoints were recorded"
        );
        // The VM's rule, replayed: strictly rising index and anchor round
        // within an epoch, or the record is refused.
        let mut seen: HashMap<u64, (u64, u64)> = HashMap::new();
        let mut indices = std::collections::HashSet::new();
        for (epoch, index, anchor, first, last_h) in &records {
            assert!(
                indices.insert((*epoch, *index)),
                "checkpoint {index} recorded twice"
            );
            if let Some((li, nr)) = seen.get(epoch) {
                assert!(
                    index > li && anchor >= nr,
                    "checkpoint {index} of epoch {epoch} would be refused"
                );
            }
            seen.insert(*epoch, (*index, anchor + 1));
            // Only a checkpoint that covers a block with a real transaction.
            assert!(
                first <= last_h,
                "a record of a checkpoint covering no block"
            );
        }
        // No checkpoint was recorded for a block holding only records: every
        // recorded checkpoint covers at least one block that is not a record
        // block.
        let store = BlockStoreImpl::new(net.machines[0].storage.clone()).unwrap();
        for (_, index, _, first, last_h) in &records {
            let mut real = false;
            for h in *first..=*last_h {
                let b = store
                    .get_block_by_height(BlockHeight(h))
                    .await
                    .unwrap()
                    .unwrap();
                real |= b.transactions.iter().any(|t| {
                    !matches!(
                        t.transaction.tx_type,
                        tenzro_types::transaction::TransactionType::RecordCheckpointSigners { .. }
                    )
                });
            }
            assert!(
                real,
                "checkpoint {index} was recorded but certifies only records"
            );
        }
        // Stored size per block (the store keeps a block as JSON), for sizing
        // history retention: record-only blocks against blocks of real work.
        let (mut rec_bytes, mut rec_n, mut real_bytes, mut real_n) =
            (0usize, 0usize, 0usize, 0usize);
        for h in 1..=tip {
            if let Some(b) = store.get_block_by_height(BlockHeight(h)).await.unwrap() {
                let n = serde_json::to_vec(&b).unwrap().len();
                let all_records = b.transactions.iter().all(|t| {
                    matches!(
                        t.transaction.tx_type,
                        tenzro_types::transaction::TransactionType::RecordCheckpointSigners { .. }
                    )
                });
                let only_records = !b.transactions.is_empty() && all_records;
                if only_records {
                    rec_bytes += n;
                    rec_n += 1;
                } else {
                    real_bytes += n;
                    real_n += 1;
                }
            }
        }
        eprintln!(
            "BLOCKSIZE record-only blocks: {rec_n} avg {} B; other blocks: {real_n} avg {} B; \
             tip {tip}; records {}",
            rec_bytes / rec_n.max(1),
            real_bytes / real_n.max(1),
            records.len()
        );
        // The chain holds the real work's tally, the same on every validator.
        let epoch = records.iter().map(|r| r.0).max().unwrap();
        for i in 0..N {
            assert!(
                recorded_votes(&net, i, epoch).1 > 0,
                "validator {i} holds no tally"
            );
        }
        assert!(
            net.stats.refusals.lock().is_empty(),
            "records not admitted: {:?}",
            net.stats.refusals.lock()
        );
        assert!(
            net.stats.skipped_idle.load(Ordering::Relaxed) > 0,
            "idle checkpoints were left unrecorded"
        );
    });
}

/// Every block of `i`'s chain through `tip`, with its epoch, the types of its
/// transactions as (is a signers record, is a transfer), and its height.
async fn block_kinds(net: &Net, i: usize, tip: u64) -> Vec<(u64, u64, Vec<(bool, bool)>)> {
    let store = BlockStoreImpl::new(net.machines[i].storage.clone()).unwrap();
    let mut out = Vec::new();
    for h in 1..=tip {
        let Some(block) = store.get_block_by_height(BlockHeight(h)).await.unwrap() else {
            continue;
        };
        let kinds = block
            .transactions
            .iter()
            .filter(|t| executed_in(&net.machines[i].storage, t, h))
            .map(|t| {
                (
                    tenzro_node::checkpoint_recorder::is_signers_record(&t.transaction.tx_type),
                    matches!(
                        t.transaction.tx_type,
                        tenzro_types::transaction::TransactionType::Transfer { .. }
                    ),
                )
            })
            .collect();
        out.push((h, block.header.epoch, kinds));
    }
    out
}

/// Waits until no validator in `up` has made a block for `quiet`.
async fn wait_quiet(net: &Net, up: &[usize], quiet: Duration, limit: Duration) {
    let mut last = (net.height(up[0]), Instant::now());
    net.wait_for("the chain goes quiet", limit, |n| {
        let h = n.height(up[0]);
        if h != last.0 {
            last = (h, Instant::now());
        }
        last.1.elapsed() >= quiet && up.iter().all(|i| n.height(*i) == h)
    })
    .await;
}

/// The accounts a record's certificate credits, with the epoch and index.
fn credited(net: &Net, records: &[(u64, u64, Vec<u16>)]) -> Vec<(u64, u64, Vec<Address>)> {
    records
        .iter()
        .map(|(epoch, index, signers)| {
            let committee = net.node(0).consensus.committee(*epoch).expect("committee");
            let accounts = signers
                .iter()
                .map(|s| committee.member(*s).expect("member").address)
                .collect();
            (*epoch, *index, accounts)
        })
        .collect()
}

/// The signers records the chain took in `i`'s blocks through `tip` as
/// (epoch, index, signer positions its certificate names). A record refused
/// as the second of its checkpoint is left out ([`refused_crossings`]), so
/// its signers are not counted twice.
async fn recorded_signers(net: &Net, i: usize, tip: u64) -> Vec<(u64, u64, Vec<u16>)> {
    chain_records(net, i, tip)
        .await
        .taken
        .iter()
        .map(|r| {
            (
                r.published.certificate.checkpoint.epoch,
                r.published.certificate.checkpoint.index,
                r.published.certificate.signers.to_vec(),
            )
        })
        .collect()
}

/// Four validators and no traffic from anyone: the only transactions are the
/// validators' own key enrolments. Their records are held and leave in a
/// block of their own: at the flush point of the epoch, or at once when the
/// enrolments were certified after it or too late for their own epoch. A
/// block of records is not work, so its checkpoint is not recorded, nothing
/// follows it and the chain is quiet for good: there are never more blocks
/// of records than blocks of work. None is dropped as stale, and the records
/// the chain takes reach it in checkpoint order, each once. One record can
/// be refused: a validator whose enrolment landed a block after the others'
/// sends its record the moment it can, which can be the moment the next
/// validator's turn comes, and the chain takes the first of the two
/// ([`refused_crossings`]).
#[test]
fn a_net_with_no_traffic_makes_no_blocks_after_one_flush_block() {
    network_test(async {
        const N: usize = 4;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        let net = Net::start_recording(
            N,
            0,
            Vec::new(),
            time_rules(),
            Accounts::RecordBonded,
            Default::default(),
            Duration::from_secs(2),
        )
        .await;
        let up: Vec<usize> = (0..N).collect();
        // Past the first two epochs, so the enrolments and the flush for
        // them have been and gone, then quiet for two and a half epochs.
        net.wait_for("two epochs certify", Duration::from_secs(120), |n| {
            (0..N).all(|i| n.certified(i).0 >= 2)
        })
        .await;
        wait_quiet(&net, &up, Duration::from_secs(25), Duration::from_secs(240)).await;
        let tip = net.height(0);
        assert!(tip >= 1, "the validators' enrolments made blocks");
        // What each block held and who sent it, so a failure below says
        // which records made a block of their own.
        let block_store = BlockStoreImpl::new(net.machines[0].storage.clone()).unwrap();
        let mut layout = Vec::new();
        let mut work_blocks = 0usize;
        let mut record_blocks = 0usize;
        for h in 1..=tip {
            let Some(b) = block_store
                .get_block_by_height(BlockHeight(h))
                .await
                .unwrap()
            else {
                continue;
            };
            if tenzro_node::checkpoint_recorder::covers_real_work(
                b.transactions.iter().map(|t| &t.transaction.tx_type),
            ) {
                work_blocks += 1;
            }
            let records: Vec<(u64, u64)> = b
                .transactions
                .iter()
                .filter_map(|t| {
                    tenzro_node::checkpoint_recorder::pooled_record_of(&t.transaction.tx_type)
                })
                .collect();
            if !records.is_empty() && records.len() == b.transactions.len() {
                record_blocks += 1;
            }
            let held: Vec<String> = b
                .transactions
                .iter()
                .map(|t| {
                    let from = hex::encode(&t.transaction.from.as_bytes()[..2]);
                    match tenzro_node::checkpoint_recorder::pooled_record_of(&t.transaction.tx_type)
                    {
                        Some((e, i)) => format!("record {e}/{i} from {from}"),
                        None => format!("other from {from}"),
                    }
                })
                .collect();
            layout.push(format!(
                "block {h} epoch {} round {}: {held:?}",
                b.header.epoch, b.header.round
            ));
        }
        let layout = layout.join("; ");
        eprintln!(
            "tip {tip}; {record_blocks} blocks of records for {work_blocks} blocks of work; \
             layout: {layout}; held {} flushed {} submitted {} suppressed {} idle {}",
            net.stats.held.load(Ordering::Relaxed),
            net.stats.flushed.load(Ordering::Relaxed),
            net.stats.submitted.load(Ordering::Relaxed),
            net.stats.suppressed_duplicate.load(Ordering::Relaxed),
            net.stats.skipped_idle.load(Ordering::Relaxed),
        );
        // A block of records is not work to record. Each record covers at
        // least one block of work no other record covers, so however the
        // enrolments fell in their epochs there are no more blocks of
        // records than blocks of work, and a record never causes another.
        // A record refused as the second of its checkpoint can add one block.
        let chain = chain_records(&net, 0, tip).await;
        let on_chain: Vec<(u64, u64)> = chain
            .taken
            .iter()
            .map(|r| {
                let cp = &r.published.certificate.checkpoint;
                (cp.epoch, cp.index)
            })
            .collect();
        assert!(
            !on_chain.is_empty(),
            "no record reached the chain: {layout}"
        );
        assert!(
            record_blocks <= work_blocks + chain.refused.len(),
            "{record_blocks} blocks of records for {work_blocks} blocks of work: {layout}"
        );
        // The records the chain took reach it in checkpoint order.
        assert!(
            on_chain.windows(2).all(|w| w[0] < w[1]),
            "records out of checkpoint order: {layout}"
        );
        assert!(
            net.stats.refusals.lock().is_empty(),
            "records not admitted: {:?}",
            net.stats.refusals.lock()
        );
        assert_eq!(net.stats.dropped_stale.load(Ordering::Relaxed), 0);
        assert_eq!(net.stats.dropped_overflow.load(Ordering::Relaxed), 0);
        assert!(
            net.stats.held.load(Ordering::Relaxed) >= 1,
            "nothing was held"
        );
        // Every record on chain is the first of its checkpoint.
        let records = recorded_signers(&net, 0, tip).await;
        let mut seen = std::collections::HashSet::new();
        for (epoch, index, _) in &records {
            assert!(
                seen.insert((*epoch, *index)),
                "checkpoint {index} recorded twice"
            );
        }
    });
}

/// A beacon contribution signed by `signer` with `nonce` for `round`. The
/// proof is not a valid VRF output, so the contribution is refused when it
/// executes; it is ordered and fills a block all the same, as a validator's
/// beacon round does.
fn signed_beacon(
    signer: &tenzro_crypto::composite::testing::TestHybridSigner,
    nonce: u64,
    round: u64,
) -> tenzro_types::transaction::SignedTransaction {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    use tenzro_types::primitives::{ChainId, Nonce};
    use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
    let tx = Transaction::new(
        ChainId::from(CHAIN_ID),
        signer.address(),
        Address::new([0xee; 32]),
        Nonce::from(nonce),
        TransactionType::BeaconContribute {
            round,
            proof: vec![0x5a; 80],
        },
        tenzro_vm::native::beacon::GAS_BEACON_CONTRIBUTE,
        10_000_000_000,
    );
    let sig = signer
        .sign(SignatureContext::Transaction, tx.hash().as_bytes())
        .unwrap();
    SignedTransaction::new(tx, signer.public_key().p256.clone(), sig)
}

/// A net whose only activity is beacon contributions records nothing: a
/// checkpoint covering only beacon contributions is upkeep, not work, so no
/// signers record is sent for it and no block is made for one. The blocks
/// after the quiet point are the contributions' own and nothing else.
#[test]
fn beacon_contributions_alone_make_no_records_and_no_record_blocks() {
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        use tenzro_crypto::composite::testing::TestHybridSigner;
        const N: usize = 4;
        const CONTRIBUTIONS: u64 = 12;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        let contributor = TestHybridSigner::hybrid(1);
        let net = Net::start_recording(
            N,
            0,
            vec![contributor.address()],
            time_rules(),
            Accounts::RecordBonded,
            Default::default(),
            Duration::from_secs(2),
        )
        .await;
        let up: Vec<usize> = (0..N).collect();
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for("two epochs certify", Duration::from_secs(120), |n| {
            (0..N).all(|i| n.certified(i).0 >= 2)
        })
        .await;
        wait_quiet(&net, &up, Duration::from_secs(25), Duration::from_secs(240)).await;
        // The contributor's key enrolment is real work and is recorded; the
        // chain goes quiet again after it.
        let enrolment = signed_transfer(&contributor, 0, 1);
        for i in 0..N {
            net.node(i)
                .consensus
                .submit_transaction(enrolment.clone())
                .ok();
        }
        net.wait_for("the enrolment executes", Duration::from_secs(120), |_| {
            reader.account_nonce(&contributor.address()) > 0
        })
        .await;
        wait_quiet(&net, &up, Duration::from_secs(25), Duration::from_secs(240)).await;
        let base = net.height(0);
        let submitted = net.stats.submitted.load(Ordering::Acquire);

        // Contributions only, spread over more than two epochs.
        for k in 0..CONTRIBUTIONS {
            let tx = signed_beacon(&contributor, k + 1, k);
            for i in 0..N {
                net.node(i).consensus.submit_transaction(tx.clone()).ok();
            }
            net.wait_for(
                "the contribution is ordered",
                Duration::from_secs(120),
                |_| reader.account_nonce(&contributor.address()) > k + 1,
            )
            .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        wait_quiet(&net, &up, Duration::from_secs(25), Duration::from_secs(240)).await;
        let tip = net.height(0);
        assert!(tip > base, "the contributions made blocks");

        let blocks = block_kinds(&net, 0, tip).await;
        let store = BlockStoreImpl::new(net.machines[0].storage.clone()).unwrap();
        let mut contributions = 0u64;
        for (h, epoch, kinds) in blocks.iter().filter(|(h, ..)| *h > base) {
            assert!(
                kinds.iter().all(|(record, _)| !*record),
                "block {h} of epoch {epoch} holds a signers record"
            );
            let b = store
                .get_block_by_height(BlockHeight(*h))
                .await
                .unwrap()
                .unwrap();
            let is_beacon = |t: &&tenzro_types::transaction::SignedTransaction| {
                matches!(
                    t.transaction.tx_type,
                    tenzro_types::transaction::TransactionType::BeaconContribute { .. }
                )
            };
            assert!(
                b.transactions.iter().any(|t| is_beacon(&t)),
                "block {h} of epoch {epoch} holds no beacon contribution"
            );
            let beacon = b
                .transactions
                .iter()
                .filter(is_beacon)
                .filter(|t| executed_in(&net.machines[0].storage, t, *h))
                .count() as u64;
            contributions += beacon;
        }
        eprintln!("blocks {base}..={tip}: {contributions} contributions");
        assert_eq!(contributions, CONTRIBUTIONS);
        assert_eq!(
            net.stats.submitted.load(Ordering::Acquire),
            submitted,
            "a signers record was sent for a beacon-only checkpoint"
        );
        assert!(net.stats.refusals.lock().is_empty());
    });
}

/// One real transaction on an otherwise quiet net: the checkpoint that
/// certifies it is recorded exactly once, in a block of its own epoch, by one
/// member, and every validator its certificate names is credited in the
/// epoch's tally.
#[test]
fn one_real_transaction_is_recorded_once_and_credits_its_signers() {
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        use tenzro_crypto::composite::testing::TestHybridSigner;
        const N: usize = 4;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        let sender = TestHybridSigner::hybrid(1);
        let net = Net::start_recording(
            N,
            0,
            vec![sender.address()],
            time_rules(),
            Accounts::RecordBonded,
            Default::default(),
            Duration::from_secs(2),
        )
        .await;
        let up: Vec<usize> = (0..N).collect();
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        // The validators' enrolments settle first, so the one transfer is
        // alone in its block.
        net.wait_for("two epochs certify", Duration::from_secs(120), |n| {
            (0..N).all(|i| n.certified(i).0 >= 2)
        })
        .await;
        wait_quiet(&net, &up, Duration::from_secs(25), Duration::from_secs(240)).await;
        // What each validator account holds and has bonded once its
        // enrolment settled: a record it sends, taken or refused, costs it
        // neither.
        let held = |net: &Net| -> Vec<(Address, u128, u128)> {
            use tenzro_vm::traits::VmState as _;
            let state = tenzro_vm::StateAdapter::with_storage(net.machines[0].storage.clone());
            net.machines
                .iter()
                .map(|m| {
                    let a = m.account.as_ref().unwrap().address();
                    (
                        a,
                        state.get_balance(a.as_bytes()),
                        tenzro_vm::native::bonded_stake_of(&state, a.as_bytes()),
                    )
                })
                .collect()
        };
        let before = held(&net);
        // The sender's enrolment, then one transfer.
        for nonce in 0..2 {
            let tx = signed_transfer(&sender, nonce, 1);
            for i in 0..N {
                net.node(i).consensus.submit_transaction(tx.clone()).ok();
            }
            net.wait_for(
                "the sender's transaction executes",
                Duration::from_secs(120),
                |_| reader.account_nonce(&sender.address()) > nonce,
            )
            .await;
        }
        wait_quiet(&net, &up, Duration::from_secs(25), Duration::from_secs(240)).await;
        let tip = net.height(0);

        let blocks = block_kinds(&net, 0, tip).await;
        let (height, transfer_epoch, _) = blocks
            .iter()
            .find(|(_, _, kinds)| kinds.iter().any(|(_, transfer)| *transfer))
            .expect("the transfer is on chain")
            .clone();
        let store = BlockStoreImpl::new(net.machines[0].storage.clone()).unwrap();
        let (records, _) = records_on_chain(&net, 0, tip).await;
        let covering: Vec<_> = records
            .iter()
            .filter(|(_, _, _, first, last)| *first <= height && height <= *last)
            .collect();
        assert_eq!(
            covering.len(),
            1,
            "the transfer's checkpoint is recorded once: {covering:?}"
        );
        let (record_epoch, record_index, ..) = *covering[0];
        assert_eq!(
            record_epoch, transfer_epoch,
            "recorded in the epoch it was certified in"
        );
        let mut seen = std::collections::HashSet::new();
        for (epoch, index, ..) in &records {
            assert!(
                seen.insert((*epoch, *index)),
                "checkpoint {index} recorded twice"
            );
        }
        // The transfer's record, of work certified mid-epoch, landed in a
        // block of its own epoch. Every other record landed in its own epoch
        // or, for work certified as its epoch ended, the next one, as a
        // block admits; none later.
        for h in 1..=tip {
            let b = store
                .get_block_by_height(BlockHeight(h))
                .await
                .unwrap()
                .unwrap();
            for t in b
                .transactions
                .iter()
                .filter(|t| executed_in(&net.machines[0].storage, t, h))
            {
                if let tenzro_types::transaction::TransactionType::RecordCheckpointSigners {
                    certificate,
                } = &t.transaction.tx_type
                {
                    let p: PublishedCertificate = bincode::deserialize(certificate).unwrap();
                    let cp = &p.certificate.checkpoint;
                    if (cp.epoch, cp.index) == (record_epoch, record_index) {
                        assert_eq!(
                            cp.epoch, b.header.epoch,
                            "the transfer's record reached a block of another epoch"
                        );
                    } else {
                        assert!(
                            b.header.epoch == cp.epoch || b.header.epoch == cp.epoch + 1,
                            "checkpoint {} of epoch {} reached a block of epoch {}",
                            cp.index,
                            cp.epoch,
                            b.header.epoch
                        );
                    }
                }
            }
        }
        // Every signer the recorded certificate names is credited.
        let signed = recorded_signers(&net, 0, tip).await;
        let named = credited(&net, &signed);
        let state = tenzro_vm::StateAdapter::with_storage(net.machines[1].storage.clone());
        let votes = tenzro_vm::native::rewards::read_epoch_votes(&state, record_epoch).unwrap();
        let (_, _, accounts) = named
            .iter()
            .find(|(e, i, _)| (*e, *i) == (record_epoch, record_index))
            .expect("the record is on chain");
        assert!(accounts.len() >= 3, "a quorum signed: {}", accounts.len());
        for account in accounts {
            assert!(
                votes.participation_bps(account).is_some_and(|bps| bps > 0),
                "signer {account} is not credited for epoch {record_epoch}: {votes:?}"
            );
        }
        // A record refused as the second of its checkpoint, sent by a member
        // whose turn came before the first was ordered, costs its sender
        // nothing: records pay no fee, and no stake is taken for it.
        let refused = chain_records(&net, 0, tip).await.refused;
        if !refused.is_empty() {
            eprintln!(
                "{} records were refused as the second of their checkpoint",
                refused.len()
            );
        }
        // Nothing in this window credits a member: the transfer pays an
        // account outside the committee and rewards are claimed, never
        // credited. So every member's balance and bond are unchanged, whether
        // its records were taken or refused, and no credit can offset a charge.
        let after = held(&net);
        assert_eq!(
            after,
            before,
            "a record cost a member balance or stake ({} refused as crossings)",
            refused.len()
        );
        assert!(net.stats.refusals.lock().is_empty());
        assert_eq!(net.stats.dropped_stale.load(Ordering::Relaxed), 0);
    });
}

/// A validator that was down when a real transaction was certified is not
/// credited for it, and the three that signed are, whichever of the four
/// held the epoch's first turn to record.
#[test]
fn a_validator_that_was_down_is_not_credited_and_the_others_are() {
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        use tenzro_crypto::composite::testing::TestHybridSigner;
        const N: usize = 4;
        const DOWN: usize = 3;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        let sender = TestHybridSigner::hybrid(1);
        let rules = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 40,
            handover_confirmations: 2,
            idle_round_interval_ms: 1_000,
            ..TimeRules::default()
        };
        let mut net = Net::start_recording(
            N,
            0,
            vec![sender.address()],
            rules,
            Accounts::RecordBonded,
            Default::default(),
            Duration::from_secs(2),
        )
        .await;
        let up: Vec<usize> = (0..N).filter(|i| *i != DOWN).collect();
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for("an epoch certifies", Duration::from_secs(120), |n| {
            (0..N).all(|i| n.certified(i).0 >= 1)
        })
        .await;
        net.down(DOWN).await;
        let (down_epoch, _) = net.certified(0);
        // The transfer is sent in an epoch the validator missed whole.
        net.wait_for("the epoch passes", Duration::from_secs(180), |n| {
            up.iter().all(|i| n.certified(*i).0 > down_epoch)
        })
        .await;
        for nonce in 0..2 {
            let tx = signed_transfer(&sender, nonce, 1);
            for i in &up {
                net.node(*i).consensus.submit_transaction(tx.clone()).ok();
            }
            net.wait_for(
                "the sender's transaction executes",
                Duration::from_secs(120),
                |_| reader.account_nonce(&sender.address()) > nonce,
            )
            .await;
        }
        wait_quiet(&net, &up, Duration::from_secs(45), Duration::from_secs(300)).await;
        let tip = net.height(0);
        let blocks = block_kinds(&net, 0, tip).await;
        let (_, transfer_epoch, _) = blocks
            .iter()
            .find(|(_, _, kinds)| kinds.iter().any(|(_, transfer)| *transfer))
            .expect("the transfer is on chain")
            .clone();
        assert!(transfer_epoch > down_epoch);
        let signed = recorded_signers(&net, 0, tip).await;
        let named = credited(&net, &signed);
        let down_account = net.machines[DOWN].account.as_ref().unwrap().address();
        let state = tenzro_vm::StateAdapter::with_storage(net.machines[0].storage.clone());
        let votes = tenzro_vm::native::rewards::read_epoch_votes(&state, transfer_epoch).unwrap();
        assert!(
            votes.certified_rounds > 0,
            "the epoch's work was recorded: {votes:?}"
        );
        assert!(
            named
                .iter()
                .filter(|(e, ..)| *e == transfer_epoch)
                .all(|(_, _, accounts)| !accounts.contains(&down_account)),
            "a certificate names the validator that was down"
        );
        assert_eq!(
            votes.participation_bps(&down_account),
            Some(0),
            "the validator that was down is credited: {votes:?}"
        );
        for i in &up {
            let account = net.machines[*i].account.as_ref().unwrap().address();
            assert!(
                votes.participation_bps(&account).is_some_and(|bps| bps > 0),
                "validator {i} is not credited: {votes:?}"
            );
        }
        assert_eq!(net.stats.dropped_stale.load(Ordering::Relaxed), 0);
    });
}

/// Validators with nothing to spend and no bond: every record of theirs is
/// refused when it executes. Blocks and checkpoints go on all the same,
/// across epochs, and a funded sender's transfers execute: no validator
/// transaction, paid for or refused, holds up consensus.
#[test]
fn refused_validator_records_never_hold_up_the_chain() {
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        use tenzro_crypto::composite::testing::TestHybridSigner;
        use tenzro_vm::traits::VmState as _;
        const N: usize = 4;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        let sender = TestHybridSigner::hybrid(1);
        let net = Net::start_full(
            N,
            vec![sender.address()],
            time_rules(),
            Accounts::RecordUnbonded,
        )
        .await;
        // Each validator account pays for the enrolment of its ML-DSA-65 key
        // first; its records, refused all the same, cost nothing after it.
        let validator_reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for(
            "every validator account has enrolled its key",
            Duration::from_secs(180),
            |n| {
                n.machines.iter().all(|m| {
                    validator_reader.account_nonce(&m.account.as_ref().unwrap().address()) > 0
                })
            },
        )
        .await;
        let after_enrolment: Vec<u128> = {
            let state = tenzro_vm::StateAdapter::with_storage(net.machines[0].storage.clone());
            net.machines
                .iter()
                .map(|m| state.get_balance(m.account.as_ref().unwrap().address().as_bytes()))
                .collect()
        };
        net.wait_for(
            "the network certifies an epoch",
            Duration::from_secs(180),
            |n| (0..N).all(|i| n.certified(i).0 >= 1),
        )
        .await;

        const TRANSFERS: u64 = 20;
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        // The sender's first transaction enrols its ML-DSA-65 key; its
        // transfers follow once that has executed.
        let enrol = signed_transfer(&sender, 0, 0);
        for i in 0..N {
            net.node(i).consensus.submit_transaction(enrol.clone()).ok();
        }
        net.wait_for(
            "the sender's key is enrolled",
            Duration::from_secs(120),
            |_| reader.account_nonce(&sender.address()) > 0,
        )
        .await;
        for nonce in 1..TRANSFERS {
            let tx = signed_transfer(&sender, nonce, 1);
            let mut ok = false;
            for i in 0..N {
                ok |= net.node(i).consensus.submit_transaction(tx.clone()).is_ok();
            }
            assert!(ok, "transfer {nonce} admitted nowhere");
        }
        let (start_epoch, _) = net.certified(0);
        net.wait_for(
            "the transfers execute and two more epochs are certified",
            Duration::from_secs(180),
            |n| {
                reader.account_nonce(&sender.address()) == TRANSFERS
                    && (0..N).all(|i| n.certified(i).0 >= start_epoch + 2)
            },
        )
        .await;

        // The validators' records were made, refused, spent their nonces and
        // charged nothing; none was credited.
        assert!(net.stats.submitted.load(Ordering::Acquire) > 0);
        let state = tenzro_vm::StateAdapter::with_storage(net.machines[0].storage.clone());
        assert!(
            net.machines
                .iter()
                .any(|m| { state.get_nonce(m.account.as_ref().unwrap().address().as_bytes()) > 0 }),
            "no record executed"
        );
        let (epoch, _) = net.certified(0);
        assert_eq!(recorded_votes(&net, 0, epoch).0, 0);
        for (m, before) in net.machines.iter().zip(&after_enrolment) {
            let account = m.account.as_ref().unwrap().address();
            assert_eq!(
                state.get_balance(account.as_bytes()),
                *before,
                "a refused record was charged"
            );
        }
    });
}

/// The recovery drill of docs/RECOVERY-BELOW-QUORUM.md on one process: two
/// of four validators are gone for good, the two survivors and two new
/// machines (which follow the chain to the anchor) apply a recovery manifest
/// and the chain certifies again under the successor set, with the history
/// up to the anchor unchanged.
#[test]
fn a_chain_halted_below_quorum_resumes_under_a_recovery_manifest() {
    use tenzro_consensus::recovery_manifest::{RecoveryManifest, SuccessorMember};

    network_test(async {
        // An idle network orders no block, so one funded account feeds it
        // a transfer whenever its last one has executed.
        let feeder_account = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(1);
        let mut net = Net::start_configured(
            4,
            2,
            vec![feeder_account.address()],
            time_rules(),
            Accounts::Silent,
            Default::default(),
        )
        .await;
        let feeder = feed_transfers(
            (0..4).map(|i| net.node(i).consensus.clone()).collect(),
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for("blocks and checkpoints", Duration::from_secs(60), |n| {
            (0..4).all(|i| n.height(i) >= 3 && n.certified(i).1 >= 2)
        })
        .await;
        feeder.abort();
        // What the feeder sent last is ordered and executed, and a
        // checkpoint covers it, before the two validators go.
        let covered = |n: &Net| {
            (0..4).all(|i| {
                n.node(i)
                    .consensus
                    .latest_certificate()
                    .is_some_and(|c| c.checkpoint.last_height == n.height(i))
            })
        };
        tokio::time::sleep(Duration::from_secs(3)).await;
        net.wait_for(
            "a checkpoint covers every block",
            Duration::from_secs(60),
            covered,
        )
        .await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        net.wait_for(
            "the checkpoints still cover every block",
            Duration::from_secs(60),
            covered,
        )
        .await;

        // Two validators are lost for good. Nothing more is certified.
        net.down(2).await;
        net.down(3).await;
        tokio::time::sleep(Duration::from_secs(6)).await;

        // The anchor: the last block of the highest checkpoint both
        // survivors hold, which both have executed.
        let cert = net
            .node(0)
            .consensus
            .latest_certificate()
            .expect("a certificate");
        let anchor = cert.checkpoint.last_height;
        for i in 0..2 {
            assert_eq!(
                net.node(i)
                    .consensus
                    .latest_certificate()
                    .map(|c| c.checkpoint.index),
                Some(cert.checkpoint.index)
            );
            assert_eq!(
                net.height(i),
                anchor,
                "survivor {i} executed past the last checkpoint"
            );
        }

        // The new machines follow the survivors to the anchor, started with
        // the survivors named as the state-sync source, as an operator does.
        net.sync_from = vec![0, 1];
        net.up(4).await;
        net.up(5).await;
        net.wait_for(
            "the new machines reach the anchor",
            Duration::from_secs(60),
            |n| n.height(4) == anchor && n.height(5) == anchor,
        )
        .await;
        let hash_at = |net: &Net, i: usize, h: u64| {
            let store = BlockStoreImpl::new(net.machines[i].storage.clone()).unwrap();
            futures::executor::block_on(store.get_block_by_height(BlockHeight::from(h)))
                .unwrap()
                .expect("block")
                .hash()
                .0
        };
        let anchor_hash = hash_at(&net, 0, anchor);
        assert_eq!(anchor_hash, hash_at(&net, 4, anchor));
        let history: Vec<[u8; 32]> = (0..=anchor).map(|h| hash_at(&net, 0, h)).collect();

        let members = [0usize, 1, 4, 5];
        let manifest = RecoveryManifest {
            chain_id: CHAIN_ID,
            anchor_height: anchor,
            anchor_hash,
            anchor_checkpoint_index: cert.checkpoint.index,
            anchor_checkpoint_digest: cert.checkpoint.digest(),
            from_epoch: cert.checkpoint.epoch,
            to_epoch: cert.checkpoint.epoch + 1,
            successor: members
                .iter()
                .map(|&i| {
                    let v = &net.validators[i];
                    SuccessorMember {
                        name: format!("v{i}"),
                        address: v.address,
                        stake: v.stake,
                        ml_dsa_public_key: v.public_key.ml_dsa.clone(),
                        p256_public_key: v.public_key.p256.clone(),
                        node_key: v.node_key,
                        live: true,
                    }
                })
                .collect(),
        };
        for i in 0..6 {
            if net.running[i].is_some() {
                net.down(i).await;
            }
        }

        let request = |m: &RecoveryManifest| tenzro_node::recovery::RecoveryRequest {
            manifest: m.clone(),
            digest: m.digest(),
            checkpoint: Some((m.anchor_height, m.anchor_hash)),
            confirm_root: None,
            check_only: false,
        };
        let refused = |r: tenzro_node::error::Result<()>, why: &str| {
            let e = r.expect_err(why).to_string();
            assert!(e.contains("recovery manifest refused"), "{why}: {e}");
        };

        // A digest other than the file's: refused.
        let mut bad = request(&manifest);
        bad.digest[0] ^= 1;
        net.recovery.insert(0, bad);
        refused(net.try_up(0).await, "a wrong digest");

        // A file changed after the digest was compared: refused.
        let mut tampered = manifest.clone();
        tampered.successor[3].stake += 1;
        let mut bad = request(&manifest);
        bad.manifest = tampered;
        net.recovery.insert(0, bad);
        refused(net.try_up(0).await, "a changed manifest");

        // The command-line checkpoint is not the anchor: refused.
        let mut bad = request(&manifest);
        bad.checkpoint = Some((anchor, [7; 32]));
        net.recovery.insert(0, bad);
        refused(net.try_up(0).await, "another checkpoint");

        // A manifest below the chain's last finalized block: refused.
        let mut below = manifest.clone();
        below.anchor_height = anchor - 1;
        net.recovery.insert(0, request(&below));
        refused(net.try_up(0).await, "an anchor below the tip");

        // A successor set that cannot certify: refused.
        let mut small = manifest.clone();
        small.successor.truncate(3);
        net.recovery.insert(0, request(&small));
        refused(net.try_up(0).await, "three validators");

        // Nothing was applied by the refusals.
        assert_eq!(
            net.machines[0]
                .storage
                .get(tenzro_storage::CF_METADATA, b"recovery/start")
                .unwrap(),
            None
        );

        // The members compare roots before applying.
        let mut roots = Vec::new();
        for &i in &members {
            let mut check = request(&manifest);
            check.check_only = true;
            net.recovery.insert(i, check);
            match net.try_up(i).await {
                Err(tenzro_node::error::NodeError::RecoveryChecked(root)) => roots.push(root),
                other => panic!("member {i}: {other:?}"),
            }
        }
        assert!(
            roots.windows(2).all(|w| w[0] == w[1]),
            "members print one root"
        );

        // A member given another root does not start.
        let mut wrong = request(&manifest);
        wrong.confirm_root = Some([5; 32]);
        net.recovery.insert(0, wrong);
        refused(net.try_up(0).await, "another root");

        // Apply and start the successor set.
        for &i in &members {
            let mut apply = request(&manifest);
            apply.confirm_root = Some(roots[0]);
            net.recovery.insert(i, apply);
            net.up(i).await;
        }
        let feeder = feed_transfers(
            members
                .iter()
                .map(|&i| net.node(i).consensus.clone())
                .collect(),
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for(
            "the successor set certifies",
            Duration::from_secs(90),
            |n| {
                members
                    .iter()
                    .all(|&i| n.height(i) >= anchor + 3 && n.certified(i).0 >= manifest.to_epoch)
            },
        )
        .await;
        for h in 0..=anchor {
            assert_eq!(
                hash_at(&net, 0, h),
                history[h as usize],
                "history changed at {h}"
            );
        }

        // A restart with the flag still set does nothing and the chain goes on.
        let before = net.height(0);
        net.down(0).await;
        net.up(0).await;
        net.wait_for(
            "a member restarted with the flag",
            Duration::from_secs(60),
            |n| n.height(0) > before + 2,
        )
        .await;
        feeder.abort();
    });
}

/// Measures how long a transaction takes to execute after it is submitted at
/// one validator, for senders the committee assigns to each of its members
/// (`assigned_validator`): the figures the release notes quote. Not an
/// assertion; run with `--ignored --nocapture`.
#[test]
#[ignore = "a measurement, not a check"]
fn measure_inclusion_latency_by_assigned_validator() {
    measure_inclusion(true);
}

/// As above, but the transaction reaches only the validator it is submitted at
/// (its gossip to the others is lost): the validators the sender is assigned
/// to never see it, and it is batched by the validator that holds it once
/// the sender's failover grace has passed.
#[test]
#[ignore = "a measurement, not a check"]
fn measure_inclusion_latency_when_the_assigned_validator_never_hears() {
    measure_inclusion(false);
}

fn measure_inclusion(gossip_to_peers: bool) {
    network_test(async {
        use tenzro_crypto::composite::HybridSigner;
        const N: usize = 3;
        const SENDERS: usize = 9;
        const ROUNDS: usize = 8;
        let accounts: Vec<_> = (0..SENDERS)
            .map(|i| {
                Arc::new(tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
                    0x50 + i as u8,
                ))
            })
            .collect();
        let net = Net::start_with(
            N,
            accounts.iter().map(|a| a.address()).collect(),
            time_rules(),
        )
        .await;
        net.wait_for(
            "the network certifies an epoch",
            Duration::from_secs(180),
            |n| (0..N).all(|i| n.certified(i).0 >= 1),
        )
        .await;
        let storage: Arc<dyn KvStore> = net.machines[0].storage.clone();
        let gossip: tenzro_node::payment_rails::GossipSlot = Arc::default();
        if gossip_to_peers {
            *gossip.lock() = Some(net.node(0).events.clone());
        }
        let submitters: Vec<_> = accounts
            .iter()
            .map(|a| {
                tenzro_node::payment_rails::LedgerSubmitter::new(
                    net.node(0).consensus.clone(),
                    a.clone() as Arc<dyn HybridSigner>,
                    Address::new(a.public_key().account_slot()),
                    storage.clone(),
                    CHAIN_ID,
                    Arc::default(),
                    gossip.clone(),
                )
            })
            .collect();
        let to = Address::new([0xee; 32]);
        let transfer = || tenzro_types::transaction::TransactionType::Transfer { amount: 1 };
        // Enrol every key first: the first submissions are told to retry.
        for sub in &submitters {
            let deadline = Instant::now() + Duration::from_secs(240);
            loop {
                match sub.submit(to, transfer()).await {
                    Ok(h) => {
                        while sub.receipt(&h).is_none() {
                            assert!(Instant::now() < deadline, "enrolment never executed");
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                        break;
                    }
                    Err(e) if e == tenzro_node::payment_rails::PQ_ENROLMENT_PENDING => {
                        assert!(Instant::now() < deadline, "the key was never enrolled");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => panic!("submission failed: {e}"),
                }
            }
        }
        let mut by_assigned: Vec<Vec<u128>> = vec![Vec::new(); N];
        for round in 0..ROUNDS {
            let started = Instant::now();
            let mut hashes = Vec::new();
            for (i, sub) in submitters.iter().enumerate() {
                let h = sub.submit(to, transfer()).await.expect("admitted");
                let assigned = tenzro_consensus::batch::assigned_validator(
                    &Address::new(accounts[i].public_key().account_slot()),
                    N as u64,
                ) as usize;
                hashes.push((h, assigned, Instant::now()));
            }
            let mut pending: Vec<_> = hashes.into_iter().collect();
            while !pending.is_empty() {
                assert!(
                    started.elapsed() < Duration::from_secs(120),
                    "a transaction was not included in 120 s"
                );
                pending.retain(|(h, assigned, at)| {
                    let done = submitters[0].receipt(h).is_some();
                    if done {
                        by_assigned[*assigned].push(at.elapsed().as_millis());
                    }
                    !done
                });
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            eprintln!("round {round} done in {:?}", started.elapsed());
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let mut all: Vec<u128> = by_assigned.iter().flatten().copied().collect();
        all.sort_unstable();
        let q = |v: &Vec<u128>, p: f64| {
            v.get(((v.len().saturating_sub(1)) as f64 * p).round() as usize)
                .copied()
                .unwrap_or(0)
        };
        eprintln!(
            "INCLUSION n={} p10={} p50={} p90={} max={} (ms)",
            all.len(),
            q(&all, 0.1),
            q(&all, 0.5),
            q(&all, 0.9),
            q(&all, 1.0)
        );
        for (v, l) in by_assigned.iter().enumerate() {
            let mut l = l.clone();
            l.sort_unstable();
            eprintln!(
                "INCLUSION assigned={v} (submitted at validator 0) n={} p50={} p90={} max={} (ms)",
                l.len(),
                q(&l, 0.5),
                q(&l, 0.9),
                q(&l, 1.0)
            );
        }
    });
}

/// A node that is not a validator signs its settlements from an account
/// whose ML-DSA-65 key is not enrolled: the ledger submitter enrols it first,
/// once however many submissions arrive meanwhile, tells each of those to
/// retry, and then the settlement transaction executes.
#[test]
fn a_non_validator_node_account_enrols_its_key_and_then_its_settlement_executes() {
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        use tenzro_crypto::composite::HybridSigner;
        const N: usize = 4;
        let account = Arc::new(tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
            0x42,
        ));
        let net = Net::start_with(N, vec![account.address()], time_rules()).await;
        net.wait_for(
            "the network certifies an epoch",
            Duration::from_secs(180),
            |n| (0..N).all(|i| n.certified(i).0 >= 1),
        )
        .await;
        let storage: Arc<dyn KvStore> = net.machines[0].storage.clone();
        let state = tenzro_vm::StateAdapter::with_storage(storage.clone());
        let p256 = account.public_key().p256.clone();
        assert!(
            tenzro_vm::account_keys::enrolled_pq_key(&state, &p256).is_none(),
            "the account starts with no key enrolled"
        );
        let gossip: tenzro_node::payment_rails::GossipSlot = Arc::default();
        *gossip.lock() = Some(net.node(0).events.clone());
        let submitter = tenzro_node::payment_rails::LedgerSubmitter::new(
            net.node(0).consensus.clone(),
            account.clone() as Arc<dyn HybridSigner>,
            Address::new(account.public_key().account_slot()),
            storage.clone(),
            CHAIN_ID,
            Arc::default(),
            gossip,
        );
        let to = Address::new([0xee; 32]);
        let transfer = || tenzro_types::transaction::TransactionType::Transfer { amount: 1 };

        // Before the key is on chain nothing is admitted from the account:
        // each submission is told to retry, and the one enrolment is
        // submitted once.
        for _ in 0..3 {
            let refused = submitter.submit(to, transfer()).await;
            assert_eq!(
                refused.unwrap_err(),
                tenzro_node::payment_rails::PQ_ENROLMENT_PENDING
            );
        }
        // The caller retries until the enrolment has executed, as the
        // settlement rail's callers do, and then the transaction executes.
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(storage.clone());
        let deadline = Instant::now() + Duration::from_secs(150);
        let tx_hash = loop {
            match submitter.submit(to, transfer()).await {
                Ok(hash) => break hash,
                Err(e) if e == tenzro_node::payment_rails::PQ_ENROLMENT_PENDING => {
                    assert!(Instant::now() < deadline, "the key was never enrolled");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => panic!("submission failed: {e}"),
            }
        };
        assert!(
            tenzro_vm::account_keys::enrolled_pq_key(&state, &p256).is_some(),
            "the transaction was admitted before the key was enrolled"
        );
        let executed = loop {
            if let Some(receipt) = submitter.receipt(&tx_hash) {
                break receipt;
            }
            assert!(
                Instant::now() < deadline + Duration::from_secs(60),
                "the settlement transaction never executed"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        assert!(executed.success, "the settlement transaction reverted");
        // Nonce 0 is the one enrolment, nonce 1 the settlement: the key was
        // enrolled once, not once per submission.
        assert_eq!(reader.account_nonce(&account.address()), 2);
        // A transaction bound to its nonce is admitted only at that nonce.
        assert_eq!(submitter.next_nonce(), 2);
        let stale = submitter
            .submit_at_nonce(to, transfer(), 100_000, 1)
            .await
            .unwrap_err();
        assert!(stale.contains("moved to 2"), "{stale}");
        submitter
            .submit_at_nonce(to, transfer(), 100_000, 2)
            .await
            .expect("admitted at the nonce it was built for");
        assert_eq!(submitter.next_nonce(), 3);
    });
}

/// Bytes the node store holds by column family (tables and blob files),
/// after a full compaction so superseded versions are gone.
fn stored_bytes(store: &RocksDbStore) -> std::collections::BTreeMap<&'static str, u64> {
    store.compact_all();
    store
        .cf_sizes()
        .into_iter()
        .map(|c| (c.name, c.sst_files + c.blob_files))
        .filter(|(_, b)| *b > 0)
        .collect()
}

/// What the blocks column family holds by key family (the first two
/// `/`-separated parts of the key when it is text): record count and bytes.
fn blocks_by_family(store: &RocksDbStore) -> std::collections::BTreeMap<String, (u64, u64)> {
    let mut out = std::collections::BTreeMap::<String, (u64, u64)>::new();
    for (k, v) in store.scan_prefix(tenzro_storage::CF_BLOCKS, b"").unwrap() {
        let text: String = k
            .iter()
            .take_while(|b| b.is_ascii_graphic())
            .map(|b| *b as char)
            .collect();
        let family = text.split('/').take(2).collect::<Vec<_>>().join("/");
        let family: String = family.chars().take(32).collect();
        let e = out.entry(family).or_default();
        e.0 += 1;
        e.1 += (k.len() + v.len()) as u64;
    }
    out
}

/// The release growth gate on a running validator network: what a block and
/// a transfer cost in the store by column family, that the body of a
/// transaction is stored once, that an idle chain adds nothing, that a
/// snapshot costs under five percent of the store, and the runway the
/// measured growth leaves. The budgets are in
/// `docs/operations/disk-growth-budgets.md`.
#[test]
fn the_store_stays_within_its_byte_budgets_and_an_idle_chain_adds_nothing() {
    /// Bytes the store may grow by per executed transfer in a block of its
    /// own, all column families, one validator's copy: the measured 27,276
    /// (the block about 13 KB, the state trie versions it writes about 13 KB,
    /// the rest about 1 KB) with a fifth of headroom.
    const BYTES_PER_TRANSFER_BUDGET: u64 = 32 * 1024;
    /// Bytes of noise an idle store may move by (compaction rounding).
    const IDLE_NOISE_BYTES: u64 = 256 * 1024;
    /// Bytes the epoch-scoped consensus records may add per epoch that went
    /// by during the traffic: the measured 67,000 (journal, session and kept
    /// certificates) with headroom for where epochs fall in the window.
    const EPOCH_RECORDS_BUDGET: u64 = 128 * 1024;
    /// Bytes a compact certificate adds: its record and the copy kept as the
    /// latest, measured at 482,599 bytes each for four validators.
    const COMPACT_CERTIFICATE_BUDGET: u64 = 1024 * 1024;
    network_test(async {
        use tenzro_consensus::mempool::AccountStateReader;
        use tenzro_crypto::composite::testing::TestHybridSigner;
        use tenzro_storage::resources::{self, EPOCH_BLOCKS};
        const N: usize = 4;
        const TRANSFERS: u64 = 40;
        let sender = TestHybridSigner::hybrid(1);
        let net = Net::start_full(N, vec![sender.address()], time_rules(), Accounts::Silent).await;
        let store = net.machines[0].storage.clone();
        let reader = tenzro_node::lane_resolver::NodeAccountStateReader::new(
            store.clone() as Arc<dyn KvStore>
        );

        // Idle: nothing is sent, and the store does not move.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let idle_from = (net.height(0), stored_bytes(&store));
        tokio::time::sleep(Duration::from_secs(20)).await;
        let idle_to = (net.height(0), stored_bytes(&store));
        let idle_total = |m: &std::collections::BTreeMap<&str, u64>| m.values().sum::<u64>();
        let idle_blocks = idle_to.0 - idle_from.0;
        let idle_added = idle_total(&idle_to.1).saturating_sub(idle_total(&idle_from.1));
        println!("GROWTH idle: {idle_blocks} blocks, {idle_added} bytes added");
        assert!(
            idle_added <= IDLE_NOISE_BYTES,
            "an idle chain added {idle_added} bytes over {idle_blocks} blocks"
        );

        // Traffic: the first transaction enrols the sender's key, then
        // transfers, each after the one before.
        let before = (net.height(0), stored_bytes(&store));
        let families_before = blocks_by_family(&store);
        let traffic_from = std::time::Instant::now();
        for nonce in 0..TRANSFERS {
            let tx = signed_transfer(&sender, nonce, 1);
            for i in 0..N {
                net.node(i).consensus.submit_transaction(tx.clone()).ok();
            }
            net.wait_for(
                "the sender's transaction executes",
                Duration::from_secs(120),
                |_| reader.account_nonce(&sender.address()) > nonce,
            )
            .await;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        let after = (net.height(0), stored_bytes(&store));
        let blocks = (after.0 - before.0).max(1);
        let added = idle_total(&after.1).saturating_sub(idle_total(&before.1));
        let per_tx = added / TRANSFERS;
        let per_block = added / blocks;
        println!(
            "GROWTH traffic took {} ms",
            traffic_from.elapsed().as_millis()
        );
        for (family, (count, bytes)) in blocks_by_family(&store) {
            let (c0, b0) = families_before.get(&family).copied().unwrap_or((0, 0));
            println!(
                "GROWTH blocks cf {family:?}: +{} records, +{} bytes",
                count - c0,
                bytes.saturating_sub(b0)
            );
        }
        println!(
            "GROWTH traffic: {TRANSFERS} transfers in {blocks} blocks added {added} bytes: {per_tx} per transaction, {per_block} per block"
        );
        for (cf, bytes) in &after.1 {
            let was = before.1.get(cf).copied().unwrap_or(0);
            println!(
                "GROWTH cf {cf}: {} -> {} (+{})",
                was,
                bytes,
                bytes.saturating_sub(was)
            );
        }
        // The consensus records of an epoch (journal, session certificates,
        // kept certificates, boundaries) are written as rounds and epochs go
        // by, not as transfers execute, and are pruned by epoch: how many
        // there are depends on how long the transfers took. The per-transfer
        // budget holds the rest.
        // Compact certificates are proven on the process's compact pool,
        // off the engine, and land when the proof ends: whether one lands
        // inside the window depends on that pool and on what else runs, not
        // on the transfers or the epochs. Each is held to its own budget.
        const COMPACT: &str = "consensus/compact";
        let epoch_scoped = |m: &std::collections::BTreeMap<String, (u64, u64)>| -> u64 {
            m.iter()
                .filter(|(f, _)| {
                    f.starts_with("consensus/") && *f != "consensus/checkpoint" && *f != COMPACT
                })
                .map(|(_, (_, bytes))| *bytes)
                .sum()
        };
        let families_after = blocks_by_family(&store);
        let scoped_added =
            epoch_scoped(&families_after).saturating_sub(epoch_scoped(&families_before));
        let compact = |m: &std::collections::BTreeMap<String, (u64, u64)>| {
            m.get(COMPACT).copied().unwrap_or((0, 0))
        };
        // One record per certificate, plus the latest copy written with the
        // first.
        let (certificates, compact_added) = {
            let ((c0, b0), (c1, b1)) = (compact(&families_before), compact(&families_after));
            let latest_written = u64::from(c0 == 0 && c1 > 0);
            (
                c1.saturating_sub(c0).saturating_sub(latest_written),
                b1.saturating_sub(b0),
            )
        };
        let per_tx_executed = added.saturating_sub(scoped_added + compact_added) / TRANSFERS;
        println!(
            "GROWTH epoch-scoped consensus records: +{scoped_added} bytes; compact certificates: +{certificates}, +{compact_added} bytes; {per_tx_executed} per transaction without them"
        );
        assert!(
            compact_added <= COMPACT_CERTIFICATE_BUDGET * certificates.max(1),
            "{certificates} compact certificates added {compact_added} bytes, over {COMPACT_CERTIFICATE_BUDGET} per certificate"
        );
        // The records are pruned by epoch (`prune_epoch_records_below`,
        // exercised by `a_checkpoint_past_pruned_records_is_certified_from_the_proof_log`),
        // so what bounds them is what one epoch writes. The window spans the
        // epochs that went by, counting the one it began in.
        let epoch_ms = time_rules().epoch_checkpoints * time_rules().checkpoint_interval_ms;
        let epochs_in_window = traffic_from.elapsed().as_millis() as u64 / epoch_ms + 1;
        println!(
            "GROWTH epoch-scoped: {} bytes per epoch over {epochs_in_window} epochs",
            scoped_added / epochs_in_window
        );
        assert!(
            scoped_added <= EPOCH_RECORDS_BUDGET * epochs_in_window,
            "{scoped_added} bytes of epoch-scoped consensus records over {epochs_in_window} epochs is over {EPOCH_RECORDS_BUDGET} per epoch"
        );
        assert!(
            per_tx_executed <= BYTES_PER_TRANSFER_BUDGET,
            "{per_tx_executed} bytes per transaction (epoch-scoped consensus records and compact certificates left out) is over the budget of {BYTES_PER_TRANSFER_BUDGET}"
        );

        // A transaction body is stored once, in its block: the transaction
        // column family holds no record under the bare hash of the new ones.
        let bare = store
            .scan_prefix(tenzro_storage::CF_TRANSACTIONS, b"")
            .unwrap()
            .into_iter()
            .filter(|(k, _)| k.len() == 64 && k.iter().all(u8::is_ascii_hexdigit))
            .count();
        assert_eq!(
            bare, 0,
            "{bare} transaction bodies are stored a second time"
        );
        // ... and every one still reads back through the block that holds it.
        let tip = net.height(0);
        let block_store = BlockStoreImpl::new(store.clone()).unwrap();
        let mut read_back = 0;
        for h in before.0..=tip {
            if let Some(b) = block_store
                .get_block_by_height(BlockHeight(h))
                .await
                .unwrap()
            {
                for t in &b.transactions {
                    let hash = t.transaction.hash().to_string();
                    let json =
                        tenzro_node::tx_record::stored_transaction_json(store.as_ref(), &hash);
                    if matches!(
                        t.transaction.tx_type,
                        tenzro_types::transaction::TransactionType::Transfer { .. }
                    ) {
                        assert!(json.is_some(), "transfer {hash} cannot be read back");
                        read_back += 1;
                    }
                }
            }
        }
        assert!(
            read_back >= TRANSFERS as usize - 1,
            "only {read_back} transfers read back"
        );

        // The runway the measured growth leaves on a 100 GiB volume with a
        // third free, and at idle (no growth), in epochs.
        let free = 33 * resources::GIB;
        let runway = resources::runway_blocks(free, Some(per_block as f64)).unwrap_or(u64::MAX);
        println!(
            "GROWTH runway at {per_block} B/block with 33 GiB free: {} epochs",
            runway / EPOCH_BLOCKS
        );
        assert!(
            resources::runway_blocks(free, Some(0.0)).is_none(),
            "an idle store has no end"
        );

        // A snapshot on the same volume holds the live files by hardlink.
        let snaps = tenzro_storage::backup::SnapshotDir::new(
            net.machines[0].dir.path().join("epoch-snapshots"),
            1,
        );
        let snap = snaps
            .take(
                &store,
                "epoch-00000000000000000001-00000000000000000001",
                b"meta",
            )
            .unwrap();
        let db_dir = net.machines[0].dir.path().join("db");
        let (_, extra) = resources::unique_bytes(&db_dir, &snap);
        let db_bytes = idle_total(&after.1);
        println!("GROWTH snapshot: {extra} extra bytes over a store of {db_bytes}");
        assert!(
            extra * 20 < db_bytes.max(1) + 20 * IDLE_NOISE_BYTES,
            "the snapshot holds {extra} bytes beyond the live store of {db_bytes}"
        );
    });
}

#[path = "validator_net/load_protection.rs"]
mod load_protection;

/// A wiped node that is not a validator restores a validator's
/// snapshot, checked against the block hash it trusts, and block-syncs the
/// rest, over real consensus, real block sync and real iroh endpoints. A
/// second wiped node replays from genesis beside it, for the comparison.
#[test]
fn a_wiped_non_validator_joins_by_snapshot_and_reaches_the_head() {
    snapshot_join(false);
}

/// The same join from a snapshot cut at the first block of an epoch, the
/// height a producer takes snapshots at: the joiner restores that epoch's
/// record and the registry, then follows the chain through later epochs.
#[test]
fn a_node_restored_at_an_epoch_start_follows_the_chain_through_later_epochs() {
    snapshot_join(true);
}

/// Log lines written by a scoped subscriber, for asserting what a node logs.
#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl CapturedLog {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock()).into_owned()
    }
}

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = CapturedLog;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn snapshot_join(at_epoch_open: bool) {
    network_test(async {
        let feeder_account = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(1);
        let tail_blocks: u64 = std::env::var("F29_TAIL_BLOCKS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(40);
        let mut net = Net::start_configured(
            4,
            2,
            vec![feeder_account.address()],
            time_rules(),
            Accounts::Silent,
            Default::default(),
        )
        .await;
        let feeder = feed_transfers(
            (0..4).map(|i| net.node(i).consensus.clone()).collect(),
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for("some history", Duration::from_secs(120), |n| {
            (0..4).all(|i| n.height(i) >= 30)
        })
        .await;

        // A snapshot of validator 0's committed state a few blocks back, as
        // its producer takes one at an epoch start.
        let tip = net
            .height(0)
            .saturating_sub(tenzro_consensus::STATE_ROOT_LAG);
        let state_height = if at_epoch_open {
            // The newest epoch start with its blocks.
            tenzro_node::snapshot::latest_epoch_open(&net.machines[0].storage, tip)
                .await
                .unwrap()
                .expect("an epoch has opened")
        } else {
            // The first epoch start a producer can cut a snapshot at.
            let mut found = None;
            for h in 2..=tip {
                if tenzro_node::snapshot::can_snapshot_at(&net.machines[0].storage, h)
                    .await
                    .unwrap()
                {
                    found = Some(h);
                    break;
                }
            }
            found.expect("an epoch has opened")
        };
        let producer = net.node(0).resolver.clone();
        let snapshots = Arc::new(tenzro_node::snapshot::SnapshotStore::new(
            net.machines[0].storage.clone(),
            Arc::new(tenzro_node::snapshot::IrohSnapshotTransport::new(
                producer.clone(),
                None,
            )),
            tenzro_node::snapshot::SnapshotConfig::default().resolved(true),
        ));
        producer.snapshot_directory().set(snapshots.clone());
        let t = Instant::now();
        let manifest = snapshots.produce(state_height).await.expect("produce");
        eprintln!(
            "SNAPSHOT-METRIC harness_produce_secs={:.3} buckets={} published_bytes={}",
            t.elapsed().as_secs_f64(),
            manifest.buckets.len(),
            snapshots.published_bytes().unwrap()
        );
        // The join checkpoint is the one the producer lists
        // (`tenzro_listSnapshots`), as an operator takes it.
        let listed = snapshots.list().await.expect("list snapshots");
        let newest = listed.first().expect("the producer lists its snapshot");
        assert_eq!(newest.height, state_height);
        let anchor_height = newest.checkpoint_height;
        let anchor = {
            let bytes: [u8; 32] = hex::decode(newest.checkpoint_hash.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap();
            Hash::new(bytes)
        };
        let anchor_block = {
            let store = BlockStoreImpl::new(net.machines[0].storage.clone()).unwrap();
            store
                .get_block_by_height(BlockHeight::from(anchor_height))
                .await
                .unwrap()
                .expect("anchor block")
        };
        assert_eq!(
            anchor_block.hash(),
            anchor,
            "the listed checkpoint is the stored block"
        );

        // Let the chain move on, so the joiner has a tail to sync.
        let target = anchor_height + tail_blocks;
        net.wait_for("a tail past the snapshot", Duration::from_secs(180), |n| {
            n.height(0) >= target
        })
        .await;

        // Node 4: wiped, restores the snapshot, then follows by block sync.
        let joined = Instant::now();
        let genesis_block =
            tenzro_node::genesis::initialize_genesis(&net.machines[4].storage, &net.genesis)
                .await
                .expect("genesis");
        assert_eq!(genesis_block.height().0, 0);
        let dial_dir = tempfile::tempdir().unwrap();
        let dialer = bind_loopback(dial_dir.path(), None, false, false).await;
        dialer
            .remember_addr(producer.endpoint().addr())
            .expect("producer address");
        // Validator 1 serves no snapshot: the joiner asks it first, is told
        // so, and goes on to the producer.
        let bystander = net.node(1).resolver.clone();
        dialer
            .remember_addr(bystander.endpoint().addr())
            .expect("bystander address");

        // With no checkpoint of its own the joiner takes the producer's
        // certified anchor, verified from the genesis: it is the block the
        // producer lists. The bystander serves none and is passed over.
        producer
            .anchor_source()
            .set(Arc::new(tenzro_node::snapshot::SnapshotAnchors::new(
                snapshots.clone(),
                net.node(0).consensus.clone(),
                None,
            )));
        let genesis = tenzro_light::TrustAnchor {
            epoch: 0,
            chain_id: net.genesis.chain_id,
            genesis_hash: genesis_block.hash().0,
            committee_root: net
                .node(0)
                .consensus
                .committee(0)
                .expect("the committee of epoch 0")
                .root(),
        };
        let asked = [bystander.endpoint_id(), producer.endpoint_id()];
        let certified =
            tenzro_node::snapshot::certified_anchor_from_peers(dialer.endpoint(), &asked, &genesis, None)
                .await
                .unwrap_or_else(|e| {
                    let c = &net.node(0).consensus;
                    let covering = c.checkpoint_covering(anchor_height);
                    let index = covering.as_ref().map(|cp| cp.index);
                    let shape = |index: u64| {
                        c.checkpoint(index)
                            .map(|cp| (cp.index, cp.epoch, cp.first_height, cp.last_height, c.certificate(index).is_some()))
                    };
                    let around: Vec<_> = index
                        .map(|i| (i.saturating_sub(4)..=i + 1).map(shape).collect())
                        .unwrap_or_default();
                    panic!(
                        "the producer serves a certified anchor: {e} [anchor height {anchor_height}, checkpoint {index:?}, certificate kept {:?}, proof from genesis {:?}, epoch {}, handover of epoch 0 {:?}, genesis committee {:?}] checkpoints around it (index, epoch, first, last, certificate kept): {around:?}",
                        index.map(|i| c.certificate(i).is_some()),
                        index.map(|i| c.checkpoint_proof(i).is_some()),
                        c.epoch_manager().current_epoch().number,
                        c.handover(0).is_some(),
                        c.committee_of(0).is_some()
                    )
                });
        assert_eq!(certified, (anchor_height, anchor));
        // The producer answers one endpoint once per interval: asked again
        // at once, it says so. Another endpoint fetches the anchor itself,
        // which holds only from this network's genesis committee and only
        // with the block hashes the certified checkpoint commits.
        let again = tenzro_node::snapshot::certified_anchor_from_peers(
            dialer.endpoint(),
            &asked[1..],
            &genesis,
            None,
        )
        .await
        .unwrap_err();
        assert!(again.to_string().contains("too soon"), "{again}");
        // An endpoint with the TLS provider the nodes use between themselves:
        // the producer accepts only the post-quantum hybrid key exchange.
        let fetcher = tenzro_iroh::identity_transport::on_loopback(
            tenzro_iroh::identity_transport::base_builder(),
        )
        .bind()
        .await
        .unwrap();
        let mut forged: tenzro_node::snapshot::CertifiedAnchor = bincode::deserialize(
            &tenzro_iroh::request_anchor(&fetcher, producer.endpoint().addr())
                .await
                .unwrap()
                .expect("an anchor"),
        )
        .unwrap();
        assert_eq!(forged.verify(&genesis, None).unwrap(), certified);
        let elsewhere = tenzro_light::TrustAnchor {
            epoch: 0,
            committee_root: [0; 32],
            ..genesis
        };
        assert!(
            forged.verify(&elsewhere, None).is_err(),
            "an anchor is certified only from this network's genesis committee"
        );
        forged.block_hashes[0][0] ^= 1;
        assert!(
            forged.verify(&genesis, None).is_err(),
            "a block hash the certified checkpoint does not commit"
        );

        let peers = [
            (
                bystander.endpoint_id(),
                tenzro_node::snapshot::IrohSnapshotTransport::new(
                    dialer.clone(),
                    Some(bystander.endpoint_id()),
                ),
            ),
            (
                producer.endpoint_id(),
                tenzro_node::snapshot::IrohSnapshotTransport::new(
                    dialer.clone(),
                    Some(producer.endpoint_id()),
                ),
            ),
        ];
        let log = CapturedLog::default();
        let synced = {
            let _capture = tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::INFO)
                    .with_ansi(false)
                    .with_writer(log.clone())
                    .finish(),
            );
            tenzro_node::snapshot::state_sync_from_peers(
                &net.machines[4].storage,
                &peers,
                anchor_height,
                anchor,
                10_000,
            )
            .await
            .expect("the wiped node restores the snapshot")
        };
        drop(peers);
        let log = log.text();
        let complete = log
            .lines()
            .find(|l| l.contains("State sync complete"))
            .unwrap_or_else(|| panic!("no 'State sync complete' line in:\n{log}"));
        assert!(
            complete.contains(&anchor_block.header.state_root.to_string()),
            "the completion names the checkpoint's root: {complete}"
        );
        assert!(
            log.contains("holds no snapshot"),
            "the bystander was asked first: {log}"
        );
        assert_eq!(synced.state_root, anchor_block.header.state_root);
        let restored_at = joined.elapsed();
        assert_eq!(synced.height, state_height);
        let _ = dialer.shutdown().await;

        net.sync_from = vec![0, 1, 2, 3];
        net.up(4).await;
        net.wait_for("node 4 reaches the head", Duration::from_secs(300), |n| {
            n.height(4) + 3 >= n.height(0)
        })
        .await;
        let snapshot_join = joined.elapsed();

        // Node 5: wiped, replays every block from genesis.
        let replayed = Instant::now();
        net.up(5).await;
        net.wait_for("node 5 reaches the head", Duration::from_secs(600), |n| {
            n.height(5) + 3 >= n.height(0)
        })
        .await;
        let replay_join = replayed.elapsed();
        let head = net.height(0);
        eprintln!(
            "SNAPSHOT-METRIC harness_state_restore_secs={:.3} harness_snapshot_join_to_head_secs={:.3} \
             harness_tail_blocks_synced={} harness_replay_to_head_secs={:.3} harness_replay_blocks={} head={}",
            restored_at.as_secs_f64(),
            snapshot_join.as_secs_f64(),
            head.saturating_sub(anchor_height),
            replay_join.as_secs_f64(),
            head,
            head
        );

        // The joiner's chain is the network's: same block at a common height,
        // and its state root at the snapshot height equals the producer's.
        let hash_at = async |i: usize, h: u64| {
            let store = BlockStoreImpl::new(net.machines[i].storage.clone()).unwrap();
            store
                .get_block_by_height(BlockHeight::from(h))
                .await
                .unwrap()
                .map(|b| b.hash())
        };
        let common = net.height(4).min(net.height(0)).saturating_sub(5);
        assert_eq!(hash_at(4, common).await, hash_at(0, common).await);
        let root_at = |i: usize| {
            tenzro_storage::StateTrie::new(net.machines[i].storage.clone() as Arc<dyn KvStore>)
                .root_at(state_height)
                .unwrap()
        };
        assert_eq!(root_at(4), root_at(0));
        assert!(
            net.height(4) > anchor_height,
            "node 4 went past its snapshot by block sync"
        );

        // The joiner went on past at least one epoch boundary after its
        // snapshot, so it learned a later epoch's validators from the blocks
        // it imported.
        let epoch_of = async |i: usize, h: u64| -> Option<u64> {
            let store = BlockStoreImpl::new(net.machines[i].storage.clone()).unwrap();
            store
                .get_block_by_height(BlockHeight::from(h))
                .await
                .unwrap()
                .map(|b| b.header.epoch)
        };
        let at_snapshot = epoch_of(0, state_height).await.expect("the snapshot block");
        let at_tip = epoch_of(4, net.height(4)).await.expect("the joiner's tip");
        assert!(
            at_tip > at_snapshot,
            "the joiner is still in epoch {at_tip}, the snapshot's epoch is {at_snapshot}"
        );

        feeder.abort();
    });
}

/// Writes the record of `did` into the chain state `store` holds, as the
/// execution of its `RegisterIdentity` does, so every reader of chain state
/// finds it registered.
fn register_did_in_chain_store(store: &Arc<dyn KvStore>, did: &str) {
    let key = format!(
        "storage:{}:{}",
        hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
        hex::encode(tenzro_types::identity::identity_slot(did))
    );
    store
        .put(tenzro_storage::CF_STATE, key.as_bytes(), b"{}")
        .expect("write the identity record");
}

/// A follower whose machine identity is registered, stopped for many times
/// the onboarding window an unregistered peer gets, comes back and catches
/// up with a chain that moved on while it was away: the validators' peer
/// gate, enforcing with a short window, admits it as the registered peer it
/// is rather than as a stranger whose window ran out.
#[test]
fn a_registered_follower_away_past_the_onboarding_window_comes_back_and_catches_up() {
    network_test(async {
        use tenzro_onboarding_types::onboarding::{GateMode, OnboardingPolicy};
        const N: usize = 4;
        const FOLLOWER: usize = N;
        const WINDOW: Duration = Duration::from_secs(2);
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
        let feeder_account = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(1);
        let mut net = Net::start_configured(
            N,
            1,
            vec![feeder_account.address()],
            time_rules(),
            Accounts::Silent,
            Default::default(),
        )
        .await;
        let follower_did = net.machines[FOLLOWER].did.clone();
        let protected: std::collections::HashSet<String> =
            net.machines[..N].iter().map(|m| m.did.clone()).collect();
        let cfg = tenzro_node::identity_gate::OnboardingConfig {
            policy: OnboardingPolicy {
                mode: GateMode::Enforce,
                window: WINDOW,
                ..OnboardingPolicy::default()
            },
            ..Default::default()
        };
        for i in 0..N {
            let store = net.machines[i].storage.clone() as Arc<dyn KvStore>;
            register_did_in_chain_store(&store, &follower_did);
            let registry = Arc::new(tenzro_node::identity_gate::ChainRegistry::new(
                store,
                Arc::new(|| true),
            ));
            tenzro_node::identity_gate::install_peer_gate(
                &cfg,
                net.node(i).resolver.identity_gate(),
                registry,
                protected.clone(),
            );
        }
        let feeder = feed_transfers(
            (0..N).map(|i| net.node(i).consensus.clone()).collect(),
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );

        // The follower syncs from the validators, as `--state-sync-from`
        // names them to a node; it keeps following them by block sync.
        net.sync_from = (0..N).collect();
        net.up(FOLLOWER).await;
        net.wait_for("the follower follows", Duration::from_secs(180), |n| {
            let head = n.height(0);
            head >= 10 && n.height(FOLLOWER) + 2 >= head
        })
        .await;

        net.down(FOLLOWER).await;
        let left = net.height(0);
        let away = Instant::now();
        net.wait_for(
            "the chain moves on while the follower is away",
            Duration::from_secs(240),
            |n| n.height(0) >= left + 40 && away.elapsed() >= WINDOW * 10,
        )
        .await;
        let head = net.height(0);

        net.up(FOLLOWER).await;
        net.wait_for(
            "the returning follower catches up",
            Duration::from_secs(180),
            |n| n.height(FOLLOWER) >= head,
        )
        .await;

        // It holds the chain the validators hold.
        let hash = |i: usize| {
            let storage = net.machines[i].storage.clone();
            async move {
                BlockStoreImpl::new(storage)
                    .unwrap()
                    .get_block_by_height(BlockHeight(head))
                    .await
                    .unwrap()
                    .map(|b| b.hash())
            }
        };
        let reference = hash(0).await;
        assert!(reference.is_some());
        assert_eq!(
            hash(FOLLOWER).await,
            reference,
            "the follower at height {head}"
        );
        feeder.abort();
    });
}

/// The primary relay of a network whose validators take no direct path is
/// stopped: the validators keep ordering blocks, with no restart.
#[test]
fn validators_keep_consensus_and_peers_when_the_primary_relay_stops() {
    network_test(async {
        // Blocks are made from transactions: a funded account feeds them.
        let feeder_account = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(1);
        let mut net = Net::start_relayed(
            4,
            0,
            vec![feeder_account.address()],
            time_rules(),
            Accounts::Silent,
            Default::default(),
            Duration::from_secs(120),
            2,
            true,
        )
        .await;
        let feeder = feed_transfers(
            (0..4).map(|i| net.node(i).consensus.clone()).collect(),
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for(
            "every validator orders blocks",
            Duration::from_secs(120),
            |n| n.heights().iter().all(|h| h.is_some_and(|h| h >= 3)),
        )
        .await;
        for i in 0..4 {
            assert_eq!(
                net.peers_reached(i).await,
                3,
                "validator {i} reaches the other three"
            );
        }
        let at_loss: Vec<u64> = net.heights().into_iter().map(|h| h.unwrap_or(0)).collect();
        let lost = Instant::now();
        net.stop_relay(0).await;
        net.wait_for(
            "blocks keep coming after the primary relay stops",
            Duration::from_secs(420),
            |n| {
                n.heights()
                    .iter()
                    .zip(&at_loss)
                    .all(|(h, before)| h.is_some_and(|h| h >= before + 2))
            },
        )
        .await;
        let ordered_after = lost.elapsed();
        eprintln!("relay loss: two more blocks on every validator after {ordered_after:?}");
        feeder.abort();
    });
}

/// One validator's TPM stops answering for 30 seconds: the other three keep
/// ordering blocks, and the validator signs and catches up when its TPM
/// answers again, without a restart.
#[test]
fn a_validator_whose_tpm_stalls_for_30_seconds_does_not_stop_the_others_and_recovers() {
    network_test(async {
        // Blocks are made from transactions: a funded account feeds them.
        let feeder_account = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(1);
        let net = Net::start_with(4, vec![feeder_account.address()], time_rules()).await;
        let feeder = feed_transfers(
            (0..4).map(|i| net.node(i).consensus.clone()).collect(),
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for(
            "every validator orders blocks",
            Duration::from_secs(120),
            |n| n.heights().iter().all(|h| h.is_some_and(|h| h >= 3)),
        )
        .await;
        let before: Vec<u64> = net.heights().into_iter().map(|h| h.unwrap_or(0)).collect();
        net.stall_tpm(0, Duration::from_secs(30));
        let stalled = Instant::now();
        // The three others keep going while it is stalled.
        net.wait_for(
            "the others order blocks during the stall",
            Duration::from_secs(25),
            |n| (1..4).all(|i| n.height(i) >= before[i] + 5),
        )
        .await;
        assert!(
            stalled.elapsed() < Duration::from_secs(30),
            "ordered inside the stall window"
        );
        // After the window the stalled validator is back at the others' height.
        let window_over = stalled + Duration::from_secs(30);
        tokio::time::sleep_until(tokio::time::Instant::from_std(window_over)).await;
        net.wait_for(
            "the validator catches up after its TPM answers",
            Duration::from_secs(60),
            |n| {
                let top = (1..4).map(|i| n.height(i)).max().unwrap_or(0);
                n.height(0) + 3 >= top
            },
        )
        .await;
        eprintln!(
            "tpm stall: caught up {:?} after the stall ended",
            Instant::now() - window_over
        );
        feeder.abort();
    });
}
