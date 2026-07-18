//! Sustained-write load measurement for the committee-resident Red Stuff DA
//! backend (`da_committee::DaCommitteeBackend`).
//!
//! Drives the writer pipeline the way a live validator does: per blob, the
//! backend encodes 2n slivers, distributes each member's pair through the
//! `DaCommitteeSurface`, and collects 2f+1 Ed25519 attestations into an
//! availability certificate. The surface here is an in-process mesh that keeps
//! everything the real libp2p path costs except the socket:
//!
//! - the sliver and shape are bincode-encoded and decoded on every store/fetch,
//!   exactly as `/tenzro/da/committee` frames them on the wire;
//! - each member independently verifies the sliver's Merkle proof before
//!   custody, signs a real Ed25519 attestation, and the writer verifies it;
//! - each member persists custody to its own RocksDB `CF_DA_COMMITTEE`.
//!
//! What it deliberately excludes: WAN propagation and libp2p connection
//! management. The numbers are single-writer pipeline throughput — the upper
//! bound the coding/signing/persistence path imposes before network latency.
//!
//! Ignored by default; run explicitly (release profile, or the RS coding
//! numbers are meaningless):
//!
//! ```bash
//! cargo test -p tenzro-node --release --test da_committee_load -- --ignored --nocapture
//! ```
//!
//! Tunables: `TENZRO_DA_BENCH_BLOBS` (writes per committee size, default 96),
//! `TENZRO_DA_BENCH_BLOB_BYTES` (payload size, default 1 MiB),
//! `TENZRO_DA_BENCH_FETCHES` (read-path samples, default 16).

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tenzro_crypto::keys::{KeyPair, KeyType};
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_node::da_committee::{
    attestation_message, challenge_message, committee_address, CommitteeMember, CommitteeView,
    DaCommitteeBackend, DaCommitteeError, DaCommitteeStore, DaCommitteeSurface, MemberAttestation,
    PossessionProof, StoredSliver,
};
use tenzro_storage::da::DaBackend;
use tenzro_storage::redstuff::{self, CommitteeShape, SliverPair};
use tenzro_storage::RocksDbStore;
use tenzro_types::primitives::{Address, Hash};

const MIB: usize = 1024 * 1024;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Static committee of freshly generated Ed25519 validators.
struct StaticCommittee {
    members: Vec<CommitteeMember>,
    keypairs: Vec<KeyPair>,
}

impl StaticCommittee {
    fn new(n: usize) -> Self {
        let mut members = Vec::with_capacity(n);
        let mut keypairs = Vec::with_capacity(n);
        for index in 0..n {
            let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
            members.push(CommitteeMember {
                index,
                address: committee_address(&kp).unwrap(),
                public_key: kp.public_key().clone(),
            });
            keypairs.push(kp);
        }
        Self { members, keypairs }
    }
}

impl CommitteeView for StaticCommittee {
    fn members(&self) -> Vec<CommitteeMember> {
        self.members.clone()
    }
}

/// In-process mesh with wire-faithful costs: bincode framing both ways,
/// per-member Merkle verification, real Ed25519 signing, RocksDB custody.
struct WireMeshSurface {
    stores: Vec<Arc<DaCommitteeStore>>,
    signers: Vec<Ed25519SignerImpl>,
    addresses: Vec<Address>,
    // Owns the temp dirs so the per-member DBs live for the surface's lifetime.
    _dirs: Vec<tempfile::TempDir>,
}

impl WireMeshSurface {
    fn new(committee: &StaticCommittee) -> Self {
        let n = committee.members.len();
        let mut stores = Vec::with_capacity(n);
        let mut signers = Vec::with_capacity(n);
        let mut addresses = Vec::with_capacity(n);
        let mut dirs = Vec::with_capacity(n);
        for kp in &committee.keypairs {
            let dir = tempfile::tempdir().unwrap();
            let db = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
            stores.push(Arc::new(DaCommitteeStore::with_storage(db).unwrap()));
            // KeyPair is not Clone (zeroizing secret); re-derive from secret bytes.
            let kp_owned = KeyPair::from_bytes(KeyType::Ed25519, &kp.to_bytes()).unwrap();
            signers.push(Ed25519SignerImpl::new(kp_owned).unwrap());
            addresses.push(committee_address(kp).unwrap());
            dirs.push(dir);
        }
        Self {
            stores,
            signers,
            addresses,
            _dirs: dirs,
        }
    }
}

#[async_trait]
impl DaCommitteeSurface for WireMeshSurface {
    async fn store_sliver(
        &self,
        to_index: usize,
        commitment: &Hash,
        shape: CommitteeShape,
        blob_len: u64,
        symbol_len: usize,
        sliver: &SliverPair,
    ) -> Result<MemberAttestation, DaCommitteeError> {
        // Writer-side wire framing, then member-side decode — the same bincode
        // round-trip `/tenzro/da/committee` performs.
        let sliver_bytes =
            bincode::serialize(sliver).map_err(|e| DaCommitteeError::Core(e.to_string()))?;
        let shape_bytes =
            bincode::serialize(&shape).map_err(|e| DaCommitteeError::Core(e.to_string()))?;
        let shape: CommitteeShape =
            bincode::deserialize(&shape_bytes).map_err(|e| DaCommitteeError::Core(e.to_string()))?;
        let sliver: SliverPair =
            bincode::deserialize(&sliver_bytes).map_err(|e| DaCommitteeError::Core(e.to_string()))?;

        if !redstuff::verify_sliver(&sliver, shape, blob_len, symbol_len, commitment) {
            return Err(DaCommitteeError::Transport(
                "sliver failed verification".into(),
            ));
        }
        self.stores[to_index].put_sliver(StoredSliver {
            shape,
            blob_len,
            symbol_len,
            commitment: *commitment,
            sliver,
        })?;
        let msg = attestation_message(commitment, &self.addresses[to_index]);
        let signature = self.signers[to_index]
            .sign(&msg)
            .map_err(|e| DaCommitteeError::Signing(e.to_string()))?;
        Ok(MemberAttestation {
            index: to_index,
            address: self.addresses[to_index],
            signature,
        })
    }

    async fn fetch_sliver(
        &self,
        to_index: usize,
        commitment: &Hash,
    ) -> Result<Option<SliverPair>, DaCommitteeError> {
        match self.stores[to_index].get_sliver(commitment) {
            Some(stored) => {
                // Member-side wire framing, then writer-side decode.
                let bytes = bincode::serialize(&stored.sliver)
                    .map_err(|e| DaCommitteeError::Core(e.to_string()))?;
                let sliver: SliverPair = bincode::deserialize(&bytes)
                    .map_err(|e| DaCommitteeError::Core(e.to_string()))?;
                Ok(Some(sliver))
            }
            None => Ok(None),
        }
    }

    async fn challenge_sliver(
        &self,
        to_index: usize,
        commitment: &Hash,
        nonce: &[u8; 32],
    ) -> Result<Option<PossessionProof>, DaCommitteeError> {
        let Some(stored) = self.stores[to_index].get_sliver(commitment) else {
            return Ok(None);
        };
        // Member-side wire framing, then challenger-side decode.
        let bytes = bincode::serialize(&stored.sliver)
            .map_err(|e| DaCommitteeError::Core(e.to_string()))?;
        let sliver: SliverPair =
            bincode::deserialize(&bytes).map_err(|e| DaCommitteeError::Core(e.to_string()))?;
        let address = self.addresses[to_index];
        let msg = challenge_message(commitment, nonce, &address);
        let signature = self.signers[to_index]
            .sign(&msg)
            .map_err(|e| DaCommitteeError::Signing(e.to_string()))?;
        Ok(Some(PossessionProof {
            index: to_index,
            address,
            signature,
            sliver,
        }))
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn report(label: &str, n: usize, blob_bytes: usize, mut latencies: Vec<Duration>, elapsed: Duration) {
    latencies.sort_unstable();
    let count = latencies.len();
    let total_bytes = (count * blob_bytes) as f64;
    let mbps = total_bytes / MIB as f64 / elapsed.as_secs_f64();
    let mean = latencies.iter().sum::<Duration>() / count as u32;
    println!(
        "DA-BENCH {label} n={n} blobs={count} blob_bytes={blob_bytes} \
         MiBps={mbps:.1} mean_ms={:.2} p50_ms={:.2} p95_ms={:.2} p99_ms={:.2}",
        mean.as_secs_f64() * 1e3,
        percentile(&latencies, 0.50).as_secs_f64() * 1e3,
        percentile(&latencies, 0.95).as_secs_f64() * 1e3,
        percentile(&latencies, 0.99).as_secs_f64() * 1e3,
    );
}

async fn run_committee(n: usize, blobs: usize, blob_bytes: usize, fetches: usize) {
    let committee = Arc::new(StaticCommittee::new(n));
    let surface = Arc::new(WireMeshSurface::new(&committee));

    // Writer is committee member 0, with its own RocksDB custody store.
    let writer_dir = tempfile::tempdir().unwrap();
    let writer_db = Arc::new(RocksDbStore::open_default(writer_dir.path()).unwrap());
    let backend = DaCommitteeBackend::new(
        KeyPair::from_bytes(KeyType::Ed25519, &committee.keypairs[0].to_bytes()).unwrap(),
        committee.clone(),
        surface,
        Arc::new(DaCommitteeStore::with_storage(writer_db).unwrap()),
    )
    .unwrap()
    .with_per_member_timeout(Duration::from_secs(30));

    // Sustained writes: distinct payload per blob so every commitment differs.
    let mut pointers = Vec::with_capacity(blobs);
    let mut write_lat = Vec::with_capacity(blobs);
    let write_start = Instant::now();
    for i in 0..blobs {
        let payload: Vec<u8> = (0..blob_bytes).map(|b| ((b + i * 31) % 251) as u8).collect();
        let t = Instant::now();
        let pointer = backend
            .submit(b"bench", &payload)
            .await
            .expect("submit reached availability quorum");
        write_lat.push(t.elapsed());
        pointers.push(pointer);
    }
    let write_elapsed = write_start.elapsed();
    report("write", n, blob_bytes, write_lat, write_elapsed);

    // Read path: reconstruct a sample of blobs from committee slivers.
    let sample = fetches.min(pointers.len());
    let mut fetch_lat = Vec::with_capacity(sample);
    let fetch_start = Instant::now();
    for pointer in pointers.iter().take(sample) {
        let t = Instant::now();
        let blob = backend.fetch(pointer).await.expect("fetch reconstructs");
        assert_eq!(blob.len(), blob_bytes);
        fetch_lat.push(t.elapsed());
    }
    let fetch_elapsed = fetch_start.elapsed();
    report("fetch", n, blob_bytes, fetch_lat, fetch_elapsed);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "sustained-load measurement; run explicitly in release"]
async fn da_committee_sustained_write_load() {
    let blobs = env_usize("TENZRO_DA_BENCH_BLOBS", 96);
    let blob_bytes = env_usize("TENZRO_DA_BENCH_BLOB_BYTES", MIB);
    let fetches = env_usize("TENZRO_DA_BENCH_FETCHES", 16);

    // Smallest fault-tolerant committee and the pre-resize fleet size.
    for n in [4usize, 10] {
        run_committee(n, blobs, blob_bytes, fetches).await;
    }
}
