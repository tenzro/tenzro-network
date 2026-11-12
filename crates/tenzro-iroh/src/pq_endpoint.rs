//! The ML-DSA leg of a peer's endpoint authentication, beside iroh's Ed25519.
//!
//! iroh authenticates an endpoint by its Ed25519 key in the TLS handshake.
//! The key exchange is already hybrid (X25519MLKEM768), the authentication is
//! not: whoever can forge Ed25519 can complete the handshake as a peer and
//! relay between two nodes. This module adds the second leg, which needs
//! ML-DSA, and makes it mandatory:
//!
//! - The machine's hardware ML-DSA key signs a [`PqBinding`]: that key, bound
//!   to the endpoint record it travels in. The record's P-256 message and
//!   signature are unchanged, so a node that does not know the binding still
//!   verifies the record.
//! - On a connection, each side signs the connection's TLS exporter with both
//!   hardware keys of its machine, the P-256 key and the ML-DSA key the
//!   record binds ([`ChannelKeys`]), and the other side verifies both against
//!   the record ([`authenticate_dialer`], [`authenticate_acceptor`]). The
//!   exporter differs on every connection, so a party sitting between two
//!   peers on a forged Ed25519 handshake cannot pass on the proofs it gets.
//! - Neither side serves or dials a peer without it. A peer whose record
//!   carries no verified ML-DSA binding, or that has no hardware keys to
//!   prove with, is refused: there is no classical-only authentication. The
//!   RPC protocols run this on their versioned ALPNs ([`PqChannel`]).
//! - [`PqPins`] remembers the hardware ML-DSA key each identity bound its
//!   records with, or the one it registered on chain. A later record from
//!   that identity without the binding, or bound by another key, is refused,
//!   so the binding cannot be stripped by forging the P-256 signature alone.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use iroh::EndpointId;
use iroh::endpoint::Connection;
use serde::{Deserialize, Serialize};
use tenzro_crypto::pq::ml_dsa_verify_scheme;
use tenzro_device_key::signer::{HardwareSigner, verify_p256};
use tenzro_types::signature_scheme::SignatureScheme;

use crate::discovery::DiscoveryStore;
use crate::error::{IrohError, IrohResult};
use crate::identity_record::{EndpointRecord, RecordError, record_message};

/// The machine's hardware ML-DSA key, as the binding uses it.
pub trait MachinePqKey: Send + Sync {
    /// The verifying key, tagged with its scheme ([`SignatureScheme::tag`]).
    fn public_key(&self) -> IrohResult<Vec<u8>>;
    /// A bare ML-DSA signature over `message` under the FIPS 204 context
    /// [`PQ_BINDING_CONTEXT`].
    fn sign_binding(&self, message: &[u8]) -> IrohResult<Vec<u8>>;
    /// A bare ML-DSA signature over `message` under the FIPS 204 context
    /// [`PQ_CHANNEL_CONTEXT`].
    fn sign_channel(&self, message: &[u8]) -> IrohResult<Vec<u8>>;
}

/// The two hardware keys a node proves a connection with: the machine's
/// P-256 key and the ML-DSA key its records bind.
#[derive(Clone)]
pub struct ChannelKeys {
    /// The machine's hardware P-256 key.
    pub p256: Arc<dyn HardwareSigner>,
    /// The machine's hardware ML-DSA key.
    pub ml_dsa: Arc<dyn MachinePqKey>,
}

/// Domain of the message a machine's ML-DSA key signs to bind an endpoint key.
pub const PQ_BINDING_DOMAIN: &[u8] = b"tenzro/iroh/pq-endpoint-binding/v2";

/// FIPS 204 context of the binding signature.
pub const PQ_BINDING_CONTEXT: &[u8] = b"tenzro/iroh/pq-endpoint-binding";

/// FIPS 204 context of the ML-DSA channel proof.
pub const PQ_CHANNEL_CONTEXT: &[u8] = b"tenzro/iroh/pq-channel-proof";

/// Domain of the message both hardware keys of the machine sign on a
/// connection: this and the connection's TLS exporter.
pub const CHANNEL_PROOF_DOMAIN: &[u8] = b"tenzro/iroh/channel-proof/v2";

/// TLS exporter label the channel proofs sign.
pub const CHANNEL_EXPORTER_LABEL: &[u8] = b"EXPORTER-tenzro-pq-channel-v2";

/// Most identities [`PqPins`] remembers.
pub const MAX_PINS: usize = 65_536;

/// Largest channel proof frame read from a peer.
const MAX_PROOF_FRAME: usize = 8 * 1024;

/// Exporter context of the proof the dialing side makes.
const DIALER: &[u8] = b"dialer";
/// Exporter context of the proof the accepting side makes.
const ACCEPTOR: &[u8] = b"acceptor";

/// The machine's hardware ML-DSA key's statement that `endpoint_pq_key` is
/// the ML-DSA-65 endpoint key of the record it travels in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBinding {
    /// The machine's hardware ML-DSA verifying key, tagged with its scheme
    /// ([`SignatureScheme::tag`]).
    #[serde(with = "hex_bytes")]
    pub machine_pq_key: Vec<u8>,
    /// The ML-DSA-65 endpoint key of this boot.
    /// The machine key's bare ML-DSA signature over [`binding_message`].
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// What the machine's ML-DSA key signs: the domain, the record's P-256
/// signed message (its endpoint key, relays, sequence and lifetime) and the
/// two ML-DSA keys.
pub fn binding_message(record: &EndpointRecord, machine_pq_key: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    for part in [PQ_BINDING_DOMAIN, &record_message(record), machine_pq_key] {
        m.extend_from_slice(&(part.len() as u32).to_be_bytes());
        m.extend_from_slice(part);
    }
    m
}

impl EndpointRecord {
    /// Binds `endpoint_pq` to this record with the machine's hardware ML-DSA
    /// key. Call it after [`EndpointRecord::sign`]; the P-256 signature is
    /// left as it is.
    /// Binds this record with the machine's hardware ML-DSA key: its signature
    /// over the record, which names the endpoint key and the time the record
    /// ends.
    pub fn bind_pq(&mut self, machine: &dyn MachinePqKey) -> IrohResult<()> {
        let machine_pq_key = machine.public_key()?;
        let signature = machine.sign_binding(&binding_message(self, &machine_pq_key))?;
        self.pq = Some(PqBinding {
            machine_pq_key,
            signature,
        });
        Ok(())
    }

    /// Checks the record's ML-DSA binding, if it has one: the machine key's
    /// signature over this record. A record with no binding passes.
    pub fn check_pq_binding(&self) -> Result<(), RecordError> {
        let Some(b) = &self.pq else {
            return Ok(());
        };
        let (scheme, key) = SignatureScheme::split_public_key(&b.machine_pq_key)
            .ok_or(RecordError::Malformed("machine ML-DSA key names no scheme"))?;
        ml_dsa_verify_scheme(
            scheme,
            key,
            PQ_BINDING_CONTEXT,
            &binding_message(self, &b.machine_pq_key),
            &b.signature,
        )
        .map_err(|_| RecordError::BadPqBinding)
    }
}

/// The hardware ML-DSA key each identity binds its endpoint records with,
/// learned from the first bound record that verifies or pinned from chain
/// state (a validator's registered key), and whether the identity has
/// presented a bound record yet.
#[derive(Debug, Default)]
pub struct PqPins {
    by_did: HashMap<String, Pin>,
    /// Counts the changes, so a holder that saves the pins knows when to.
    changes: u64,
}

/// One pin as it is saved: the identity, the key it is held to (tagged with
/// its scheme) and whether it has presented a bound record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPin {
    /// The identity.
    pub did: String,
    /// The ML-DSA key it is held to, tagged with its scheme.
    #[serde(with = "hex_bytes")]
    pub key: Vec<u8>,
    /// Whether it has presented a bound record, so an unbound one is refused.
    pub required: bool,
}

#[derive(Debug)]
struct Pin {
    key: Vec<u8>,
    /// Set once the identity presented a bound record that verified: from
    /// then on a record without the binding is refused.
    required: bool,
}

impl PqPins {
    /// No pins.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins `machine_pq_key` (tagged with its scheme) for `did`, as
    /// registered on chain: the only key `did` may bind its records with.
    /// An identity that has not presented a bound record yet (a node on an
    /// older build) keeps being accepted without one until it does.
    pub fn pin(&mut self, did: &str, machine_pq_key: Vec<u8>) {
        if let Some(pin) = self.by_did.get_mut(did) {
            if pin.key != machine_pq_key {
                pin.key = machine_pq_key;
                self.changes += 1;
            }
        } else if self.by_did.len() < MAX_PINS {
            self.by_did.insert(
                did.to_string(),
                Pin {
                    key: machine_pq_key,
                    required: false,
                },
            );
            self.changes += 1;
        }
    }

    /// Every pin, to save.
    pub fn saved(&self) -> Vec<SavedPin> {
        let mut out: Vec<SavedPin> = self
            .by_did
            .iter()
            .map(|(did, p)| SavedPin {
                did: did.clone(),
                key: p.key.clone(),
                required: p.required,
            })
            .collect();
        out.sort_by(|a, b| a.did.cmp(&b.did));
        out
    }

    /// Takes back pins saved by an earlier run. A pin held now wins over a
    /// saved one for another key (it came from chain state or a live
    /// record), and a saved pin never makes a held one less strict.
    pub fn restore(&mut self, saved: Vec<SavedPin>) {
        for s in saved {
            let full = self.by_did.len() >= MAX_PINS;
            match self.by_did.get_mut(&s.did) {
                Some(pin) if pin.key == s.key && s.required && !pin.required => {
                    pin.required = true;
                    self.changes += 1;
                }
                Some(_) => {}
                None if !full => {
                    self.by_did.insert(
                        s.did,
                        Pin {
                            key: s.key,
                            required: s.required,
                        },
                    );
                    self.changes += 1;
                }
                None => {}
            }
        }
    }

    /// How many times the pins changed.
    pub fn changes(&self) -> u64 {
        self.changes
    }

    /// The key pinned for `did`.
    pub fn get(&self, did: &str) -> Option<&[u8]> {
        self.by_did.get(did).map(|p| p.key.as_slice())
    }

    /// Accepts `record` for `did` only if its binding verifies and names the
    /// key pinned for `did`. The first bound record of an identity with no
    /// pin pins its key. Once an identity has presented a bound record, a
    /// record without the binding is refused.
    pub fn check(&mut self, did: &str, record: &EndpointRecord) -> Result<(), RecordError> {
        record.check_pq_binding()?;
        match (&record.pq, self.by_did.get_mut(did)) {
            (None, Some(pin)) if pin.required => Err(RecordError::PqBindingMissing),
            (None, _) => Ok(()),
            (Some(b), Some(pin)) if b.machine_pq_key != pin.key => Err(RecordError::PqKeyChanged),
            (Some(_), Some(pin)) => {
                if !pin.required {
                    pin.required = true;
                    self.changes += 1;
                }
                Ok(())
            }
            (Some(b), None) => {
                if self.by_did.len() < MAX_PINS {
                    self.by_did.insert(
                        did.to_string(),
                        Pin {
                            key: b.machine_pq_key.clone(),
                            required: true,
                        },
                    );
                    self.changes += 1;
                }
                Ok(())
            }
        }
    }
}

fn exporter(conn: &Connection, context: &[u8]) -> IrohResult<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, CHANNEL_EXPORTER_LABEL, context)
        .map_err(|e| IrohError::Backend(format!("TLS exporter: {e:?}")))?;
    Ok(out)
}

/// The message both hardware keys of the machine sign on a connection.
pub fn channel_message(exporter: &[u8; 32]) -> Vec<u8> {
    let mut m = CHANNEL_PROOF_DOMAIN.to_vec();
    m.extend_from_slice(exporter);
    m
}

/// Checks `proof` against the keys `peer`'s record names, both of which must
/// have signed `exporter`: the P-256 machine key, and the ML-DSA machine key
/// the record's binding names. The proof is the P-256 signature's length as
/// two big-endian bytes, the P-256 signature, then the ML-DSA signature.
pub fn verify_channel_proof(
    peer: &EndpointRecord,
    exporter: &[u8; 32],
    proof: &[u8],
) -> IrohResult<()> {
    let refused = || IrohError::Backend("the peer's channel proof does not verify".into());
    let p256_key = bound_key(peer)?;
    let binding = peer.pq.as_ref().ok_or_else(refused)?;
    let (len, rest) = proof.split_first_chunk::<2>().ok_or_else(refused)?;
    let len = u16::from_be_bytes(*len) as usize;
    if rest.len() < len {
        return Err(refused());
    }
    let (p256_sig, ml_dsa_sig) = rest.split_at(len);
    let message = channel_message(exporter);
    if !verify_p256(p256_key, &message, p256_sig) {
        return Err(refused());
    }
    let (scheme, key) =
        SignatureScheme::split_public_key(&binding.machine_pq_key).ok_or_else(refused)?;
    ml_dsa_verify_scheme(scheme, key, PQ_CHANNEL_CONTEXT, &message, ml_dsa_sig)
        .map_err(|_| refused())
}

/// Milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The machine P-256 key the peer's record names, once the record's
/// hardware ML-DSA binding verifies and has not lapsed. The binding is the
/// two-leg statement "this identity authorises this transport key until the
/// record ends": the record's P-256 signature and the ML-DSA binding both
/// cover the endpoint key and the record's `not_after_ms`.
fn bound_key(peer: &EndpointRecord) -> IrohResult<&[u8]> {
    peer.check_pq_binding()
        .map_err(|e| IrohError::Backend(format!("peer record: {e}")))?;
    if peer.pq.is_none() {
        return Err(IrohError::Backend(
            "the peer's record carries no ML-DSA binding".into(),
        ));
    }
    if now_ms() > peer.not_after_ms {
        return Err(IrohError::Backend(
            "the peer's endpoint binding has lapsed".into(),
        ));
    }
    Ok(peer.machine_key.as_slice())
}

fn prove(own: &ChannelKeys, exporter: &[u8; 32]) -> IrohResult<Vec<u8>> {
    let message = channel_message(exporter);
    let p256 = own
        .p256
        .sign(&message)
        .map_err(|e| IrohError::Backend(format!("hardware channel proof: {e}")))?;
    let ml_dsa = own.ml_dsa.sign_channel(&message)?;
    let mut proof = (p256.len() as u16).to_be_bytes().to_vec();
    proof.extend_from_slice(&p256);
    proof.extend_from_slice(&ml_dsa);
    Ok(proof)
}

/// The dialing side of the channel authentication on `conn`: opens one
/// stream, sends its proof of both hardware keys over the connection's
/// exporter, and checks the acceptor's against the keys `peer`'s record
/// names, which must carry a verified ML-DSA binding. `peer` must be the
/// record verified for the endpoint key `conn` authenticated.
pub async fn authenticate_dialer(
    conn: &Connection,
    own: &ChannelKeys,
    peer: &EndpointRecord,
) -> IrohResult<()> {
    bound_key(peer)?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| IrohError::Backend(format!("open_bi: {e}")))?;
    let proof = prove(own, &exporter(conn, DIALER)?)?;
    crate::consensus::write_frame(&mut send, &proof).await?;
    send.finish()
        .map_err(|e| IrohError::Backend(format!("send.finish: {e}")))?;
    let proof = crate::consensus::read_frame(&mut recv, MAX_PROOF_FRAME).await?;
    verify_channel_proof(peer, &exporter(conn, ACCEPTOR)?, &proof)
}

/// The accepting side on `conn`: accepts the dialer's stream, checks its
/// proof against the keys the dialer's record names, and answers with its
/// own. `peer` is the record this node holds for the endpoint key `conn`
/// authenticated. A dialer this node holds no record for, or whose record
/// carries no verified ML-DSA binding, is refused before any stream is
/// accepted: authentication by Ed25519 and P-256 alone is not accepted.
pub async fn authenticate_acceptor(
    conn: &Connection,
    own: &ChannelKeys,
    peer: Option<&EndpointRecord>,
) -> IrohResult<()> {
    let peer = peer.ok_or_else(|| {
        IrohError::Backend(
            "no record of the dialer: classical-only authentication is refused".into(),
        )
    })?;
    bound_key(peer)?;
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| IrohError::Backend(format!("accept_bi: {e}")))?;
    let proof = crate::consensus::read_frame(&mut recv, MAX_PROOF_FRAME).await?;
    verify_channel_proof(peer, &exporter(conn, DIALER)?, &proof)?;
    crate::consensus::write_frame(&mut send, &prove(own, &exporter(conn, ACCEPTOR)?)?).await?;
    send.finish()
        .map_err(|e| IrohError::Backend(format!("send.finish: {e}")))?;
    Ok(())
}

/// What the RPC protocols need: the records this node holds, to find the
/// machine keys a peer names, and this node's hardware keys for the proofs.
/// No private key is held here: the keys are the machine's TPM or Secure
/// Enclave keys.
#[derive(Clone)]
pub struct PqChannel {
    store: Arc<DiscoveryStore>,
    own: Arc<OnceLock<ChannelKeys>>,
}

impl std::fmt::Debug for PqChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqChannel")
            .field("bound", &self.own.get().is_some())
            .finish_non_exhaustive()
    }
}

impl PqChannel {
    /// A channel over the records of `store`, with no signer yet.
    pub fn new(store: Arc<DiscoveryStore>) -> Self {
        Self {
            store,
            own: Arc::new(OnceLock::new()),
        }
    }

    /// This node's hardware channel keys, once it binds records.
    pub fn own_key(&self) -> Option<ChannelKeys> {
        self.own.get().cloned()
    }

    /// Sets this node's hardware channel keys; the first set stays. Returns
    /// whether `keys` were set.
    pub fn set_own_key(&self, keys: ChannelKeys) -> bool {
        self.own.set(keys).is_ok()
    }

    /// The record this node holds for the peer authenticated as `peer`.
    pub fn peer_record(&self, peer: EndpointId) -> Option<EndpointRecord> {
        self.store.naming(peer)
    }

    /// The record of `peer` when it carries the hardware binding: a call to
    /// `peer` then takes the versioned ALPN and requires its proof.
    pub fn bound_record(&self, peer: EndpointId) -> Option<EndpointRecord> {
        self.peer_record(peer).filter(|r| r.pq.is_some())
    }

    /// The acceptor's side on `conn`. Refused when this node holds no
    /// channel keys.
    pub async fn accept(&self, conn: &Connection) -> IrohResult<()> {
        let own = self
            .own_key()
            .ok_or_else(|| IrohError::Backend("this node binds no channel keys".into()))?;
        let peer = self.peer_record(conn.remote_id());
        authenticate_acceptor(conn, &own, peer.as_ref()).await
    }

    /// The dialer's side on `conn` to the peer whose record is `peer`.
    /// Refused when this node holds no channel keys.
    pub async fn dial(&self, conn: &Connection, peer: &EndpointRecord) -> IrohResult<()> {
        let own = self
            .own_key()
            .ok_or_else(|| IrohError::Backend("this node binds no channel keys".into()))?;
        authenticate_dialer(conn, &own, peer).await
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// Reads pins saved by [`save_pins`]. A missing file is no pins.
pub fn load_pins(path: &std::path::Path) -> std::io::Result<Vec<SavedPin>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Saves `pins` to `path` whole or not at all: written beside it, flushed,
/// then renamed over it.
pub fn save_pins(path: &std::path::Path, pins: &[SavedPin]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec(pins).map_err(std::io::Error::other)?)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::identity_record::tests::TestMachineKey;
    use crate::identity_record::{EndpointKey, RecordBook, RecordScope};
    use iroh::Endpoint;
    use iroh::endpoint::presets;
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use tenzro_crypto::pq::MlDsaSigningKey;

    const NOW: u64 = 1_900_000_000_000;
    const ALPN: &[u8] = b"tenzro/test/pq-channel";

    /// A software ML-DSA-65 key standing in for a machine's hardware one.
    pub(crate) struct TestMachinePq(pub(crate) MlDsaSigningKey);

    impl TestMachinePq {
        pub(crate) fn generate() -> Self {
            Self(MlDsaSigningKey::generate())
        }
    }

    impl MachinePqKey for TestMachinePq {
        fn public_key(&self) -> IrohResult<Vec<u8>> {
            Ok(SignatureScheme::MlDsa65P256.tag(self.0.verifying_key_bytes()))
        }
        fn sign_binding(&self, message: &[u8]) -> IrohResult<Vec<u8>> {
            Ok(self.0.sign(PQ_BINDING_CONTEXT, message))
        }
        fn sign_channel(&self, message: &[u8]) -> IrohResult<Vec<u8>> {
            Ok(self.0.sign(PQ_CHANNEL_CONTEXT, message))
        }
    }

    fn record(machine: &TestMachineKey, sequence: u64) -> EndpointRecord {
        EndpointRecord::sign(
            machine,
            EndpointKey {
                transport: "test/ed25519".to_string(),
                key: vec![sequence as u8; 32],
            },
            Vec::new(),
            Vec::new(),
            None,
            RecordScope::Network,
            Vec::new(),
            sequence,
            NOW,
        )
        .unwrap()
    }

    fn bound(
        machine: &TestMachineKey,
        machine_pq: &TestMachinePq,
        sequence: u64,
    ) -> EndpointRecord {
        let mut r = record(machine, sequence);
        r.bind_pq(machine_pq).unwrap();
        r
    }

    #[test]
    fn a_bound_record_verifies_and_a_moved_or_altered_binding_does_not() {
        let machine = TestMachineKey::from_seed(1);
        let machine_pq = TestMachinePq::generate();
        let r = bound(&machine, &machine_pq, 1);
        r.check_current(NOW).unwrap();
        r.check_pq_binding().unwrap();

        // Through JSON, as records travel.
        let back: EndpointRecord =
            serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        back.check_pq_binding().unwrap();
        // A record without a binding serializes as it did before.
        let plain = record(&machine, 1);
        assert!(
            !String::from_utf8(serde_json::to_vec(&plain).unwrap())
                .unwrap()
                .contains("\"pq\"")
        );

        let mut swapped = r.clone();
        swapped.pq.as_mut().unwrap().signature[0] ^= 1;
        assert_eq!(swapped.check_pq_binding(), Err(RecordError::BadPqBinding));

        let mut moved = record(&machine, 2);
        moved.pq = r.pq.clone();
        assert_eq!(moved.check_pq_binding(), Err(RecordError::BadPqBinding));
    }

    /// Pins outlive a restart: saved and taken back by a new book, a pinned
    /// identity's unbound record and a record bound by another key are still
    /// refused, a pin taken from chain state wins over a saved one, and a
    /// saved pin never loosens a held one.
    #[test]
    fn pins_survive_a_restart() {
        let machine = TestMachineKey::from_seed(4);
        let did = machine.did();
        let machine_pq = TestMachinePq::generate();
        let other = TestMachinePq::generate();

        let mut book = RecordBook::new();
        assert!(
            book.offer(&did, bound(&machine, &machine_pq, 2), NOW)
                .unwrap()
        );
        let dir = std::env::temp_dir().join(format!("tenzro-pins-{}", std::process::id()));
        let path = dir.join("pq-pins.json");
        save_pins(&path, &book.saved_pq_pins()).unwrap();

        let mut restarted = RecordBook::new();
        restarted.restore_pq_pins(load_pins(&path).unwrap());
        assert_eq!(
            restarted.offer(&did, record(&machine, 3), NOW),
            Err(RecordError::PqBindingMissing)
        );
        assert_eq!(
            restarted.offer(&did, bound(&machine, &other, 3), NOW),
            Err(RecordError::PqKeyChanged)
        );
        assert!(
            restarted
                .offer(&did, bound(&machine, &machine_pq, 4), NOW)
                .unwrap()
        );

        // Chain state named another key before the saved pins were read.
        let mut chain_first = RecordBook::new();
        chain_first.pin_pq_key(&did, other.public_key().unwrap());
        chain_first.restore_pq_pins(load_pins(&path).unwrap());
        assert_eq!(
            chain_first.pinned_pq_key(&did),
            Some(other.public_key().unwrap().as_slice())
        );

        let mut pins = PqPins::new();
        let before = pins.changes();
        pins.restore(vec![SavedPin {
            did: did.clone(),
            key: machine_pq.public_key().unwrap(),
            required: false,
        }]);
        pins.restore(load_pins(&path).unwrap());
        assert!(pins.changes() > before);
        assert_eq!(
            pins.check(&did, &record(&machine, 5)),
            Err(RecordError::PqBindingMissing)
        );
        pins.restore(vec![SavedPin {
            did: did.clone(),
            key: machine_pq.public_key().unwrap(),
            required: false,
        }]);
        assert_eq!(
            pins.check(&did, &record(&machine, 6)),
            Err(RecordError::PqBindingMissing)
        );

        assert!(load_pins(&dir.join("missing.json")).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Forging the P-256 signature alone gives a record with no binding, or
    /// one bound by another ML-DSA key: both are refused once the identity's
    /// key is pinned, by the pins and by a record book.
    #[test]
    fn a_binding_cannot_be_stripped_or_replaced_once_pinned() {
        let machine = TestMachineKey::from_seed(2);
        let did = machine.did();
        let machine_pq = TestMachinePq::generate();

        let mut pins = PqPins::new();
        pins.check(&did, &record(&machine, 1)).unwrap();
        pins.check(&did, &bound(&machine, &machine_pq, 2)).unwrap();
        assert!(pins.get(&did).is_some());
        assert_eq!(
            pins.check(&did, &record(&machine, 3)),
            Err(RecordError::PqBindingMissing)
        );
        let other = TestMachinePq::generate();
        assert_eq!(
            pins.check(&did, &bound(&machine, &other, 3)),
            Err(RecordError::PqKeyChanged)
        );

        let mut book = RecordBook::new();
        assert!(
            book.offer(&did, bound(&machine, &machine_pq, 2), NOW)
                .unwrap()
        );
        assert_eq!(
            book.offer(&did, record(&machine, 3), NOW),
            Err(RecordError::PqBindingMissing)
        );
        assert_eq!(
            book.offer(&did, bound(&machine, &other, 3), NOW),
            Err(RecordError::PqKeyChanged)
        );
        assert!(
            book.offer(&did, bound(&machine, &machine_pq, 3), NOW)
                .unwrap()
        );

        // An identity that never bound a record keeps working without one.
        let plain = TestMachineKey::from_seed(3);
        assert!(book.offer(&plain.did(), record(&plain, 1), NOW).unwrap());
        assert!(book.offer(&plain.did(), record(&plain, 2), NOW).unwrap());
    }

    #[derive(Clone)]
    struct Acceptor {
        own: ChannelKeys,
        peer: Option<EndpointRecord>,
        done: tokio::sync::mpsc::UnboundedSender<IrohResult<()>>,
    }

    impl std::fmt::Debug for Acceptor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Acceptor")
        }
    }

    impl ProtocolHandler for Acceptor {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            let r = authenticate_acceptor(&conn, &self.own, self.peer.as_ref()).await;
            if r.is_err() {
                conn.close(1u32.into(), b"ml-dsa endpoint authentication failed");
            }
            let _ = self.done.send(r);
            conn.closed().await;
            Ok(())
        }
    }

    fn channel_keys(machine: &Arc<TestMachineKey>, pq: &Arc<TestMachinePq>) -> ChannelKeys {
        ChannelKeys {
            p256: machine.clone(),
            ml_dsa: pq.clone(),
        }
    }

    struct Pair {
        _router: Router,
        server: Endpoint,
        client: Endpoint,
        client_record: EndpointRecord,
        server_record: EndpointRecord,
        client_keys: ChannelKeys,
        done: tokio::sync::mpsc::UnboundedReceiver<IrohResult<()>>,
    }

    /// A server that knows the client by `known` (its bound record, no
    /// record, or an unbound one), and a client with bound records.
    async fn pair_knowing(known: impl FnOnce(&EndpointRecord) -> Option<EndpointRecord>) -> Pair {
        let server_machine = Arc::new(TestMachineKey::from_seed(4));
        let server_pq = Arc::new(TestMachinePq::generate());
        let client_machine = Arc::new(TestMachineKey::from_seed(5));
        let client_pq = Arc::new(TestMachinePq::generate());
        let server_record = bound(&server_machine, &server_pq, 1);
        let client_record = bound(&client_machine, &client_pq, 1);
        let (tx, done) = tokio::sync::mpsc::unbounded_channel();
        let server = Endpoint::bind(presets::Minimal).await.unwrap();
        let router = Router::builder(server.clone())
            .accept(
                ALPN,
                Acceptor {
                    own: channel_keys(&server_machine, &server_pq),
                    peer: known(&client_record),
                    done: tx,
                },
            )
            .spawn();
        let client = Endpoint::bind(presets::Minimal).await.unwrap();
        Pair {
            _router: router,
            server,
            client,
            client_keys: channel_keys(&client_machine, &client_pq),
            client_record,
            server_record,
            done,
        }
    }

    async fn pair() -> Pair {
        pair_knowing(|r| Some(r.clone())).await
    }

    #[tokio::test]
    async fn two_peers_prove_both_hardware_keys_over_the_connection() {
        let mut p = pair().await;
        let conn = p.client.connect(p.server.addr(), ALPN).await.unwrap();
        authenticate_dialer(&conn, &p.client_keys, &p.server_record)
            .await
            .unwrap();
        p.done.recv().await.unwrap().unwrap();
        conn.close(0u32.into(), b"done");
    }

    /// A dialer that holds the P-256 key but not the ML-DSA key the record
    /// binds is refused, and a proof made on one connection does not verify
    /// on another.
    #[tokio::test]
    async fn a_proof_by_another_key_or_from_another_connection_is_refused() {
        let mut p = pair().await;
        let conn = p.client.connect(p.server.addr(), ALPN).await.unwrap();
        // The client's real P-256 key with an ML-DSA key the record does not bind.
        let stolen_p256 = ChannelKeys {
            p256: p.client_keys.p256.clone(),
            ml_dsa: Arc::new(TestMachinePq::generate()),
        };
        assert!(
            authenticate_dialer(&conn, &stolen_p256, &p.server_record)
                .await
                .is_err()
        );
        assert!(p.done.recv().await.unwrap().is_err());
        conn.close(0u32.into(), b"done");

        let a = p.client.connect(p.server.addr(), ALPN).await.unwrap();
        let b = p.client.connect(p.server.addr(), ALPN).await.unwrap();
        let on_a = prove(&p.client_keys, &exporter(&a, DIALER).unwrap()).unwrap();
        verify_channel_proof(&p.client_record, &exporter(&a, DIALER).unwrap(), &on_a).unwrap();
        assert!(
            verify_channel_proof(&p.client_record, &exporter(&b, DIALER).unwrap(), &on_a).is_err()
        );
        // Nor does the dialer's proof pass as the acceptor's.
        assert!(
            verify_channel_proof(&p.client_record, &exporter(&a, ACCEPTOR).unwrap(), &on_a)
                .is_err()
        );
        // A proof with only its P-256 leg, or with the ML-DSA leg cut, fails.
        let p256_len = u16::from_be_bytes([on_a[0], on_a[1]]) as usize;
        assert!(
            verify_channel_proof(
                &p.client_record,
                &exporter(&a, DIALER).unwrap(),
                &on_a[..2 + p256_len]
            )
            .is_err()
        );
        let mut flipped = on_a.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(
            verify_channel_proof(&p.client_record, &exporter(&a, DIALER).unwrap(), &flipped)
                .is_err()
        );
        a.close(0u32.into(), b"done");
        b.close(0u32.into(), b"done");
    }

    /// A peer that authenticates with Ed25519 and P-256 alone is refused: a
    /// dialer the acceptor holds no record for, a dialer whose record carries
    /// no ML-DSA binding, and an acceptor whose record carries none.
    #[tokio::test]
    async fn a_classical_only_peer_is_refused() {
        // The acceptor holds no record of the dialer.
        let mut p = pair_knowing(|_| None).await;
        let conn = p.client.connect(p.server.addr(), ALPN).await.unwrap();
        let _ = authenticate_dialer(&conn, &p.client_keys, &p.server_record).await;
        let err = p.done.recv().await.unwrap().unwrap_err();
        assert!(err.to_string().contains("classical-only"), "{err}");
        conn.close(0u32.into(), b"done");

        // The acceptor's record of the dialer has no ML-DSA binding.
        let mut p = pair_knowing(|r| {
            let mut unbound = r.clone();
            unbound.pq = None;
            Some(unbound)
        })
        .await;
        let conn = p.client.connect(p.server.addr(), ALPN).await.unwrap();
        let _ = authenticate_dialer(&conn, &p.client_keys, &p.server_record).await;
        let err = p.done.recv().await.unwrap().unwrap_err();
        assert!(err.to_string().contains("no ML-DSA binding"), "{err}");
        conn.close(0u32.into(), b"done");

        // The dialer's record of the acceptor has no ML-DSA binding: it does
        // not dial.
        let p = pair().await;
        let conn = p.client.connect(p.server.addr(), ALPN).await.unwrap();
        let mut unbound = p.server_record.clone();
        unbound.pq = None;
        let err = authenticate_dialer(&conn, &p.client_keys, &unbound)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no ML-DSA binding"), "{err}");
        conn.close(0u32.into(), b"done");
    }

    /// A channel without hardware keys neither accepts nor dials.
    #[tokio::test]
    async fn a_channel_with_no_hardware_keys_authenticates_nobody() {
        let p = pair().await;
        let channel = PqChannel::new(Arc::new(DiscoveryStore::new()));
        let conn = p.client.connect(p.server.addr(), ALPN).await.unwrap();
        let err = channel.dial(&conn, &p.server_record).await.unwrap_err();
        assert!(err.to_string().contains("no channel keys"), "{err}");
        let err = channel.accept(&conn).await.unwrap_err();
        assert!(err.to_string().contains("no channel keys"), "{err}");
        conn.close(0u32.into(), b"done");
    }

    /// A key pinned from chain is the only one an identity may bind its
    /// records with, from its first record on, so seeing a forged record
    /// first pins nothing. A node not yet binding its records (an older
    /// build) stays reachable until it presents a bound record; from then
    /// a record without the binding is refused.
    #[test]
    fn a_chain_pin_refuses_another_key_and_keeps_an_unbound_node_reachable() {
        let machine = TestMachineKey::from_seed(6);
        let did = machine.did();
        let registered = TestMachinePq::generate();
        let mut book = RecordBook::new();
        book.pin_pq_key(&did, registered.public_key().unwrap());

        assert!(book.offer(&did, record(&machine, 1), NOW).unwrap());
        assert_eq!(
            book.offer(&did, bound(&machine, &TestMachinePq::generate(), 2), NOW),
            Err(RecordError::PqKeyChanged)
        );
        assert!(
            book.offer(&did, bound(&machine, &registered, 3), NOW)
                .unwrap()
        );
        assert_eq!(
            book.offer(&did, record(&machine, 4), NOW),
            Err(RecordError::PqBindingMissing)
        );
        // Pinning the same key again from chain keeps the binding required.
        book.pin_pq_key(&did, registered.public_key().unwrap());
        assert_eq!(
            book.offer(&did, record(&machine, 5), NOW),
            Err(RecordError::PqBindingMissing)
        );
    }
}
