//! Signed inference receipts.
//!
//! A node that serves a chat completion signs a receipt over what it served:
//! the model and its identity as the signed catalog states it (the hash of
//! the weights and the engine that runs them), the machine that served it,
//! the caller's nonce, a commitment to the input the engine was given, a hash
//! of the output, the billable units it claims, the sampling parameters and
//! seed it decoded with, and the hash of the decode commitment when one was
//! produced. A node without a catalog identity for the model, or without a
//! machine identity, signs no receipt. It signs with an in-memory
//! session key certified by its hardware identity key, the key a gateway
//! resolves from the identity registry for the machine DID the provider's
//! gossip announcement is signed as; the receipt carries the certificate, so
//! the gateway checks both against that key.
//!
//! A gateway forwarding to that provider uses the receipt two ways:
//!
//! * **Billing.** The units a provider reports are only billed when a receipt
//!   signed by the pinned key binds them to this request's nonce and to the
//!   output the gateway actually received. They are then capped against the
//!   request itself (see [`crate::forward_billing`]).
//! * **Disputes.** The receipt carries the seed, the sampling parameters and
//!   the commitment hash, so a challenge committee re-executing the request
//!   knows exactly which decode the provider claimed, and the provider cannot
//!   later deny having served it.
//!
//! A receipt also verifies on its own, with nothing but the catalog entry of
//! the model it names ([`InferenceReceipt::verify_offline`]): the signature
//! is checked against the key and session certificate it carries, at the time
//! it was signed, and the model hash against the one the catalog states.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::batch::{RecordSignature, RecordSigner};
use tenzro_crypto::composite::CompositePublicKey;
use tenzro_types::inference_verification::VerificationLevel;
use tenzro_types::model::BillableUnits;

// The receipt preimage's domain tag and field encoding are shared with
// consensus, which checks a filed fault against them.
use tenzro_types::inference_verification::{
    INFERENCE_RECEIPT_DOMAIN as RECEIPT_DOMAIN, put_receipt_field, receipt_preimage_tail,
};
/// Domain tag of [`model_hash_of`].
const MODEL_HASH_DOMAIN: &[u8] = b"tenzro/model-hash";
/// Domain tag of [`input_commitment`].
const INPUT_COMMITMENT_DOMAIN: &[u8] = b"tenzro/inference-input";
/// Domain tag of [`prompt_commitment`], so a raw prompt never commits like a
/// conversation.
const PROMPT_COMMITMENT_DOMAIN: &[u8] = b"tenzro/inference-input/prompt";
/// Domain tag of [`InferenceReceipt::tee_binding`].
const TEE_BINDING_DOMAIN: &[u8] = b"tenzro/inference-receipt/tee-binding";
/// Domain tag of [`upstream_identity`].
const UPSTREAM_MODEL_DOMAIN: &[u8] = b"tenzro/model-hash/upstream";
/// The engine a receipt names for a model served from an operator's own
/// endpoint ([`crate::connector`]).
pub const UPSTREAM_ENGINE: &str = "upstream";

/// A confidential-compute attestation over one served completion. The
/// report's user data is [`InferenceReceipt::tee_binding`], so the hardware
/// signature over the report covers the model hash and the input and output
/// commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeEvidence {
    pub report: tenzro_types::tee::AttestationReport,
}

impl TeeEvidence {
    /// SHA-256 over the report's canonical encoding, bound into the receipt
    /// signature so the evidence cannot be swapped for another report.
    fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(&self.report).unwrap_or_default(),
        ))
    }
}

/// A model's identity as its signed catalog entry states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelIdentity {
    /// [`model_hash_of`] the entry.
    pub model_hash: String,
    /// The engine family that runs it, as the entry names it.
    pub engine: String,
}

/// The hash that identifies a model's weights: SHA-256 over every file the
/// catalog entry lists, in `(repo, path)` order, each as its repository, path
/// and the SHA-256 its bytes must have. Any change to any weight file, or a
/// file added or dropped, changes it.
pub fn model_hash_of(entry: &tenzro_model::catalog::CatalogEntry) -> String {
    let mut files: Vec<&tenzro_model::catalog::Component> = entry.components.iter().collect();
    files.sort_by(|a, b| (&a.repo, &a.path).cmp(&(&b.repo, &b.path)));
    let mut buf = MODEL_HASH_DOMAIN.to_vec();
    for c in files {
        put_str(&mut buf, &c.repo);
        put_str(&mut buf, &c.path);
        put_str(&mut buf, &c.sha256);
    }
    hex::encode(Sha256::digest(&buf))
}

/// The identity of `model_id` in this node's installed catalog. `None` for a
/// model the catalog does not list or lists without files.
pub fn catalog_identity(model_id: &str) -> Option<ModelIdentity> {
    let entry = tenzro_model::catalog::entry(model_id)?;
    if entry.components.is_empty() {
        return None;
    }
    Some(ModelIdentity {
        model_hash: model_hash_of(&entry),
        engine: entry.model.engine().to_string(),
    })
}

/// The identity of a model the catalog does not list, served from an
/// operator's own endpoint ([`crate::connector`]). The network pins no
/// weights for it, so the identity is its id alone under the engine
/// [`UPSTREAM_ENGINE`]: a receipt for it binds the call, the output and the
/// units, and says no more about the weights than the id does.
pub fn upstream_identity(model_id: &str) -> ModelIdentity {
    let mut buf = UPSTREAM_MODEL_DOMAIN.to_vec();
    put_str(&mut buf, model_id);
    ModelIdentity {
        model_hash: hex::encode(Sha256::digest(&buf)),
        engine: UPSTREAM_ENGINE.to_string(),
    }
}

/// The identity a receipt for `model_id` must name: the catalog's, for a
/// model the catalog lists (`None` when it lists it without files), and
/// [`upstream_identity`] for one it does not.
pub fn expected_identity(model_id: &str) -> Option<ModelIdentity> {
    match tenzro_model::catalog::entry(model_id) {
        Some(_) => catalog_identity(model_id),
        None => Some(upstream_identity(model_id)),
    }
}

/// SHA-256 over the exact input the engine was given: the conversation in
/// its canonical JSON encoding, then every attached media item's bytes,
/// length-prefixed. Two providers given the same request derive the same
/// engine input, so their commitments agree.
pub fn input_commitment(messages: &[tenzro_model::ChatMessage], media: &[Vec<u8>]) -> String {
    let mut h = Sha256::new();
    h.update(INPUT_COMMITMENT_DOMAIN);
    let encoded = serde_json::to_vec(messages).unwrap_or_default();
    h.update((encoded.len() as u64).to_le_bytes());
    h.update(&encoded);
    for item in media {
        h.update((item.len() as u64).to_le_bytes());
        h.update(item);
    }
    hex::encode(h.finalize())
}

/// The input commitment of a raw completion, where the engine was given
/// `prompt` as it is, with no chat template.
pub fn prompt_commitment(prompt: &str) -> String {
    let mut h = Sha256::new();
    h.update(PROMPT_COMMITMENT_DOMAIN);
    h.update((prompt.len() as u64).to_le_bytes());
    h.update(prompt.as_bytes());
    hex::encode(h.finalize())
}

/// The sampling configuration a completion was decoded with. Bound into the
/// receipt so a verifier replays the same sampler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SamplingParams {
    pub seed: u64,
    pub temperature: f64,
    pub top_p: f64,
    pub top_k: Option<u32>,
    pub min_p: Option<f64>,
    pub max_output_tokens: u32,
    /// Whether tokens were drawn by the keyed sampler, so a verifier holding
    /// the seed can recompute each draw from the logits
    /// ([`crate::decode_check`]).
    pub keyed_sampler: bool,
}

/// The decode a receipt was produced under, beyond the weights and seed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodeContext {
    /// The weights' numeric format as the catalog states it (`Q4_K_M`,
    /// `BF16`, ...).
    pub precision: String,
    /// The build of the engine that ran it.
    pub engine_version: String,
    /// The accelerator backend it ran on (`cpu`, `cuda`, `metal`, ...).
    pub hardware_class: String,
}

impl DecodeContext {
    /// A decode the operator's own endpoint ran: no precision the catalog
    /// states, and the hardware class [`UPSTREAM_ENGINE`].
    pub fn upstream() -> Self {
        Self {
            precision: String::new(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            hardware_class: UPSTREAM_ENGINE.to_string(),
        }
    }

    /// This node's decode of `model_id`.
    pub fn of_this_node(model_id: &str) -> Self {
        let backend = if cfg!(feature = "cuda") || cfg!(feature = "cuda-no-vmm") {
            "cuda"
        } else if cfg!(feature = "rocm") {
            "rocm"
        } else if cfg!(feature = "metal") {
            "metal"
        } else if cfg!(feature = "vulkan") {
            "vulkan"
        } else {
            "cpu"
        };
        Self {
            precision: tenzro_model::get_model_by_id(model_id)
                .map(|e| e.quantization)
                .unwrap_or_default(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            hardware_class: backend.to_string(),
        }
    }
}

/// A provider's signed statement about one completion it served.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceReceipt {
    pub model_id: String,
    /// [`model_hash_of`] the catalog entry the provider served from.
    pub model_hash: String,
    /// The engine family that ran the model.
    pub engine: String,
    /// The serving machine's hardware-derived identity,
    /// `did:tenzro:machine:...`.
    pub machine_did: String,
    /// The gateway's per-request nonce, echoed back. Binds the receipt to one
    /// forwarded request so it cannot be replayed onto another.
    pub nonce: String,
    /// [`input_commitment`] over what the engine was given.
    pub input_commitment: String,
    /// SHA-256 over the served output, see [`output_hash`].
    pub output_hash: String,
    pub units: BillableUnits,
    /// The anchored price card the units are charged on, the rate a USD card
    /// converted at, and the charge, when this node's operator anchored a
    /// card for the model.
    #[serde(default)]
    pub priced: Option<crate::inference_pricing::PricedOn>,
    /// Content hashes of what the call used beyond the model itself, such as
    /// a dataset or adapter a card line pays a licensor for.
    #[serde(default)]
    pub provenance: Vec<String>,
    pub sampling: SamplingParams,
    /// What a re-execution on other hardware must match besides the weights
    /// and the seed: the numeric precision the engine ran at, the engine
    /// build, and the hardware class it ran on.
    #[serde(default)]
    pub decode: DecodeContext,
    /// Hash of the decode commitment, when the request asked for one.
    pub commitment_hash: Option<String>,
    /// The confidential-compute attestation, when the request asked for the
    /// TEE level.
    pub tee: Option<TeeEvidence>,
    /// Reserved for a commitment to the model's intermediate activations on
    /// this request, so a check that the stated weights produced the answer
    /// can land without a receipt format change. `None` until the engine
    /// produces one; signed either way, so it cannot be added or stripped
    /// after signing.
    pub activation_fingerprint: Option<String>,
    pub signed_at_ms: u64,
    /// The signing node's hardware identity key.
    pub public_key: CompositePublicKey,
    /// Signature over [`InferenceReceipt::preimage`] by a session key that
    /// `public_key` certified.
    pub signature: RecordSignature,
}

/// Why a receipt was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    #[error("receipt is signed by a key other than the provider's announced key")]
    KeyMismatch,
    #[error("receipt signature does not verify")]
    BadSignature,
    #[error("receipt is for model {0}, not the routed model")]
    ModelMismatch(String),
    #[error("receipt nonce does not match this request")]
    NonceMismatch,
    #[error("receipt output hash does not match the output received")]
    OutputMismatch,
    #[error("receipt units differ from the usage the provider reported")]
    UnitsMismatch,
    #[error("receipt names model hash {0}, not the one the catalog states for the model")]
    ModelHashMismatch(String),
    #[error("the catalog states no identity for model {0}")]
    UnknownModel(String),
    #[error("receipt carries no TEE attestation")]
    NoTeeEvidence,
    #[error("TEE attestation refused: {0}")]
    BadTeeEvidence(String),
    #[error("receipt is malformed: {0}")]
    Malformed(String),
}

/// Everything a receipt states, before it is signed.
#[derive(Debug, Clone)]
pub struct ReceiptClaims {
    pub decode: DecodeContext,
    pub model_id: String,
    pub identity: ModelIdentity,
    pub machine_did: String,
    pub nonce: String,
    pub input_commitment: String,
    pub output_hash: String,
    pub units: BillableUnits,
    pub priced: Option<crate::inference_pricing::PricedOn>,
    pub provenance: Vec<String>,
    pub sampling: SamplingParams,
    pub commitment_hash: Option<String>,
    pub tee: Option<TeeEvidence>,
    /// See [`InferenceReceipt::activation_fingerprint`].
    pub activation_fingerprint: Option<String>,
}

/// The receipt fields a TEE report binds.
struct ReceiptBinding<'a> {
    model_id: &'a str,
    model_hash: &'a str,
    engine: &'a str,
    machine_did: &'a str,
    nonce: &'a str,
    input_commitment: &'a str,
    output_hash: &'a str,
    public_key: &'a CompositePublicKey,
}

fn tee_binding_of(b: &ReceiptBinding<'_>) -> [u8; 32] {
    let mut buf = TEE_BINDING_DOMAIN.to_vec();
    for s in [
        b.model_id,
        b.model_hash,
        b.engine,
        b.machine_did,
        b.nonce,
        b.input_commitment,
        b.output_hash,
    ] {
        put_str(&mut buf, s);
    }
    put_key(&mut buf, b.public_key);
    Sha256::digest(&buf).into()
}

/// SHA-256 over what a completion returned: the visible text, the reasoning
/// and the tool calls, each length-prefixed so no two different outputs
/// share a preimage. Both sides compute it from the same three strings.
pub fn output_hash(text: &str, reasoning: &str, tool_calls_json: &str) -> String {
    let mut h = Sha256::new();
    for part in [text, reasoning, tool_calls_json] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(h.finalize())
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    put_receipt_field(buf, b);
}

/// A composite key: its P-256 point, then its ML-DSA-65 key (empty when it
/// has none).
fn put_key(buf: &mut Vec<u8>, key: &CompositePublicKey) {
    put_bytes(buf, &key.p256);
    put_bytes(buf, key.pq.as_deref().unwrap_or_default());
}

/// The signed fields of a receipt.
struct Unsigned<'a> {
    model_id: &'a str,
    model_hash: &'a str,
    engine: &'a str,
    machine_did: &'a str,
    nonce: &'a str,
    input_commitment: &'a str,
    output_hash: &'a str,
    units: &'a BillableUnits,
    priced: Option<&'a crate::inference_pricing::PricedOn>,
    provenance: &'a [String],
    sampling: &'a SamplingParams,
    decode: &'a DecodeContext,
    commitment_hash: Option<&'a str>,
    tee: Option<&'a TeeEvidence>,
    activation_fingerprint: Option<&'a str>,
    signed_at_ms: u64,
    public_key: &'a CompositePublicKey,
}

impl Unsigned<'_> {
    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(RECEIPT_DOMAIN);
        put_str(&mut buf, self.model_id);
        put_str(&mut buf, self.model_hash);
        put_str(&mut buf, self.engine);
        put_str(&mut buf, self.machine_did);
        put_str(&mut buf, self.nonce);
        put_str(&mut buf, self.input_commitment);
        put_str(&mut buf, self.output_hash);
        put_bytes(&mut buf, &self.units.canonical_bytes());
        match self.priced {
            Some(p) => {
                buf.push(1);
                put_str(&mut buf, &p.card);
                buf.extend_from_slice(&p.rate_nano_usd.to_le_bytes());
                buf.extend_from_slice(&p.charge.to_le_bytes());
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&(self.provenance.len() as u32).to_le_bytes());
        for h in self.provenance {
            put_str(&mut buf, h);
        }
        let s = self.sampling;
        buf.extend_from_slice(&s.seed.to_le_bytes());
        buf.extend_from_slice(&s.temperature.to_bits().to_le_bytes());
        buf.extend_from_slice(&s.top_p.to_bits().to_le_bytes());
        buf.extend_from_slice(&s.top_k.map_or(u64::MAX, u64::from).to_le_bytes());
        buf.extend_from_slice(&s.min_p.map_or(u64::MAX, f64::to_bits).to_le_bytes());
        buf.extend_from_slice(&s.max_output_tokens.to_le_bytes());
        buf.push(s.keyed_sampler as u8);
        put_str(&mut buf, &self.decode.precision);
        put_str(&mut buf, &self.decode.engine_version);
        put_str(&mut buf, &self.decode.hardware_class);
        put_str(&mut buf, self.commitment_hash.unwrap_or(""));
        put_str(
            &mut buf,
            &self.tee.map(TeeEvidence::digest).unwrap_or_default(),
        );
        put_str(&mut buf, self.activation_fingerprint.unwrap_or(""));
        // The tail consensus checks a filed fault against: when it was signed,
        // and the signer's identity key.
        buf.extend_from_slice(&receipt_preimage_tail(
            self.signed_at_ms,
            &self.public_key.p256,
            self.public_key.pq.as_deref(),
        ));
        buf
    }
}

impl InferenceReceipt {
    /// The exact bytes the signature covers. Every field except the signature
    /// itself, in a fixed order with fixed-width or length-prefixed encoding.
    pub fn preimage(&self) -> Vec<u8> {
        Unsigned {
            model_id: &self.model_id,
            model_hash: &self.model_hash,
            engine: &self.engine,
            machine_did: &self.machine_did,
            nonce: &self.nonce,
            input_commitment: &self.input_commitment,
            output_hash: &self.output_hash,
            units: &self.units,
            priced: self.priced.as_ref(),
            provenance: &self.provenance,
            sampling: &self.sampling,
            decode: &self.decode,
            commitment_hash: self.commitment_hash.as_deref(),
            tee: self.tee.as_ref(),
            activation_fingerprint: self.activation_fingerprint.as_deref(),
            signed_at_ms: self.signed_at_ms,
            public_key: &self.public_key,
        }
        .preimage()
    }

    /// SHA-256 of the signed preimage: the receipt's identity, the same for
    /// every holder of it.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.preimage()))
    }

    /// Sign a receipt with the node's session key, certified by its
    /// hardware identity key.
    pub fn sign(signer: &dyn RecordSigner, claims: ReceiptClaims) -> Result<Self, ReceiptError> {
        let public_key = signer.identity().clone();
        let signed_at_ms = tenzro_crypto::session::now_ms();
        let preimage = Unsigned {
            model_id: &claims.model_id,
            model_hash: &claims.identity.model_hash,
            engine: &claims.identity.engine,
            machine_did: &claims.machine_did,
            nonce: &claims.nonce,
            input_commitment: &claims.input_commitment,
            output_hash: &claims.output_hash,
            units: &claims.units,
            priced: claims.priced.as_ref(),
            provenance: &claims.provenance,
            sampling: &claims.sampling,
            decode: &claims.decode,
            commitment_hash: claims.commitment_hash.as_deref(),
            tee: claims.tee.as_ref(),
            activation_fingerprint: claims.activation_fingerprint.as_deref(),
            signed_at_ms,
            public_key: &public_key,
        }
        .preimage();
        let signature = signer
            .sign_record(&preimage)
            .map_err(|e| ReceiptError::Malformed(e.to_string()))?;
        Ok(Self {
            model_id: claims.model_id,
            model_hash: claims.identity.model_hash,
            engine: claims.identity.engine,
            machine_did: claims.machine_did,
            nonce: claims.nonce,
            input_commitment: claims.input_commitment,
            output_hash: claims.output_hash,
            units: claims.units,
            priced: claims.priced,
            provenance: claims.provenance,
            sampling: claims.sampling,
            decode: claims.decode,
            commitment_hash: claims.commitment_hash,
            tee: claims.tee,
            activation_fingerprint: claims.activation_fingerprint,
            signed_at_ms,
            public_key,
            signature,
        })
    }

    /// Verify the receipt with nothing but `catalog_model_hash`, the hash
    /// the catalog states for the model it names: the signature against the
    /// key and session certificate the receipt carries, as of when it was
    /// signed, and the model hash against the catalog's.
    pub fn verify_offline(&self, catalog_model_hash: &str) -> Result<(), ReceiptError> {
        self.signature
            .verify_record_at(&self.public_key, &self.preimage(), self.signed_at_ms)
            .map_err(|_| ReceiptError::BadSignature)?;
        if self.model_hash != catalog_model_hash {
            return Err(ReceiptError::ModelHashMismatch(self.model_hash.clone()));
        }
        if self.machine_did.is_empty() || self.input_commitment.is_empty() {
            return Err(ReceiptError::Malformed(
                "a receipt names the serving machine and commits to its input".to_string(),
            ));
        }
        Ok(())
    }

    /// The 32 bytes a TEE report for this receipt carries as its user data:
    /// SHA-256 over the model, its hash and engine, the serving machine, the
    /// nonce, the input and output commitments and the signing key.
    pub fn tee_binding(&self) -> [u8; 32] {
        tee_binding_of(&ReceiptBinding {
            model_id: &self.model_id,
            model_hash: &self.model_hash,
            engine: &self.engine,
            machine_did: &self.machine_did,
            nonce: &self.nonce,
            input_commitment: &self.input_commitment,
            output_hash: &self.output_hash,
            public_key: &self.public_key,
        })
    }

    /// Check the receipt's TEE evidence end to end: the report verifies
    /// against the vendor's roots as of when the receipt was signed, its user
    /// data is this receipt's [`Self::tee_binding`], and the launch
    /// measurement it proves is in `log`, the attestation transparency log.
    /// The receipt signature (which covers the report) is checked separately,
    /// by [`Self::verify_offline`] or [`Self::verify_signature`].
    pub fn verify_tee(
        &self,
        log: &tenzro_tee::verify::transparency::TransparencyLog,
    ) -> Result<tenzro_tee::VerifiedAttestation, ReceiptError> {
        let evidence = self.tee.as_ref().ok_or(ReceiptError::NoTeeEvidence)?;
        let report = &evidence.report;
        let expected =
            tenzro_types::tee::pack_user_data_for_vendor(report.vendor, &self.tee_binding());
        let mut policy = tenzro_tee::VerifyPolicy::now(expected);
        policy.now = self.signed_at_ms / 1000;
        let verified = tenzro_tee::verify_report(report, &policy)
            .map_err(|e| ReceiptError::BadTeeEvidence(e.to_string()))?;
        if !log.contains_measurement(verified.vendor, &verified.measurement) {
            return Err(ReceiptError::BadTeeEvidence(
                "the attested measurement is not in the attestation transparency log".to_string(),
            ));
        }
        Ok(verified)
    }

    /// [`Self::verify_offline`] against this node's installed catalog, or for
    /// a model the catalog does not list, against [`upstream_identity`].
    pub fn verify_against_catalog(&self) -> Result<(), ReceiptError> {
        let identity = expected_identity(&self.model_id)
            .ok_or_else(|| ReceiptError::UnknownModel(self.model_id.clone()))?;
        self.verify_offline(&identity.model_hash)
    }

    /// Check the signature, and that it was made by `pinned_key`: the
    /// hardware identity key registered for the provider's machine DID, both
    /// legs.
    pub fn verify_signature(&self, pinned_key: &CompositePublicKey) -> Result<(), ReceiptError> {
        if self.public_key != *pinned_key {
            return Err(ReceiptError::KeyMismatch);
        }
        self.signature
            .verify_now(&self.public_key, &self.preimage())
            .map_err(|_| ReceiptError::BadSignature)
    }

    /// Everything a gateway checks before it bills from a receipt: the
    /// provider's pinned key signed it, it names the routed model with the
    /// identity `expected` (from the gateway's own catalog), it carries the
    /// serving machine and an input commitment, it names this request's
    /// nonce, it hashes the output the gateway received, and its units are
    /// the ones the provider's usage block reported.
    pub fn verify_for_forward(
        &self,
        pinned_key: &CompositePublicKey,
        model_id: &str,
        expected: &ModelIdentity,
        nonce: &str,
        received_output_hash: &str,
        reported_units: &BillableUnits,
    ) -> Result<(), ReceiptError> {
        self.verify_signature(pinned_key)?;
        if self.model_id != model_id {
            return Err(ReceiptError::ModelMismatch(self.model_id.clone()));
        }
        if self.model_hash != expected.model_hash || self.engine != expected.engine {
            return Err(ReceiptError::ModelHashMismatch(self.model_hash.clone()));
        }
        if self.machine_did.is_empty() || self.input_commitment.is_empty() {
            return Err(ReceiptError::Malformed(
                "a receipt names the serving machine and commits to its input".to_string(),
            ));
        }
        if self.nonce != nonce {
            return Err(ReceiptError::NonceMismatch);
        }
        if self.output_hash != received_output_hash {
            return Err(ReceiptError::OutputMismatch);
        }
        if &self.units != reported_units {
            return Err(ReceiptError::UnitsMismatch);
        }
        Ok(())
    }
}

impl SamplingParams {
    /// The parameters a generation config decodes with.
    pub fn from_config(config: &tenzro_model::GenerationConfig) -> Self {
        Self {
            seed: config.seed,
            temperature: config.temperature,
            top_p: config.top_p,
            top_k: config.top_k,
            min_p: config.min_p,
            max_output_tokens: config.max_tokens,
            // The engine draws with its own generator today; a verifier can
            // only recompute greedy decodes from logits.
            keyed_sampler: false,
        }
    }
}

/// What a served completion's receipt states beyond the node's own identity.
pub struct Served<'a> {
    pub model_id: &'a str,
    pub nonce: Option<&'a str>,
    /// [`input_commitment`] over what the engine was given.
    pub input_commitment: String,
    /// [`output_hash`] over what the response returns.
    pub output_hash: String,
    pub units: BillableUnits,
    pub sampling: SamplingParams,
    pub commitment_hash: Option<String>,
    /// The verification the request asked for.
    pub level: VerificationLevel,
}

/// Sign a receipt for a completion this node served, with its session key.
///
/// At [`VerificationLevel::None`] a receipt is best effort: `Ok(None)` when
/// the node has no hardware identity key, no machine identity, or no catalog
/// identity for the model, in which case a forwarding node bills the
/// per-request floor. At any other level the same gaps are an error, so a
/// caller that asked for evidence never gets an answer without it. At
/// [`VerificationLevel::Tee`] the receipt also carries a report from this
/// node's confidential-compute hardware binding [`InferenceReceipt::tee_binding`].
pub async fn sign_local(
    node: &crate::node::TenzroNode,
    served: Served<'_>,
) -> Result<Option<InferenceReceipt>, ReceiptError> {
    let model_id = served.model_id;
    let level = served.level;
    let missing = |what: &str| {
        let message = format!("cannot sign a receipt for {model_id}: {what}");
        if level.requires_receipt() {
            Err(ReceiptError::Malformed(message))
        } else {
            tracing::warn!(model = %model_id, "{message}");
            Ok(None)
        }
    };
    let Some(signer) = node.records() else {
        return missing("this node has no hardware identity key");
    };
    // A model this node serves from the operator's endpoint has the upstream
    // identity; every other model has the catalog's.
    let upstream = node.upstream_model(model_id).is_some();
    let identity = if upstream {
        Some(upstream_identity(model_id))
    } else {
        catalog_identity(model_id)
    };
    let Some(identity) = identity else {
        return missing("the catalog states no identity for the model");
    };
    let Some(machine_did) = crate::identity_bootstrap::machine_did() else {
        return missing("this machine has no hardware identity");
    };
    let priced = crate::inference_pricing::priced_on(node, model_id, &served.units);
    let mut claims = ReceiptClaims {
        model_id: model_id.to_string(),
        identity,
        machine_did,
        nonce: served.nonce.unwrap_or("").to_string(),
        input_commitment: served.input_commitment,
        output_hash: served.output_hash,
        units: served.units,
        priced,
        provenance: Vec::new(),
        decode: if upstream {
            DecodeContext::upstream()
        } else {
            DecodeContext::of_this_node(model_id)
        },
        sampling: served.sampling,
        commitment_hash: served.commitment_hash,
        tee: None,
        activation_fingerprint: None,
    };
    if level == VerificationLevel::Tee {
        let provider = node.tee_provider().ok_or_else(|| {
            ReceiptError::BadTeeEvidence(
                "TEE verification requested but this node has no confidential compute".to_string(),
            )
        })?;
        claims.tee = Some(attest(provider, &claims, signer.identity()).await?);
    }
    match InferenceReceipt::sign(signer.as_ref(), claims) {
        Ok(r) => Ok(Some(r)),
        Err(e) if level.requires_receipt() => Err(e),
        Err(e) => {
            tracing::warn!(model = %model_id, error = %e, "Failed to sign inference receipt");
            Ok(None)
        }
    }
}

/// Ask `provider` for a report whose user data binds `claims` as they will be
/// signed by `signing_key`.
async fn attest(
    provider: &dyn tenzro_tee::TeeProvider,
    claims: &ReceiptClaims,
    public_key: &CompositePublicKey,
) -> Result<TeeEvidence, ReceiptError> {
    let binding = tee_binding_of(&ReceiptBinding {
        model_id: &claims.model_id,
        model_hash: &claims.identity.model_hash,
        engine: &claims.identity.engine,
        machine_did: &claims.machine_did,
        nonce: &claims.nonce,
        input_commitment: &claims.input_commitment,
        output_hash: &claims.output_hash,
        public_key,
    });
    let report = provider
        .generate_attestation(&binding)
        .await
        .map_err(|e| ReceiptError::BadTeeEvidence(e.to_string()))?;
    Ok(TeeEvidence { report })
}

/// Domain tag of a task commitment.
const TASK_COMMITMENT_DOMAIN: &[u8] = b"tenzro/inference/task/v1";

/// A commitment to what a call other than a chat completion was given or
/// returned: SHA-256 over a domain tag, the task's name (`embed`, `rerank`,
/// `transcribe`, `speech`, ...) and the canonical bytes, each length-prefixed.
/// The task name keeps a commitment for one modality from ever matching one
/// for another.
pub fn task_commitment(task: &str, bytes: &[u8]) -> String {
    let mut buf = TASK_COMMITMENT_DOMAIN.to_vec();
    put_str(&mut buf, task);
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
    hex::encode(Sha256::digest(&buf))
}

/// The sampling a deterministic task runs with: no sampler at all, so a
/// verifier re-runs exactly the served computation.
pub fn deterministic_sampling() -> SamplingParams {
    SamplingParams {
        seed: 0,
        temperature: 0.0,
        top_p: 1.0,
        top_k: None,
        min_p: None,
        max_output_tokens: 0,
        keyed_sampler: false,
    }
}

/// One call other than a chat completion, as its receipt states it.
pub struct ServedTask<'a> {
    pub model_id: &'a str,
    /// The task's name, bound into both commitments.
    pub task: &'a str,
    /// The request's `receipt_nonce`, when the caller sent one.
    pub nonce: Option<&'a str>,
    /// Canonical bytes of what the engine was given.
    pub input: &'a [u8],
    /// Canonical bytes of what the response returns.
    pub output: &'a [u8],
    pub units: BillableUnits,
    /// The sampling the task ran with; [`deterministic_sampling`] for every
    /// task that draws nothing.
    pub sampling: SamplingParams,
    /// The verification the request asked for, admitted before the work.
    pub level: VerificationLevel,
}

/// Sign the receipt of a call other than a chat completion, under the same
/// rules as [`sign_local`]: best effort at [`VerificationLevel::None`], an
/// error at any other level when the node cannot sign.
pub async fn sign_task(
    node: &crate::node::TenzroNode,
    served: ServedTask<'_>,
) -> Result<Option<InferenceReceipt>, ReceiptError> {
    sign_local(
        node,
        Served {
            model_id: served.model_id,
            nonce: served.nonce,
            input_commitment: task_commitment(served.task, served.input),
            output_hash: task_commitment(served.task, served.output),
            units: served.units,
            sampling: served.sampling,
            commitment_hash: None,
            level: served.level,
        },
    )
    .await
}

/// A fresh 128-bit nonce for one forwarded request, hex encoded.
pub fn fresh_nonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::batch::ImmediateRecordSigner;

    #[test]
    fn task_commitments_bind_the_task_and_the_bytes() {
        let a = task_commitment("embed", b"hello");
        assert_eq!(a, task_commitment("embed", b"hello"));
        assert_ne!(a, task_commitment("rerank", b"hello"));
        assert_ne!(a, task_commitment("embed", b"hellp"));
        // Length prefixes: moving a byte across the boundary changes the hash.
        assert_ne!(task_commitment("embe", b"dhello"), a);
    }
    use tenzro_crypto::composite::testing::TestHybridSigner;

    fn session() -> ImmediateRecordSigner {
        ImmediateRecordSigner::new(std::sync::Arc::new(TestHybridSigner::random()))
    }

    fn sampling() -> SamplingParams {
        SamplingParams {
            seed: 7,
            temperature: 0.7,
            top_p: 0.9,
            top_k: Some(40),
            min_p: None,
            max_output_tokens: 64,
            keyed_sampler: false,
        }
    }

    fn identity() -> ModelIdentity {
        ModelIdentity {
            model_hash: "ab".repeat(32),
            engine: "gguf".to_string(),
        }
    }

    fn signed(signer: &dyn RecordSigner) -> InferenceReceipt {
        InferenceReceipt::sign(signer, claims()).unwrap()
    }

    /// Hands back a report carrying whatever user data it is asked to bind,
    /// as a provider's hardware would, signed by no vendor root.
    struct UnrootedTee;

    #[async_trait::async_trait]
    impl tenzro_tee::TeeProvider for UnrootedTee {
        fn vendor(&self) -> tenzro_types::tee::TeeVendor {
            tenzro_types::tee::TeeVendor::IntelTdx
        }
        async fn is_available(&self) -> tenzro_tee::Result<bool> {
            Ok(true)
        }
        async fn generate_attestation(
            &self,
            user_data: &[u8],
        ) -> tenzro_tee::Result<tenzro_types::tee::AttestationReport> {
            Ok(tenzro_types::tee::AttestationReport {
                id: uuid::Uuid::nil(),
                vendor: self.vendor(),
                user_data: user_data.to_vec(),
                attestation_data: Vec::new(),
                certificates: Vec::new(),
                timestamp: tenzro_types::primitives::Timestamp::now(),
                metadata: Default::default(),
                quote: vec![0; 64],
                measurement: vec![7; 48],
                signature: Vec::new(),
                vendor_data: Vec::new(),
            })
        }
        async fn execute_in_enclave(
            &self,
            _request: tenzro_types::tee::EnclaveRequest,
        ) -> tenzro_tee::Result<tenzro_types::tee::EnclaveResponse> {
            Err(tenzro_tee::TeeError::NotAvailable("not used".to_string()))
        }
    }

    async fn tee_signed(signer: &ImmediateRecordSigner) -> InferenceReceipt {
        let mut c = claims();
        c.tee = Some(attest(&UnrootedTee, &c, signer.identity()).await.unwrap());
        InferenceReceipt::sign(signer, c).unwrap()
    }

    #[tokio::test]
    async fn the_tee_report_binds_the_model_hash_and_both_commitments() {
        let signer = session();
        let r = tee_signed(&signer).await;
        assert_eq!(
            r.tee.as_ref().unwrap().report.user_data,
            r.tee_binding().to_vec()
        );
        r.verify_offline(&identity().model_hash).unwrap();
        // The binding moves with each field the report vouches for.
        for edit in [
            |r: &mut InferenceReceipt| r.model_hash = "cd".repeat(32),
            |r: &mut InferenceReceipt| r.input_commitment = "00".repeat(32),
            |r: &mut InferenceReceipt| r.output_hash = "00".repeat(32),
            |r: &mut InferenceReceipt| r.machine_did = "did:tenzro:machine:x".to_string(),
        ] {
            let mut other = r.clone();
            edit(&mut other);
            assert_ne!(other.tee_binding(), r.tee_binding());
        }
    }

    #[tokio::test]
    async fn tee_evidence_cannot_be_swapped_or_dropped_under_the_signature() {
        let signer = session();
        let a = tee_signed(&signer).await;
        let mut b = claims();
        b.output_hash = output_hash("other", "", "");
        b.tee = Some(attest(&UnrootedTee, &b, signer.identity()).await.unwrap());
        let b = InferenceReceipt::sign(&signer, b).unwrap();
        let mut swapped = a.clone();
        swapped.tee = b.tee.clone();
        assert_eq!(
            swapped.verify_offline(&identity().model_hash),
            Err(ReceiptError::BadSignature)
        );
        let mut dropped = a.clone();
        dropped.tee = None;
        assert_eq!(
            dropped.verify_offline(&identity().model_hash),
            Err(ReceiptError::BadSignature)
        );
    }

    #[tokio::test]
    async fn a_report_no_vendor_root_signed_is_refused_and_a_missing_one_named() {
        let log = tenzro_tee::verify::transparency::TransparencyLog::new();
        let r = tee_signed(&session()).await;
        assert!(matches!(
            r.verify_tee(&log),
            Err(ReceiptError::BadTeeEvidence(_))
        ));
        assert_eq!(
            signed(&session()).verify_tee(&log),
            Err(ReceiptError::NoTeeEvidence)
        );
    }

    fn claims() -> ReceiptClaims {
        ReceiptClaims {
            decode: DecodeContext::default(),
            model_id: "m".to_string(),
            identity: identity(),
            machine_did: "did:tenzro:machine:abc".to_string(),
            nonce: "nonce-1".to_string(),
            input_commitment: input_commitment(
                &[tenzro_model::ChatMessage {
                    role: "user".to_string(),
                    content: "hi".to_string(),
                    ..Default::default()
                }],
                &[],
            ),
            output_hash: output_hash("hello", "", ""),
            units: BillableUnits::tokens(10, 5),
            priced: None,
            provenance: Vec::new(),
            sampling: sampling(),
            commitment_hash: None,
            tee: None,
            activation_fingerprint: None,
        }
    }

    #[test]
    fn a_receipt_verifies_against_its_signer_and_request() {
        let signer = session();
        let r = signed(&signer);
        let pk = signer.identity().clone();
        r.verify_for_forward(
            &pk,
            "m",
            &identity(),
            "nonce-1",
            &output_hash("hello", "", ""),
            &BillableUnits::tokens(10, 5),
        )
        .unwrap();
    }

    #[test]
    fn a_receipt_verifies_offline_against_the_catalog_hash_alone() {
        let r = signed(&session());
        // Round-trips through its wire form, as a holder would keep it.
        let r: InferenceReceipt =
            serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
        r.verify_offline(&identity().model_hash).unwrap();
        assert!(matches!(
            r.verify_offline(&"cd".repeat(32)),
            Err(ReceiptError::ModelHashMismatch(_))
        ));
    }

    #[test]
    fn every_bound_identity_field_breaks_the_signature_when_changed() {
        let r = signed(&session());
        let hash = identity().model_hash;
        let edits: [fn(&mut InferenceReceipt); 5] = [
            |r| r.model_hash = "cd".repeat(32),
            |r| r.engine = "onnx-vision".to_string(),
            |r| r.machine_did = "did:tenzro:machine:other".to_string(),
            |r| r.input_commitment = "00".repeat(32),
            |r| r.output_hash = "00".repeat(32),
        ];
        for edit in edits {
            let mut forged = r.clone();
            edit(&mut forged);
            // Re-claiming the catalog's hash does not help: the signature
            // covers the field.
            assert!(forged.verify_offline(&hash).is_err());
            if forged.model_hash == hash {
                assert_eq!(
                    forged.verify_offline(&hash),
                    Err(ReceiptError::BadSignature)
                );
            }
        }
    }

    #[test]
    fn the_model_hash_commits_to_every_weight_file() {
        tenzro_catalog::install_test_seed();
        let entry = tenzro_catalog::entry("qwen3-0.6b").unwrap();
        let base = model_hash_of(&entry);
        assert_eq!(catalog_identity("qwen3-0.6b").unwrap().model_hash, base);
        let mut swapped = entry.clone();
        swapped.components[0].sha256 = "00".repeat(32);
        assert_ne!(model_hash_of(&swapped), base);
        let mut reordered = entry.clone();
        reordered.components.reverse();
        assert_eq!(model_hash_of(&reordered), base);
        assert!(catalog_identity("not-in-the-catalog").is_none());
    }

    #[test]
    fn the_input_commitment_covers_messages_and_media() {
        let msg = |c: &str| tenzro_model::ChatMessage {
            role: "user".to_string(),
            content: c.to_string(),
            ..Default::default()
        };
        let base = input_commitment(&[msg("hi")], &[]);
        assert_ne!(base, input_commitment(&[msg("ho")], &[]));
        assert_ne!(base, input_commitment(&[msg("hi")], &[vec![1]]));
        assert_ne!(
            input_commitment(&[msg("hi")], &[vec![1, 2]]),
            input_commitment(&[msg("hi")], &[vec![1], vec![2]])
        );
    }

    #[test]
    fn inflated_units_break_the_signature() {
        let signer = session();
        let mut r = signed(&signer);
        let pk = signer.identity().clone();
        r.units.set("output_tokens", 5_000_000).unwrap();
        assert_eq!(r.verify_signature(&pk), Err(ReceiptError::BadSignature));
    }

    #[test]
    fn the_priced_card_and_provenance_are_signed() {
        let signer = session();
        let pk = signer.identity().clone();
        let mut c = claims();
        c.priced = Some(crate::inference_pricing::PricedOn {
            card: "ab".repeat(32),
            rate_nano_usd: 500_000_000,
            charge: 1_000,
        });
        c.provenance = vec!["11".repeat(32)];
        let r = InferenceReceipt::sign(&signer, c).unwrap();
        r.verify_signature(&pk).unwrap();
        for f in 0..8 {
            let mut t = r.clone();
            match f {
                5 => t.decode.precision = "Q8_0".into(),
                6 => t.decode.engine_version = "x".into(),
                7 => t.decode.hardware_class = "cuda".into(),
                0 => t.priced.as_mut().unwrap().charge += 1,
                1 => t.priced.as_mut().unwrap().card = "cd".repeat(32),
                2 => t.priced.as_mut().unwrap().rate_nano_usd -= 1,
                3 => t.priced = None,
                _ => t.provenance.clear(),
            }
            assert_eq!(
                t.verify_signature(&pk),
                Err(ReceiptError::BadSignature),
                "field {f}"
            );
        }
        // A new unit on the meter is signed like any other.
        let mut t = r.clone();
        t.units.set("action_chunks", 1).unwrap();
        assert_eq!(t.verify_signature(&pk), Err(ReceiptError::BadSignature));
    }

    #[test]
    fn the_activation_fingerprint_is_signed_and_cannot_be_added_or_stripped() {
        let signer = session();
        let pk = signer.identity().clone();
        let mut r = signed(&signer);
        assert_eq!(r.activation_fingerprint, None);
        r.activation_fingerprint = Some("cd".repeat(32));
        assert_eq!(r.verify_signature(&pk), Err(ReceiptError::BadSignature));

        let mut c = claims();
        c.activation_fingerprint = Some("cd".repeat(32));
        let mut r = InferenceReceipt::sign(&signer, c).unwrap();
        r.verify_signature(&pk)
            .expect("a fingerprinted receipt verifies");
        r.activation_fingerprint = None;
        assert_eq!(r.verify_signature(&pk), Err(ReceiptError::BadSignature));
    }

    #[test]
    fn a_receipt_signed_by_another_key_is_refused() {
        let signer = session();
        let other = session();
        let r = signed(&other);
        assert_eq!(
            r.verify_signature(signer.identity()),
            Err(ReceiptError::KeyMismatch)
        );
        // Naming the pinned key does not help a session the pinned key never
        // certified.
        let mut r = signed(&other);
        r.public_key = signer.identity().clone();
        assert_eq!(
            r.verify_signature(signer.identity()),
            Err(ReceiptError::BadSignature)
        );
        // A pin is the whole registered key: the P-256 point alone does not
        // match a hybrid identity.
        let hybrid = ImmediateRecordSigner::new(std::sync::Arc::new(TestHybridSigner::hybrid(9)));
        let r = signed(&hybrid);
        r.verify_signature(hybrid.identity()).unwrap();
        let classical_only = CompositePublicKey::new(hybrid.identity().p256.clone(), None).unwrap();
        assert_eq!(
            r.verify_signature(&classical_only),
            Err(ReceiptError::KeyMismatch)
        );
    }

    #[test]
    fn a_receipt_is_bound_to_model_nonce_output_and_units() {
        let signer = session();
        let r = signed(&signer);
        let pk = signer.identity().clone();
        let out = output_hash("hello", "", "");
        let units = BillableUnits::tokens(10, 5);
        let id = identity();
        assert_eq!(
            r.verify_for_forward(&pk, "m", &id, "nonce-2", &out, &units),
            Err(ReceiptError::NonceMismatch)
        );
        assert_eq!(
            r.verify_for_forward(
                &pk,
                "m",
                &id,
                "nonce-1",
                &output_hash("hellO", "", ""),
                &units
            ),
            Err(ReceiptError::OutputMismatch)
        );
        assert_eq!(
            r.verify_for_forward(
                &pk,
                "m",
                &id,
                "nonce-1",
                &out,
                &BillableUnits::tokens(10, 6)
            ),
            Err(ReceiptError::UnitsMismatch)
        );
        assert!(matches!(
            r.verify_for_forward(&pk, "other", &id, "nonce-1", &out, &units),
            Err(ReceiptError::ModelMismatch(_))
        ));
        let other_weights = ModelIdentity {
            model_hash: "cd".repeat(32),
            engine: "gguf".to_string(),
        };
        assert!(matches!(
            r.verify_for_forward(&pk, "m", &other_weights, "nonce-1", &out, &units),
            Err(ReceiptError::ModelHashMismatch(_))
        ));
    }

    #[test]
    fn output_hash_separates_its_parts() {
        assert_ne!(output_hash("ab", "", ""), output_hash("a", "b", ""));
        assert_ne!(output_hash("", "x", ""), output_hash("", "", "x"));
    }

    #[test]
    fn a_receipt_signed_in_a_hardware_batch_verifies_and_round_trips() {
        use tenzro_crypto::batch::{BatchParams, BatchRecordSigner, BatchService};
        let id: std::sync::Arc<dyn tenzro_crypto::composite::HybridSigner> =
            std::sync::Arc::new(TestHybridSigner::hybrid(14));
        let service = std::sync::Arc::new(
            BatchService::new(
                id,
                BatchParams {
                    max_batch: 1,
                    flush_interval_ms: 1_000,
                },
                0,
            )
            .unwrap(),
        );
        let signer = BatchRecordSigner::new(service, std::time::Duration::from_millis(200));
        let r = signed(&signer);
        let key = r.public_key.clone();
        r.verify_signature(&key).unwrap();
        r.verify_offline(&r.model_hash.clone()).unwrap();
        let again: InferenceReceipt =
            serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(again, r);
        // Another key does not stand behind it.
        let other = TestHybridSigner::hybrid(15);
        assert_eq!(
            r.verify_signature(tenzro_crypto::composite::HybridSigner::public_key(&other)),
            Err(ReceiptError::KeyMismatch)
        );
    }
}
