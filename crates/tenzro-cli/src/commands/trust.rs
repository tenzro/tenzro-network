//! Certifications, ratings, operator policies and model
//! provenance.
//!
//! Drafting and signing happen on this machine: `draft-*` writes the
//! unsigned document, `sign` signs it with a P-256 key held in this machine's
//! TPM or Secure Enclave (the key never leaves it), and `submit` sends the
//! signed record to a node, which verifies it and gossips it. Anyone can
//! issue; what a credential is worth is up to each relying party.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use tenzro_trust::credential::{Claim, ClaimKind, Evidence, Subject};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    #[command(flatten)]
    Rpc(TrustRpcCommand),
    /// Print the DID a hardware key derives.
    Whoami(WhoamiCmd),
    /// Sign a trust document with a hardware key.
    Sign(SignCmd),
    /// Submit a signed record (or a manifest) to a node.
    Submit(SubmitCmd),
    /// Verify a credential against a node's revocation state.
    Verify(VerifyCmd),
    /// Draft an unsigned certification, rating, evaluation or scan credential.
    DraftCredential(DraftCredentialCmd),
    /// Draft an unsigned revocation of status list entries.
    DraftRevocation(DraftRevocationCmd),
    /// Draft an unsigned revocation of an issuer's own key.
    DraftIssuerRevocation(DraftIssuerRevocationCmd),
    /// Draft an unsigned operator policy from a terms file.
    DraftPolicy(DraftPolicyCmd),
    /// Assemble violation evidence from a signed policy and a signed receipt.
    DraftViolation(DraftViolationCmd),
    /// Check one downloaded file against a model's manifest root.
    VerifyFile(VerifyFileCmd),
    /// Hash a local model directory into a content-addressed manifest.
    Manifest(ManifestCmd),
    /// Draft an unsigned Hugging Face origin observation from a saved Hub
    /// revision listing (`/api/models/<repo>/revision/<commit>?blobs=true`).
    ObserveHub(ObserveHubCmd),
    /// Credentials stated about a model or operator.
    Credentials(QueryCmd),
    /// An issuer's revocation status list.
    StatusList(QueryCmd),
    /// An operator's policy, history and proven violations.
    Policy(QueryCmd),
    /// A model's manifests, observations and verification status.
    Provenance(QueryCmd),
}

impl TrustCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Whoami(c) => c.execute(),
            Self::Sign(c) => c.execute(),
            Self::Submit(c) => c.execute().await,
            Self::Verify(c) => c.execute().await,
            Self::DraftCredential(c) => c.execute(),
            Self::DraftRevocation(c) => c.execute(),
            Self::DraftIssuerRevocation(c) => c.execute(),
            Self::DraftPolicy(c) => c.execute(),
            Self::DraftViolation(c) => c.execute(),
            Self::VerifyFile(c) => c.execute().await,
            Self::Manifest(c) => c.execute(),
            Self::ObserveHub(c) => c.execute(),
            Self::Credentials(c) => c.query("tenzro_getTrustCredentials", "subject").await,
            Self::StatusList(c) => c.query("tenzro_getStatusList", "issuer").await,
            Self::Policy(c) => c.query("tenzro_getOperatorPolicy", "operator").await,
            Self::Provenance(c) => {
                let key = if c.id.starts_with("tenzro:model:") || c.id.len() == 64 {
                    "root"
                } else {
                    "name"
                };
                let id =
                    c.id.strip_prefix("tenzro:model:")
                        .unwrap_or(&c.id)
                        .to_string();
                QueryCmd {
                    id,
                    rpc: c.rpc.clone(),
                }
                .query("tenzro_getModelProvenance", key)
                .await
            }
        }
    }
}

fn read_json(path: &PathBuf) -> Result<Value> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

fn write_or_print(value: &Value, out: Option<&PathBuf>) -> Result<()> {
    match out {
        Some(p) => {
            std::fs::write(p, serde_json::to_vec_pretty(value)?)?;
            output::print_success(&format!("Wrote {}", p.display()));
            Ok(())
        }
        None => output::print_json(value),
    }
}

/// The labelled key in this machine's TPM or Secure Enclave, created on
/// first use. There is no software fallback.
fn open_key(label: &str) -> Result<Box<dyn tenzro_device_key::HardwareSigner>> {
    tenzro_device_key::signer::open_or_create(label)
        .map_err(|e| anyhow!("hardware key {label}: {e}"))
}

/// `tenzro trust whoami --key-label <label>`: the key is created in this
/// machine's TPM or Secure Enclave on first use.
#[derive(Debug, Parser)]
pub struct WhoamiCmd {
    #[arg(long)]
    key_label: String,
}

impl WhoamiCmd {
    fn execute(&self) -> Result<()> {
        output::print_json(&json!({ "did": hardware_did(&self.key_label)? }))
    }
}

/// The DID the labelled hardware key derives.
pub(crate) fn hardware_did(key_label: &str) -> Result<String> {
    let key = open_key(key_label)?;
    let pk = key.public_key_sec1().map_err(|e| anyhow!("{e}"))?;
    Ok(tenzro_trust::proof::machine_did(&pk))
}

/// `tenzro trust sign --doc <file> --key-label <label>`
#[derive(Debug, Parser)]
pub struct SignCmd {
    #[arg(long)]
    doc: PathBuf,
    #[arg(long)]
    key_label: String,
    #[arg(long)]
    out: Option<PathBuf>,
}

impl SignCmd {
    fn execute(&self) -> Result<()> {
        let signed = sign_with_hardware(read_json(&self.doc)?, &self.key_label)?;
        write_or_print(&signed, self.out.as_ref())
    }
}

/// Sign `doc` for `assertionMethod` with the labelled key in this machine's
/// TPM or Secure Enclave, and check the result verifies.
pub(crate) fn sign_with_hardware(doc: Value, key_label: &str) -> Result<Value> {
    let key = open_key(key_label)?;
    let pk = key.public_key_sec1().map_err(|e| anyhow!("{e}"))?;
    let did = tenzro_trust::proof::machine_did(&pk);
    let opts = tenzro_trust::proof::options(&tenzro_trust::proof::ProofRequest {
        signer_did: did,
        public_key_sec1: pk,
        purpose: "assertionMethod".into(),
        created: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        rp_id: None,
    });
    let digest = tenzro_trust::proof::signing_digest(&doc, &opts);
    let sig = key
        .sign_prehash(&digest)
        .map_err(|e| anyhow!("hardware signing failed: {e}"))?;
    let signed = tenzro_trust::proof::attach_hardware(doc, opts, &sig);
    tenzro_trust::proof::verify(&signed)
        .map_err(|e| anyhow!("the signed document does not verify: {e}"))?;
    Ok(signed)
}

/// `tenzro trust submit --file <record.json>`
#[derive(Debug, Parser)]
pub struct SubmitCmd {
    #[arg(long)]
    file: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SubmitCmd {
    async fn execute(&self) -> Result<()> {
        let record = read_json(&self.file)?;
        let res: Value = RpcClient::new(&self.rpc)
            .call("tenzro_submitTrustRecord", json!({ "record": record }))
            .await?;
        output::print_json(&res)
    }
}

/// `tenzro trust verify --file <credential.json>`
#[derive(Debug, Parser)]
pub struct VerifyCmd {
    #[arg(long)]
    file: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VerifyCmd {
    async fn execute(&self) -> Result<()> {
        let credential = read_json(&self.file)?;
        let res: Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_verifyTrustCredential",
                json!({ "credential": credential }),
            )
            .await?;
        output::print_json(&res)
    }
}

/// `tenzro trust draft-credential ...`
#[derive(Debug, Parser)]
pub struct DraftCredentialCmd {
    /// Issuer DID (from `tenzro trust whoami`).
    #[arg(long)]
    issuer: String,
    /// `tenzro:model:<root>` or an operator DID.
    #[arg(long)]
    subject: String,
    /// certification, rating, evaluation, safety-scan or policy-conformance.
    #[arg(long)]
    kind: String,
    #[arg(long)]
    scheme: String,
    #[arg(long)]
    grade: Option<String>,
    /// 0..=10000.
    #[arg(long)]
    score: Option<u32>,
    #[arg(long)]
    scope: Option<String>,
    /// Report reference as `<uri>=<sha256 hex>`; repeatable.
    #[arg(long)]
    evidence: Vec<String>,
    #[arg(long, default_value_t = 365)]
    valid_days: i64,
    /// Status list index this credential occupies in the issuer's list.
    #[arg(long)]
    index: u32,
    #[arg(long)]
    out: Option<PathBuf>,
}

impl DraftCredentialCmd {
    fn execute(&self) -> Result<()> {
        let kind: ClaimKind = serde_json::from_value(json!(self.kind))
            .map_err(|_| anyhow!("unknown kind {}", self.kind))?;
        let evidence = self
            .evidence
            .iter()
            .map(|e| {
                let (uri, sha256) = e
                    .rsplit_once('=')
                    .ok_or_else(|| anyhow!("evidence is <uri>=<sha256>"))?;
                Ok(Evidence {
                    uri: uri.into(),
                    sha256: sha256.to_lowercase(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let claim = Claim {
            kind,
            scheme: self.scheme.clone(),
            grade: self.grade.clone(),
            score: self.score,
            scope: self.scope.clone(),
            evidence,
        };
        let subject = Subject::parse(&self.subject).map_err(|e| anyhow!("{e}"))?;
        let now = chrono::Utc::now();
        let doc = tenzro_trust::credential::unsigned(
            &self.issuer,
            &subject,
            &claim,
            now,
            now + chrono::Duration::days(self.valid_days),
            self.index,
        );
        write_or_print(&doc, self.out.as_ref())
    }
}

/// `tenzro trust draft-revocation --issuer <did> --index 3 --index 9`
#[derive(Debug, Parser)]
pub struct DraftRevocationCmd {
    #[arg(long)]
    issuer: String,
    #[arg(long, required = true)]
    index: Vec<u32>,
    #[arg(long)]
    out: Option<PathBuf>,
}

impl DraftRevocationCmd {
    fn execute(&self) -> Result<()> {
        let doc = tenzro_trust::status_list::Revocation::unsigned(
            &self.issuer,
            &self.index,
            chrono::Utc::now(),
        );
        write_or_print(&doc, self.out.as_ref())
    }
}

/// `tenzro trust draft-issuer-revocation --issuer <did> --reason <text>`
#[derive(Debug, Parser)]
pub struct DraftIssuerRevocationCmd {
    #[arg(long)]
    issuer: String,
    #[arg(long, default_value = "")]
    reason: String,
    #[arg(long)]
    out: Option<PathBuf>,
}

impl DraftIssuerRevocationCmd {
    fn execute(&self) -> Result<()> {
        let doc = tenzro_trust::status_list::IssuerRevocation::unsigned(
            &self.issuer,
            chrono::Utc::now(),
            &self.reason,
        );
        write_or_print(&doc, self.out.as_ref())
    }
}

/// `tenzro trust draft-policy --operator <did> --sequence 1 --terms <file>`
///
/// The terms file is `{ "receiptKeys", "serves", "jurisdictions", "refuses", "data" }`.
/// Each receipt key's `binding` is that key's signature over
/// `"tenzro/trust/receipt-key" || operator DID`.
#[derive(Debug, Parser)]
pub struct DraftPolicyCmd {
    #[arg(long)]
    operator: String,
    #[arg(long)]
    sequence: u64,
    #[arg(long)]
    terms: PathBuf,
    #[arg(long, default_value_t = 90)]
    valid_days: i64,
    #[arg(long)]
    out: Option<PathBuf>,
}

impl DraftPolicyCmd {
    fn execute(&self) -> Result<()> {
        let terms: tenzro_trust::policy::PolicyTerms =
            serde_json::from_value(read_json(&self.terms)?).context("terms")?;
        // A policy cannot take effect before it is signed, so it starts a
        // minute from now to leave time for `tenzro trust sign`.
        let from = chrono::Utc::now() + chrono::Duration::minutes(1);
        let doc = tenzro_trust::OperatorPolicy::unsigned(
            &self.operator,
            self.sequence,
            from,
            from + chrono::Duration::days(self.valid_days),
            &terms,
        );
        write_or_print(&doc, self.out.as_ref())
    }
}

/// `tenzro trust draft-violation --policy <signed policy> --receipt <receipt> --clause serves.models`
#[derive(Debug, Parser)]
pub struct DraftViolationCmd {
    #[arg(long)]
    policy: PathBuf,
    /// A signed jurisdiction receipt, as returned with an inference response.
    #[arg(long)]
    receipt: PathBuf,
    /// `serves.models` or `jurisdictions`.
    #[arg(long)]
    clause: String,
    #[arg(long)]
    out: Option<PathBuf>,
}

impl DraftViolationCmd {
    fn execute(&self) -> Result<()> {
        let policy = read_json(&self.policy)?;
        let receipt: tenzro_types::model::JurisdictionReceipt =
            serde_json::from_value(read_json(&self.receipt)?).context("receipt")?;
        let clause: tenzro_trust::policy::Clause = serde_json::from_value(json!(self.clause))
            .map_err(|_| anyhow!("clause is serves.models or jurisdictions"))?;
        let doc = tenzro_trust::policy::violation_evidence(&policy, &receipt, clause);
        let history = [tenzro_trust::OperatorPolicy::parse(&policy).map_err(|e| anyhow!("{e}"))?];
        tenzro_trust::policy::verify_violation(&doc, &history)
            .map_err(|e| anyhow!("this evidence proves nothing: {e}"))?;
        write_or_print(&doc, self.out.as_ref())
    }
}

/// `tenzro trust verify-file --root <hex> --file <path in model> --path <local file>`
#[derive(Debug, Parser)]
pub struct VerifyFileCmd {
    #[arg(long)]
    root: String,
    /// The file's path inside the model.
    #[arg(long)]
    file: String,
    /// The downloaded file on this machine.
    #[arg(long)]
    path: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VerifyFileCmd {
    async fn execute(&self) -> Result<()> {
        let res: Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_getModelProvenance",
                json!({ "root": self.root, "file": self.file }),
            )
            .await?;
        let inc = res
            .pointer("/manifests/0/inclusion")
            .filter(|v| !v.is_null())
            .ok_or_else(|| {
                anyhow!(
                    "the node has no manifest {} listing {}",
                    self.root,
                    self.file
                )
            })?;
        let entry: tenzro_trust::FileEntry = serde_json::from_value(inc["entry"].clone())?;
        let proof: tenzro_trust::manifest::InclusionProof =
            serde_json::from_value(inc["proof"].clone())?;
        // The proof is checked against the root the caller named, not one the
        // node reports, so a lying node cannot vouch for other bytes.
        if !tenzro_trust::manifest::verify_inclusion(&self.root, &entry, &proof) {
            bail!(
                "the node's entry for {} is not under root {}",
                self.file,
                self.root
            );
        }
        tenzro_trust::manifest::verify_file(&entry, &self.path).map_err(|e| anyhow!("{e}"))?;
        output::print_success(&format!(
            "{} matches {} under {}",
            self.path.display(),
            self.file,
            self.root
        ));
        output::print_json(&json!({ "verified": res.pointer("/manifests/0/verified") }))
    }
}

/// `tenzro trust manifest --name <repo or id> --path <dir>`
#[derive(Debug, Parser)]
pub struct ManifestCmd {
    #[arg(long)]
    name: String,
    #[arg(long)]
    path: PathBuf,
    #[arg(long)]
    out: Option<PathBuf>,
}

impl ManifestCmd {
    fn execute(&self) -> Result<()> {
        let m = tenzro_trust::manifest::build_from_dir(&self.name, &self.path)
            .map_err(|e| anyhow!("{e}"))?;
        output::print_info(&format!(
            "{} files, {} bytes, subject {}",
            m.files.len(),
            m.total_size(),
            m.subject_id()
        ));
        write_or_print(&m.to_json(), self.out.as_ref())
    }
}

/// `tenzro trust observe-hub --repo <owner/repo> --listing <file> --observer <did>`
#[derive(Debug, Parser)]
pub struct ObserveHubCmd {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    listing: PathBuf,
    #[arg(long)]
    observer: String,
    #[arg(long)]
    out: Option<PathBuf>,
}

impl ObserveHubCmd {
    fn execute(&self) -> Result<()> {
        let listing = read_json(&self.listing)?;
        let (locator, files) = tenzro_trust::origin::observe_hub_listing(&self.repo, &listing)
            .map_err(|e| anyhow!("{e}"))?;
        let doc = tenzro_trust::origin::OriginAttestation::unsigned(
            &self.observer,
            tenzro_trust::OriginKind::Huggingface,
            &locator,
            &self.repo,
            &files,
            chrono::Utc::now(),
        );
        write_or_print(&doc, self.out.as_ref())
    }
}

/// A lookup by one id.
#[derive(Debug, Parser)]
pub struct QueryCmd {
    id: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl QueryCmd {
    async fn query(&self, method: &str, key: &str) -> Result<()> {
        let res: Value = RpcClient::new(&self.rpc)
            .call(method, json!({ key: self.id }))
            .await?;
        output::print_json(&res)
    }
}

/// Trust commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum TrustRpcCommand {
    /// Call tenzro_hostModel (host model) and print the node's answer
    HostModel(TrustHostModelRpcCmd),
    /// Call tenzro_scanModelFiles (scan model files) and print the node's answer
    ScanModelFiles(TrustScanModelFilesRpcCmd),
    /// Call tenzro_verifyModelFiles (verify model files) and print the node's answer
    VerifyModelFiles(TrustVerifyModelFilesRpcCmd),
    /// Log the measurement of the TEE this machine runs in (tenzro_publishTeeMeasurement)
    PublishTeeMeasurement(TrustPublishTeeMeasurementRpcCmd),
}

impl TrustRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::HostModel(cmd) => cmd.execute().await,
            Self::ScanModelFiles(cmd) => cmd.execute().await,
            Self::VerifyModelFiles(cmd) => cmd.execute().await,
            Self::PublishTeeMeasurement(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_hostModel (host model)
#[derive(Debug, clap::Parser)]
pub struct TrustHostModelRpcCmd {
    /// name
    #[arg(long)]
    name: Option<String>,
    /// root
    #[arg(long)]
    root: Option<String>,
    /// path
    #[arg(long)]
    path: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrustHostModelRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_hostModel",
                serde_json::json!({ "name": self.name, "root": self.root, "path": self.path }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_scanModelFiles (scan model files)
#[derive(Debug, clap::Parser)]
pub struct TrustScanModelFilesRpcCmd {
    /// name
    #[arg(long)]
    name: Option<String>,
    /// root
    #[arg(long)]
    root: Option<String>,
    /// path
    #[arg(long)]
    path: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrustScanModelFilesRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_scanModelFiles",
                serde_json::json!({ "name": self.name, "root": self.root, "path": self.path }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_verifyModelFiles (verify model files)
#[derive(Debug, clap::Parser)]
pub struct TrustVerifyModelFilesRpcCmd {
    /// name
    #[arg(long)]
    name: Option<String>,
    /// root
    #[arg(long)]
    root: Option<String>,
    /// path
    #[arg(long)]
    path: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrustVerifyModelFilesRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyModelFiles",
                serde_json::json!({ "name": self.name, "root": self.root, "path": self.path }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Log the measurement of the build this machine runs in the attestation
/// transparency log. The report answers a `tenzro_teeAttestationChallenge`
/// nonce and names this machine's hardware P-256 key, which signs the
/// publication.
#[derive(Debug, clap::Parser)]
pub struct TrustPublishTeeMeasurementRpcCmd {
    /// Path to the attestation report (JSON)
    #[arg(long)]
    report: std::path::PathBuf,
    /// The challenge nonce the report answers, hex
    #[arg(long)]
    nonce: String,
    /// The report's measurement, hex (the node checks it against the report)
    #[arg(long)]
    measurement: String,
    /// The hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrustPublishTeeMeasurementRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        use anyhow::Context as _;
        let raw = std::fs::read_to_string(&self.report)
            .with_context(|| format!("reading {}", self.report.display()))?;
        let report: tenzro_types::tee::AttestationReport =
            serde_json::from_str(&raw).context("--report is not an attestation report")?;
        let measurement = hex::decode(self.measurement.trim_start_matches("0x"))
            .context("--measurement is not hex")?;
        let statement = tenzro_types::tee::publication_statement(report.vendor, &measurement);
        let (public_key, signature, _) =
            crate::keystore::sign_p256(&self.key_namespace, &statement)?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_publishTeeMeasurement",
                serde_json::json!({
                    "report": report,
                    "nonce": self.nonce.trim_start_matches("0x"),
                    "publisher_key_hex": hex::encode(public_key),
                    "signature_hex": hex::encode(signature),
                }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}
