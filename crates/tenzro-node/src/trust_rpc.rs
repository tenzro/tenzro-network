//! JSON-RPC surface of the trust ledger: certifications and ratings, their
//! revocation, relying-party trust lists, operator policies and violations,
//! and model provenance.
//!
//! Nothing here signs on anyone's behalf. Issuers, relying parties,
//! operators and observers sign their records on their own hardware and
//! submit them; the node verifies, stores, gossips and (for a proven policy
//! violation) slashes. The admin methods only read this node's own disk.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_trust::credential::{Credential, Subject};
use tenzro_trust::ledger::RecordKind;
use tenzro_trust::{ModelManifest, TrustError, manifest, scan};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;
use crate::trust_hooks::{self, did_revoked, invalid, ledger, refused};

/// How far a policy's signing time may be from this node's clock when it is
/// first submitted here, so a policy cannot be signed with a back-dated
/// `created` to excuse receipts already served.
const POLICY_FRESHNESS_SECS: i64 = 15 * 60;

fn object_params(params: Option<Value>) -> Value {
    match params {
        Some(Value::Array(a)) => a.into_iter().next().unwrap_or(Value::Null),
        Some(v) => v,
        None => Value::Null,
    }
}

fn str_param<'a>(p: &'a Value, name: &str) -> Result<&'a str, JsonRpcError> {
    p.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid(format!("Missing {name}")))
}

fn trust_error(e: TrustError) -> JsonRpcError {
    match e {
        TrustError::Storage(_) | TrustError::Io(_) => JsonRpcError {
            code: -32603,
            message: e.to_string(),
            data: None,
        },
        other => invalid(other.to_string()),
    }
}

/// `tenzro_submitTrustRecord`: params `record` (a signed credential,
/// revocation, issuer revocation, trust list, operator policy, origin
/// attestation, an unsigned model manifest, or violation evidence).
pub(crate) async fn handle_submit(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let record = p.get("record").ok_or_else(|| invalid("Missing record"))?;
    if tenzro_trust::ledger::RecordKind::of(record).map_err(trust_error)? == RecordKind::Policy {
        let policy = tenzro_trust::OperatorPolicy::parse(record).map_err(trust_error)?;
        let skew = (chrono::Utc::now() - policy.proof_created)
            .num_seconds()
            .abs();
        if skew > POLICY_FRESHNESS_SECS {
            return Err(invalid(format!(
                "the policy was signed {skew}s from this node's clock; sign it now and submit it at once"
            )));
        }
    }
    let applied = trust_hooks::apply_record(node, record).map_err(trust_error)?;
    if applied.new {
        trust_hooks::broadcast(node, record);
    }
    Ok(json!({
        "kind": applied.kind,
        "key": applied.key,
        "new": applied.new,
        "violation": applied.violation,
    }))
}

fn describe(node: &TenzroNode, c: &Credential) -> Value {
    let state = ledger(node)
        .map(|l| l.state(c, chrono::Utc::now(), &did_revoked(node)))
        .ok();
    json!({
        "digest": c.digest,
        "issuer": c.issuer,
        "subject": c.subject.id(),
        "claim": c.claim,
        "validFrom": c.valid_from,
        "validUntil": c.valid_until,
        "statusListIndex": c.status_index,
        "state": state,
    })
}

/// `tenzro_verifyTrustCredential`: params `credential`. Checks the proof,
/// the validity window, the issuer's status list and issuer revocation.
pub(crate) async fn handle_verify(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let doc = p
        .get("credential")
        .ok_or_else(|| invalid("Missing credential"))?;
    Ok(match Credential::parse(doc) {
        Ok(c) => {
            let l = ledger(node)?;
            let state = l.state(&c, chrono::Utc::now(), &did_revoked(node));
            json!({
                "valid": state == tenzro_trust::CredentialState::Valid,
                "state": state,
                "anchored": l.credential(&c.digest).is_some(),
                "credential": describe(node, &c),
            })
        }
        Err(e) => json!({ "valid": false, "error": e.to_string() }),
    })
}

/// Resolve a subject parameter: a model subject, an operator DID, or a model
/// name (resolved to its verified manifest).
fn resolve_subject(node: &TenzroNode, id: &str) -> Result<Subject, JsonRpcError> {
    if let Ok(s) = Subject::parse(id) {
        return Ok(s);
    }
    trust_hooks::model_subject(ledger(node)?, id).ok_or_else(|| {
        invalid(format!(
            "{id} is not a subject and names no verified manifest"
        ))
    })
}

/// `tenzro_getTrustCredentials`: params `subject`.
pub(crate) async fn handle_get_credentials(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let subject = resolve_subject(node, str_param(&p, "subject")?)?;
    let creds: Vec<Value> = ledger(node)?
        .credentials_for(&subject)
        .iter()
        .map(|c| describe(node, c))
        .collect();
    Ok(json!({ "subject": subject.id(), "credentials": creds }))
}

/// `tenzro_getStatusList`: params `issuer`.
pub(crate) async fn handle_status_list(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    Ok(ledger(node)?.status_list(str_param(&p, "issuer")?))
}

/// `tenzro_getOperatorPolicy`: params `operator`, optional `at` (RFC 3339).
/// Returns the policy in force, its history, the violations proven against
/// the operator, and the verdict on it: the operator requirements of its
/// policy, and no proven violation.
pub(crate) async fn handle_get_policy(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let operator = str_param(&p, "operator")?;
    let at = match p.get("at").and_then(Value::as_str) {
        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|_| invalid("at is not an RFC 3339 time"))?
            .with_timezone(&chrono::Utc),
        None => chrono::Utc::now(),
    };
    let l = ledger(node)?;
    let in_force = l.policy_in_force(operator, at);
    let verdict = l.verdict(
        &in_force
            .as_ref()
            .map(|p| p.serves.trust.clone())
            .unwrap_or_default(),
        &Subject::Operator(operator.to_string()),
        at,
        &did_revoked(node),
    );
    let history: Vec<Value> = l
        .policies(operator)
        .iter()
        .map(|p| json!({"sequence": p.sequence, "digest": p.digest, "validFrom": p.valid_from, "validUntil": p.valid_until}))
        .collect();
    Ok(json!({
        "operator": operator,
        "in_force": in_force.map(|p| p.document),
        "history": history,
        "violations": l.violations_of(operator),
        "verdict": verdict,
    }))
}

fn manifest_param(node: &TenzroNode, p: &Value) -> Result<ModelManifest, JsonRpcError> {
    let l = ledger(node)?;
    if let Some(root) = p.get("root").and_then(Value::as_str) {
        return l
            .manifest(root)
            .ok_or_else(|| invalid(format!("no manifest with root {root}")));
    }
    let name = str_param(p, "name")?;
    l.verified_manifest_named(name)
        .ok_or_else(|| invalid(format!("{name} has no verified manifest")))
}

/// `tenzro_getModelProvenance`: params `root`, or `name` (every manifest
/// published under it), and optionally `file`: the path of one file, for
/// which each manifest also returns its entry and Merkle inclusion proof so
/// a downloader of that one file can check it against the root.
pub(crate) async fn handle_get_provenance(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let l = ledger(node)?;
    let roots: Vec<String> = match p.get("root").and_then(Value::as_str) {
        Some(r) => vec![r.to_string()],
        None => l
            .manifests_named(str_param(&p, "name")?)
            .iter()
            .map(|m| m.root_hex())
            .collect(),
    };
    let file = p.get("file").and_then(Value::as_str);
    let mut out = Vec::new();
    for root in roots {
        if let Some((m, atts, status)) = l.provenance(&root) {
            let inclusion = file
                .and_then(|f| Some(json!({ "entry": m.file(f)?, "proof": m.inclusion_proof(f)? })));
            out.push(json!({
                "inclusion": inclusion,
                "subject": m.subject_id(),
                "manifest": m.to_json(),
                "verified": status.verified(),
                "status": status,
                "observations": atts.iter().map(|a| json!({
                    "digest": a.digest, "observer": a.observer, "kind": a.kind,
                    "locator": a.locator, "observedAt": a.observed_at,
                })).collect::<Vec<_>>(),
            }));
        }
    }
    Ok(json!({ "manifests": out }))
}

/// A directory on this node's disk that holds a model.
fn local_dir(p: &Value) -> Result<PathBuf, JsonRpcError> {
    let dir = PathBuf::from(str_param(p, "path")?);
    if !dir.is_absolute() || !dir.is_dir() {
        return Err(invalid("path must be an absolute directory on this node"));
    }
    Ok(dir)
}

/// `tenzro_buildModelManifest` (admin): params `name`, `path`. Hashes the
/// model's files, records the manifest and gossips it.
pub(crate) async fn handle_build_manifest(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let name = str_param(&p, "name")?.to_string();
    let dir = local_dir(&p)?;
    let m = tokio::task::spawn_blocking(move || manifest::build_from_dir(&name, &dir))
        .await
        .map_err(|e| refused(e.to_string()))?
        .map_err(trust_error)?;
    let doc = m.to_json();
    let applied = trust_hooks::apply_record(node, &doc).map_err(trust_error)?;
    if applied.new {
        trust_hooks::broadcast(node, &doc);
    }
    Ok(json!({ "subject": m.subject_id(), "manifest": doc }))
}

/// `tenzro_verifyModelFiles` (admin): params `root` or `name`, and `path`.
pub(crate) async fn handle_verify_files(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let m = manifest_param(node, &p)?;
    let dir = local_dir(&p)?;
    let subject = m.subject_id();
    let result = tokio::task::spawn_blocking(move || manifest::verify_dir(&m, &dir))
        .await
        .map_err(|e| refused(e.to_string()))?;
    Ok(match result {
        Ok(()) => json!({ "subject": subject, "verified": true }),
        Err(TrustError::FileMismatch { path, reason }) => {
            json!({ "subject": subject, "verified": false, "file": path, "reason": reason })
        }
        Err(e) => return Err(trust_error(e)),
    })
}

/// `tenzro_scanModelFiles` (admin): params `root` or `name`, and `path`.
/// Returns the scan report and the claim a scanning party would sign as a
/// `safety-scan` credential.
pub(crate) async fn handle_scan_files(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let m = manifest_param(node, &p)?;
    let dir = local_dir(&p)?;
    let subject = m.subject_id();
    let report = tokio::task::spawn_blocking(move || {
        manifest::verify_dir(&m, &dir)?;
        scan::scan_dir(&m, &dir)
    })
    .await
    .map_err(|e| refused(e.to_string()))?
    .map_err(trust_error)?;
    let report_json = serde_json::to_value(&report).unwrap_or(Value::Null);
    let report_sha = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(tenzro_trust::jcs::canonical_json(
            &report_json,
        )))
    };
    Ok(json!({
        "subject": subject,
        "accepted": report.accepted,
        "report": report_json,
        "claim": {
            "kind": "safety-scan",
            "scheme": "tenzro-format-scan",
            "grade": if report.accepted { "accepted" } else { "refused" },
            "evidence": [{ "uri": format!("{subject}#scan"), "sha256": report_sha }],
        },
    }))
}

/// `tenzro_hostModel` (admin): params `root` or `name`, and `path`. Checks
/// the files against the manifest, then publishes each to this node's blob
/// store; peers fetch them by BLAKE3 and verify every chunk as it streams.
/// Files gated behind a licence are bound to it first, and served only to
/// nodes whose operator accepted it; hosting them needs this node's operator
/// to have accepted it too.
pub(crate) async fn handle_host_model(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_iroh::IrohResolver;
    let p = object_params(params);
    let m = manifest_param(node, &p)?;
    let dir = local_dir(&p)?;
    let resolver = node
        .iroh_resolver
        .clone()
        .ok_or_else(|| refused("this node has no blob store"))?;
    {
        let (m, dir) = (m.clone(), dir.clone());
        tokio::task::spawn_blocking(move || manifest::verify_dir(&m, &dir))
            .await
            .map_err(|e| refused(e.to_string()))?
            .map_err(trust_error)?;
    }
    let mut hosted = Vec::new();
    for f in &m.files {
        trust_hooks::bind_gated(node, &resolver, &m.name, &f.path, &f.blake3)
            .await
            .map_err(refused)?;
    }
    for f in &m.files {
        let uri = resolver
            .publish_path(&dir.join(&f.path))
            .await
            .map_err(|e| refused(format!("{}: {e}", f.path)))?;
        let tenzro_types::tenzro_uri::TenzroUri::Blob { hash, .. } = &uri else {
            return Err(refused(format!(
                "{}: the blob store returned {uri}",
                f.path
            )));
        };
        if *hash != f.blake3 {
            return Err(refused(format!(
                "{}: the blob store hashed it as {hash}",
                f.path
            )));
        }
        hosted.push(json!({ "path": f.path, "uri": f.blob_uri(), "size": f.size }));
    }
    Ok(json!({ "subject": m.subject_id(), "files": hosted }))
}
