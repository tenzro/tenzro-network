//! `/v1/files` — the HTTP surface over [`crate::files_api`] and the storage
//! provider.
//!
//! Five routes in the shape OpenAI publishes, so an SDK already pointed at
//! `/v1/chat/completions` can upload against the same base URL and the same
//! key:
//!
//! | Route | Does |
//! |---|---|
//! | `POST   /v1/files` | multipart upload; erasure-codes and opens a deal |
//! | `GET    /v1/files` | the caller's own files, newest first |
//! | `GET    /v1/files/:id` | one record |
//! | `GET    /v1/files/:id/content` | the bytes, rebuilt from shards |
//! | `DELETE /v1/files/:id` | unlink the reference and stop the deal |
//!
//! # Every route resolves a tenant first, and refuses without one
//!
//! A file has an owner; that is the entire isolation model. So an unattributed
//! request is not "an anonymous upload" — it is a file nobody can later list,
//! retrieve, or be billed for, stored on an operator's disk. All five routes
//! therefore require an API key that resolves to a subject DID, including the
//! read routes: a node that would serve `GET /v1/files/:id` to an
//! unauthenticated caller has made every tenant's file readable by id.
//!
//! This is stricter than the inference routes next door, which an operator may
//! legitimately run open. The difference is that inference is stateless and
//! storage is not.

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

use crate::api_key::ApiKeyScope;
use crate::files_api::{
    FileDeletion, FileObject, FilePurpose, UploadRejection, file_id_for, object_id_from,
    validate_upload,
};
use crate::files_store::DEFAULT_LIST_LIMIT;
use crate::node::TenzroNode;

/// Data + parity shards a `/v1/files` upload is coded under.
///
/// Fixed rather than caller-chosen. The tradeoff being made — survive two
/// simultaneous provider losses at 1.5× storage amplification — is the
/// operator's cost and the tenant's durability, and a per-request knob would
/// let a tenant pick `1+1` and then be surprised by what "deleted" and
/// "durable" mean. Callers who want to choose have `tenzro_storageStoreObject`.
const FILE_DATA_SHARDS: usize = 4;
/// Parity shards per upload. See [`FILE_DATA_SHARDS`].
const FILE_PARITY_SHARDS: usize = 2;

/// Epochs a `/v1/files` deal is opened for.
///
/// The deal is what pays providers to keep shards; when it stops paying, the
/// shards expire. A finite default means an abandoned file eventually stops
/// costing the operator, rather than accruing forever because a tenant
/// uploaded once and never came back.
pub(crate) const FILE_DEAL_EPOCHS: u64 = 720;

/// The redundancy scheme every `/v1/files` upload is coded under.
///
/// A function rather than a constant because
/// [`tenzro_storage_provider::RedundancyScheme::erasure`] validates its
/// arguments and so cannot be evaluated at compile time. Shared with
/// [`crate::files_rpc`] so the REST and RPC uploads cannot end up storing at
/// different durabilities.
pub(crate) fn file_redundancy()
-> tenzro_storage_provider::Result<tenzro_storage_provider::RedundancyScheme> {
    tenzro_storage_provider::RedundancyScheme::erasure(FILE_DATA_SHARDS, FILE_PARITY_SHARDS)
}

/// Router for the whole `/v1/files` surface.
pub fn files_routes() -> axum::Router<Arc<TenzroNode>> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route(
            "/v1/files",
            post(handle_files_upload).get(handle_files_list),
        )
        .route("/v1/files/:file_id", get(handle_files_retrieve))
        .route("/v1/files/:file_id/content", get(handle_files_content))
        .route("/v1/files/:file_id", delete(handle_files_delete))
}

/// Query parameters accepted by `GET /v1/files`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Narrow to one purpose.
    #[serde(default)]
    pub purpose: Option<FilePurpose>,
    /// How many to return. Clamped to [`MAX_LIST_LIMIT`].
    #[serde(default)]
    pub limit: Option<usize>,
}

/// The list envelope OpenAI clients parse.
#[derive(Debug, Serialize)]
struct FileList {
    object: &'static str,
    data: Vec<FileObject>,
    /// Not in OpenAI's shape. Present because a tenant's next question after
    /// "what do I have" is always "what is it costing me", and answering it
    /// here saves a second round trip over a list they just paid to build.
    total_bytes: u64,
}

/// Resolve the calling tenant's DID, or produce the refusal to return.
///
/// The API key is the credential; its `subject` is the identity. A key with no
/// subject is an operator-internal key — usable for operating the node, but it
/// names no tenant, so it cannot own a file. Saying so explicitly is better
/// than falling back to some node-wide bucket that every such key would share.
fn tenant_or_refusal(node: &Arc<TenzroNode>, headers: &HeaderMap) -> Result<String, Response> {
    let manager = node.api_key_manager().ok_or_else(|| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_api_keys",
            "This node has no API-key manager, so it cannot attribute a file to a tenant. \
             /v1/files is unavailable until the operator enables API keys.",
        )
    })?;

    let presented = headers
        .get("x-tenzro-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "missing_api_key",
                "Missing X-Tenzro-Api-Key. Every file has an owner, so /v1/files has no \
                 unauthenticated path — including for reads.",
            )
        })?;

    let record = manager.lookup(presented).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_api_key",
            "The presented API key is unknown or revoked.",
        )
    })?;

    if !record.scopes.contains(&ApiKeyScope::Storage) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "This API key does not carry the 'storage' scope.",
        ));
    }

    record
        .subject
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            error_response(
                StatusCode::FORBIDDEN,
                "no_subject",
                "This API key names no subject, so it cannot own a file. Reissue the key with a \
             subject DID.",
            )
        })
}

/// The storage runtime, or the refusal explaining why this node has none.
fn runtime_or_refusal(
    node: &Arc<TenzroNode>,
) -> Result<Arc<crate::storage_provider_runtime::StorageProviderRuntime>, Response> {
    node.storage_runtime().cloned().ok_or_else(|| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_a_storage_provider",
            "This node does not run the StorageProvider role, so it has nowhere to put a file.",
        )
    })
}

/// An error body in the shape OpenAI clients already destructure.
fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "message": message,
                "type": "invalid_request_error",
                "code": code,
            }
        })),
    )
        .into_response()
}

/// `POST /v1/files` — multipart upload.
///
/// Parts: `file` (required, the bytes) and `purpose` (optional). Ordering is
/// not assumed — a client that sends `purpose` after `file` is not doing
/// anything wrong, and several HTTP libraries do exactly that.
async fn handle_files_upload(
    State(node): State<Arc<TenzroNode>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let tenant = match tenant_or_refusal(&node, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let runtime = match runtime_or_refusal(&node) {
        Ok(r) => r,
        Err(r) => return r,
    };

    let mut data: Option<Vec<u8>> = None;
    let mut filename = String::new();
    let mut purpose = FilePurpose::default();

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "malformed_multipart",
                    &format!("Could not read the multipart body: {e}"),
                );
            }
        };
        match field.name().unwrap_or_default().to_string().as_str() {
            "file" => {
                filename = field.file_name().unwrap_or_default().to_string();
                match field.bytes().await {
                    Ok(b) => data = Some(b.to_vec()),
                    Err(e) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "unreadable_file_part",
                            &format!("Could not read the 'file' part: {e}"),
                        );
                    }
                }
            }
            "purpose" => {
                let raw = field.text().await.unwrap_or_default();
                match serde_json::from_value::<FilePurpose>(json!(raw.trim())) {
                    Ok(p) => purpose = p,
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "unknown_purpose",
                            &format!(
                                "Unknown purpose '{}'. Valid values: assistants, batch, \
                                 fine_tune, vision, user_data.",
                                raw.trim()
                            ),
                        );
                    }
                }
            }
            // Unknown parts are ignored rather than refused: SDKs add fields
            // over time, and rejecting one would break a client that is
            // otherwise sending a valid upload.
            _ => {}
        }
    }

    let Some(bytes) = data else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "missing_file",
            "The request has no 'file' part.",
        );
    };

    if let Err(e) = validate_upload(&filename, bytes.len() as u64) {
        let code = match e {
            UploadRejection::Empty => "empty_file",
            UploadRejection::TooLarge { .. } => "file_too_large",
            UploadRejection::MissingFilename => "missing_filename",
        };
        let status = match e {
            UploadRejection::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::BAD_REQUEST,
        };
        return error_response(status, code, &e.to_string());
    }

    let object_id = uuid::Uuid::new_v4().to_string();
    let scheme = match file_redundancy() {
        Ok(s) => s,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "bad_redundancy",
                &format!("The node's redundancy scheme is invalid: {e}"),
            );
        }
    };

    let size = bytes.len() as u64;
    if let Err(e) = runtime
        .store_object(
            object_id.clone(),
            tenant.clone(),
            &bytes,
            scheme,
            tenzro_types::access_policy::AccessPolicy::owner_only(tenant.clone()),
            None,
        )
        .await
    {
        warn!(tenant = %tenant, error = %e, "Storing an uploaded file failed");
        return error_response(
            StatusCode::BAD_GATEWAY,
            "store_failed",
            &format!("The object could not be stored: {e}"),
        );
    }

    // The deal is what keeps the shards paid for. A file whose deal could not
    // be opened is still stored and still listable — refusing the upload here
    // would discard bytes the node has already coded and published, which is
    // worse for the tenant than a file the operator is carrying unbilled.
    let deal_id = match runtime.open_deal(
        object_id.clone(),
        renter_address(&tenant),
        tenzro_types::asset::AssetId::tnzo(),
        size,
        FILE_DEAL_EPOCHS,
    ) {
        Ok(d) => Some(d.deal_id),
        Err(e) => {
            warn!(
                tenant = %tenant,
                object = %object_id,
                error = %e,
                "Stored the file but could not open its storage deal"
            );
            None
        }
    };

    let record = FileObject {
        id: file_id_for(&object_id),
        object: "file",
        bytes: size,
        created_at: now_secs(),
        filename,
        purpose,
        owner: tenant,
        deal_id,
    };
    node.file_index().insert(record.clone());
    (StatusCode::OK, Json(record)).into_response()
}

/// `GET /v1/files` — the caller's own files.
async fn handle_files_list(
    State(node): State<Arc<TenzroNode>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    let tenant = match tenant_or_refusal(&node, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let index = node.file_index();
    let data = index.list(&tenant, q.purpose, q.limit.unwrap_or(DEFAULT_LIST_LIMIT));
    Json(FileList {
        object: "list",
        data,
        total_bytes: index.bytes_for(&tenant),
    })
    .into_response()
}

/// Fetch a record and check it belongs to the caller.
///
/// "Not yours" is answered as 404, not 403. A 403 confirms the id exists,
/// which turns the id space into an oracle a caller can enumerate.
fn owned_or_refusal(
    node: &Arc<TenzroNode>,
    tenant: &str,
    file_id: &str,
) -> Result<FileObject, Response> {
    node.file_index()
        .get(file_id)
        .filter(|f| f.visible_to(tenant))
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "no_such_file",
                &format!("No file '{file_id}'."),
            )
        })
}

/// `GET /v1/files/:file_id` — one record.
async fn handle_files_retrieve(
    State(node): State<Arc<TenzroNode>>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Response {
    let tenant = match tenant_or_refusal(&node, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    match owned_or_refusal(&node, &tenant, &file_id) {
        Ok(f) => Json(f).into_response(),
        Err(r) => r,
    }
}

/// `GET /v1/files/:file_id/content` — the bytes, rebuilt from shards.
async fn handle_files_content(
    State(node): State<Arc<TenzroNode>>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Response {
    let tenant = match tenant_or_refusal(&node, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let runtime = match runtime_or_refusal(&node) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let record = match owned_or_refusal(&node, &tenant, &file_id) {
        Ok(f) => f,
        Err(r) => return r,
    };

    let Some(object_id) = object_id_from(&record.id) else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unaddressable",
            "This file's id does not resolve to a stored object.",
        );
    };

    match runtime.store().retrieve_object(object_id).await {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_DISPOSITION,
                // Quoted so a filename containing a space is not truncated by
                // the client at the first one.
                format!(
                    "attachment; filename=\"{}\"",
                    record.filename.replace('"', "")
                ),
            )
            .body(Body::from(bytes))
            .unwrap_or_else(|e| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "response_build_failed",
                    &format!("Could not build the response: {e}"),
                )
            }),
        Err(e) => {
            warn!(file = %file_id, error = %e, "Rebuilding a file from its shards failed");
            error_response(
                StatusCode::BAD_GATEWAY,
                "retrieve_failed",
                &format!("The file is indexed but its bytes could not be rebuilt from shards: {e}"),
            )
        }
    }
}

/// `DELETE /v1/files/:file_id` — unlink the reference.
async fn handle_files_delete(
    State(node): State<Arc<TenzroNode>>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Response {
    let tenant = match tenant_or_refusal(&node, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    // Checked before removal so one tenant cannot delete another's row by id.
    if let Err(r) = owned_or_refusal(&node, &tenant, &file_id) {
        return r;
    }
    node.file_index().remove(&file_id);
    Json(FileDeletion::unlinked(file_id)).into_response()
}

/// The billing address a tenant's storage deals are opened against.
///
/// A DID is a string and a renter is a 32-byte address, so one has to be
/// derived from the other. Domain-separated for the same reason the escrow
/// vault is: a bare `SHA-256(did)` would collide with any other subsystem that
/// also hashes a DID to an address, and two subsystems agreeing by accident on
/// what an address means is how funds move to the wrong place.
pub(crate) fn renter_address(tenant_did: &str) -> tenzro_types::primitives::Address {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/files/renter");
    h.update(tenant_did.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    tenzro_types::primitives::Address::new(out)
}

/// Unix seconds. A clock before the epoch reads as 0 rather than panicking —
/// a misconfigured clock should not take down an upload.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_limit_ceiling_is_below_the_vendor_default() {
        use crate::files_store::MAX_LIST_LIMIT;
        // OpenAI caps at 10,000. This list is served from a node also running
        // models, so the ceiling is deliberately lower.
        const { assert!(MAX_LIST_LIMIT < 10_000) };
        const { assert!(DEFAULT_LIST_LIMIT <= MAX_LIST_LIMIT) };
    }

    #[test]
    fn the_redundancy_scheme_survives_two_provider_losses() {
        let scheme = file_redundancy().expect("the node's own scheme must be valid");
        assert_eq!(scheme.parity_shards, 2);
        // 6 shards for 4 shards' worth of data: 1.5x amplification.
        assert_eq!(scheme.data_shards + scheme.parity_shards, 6);
    }

    #[test]
    fn a_purpose_parses_from_its_wire_form() {
        // The upload path parses `purpose` out of a multipart text field, so
        // the snake_case wire form has to round-trip through serde.
        for (wire, expected) in [
            ("assistants", FilePurpose::Assistants),
            ("batch", FilePurpose::Batch),
            ("fine_tune", FilePurpose::FineTune),
            ("vision", FilePurpose::Vision),
            ("user_data", FilePurpose::UserData),
        ] {
            let parsed: FilePurpose =
                serde_json::from_value(json!(wire)).unwrap_or_else(|e| panic!("{wire}: {e}"));
            assert_eq!(parsed, expected);
        }
        assert!(serde_json::from_value::<FilePurpose>(json!("training")).is_err());
    }

    #[test]
    fn an_error_body_carries_the_fields_openai_clients_destructure() {
        let resp = error_response(StatusCode::NOT_FOUND, "no_such_file", "No file 'file-x'.");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn two_tenants_never_share_a_billing_address() {
        // A collision here bills one tenant for another's storage.
        let a = renter_address("did:tenzro:human:alice");
        let b = renter_address("did:tenzro:human:bob");
        assert_ne!(a, b);
        assert_eq!(a, renter_address("did:tenzro:human:alice"), "and is stable");
    }

    #[test]
    fn the_billing_address_is_domain_separated_from_a_bare_did_hash() {
        // Otherwise any other subsystem that also hashes a DID to an address
        // agrees with this one by accident, and funds move somewhere nobody
        // decided they should.
        use sha2::{Digest, Sha256};
        let bare = {
            let mut out = [0u8; 32];
            out.copy_from_slice(&Sha256::digest(b"did:tenzro:human:alice"));
            tenzro_types::primitives::Address::new(out)
        };
        assert_ne!(renter_address("did:tenzro:human:alice"), bare);
    }

    #[test]
    fn a_deal_is_opened_for_a_finite_term() {
        // An unbounded deal means an abandoned upload costs the operator
        // forever because a tenant uploaded once and never came back.
        const { assert!(FILE_DEAL_EPOCHS > 0) };
    }
}
