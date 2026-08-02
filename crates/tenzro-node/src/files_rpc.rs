//! The JSON-RPC half of `/v1/files`, and the surface the MCP tools sit on.
//!
//! # Why the same thing twice
//!
//! `/v1/files` exists because an application developer already has an OpenAI
//! SDK pointed at this node and expects `client.files.create(...)` to work.
//! These RPCs exist because an *agent* reaching the node over MCP has no HTTP
//! client, no multipart encoder, and no notion of a REST path — it has a tool
//! list. Both surfaces run the same tenant resolution, the same validation, and
//! the same index, so they cannot drift into disagreeing about who owns what.
//!
//! Base64 rather than multipart here, because a JSON-RPC envelope has nowhere
//! to put a binary part. That caps the practical upload well below
//! [`crate::files_api::MAX_UPLOAD_BYTES`] — base64 inflates by a third and the
//! whole envelope must be buffered as one JSON value — which is the honest
//! trade for a surface an agent can reach at all.

use std::sync::Arc;

use base64::Engine as _;
use serde_json::{Value, json};

use crate::api_key::ApiKeyScope;
use crate::files_api::{
    FileDeletion, FileObject, FilePurpose, file_id_for, object_id_from, validate_upload,
};
use crate::files_store::DEFAULT_LIST_LIMIT;
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Every RPC method this module serves.
///
/// Named once so the scope gate, the default-deny classification table, and
/// the MCP tool list cannot disagree about what the storage surface is.
pub const FILE_METHODS: &[&str] = &[
    "tenzro_deleteFile",
    "tenzro_downloadFile",
    "tenzro_fileStorageUsage",
    "tenzro_getFile",
    "tenzro_listFiles",
    "tenzro_uploadFile",
];

/// Whether `method` belongs to the storage surface.
pub fn is_file_method(method: &str) -> bool {
    FILE_METHODS.contains(&method)
}

/// Resolve the calling tenant's DID from their API key.
///
/// The scope check is deliberately repeated here even though `gate_api_key`
/// runs upstream: this function is what turns a key into an *owner*, and an
/// ownership decision that depends on a gate somewhere else having run is one
/// that silently becomes wrong the day a new dispatch path forgets to call it.
fn tenant_did(node: &Arc<TenzroNode>, api_key: Option<&str>) -> Result<String, JsonRpcError> {
    let mgr = node.api_key_manager().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "API key manager is not initialized; this node cannot attribute a file to a \
                  tenant"
            .to_string(),
        data: None,
    })?;
    let presented = api_key.ok_or_else(|| JsonRpcError {
        code: -32004,
        message: "Unauthorized: missing X-Tenzro-Api-Key header. Every file has an owner, so \
                  the storage surface has no unauthenticated path — including for reads."
            .to_string(),
        data: None,
    })?;
    let record = mgr.lookup(presented).ok_or_else(|| JsonRpcError {
        code: -32004,
        message: "Unauthorized: API key is unknown or revoked".to_string(),
        data: None,
    })?;
    if !record.scopes.contains(&ApiKeyScope::Storage) {
        return Err(JsonRpcError {
            code: -32004,
            message: "Unauthorized: API key lacks required scope (storage)".to_string(),
            data: None,
        });
    }
    record
        .subject
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| JsonRpcError {
            code: -32004,
            message: "Unauthorized: the presented key names no subject, so it cannot own a file"
                .to_string(),
            data: None,
        })
}

fn missing(field: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: format!("Missing '{field}'"),
        data: None,
    }
}

fn params_or_err(params: Option<Value>) -> Result<Value, JsonRpcError> {
    params.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Missing params".to_string(),
        data: None,
    })
}

/// The record for `file_id`, if it belongs to `tenant`.
///
/// "Not yours" and "no such file" collapse to one error, deliberately: a
/// distinct "forbidden" confirms the id exists and turns the id space into an
/// oracle a caller can walk.
fn owned(node: &Arc<TenzroNode>, tenant: &str, file_id: &str) -> Result<FileObject, JsonRpcError> {
    node.file_index()
        .get(file_id)
        .filter(|f| f.visible_to(tenant))
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: format!("No file '{file_id}'"),
            data: None,
        })
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, JsonRpcError> {
    serde_json::to_value(v).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("Serialization failed: {e}"),
        data: None,
    })
}

/// `tenzro_uploadFile` — store a base64 payload as a tenant-owned file.
///
/// Params: `filename`, `data` (base64), optional `purpose`.
pub(crate) async fn handle_upload_file(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    api_key: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let tenant = tenant_did(node, api_key)?;
    let params = params_or_err(params)?;
    let runtime = node
        .storage_runtime()
        .cloned()
        .ok_or_else(|| JsonRpcError {
            code: -32004,
            message:
                "This node does not run the StorageProvider role, so it has nowhere to put a file"
                    .to_string(),
            data: None,
        })?;

    let filename = params
        .get("filename")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("filename"))?
        .to_string();
    let data_b64 = params
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("data"))?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("Invalid base64 'data': {e}"),
            data: None,
        })?;
    // An explicit `null` is treated as absent, not as a parse failure: an MCP
    // client serializing an `Option<String>` field emits `"purpose": null`
    // when the caller omitted it, and refusing that would make the optional
    // parameter mandatory for every agent.
    let purpose = match params.get("purpose").filter(|p| !p.is_null()) {
        Some(p) => serde_json::from_value::<FilePurpose>(p.clone()).map_err(|_| JsonRpcError {
            code: -32602,
            message: "Unknown 'purpose'. Valid values: assistants, batch, fine_tune, vision, \
                      user_data"
                .to_string(),
            data: None,
        })?,
        None => FilePurpose::default(),
    };

    validate_upload(&filename, data.len() as u64).map_err(|e| JsonRpcError {
        code: -32602,
        message: e.to_string(),
        data: None,
    })?;

    let object_id = uuid::Uuid::new_v4().to_string();
    let scheme = crate::files_routes::file_redundancy().map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("The node's redundancy scheme is invalid: {e}"),
        data: None,
    })?;
    let size = data.len() as u64;

    runtime
        .store_object(
            object_id.clone(),
            tenant.clone(),
            &data,
            scheme,
            tenzro_types::access_policy::AccessPolicy::owner_only(tenant.clone()),
            None,
        )
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("The object could not be stored: {e}"),
            data: None,
        })?;

    // As on the HTTP path: a file whose deal could not be opened is still
    // stored and still listable. Discarding bytes the node has already coded
    // and published would be worse for the tenant than a file the operator is
    // carrying unbilled.
    let deal_id = runtime
        .open_deal(
            object_id.clone(),
            crate::files_routes::renter_address(&tenant),
            tenzro_types::asset::AssetId::tnzo(),
            size,
            crate::files_routes::FILE_DEAL_EPOCHS,
        )
        .ok()
        .map(|d| d.deal_id);

    let record = FileObject {
        id: file_id_for(&object_id),
        object: "file",
        bytes: size,
        created_at: crate::files_routes::now_secs(),
        filename,
        purpose,
        owner: tenant,
        deal_id,
    };
    node.file_index().insert(record.clone());
    to_value(record)
}

/// `tenzro_listFiles` — the caller's own files. Params: optional `purpose`,
/// optional `limit`.
pub(crate) async fn handle_list_files(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    api_key: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let tenant = tenant_did(node, api_key)?;
    let params = params.unwrap_or_else(|| json!({}));
    let purpose = match params.get("purpose") {
        Some(p) if !p.is_null() => Some(serde_json::from_value::<FilePurpose>(p.clone()).map_err(
            |_| JsonRpcError {
                code: -32602,
                message: "Unknown 'purpose'".to_string(),
                data: None,
            },
        )?),
        _ => None,
    };
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(DEFAULT_LIST_LIMIT);

    let index = node.file_index();
    let data = index.list(&tenant, purpose, limit);
    Ok(json!({
        "object": "list",
        "data": data,
        "total_bytes": index.bytes_for(&tenant),
    }))
}

/// `tenzro_getFile` — one record. Params: `file_id`.
pub(crate) async fn handle_get_file(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    api_key: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let tenant = tenant_did(node, api_key)?;
    let params = params_or_err(params)?;
    let file_id = params
        .get("file_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("file_id"))?;
    to_value(owned(node, &tenant, file_id)?)
}

/// `tenzro_downloadFile` — the bytes, base64-encoded. Params: `file_id`.
pub(crate) async fn handle_download_file(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    api_key: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let tenant = tenant_did(node, api_key)?;
    let params = params_or_err(params)?;
    let file_id = params
        .get("file_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("file_id"))?;
    let record = owned(node, &tenant, file_id)?;
    let runtime = node
        .storage_runtime()
        .cloned()
        .ok_or_else(|| JsonRpcError {
            code: -32004,
            message: "This node does not run the StorageProvider role".to_string(),
            data: None,
        })?;
    let object_id = object_id_from(&record.id).ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "This file's id does not resolve to a stored object".to_string(),
        data: None,
    })?;
    let bytes = runtime
        .store()
        .retrieve_object(object_id)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!(
                "The file is indexed but its bytes could not be rebuilt from shards: {e}"
            ),
            data: None,
        })?;
    Ok(json!({
        "file_id": record.id,
        "filename": record.filename,
        "bytes": bytes.len(),
        "data": base64::engine::general_purpose::STANDARD.encode(&bytes),
    }))
}

/// `tenzro_deleteFile` — unlink the tenant's reference. Params: `file_id`.
pub(crate) async fn handle_delete_file(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    api_key: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let tenant = tenant_did(node, api_key)?;
    let params = params_or_err(params)?;
    let file_id = params
        .get("file_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("file_id"))?;
    // Ownership is checked before removal so one tenant cannot delete
    // another's row by naming its id.
    owned(node, &tenant, file_id)?;
    node.file_index().remove(file_id);
    to_value(FileDeletion::unlinked(file_id))
}

/// `tenzro_fileStorageUsage` — what the caller is storing, and what it will be
/// billed against.
pub(crate) async fn handle_file_storage_usage(
    node: &Arc<TenzroNode>,
    api_key: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let tenant = tenant_did(node, api_key)?;
    let index = node.file_index();
    let files = index.list(&tenant, None, crate::files_store::MAX_LIST_LIMIT);
    let with_deal = files.iter().filter(|f| f.deal_id.is_some()).count();
    Ok(json!({
        "owner": tenant,
        "file_count": files.len(),
        "total_bytes": index.bytes_for(&tenant),
        "files_with_open_deal": with_deal,
        // Surfaced rather than left to be inferred: a file without a deal is
        // stored but unbilled, which the operator is carrying and the tenant
        // should not assume is durable indefinitely.
        "files_without_open_deal": files.len().saturating_sub(with_deal),
        "renter_address": crate::files_routes::renter_address(&tenant).to_base58(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_method_list_is_sorted_and_unique() {
        // Three tables key off this list — the scope gate, the default-deny
        // classification, and the MCP tool set. Sorted-and-unique is what
        // makes a diff against any of them readable.
        let mut sorted = FILE_METHODS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, FILE_METHODS);
    }

    #[test]
    fn every_file_method_is_namespaced() {
        for m in FILE_METHODS {
            assert!(m.starts_with("tenzro_"), "{m}");
            assert!(is_file_method(m));
        }
        assert!(!is_file_method("tenzro_chat"));
        assert!(!is_file_method(""));
    }
}
