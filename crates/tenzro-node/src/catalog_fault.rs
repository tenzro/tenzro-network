//! A validator's verdict on a catalog fault.
//!
//! A catalog fault says a signed catalog entry pins a SHA-256 or size its
//! component's source does not hold. The validator fetches what the source
//! holds and compares:
//!
//! - a network component is fetched by its BLAKE3 content address from the
//!   storage providers holding it; bytes that do not hash to the address are
//!   not the addressed bytes and give no verdict;
//! - a hub component is read at its pinned commit: the repository's record
//!   of a large file names its SHA-256 and size, and a small file's bytes are
//!   fetched and hashed.
//!
//! Upheld means the source holds something other than what the entry pins.
//! A source that cannot be reached gives no verdict, so an outage never
//! slashes a publisher.

use sha2::{Digest, Sha256};
use tenzro_iroh::IrohResolver as _;
use tenzro_model::catalog::{Component, Source};
use tenzro_vm::native::inference_fault::CatalogFault;
use tracing::debug;

use crate::node::TenzroNode;

/// Largest hub file fetched whole to hash it; larger hub files are checked
/// against the repository's own SHA-256 record.
const HUB_INLINE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// What a component's source holds: its size and lowercase hex SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    size: u64,
    sha256: String,
}

/// The verdict on `fault`: `Some(true)` when the source holds bytes other
/// than the entry pins, `Some(false)` when it holds exactly them, `None` when
/// this validator could not read the source.
pub async fn judge(node: &TenzroNode, fault: &CatalogFault) -> Option<bool> {
    let Ok(component) = serde_json::from_value::<Component>(fault.pinned.clone()) else {
        // The chain read the component out of a signed entry; one this node
        // cannot read gives no verdict.
        return None;
    };
    let held = match &component.source {
        Source::Network { blake3, .. } => network_held(node, blake3).await,
        Source::Hub { revision } => {
            hub_held(node, &component.repo, revision, &component.path).await
        }
    }?;
    Some(differs(&component, &held))
}

fn differs(component: &Component, held: &Held) -> bool {
    held.size != component.size || !held.sha256.eq_ignore_ascii_case(&component.sha256)
}

async fn network_held(node: &TenzroNode, blake3_hex: &str) -> Option<Held> {
    let resolver = node.iroh_resolver.as_ref()?;
    let uri = tenzro_types::tenzro_uri::TenzroUri::Blob {
        hash: blake3_hex.to_ascii_lowercase(),
        provider_hint: None,
    };
    let bytes = match resolver.fetch_bytes(&uri).await {
        Ok(b) => b,
        Err(e) => {
            debug!(address = %blake3_hex, error = %e, "catalog fault: component not fetched");
            return None;
        }
    };
    if !blake3::hash(&bytes)
        .to_hex()
        .as_str()
        .eq_ignore_ascii_case(blake3_hex)
    {
        return None;
    }
    Some(Held {
        size: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

/// One entry of a hub repository tree listing.
#[derive(serde::Deserialize)]
struct TreeEntry {
    path: String,
    size: u64,
    #[serde(default)]
    lfs: Option<LfsRecord>,
}

#[derive(serde::Deserialize)]
struct LfsRecord {
    oid: String,
    size: u64,
}

async fn hub_held(node: &TenzroNode, repo: &str, revision: &str, path: &str) -> Option<Held> {
    let egress = node.egress();
    let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    let listing = format!("https://huggingface.co/api/models/{repo}/tree/{revision}/{dir}");
    let request = egress
        .get(&listing, crate::egress_guard::Scheme::HttpsOnly)
        .ok()?;
    let response = egress
        .send(request)
        .await
        .ok()
        .filter(|r| r.status().is_success())?;
    let entries: Vec<TreeEntry> = response.json().await.ok()?;
    let entry = entries.into_iter().find(|e| e.path == path)?;
    if let Some(lfs) = entry.lfs {
        return Some(Held {
            size: lfs.size,
            sha256: lfs.oid.to_ascii_lowercase(),
        });
    }
    if entry.size as usize > HUB_INLINE_MAX_BYTES {
        return None;
    }
    let file = format!("https://huggingface.co/{repo}/resolve/{revision}/{path}");
    let request = egress
        .get(&file, crate::egress_guard::Scheme::HttpsOnly)
        .ok()?;
    let response = egress
        .send(request)
        .await
        .ok()
        .filter(|r| r.status().is_success())?;
    let bytes = response
        .with_limit(HUB_INLINE_MAX_BYTES)
        .bytes()
        .await
        .ok()?;
    Some(Held {
        size: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(size: u64, sha256: &str) -> Component {
        serde_json::from_value(serde_json::json!({
            "repo": "o/m",
            "path": "m.gguf",
            "revision": "c".repeat(40),
            "size": size,
            "sha256": sha256,
        }))
        .unwrap()
    }

    #[test]
    fn a_source_holding_other_bytes_or_another_size_upholds_the_fault() {
        let pinned = component(4, &"ab".repeat(32));
        let same = Held {
            size: 4,
            sha256: "AB".repeat(32),
        };
        assert!(!differs(&pinned, &same));
        assert!(differs(
            &pinned,
            &Held {
                size: 5,
                ..same.clone()
            }
        ));
        assert!(differs(
            &pinned,
            &Held {
                sha256: "cd".repeat(32),
                ..same
            }
        ));
    }
}
