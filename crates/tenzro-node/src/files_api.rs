//! `/v1/files` — an OpenAI-shaped file API over the storage provider.
//!
//! # Why a projection rather than a new store
//!
//! [`tenzro_storage_provider`] already does the hard parts: systematic
//! Reed-Solomon erasure coding, proof-of-retrievability spot checks, per-epoch
//! metered payment gated on passing those checks, and rendezvous shard
//! placement with no coordinator. What it does not have is a shape an
//! application developer recognises. Its surface is a *storage-deal
//! marketplace* — open a funded deal, store against it, prove retrievability,
//! stream payment — which is the right primitive and the wrong first
//! encounter.
//!
//! So this is a thin projection: a developer who can call
//! `/v1/chat/completions` can upload a file without learning any of the above,
//! while the operator keeps metering and the renter keeps their guarantees.
//!
//! # Deletion does not erase bytes
//!
//! The honest part, stated here because it belongs in the API documentation
//! rather than only in a code comment. Objects are content-addressed and
//! erasure-coded across independent providers. `DELETE` unlinks the tenant's
//! reference and stops the deal; it does not and cannot reach into every
//! provider holding a shard and erase it. Shards expire when the deal stops
//! paying for them.
//!
//! That has real consequences a tenant must understand *before* storing
//! anything sensitive, so [`FileDeletion::note`] carries it in the response
//! rather than leaving it to be discovered.

use serde::{Deserialize, Serialize};

/// Ceiling on a single upload, in bytes.
///
/// Erasure coding expands an object before it is distributed, so the shard
/// traffic is a multiple of what arrives. A cap belongs at the entry point
/// rather than only at the provider, where the amplification has already
/// happened.
pub const MAX_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// What a file is for, mirroring OpenAI's `purpose`.
///
/// Kept because SDKs send it and tooling filters on it. Tenzro attaches no
/// behaviour to it beyond storing and returning it — inventing meanings that
/// OpenAI's does not have would make the field mean two different things
/// depending on which server answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilePurpose {
    /// Retrieval / RAG corpora.
    Assistants,
    /// Batch job input.
    Batch,
    /// Fine-tuning data.
    FineTune,
    /// Vision inputs.
    Vision,
    /// Anything else the tenant is keeping.
    ///
    /// The default: a tenant who says nothing about what a file is for has
    /// not said it is training data.
    #[default]
    UserData,
}

/// SHA-256 of a stored payload, lowercase hex.
///
/// Over the decoded bytes, never the transport encoding they arrived in: a
/// digest of the base64 would describe how the file was sent rather than what
/// it contains, and two callers using different encodings would get different
/// digests for identical content.
///
/// One function because both upload paths need it. Written inline twice, the
/// two copies drift and the same bytes get two answers.
pub(crate) fn content_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// A stored file, in the shape OpenAI clients expect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileObject {
    /// Opaque id. Prefixed `file-` so it is recognisable in logs and matches
    /// the convention clients already parse.
    pub id: String,
    /// Always `"file"`.
    ///
    /// A constant of the type rather than stored data. It is emitted because
    /// OpenAI clients switch on it, and ignored on the way back in: a
    /// persisted record whose tag disagreed with its type would be one this
    /// node should not have written, so trusting the stored value over the
    /// type would be trusting the wrong side.
    #[serde(skip_deserializing, default = "file_tag")]
    pub object: &'static str,
    /// Size in bytes.
    pub bytes: u64,
    /// SHA-256 of the stored payload, lowercase hex.
    ///
    /// A `file_id` names a location; this names the content. An agent that
    /// offloads a tool result and hands the id to its next turn -- or to a
    /// subagent it delegated to -- can check that what it reads back is what
    /// was written, instead of trusting the index.
    ///
    /// Deliberately not `#[serde(default)]`: a record written before this
    /// existed fails to load rather than loading with an empty digest, which
    /// would read as "verified" against nothing.
    pub sha256: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Original filename.
    pub filename: String,
    /// What it is for.
    pub purpose: FilePurpose,

    /// The tenant that owns it.
    ///
    /// Not in OpenAI's shape — they scope by API key implicitly. Carried
    /// explicitly because this node serves many tenants and an ownership
    /// field that is implicit is an ownership field that gets forgotten in
    /// the query that lists them.
    pub owner: String,
    /// The storage deal paying for it, so an operator can join a file to what
    /// is funding its shards.
    pub deal_id: Option<String>,
}

impl FileObject {
    /// Whether `tenant` may see this file.
    ///
    /// The whole isolation property, in one place so it cannot be applied
    /// inconsistently across list, retrieve, content and delete. Every one of
    /// those must ask, and asking in four places is how three of them end up
    /// asking differently.
    pub fn visible_to(&self, tenant: &str) -> bool {
        self.owner == tenant
    }
}

/// What a deletion actually did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeletion {
    /// The id that was unlinked.
    pub id: String,
    /// Always `"file"`. See [`FileObject::object`].
    #[serde(skip_deserializing, default = "file_tag")]
    pub object: &'static str,
    /// Whether the reference was removed.
    pub deleted: bool,
    /// What deletion means here.
    ///
    /// Present on every response, not only the first: a tenant automating
    /// against this API should not have to have read the documentation to
    /// learn that content-addressed shards are not erased on request.
    #[serde(skip_deserializing, default = "deletion_note")]
    pub note: &'static str,
}

/// The `object` discriminator, as a function so serde can name it.
fn file_tag() -> &'static str {
    "file"
}

/// [`DELETION_NOTE`], as a function so serde can name it.
fn deletion_note() -> &'static str {
    DELETION_NOTE
}

/// The note returned with every deletion.
pub const DELETION_NOTE: &str = "The tenant reference was removed and its storage deal stopped. Shards are \
     content-addressed and erasure-coded across independent providers, so the \
     underlying bytes are not erased on request — they expire when the deal stops \
     paying for them. Do not treat deletion as redaction.";

impl FileDeletion {
    /// An unlinked file.
    pub fn unlinked(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            object: "file",
            deleted: true,
            note: DELETION_NOTE,
        }
    }
}

/// Why an upload was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadRejection {
    /// Nothing was sent.
    Empty,
    /// Larger than [`MAX_UPLOAD_BYTES`].
    TooLarge {
        /// What arrived.
        bytes: u64,
        /// The cap.
        limit: u64,
    },
    /// No filename was given.
    MissingFilename,
}

impl std::fmt::Display for UploadRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "the uploaded file is empty"),
            Self::TooLarge { bytes, limit } => write!(
                f,
                "the upload is {:.1} MB; the limit is {:.0} MB. Erasure coding expands an \
                 object before distributing it, so the shard traffic is a multiple of what \
                 arrives",
                *bytes as f64 / 1e6,
                *limit as f64 / 1e6
            ),
            Self::MissingFilename => write!(f, "the upload has no filename"),
        }
    }
}

impl std::error::Error for UploadRejection {}

/// Check an upload before anything is stored.
pub fn validate_upload(filename: &str, bytes: u64) -> Result<(), UploadRejection> {
    if filename.trim().is_empty() {
        return Err(UploadRejection::MissingFilename);
    }
    if bytes == 0 {
        return Err(UploadRejection::Empty);
    }
    if bytes > MAX_UPLOAD_BYTES {
        return Err(UploadRejection::TooLarge {
            bytes,
            limit: MAX_UPLOAD_BYTES,
        });
    }
    Ok(())
}

/// Derive a stable file id from the object id.
pub fn file_id_for(object_id: &str) -> String {
    format!("file-{object_id}")
}

/// Recover the object id from a file id.
///
/// Returns `None` for an id that was not minted here, so a caller cannot
/// address arbitrary objects by inventing a `file-` prefix.
pub fn object_id_from(file_id: &str) -> Option<&str> {
    file_id.strip_prefix("file-").filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest is over the payload, not the encoding it arrived in.
    ///
    /// The upload decodes base64 before storing, so hashing the wrong side is
    /// a live mistake rather than a hypothetical one — and it would still
    /// produce a plausible-looking digest. Comparing the two candidates is
    /// what makes this test able to fail.
    #[test]
    fn the_digest_covers_the_decoded_payload_not_its_encoding() {
        use base64::Engine as _;

        let payload = b"the quick brown fox";
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);

        let of_payload = content_digest(payload);
        let of_encoding = content_digest(encoded.as_bytes());

        assert_ne!(
            of_payload, of_encoding,
            "the two candidates must differ or this proves nothing"
        );
        assert_eq!(
            of_payload, "9ecb36561341d18eb65484e833efea61edc74b84cf5e6ae1b81c63533e25fc8f",
            "the digest a caller verifies against must not move"
        );
    }

    /// Both upload routes agree on the same bytes.
    ///
    /// This is the property the extraction exists to hold: a file uploaded
    /// over JSON-RPC and the same file uploaded over REST must be addressable
    /// by the same digest, or "verify this handle" means different things
    /// depending on how the bytes got there.
    ///
    /// The property is held *by construction* — there is one
    /// [`content_digest`] and both routes call it — so no value-level
    /// assertion can fail. This previously compared `content_digest(bytes)`
    /// against `content_digest(&bytes.to_vec())`, which is the same function
    /// over the same `&[u8]`: it asserted that a pure function is
    /// deterministic and would have passed just as happily with the two routes
    /// hashing differently.
    ///
    /// What can actually regress is a route grinding its own digest inline, so
    /// the guard is structural: each route must delegate here, and must not
    /// construct a hasher of its own.
    #[test]
    fn every_upload_route_digests_identically() {
        for (name, src) in [
            ("files_routes.rs", include_str!("files_routes.rs")),
            ("files_rpc.rs", include_str!("files_rpc.rs")),
        ] {
            let impl_only = src.split("#[cfg(test)]").next().unwrap();
            // Self-check: if the file were empty or unreadable the two
            // assertions below would pass vacuously, which is the failure mode
            // that makes a structural guard worse than no guard.
            assert!(
                impl_only.len() > 500,
                "{name} read as {} bytes — this guard is no longer reading the \
                 route it claims to cover",
                impl_only.len()
            );
            // Pins the binding, not merely a mention of the function: what
            // regresses is a route computing `sha256` some other way, and
            // `contains("content_digest(")` would still pass if the call
            // survived somewhere unrelated while the stored digest changed.
            //
            // Deliberately *not* a blanket ban on `Sha256::new()` in these
            // files. `files_routes.rs::renter_address` legitimately hashes a
            // DID into a billing address under its own domain separator, so
            // that ban fires on correct code — which is how a structural guard
            // gets weakened or deleted rather than fixed.
            assert!(
                impl_only.contains("let sha256 = crate::files_api::content_digest("),
                "{name} no longer binds its stored digest from \
                 files_api::content_digest, so the two upload routes can \
                 disagree on the digest a handle is verified against"
            );
        }
    }

    fn file(owner: &str) -> FileObject {
        FileObject {
            id: "file-abc".to_string(),
            object: "file",
            bytes: 1024,
            // sha256 of the empty string: a real digest of real bytes, so a
            // test that later verifies one finds a value a payload could
            // actually produce.
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            created_at: 0,
            filename: "notes.txt".to_string(),
            purpose: FilePurpose::UserData,
            owner: owner.to_string(),
            deal_id: None,
        }
    }

    #[test]
    fn a_file_is_visible_only_to_its_owner() {
        // The isolation property. Kept in one place so list, retrieve,
        // content and delete cannot end up asking it differently.
        let f = file("did:tenzro:human:alice");
        assert!(f.visible_to("did:tenzro:human:alice"));
        assert!(!f.visible_to("did:tenzro:human:bob"));
        assert!(!f.visible_to(""));
    }

    #[test]
    fn an_empty_upload_is_refused() {
        assert_eq!(
            validate_upload("a.txt", 0).unwrap_err(),
            UploadRejection::Empty
        );
    }

    #[test]
    fn an_upload_without_a_filename_is_refused() {
        assert_eq!(
            validate_upload("   ", 10).unwrap_err(),
            UploadRejection::MissingFilename
        );
    }

    #[test]
    fn an_oversize_upload_is_refused_and_explains_the_amplification() {
        // The cap belongs at the entry point: erasure coding expands the
        // object before distribution, so by the time the provider sees it the
        // multiplication has already happened.
        let err = validate_upload("big.bin", MAX_UPLOAD_BYTES + 1).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Erasure coding expands"), "{msg}");
        validate_upload("ok.bin", MAX_UPLOAD_BYTES).expect("exactly at the cap is fine");
    }

    #[test]
    fn deletion_always_says_that_it_is_not_erasure() {
        // A tenant automating against this should not have to have read the
        // docs to learn that content-addressed shards survive a DELETE.
        let d = FileDeletion::unlinked("file-abc");
        assert!(d.deleted);
        assert!(d.note.contains("not erased on request"), "{}", d.note);
        assert!(d.note.contains("Do not treat deletion as redaction"));
    }

    #[test]
    fn file_ids_round_trip_through_their_object_id() {
        let id = file_id_for("obj-123");
        assert_eq!(id, "file-obj-123");
        assert_eq!(object_id_from(&id), Some("obj-123"));
    }

    #[test]
    fn an_id_that_was_not_minted_here_resolves_to_nothing() {
        // Otherwise a caller could address arbitrary stored objects just by
        // inventing the prefix.
        assert_eq!(object_id_from("obj-123"), None);
        assert_eq!(object_id_from("file-"), None);
        assert_eq!(object_id_from(""), None);
    }

    #[test]
    fn the_default_purpose_is_the_neutral_one() {
        // A tenant who says nothing about what a file is for has not said it
        // is training data.
        assert_eq!(FilePurpose::default(), FilePurpose::UserData);
    }

    #[test]
    fn the_wire_shape_matches_what_openai_clients_parse() {
        let json = serde_json::to_value(file("alice")).expect("serializes");
        for key in ["id", "object", "bytes", "created_at", "filename", "purpose"] {
            assert!(json.get(key).is_some(), "missing {key}");
        }
        assert_eq!(json["object"], "file");
        assert_eq!(json["purpose"], "user_data");
    }
}
