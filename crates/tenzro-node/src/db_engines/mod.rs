//! Node-layer database-engine drivers.
//!
//! [`tenzro_database`] owns the engine-agnostic protocol layer: the catalog,
//! placement rules, the [`tenzro_database::DatabaseEngine`] trait, and the
//! opaque per-engine config. It never links an engine driver. This module is
//! the counterpart — one concrete `impl DatabaseEngine` per engine a node can
//! serve, plus [`build_registry_from_config`], which reads the operator's
//! [`DatabasesConfig`] and registers the backends the operator wired up.
//!
//! The model is connect-to-existing for the external-process engines: the
//! operator runs Postgres / Qdrant / Valkey themselves and points the node at
//! the endpoint via config. The driver is a thin client — it never spawns,
//! supervises, or tears down the server process; `start_partition` /
//! `stop_partition` are the logical partition seam (create/drop the
//! collection, schema, or namespace), not process lifecycle. The embedded
//! engines (Lance / Tantivy) serve in-process under `{data_dir}/databases/`.

use std::path::PathBuf;
use std::sync::Arc;

use tenzro_database::DatabaseEngine;

use crate::config::DatabasesConfig;
use crate::db_engine_registry::EngineRegistry;

pub mod lance;
pub mod postgres;
pub mod qdrant;
pub mod tantivy;
pub mod valkey;

pub use lance::LanceEngine;
pub use postgres::PostgresEngine;
pub use qdrant::QdrantEngine;
pub use tantivy::TantivyEngine;
pub use valkey::ValkeyEngine;

/// Builds an [`EngineRegistry`] from the operator's database config.
///
/// Each engine is registered only when the operator configured its endpoint
/// (external engines) or opted the embedded engine in. A node with no database
/// config serves no engines and its registry is empty — the query path answers
/// with a routing error, never a panic. `data_dir` roots the embedded engines
/// under `{data_dir}/databases/{lance,tantivy}/`.
pub fn build_registry_from_config(cfg: &DatabasesConfig, data_dir: &std::path::Path) -> EngineRegistry {
    let registry = EngineRegistry::new();

    if let Some(url) = &cfg.postgres_url {
        registry.register(Arc::new(PostgresEngine::new(url.clone())) as Arc<dyn DatabaseEngine>);
    }
    if let Some(url) = &cfg.qdrant_url {
        registry.register(
            Arc::new(QdrantEngine::new(url.clone(), cfg.qdrant_api_key.clone()))
                as Arc<dyn DatabaseEngine>,
        );
    }
    if let Some(url) = &cfg.valkey_url {
        registry.register(Arc::new(ValkeyEngine::new(url.clone())) as Arc<dyn DatabaseEngine>);
    }
    if cfg.lance_embedded {
        let root: PathBuf = data_dir.join("databases").join("lance");
        registry.register(Arc::new(LanceEngine::new(root)) as Arc<dyn DatabaseEngine>);
    }
    if cfg.tantivy_embedded {
        let root: PathBuf = data_dir.join("databases").join("tantivy");
        registry.register(Arc::new(TantivyEngine::new(root)) as Arc<dyn DatabaseEngine>);
    }

    registry
}
