//! Qdrant driver — connect-to-existing over the REST API.
//!
//! The operator runs Qdrant; the node talks to its HTTP endpoint
//! (`http://host:6333`) with an optional api-key header. Tenzro shards by
//! placing one collection per partition, so a partition maps to a named
//! collection. `start_partition` creates the collection with the descriptor's
//! vector dimension + distance; `stop_partition` deletes it (both idempotent).
//!
//! The query `body` is `{ "op": "upsert" | "search" | "count", ... }`:
//! - `upsert`: `{ "op": "upsert", "points": [ {id, vector, payload?}, ... ] }`
//! - `search`: `{ "op": "search", "vector": [...], "limit": N, "filter"?: {...} }`
//! - `count`:  `{ "op": "count" }`
//!
//! Each op forwards to the matching Qdrant REST endpoint and returns Qdrant's
//! JSON `result` verbatim.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use tenzro_database::{
    DatabaseEngine, DatabaseError, PartitionHandle, PartitionHealth, QueryRequest, QueryResponse,
    Result, catalog::engine_ids,
};

/// A thin REST client to an operator-run Qdrant endpoint.
pub struct QdrantEngine {
    base_url: String,
    api_key: Option<String>,
    http: Client,
}

impl QdrantEngine {
    /// Binds the driver to the operator's Qdrant base URL (`http://host:6333`)
    /// and optional api key.
    pub fn new(base_url: String, api_key: Option<String>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            http: crate::http_client::shared().clone(),
        }
    }

    fn collection_name(handle: &PartitionHandle) -> String {
        // Prefer the descriptor's explicit collection name; fall back to a
        // deterministic per-partition name.
        if let Ok(cfg) = serde_json::from_value::<QdrantCfg>(handle.engine_config.clone())
            && let Some(c) = cfg.collection
        {
            return format!("{c}_{}", handle.partition_index);
        }
        format!("tz_{}_{}", handle.database_id, handle.partition_index)
    }

    fn collection_for_request(&self, request: &QueryRequest) -> String {
        format!("tz_{}_{}", request.database_id, request.partition_index)
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut b = self
            .http
            .request(method, format!("{}{path}", self.base_url));
        if let Some(k) = &self.api_key {
            b = b.header("api-key", k);
        }
        b
    }

    async fn send(&self, b: reqwest::RequestBuilder) -> Result<serde_json::Value> {
        let resp = b
            .send()
            .await
            .map_err(|e| DatabaseError::Backend(format!("qdrant request: {e}")))?;
        let status = resp.status();
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| DatabaseError::Backend(format!("qdrant decode: {e}")))?;
        if !status.is_success() {
            return Err(DatabaseError::Query(format!("qdrant {status}: {json}")));
        }
        Ok(json)
    }
}

#[async_trait]
impl DatabaseEngine for QdrantEngine {
    fn engine_id(&self) -> &str {
        engine_ids::QDRANT
    }

    async fn start_partition(&self, handle: &PartitionHandle) -> Result<()> {
        let cfg: QdrantCfg = serde_json::from_value(handle.engine_config.clone())
            .map_err(|e| DatabaseError::InvalidRequest(format!("qdrant config: {e}")))?;
        let dimension = cfg.dimension.ok_or_else(|| {
            DatabaseError::InvalidRequest("qdrant config missing dimension".into())
        })?;
        let distance = match cfg.distance.as_deref().unwrap_or("cosine") {
            "cosine" | "Cosine" => "Cosine",
            "dot" | "Dot" => "Dot",
            "euclid" | "Euclid" => "Euclid",
            other => {
                return Err(DatabaseError::InvalidRequest(format!(
                    "qdrant distance '{other}' not one of cosine/dot/euclid"
                )));
            }
        };
        let collection = Self::collection_name(handle);
        let body = serde_json::json!({
            "vectors": { "size": dimension, "distance": distance }
        });
        // PUT is idempotent-ish: Qdrant returns 409 if it already exists, which
        // we treat as success.
        let resp = self
            .req(reqwest::Method::PUT, &format!("/collections/{collection}"))
            .json(&body)
            .send()
            .await
            .map_err(|e| DatabaseError::Backend(format!("qdrant create: {e}")))?;
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::CONFLICT {
            Ok(())
        } else {
            let status = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            Err(DatabaseError::Backend(format!(
                "qdrant create {status}: {txt}"
            )))
        }
    }

    async fn stop_partition(&self, handle: &PartitionHandle) -> Result<()> {
        let collection = Self::collection_name(handle);
        let resp = self
            .req(
                reqwest::Method::DELETE,
                &format!("/collections/{collection}"),
            )
            .send()
            .await
            .map_err(|e| DatabaseError::Backend(format!("qdrant delete: {e}")))?;
        // 404 = already gone; treat as success (idempotent).
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            let status = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            Err(DatabaseError::Backend(format!(
                "qdrant delete {status}: {txt}"
            )))
        }
    }

    async fn query(&self, request: &QueryRequest) -> Result<QueryResponse> {
        let op: QdrantOp = serde_json::from_value(request.body.clone())
            .map_err(|e| DatabaseError::InvalidRequest(format!("qdrant op: {e}")))?;
        let collection = self.collection_for_request(request);
        let result = match op {
            QdrantOp::Upsert { points } => {
                let body = serde_json::json!({ "points": points });
                self.send(
                    self.req(
                        reqwest::Method::PUT,
                        &format!("/collections/{collection}/points?wait=true"),
                    )
                    .json(&body),
                )
                .await?
            }
            QdrantOp::Search {
                vector,
                limit,
                filter,
            } => {
                let mut body = serde_json::json!({
                    "vector": vector,
                    "limit": limit,
                    "with_payload": true,
                });
                if let Some(f) = filter {
                    body["filter"] = f;
                }
                self.send(
                    self.req(
                        reqwest::Method::POST,
                        &format!("/collections/{collection}/points/search"),
                    )
                    .json(&body),
                )
                .await?
            }
            QdrantOp::Count => {
                self.send(
                    self.req(
                        reqwest::Method::POST,
                        &format!("/collections/{collection}/points/count"),
                    )
                    .json(&serde_json::json!({ "exact": true })),
                )
                .await?
            }
        };
        // Qdrant wraps payloads in { "result": ..., "status": ..., "time": ... }.
        let inner = result.get("result").cloned().unwrap_or(result);
        Ok(QueryResponse { body: inner })
    }

    async fn partition_health(&self, handle: &PartitionHandle) -> Result<PartitionHealth> {
        let collection = Self::collection_name(handle);
        let resp = self
            .req(reqwest::Method::GET, &format!("/collections/{collection}"))
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => Ok(PartitionHealth::Serving),
            Ok(_) => Ok(PartitionHealth::Down),
            Err(_) => Ok(PartitionHealth::Down),
        }
    }
}

/// The subset of the engine config the Qdrant driver reads.
#[derive(Debug, Deserialize)]
struct QdrantCfg {
    #[serde(default)]
    collection: Option<String>,
    #[serde(default)]
    dimension: Option<usize>,
    #[serde(default)]
    distance: Option<String>,
}

/// A Qdrant query op.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum QdrantOp {
    /// Upsert points into the collection.
    Upsert { points: serde_json::Value },
    /// kNN search by query vector.
    Search {
        vector: Vec<f32>,
        #[serde(default = "default_limit")]
        limit: usize,
        #[serde(default)]
        filter: Option<serde_json::Value>,
    },
    /// Exact point count.
    Count,
}

fn default_limit() -> usize {
    10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_name_uses_config_when_present() {
        let h = PartitionHandle {
            database_id: "kb".into(),
            engine_id: engine_ids::QDRANT.into(),
            partition_index: 1,
            engine_config: serde_json::json!({ "collection": "docs", "dimension": 768 }),
        };
        assert_eq!(QdrantEngine::collection_name(&h), "docs_1");
    }

    #[test]
    fn collection_name_falls_back_without_config() {
        let h = PartitionHandle {
            database_id: "kb".into(),
            engine_id: engine_ids::QDRANT.into(),
            partition_index: 0,
            engine_config: serde_json::json!({}),
        };
        assert_eq!(QdrantEngine::collection_name(&h), "tz_kb_0");
    }

    #[test]
    fn search_op_parses_with_defaults() {
        let v = serde_json::json!({ "op": "search", "vector": [0.1, 0.2] });
        let op: QdrantOp = serde_json::from_value(v).unwrap();
        match op {
            QdrantOp::Search { limit, filter, .. } => {
                assert_eq!(limit, 10);
                assert!(filter.is_none());
            }
            _ => panic!("wrong op"),
        }
    }
}
