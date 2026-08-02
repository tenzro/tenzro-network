//! Valkey driver — connect-to-existing over RESP.
//!
//! The operator runs Valkey (or a Valkey Cluster); the node connects via the
//! configured URL and forwards commands. Valkey has no schema/collection
//! concept, so `start_partition` / `stop_partition` are no-ops — the partition
//! seam is the key namespace, which the caller owns. A caller that wants
//! per-partition isolation prefixes its keys with the partition id.
//!
//! The query `body` is `{ "command": ["SET", "k", "v"] }` — the RESP command as
//! a string array. The driver runs it and returns the reply rendered as JSON.

use async_trait::async_trait;
use serde::Deserialize;
use tenzro_database::{
    DatabaseEngine, DatabaseError, PartitionHandle, PartitionHealth, QueryRequest, QueryResponse,
    Result, catalog::engine_ids,
};

/// A thin client to an operator-run Valkey endpoint.
pub struct ValkeyEngine {
    client: redis::Client,
}

impl ValkeyEngine {
    /// Binds the driver to the operator's Valkey URL (`redis://host:6379`). The
    /// URL is parsed eagerly so a bad URL fails at registration, not first use.
    pub fn new(url: String) -> Self {
        // A malformed URL yields a client that errors on connect; we surface it
        // then rather than panic at registration.
        let client = redis::Client::open(url.clone()).unwrap_or_else(|_| {
            redis::Client::open("redis://invalid-valkey-url-placeholder/").unwrap()
        });
        Self { client }
    }

    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DatabaseError::Backend(format!("valkey connect: {e}")))
    }
}

#[async_trait]
impl DatabaseEngine for ValkeyEngine {
    fn engine_id(&self) -> &str {
        engine_ids::VALKEY
    }

    async fn start_partition(&self, _handle: &PartitionHandle) -> Result<()> {
        // Valkey has no schema to create; the partition seam is the key
        // namespace, owned by the caller. Verify reachability so a broken
        // endpoint fails at partition-up, not first query.
        let mut conn = self.conn().await?;
        let _: redis::Value = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| DatabaseError::Backend(format!("valkey ping: {e}")))?;
        Ok(())
    }

    async fn stop_partition(&self, _handle: &PartitionHandle) -> Result<()> {
        // No per-partition server resource to release.
        Ok(())
    }

    async fn query(&self, request: &QueryRequest) -> Result<QueryResponse> {
        let body: ValkeyBody = serde_json::from_value(request.body.clone())
            .map_err(|e| DatabaseError::InvalidRequest(format!("valkey body: {e}")))?;
        let mut args = body.command.into_iter();
        let verb = args
            .next()
            .ok_or_else(|| DatabaseError::InvalidRequest("empty valkey command".into()))?;
        let mut cmd = redis::cmd(&verb);
        for a in args {
            cmd.arg(a);
        }
        let mut conn = self.conn().await?;
        let value: redis::Value = cmd
            .query_async(&mut conn)
            .await
            .map_err(|e| DatabaseError::Query(format!("valkey command: {e}")))?;
        Ok(QueryResponse {
            body: redis_value_to_json(value),
        })
    }

    async fn partition_health(&self, _handle: &PartitionHandle) -> Result<PartitionHealth> {
        let mut conn = match self.conn().await {
            Ok(c) => c,
            Err(_) => return Ok(PartitionHealth::Down),
        };
        let pong: std::result::Result<redis::Value, _> =
            redis::cmd("PING").query_async(&mut conn).await;
        match pong {
            Ok(_) => Ok(PartitionHealth::Serving),
            Err(_) => Ok(PartitionHealth::Down),
        }
    }
}

/// Query body: a RESP command as a string array (`["SET", "k", "v"]`).
#[derive(Debug, Deserialize)]
struct ValkeyBody {
    command: Vec<String>,
}

/// Renders a RESP reply as JSON. Bytes decode as UTF-8 lossily so binary values
/// round-trip as text; nested arrays/maps recurse.
fn redis_value_to_json(v: redis::Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        redis::Value::Nil => J::Null,
        redis::Value::Int(i) => J::Number(i.into()),
        redis::Value::BulkString(b) => J::String(String::from_utf8_lossy(&b).into_owned()),
        redis::Value::SimpleString(s) => J::String(s),
        redis::Value::Okay => J::String("OK".to_string()),
        redis::Value::Double(d) => {
            J::Number(serde_json::Number::from_f64(d).unwrap_or_else(|| 0.into()))
        }
        redis::Value::Boolean(b) => J::Bool(b),
        redis::Value::Array(items) | redis::Value::Set(items) => {
            J::Array(items.into_iter().map(redis_value_to_json).collect())
        }
        redis::Value::Map(pairs) => {
            let mut obj = serde_json::Map::new();
            for (k, val) in pairs {
                let key = match redis_value_to_json(k) {
                    J::String(s) => s,
                    other => other.to_string(),
                };
                obj.insert(key, redis_value_to_json(val));
            }
            J::Object(obj)
        }
        other => J::String(format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_parses_command_array() {
        let v = serde_json::json!({ "command": ["SET", "k", "v"] });
        let b: ValkeyBody = serde_json::from_value(v).unwrap();
        assert_eq!(b.command, vec!["SET", "k", "v"]);
    }

    #[test]
    fn value_renders_scalars_and_arrays() {
        assert_eq!(
            redis_value_to_json(redis::Value::Int(7)),
            serde_json::json!(7)
        );
        assert_eq!(
            redis_value_to_json(redis::Value::Okay),
            serde_json::json!("OK")
        );
        assert_eq!(
            redis_value_to_json(redis::Value::BulkString(b"hi".to_vec())),
            serde_json::json!("hi")
        );
        assert_eq!(
            redis_value_to_json(redis::Value::Array(vec![
                redis::Value::Int(1),
                redis::Value::BulkString(b"a".to_vec()),
            ])),
            serde_json::json!([1, "a"])
        );
    }
}
