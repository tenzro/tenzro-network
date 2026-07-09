//! PostgreSQL driver — connect-to-existing.
//!
//! The operator runs Postgres (optionally with Citus); the node connects to it
//! via the configured libpq URL. A partition is a logical schema inside the
//! operator's database — `start_partition` creates the schema, `stop_partition`
//! drops it (idempotent both ways). The query `body` is
//! `{ "sql": "...", "params": ["...", ...]? }`; the driver runs it and returns
//! `{ "rows": [ {col: value, ...}, ... ], "row_count": N }`, with each column
//! rendered as JSON by its Postgres type.

use async_trait::async_trait;
use serde::Deserialize;
use tenzro_database::{
    catalog::engine_ids, DatabaseEngine, DatabaseError, PartitionHandle, PartitionHealth,
    QueryRequest, QueryResponse, Result,
};
use tokio_postgres::types::Type;
use tokio_postgres::{Client, NoTls, Row};

/// A thin client to an operator-run Postgres endpoint.
pub struct PostgresEngine {
    url: String,
}

impl PostgresEngine {
    /// Binds the driver to the operator's libpq connection URL. No connection is
    /// opened until a partition op or query runs.
    pub fn new(url: String) -> Self {
        Self { url }
    }

    /// Opens a fresh connection for one operation. Connect-to-existing keeps the
    /// driver stateless; the operator's server owns pooling / PgBouncer if it
    /// wants it.
    async fn connect(&self) -> Result<Client> {
        let (client, connection) = tokio_postgres::connect(&self.url, NoTls)
            .await
            .map_err(|e| DatabaseError::Backend(format!("postgres connect: {e}")))?;
        // The connection future must be driven for the client to work; it ends
        // when the client is dropped.
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    /// Schema name for a partition. Deterministic from database id + index so a
    /// restart resolves the same schema.
    fn schema_name(handle: &PartitionHandle) -> String {
        sanitize_ident(&format!("tz_{}_{}", handle.database_id, handle.partition_index))
    }
}

#[async_trait]
impl DatabaseEngine for PostgresEngine {
    fn engine_id(&self) -> &str {
        engine_ids::POSTGRES
    }

    async fn start_partition(&self, handle: &PartitionHandle) -> Result<()> {
        let schema = Self::schema_name(handle);
        let client = self.connect().await?;
        client
            .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
            .await
            .map_err(|e| DatabaseError::Backend(format!("create schema {schema}: {e}")))?;
        Ok(())
    }

    async fn stop_partition(&self, handle: &PartitionHandle) -> Result<()> {
        let schema = Self::schema_name(handle);
        let client = self.connect().await?;
        client
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .await
            .map_err(|e| DatabaseError::Backend(format!("drop schema {schema}: {e}")))?;
        Ok(())
    }

    async fn query(&self, request: &QueryRequest) -> Result<QueryResponse> {
        let body: PgBody = serde_json::from_value(request.body.clone())
            .map_err(|e| DatabaseError::InvalidRequest(format!("postgres body: {e}")))?;
        if body.sql.trim().is_empty() {
            return Err(DatabaseError::InvalidRequest("empty sql".into()));
        }
        let client = self.connect().await?;
        // Set the search_path to the partition's schema so unqualified table
        // names resolve to it.
        let schema = sanitize_ident(&format!("tz_{}_{}", request.database_id, request.partition_index));
        client
            .batch_execute(&format!("SET search_path TO {schema}, public"))
            .await
            .map_err(|e| DatabaseError::Query(format!("set search_path: {e}")))?;

        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            body.params.iter().map(|p| p as &(dyn tokio_postgres::types::ToSql + Sync)).collect();
        let rows = client
            .query(&body.sql, &params)
            .await
            .map_err(|e| DatabaseError::Query(format!("query: {e}")))?;

        let json_rows: Vec<serde_json::Value> = rows.iter().map(row_to_json).collect();
        Ok(QueryResponse {
            body: serde_json::json!({
                "row_count": json_rows.len(),
                "rows": json_rows,
            }),
        })
    }

    async fn partition_health(&self, handle: &PartitionHandle) -> Result<PartitionHealth> {
        let schema = Self::schema_name(handle);
        let client = match self.connect().await {
            Ok(c) => c,
            Err(_) => return Ok(PartitionHealth::Down),
        };
        let row = client
            .query_opt(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = $1",
                &[&schema],
            )
            .await;
        match row {
            Ok(Some(_)) => Ok(PartitionHealth::Serving),
            Ok(None) => Ok(PartitionHealth::Down),
            Err(_) => Ok(PartitionHealth::Down),
        }
    }
}

/// Query body: a SQL string plus optional text-bound parameters. Parameters are
/// bound as text — Postgres coerces to the column type — which keeps the driver
/// free of a per-type binding matrix while still being injection-safe.
#[derive(Debug, Deserialize)]
struct PgBody {
    sql: String,
    #[serde(default)]
    params: Vec<String>,
}

/// Renders one row as a JSON object, mapping each column by its Postgres type.
fn row_to_json(row: &Row) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (i, col) in row.columns().iter().enumerate() {
        let name = col.name().to_string();
        let value = cell_to_json(row, i, col.type_());
        obj.insert(name, value);
    }
    serde_json::Value::Object(obj)
}

/// Converts a single cell to JSON by its Postgres type. Unknown types fall back
/// to a text render so no column is silently dropped.
fn cell_to_json(row: &Row, idx: usize, ty: &Type) -> serde_json::Value {
    use serde_json::Value;
    match *ty {
        Type::BOOL => row.try_get::<_, Option<bool>>(idx).ok().flatten().map(Value::Bool).unwrap_or(Value::Null),
        Type::INT2 => opt_i64(row.try_get::<_, Option<i16>>(idx).ok().flatten().map(|v| v as i64)),
        Type::INT4 => opt_i64(row.try_get::<_, Option<i32>>(idx).ok().flatten().map(|v| v as i64)),
        Type::INT8 => opt_i64(row.try_get::<_, Option<i64>>(idx).ok().flatten()),
        Type::FLOAT4 => opt_f64(row.try_get::<_, Option<f32>>(idx).ok().flatten().map(|v| v as f64)),
        Type::FLOAT8 => opt_f64(row.try_get::<_, Option<f64>>(idx).ok().flatten()),
        Type::JSON | Type::JSONB => row
            .try_get::<_, Option<serde_json::Value>>(idx)
            .ok()
            .flatten()
            .unwrap_or(Value::Null),
        _ => row
            .try_get::<_, Option<String>>(idx)
            .ok()
            .flatten()
            .map(Value::String)
            .unwrap_or(Value::Null),
    }
}

fn opt_i64(v: Option<i64>) -> serde_json::Value {
    v.map(|n| serde_json::Value::Number(n.into())).unwrap_or(serde_json::Value::Null)
}

fn opt_f64(v: Option<f64>) -> serde_json::Value {
    v.and_then(serde_json::Number::from_f64)
        .map(serde_json::Value::Number)
        .unwrap_or(serde_json::Value::Null)
}

/// Restricts an identifier to `[a-z0-9_]`, lowercasing and replacing anything
/// else with `_`. Partition schema names are built from database ids the node
/// controls; this keeps a stray character from breaking the DDL and blocks
/// identifier injection through the schema seam.
fn sanitize_ident(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            let lc = c.to_ascii_lowercase();
            if lc.is_ascii_alphanumeric() || lc == '_' {
                lc
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true) {
        out.insert(0, '_');
    }
    out.truncate(63); // Postgres identifier limit.
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_blocks_injection_and_bad_leading_char() {
        assert_eq!(sanitize_ident("db-1"), "db_1");
        assert_eq!(sanitize_ident("1abc"), "_1abc");
        assert_eq!(sanitize_ident("a; DROP TABLE x"), "a__drop_table_x");
        assert_eq!(sanitize_ident(""), "_");
    }

    #[test]
    fn schema_name_is_deterministic() {
        let h = PartitionHandle {
            database_id: "orders".into(),
            engine_id: engine_ids::POSTGRES.into(),
            partition_index: 2,
            engine_config: serde_json::json!({}),
        };
        assert_eq!(PostgresEngine::schema_name(&h), "tz_orders_2");
    }
}
