//! The chain's event stream as MCP resources an agent subscribes to.
//!
//! One resource template, `tenzro://events{?filter,from_cursor}`: `filter`
//! is the JSON event filter (URL-encoded) and `from_cursor` the cursor to
//! resume after. Reading a resource returns the next page of events after
//! that cursor, each with its proof, and the cursor to read from next.
//! Subscribing to one sends `notifications/resources/updated` for it
//! whenever a new block brings events the filter selects; the agent then
//! reads from the cursor it holds, so a restarted agent resumes with no gap.
//!
//! Every read runs through the same JSON-RPC path as `tenzro_subscribe`,
//! with the caller's credentials, so a delegated agent reads only what its
//! terms allow.

use std::sync::Arc;

use rmcp::ErrorData;
use rmcp::model::{ErrorCode, ReadResourceResult, ResourceContents, ResourceTemplate};
use serde_json::{Value, json};
use tenzro_events::EventFilter;
use tenzro_events::log::end_of_height;
use tenzro_types::chain_event::EventCursor;

use crate::node::TenzroNode;

/// Scheme and path of an event resource.
pub(crate) const EVENTS_URI: &str = "tenzro://events";

/// The template agents discover.
pub(crate) fn template() -> ResourceTemplate {
    ResourceTemplate::new(format!("{EVENTS_URI}{{?filter,from_cursor}}"), "chain-events")
        .with_title("Chain events")
        .with_description(
            "The chain's events after a cursor, each with a proof against a certified checkpoint. \
             `filter` is the JSON event filter, `from_cursor` the cursor to resume after. Subscribe \
             to be told when new events match.",
        )
}

fn invalid(msg: impl Into<String>) -> ErrorData {
    ErrorData {
        code: ErrorCode(-32602),
        message: msg.into().into(),
        data: None,
    }
}

/// The `tenzro_subscribe` parameters an event resource URI names.
pub(crate) fn params_of(uri: &str) -> Result<Value, ErrorData> {
    let rest = uri
        .strip_prefix(EVENTS_URI)
        .ok_or_else(|| invalid(format!("not an event resource: {uri}")))?;
    let query = match rest {
        "" => "",
        q if q.starts_with('?') => &q[1..],
        _ => return Err(invalid(format!("not an event resource: {uri}"))),
    };
    let mut params = json!({ "proofs": true });
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = urlencoding::decode(value).map_err(|e| invalid(format!("{key}: {e}")))?;
        match key {
            "filter" => {
                params["filter"] = serde_json::from_str(&value)
                    .map_err(|e| invalid(format!("filter is not JSON: {e}")))?;
            }
            "from_cursor" => params["from_cursor"] = json!(value),
            other => {
                return Err(invalid(format!(
                    "unknown event resource parameter {other:?}"
                )));
            }
        }
    }
    Ok(params)
}

/// `resources/read` of an event resource, through `dispatch` (the caller's
/// credentialed JSON-RPC path).
pub(crate) async fn read<F, Fut>(uri: &str, dispatch: F) -> Result<ReadResourceResult, ErrorData>
where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, ErrorData>>,
{
    let page = dispatch(params_of(uri)?).await?;
    let text = serde_json::to_string(&page).expect("JSON values encode");
    Ok(ReadResourceResult::new(vec![
        ResourceContents::text(text, uri).with_mime_type("application/json"),
    ]))
}

/// Watches the log for `uri`'s subscriber and calls `notify` each time a new
/// block brings events its filter selects. Ends when `notify` reports the
/// peer gone.
pub(crate) async fn watch<F, Fut>(
    node: Arc<TenzroNode>,
    uri: String,
    notify: F,
) -> Result<(), ErrorData>
where
    F: Fn(String) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = bool> + Send,
{
    let params = params_of(&uri)?;
    let filter =
        EventFilter::from_json(params.get("filter").unwrap_or(&Value::Null)).map_err(invalid)?;
    let Some(log) = node.event_log().cloned() else {
        return Err(ErrorData {
            code: ErrorCode(-32603),
            message: "the event log is not open".into(),
            data: None,
        });
    };
    let mut after: Option<EventCursor> = match params.get("from_cursor").and_then(Value::as_str) {
        Some(c) => Some(c.parse().map_err(invalid)?),
        None => log.tip().map(end_of_height),
    };
    let mut tip = log.watch_tip();
    tokio::spawn(async move {
        while tip.changed().await.is_ok() {
            let Ok(page) = log.read_after(after, None, 1, u64::MAX, &|e| filter.matches_chain(e))
            else {
                return;
            };
            if page.events.is_empty() {
                after = page.cursor;
                continue;
            }
            // Notify once per batch of new blocks; the reader catches up from
            // its own cursor.
            after = log.tip().map(end_of_height);
            if !notify(uri.clone()).await {
                return;
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resource_uri_names_its_subscription() {
        let filter = urlencoding::encode(r#"{"event_types":["log"]}"#);
        let p = params_of(&format!("{EVENTS_URI}?filter={filter}&from_cursor=5:0:1")).unwrap();
        assert_eq!(p["filter"]["event_types"][0], "log");
        assert_eq!(p["from_cursor"], "5:0:1");
        assert_eq!(p["proofs"], true);
        assert!(params_of("tenzro://other").is_err());
        assert!(params_of(&format!("{EVENTS_URI}?limit=5")).is_err());
    }
}
