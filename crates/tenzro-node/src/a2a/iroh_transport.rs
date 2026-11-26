//! A2A JSON-RPC dispatcher adapter for the iroh transport.
//!
//! Glue between [`tenzro_iroh::JsonRpcDispatcher`] (raw opaque request/response
//! bytes on a QUIC bistream) and [`super::server::dispatch_jsonrpc`] (the
//! transport-agnostic A2A method router).
//!
//! The HTTPS axum surface and this iroh-transport surface share the **same**
//! `Arc<A2aState>` — A2A tasks created over either transport land in the
//! same `TaskManager`. See [`super::server::build_a2a_state`].
//!
//! # Wire format
//!
//! Identical to the HTTPS surface: UTF-8 JSON-RPC 2.0 request/response
//! envelopes (`{"jsonrpc":"2.0","method":..,"params":..,"id":..}`). The
//! iroh transport layer adds only a `u32_LE` length prefix per frame (see
//! `tenzro_iroh::jsonrpc` for the framing). The ALPN speaks A2A 1.0 and
//! carries unary methods only; `SendStreamingMessage` needs the HTTPS route.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tenzro_iroh::{IrohError, IrohResult, JsonRpcDispatcher};

use super::server::{A2aState, JsonRpcRequest, JsonRpcResponse, dispatch_jsonrpc};

/// `JsonRpcDispatcher` impl that decodes the request body as A2A
/// JSON-RPC 2.0 and delegates to the shared `dispatch_jsonrpc` router.
pub struct IrohA2aDispatcher {
    state: Arc<A2aState>,
}

impl std::fmt::Debug for IrohA2aDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohA2aDispatcher").finish_non_exhaustive()
    }
}

impl IrohA2aDispatcher {
    /// Wrap the shared A2A state for iroh-side dispatch.
    pub fn new(state: Arc<A2aState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl JsonRpcDispatcher for IrohA2aDispatcher {
    async fn dispatch(&self, request: Bytes) -> IrohResult<Bytes> {
        // JSON parse error → JSON-RPC `-32700` envelope (per spec). Don't
        // surface this as a transport error — that would close the stream.
        let req: JsonRpcRequest = match serde_json::from_slice(&request) {
            Ok(r) => r,
            Err(e) => {
                let body =
                    serde_json::to_vec(&JsonRpcResponse::parse_error(format!("Parse error: {e}")))
                        .map_err(|e| IrohError::Backend(format!("encode parse-error: {e}")))?;
                return Ok(Bytes::from(body));
            }
        };

        // The `tenzro/a2a` ALPN carries no headers; the ALPN itself pins the
        // protocol version the peer speaks.
        let resp = dispatch_jsonrpc(
            &self.state,
            req,
            Some(super::agent_card::A2A_PROTOCOL_VERSION),
        )
        .await;
        let body = serde_json::to_vec(&resp)
            .map_err(|e| IrohError::Backend(format!("encode response: {e}")))?;
        Ok(Bytes::from(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::handlers::WebState;

    async fn dispatcher() -> (IrohA2aDispatcher, Arc<A2aState>, tempfile::TempDir) {
        let (node, tmp) = crate::bare_node().await;
        let state = super::super::server::build_a2a_state(
            node,
            Arc::new(WebState::new()),
            Some(crate::a2a::did_envelope::tests::TEST_AUDIENCE.to_string()),
        );
        (IrohA2aDispatcher::new(state.clone()), state, tmp)
    }

    async fn call(d: &IrohA2aDispatcher, body: &[u8]) -> serde_json::Value {
        let out = d
            .dispatch(Bytes::copy_from_slice(body))
            .await
            .expect("a reply frame");
        serde_json::from_slice(&out).expect("a JSON-RPC reply")
    }

    fn code(reply: &serde_json::Value) -> i64 {
        reply["error"]["code"].as_i64().expect("an error reply")
    }

    #[tokio::test]
    async fn bytes_that_are_not_json_rpc_are_answered_with_a_parse_error_not_a_dropped_stream() {
        let (d, _state, _tmp) = dispatcher().await;
        for body in [
            &b""[..],
            b"not json",
            b"{\"jsonrpc\":",
            b"[1,2,3]",
            &[0xff, 0xfe],
        ] {
            let reply = call(&d, body).await;
            assert_eq!(code(&reply), -32700, "{body:?}");
            assert!(reply["id"].is_null());
        }
    }

    #[tokio::test]
    async fn a_request_that_is_not_json_rpc_2_0_is_refused() {
        let (d, _state, _tmp) = dispatcher().await;
        let reply = call(
            &d,
            br#"{"jsonrpc":"1.0","method":"GetTask","params":{},"id":4}"#,
        )
        .await;
        assert_eq!(code(&reply), -32600);
        assert_eq!(reply["id"], 4);
    }

    #[tokio::test]
    async fn an_unknown_method_is_not_found() {
        let (d, _state, _tmp) = dispatcher().await;
        let reply = call(
            &d,
            br#"{"jsonrpc":"2.0","method":"DeleteEverything","params":{},"id":1}"#,
        )
        .await;
        assert_eq!(code(&reply), -32601);
    }

    #[tokio::test]
    async fn streaming_and_subscription_need_a_stream_the_unary_alpn_cannot_give() {
        let (d, _state, _tmp) = dispatcher().await;
        for method in ["SendStreamingMessage", "SubscribeToTask"] {
            let body = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{{}},"id":1}}"#);
            let reply = call(&d, body.as_bytes()).await;
            assert_eq!(code(&reply), -32004, "{method} is unsupported over iroh");
        }
        let reply = call(
            &d,
            br#"{"jsonrpc":"2.0","method":"CreateTaskPushNotificationConfig","params":{},"id":1}"#,
        )
        .await;
        assert_ne!(code(&reply), 0, "push notifications are refused");
    }

    #[tokio::test]
    async fn a_state_changing_call_without_the_did_envelope_opens_no_task() {
        let (d, state, _tmp) = dispatcher().await;
        for method in ["SendMessage", "CancelTask"] {
            let body = format!(
                r#"{{"jsonrpc":"2.0","method":"{method}","params":{{"message":{{"messageId":"m","role":"ROLE_USER","parts":[{{"text":"hi"}}]}},"id":"t1"}},"id":1}}"#
            );
            let reply = call(&d, body.as_bytes()).await;
            assert!(reply["error"].is_object(), "{method}: {reply}");
            assert!(reply["result"].is_null());
        }
        assert!(state.task_manager.get_task("t1").is_none());
    }

    #[tokio::test]
    async fn a_task_read_without_the_did_envelope_is_refused() {
        let (d, _state, _tmp) = dispatcher().await;
        for body in [
            &br#"{"jsonrpc":"2.0","method":"GetTask","params":{"id":"missing"},"id":9}"#[..],
            br#"{"jsonrpc":"2.0","method":"ListTasks","params":{},"id":9}"#,
            br#"{"jsonrpc":"2.0","method":"ListTasks","id":9}"#,
        ] {
            let reply = call(&d, body).await;
            assert_eq!(code(&reply), -32050, "{reply}");
            assert!(reply["result"].is_null(), "{reply}");
            assert_eq!(reply["id"], 9);
        }
    }

    /// A2A over a real iroh pair, two clients of one node: the framed
    /// request reaches the dispatcher and the framed reply comes back; each
    /// client opens a task and lists and gets only its own, and a read or a
    /// message without the DID envelope is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn over_iroh_a_client_reads_only_its_own_tasks_and_an_unsigned_call_is_refused() {
        use super::super::server::tests::{listed_ids, signed_body, two_clients};
        use tenzro_iroh::identity_transport::base_builder;
        use tenzro_iroh::limits::AdmissionLimits;
        use tenzro_iroh::{ALPN_A2A, JsonRpcProtocol};

        let (state, alice, bob, _tmp) = two_clients().await;
        let d = IrohA2aDispatcher::new(state.clone());
        let server = tenzro_iroh::identity_transport::on_loopback(base_builder())
            .bind()
            .await
            .unwrap();
        let router = iroh::protocol::Router::builder(server.clone())
            .accept(
                ALPN_A2A,
                JsonRpcProtocol::a2a(Arc::new(d), AdmissionLimits::default()),
            )
            .spawn();
        let client = tenzro_iroh::identity_transport::on_loopback(base_builder())
            .bind()
            .await
            .unwrap();

        let ask = |body: serde_json::Value| {
            let client = client.clone();
            let addr = server.addr();
            async move {
                let out = tenzro_iroh::jsonrpc::call(
                    &client,
                    addr,
                    ALPN_A2A,
                    Bytes::from(serde_json::to_vec(&body).unwrap()),
                )
                .await
                .expect("a framed reply");
                serde_json::from_slice::<serde_json::Value>(&out).expect("a JSON-RPC reply")
            }
        };
        let message = |text: &str| {
            serde_json::json!({
                "message": {"messageId": "m1", "role": "ROLE_USER", "parts": [{"text": text}]}
            })
        };

        let a = ask(signed_body(
            &alice,
            "SendMessage",
            message("what is the node status? alice-private-question"),
        ))
        .await;
        let a_id = a["result"]["task"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{a}"))
            .to_string();
        let b = ask(signed_body(
            &bob,
            "SendMessage",
            message("what is the node status? bob-private-question"),
        ))
        .await;
        let b_id = b["result"]["task"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{b}"))
            .to_string();

        let mine = ask(signed_body(&alice, "ListTasks", serde_json::json!({}))).await;
        assert_eq!(listed_ids(&mine), std::slice::from_ref(&a_id), "{mine}");
        assert!(!mine.to_string().contains("bob-private-question"), "{mine}");
        let theirs = ask(signed_body(
            &bob,
            "ListTasks",
            serde_json::json!({ "includeArtifacts": true }),
        ))
        .await;
        assert_eq!(listed_ids(&theirs), std::slice::from_ref(&b_id), "{theirs}");
        assert!(
            !theirs.to_string().contains("alice-private-question"),
            "{theirs}"
        );

        let own = ask(signed_body(
            &bob,
            "GetTask",
            serde_json::json!({ "id": b_id }),
        ))
        .await;
        assert_eq!(own["result"]["id"], b_id.as_str(), "{own}");
        let other = ask(signed_body(
            &bob,
            "GetTask",
            serde_json::json!({ "id": a_id }),
        ))
        .await;
        assert_eq!(code(&other), -32001, "{other}");
        assert!(!other.to_string().contains("alice-private-question"));

        for body in [
            serde_json::json!({"jsonrpc":"2.0","method":"ListTasks","params":{},"id":1}),
            serde_json::json!({"jsonrpc":"2.0","method":"GetTask","params":{"id":a_id},"id":2}),
            serde_json::json!({"jsonrpc":"2.0","method":"SendMessage","params":message("hi"),"id":3}),
        ] {
            let unsigned = ask(body).await;
            assert_eq!(code(&unsigned), -32050, "{unsigned}");
        }
        assert_eq!(state.task_manager.task_count(), 2);

        router.shutdown().await.unwrap();
    }
}
