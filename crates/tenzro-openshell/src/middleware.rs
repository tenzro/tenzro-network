//! Supervisor middleware: every network and tool call held to Terms and
//! recorded, and payments answered from inside the sandbox.
//!
//! On the request path (before credentials are injected) each HTTP request a
//! sandbox makes is checked against its agent's Terms as `fetch`, and an MCP
//! `tools/call` additionally as `tool`; the allow or deny is a signed record.
//! A payment the [`Payer`] authorized for this exact request is written into
//! it here, so the credential never passes through the agent. On the return
//! path a `402` is handed to the [`Payer`]; the payee's answer to the retried
//! request settles the payment; and a Tenzro provider's receipt is recorded
//! as the model call it settled.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tenzro_types::agent_audit::{ActionKind, ActionOutcome};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::authority::{Authority, Proposed};
use crate::gateway_auth::{self, Caller, CallerKind};
use crate::openshell::middleware::v1::http_response_event::Event;
use crate::openshell::middleware::v1::http_response_event_result::Result as EventResult;
use crate::openshell::middleware::v1::http_response_pre_return_server::HttpResponsePreReturn;
use crate::openshell::middleware::v1::http_response_preflight_result::Action as PreflightAction;
use crate::openshell::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use crate::openshell::middleware::v1::*;
use crate::payments::{Paid, Payer, Target};
use crate::peer;
use crate::records::{Decision, RecordLog};

/// The response header a Tenzro provider carries its signed receipt in.
pub const RECEIPT_HEADER: &str = "x-tenzro-receipt";
/// The response header this middleware reports a payment decision in.
pub const PAYMENT_HEADER: &str = "x-tenzro-payment";

const MAX_PAYLOAD: u64 = 1 << 20;

/// The Tenzro supervisor middleware.
#[derive(Clone)]
pub struct TenzroMiddleware {
    authority: Arc<dyn Authority>,
    records: Arc<RecordLog>,
    payer: Arc<Payer>,
    last: Arc<Mutex<HashMap<Target, String>>>,
    audience: String,
}

fn write(name: &str, value: &str) -> HeaderMutation {
    HeaderMutation {
        operation: Some(header_mutation::Operation::Write(WriteHeader {
            name: name.to_string(),
            value: value.to_string(),
            on_existing: ExistingHeaderAction::Overwrite as i32,
        })),
    }
}

/// The tool an MCP `tools/call` request body calls.
fn mcp_tool(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    (v.get("method")?.as_str()? == "tools/call")
        .then(|| v.pointer("/params/name")?.as_str().map(str::to_string))
        .flatten()
}

/// Refuse a supervisor acting for a sandbox other than the one its token
/// names, and any caller that is not a supervisor.
fn same_sandbox(caller: &Caller, context: Option<&RequestContext>) -> Result<(), Status> {
    if caller.kind != CallerKind::Supervisor {
        return Err(Status::permission_denied(
            "only a sandbox's supervisor evaluates its traffic",
        ));
    }
    let named = caller.sandbox_id.as_deref().unwrap_or_default();
    let asked = context.map(|c| c.sandbox_id.as_str()).unwrap_or_default();
    if named.is_empty() || named != asked {
        return Err(Status::permission_denied(format!(
            "the supervisor of {named} asked about sandbox {asked}"
        )));
    }
    Ok(())
}

fn target_of(context: Option<&RequestContext>, target: Option<&HttpRequestTarget>) -> Target {
    let c = context.cloned().unwrap_or_default();
    let t = target.cloned().unwrap_or_default();
    Target {
        sandbox: if c.sandbox.is_empty() {
            c.sandbox_id
        } else {
            c.sandbox
        },
        method: t.method.to_ascii_uppercase(),
        host: t.host.to_ascii_lowercase(),
        port: t.port,
        path: t.path,
    }
}

impl TenzroMiddleware {
    /// A middleware deciding against `authority`, paying with `payer`.
    pub fn new(authority: Arc<dyn Authority>, records: Arc<RecordLog>, payer: Arc<Payer>) -> Self {
        Self {
            authority,
            records,
            payer,
            last: Arc::new(Mutex::new(HashMap::new())),
            audience: String::new(),
        }
    }

    /// Advertise the token audience this middleware's guard verifies, so
    /// supervisors confirm they present tokens for the same one.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    fn agent(&self, target: &Target, context: Option<&RequestContext>) -> Option<String> {
        self.authority
            .agent_of_sandbox(&target.sandbox)
            .or_else(|| context.and_then(|c| self.authority.agent_of_sandbox(&c.sandbox_id)))
    }

    fn record(
        &self,
        target: &Target,
        agent: &str,
        kind: ActionKind,
        action: &str,
        outcome: ActionOutcome,
        detail: &[u8],
        linked: Option<String>,
    ) -> Option<String> {
        match self.records.record(Decision {
            session: &target.sandbox,
            agent,
            kind,
            action,
            outcome,
            detail,
            linked_tx: linked,
        }) {
            Ok(e) => Some(hex::encode(e.leaf_hash())),
            Err(e) => {
                tracing::error!("middleware record not written: {e}");
                None
            }
        }
    }

    /// Decide one outbound request.
    pub fn decide_request(&self, e: &HttpRequestEvaluation) -> HttpRequestResult {
        let target = target_of(e.context.as_ref(), e.target.as_ref());
        let label = target.label();
        let tool = mcp_tool(&e.body);
        let kind = if tool.is_some() {
            ActionKind::ToolCall
        } else {
            ActionKind::Egress
        };
        let action = tool.clone().unwrap_or_else(|| label.clone());
        let detail = [label.as_bytes(), &e.body].concat();
        let deny = |agent: &str, why: String, kind: ActionKind| {
            let kind = if why == crate::authority::REVOKED {
                ActionKind::GrantUse
            } else {
                kind
            };
            self.record(
                &target,
                agent,
                kind,
                &action,
                ActionOutcome::Refused(why.clone()),
                &detail,
                None,
            );
            HttpRequestResult {
                decision: Decision_::Deny as i32,
                reason: why,
                reason_code: "tenzro_terms".to_string(),
                ..Default::default()
            }
        };
        let Some(agent) = self.agent(&target, e.context.as_ref()) else {
            return deny(
                "",
                "the sandbox runs no Tenzro agent".to_string(),
                ActionKind::Violation,
            );
        };
        let now = crate::now_ms();
        let mut checks = vec!["fetch"];
        if tool.is_some() {
            checks.push("tool");
        }
        for op in checks {
            let proposed = Proposed {
                operation: op.to_string(),
                ..Default::default()
            };
            if let Err(r) = self.authority.authorize(&agent, &proposed, now) {
                return deny(&agent, r.0, kind);
            }
        }
        let mut mutations = Vec::new();
        let mut linked = None;
        match self.payer.presented(&target) {
            Some(Ok(p)) => {
                mutations.push(write(&p.header.0, &p.header.1));
                linked = Some(p.challenge_id);
            }
            Some(Err(why)) => return deny(&agent, why, ActionKind::Spend),
            None => {}
        }
        let leaf = self.record(
            &target,
            &agent,
            kind,
            &action,
            ActionOutcome::Allowed,
            &detail,
            linked,
        );
        if let Some(leaf) = &leaf {
            self.last.lock().insert(target.clone(), leaf.clone());
        }
        HttpRequestResult {
            decision: Decision_::Allow as i32,
            header_mutations: mutations,
            metadata: HashMap::from([("tenzro.record".to_string(), leaf.unwrap_or_default())]),
            ..Default::default()
        }
    }

    /// Decide one response before it returns to the sandbox.
    pub fn decide_response(&self, p: &HttpResponsePreflight) -> HttpResponsePreflightResult {
        let skip = HttpResponsePreflightResult {
            action: Some(PreflightAction::Skip(HttpResponsePreflightSkip {})),
            ..Default::default()
        };
        let target = target_of(p.context.as_ref(), p.target.as_ref());
        let Some(agent) = self.agent(&target, p.context.as_ref()) else {
            return skip;
        };
        let headers: Vec<(String, String)> = p
            .headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect();
        let report = |value: String| {
            let headers_only = p
                .permitted_body_modes
                .contains(&(HttpResponseBodyMode::HeadersOnly as i32));
            if !headers_only {
                return skip.clone();
            }
            HttpResponsePreflightResult {
                action: Some(PreflightAction::Inspect(HttpResponsePreflightInspect {
                    body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                    header_mutations: vec![write(PAYMENT_HEADER, &value)],
                })),
                ..Default::default()
            }
        };
        if p.status_code == 402 {
            let action = self.last.lock().get(&target).cloned().unwrap_or_default();
            return match self
                .payer
                .answer(&target, &agent, p.status_code, &headers, &action)
            {
                Paid::Authorized { challenge_id } => {
                    report(format!("authorized {challenge_id}; retry the request"))
                }
                Paid::Refused(why) => report(format!("refused: {why}")),
                Paid::NotAChallenge => skip,
            };
        }
        if let Some(ok) = self.payer.settled(&target, p.status_code, &headers) {
            return report(if ok {
                "settled".into()
            } else {
                "unsettled".into()
            });
        }
        if let Some((_, receipt)) = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(RECEIPT_HEADER))
        {
            self.record(
                &target,
                &agent,
                ActionKind::ModelCall,
                &target.label(),
                ActionOutcome::Allowed,
                receipt.as_bytes(),
                Some(crate::provider::receipt_reference(receipt)),
            );
        }
        skip
    }
}

use crate::openshell::middleware::v1::Decision as Decision_;

#[tonic::async_trait]
impl SupervisorMiddleware for TenzroMiddleware {
    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        gateway_auth::caller(&request)?;
        peer::negotiate(request.get_ref().gateway.as_ref(), peer::MIDDLEWARE)?;
        let binding = |operation: SupervisorMiddlewareOperation,
                       phase: SupervisorMiddlewarePhase| {
            MiddlewareBinding {
                operation: operation as i32,
                phase: phase as i32,
                max_payload_bytes: MAX_PAYLOAD,
                request_timeout: None,
            }
        };
        Ok(Response::new(MiddlewareManifest {
            name: "tenzro".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            bindings: vec![
                binding(
                    SupervisorMiddlewareOperation::HttpRequest,
                    SupervisorMiddlewarePhase::PreCredentials,
                ),
                binding(
                    SupervisorMiddlewareOperation::HttpResponse,
                    SupervisorMiddlewarePhase::PreReturn,
                ),
            ],
            expected_audience: self.audience.clone(),
            extension: Some(peer::metadata(peer::MIDDLEWARE)),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        gateway_auth::caller(&request)?;
        Ok(Response::new(ValidateConfigResponse {
            valid: true,
            reason: String::new(),
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        same_sandbox(
            gateway_auth::caller(&request)?,
            request.get_ref().context.as_ref(),
        )?;
        Ok(Response::new(self.decide_request(request.get_ref())))
    }

    type EvaluateWebSocketSessionStream =
        ReceiverStream<Result<WebSocketSessionEventResult, Status>>;

    async fn evaluate_web_socket_session(
        &self,
        request: Request<Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        gateway_auth::caller(&request)?;
        Err(Status::unimplemented(
            "Tenzro binds no WebSocket middleware",
        ))
    }
}

#[tonic::async_trait]
impl HttpResponsePreReturn for TenzroMiddleware {
    type EvaluateStream = ReceiverStream<Result<HttpResponseEventResult, Status>>;

    async fn evaluate(
        &self,
        request: Request<Streaming<HttpResponseEvent>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        let caller = gateway_auth::caller(&request)?.clone();
        if caller.kind != CallerKind::Supervisor {
            return Err(Status::permission_denied(
                "only a sandbox's supervisor evaluates its traffic",
            ));
        }
        let mut inbound = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let event = match inbound.message().await {
                    Ok(Some(e)) => e,
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                };
                let reply = match event.event {
                    Some(Event::Preflight(p)) => {
                        if let Err(refused) = same_sandbox(&caller, p.context.as_ref()) {
                            let _ = tx.send(Err(refused)).await;
                            break;
                        }
                        EventResult::PreflightResult(me.decide_response(&p))
                    }
                    Some(Event::Body(b)) => EventResult::BodyResult(HttpResponseBodyResult {
                        sequence: b.sequence,
                        action: Some(http_response_body_result::Action::PassThrough(
                            HttpResponseBodyPassThrough {},
                        )),
                        ..Default::default()
                    }),
                    Some(Event::Trailers(_)) => {
                        EventResult::TrailersResult(HttpResponseTrailersResult::default())
                    }
                    Some(Event::SessionEnd(_)) | None => break,
                };
                if tx
                    .send(Ok(HttpResponseEventResult {
                        result: Some(reply),
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_driver::tests::{ROOT, agent};
    use crate::payments::tests::{gateway, payer_fixture};
    use crate::records::verify_session;
    use tenzro_payments::traits::PaymentGateway;

    fn fixture(
        ops_extra: &[&str],
    ) -> (
        TenzroMiddleware,
        Arc<crate::authority::StateAuthority>,
        Arc<RecordLog>,
    ) {
        let (payer, authority, records, _) = payer_fixture("500");
        let mut t = crate::credential_driver::tests::terms(&["fetch", "pay"]);
        t.delegation_scope.max_transaction_value = Some("500".into());
        t.delegation_scope.allowed_payment_protocols = vec!["x402".into()];
        for op in ops_extra {
            t.delegation_scope.allowed_operations.push(op.to_string());
        }
        authority.install_terms(&agent(), t);
        authority.bind_sandbox(&["sb1", "id-1"], &agent());
        (
            TenzroMiddleware::new(authority.clone(), records.clone(), Arc::new(payer)),
            authority,
            records,
        )
    }

    fn request(sandbox: &str, body: &[u8]) -> HttpRequestEvaluation {
        HttpRequestEvaluation {
            phase: SupervisorMiddlewarePhase::PreCredentials as i32,
            context: Some(RequestContext {
                request_id: "r".into(),
                sandbox_id: "id-1".into(),
                sandbox: sandbox.into(),
                ..Default::default()
            }),
            target: Some(HttpRequestTarget {
                scheme: "http".into(),
                host: "data.example".into(),
                port: 80,
                method: "GET".into(),
                path: "/report".into(),
                query: String::new(),
            }),
            body: body.to_vec(),
            ..Default::default()
        }
    }

    fn preflight(status: u32, headers: Vec<(String, String)>) -> HttpResponsePreflight {
        let r = request("sb1", b"");
        HttpResponsePreflight {
            context: r.context,
            target: r.target,
            status_code: status,
            headers: headers
                .into_iter()
                .map(|(name, value)| HttpHeader { name, value })
                .collect(),
            permitted_body_modes: vec![HttpResponseBodyMode::HeadersOnly as i32],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn every_request_is_decided_against_the_terms_and_recorded() {
        let (m, authority, records) = fixture(&[]);
        assert_eq!(
            m.decide_request(&request("sb1", b"")).decision,
            Decision_::Allow as i32
        );
        // An MCP tool call needs the tool operation too.
        let call = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}"#;
        let denied = m.decide_request(&request("sb1", call));
        assert_eq!(denied.decision, Decision_::Deny as i32);
        // A sandbox with no agent is refused.
        let mut stranger = request("other", b"");
        stranger.context.as_mut().unwrap().sandbox_id = "id-9".into();
        assert_eq!(m.decide_request(&stranger).decision, Decision_::Deny as i32);
        authority.revoke(ROOT, "kill switch");
        let r = m.decide_request(&request("sb1", b""));
        assert_eq!(r.decision, Decision_::Deny as i32);
        assert!(r.reason.contains("revoked"), "{}", r.reason);
        let entries = verify_session(records.identity(), &records.entries("sb1")).unwrap();
        let kinds: Vec<_> = entries
            .iter()
            .map(|e| (e.kind, crate::records::allowed(&e.outcome)))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (ActionKind::Egress, true),
                (ActionKind::ToolCall, false),
                (ActionKind::GrantUse, false)
            ]
        );
    }

    #[tokio::test]
    async fn a_tool_call_inside_the_terms_is_recorded_as_one() {
        let (m, _, records) = fixture(&["tool"]);
        let call = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}"#;
        assert_eq!(
            m.decide_request(&request("sb1", call)).decision,
            Decision_::Allow as i32
        );
        let entries = verify_session(records.identity(), &records.entries("sb1")).unwrap();
        assert_eq!(entries[0].kind, ActionKind::ToolCall);
        assert_eq!(entries[0].action, "search");
    }

    #[tokio::test]
    async fn a_402_is_paid_on_the_retry_and_the_payment_links_to_the_request() {
        let (m, authority, records) = fixture(&[]);
        let gw = gateway(&authority).await;
        let first = m.decide_request(&request("sb1", b""));
        assert!(first.header_mutations.is_empty());
        let request_leaf = first.metadata["tenzro.record"].clone();
        let c = gw
            .create_challenge(
                "x402",
                "/report",
                250,
                "TNZO",
                "0909090909090909090909090909090909090909",
            )
            .await
            .unwrap();
        let h = tenzro_payments::middleware::payment_required_header(&c).unwrap();
        let r = m.decide_response(&preflight(
            402,
            vec![(
                tenzro_payments::x402::PAYMENT_REQUIRED_HEADER.into(),
                h.to_str().unwrap().into(),
            )],
        ));
        let Some(PreflightAction::Inspect(i)) = r.action else {
            panic!("402 not inspected")
        };
        assert_eq!(i.header_mutations.len(), 1);
        // The retried request carries the credential.
        let retry = m.decide_request(&request("sb1", b""));
        let Some(header_mutation::Operation::Write(w)) = &retry.header_mutations[0].operation
        else {
            panic!("no payment header");
        };
        assert_eq!(w.name, tenzro_payments::x402::PAYMENT_SIGNATURE_HEADER);
        m.decide_response(&preflight(
            200,
            vec![(
                tenzro_payments::x402::PAYMENT_RESPONSE_HEADER.into(),
                "receipt".into(),
            )],
        ));
        let entries = verify_session(records.identity(), &records.entries("sb1")).unwrap();
        let spend: Vec<_> = entries
            .iter()
            .filter(|e| e.kind == ActionKind::Spend)
            .collect();
        assert_eq!(spend.len(), 2);
        assert_eq!(spend[0].linked_tx.as_deref(), Some(c.challenge_id.as_str()));
        assert_eq!(spend[1].outcome, ActionOutcome::Allowed);
        assert!(!request_leaf.is_empty());
    }

    #[tokio::test]
    async fn the_manifest_binds_requests_and_responses() {
        let (m, _, _) = fixture(&[]);
        let manifest = SupervisorMiddleware::describe(
            &m,
            gateway_auth::testing::from_gateway(MiddlewareDescribeRequest {
                gateway: Some(peer::metadata(peer::MIDDLEWARE)),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(manifest.bindings.len(), 2);
        assert_eq!(
            manifest.extension.unwrap().supported_capabilities,
            vec![peer::MIDDLEWARE.to_string()]
        );
    }

    #[tokio::test]
    async fn only_the_sandboxs_own_supervisor_reaches_the_middleware() {
        let (m, _, _) = fixture(&[]);
        let e = m
            .evaluate_http_request(Request::new(request("sb1", b"")))
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::Unauthenticated);
        let other = gateway_auth::testing::from_supervisor(request("sb1", b""), "id-9");
        let e = m.evaluate_http_request(other).await.unwrap_err();
        assert_eq!(e.code(), tonic::Code::PermissionDenied);
        let gateway = gateway_auth::testing::from_gateway(request("sb1", b""));
        let e = m.evaluate_http_request(gateway).await.unwrap_err();
        assert_eq!(e.code(), tonic::Code::PermissionDenied);
        let own = gateway_auth::testing::from_supervisor(request("sb1", b""), "id-1");
        let r = m.evaluate_http_request(own).await.unwrap().into_inner();
        assert_eq!(r.decision, Decision_::Allow as i32);
        let d = m
            .with_audience("urn:openshell:extension:middleware:tenzro")
            .describe(Request::new(MiddlewareDescribeRequest { gateway: None }))
            .await
            .unwrap_err();
        assert_eq!(d.code(), tonic::Code::Unauthenticated);
    }
}
