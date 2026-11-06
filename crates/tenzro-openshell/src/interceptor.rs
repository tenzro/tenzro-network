//! Gateway interceptor: sandbox creation and policy changes held to Terms.
//!
//! The caller is the OpenShell principal; it acts for the controller account
//! its subject is bound to on Tenzro. A sandbox names the agent it runs in
//! its `tenzro.agent` annotation (a DID is longer than OpenShell allows a
//! label value to be). Creating it is allowed only when that agent was
//! delegated by the caller's controller, neither is revoked, the Terms allow
//! the `sandbox` operation and this host's attestation verified; the
//! operation is then annotated with the agent and the host binding. A policy
//! change to the sandbox is allowed only under the same conditions and the
//! `sandbox.policy` operation. Every decision is a signed record.

use std::collections::HashMap;
use std::sync::Arc;

use prost_types::value::Kind;
use serde_json::Value as Json;
use tenzro_types::agent_audit::{ActionKind, ActionOutcome};
use tonic::{Request, Response, Status};

use crate::authority::{Authority, Proposed};
use crate::gateway_auth::{self, CallerKind};
use crate::openshell::gateway_interceptor::v1::gateway_interceptor_server::GatewayInterceptor;
use crate::openshell::gateway_interceptor::v1::interceptor_evaluation::Phase;
use crate::openshell::gateway_interceptor::v1::*;
use crate::peer;
use crate::records::{Decision, RecordLog};

/// The annotation a sandbox names its agent in.
pub const AGENT_LABEL: &str = "tenzro.agent";
/// The annotation the host binding is written to.
pub const HOST_ANNOTATION: &str = "tenzro.host";

const CREATE: &str = "openshell.v1.OpenShell/CreateSandbox";
const UPDATE_CONFIG: &str = "openshell.v1.OpenShell/UpdateConfig";

/// The Tenzro gateway interceptor.
pub struct TenzroInterceptor {
    authority: Arc<dyn Authority>,
    records: Arc<RecordLog>,
    audience: String,
}

impl TenzroInterceptor {
    /// An interceptor deciding against `authority`. The host binding comes
    /// from the record log: without one, no sandbox is created.
    pub fn new(authority: Arc<dyn Authority>, records: Arc<RecordLog>) -> Self {
        Self {
            authority,
            records,
            audience: String::new(),
        }
    }

    /// Advertise the token audience this interceptor's guard verifies, so
    /// the gateway confirms it mints for the same one.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    fn binding(
        id: &str,
        rpc: &str,
        phases: &[GatewayInterceptorPhase],
        policy: &str,
    ) -> InterceptorBinding {
        InterceptorBinding {
            id: id.to_string(),
            selector: Some(InterceptorSelector {
                rpc: rpc.to_string(),
                ..Default::default()
            }),
            phases: phases.iter().map(|p| *p as i32).collect(),
            failure_policy: policy.to_string(),
        }
    }

    fn record(&self, session: &str, agent: &str, rpc: &str, outcome: ActionOutcome, detail: &[u8]) {
        if let Err(e) = self.records.record(Decision {
            session,
            agent,
            kind: ActionKind::GrantUse,
            action: rpc,
            outcome,
            detail,
            linked_tx: None,
        }) {
            tracing::error!("interceptor record not written: {e}");
        }
    }

    /// The agent the caller may act for, checked against its Terms for
    /// `operation`.
    fn check(
        &self,
        principal: &HashMap<String, String>,
        agent: &str,
        operation: &str,
    ) -> Result<(), String> {
        let subject = principal.get("subject").map(String::as_str).unwrap_or("");
        let controller = self
            .authority
            .controller_of(subject)
            .ok_or_else(|| format!("caller {subject:?} is not bound to a Tenzro account"))?;
        let terms = self
            .authority
            .terms(agent)
            .ok_or_else(|| format!("{agent} has no Terms"))?;
        if terms.controller_did != controller {
            return Err(format!("{agent} was not delegated by {controller}"));
        }
        self.authority
            .authorize(
                agent,
                &Proposed {
                    operation: operation.to_string(),
                    ..Default::default()
                },
                crate::now_ms(),
            )
            .map_err(|r| r.0)
    }

    fn create_agent(op: &Json) -> Result<String, String> {
        op.pointer("/annotations")
            .and_then(|l| l.get(AGENT_LABEL))
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("the sandbox names no agent in its {AGENT_LABEL} annotation"))
    }

    fn sandbox_name(op: &Json) -> String {
        op.get("name")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string()
    }

    fn evaluate_create(
        &self,
        principal: &HashMap<String, String>,
        op: &Json,
        modify: bool,
    ) -> InterceptorResult {
        let name = Self::sandbox_name(op);
        let detail = serde_json::to_vec(op).unwrap_or_default();
        let decided = Self::create_agent(op).and_then(|agent| {
            let host = self
                .records
                .image()
                .ok_or_else(|| "this host's attestation did not verify".to_string())?
                .to_string();
            self.check(principal, &agent, "sandbox")?;
            Ok((agent, host))
        });
        match decided {
            Ok((agent, host)) => {
                let session = if name.is_empty() {
                    agent.as_str()
                } else {
                    name.as_str()
                };
                self.record(session, &agent, CREATE, ActionOutcome::Allowed, &detail);
                let mut result = allow(&agent);
                if modify {
                    result.patches = annotate(op, &[(HOST_ANNOTATION, &host)]);
                }
                result
            }
            Err(why) => {
                let agent = Self::create_agent(op).unwrap_or_default();
                let session = if name.is_empty() {
                    "unnamed"
                } else {
                    name.as_str()
                };
                self.record(
                    session,
                    &agent,
                    CREATE,
                    ActionOutcome::Refused(why.clone()),
                    &detail,
                );
                deny(why)
            }
        }
    }

    fn evaluate_update(&self, principal: &HashMap<String, String>, op: &Json) -> InterceptorResult {
        let detail = serde_json::to_vec(op).unwrap_or_default();
        if op.get("global").and_then(Json::as_bool).unwrap_or(false) {
            // A gateway-wide change is the operator's, not an agent's.
            let subject = principal.get("subject").cloned().unwrap_or_default();
            self.record(
                "gateway",
                &subject,
                UPDATE_CONFIG,
                ActionOutcome::Allowed,
                &detail,
            );
            return allow("");
        }
        let sandbox = op.get("sandbox").and_then(Json::as_str).unwrap_or("");
        let decided = self
            .authority
            .agent_of_sandbox(sandbox)
            .ok_or_else(|| format!("sandbox {sandbox:?} runs no Tenzro agent"))
            .and_then(|agent| {
                self.check(principal, &agent, "sandbox.policy")?;
                Ok(agent)
            });
        match decided {
            Ok(agent) => {
                self.record(
                    sandbox,
                    &agent,
                    UPDATE_CONFIG,
                    ActionOutcome::Allowed,
                    &detail,
                );
                allow(&agent)
            }
            Err(why) => {
                let agent = self.authority.agent_of_sandbox(sandbox).unwrap_or_default();
                self.record(
                    sandbox,
                    &agent,
                    UPDATE_CONFIG,
                    ActionOutcome::Refused(why.clone()),
                    &detail,
                );
                deny(why)
            }
        }
    }

    /// After a sandbox is created, remember which agent it runs under each
    /// of its names.
    fn committed_create(&self, response: &Json) {
        let meta = response.pointer("/sandbox/metadata");
        let label = meta
            .and_then(|m| m.pointer("/annotations"))
            .and_then(|l| l.get(AGENT_LABEL))
            .and_then(Json::as_str);
        if let (Some(meta), Some(agent)) = (meta, label) {
            let id = meta.get("id").and_then(Json::as_str).unwrap_or("");
            let name = meta.get("name").and_then(Json::as_str).unwrap_or("");
            self.authority.bind_sandbox(&[id, name], agent);
        }
    }
}

fn allow(agent: &str) -> InterceptorResult {
    InterceptorResult {
        allowed: true,
        reason: String::new(),
        status_code: String::new(),
        patches: Vec::new(),
        log_annotations: HashMap::from([("tenzro.agent".to_string(), agent.to_string())]),
    }
}

fn deny(reason: String) -> InterceptorResult {
    InterceptorResult {
        allowed: false,
        reason,
        status_code: "PERMISSION_DENIED".to_string(),
        patches: Vec::new(),
        log_annotations: HashMap::new(),
    }
}

fn string_value(s: &str) -> prost_types::Value {
    prost_types::Value {
        kind: Some(Kind::StringValue(s.to_string())),
    }
}

/// RFC 6902 patches adding `pairs` to the operation's annotations.
fn annotate(op: &Json, pairs: &[(&str, &str)]) -> Vec<JsonPatch> {
    let escape = |k: &str| k.replace('~', "~0").replace('/', "~1");
    if op.get("annotations").is_some_and(Json::is_object) {
        pairs
            .iter()
            .map(|(k, v)| JsonPatch {
                op: "add".into(),
                path: format!("/annotations/{}", escape(k)),
                value: Some(string_value(v)),
                from: String::new(),
            })
            .collect()
    } else {
        let fields = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), string_value(v)))
            .collect();
        vec![JsonPatch {
            op: "add".into(),
            path: "/annotations".into(),
            value: Some(prost_types::Value {
                kind: Some(Kind::StructValue(prost_types::Struct { fields })),
            }),
            from: String::new(),
        }]
    }
}

fn to_json(s: Option<&prost_types::Struct>) -> Json {
    s.map(openshell_core::proto_struct::struct_to_json_value)
        .unwrap_or(Json::Null)
}

/// Refuse a call that is not the gateway's.
fn from_gateway<T>(request: &Request<T>) -> Result<(), Status> {
    match gateway_auth::caller(request)?.kind {
        CallerKind::Gateway => Ok(()),
        CallerKind::Supervisor => Err(Status::permission_denied(
            "only the gateway calls the interceptor",
        )),
    }
}

#[tonic::async_trait]
impl GatewayInterceptor for TenzroInterceptor {
    async fn describe(
        &self,
        request: Request<DescribeRequest>,
    ) -> Result<Response<InterceptorManifest>, Status> {
        from_gateway(&request)?;
        peer::negotiate(request.get_ref().gateway.as_ref(), peer::INTERCEPTOR)?;
        use GatewayInterceptorPhase as P;
        Ok(Response::new(InterceptorManifest {
            name: "tenzro".to_string(),
            bindings: vec![
                Self::binding(
                    "tenzro-sandbox-create",
                    CREATE,
                    &[P::ModifyOperation, P::Validate],
                    "fail_closed",
                ),
                Self::binding(
                    "tenzro-sandbox-created",
                    CREATE,
                    &[P::PostCommit],
                    "fail_open",
                ),
                Self::binding(
                    "tenzro-policy-change",
                    UPDATE_CONFIG,
                    &[P::Validate],
                    "fail_closed",
                ),
            ],
            failure_policy: "fail_closed".to_string(),
            provider_profiles: false,
            expected_audience: self.audience.clone(),
            extension: Some(peer::metadata(peer::INTERCEPTOR)),
        }))
    }

    async fn snapshot_provider_profiles(
        &self,
        request: Request<ProviderProfileSnapshotRequest>,
    ) -> Result<Response<ProviderProfileSnapshot>, Status> {
        from_gateway(&request)?;
        Err(Status::unimplemented("Tenzro vends no provider profiles"))
    }

    async fn evaluate(
        &self,
        request: Request<InterceptorEvaluation>,
    ) -> Result<Response<InterceptorResult>, Status> {
        from_gateway(&request)?;
        let e = request.into_inner();
        let rpc = format!("{}/{}", e.service, e.method);
        let result = match (rpc.as_str(), e.phase) {
            (CREATE, Some(Phase::ModifyOperation(m))) => {
                self.evaluate_create(&e.principal, &to_json(m.proposed_operation.as_ref()), true)
            }
            (CREATE, Some(Phase::Validate(v))) => {
                self.evaluate_create(&e.principal, &to_json(v.proposed_operation.as_ref()), false)
            }
            (CREATE, Some(Phase::PostCommit(p))) => {
                self.committed_create(&to_json(p.committed_response.as_ref()));
                allow("")
            }
            (UPDATE_CONFIG, Some(Phase::Validate(v))) => {
                self.evaluate_update(&e.principal, &to_json(v.proposed_operation.as_ref()))
            }
            (UPDATE_CONFIG, Some(Phase::PostCommit(_))) => allow(""),
            _ => deny(format!(
                "{rpc} is not bound to the Tenzro interceptor in this phase"
            )),
        };
        Ok(Response::new(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_driver::tests::{ROOT, agent, fixture};
    use crate::openshell::gateway_interceptor::v1::{
        ModifyOperationEvaluation, ValidateEvaluation,
    };
    use crate::records::verify_session;

    fn principal(subject: &str) -> HashMap<String, String> {
        HashMap::from([
            ("kind".to_string(), "operator".to_string()),
            ("subject".to_string(), subject.to_string()),
        ])
    }

    fn proto(v: Json) -> Option<prost_types::Struct> {
        let Json::Object(map) = v else { unreachable!() };
        Some(openshell_core::proto_struct::json_object_to_struct(map).unwrap())
    }

    fn interceptor(
        ops: &[&str],
        host: bool,
    ) -> (
        TenzroInterceptor,
        Arc<crate::authority::StateAuthority>,
        Arc<RecordLog>,
    ) {
        let (a, s, _) = fixture(ops);
        let records = Arc::new(RecordLog::new(s, host.then(|| "tee:tpm:00".to_string())));
        a.bind_principal("alice", ROOT);
        (
            TenzroInterceptor::new(a.clone(), records.clone()),
            a,
            records,
        )
    }

    async fn create(
        i: &TenzroInterceptor,
        who: &str,
        labels: Json,
        modify: bool,
    ) -> InterceptorResult {
        let op = proto(serde_json::json!({"name": "sb1", "annotations": labels}));
        let phase = if modify {
            Phase::ModifyOperation(ModifyOperationEvaluation {
                proposed_operation: op,
            })
        } else {
            Phase::Validate(ValidateEvaluation {
                proposed_operation: op,
                current_state: None,
            })
        };
        i.evaluate(gateway_auth::testing::from_gateway(InterceptorEvaluation {
            interceptor_name: "tenzro".into(),
            binding_id: "b".into(),
            service: "openshell.v1.OpenShell".into(),
            method: "CreateSandbox".into(),
            principal: principal(who),
            phase: Some(phase),
        }))
        .await
        .unwrap()
        .into_inner()
    }

    #[tokio::test]
    async fn the_manifest_binds_creation_and_policy_changes() {
        let (i, _, _) = interceptor(&["sandbox"], true);
        let m = i
            .describe(gateway_auth::testing::from_gateway(DescribeRequest {
                gateway: Some(peer::metadata(peer::INTERCEPTOR)),
            }))
            .await
            .unwrap()
            .into_inner();
        let rpcs: Vec<_> = m
            .bindings
            .iter()
            .map(|b| b.selector.as_ref().unwrap().rpc.clone())
            .collect();
        assert!(rpcs.contains(&CREATE.to_string()) && rpcs.contains(&UPDATE_CONFIG.to_string()));
        assert_eq!(m.failure_policy, "fail_closed");
    }

    #[tokio::test]
    async fn the_delegating_account_creates_its_agents_sandbox_annotated_with_the_host() {
        let (i, _, records) = interceptor(&["sandbox"], true);
        let r = create(&i, "alice", serde_json::json!({AGENT_LABEL: agent()}), true).await;
        assert!(r.allowed, "{}", r.reason);
        assert_eq!(r.patches.len(), 1);
        assert_eq!(r.patches[0].path, "/annotations/tenzro.host");
        let entries = verify_session(records.identity(), &records.entries("sb1")).unwrap();
        assert_eq!(entries[0].outcome, ActionOutcome::Allowed);
    }

    #[tokio::test]
    async fn another_account_cannot_create_the_agents_sandbox() {
        let (i, a, _) = interceptor(&["sandbox"], true);
        a.bind_principal("mallory", "did:tenzro:human:ffff");
        let r = create(
            &i,
            "mallory",
            serde_json::json!({AGENT_LABEL: agent()}),
            false,
        )
        .await;
        assert!(!r.allowed);
        assert!(r.reason.contains("not delegated"), "{}", r.reason);
        let r = create(
            &i,
            "unbound",
            serde_json::json!({AGENT_LABEL: agent()}),
            false,
        )
        .await;
        assert!(!r.allowed);
    }

    #[tokio::test]
    async fn a_sandbox_without_an_agent_or_outside_the_terms_is_refused() {
        let (i, _, records) = interceptor(&["fetch"], true);
        assert!(
            !create(&i, "alice", serde_json::json!({}), false)
                .await
                .allowed
        );
        let r = create(
            &i,
            "alice",
            serde_json::json!({AGENT_LABEL: agent()}),
            false,
        )
        .await;
        assert!(!r.allowed);
        assert!(r.reason.contains("operation"), "{}", r.reason);
        let entries = verify_session(records.identity(), &records.entries("sb1")).unwrap();
        assert!(
            entries
                .iter()
                .all(|e| matches!(e.outcome, ActionOutcome::Refused(_)))
        );
    }

    #[tokio::test]
    async fn without_a_verified_host_no_sandbox_is_created() {
        let (i, _, _) = interceptor(&["sandbox"], false);
        let r = create(
            &i,
            "alice",
            serde_json::json!({AGENT_LABEL: agent()}),
            false,
        )
        .await;
        assert!(!r.allowed);
        assert!(r.reason.contains("attestation"), "{}", r.reason);
    }

    #[tokio::test]
    async fn a_revoked_agent_gets_no_sandbox_and_no_policy_change() {
        let (i, a, _) = interceptor(&["sandbox", "sandbox.policy"], true);
        let committed = proto(serde_json::json!({"sandbox": {"metadata": {
            "id": "id-1", "name": "sb1", "annotations": {AGENT_LABEL: agent()}}}}));
        let post = InterceptorEvaluation {
            service: "openshell.v1.OpenShell".into(),
            method: "CreateSandbox".into(),
            principal: principal("alice"),
            phase: Some(Phase::PostCommit(PostCommitEvaluation {
                committed_response: committed,
            })),
            ..Default::default()
        };
        assert!(
            i.evaluate(gateway_auth::testing::from_gateway(post))
                .await
                .unwrap()
                .into_inner()
                .allowed
        );
        let update = |who: &str| InterceptorEvaluation {
            service: "openshell.v1.OpenShell".into(),
            method: "UpdateConfig".into(),
            principal: principal(who),
            phase: Some(Phase::Validate(ValidateEvaluation {
                proposed_operation: proto(serde_json::json!({"sandbox": "sb1"})),
                current_state: None,
            })),
            ..Default::default()
        };
        assert!(
            i.evaluate(gateway_auth::testing::from_gateway(update("alice")))
                .await
                .unwrap()
                .into_inner()
                .allowed
        );
        a.revoke(&agent(), "compromised");
        let r = i
            .evaluate(gateway_auth::testing::from_gateway(update("alice")))
            .await
            .unwrap()
            .into_inner();
        assert!(!r.allowed);
        assert!(r.reason.contains("revoked"), "{}", r.reason);
        assert!(
            !create(
                &i,
                "alice",
                serde_json::json!({AGENT_LABEL: agent()}),
                false
            )
            .await
            .allowed
        );
    }

    #[tokio::test]
    async fn only_the_authenticated_gateway_reaches_the_interceptor() {
        let (i, _, _) = interceptor(&["sandbox"], true);
        let e = i
            .evaluate(Request::new(InterceptorEvaluation {
                interceptor_name: "tenzro".into(),
                binding_id: "b".into(),
                service: "openshell.v1.OpenShell".into(),
                method: "CreateSandbox".into(),
                principal: principal("alice"),
                phase: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::Unauthenticated);
        let e = i
            .describe(gateway_auth::testing::from_supervisor(
                DescribeRequest {
                    gateway: Some(peer::metadata(peer::INTERCEPTOR)),
                },
                "id-1",
            ))
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::PermissionDenied);
        let m = i
            .with_audience("urn:tenzro:openshell:interceptor")
            .describe(gateway_auth::testing::from_gateway(DescribeRequest {
                gateway: Some(peer::metadata(peer::INTERCEPTOR)),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(m.expected_audience, "urn:tenzro:openshell:interceptor");
    }
}
