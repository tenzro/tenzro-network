//! A node tells its operator, once, when it needs them.
//!
//! A node that has lost its key grant, or has not followed the network for
//! [`STALLED_FOR`], cannot fix itself. Its status and health say so, but
//! nobody reads a status nobody looks at. So the node sends one message to
//! its operator's contact route: the first `MessagingService` entry with an
//! https endpoint in the operator identity's DID document. One message per
//! episode: it is sent when the node starts needing its operator for a
//! reason and not again until that has cleared. A node with no operator
//! identity, or an operator with no such entry, sends nothing.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tenzro_types::did_services::DidServices;

use crate::follow_state::{FollowState, Following};

/// How often the node looks at whether it needs its operator.
pub const ALERT_EVERY: Duration = Duration::from_secs(60);

/// How long a node must be stalled before its operator is told.
pub const STALLED_FOR: Duration = Duration::from_secs(600);

/// The DID service type of an operator's contact route.
pub const MESSAGING_SERVICE: &str = "MessagingService";

/// How long the contact route is given to take the message.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the node needs its operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// `key_grant` or `not_following`.
    pub kind: &'static str,
    /// What is wrong, in plain words.
    pub reason: String,
}

/// Why a node needs its operator now, if it does: its key grant is wanted
/// (`key_wanted`), or it has been stalled for [`STALLED_FOR`].
pub fn needs_operator(key_wanted: Option<String>, follow: &FollowState) -> Option<Alert> {
    if let Some(reason) = key_wanted {
        return Some(Alert {
            kind: "key_grant",
            reason: format!("the node is waiting for the operator's approval: {reason}"),
        });
    }
    let stalled_for = STALLED_FOR.as_millis() as u64;
    (follow.state == Following::Stalled && follow.last_import_ms.is_none_or(|ms| ms >= stalled_for))
        .then(|| Alert {
            kind: "not_following",
            reason: crate::follow_state::unhealthy_reason(follow)
                .unwrap_or_else(|| "the node does not follow the network".to_string()),
        })
}

/// The operator's contact route among `services`: the first
/// `MessagingService` entry served over https.
pub fn contact_route(services: &DidServices) -> Option<&str> {
    services
        .services
        .iter()
        .find(|s| s.service_type == MESSAGING_SERVICE && s.endpoint.starts_with("https://"))
        .map(|s| s.endpoint.as_str())
}

/// The message the operator receives.
pub fn message(machine_did: &str, operator_did: &str, alert: &Alert) -> serde_json::Value {
    serde_json::json!({
        "type": "tenzro.node.needs_operator",
        "node": machine_did,
        "operator": operator_did,
        "kind": alert.kind,
        "reason": alert.reason,
    })
}

/// Why the node needs its operator now, from its key grant and its follow
/// state.
async fn current(node: &crate::node::TenzroNode) -> Option<Alert> {
    #[cfg(unix)]
    let key_wanted = crate::tpm_key_holder::running_grant().and_then(|g| g.waiting_for());
    #[cfg(not(unix))]
    let key_wanted = None;
    let consensus = node.consensus()?;
    let height = node.status().await.block_height;
    needs_operator(
        key_wanted,
        &consensus
            .follow()
            .state(height, consensus.validates_alone()),
    )
}

/// Sends `alert` to the operator's contact route, when there is one.
async fn send(node: &crate::node::TenzroNode, alert: &Alert) {
    let (Some(machine), Some(operator)) = (
        crate::identity_bootstrap::machine_did(),
        node.operator_did(),
    ) else {
        return;
    };
    let Some(chain) = crate::rpc::chain_state_of(node) else {
        return;
    };
    let services = tenzro_vm::native::read_did_services(&chain, &operator);
    let Some(route) = contact_route(&services) else {
        tracing::info!(
            %operator,
            "the operator identity names no MessagingService to tell of: {}",
            alert.reason
        );
        return;
    };
    let sent = crate::http_client::shared()
        .post(route)
        .timeout(SEND_TIMEOUT)
        .json(&message(&machine, &operator, alert))
        .send()
        .await
        .and_then(|r| r.error_for_status());
    match sent {
        Ok(_) => tracing::info!(%route, kind = alert.kind, "told the operator"),
        Err(e) => tracing::warn!(%route, error = %e, "could not tell the operator"),
    }
}

/// Watches, for as long as the node runs, whether it needs its operator,
/// and tells them once per episode.
pub fn spawn(node: Arc<crate::node::TenzroNode>) {
    tokio::spawn(async move {
        let mut told: Option<&'static str> = None;
        loop {
            tokio::time::sleep(ALERT_EVERY).await;
            match current(&node).await {
                Some(alert) if told != Some(alert.kind) => {
                    send(&node, &alert).await;
                    told = Some(alert.kind);
                }
                Some(_) => {}
                None => told = None,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::follow_state::{Seen, judge};
    use tenzro_types::did_services::DidServiceEntry;

    const S: Duration = Duration::from_secs(1);

    fn seen(last_import: Option<Duration>) -> Seen {
        Seen {
            local_height: 100,
            alone: false,
            up: 3_600 * S,
            head: Some((2_000, 3 * S)),
            last_import,
            behind_before: None,
            fruitless: None,
        }
    }

    #[test]
    fn a_lost_grant_or_a_long_stall_needs_the_operator_and_nothing_else_does() {
        let following = judge(Seen {
            head: Some((100, 3 * S)),
            ..seen(Some(S))
        });
        assert_eq!(needs_operator(None, &following), None);
        let key = needs_operator(Some("the grant has expired".into()), &following).unwrap();
        assert_eq!(key.kind, "key_grant");
        assert!(key.reason.contains("operator's approval"));

        let catching_up = judge(seen(Some(S)));
        assert_eq!(needs_operator(None, &catching_up), None);
        let briefly = judge(seen(Some(STALLED_FOR - 60 * S)));
        assert_eq!(
            needs_operator(None, &briefly),
            None,
            "not stalled long enough"
        );
        let long = needs_operator(None, &judge(seen(Some(STALLED_FOR + S)))).unwrap();
        assert_eq!(long.kind, "not_following");
        assert!(long.reason.contains("blocks behind"), "{}", long.reason);
    }

    #[test]
    fn the_contact_route_is_the_first_https_messaging_service() {
        let entry = |id: &str, kind: &str, endpoint: &str| DidServiceEntry {
            id: id.into(),
            service_type: kind.into(),
            endpoint: endpoint.into(),
        };
        let mut services = DidServices::default();
        assert_eq!(contact_route(&services), None);
        services.services = vec![
            entry("site", "LinkedDomains", "https://op.example"),
            entry("plain", MESSAGING_SERVICE, "http://op.example/inbox"),
            entry("inbox", MESSAGING_SERVICE, "https://op.example/inbox"),
        ];
        assert_eq!(contact_route(&services), Some("https://op.example/inbox"));
        let alert = Alert {
            kind: "key_grant",
            reason: "r".into(),
        };
        let m = message("did:tenzro:machine:a", "did:tenzro:human:b", &alert);
        assert_eq!(m["kind"], "key_grant");
        assert_eq!(m["operator"], "did:tenzro:human:b");
    }
}
