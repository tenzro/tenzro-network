//! `control_summary`: one answer an app draws its overview from, composed
//! from the node's reads and from what only this machine knows about its node.

use serde_json::{Value, json};

use crate::onboarding::role::JoinRole;

/// What only this machine can say about its node.
#[derive(Debug, Clone, Default)]
pub(crate) struct Local {
    /// A node process runs here.
    pub node_process: bool,
    /// The node program is on this machine.
    pub node_installed: bool,
    /// Why the node cannot use its key holder yet, on a machine whose keys
    /// another machine holds.
    pub grant_wanted: Option<String>,
    /// Where this machine's keys are: `tpm`, `secure_enclave`, `key_holder`
    /// or `none`.
    pub keys_in: &'static str,
    /// The name the operator gave the key holder.
    pub key_holder_label: Option<String>,
    /// Whether the operator authorises with a passkey, once setup has asked.
    pub passkey_bound: Option<bool>,
    /// The operator's identity, once setup has made it.
    pub did: Option<String>,
    /// The operator's account, once setup has made it.
    pub wallet_address: Option<String>,
}

/// What the node answered to each read; `None` where it gave no result.
#[derive(Debug, Default)]
pub(crate) struct Reads {
    /// `tenzro_getNodeStatus`
    pub status: Option<Value>,
    /// `tenzro_syncing`
    pub syncing: Option<Value>,
    /// `tenzro_getRole`
    pub role: Option<Value>,
    /// `tenzro_getRoleStakes`
    pub stakes: Option<Value>,
    /// `tenzro_getUpdateNotice`
    pub notice: Option<Value>,
    /// `eth_getBalance` of the staking account
    pub balance: Option<Value>,
    /// `tenzro_listConditions`
    pub conditions: Option<Value>,
}

/// The summary. `node` is `None` when the node gave no answer at all.
pub(crate) fn compose(node: Option<&Reads>, local: &Local) -> Value {
    match node {
        Some(reads) => answering(reads, local),
        None => silent(local),
    }
}

/// The account whose stake the summary reports: the one the node answered
/// stakes for, else its operator payee.
pub(crate) fn stake_address(status: Option<&Value>, stakes: Option<&Value>) -> Option<String> {
    text(stakes, "address").or_else(|| text(status, "payee"))
}

/// Whether the node runs here, is installed and stopped, or is not installed.
pub(crate) fn service_state(local: &Local) -> &'static str {
    if local.node_process {
        "running"
    } else if local.node_installed {
        "stopped"
    } else {
        "not_installed"
    }
}

fn silent(local: &Local) -> Value {
    let service = service_state(local);
    let (state, reason) = match (service, &local.grant_wanted) {
        ("running", Some(why)) => ("waiting_for_key_grant", Some(why.as_str())),
        ("running", None) => ("starting", None),
        (other, _) => (other, None),
    };
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "node": {
            "service": service,
            "follow": {
                "state": state,
                "height": 0,
                "target": 0,
                "last_block_secs": null,
                "reason": reason,
            },
            "peers": 0,
            "uptime_secs": 0,
            "health": "unknown",
            "disk": null,
        },
        "role": { "roles": [] },
        "stake": {
            "address": local.wallet_address,
            "bonded": "0",
            "required": null,
            "available": null,
            "token": "TNZO",
        },
        "identity": identity(local.did.clone(), local),
        "update": { "current": null, "latest": null, "severity": null, "auto": null },
        "conditions": 0,
    })
}

fn answering(reads: &Reads, local: &Local) -> Value {
    let status = reads.status.as_ref();
    let syncing = reads.syncing.as_ref().filter(|s| s.is_object());
    let height = number(syncing, "local_height")
        .or_else(|| number(status, "block_height"))
        .unwrap_or(0);
    let binary = status
        .and_then(|s| s.get("update"))
        .and_then(|u| u.get("binary_version"))
        .and_then(Value::as_str);
    let roles = roles(reads);
    let (bonded, required) = stake_totals(reads.stakes.as_ref(), &roles);
    let did = text(status, "operator_did")
        .or_else(|| local.did.clone())
        .or_else(|| text(status, "machine_did"));
    json!({
        "version": binary.unwrap_or(env!("CARGO_PKG_VERSION")),
        "node": {
            "service": "running",
            "follow": {
                "state": text(syncing, "state").unwrap_or_else(|| "starting".into()),
                "height": height,
                "target": number(syncing, "network_head").unwrap_or(height),
                "last_block_secs": number(syncing, "last_import_ms").map(|ms| ms / 1000),
                "reason": syncing.and_then(|s| s.get("reason")),
            },
            "peers": number(status, "peer_count").unwrap_or(0),
            "uptime_secs": number(status, "uptime_secs").unwrap_or(0),
            "health": text(status, "health_status")
                .map_or_else(|| "unknown".into(), |h| h.to_ascii_lowercase()),
            "disk": status.and_then(|s| s.get("disk")).filter(|d| d.is_object()).map(|d| json!({
                "used_pct": d.get("used_pct"),
                "level": d.get("level"),
                "free_bytes": d.get("assessment").and_then(|a| a.get("free_bytes")),
            })),
        },
        "role": { "roles": roles },
        "stake": {
            "address": stake_address(status, reads.stakes.as_ref())
                .or_else(|| local.wallet_address.clone()),
            "bonded": bonded.to_string(),
            "required": required.map(|r| r.to_string()),
            "available": reads.balance.as_ref().and_then(amount).map(|a| a.to_string()),
            "token": "TNZO",
        },
        "identity": identity(did, local),
        "update": {
            "current": binary,
            "latest": reads.notice.as_ref().and_then(|n| n.get("latest_version")),
            "severity": reads.notice.as_ref().and_then(|n| n.get("severity")),
            "auto": null,
        },
        "conditions": reads
            .conditions
            .as_ref()
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    })
}

fn identity(did: Option<String>, local: &Local) -> Value {
    json!({
        "did": did,
        "keys_in": local.keys_in,
        "key_holder_label": local.key_holder_label,
        "passkey_bound": local.passkey_bound,
    })
}

/// The roles the node runs, in lower case: from `tenzro_getRole`, else from
/// its status.
fn roles(reads: &Reads) -> Vec<String> {
    [reads.role.as_ref(), reads.status.as_ref()]
        .into_iter()
        .flatten()
        .find_map(|v| v.get("roles")?.as_array())
        .map(|roles| {
            roles
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default()
}

/// What the account has bonded across its roles, and what its roles require:
/// each bonded role's own requirement, and the entry minimum of every role the
/// node runs with nothing bonded yet. `None` when no role asks for a stake.
fn stake_totals(stakes: Option<&Value>, roles: &[String]) -> (u128, Option<u128>) {
    let entries: Vec<(Option<JoinRole>, u128, u128)> = stakes
        .and_then(|s| s.get("stakes"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|s| {
                    (
                        s.get("role")
                            .and_then(Value::as_str)
                            .and_then(JoinRole::parse),
                        s.get("bonded").and_then(amount).unwrap_or(0),
                        s.get("required").and_then(amount).unwrap_or(0),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let bonded = entries.iter().map(|e| e.1).sum();
    let unbonded: Vec<u128> = roles
        .iter()
        .filter_map(|r| JoinRole::parse(r))
        .filter(|role| !entries.iter().any(|e| e.0 == Some(*role)))
        .map(JoinRole::stake_minimum_wei)
        .collect();
    let required = (!entries.is_empty() || !unbonded.is_empty())
        .then(|| entries.iter().map(|e| e.2).sum::<u128>() + unbonded.iter().sum::<u128>());
    (bonded, required)
}

/// An amount in the smallest unit: a decimal string, a `0x` quantity, or a
/// number.
fn amount(v: &Value) -> Option<u128> {
    match v {
        Value::String(s) => match s.strip_prefix("0x") {
            Some(hex) => u128::from_str_radix(hex, 16).ok(),
            None => s.parse().ok(),
        },
        Value::Number(n) => n.as_u64().map(u128::from),
        _ => None,
    }
}

fn text(v: Option<&Value>, key: &str) -> Option<String> {
    v?.get(key)?.as_str().map(str::to_owned)
}

fn number(v: Option<&Value>, key: &str) -> Option<u64> {
    v?.get(key)?.as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn following() -> Reads {
        Reads {
            status: Some(json!({
                "state": "Running",
                "roles": ["Validator"],
                "health_status": "Healthy",
                "uptime_secs": 7200,
                "block_height": 41,
                "peer_count": 9,
                "data_dir": "/var/lib/tenzro",
                "disk": { "used_pct": 37, "level": "ok", "assessment": { "free_bytes": 5_000_000_000u64 } },
                "machine_did": "did:tenzro:machine:m1",
                "operator_did": "did:tenzro:human:op",
                "update": { "binary_version": "0.2.2", "state": "current" },
                "payee": "0x00000000000000000000000000000000000000aa",
            })),
            syncing: Some(json!({
                "state": "catching_up", "reason": "behind", "detail": null,
                "local_height": 40, "network_head": 90, "head_heard_ms": 300,
                "behind": 50, "behind_before": 70, "last_import_ms": 2400,
            })),
            role: Some(
                json!({ "roles": ["validator", "model-provider"], "roles_str": "validator,model-provider" }),
            ),
            stakes: Some(json!({
                "address": "0x00000000000000000000000000000000000000bb",
                "stakes": [{ "role": "validator", "bonded": "3000000000000000000", "required": "5000000000000000000" }],
                "totals": [],
            })),
            notice: Some(json!({ "latest_version": "0.2.9", "severity": "recommended" })),
            balance: Some(json!("0xde0b6b3a7640000")),
            conditions: Some(json!([{ "id": "c1" }, { "id": "c2" }])),
        }
    }

    fn machine() -> Local {
        Local {
            node_process: true,
            node_installed: true,
            grant_wanted: None,
            keys_in: "tpm",
            key_holder_label: None,
            passkey_bound: Some(true),
            did: Some("did:tenzro:human:saved".into()),
            wallet_address: Some("0x00000000000000000000000000000000000000cc".into()),
        }
    }

    #[test]
    fn a_following_node_is_summarised_from_its_reads() {
        let s = compose(Some(&following()), &machine());
        assert_eq!(s["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(s["node"]["service"], "running");
        assert_eq!(
            s["node"]["follow"],
            json!({ "state": "catching_up", "height": 40, "target": 90, "last_block_secs": 2, "reason": "behind" })
        );
        assert_eq!(s["node"]["peers"], 9);
        assert_eq!(s["node"]["uptime_secs"], 7200);
        assert_eq!(s["node"]["health"], "healthy");
        assert_eq!(
            s["node"]["disk"],
            json!({ "used_pct": 37, "level": "ok", "free_bytes": 5_000_000_000u64 })
        );
        // Where the node keeps its data is not an app's to know.
        assert!(s["node"].get("data_dir").is_none());
        assert_eq!(
            s["role"],
            json!({ "roles": ["validator", "model-provider"] })
        );
        assert_eq!(
            s["stake"]["address"],
            "0x00000000000000000000000000000000000000bb"
        );
        assert_eq!(s["stake"]["bonded"], "3000000000000000000");
        assert_eq!(
            s["stake"]["required"],
            (5_000_000_000_000_000_000u128 + JoinRole::ModelProvider.stake_minimum_wei())
                .to_string()
        );
        assert_eq!(s["stake"]["available"], "1000000000000000000");
        assert_eq!(s["stake"]["token"], "TNZO");
        assert_eq!(
            s["identity"],
            json!({ "did": "did:tenzro:human:op", "keys_in": "tpm", "key_holder_label": null, "passkey_bound": true })
        );
        assert_eq!(
            s["update"],
            json!({ "current": "0.2.2", "latest": "0.2.9", "severity": "recommended", "auto": null })
        );
        assert_eq!(s["conditions"], 2);
    }

    #[test]
    fn a_node_that_answers_only_its_status_still_gives_every_field() {
        let reads = Reads {
            status: Some(json!({ "roles": ["Validator"], "block_height": 12, "peer_count": 1 })),
            ..Reads::default()
        };
        let s = compose(Some(&reads), &machine());
        assert_eq!(s["node"]["service"], "running");
        assert_eq!(
            s["node"]["follow"],
            json!({ "state": "starting", "height": 12, "target": 12, "last_block_secs": null, "reason": null })
        );
        assert_eq!(s["node"]["disk"], Value::Null);
        assert_eq!(s["role"]["roles"], json!(["validator"]));
        assert_eq!(
            s["stake"]["address"],
            "0x00000000000000000000000000000000000000cc"
        );
        assert_eq!(s["stake"]["bonded"], "0");
        assert_eq!(
            s["stake"]["required"],
            JoinRole::Validator.stake_minimum_wei().to_string()
        );
        assert_eq!(s["stake"]["available"], Value::Null);
        assert_eq!(s["identity"]["did"], "did:tenzro:human:saved");
        assert_eq!(s["update"]["latest"], Value::Null);
        assert_eq!(s["conditions"], 0);
    }

    #[test]
    fn the_head_is_the_nodes_own_height_until_it_has_heard_one() {
        let mut reads = following();
        reads.syncing = Some(
            json!({ "state": "starting", "local_height": 40, "network_head": null, "last_import_ms": null }),
        );
        let s = compose(Some(&reads), &machine());
        assert_eq!(s["node"]["follow"]["target"], 40);
        assert_eq!(s["node"]["follow"]["last_block_secs"], Value::Null);
    }

    #[test]
    fn a_node_with_no_staked_role_requires_nothing() {
        let reads = Reads {
            status: Some(json!({})),
            role: Some(json!({ "roles": ["light-client"] })),
            ..Reads::default()
        };
        let s = compose(Some(&reads), &machine());
        assert_eq!(s["stake"]["bonded"], "0");
        assert_eq!(s["stake"]["required"], Value::Null);
    }

    #[test]
    fn a_silent_node_is_starting_stopped_or_not_installed() {
        let mut local = machine();
        let s = compose(None, &local);
        assert_eq!(s["node"]["service"], "running");
        assert_eq!(s["node"]["follow"]["state"], "starting");
        assert_eq!(s["node"]["follow"]["reason"], Value::Null);

        local.node_process = false;
        let s = compose(None, &local);
        assert_eq!(s["node"]["service"], "stopped");
        assert_eq!(s["node"]["follow"]["state"], "stopped");

        local.node_installed = false;
        let s = compose(None, &local);
        assert_eq!(s["node"]["service"], "not_installed");
        assert_eq!(s["node"]["follow"]["state"], "not_installed");
        assert_eq!(s["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(s["node"]["follow"]["height"], 0);
        assert_eq!(s["node"]["disk"], Value::Null);
        assert_eq!(s["role"]["roles"], json!([]));
        assert_eq!(
            s["stake"]["address"],
            "0x00000000000000000000000000000000000000cc"
        );
        assert_eq!(s["stake"]["bonded"], "0");
        assert_eq!(s["identity"]["did"], "did:tenzro:human:saved");
        assert_eq!(s["update"]["current"], Value::Null);
        assert_eq!(s["conditions"], 0);
    }

    #[test]
    fn a_running_node_whose_key_holder_has_no_grant_is_waiting_for_it() {
        let local = Local {
            grant_wanted: Some("the key holder has no grant".into()),
            keys_in: "key_holder",
            key_holder_label: Some("the office server".into()),
            ..machine()
        };
        let s = compose(None, &local);
        assert_eq!(s["node"]["service"], "running");
        assert_eq!(s["node"]["follow"]["state"], "waiting_for_key_grant");
        assert_eq!(s["node"]["follow"]["reason"], "the key holder has no grant");
        assert_eq!(s["identity"]["keys_in"], "key_holder");
        assert_eq!(s["identity"]["key_holder_label"], "the office server");

        // A node that is not running is stopped, whatever its key holder says.
        let stopped = Local {
            node_process: false,
            ..local
        };
        assert_eq!(
            compose(None, &stopped)["node"]["follow"]["state"],
            "stopped"
        );
    }

    #[test]
    fn amounts_read_as_decimal_text_hex_quantities_and_numbers() {
        assert_eq!(
            amount(&json!("340282366920938463463374607431768211455")),
            Some(u128::MAX)
        );
        assert_eq!(amount(&json!("0x10")), Some(16));
        assert_eq!(amount(&json!(7)), Some(7));
        assert_eq!(amount(&json!("seven")), None);
        assert_eq!(amount(&Value::Null), None);
    }
}
