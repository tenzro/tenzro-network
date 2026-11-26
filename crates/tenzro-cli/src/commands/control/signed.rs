//! The helper's calls that change the operator's standing on the network:
//! `control_stake`, `control_unstake` and `control_setRole`.
//!
//! A stake is bonded or unbonded by `tenzro stake bond` and `tenzro stake
//! unbond`, signed in this machine's hardware as the node's account, exactly
//! as the terminal signs it. The roles the node takes are set through the
//! node's own `tenzro_setRole` with the operator's session. Each call needs
//! `confirm` set to its own name. Nothing waits on a passkey, so the answer's
//! `condition_id` and `ceremony` are null.

use clap::Parser;
use serde_json::{Value, json};

use super::{Helper, INVALID_PARAMS, REFUSED, error};
use crate::commands::stake::{StakeBondCmd, StakeUnbondCmd};

impl Helper {
    /// `control_stake {role, amount, confirm: "stake"}` and `control_unstake
    /// {role, amount, confirm: "unstake"}`. `amount` is in the smallest unit.
    pub(super) async fn stake(&self, name: &str, params: &Value) -> Result<Value, Value> {
        confirmed(name, params)?;
        let role = text(params, "role")?;
        let amount = text(params, "amount")?;
        if amount.is_empty() || !amount.bytes().all(|b| b.is_ascii_digit()) {
            return Err(error(
                INVALID_PARAMS,
                "amount is a whole number of the smallest unit",
            ));
        }
        let args = stake_args(name, role, amount, self.node.url());
        let done = if name == "stake" {
            match StakeBondCmd::try_parse_from(&args) {
                Ok(cmd) => cmd.execute().await,
                Err(e) => return Err(error(INVALID_PARAMS, &e.to_string())),
            }
        } else {
            match StakeUnbondCmd::try_parse_from(&args) {
                Ok(cmd) => cmd.execute().await,
                Err(e) => return Err(error(INVALID_PARAMS, &e.to_string())),
            }
        };
        done.map_err(|e| error(REFUSED, &format!("{e:#}")))?;
        Ok(json!({ "condition_id": null, "ceremony": null }))
    }

    /// `control_setRole {role, confirm: "setRole"}`: the node takes `role`
    /// in place of the roles it took.
    pub(super) async fn set_role(&self, params: &Value) -> Result<Value, Value> {
        confirmed("setRole", params)?;
        let role = text(params, "role")?;
        match self
            .ask_node(
                "tenzro_setRole",
                json!({ "roles": [role] }),
                self.node_has_until(),
            )
            .await
        {
            Some(Ok(_)) => Ok(json!({ "condition_id": null, "ceremony": null })),
            Some(Err(refused)) => Err(refused),
            None => Err(error(REFUSED, "This machine's node is not answering.")),
        }
    }
}

/// The arguments `tenzro stake bond` or `tenzro stake unbond` would be run
/// with to sign as this machine's node account.
fn stake_args(name: &str, role: &str, amount: &str, node: &str) -> Vec<String> {
    let verb = if name == "stake" { "bond" } else { "unbond" };
    [
        verb,
        "--role",
        role,
        "--amount",
        &format!("{amount}wei"),
        "--node-account",
        "--rpc",
        node,
    ]
    .map(str::to_string)
    .to_vec()
}

fn confirmed(name: &str, params: &Value) -> Result<(), Value> {
    if params.get("confirm").and_then(Value::as_str) == Some(name) {
        Ok(())
    } else {
        Err(error(
            REFUSED,
            &format!(
                "This changes the node's standing on the network: send it again with confirm set to \"{name}\""
            ),
        ))
    }
}

fn text<'a>(params: &'a Value, field: &str) -> Result<&'a str, Value> {
    params
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| error(INVALID_PARAMS, &format!("{field} is needed")))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{helper, machine};
    use super::*;
    use crate::rpc::nonce_and_chain_id_tests::node_answering;

    async fn ask(helper: &Helper, method: &str, params: Value) -> Value {
        let line = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let answer = helper.answer(line.to_string().as_bytes()).await.unwrap();
        serde_json::from_str(&answer).unwrap()
    }

    #[test]
    fn a_stake_is_signed_by_the_terminals_own_command_as_the_node_account() {
        let args = stake_args("stake", "ai", "5000", "http://127.0.0.1:8545");
        assert_eq!(
            args.join(" "),
            "bond --role ai --amount 5000wei --node-account --rpc http://127.0.0.1:8545"
        );
        let cmd = StakeBondCmd::try_parse_from(&args);
        assert!(cmd.is_ok(), "{:?}", cmd.err());
        let args = stake_args("unstake", "ai", "5000", "http://127.0.0.1:8545");
        assert!(args[0] == "unbond" && StakeUnbondCmd::try_parse_from(&args).is_ok());
    }

    #[tokio::test]
    async fn nothing_is_signed_or_set_unless_confirmed_by_name() {
        let helper = helper("http://127.0.0.1:1", machine());
        for (method, params) in [
            ("control_stake", json!({ "role": "ai", "amount": "1" })),
            (
                "control_stake",
                json!({ "role": "ai", "amount": "1", "confirm": "unstake" }),
            ),
            (
                "control_unstake",
                json!({ "role": "ai", "amount": "1", "confirm": "stake" }),
            ),
            ("control_setRole", json!({ "role": "ai", "confirm": true })),
        ] {
            let answer = ask(&helper, method, params.clone()).await;
            assert_eq!(answer["error"]["code"], REFUSED, "{method} {params}");
            assert!(
                answer["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("This changes the node's standing on the network"),
                "{answer}"
            );
        }
        for params in [
            json!({ "role": "ai", "amount": "1.5", "confirm": "stake" }),
            json!({ "role": "ai", "amount": "", "confirm": "stake" }),
            json!({ "amount": "1", "confirm": "stake" }),
        ] {
            let answer = ask(&helper, "control_stake", params.clone()).await;
            assert_eq!(answer["error"]["code"], INVALID_PARAMS, "{params}");
        }
    }

    #[tokio::test]
    async fn a_role_is_set_through_the_node_and_its_refusal_comes_back() {
        let node = node_answering(&[("tenzro_setRole", r#"{"roles":["ai"]}"#)]).await;
        let answer = ask(
            &helper(&node, machine()),
            "control_setRole",
            json!({ "role": "ai", "confirm": "setRole" }),
        )
        .await;
        assert_eq!(
            answer["result"],
            json!({ "condition_id": null, "ceremony": null })
        );
        let silent = ask(
            &helper("http://127.0.0.1:1", machine()),
            "control_setRole",
            json!({ "role": "ai", "confirm": "setRole" }),
        )
        .await;
        assert_eq!(silent["error"]["code"], REFUSED);
    }
}
