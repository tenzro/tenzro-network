//! Following a node: which methods to call, in which order, with every reply
//! checked.
//!
//! The transport is the caller's: [`Node`] is one JSON-RPC call. Nothing a
//! node answers is kept unless the light client verified it.

use serde_json::{Value, json};
use tenzro_finality::checkpoint::Checkpoint;

use crate::client::{Clock, LightClient};
use crate::error::{LightError, Result, malformed};
use crate::rpc;

/// A node's JSON-RPC, as the caller reaches it.
pub trait Node {
    /// Calls `method` with `params` and returns the reply's `result`, or why
    /// the call failed.
    fn call(&mut self, method: &str, params: Value) -> std::result::Result<Value, String>;
}

fn call(node: &mut impl Node, method: &'static str, params: Value) -> Result<Value> {
    node.call(method, params)
        .map_err(|why| LightError::Node { method, why })
}

/// Brings `client` to the node's newest certified checkpoint: one handover
/// per epoch between the client's committee and the checkpoint's, then the
/// checkpoint's certificate. Returns the checkpoint, which must be within
/// `clock`'s bounds: a node that serves an old checkpoint as its newest is
/// refused even when the client holds nothing newer to compare it with. The
/// client keeps what it verified either way, so after a failed sync
/// [`LightClient::latest`] may be outside `clock`'s bounds: a handover keeps
/// the epoch's last checkpoint however old it is.
pub fn sync(client: &mut LightClient, node: &mut impl Node, clock: &Clock) -> Result<Checkpoint> {
    let newest = call(node, "tenzro_getCheckpointCertificate", json!({}))?;
    let epoch = newest
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("certificate reply", "no 'epoch'"))?;
    while client.epoch() < epoch {
        let handover = call(
            node,
            "tenzro_getEpochHandover",
            json!({ "epoch": client.epoch() }),
        )?;
        rpc::hand_over(client, &handover)?;
    }
    rpc::advance(client, &newest, clock)
}

/// Reads the entry (`namespace`, `key`) from the state `checkpoint`
/// certifies and checks the node's proof. `None` is a proven absence. The
/// checkpoint must still be within `clock`'s bounds, so a value is never
/// read from a state the caller would no longer accept as current.
pub fn state_value(
    node: &mut impl Node,
    checkpoint: &Checkpoint,
    clock: &Clock,
    namespace: &str,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    clock.check(checkpoint)?;
    let reply = call(
        node,
        "tenzro_getStateProof",
        json!({
            "namespace": namespace,
            "key": hex::encode(key),
            "height": checkpoint.state_height,
        }),
    )?;
    rpc::state_value(checkpoint, namespace, key, &reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::Net;

    /// A clock shortly after the newest checkpoint [`TwoEpochs`] serves.
    fn clock(node: &TwoEpochs) -> Clock {
        Net::clock_after(&node.second.checkpoint(6))
    }

    fn hex_bincode<T: serde::Serialize>(v: &T) -> Value {
        Value::String(format!("0x{}", hex::encode(bincode::serialize(v).unwrap())))
    }

    /// A node serving two epochs: epoch 0 ends at checkpoint 3, the newest
    /// checkpoint is 6 in epoch 1.
    struct TwoEpochs {
        first: Net,
        second: Net,
        /// Serve the newest checkpoint of epoch 0 as the newest of all.
        withhold_second_epoch: bool,
        calls: Vec<String>,
    }

    impl TwoEpochs {
        fn new() -> Self {
            let first = Net::new(4);
            let second = first.next_epoch(4);
            Self {
                first,
                second,
                withhold_second_epoch: false,
                calls: Vec::new(),
            }
        }

        fn certificate_reply(net: &Net, index: u64, ends_into: Option<&Net>) -> Value {
            let mut cp = net.checkpoint(index);
            cp.next_committee_root = ends_into.map(|n| n.committee().root());
            let (cert, sessions) = net.certify(&cp, &[0, 1, 2]);
            let mut reply = json!({
                "epoch": net.epoch,
                "certificate": hex_bincode(&cert),
                "sessions": hex_bincode(&sessions),
            });
            if let Some(next) = ends_into {
                reply["next_members"] = hex_bincode(&next.members);
            }
            reply
        }
    }

    impl Node for TwoEpochs {
        fn call(&mut self, method: &str, params: Value) -> std::result::Result<Value, String> {
            self.calls.push(method.to_string());
            match method {
                "tenzro_getCheckpointCertificate" if self.withhold_second_epoch => {
                    Ok(Self::certificate_reply(&self.first, 2, None))
                }
                "tenzro_getCheckpointCertificate" => {
                    Ok(Self::certificate_reply(&self.second, 6, None))
                }
                "tenzro_getEpochHandover" if params["epoch"] == 0 => {
                    Ok(Self::certificate_reply(&self.first, 3, Some(&self.second)))
                }
                other => Err(format!("unexpected call {other} {params}")),
            }
        }
    }

    #[test]
    fn sync_walks_the_handovers_and_lands_on_the_newest_checkpoint() {
        let mut node = TwoEpochs::new();
        let mut lc = node.first.client();
        let clock = clock(&node);
        let cp = sync(&mut lc, &mut node, &clock).unwrap();
        assert_eq!((cp.epoch, cp.index), (1, 6));
        assert_eq!(lc.epoch(), 1);
        assert_eq!(
            node.calls,
            ["tenzro_getCheckpointCertificate", "tenzro_getEpochHandover"]
        );
    }

    #[test]
    fn a_node_that_serves_an_older_checkpoint_after_a_newer_one_is_caught() {
        let mut node = TwoEpochs::new();
        let mut lc = node.first.client();
        let clock = clock(&node);
        sync(&mut lc, &mut node, &clock).unwrap();
        node.withhold_second_epoch = true;
        assert!(sync(&mut lc, &mut node, &clock).is_err());
        assert_eq!(lc.latest().unwrap().index, 6);
    }

    #[test]
    fn a_fresh_client_refuses_an_old_checkpoint_served_as_the_newest() {
        let mut node = TwoEpochs::new();
        node.withhold_second_epoch = true;
        let served = node.first.checkpoint(2);
        // Nothing held to compare with: only the clock tells old from new.
        let mut lc = node.first.client();
        let late = Clock {
            now_ms: served.timestamp_ms + 3_600_000,
            max_age_ms: 60_000,
            max_ahead_ms: 5_000,
        };
        assert!(matches!(
            sync(&mut lc, &mut node, &late),
            Err(LightError::TooOld { .. })
        ));
        // Refused before it was kept: nothing stale is saved.
        assert_eq!(lc.latest(), None);
        let mut lc = node.first.client();
        let early = Clock {
            now_ms: served.timestamp_ms - 3_600_000,
            ..late
        };
        assert!(matches!(
            sync(&mut lc, &mut node, &early),
            Err(LightError::AheadOfClock { .. })
        ));
        let mut lc = node.first.client();
        sync(&mut lc, &mut node, &Net::clock_after(&served)).unwrap();
    }

    #[test]
    fn a_value_is_not_read_from_a_checkpoint_that_has_gone_stale() {
        struct Unreached;
        impl Node for Unreached {
            fn call(&mut self, method: &str, _: Value) -> std::result::Result<Value, String> {
                panic!("{method} called for a checkpoint outside the clock's bounds")
            }
        }
        let cp = Net::new(4).checkpoint(2);
        let late = Clock {
            now_ms: cp.timestamp_ms + 3_600_000,
            max_age_ms: 60_000,
            max_ahead_ms: 5_000,
        };
        assert!(matches!(
            state_value(&mut Unreached, &cp, &late, "state", b"k"),
            Err(LightError::TooOld { .. })
        ));
    }

    #[test]
    fn a_failed_call_is_reported_with_its_method() {
        struct Down;
        impl Node for Down {
            fn call(&mut self, _: &str, _: Value) -> std::result::Result<Value, String> {
                Err("connection refused".into())
            }
        }
        let mut lc = Net::new(4).client();
        assert!(matches!(
            sync(
                &mut lc,
                &mut Down,
                &Net::clock_after(&Net::new(4).checkpoint(1))
            ),
            Err(LightError::Node {
                method: "tenzro_getCheckpointCertificate",
                ..
            })
        ));
    }
}
