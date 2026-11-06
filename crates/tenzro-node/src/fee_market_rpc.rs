//! `tenzro_getFeeMarket {}`: the base fee of every resource market the next
//! block charges, from consensus state (see `tenzro_vm::ledger`): compute
//! gas, state growth, bandwidth and proof verification, each in atto-USD per
//! unit and in TNZO base units at the rate in force, with its per-block
//! target.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_vm::ledger::{Resource, block_base_fee, block_base_fee_usd, resource_base_fee_usd};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// `tenzro_getFeeMarket`.
pub(crate) async fn handle_get_fee_market(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let chain = crate::rpc::chain_state(node)?;
    let mut markets = serde_json::Map::new();
    markets.insert(
        "compute".into(),
        json!({
            "base_fee_usd": block_base_fee_usd(&chain).to_string(),
            "base_fee": block_base_fee(&chain).to_string(),
            "target_per_block": tenzro_vm::ledger::fee_market_config(&chain).target_gas_per_block,
        }),
    );
    for r in Resource::ALL {
        let usd = resource_base_fee_usd(&chain, r);
        markets.insert(
            r.name().into(),
            json!({
                "base_fee_usd": usd.to_string(),
                "base_fee": tenzro_vm::native::usd_to_wei(&chain, usd).to_string(),
                "target_per_block": tenzro_vm::native::network_param(&chain, r.target_param()),
            }),
        );
    }
    Ok(Value::Object(markets))
}
