//! Fuzzes settlement-plan operations and the split engine:
//! - any `PlanOp` that decodes (JSON or bincode) validates without panic,
//!   and one that validates re-encodes to the same value;
//! - any split rule that validates divides any gross exactly: the parts
//!   sum to the gross, and the result is the same twice.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_types::settlement::PlanOp;
use tenzro_types::split::{FeeParams, apply};

fuzz_target!(|input: (&[u8], u128, u16, u16, u16, u128)| {
    let (data, gross, fee_bps, burn_bps, insurance_bps, network_fees) = input;

    for op in [
        serde_json::from_slice::<PlanOp>(data).ok(),
        bincode::deserialize::<PlanOp>(data).ok(),
    ]
    .into_iter()
    .flatten()
    {
        if op.validate().is_ok() {
            let again: PlanOp = bincode::deserialize(&bincode::serialize(&op).unwrap()).unwrap();
            assert_eq!(again, op);
            if let PlanOp::Open { split, .. } = &op {
                let params = FeeParams { fee_bps, min_fee: 0, burn_bps, insurance_bps };
                if let Ok(a) = apply(gross, split, &params, network_fees) {
                    assert!(a.conserves());
                    assert_eq!(apply(gross, split, &params, network_fees).unwrap(), a);
                }
            }
        }
    }
});
