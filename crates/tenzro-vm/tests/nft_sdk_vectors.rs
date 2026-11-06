//! The SDKs' NFT vectors (`sdk/fixtures/nft/vectors.json`) run through the NFT
//! factory precompile: every calldata the SDKs build executes as the vectors
//! say, returns the bytes the SDKs decode, and emits the transfer logs they
//! read. Writes go through `execute_transaction`, reads through `call`.

use serde_json::Value;
use tenzro_vm::precompiles::PRECOMPILE_NFT_FACTORY;
use tenzro_vm::traits::VmState;
use tenzro_vm::{ContractCall, MultiVmRuntime, StateAdapter, VmConfig, VmTransaction, VmType};

const CHAIN: u64 = 1337;
const GAS_PRICE: u128 = 1_000_000_000;
const GAS_LIMIT: u64 = 3_000_000;
const TEN_TNZO: u128 = 10_000_000_000_000_000_000;
const BLOCK: u64 = 100;
const BLOCK_MS: i64 = 1_700_000_000_000;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sdk/fixtures/nft/vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("NFT vectors"))
        .expect("NFT vectors JSON")
}

fn bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex")
}

fn account(v: &Value, name: &str) -> [u8; 20] {
    let b = bytes(&v["accounts"][name]);
    b.try_into().expect("20-byte account")
}

#[tokio::test]
async fn sdk_nft_vectors_run_as_the_factory_executes_them() {
    let v = vectors();
    assert_eq!(bytes(&v["factory"]), PRECOMPILE_NFT_FACTORY.to_vec());
    let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let mut state = StateAdapter::new();
    for name in ["alice", "bob"] {
        state.set_balance(&account(&v, name), TEN_TNZO);
    }
    let steps = v["steps"].as_array().expect("steps");
    assert!(!steps.is_empty());
    for (i, s) in steps.iter().enumerate() {
        let what = format!("step {i} {} {}", s["call"], s["args"]);
        let from = account(&v, s["from"].as_str().unwrap());
        let data = bytes(&s["calldata"]);
        let r = if s["kind"] == "read" {
            let call = ContractCall::new(
                from.to_vec(),
                PRECOMPILE_NFT_FACTORY.to_vec(),
                data,
                0,
                GAS_LIMIT,
                VmType::Evm,
            );
            let r = rt.call(&call, &state).await.unwrap();
            (r.success, r.output, r.revert_reason, Vec::new())
        } else {
            let nonce = state.get_nonce(&from);
            let tx = VmTransaction::new(
                from.to_vec(),
                Some(PRECOMPILE_NFT_FACTORY.to_vec()),
                0,
                data,
                GAS_LIMIT,
                GAS_PRICE,
                nonce,
                VmType::Evm,
                CHAIN,
            )
            .with_block_height(BLOCK)
            .with_block_timestamp_ms(BLOCK_MS);
            let r = rt.execute_transaction(&tx, &mut state).await.unwrap();
            (r.success, r.output, r.revert_reason, r.logs)
        };
        let (success, output, revert_reason, logs) = r;
        assert_eq!(
            success,
            s["success"].as_bool().unwrap(),
            "{what}: {revert_reason:?}"
        );
        if !success {
            continue;
        }
        assert_eq!(
            hex::encode(&output),
            hex::encode(bytes(&s["output"])),
            "{what}: output"
        );
        if s["kind"] == "send" {
            let want: Vec<(Vec<Vec<u8>>, Vec<u8>)> = s["logs"]
                .as_array()
                .map(|logs| {
                    logs.iter()
                        .map(|l| {
                            let topics =
                                l["topics"].as_array().unwrap().iter().map(bytes).collect();
                            (topics, bytes(&l["data"]))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let got: Vec<(Vec<Vec<u8>>, Vec<u8>)> = logs
                .iter()
                .filter(|l| l.address == PRECOMPILE_NFT_FACTORY.to_vec())
                .map(|l| (l.topics.clone(), l.data.clone()))
                .collect();
            assert_eq!(got, want, "{what}: logs");
        }
    }
}

#[test]
fn sdk_nft_selectors_and_collection_ids_are_the_factorys() {
    use tenzro_vm::evm::nft_factory::{compute_collection_id, selectors};
    let v = vectors();
    let s = &v["selectors"];
    for (name, sel) in [
        ("createCollection", selectors::CREATE_COLLECTION),
        ("getCollection", selectors::GET_COLLECTION),
        ("mint", selectors::MINT),
        ("mintBatch", selectors::MINT_BATCH),
        ("transferNft", selectors::TRANSFER_NFT),
        ("ownerOf", selectors::OWNER_OF),
        ("balanceOf", selectors::BALANCE_OF),
        ("tokenUri", selectors::TOKEN_URI),
        ("registerEvmPointer", selectors::REGISTER_EVM_POINTER),
        ("registerSvmPointer", selectors::REGISTER_SVM_POINTER),
        ("mintMulti", selectors::MINT_MULTI),
        ("balanceOfMulti", selectors::BALANCE_OF_MULTI),
        ("mintRandom", selectors::MINT_RANDOM),
        ("fulfillRandom", selectors::FULFILL_RANDOM),
    ] {
        assert_eq!(bytes(&s[name]), sel.to_vec(), "{name}");
    }
    assert_eq!(s.as_object().unwrap().len(), 14);
    for c in v["collection_ids"].as_array().unwrap() {
        let creator: [u8; 20] = bytes(&c["creator"]).try_into().unwrap();
        let id = compute_collection_id(&creator, c["nonce"].as_u64().unwrap());
        assert_eq!(id.to_vec(), bytes(&c["id"]));
    }
}
