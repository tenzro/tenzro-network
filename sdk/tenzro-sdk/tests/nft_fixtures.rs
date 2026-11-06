//! The NFT factory vectors under `sdk/fixtures/nft`, which the VM test runs
//! through the precompile and the TypeScript and Python SDKs check too.

use serde_json::Value;
use std::path::PathBuf;
use tenzro_sdk::nft::{self, NftStandard};

fn vectors() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/nft/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn b(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    hex::decode(s.trim_start_matches("0x")).unwrap()
}
fn a20(v: &Value) -> [u8; 20] {
    b(v).try_into().unwrap()
}
fn a32(v: &Value) -> [u8; 32] {
    b(v).try_into().unwrap()
}
fn n(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

#[test]
fn calldata_returns_and_logs_match_the_vectors() {
    let v = vectors();
    assert_eq!(b(&v["factory"]), nft::NFT_FACTORY_ADDRESS.to_vec());
    assert_eq!(b(&v["transfer_topic"]), nft::nft_transfer_topic().to_vec());
    for c in v["collection_ids"].as_array().unwrap() {
        let id = nft::nft_collection_id(&a20(&c["creator"]), c["nonce"].as_u64().unwrap());
        assert_eq!(id.to_vec(), b(&c["id"]));
    }
    for s in v["steps"].as_array().unwrap() {
        let a = s["args"].as_array().unwrap();
        let call = s["call"].as_str().unwrap();
        let got = match call {
            "createCollection" => {
                let std = if a[2] == "erc721" {
                    NftStandard::Erc721
                } else {
                    NftStandard::Erc1155
                };
                nft::create_collection(a[0].as_str().unwrap(), a[1].as_str().unwrap(), std).unwrap()
            }
            "mint" => {
                nft::mint(&a32(&a[0]), &a20(&a[1]), n(&a[2]), a[3].as_str().unwrap()).unwrap()
            }
            "mintBatch" => {
                let tokens: Vec<u128> = a[2].as_array().unwrap().iter().map(n).collect();
                let uris: Vec<&str> = a[3]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|u| u.as_str().unwrap())
                    .collect();
                nft::mint_batch(&a32(&a[0]), &a20(&a[1]), &tokens, &uris).unwrap()
            }
            "transfer" => nft::transfer(&a32(&a[0]), &a20(&a[1]), n(&a[2])).unwrap(),
            "ownerOf" => nft::owner_of(&a32(&a[0]), n(&a[1])),
            "balanceOf" => nft::balance_of(&a32(&a[0]), &a20(&a[1])),
            "tokenUri" => nft::token_uri(&a32(&a[0]), n(&a[1])),
            "getCollection" => nft::get_collection(&a32(&a[0])),
            "registerEvmPointer" => nft::register_evm_pointer(&a32(&a[0]), &a20(&a[1])),
            "mintMulti" => nft::mint_multi(&a32(&a[0]), &a20(&a[1]), n(&a[2]), n(&a[3])).unwrap(),
            "balanceOfMulti" => nft::balance_of_multi(&a32(&a[0]), &a20(&a[1]), n(&a[2])),
            other => panic!("no builder for {other}"),
        };
        assert_eq!(
            hex::encode(&got),
            hex::encode(b(&s["calldata"])),
            "{call} {a:?}"
        );
        if s["output"].is_null() || s.get("decoded").is_none() {
            continue;
        }
        let out = b(&s["output"]);
        let d = &s["decoded"];
        match call {
            "createCollection" => assert_eq!(out, b(d)),
            "mint" | "transfer" | "registerEvmPointer" | "mintMulti" => {
                assert_eq!(nft::decode_bool(&out).unwrap(), d.as_bool().unwrap())
            }
            "mintBatch" | "balanceOf" | "balanceOfMulti" => {
                assert_eq!(nft::decode_uint(&out).unwrap(), n(d))
            }
            "ownerOf" => assert_eq!(nft::decode_address(&out).unwrap(), a20(d)),
            "tokenUri" => assert_eq!(nft::decode_string(&out).unwrap(), d.as_str().unwrap()),
            "getCollection" => {
                let c = nft::decode_collection(&out).unwrap();
                assert_eq!(c.name, d["name"].as_str().unwrap());
                assert_eq!(c.symbol, d["symbol"].as_str().unwrap());
                assert_eq!(c.creator, a20(&d["creator"]));
                assert_eq!(c.total_supply, n(&d["totalSupply"]));
                let std = if d["standard"] == "erc721" {
                    NftStandard::Erc721
                } else {
                    NftStandard::Erc1155
                };
                assert_eq!(c.standard, std);
            }
            _ => unreachable!(),
        }
        for log in s["logs"].as_array().into_iter().flatten() {
            let topics: Vec<[u8; 32]> = log["topics"].as_array().unwrap().iter().map(a32).collect();
            let t = nft::decode_nft_transfer(&topics, &b(&log["data"])).unwrap();
            assert_eq!(t.collection, topics[1]);
        }
    }
    let id1 = a32(&v["collection_ids"][0]["id"]);
    let id2 = a32(&v["collection_ids"][1]["id"]);
    let bob = a20(&v["accounts"]["bob"]);
    assert_eq!(
        nft::mint_random(&id1, &bob, 100).unwrap(),
        b(&v["random"]["mint_random"])
    );
    assert_eq!(
        nft::fulfill_random(&[0xee; 32]),
        b(&v["random"]["fulfill_random"])
    );
    assert_eq!(
        nft::register_svm_pointer(&id2, &[0x5a; 32]),
        b(&v["random"]["register_svm_pointer"])
    );
}

#[test]
fn inputs_the_factory_would_refuse_are_refused_before_signing() {
    let id = [1u8; 32];
    assert!(nft::mint(&id, &[0u8; 20], 1, "").is_err());
    assert!(nft::mint(&id, &[2u8; 20], 1, &"x".repeat(513)).is_err());
    assert!(nft::mint_batch(&id, &[2u8; 20], &[], &[]).is_err());
    assert!(nft::create_collection("", "X", NftStandard::Erc721).is_err());
    assert!(nft::mint_multi(&id, &[2u8; 20], 1, 0).is_err());
    let fields = nft::nft_contract_call(&[nft::owner_of(&id, 1)]);
    assert_eq!(fields["calls"][0]["vm"], "evm");
    assert_eq!(fields["calls"][0]["to"].as_array().unwrap().len(), 20);
}
