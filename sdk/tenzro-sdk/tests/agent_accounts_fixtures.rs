//! The shared vectors (`sdk/fixtures/remote_grant`): every account this SDK
//! derives is the one Tenzro derives, and the digests match.

use tenzro_sdk::agent_accounts::{
    AccountDeployment, act_digest, grant_tree_key, omni_address, salt,
};

const VECTORS: &str = include_str!("../../fixtures/remote_grant/vectors.json");

#[test]
fn every_account_and_digest_matches_the_vectors() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let did = v["did"].as_str().unwrap();
    for c in v["chains"].as_array().unwrap() {
        let caip2 = c["chain"].as_str().unwrap();
        let deployment: AccountDeployment =
            serde_json::from_value(c["deployment"].clone()).unwrap();
        let a = omni_address(did, caip2, &deployment).unwrap();
        assert_eq!(a.address, c["account"].as_str().unwrap(), "{caip2}");
        assert_eq!(
            hex::encode(&a.raw),
            c["account_raw"].as_str().unwrap(),
            "{caip2}"
        );
        assert_eq!(a.caip10(), c["caip10"].as_str().unwrap(), "{caip2}");
        assert_eq!(
            a.to_erc7930().map(hex::encode),
            c["erc7930"].as_str().map(str::to_string),
            "{caip2}"
        );
        assert_eq!(hex::encode(salt(did)), c["salt"].as_str().unwrap());
        assert_eq!(
            hex::encode(grant_tree_key(did, caip2)),
            c["tree_key"].as_str().unwrap()
        );
        let word: [u8; 32] = hex::decode(c["account_word"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let action = hex::decode(c["action"]["encoded"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex::encode(act_digest(caip2, &word, 1, 0, &action)),
            c["action_digest"].as_str().unwrap()
        );
    }
}

#[test]
fn a_deployment_of_another_family_is_refused() {
    let d = AccountDeployment::Solana {
        program_id: [7; 32],
    };
    assert!(omni_address("did:x", "eip155:1", &d).is_err());
}

#[test]
fn a_channel_voucher_digest_and_pay_data_match_the_account_layout() {
    let mut account = [0u8; 32];
    account[12..].copy_from_slice(&[0x11; 20]);
    assert_eq!(
        hex::encode(tenzro_sdk::agent_accounts::channel_voucher_digest(
            "eip155:8453",
            &account,
            7,
            1000
        )),
        "046c669c72b5951a78639fc0849f070e8a5c2a8d0ddc0760d631aac95a2523d9"
    );
    let d = tenzro_sdk::agent_accounts::pay_data(&[1; 32], &[2; 32], &[3; 32], 30);
    assert_eq!(hex::encode(&d[96..]), "000000000000001e");
}
