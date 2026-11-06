//! Writes `CLUSTER_GENESIS`, the genesis hash of the one Solana cluster
//! this build accepts approvals for. Mainnet-beta by default;
//! `TENZRO_SVM_CLUSTER_GENESIS` (64 hex characters) names another.

const MAINNET_BETA: &str = "45296998a6f8e2a784db5d9f95e18fc23f70441a1039446801089879b08c7ef0";

fn main() {
    println!("cargo:rerun-if-env-changed=TENZRO_SVM_CLUSTER_GENESIS");
    let hex = std::env::var("TENZRO_SVM_CLUSTER_GENESIS")
        .unwrap_or_else(|_| MAINNET_BETA.to_string());
    assert!(
        hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "TENZRO_SVM_CLUSTER_GENESIS must be 64 hex characters"
    );
    let bytes: Vec<String> = (0..32)
        .map(|i| format!("0x{}", &hex[2 * i..2 * i + 2]))
        .collect();
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("cluster.rs");
    std::fs::write(
        out,
        format!(
            "/// Genesis hash of the cluster this build accepts approvals for.\n\
             pub const CLUSTER_GENESIS: [u8; 32] = [{}];\n",
            bytes.join(", ")
        ),
    )
    .unwrap();
}
