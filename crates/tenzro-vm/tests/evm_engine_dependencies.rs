//! Two EVM engines are linked side by side, and each names the `c-kzg`
//! library as an optional dependency at a different major version. Cargo
//! allows one package with `links = "ckzg"` in a dependency graph, so the
//! workspace replaces the Osaka engine's `c-kzg` 2 with a placeholder that
//! cannot be compiled (`vendor/c-kzg-unlinked`). That engine verifies KZG
//! proofs with its BLS12-381 backend instead.
//!
//! This holds the arrangement in place: the Osaka engine's `c-kzg` feature
//! is off, its `c-kzg` is the placeholder, and the placeholder never stands
//! in for the `c-kzg` 1 of the first engine.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn metadata() -> Value {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("cargo metadata prints JSON")
}

fn packages<'a>(metadata: &'a Value, name: &str) -> Vec<&'a Value> {
    metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter(|p| p["name"] == name)
        .collect()
}

fn major(package: &Value) -> &str {
    let version = package["version"].as_str().expect("a version");
    version.split('.').next().expect("a major version")
}

#[test]
fn the_osaka_engine_is_built_without_its_c_kzg_feature() {
    let metadata = metadata();
    let engine = packages(&metadata, "revm-precompile")
        .into_iter()
        .find(|p| major(p) == "43")
        .expect("the Osaka engine's precompiles are in the graph");
    let node = metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve nodes")
        .iter()
        .find(|n| n["id"] == engine["id"])
        .expect("the engine's resolve node");
    let features: Vec<&str> = node["features"]
        .as_array()
        .expect("features")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        !features.contains(&"c-kzg"),
        "the Osaka engine's `c-kzg` feature is on ({features:?}): its c-kzg is a placeholder \
         that cannot be compiled"
    );
    assert!(
        features.contains(&"blst"),
        "the Osaka engine verifies KZG proofs with blst: {features:?}"
    );
}

#[test]
fn the_placeholder_stands_in_for_c_kzg_2_alone() {
    let metadata = metadata();
    let all = packages(&metadata, "c-kzg");
    let two: Vec<&&Value> = all.iter().filter(|p| major(p) == "2").collect();
    assert_eq!(two.len(), 1, "one c-kzg 2 in the graph");
    assert!(
        two[0]["source"].is_null(),
        "c-kzg 2 is the workspace placeholder, not the registry crate"
    );
    assert!(
        two[0]["links"].is_null(),
        "the placeholder links no native library"
    );
    for package in all.iter().filter(|p| major(p) != "2") {
        assert!(
            package["source"]
                .as_str()
                .is_some_and(|s| s.starts_with("registry+")),
            "c-kzg {} comes from the registry: the placeholder never replaces it",
            package["version"]
        );
    }
}
