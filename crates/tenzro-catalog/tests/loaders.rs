//! Every registry entry resolves to something that loads it on this release.
//!
//! A GGUF, reranker, embedder or speech entry must name a model architecture
//! the Praecise engine has a loader for, a media entry is either native
//! (pinned to an engine revision) or planned (refused at serve time), and an
//! ONNX entry runs on the node's ONNX runtime. An entry nothing loads is
//! refused here, with the reason, before it reaches a node. Whether the
//! engine really loads each architecture is the scheduled loader stage's job
//! (`scripts/testnet/stages.sh`, stage `model-loaders`).

use tenzro_catalog::{Loader, read_entries};

#[test]
fn every_registry_entry_has_a_loader() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seed");
    let entries = read_entries(&dir).expect("the seed parses");
    assert!(!entries.is_empty());
    let missing: Vec<String> = entries
        .iter()
        .filter_map(|e| match e.model.loader() {
            Loader::Missing(why) => Some(format!("{}: {why}", e.id())),
            Loader::Engine([]) => Some(format!("{}: no engine architecture named", e.id())),
            _ => None,
        })
        .collect();
    assert!(
        missing.is_empty(),
        "{} registry entr{} with no loader:\n{}",
        missing.len(),
        if missing.len() == 1 { "y" } else { "ies" },
        missing.join("\n")
    );
}
