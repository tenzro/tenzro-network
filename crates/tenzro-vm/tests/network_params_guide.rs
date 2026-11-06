//! docs/GOVERNANCE_PARAMS.md lists every governed network parameter with its
//! genesis value, bounds and tightening direction, generated from the
//! registry. Regenerate with `UPDATE_DOCS=1 cargo test -p tenzro-vm --test
//! network_params_guide`.

use std::path::Path;

use tenzro_vm::governance::{GOVERNED_PARAMS, Tighten};

const BEGIN: &str = "<!-- BEGIN GENERATED PARAMETERS -->";
const END: &str = "<!-- END GENERATED PARAMETERS -->";

fn rendered() -> String {
    let mut params: Vec<_> = GOVERNED_PARAMS.iter().collect();
    params.sort_by_key(|p| p.key);
    let mut out = String::from(
        "| Key | Genesis | Min | Max | Tightens | What it does |\n|---|---|---|---|---|---|\n",
    );
    for p in params {
        let tightens = match p.tighten {
            Tighten::Up => "up",
            Tighten::Down => "down",
            Tighten::Neither => "neither",
            Tighten::Retire => "retire",
        };
        let what = p
            .description
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace('|', "/");
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            p.key, p.genesis, p.min, p.max, tightens, what
        ));
    }
    out
}

#[test]
fn the_parameter_guide_lists_every_parameter() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/GOVERNANCE_PARAMS.md");
    let doc = std::fs::read_to_string(&path).expect("docs/GOVERNANCE_PARAMS.md");
    let start = doc.find(BEGIN).expect("generated block start");
    let end = doc.find(END).expect("generated block end");
    let block = format!("{BEGIN}\n{}{END}", rendered());
    let current = &doc[start..end + END.len()];
    if std::env::var_os("UPDATE_DOCS").is_some() {
        std::fs::write(&path, doc.replace(current, &block)).expect("write guide");
        return;
    }
    assert_eq!(
        current, block,
        "docs/GOVERNANCE_PARAMS.md is stale; regenerate with UPDATE_DOCS=1"
    );
}
