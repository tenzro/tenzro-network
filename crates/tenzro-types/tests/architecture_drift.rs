//! Architecture drift check: one mechanism per concern, and value moves only
//! inside consensus.
//!
//! Two scans over the workspace source (test modules excluded):
//!
//! - Mechanisms. Every definition that implements a listed concern (slash
//!   paths, reputation stores, rate oracles, balance stores, bond ledgers,
//!   markets, disputes, event logs, routers, policy engines, access policies)
//!   must appear in `MECHANISMS`, tagged OWNER (the one mechanism) or with the open gap that
//!   folds it away. A new definition fails the check: extend the owner instead.
//! - Consensus deny-list. Node code (`crates/tenzro-node/src`) must not move
//!   value: no call to a writer of a value read model listed in `GUARDED`
//!   (bonds are chain state only; `TnzoToken` has no writer) and no
//!   `CF_TOKENS`/`CF_METADATA` write. A writer is any `pub fn` of the type taking `&self` and returning
//!   `Result`, read from the type's own impl; a call is matched by the type of
//!   its receiver (a binding, field or parameter of that type, or an accessor
//!   returning it), whatever the variable is called. Today's sites are listed
//!   in `NODE_WRITES` with their count and tag; a count above the list fails,
//!   and so does one below it, so the list shrinks as each gap closes.
//!
//! Tags: `OWNER` is the concern's one mechanism; `REPLAY` maintains a read
//! model from consensus logs; `FLAG` hands a proven fault to the consensus
//! finding that slashes; `READ` is a seam whose only implementation reads the
//! owner; `LOCAL` is node-local cache, index or operator metadata that holds
//! no value and no authority over anything but the machine itself;
//! `GENESIS` is state before block 0. No other tag is accepted.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// (concern, file, item, tag)
const MECHANISMS: &[(&str, &str, &str, &str)] = &[
    (
        "access",
        "crates/tenzro-model/src/access.rs",
        "AccessPolicy",
        "READ",
    ),
    (
        "access",
        "crates/tenzro-node/src/access.rs",
        "AccessPolicyStore",
        "OWNER: NodeAccessPolicy",
    ),
    (
        "access",
        "crates/tenzro-types/src/access_policy.rs",
        "AccessPolicy",
        "OWNER: a resource owner's grant, applied after the node policy",
    ),
    (
        "access",
        "crates/tenzro-types/src/node_access.rs",
        "NodeAccessPolicy",
        "OWNER",
    ),
    (
        "balances",
        "crates/tenzro-token/src/registry.rs",
        "TokenRegistry",
        "REPLAY",
    ),
    (
        "balances",
        "crates/tenzro-token/src/tnzo.rs",
        "TnzoToken",
        "READ: the balance map block execution writes; no writer",
    ),
    (
        "disputes",
        "crates/tenzro-types/src/metering.rs",
        "MeterDispute",
        "OWNER",
    ),
    (
        "events",
        "crates/tenzro-events/src/bus.rs",
        "EventBus",
        "OWNER",
    ),
    (
        "events",
        "crates/tenzro-events/src/log.rs",
        "EventLog",
        "OWNER",
    ),
    (
        "routing",
        "crates/tenzro-model/src/routing.rs",
        "InferenceRouter",
        "OWNER",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/bridge_committee.rs",
        "slash_member",
        "OWNER: role_stake::take_role_stake",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/economy.rs",
        "slash_agent_bond",
        "OWNER",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/inference_fault.rs",
        "slash_compute_bond",
        "OWNER",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/inference_fault.rs",
        "slash_for_fault",
        "OWNER: slash_compute_bond",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/inference_fault.rs",
        "slash_publisher",
        "OWNER: slash_split",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/payment_settlement/recon.rs",
        "slash_committee",
        "OWNER: slash_to_insurance",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/staking.rs",
        "slash",
        "OWNER",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/staking.rs",
        "slash_for_equivocation",
        "OWNER",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/staking.rs",
        "slash_split",
        "OWNER: slash_to_insurance",
    ),
    (
        "slashing",
        "crates/tenzro-vm/src/native/staking.rs",
        "slash_to_insurance",
        "OWNER",
    ),
];

/// (file, kind, count, tag)
const NODE_WRITES: &[(&str, &str, usize, &str)] = &[
    (
        "crates/tenzro-node/src/agent_guardrails.rs",
        "cf",
        2,
        "LOCAL: the taint label of an agent that read outside content, kept across a restart so the hold window survives it; a node-side security mark, moves no value",
    ),
    (
        "crates/tenzro-node/src/attestation_log.rs",
        "cf",
        1,
        "LOCAL: this node's copy of the measurement transparency log; answers verification queries, moves no value",
    ),
    (
        "crates/tenzro-node/src/epoch_state_store.rs",
        "cf",
        1,
        "REPLAY: epochs the consensus engine closed, kept for block-sync verification",
    ),
    (
        "crates/tenzro-node/src/genesis.rs",
        "cf",
        5,
        "GENESIS: state before block 0",
    ),
    (
        "crates/tenzro-node/src/history_archive.rs",
        "cf",
        1,
        "LOCAL: pruning cursor and pointers to segments the DA layer holds",
    ),
    (
        "crates/tenzro-node/src/machine_access.rs",
        "cf",
        1,
        "LOCAL: the owner's passkey-signed grants over this machine's own network and folders; no spending authority",
    ),
    (
        "crates/tenzro-node/src/snapshot.rs",
        "cf",
        1,
        "LOCAL: index of published snapshot manifests, each checked against its state root",
    ),
    (
        "crates/tenzro-node/src/visibility_rpc.rs",
        "cf",
        1,
        "LOCAL: the operator's visibility setting",
    ),
];

/// Value read models in node code: (kind, file, type).
const GUARDED: &[(&str, &str, &str)] = &[];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn rust_files(dir: &Path, skip_test_dirs: bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target"
                || (skip_test_dirs && matches!(name, "tests" | "benches" | "examples"))
            {
                continue;
            }
            rust_files(&p, skip_test_dirs, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Source without its unit-test module and without line comments.
fn production_source(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut cut = text.len();
    for marker in [
        "#[cfg(test)]\nmod tests",
        "#[cfg(test)]\npub mod tests",
        "#[cfg(test)]\npub(crate) mod tests",
        "#[cfg(test)]\npub(super) mod tests",
    ] {
        if let Some(i) = text.find(marker) {
            cut = cut.min(i);
        }
    }
    text[..cut]
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn ident_after(s: &str) -> &str {
    let end = s
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    &s[..end]
}

fn concern_of(keyword: &str, name: &str) -> Option<&'static str> {
    let has = |subs: &[&str]| subs.iter().any(|s| name.contains(s));
    if keyword == "fn" {
        return name.starts_with("slash").then_some("slashing");
    }
    // Request parameters and typed tool outputs name a method and its result,
    // not a mechanism.
    if name.ends_with("Params") || name.ends_with("Output") {
        return None;
    }
    let ty = matches!(keyword, "struct" | "trait" | "enum");
    if !ty {
        return None;
    }
    if name.contains("Reputation")
        && ["Ledger", "Store", "Registry", "Resolver"]
            .iter()
            .any(|s| name.ends_with(s))
    {
        return Some("reputation");
    }
    if has(&["RateOracle", "PriceOracle", "FeeOracle", "PriceFeed"]) {
        return Some("oracle");
    }
    if matches!(name, "TokenRegistry" | "TnzoToken") || has(&["BalanceStore", "TokenLedger"]) {
        return Some("balances");
    }
    if keyword == "struct" && has(&["BondManager", "StakingManager", "BondLedger"]) {
        return Some("bonds");
    }
    if keyword == "struct"
        && has(&[
            "TaskMarket",
            "DealBook",
            "RentalMarket",
            "ComputeMarket",
            "Marketplace",
        ])
    {
        return Some("markets");
    }
    if keyword != "trait"
        && (name.ends_with("Dispute") || has(&["DisputeStore", "DisputeManager", "DisputeRecord"]))
    {
        return Some("disputes");
    }
    if keyword == "struct"
        && (matches!(name, "EventLog" | "EventBus")
            || name.starts_with("EventIndex")
            || name.starts_with("EventStore"))
    {
        return Some("events");
    }
    if keyword == "struct"
        && ["InferenceRouter", "PlacementScheduler", "ProviderSelector"]
            .iter()
            .any(|s| name.ends_with(s))
    {
        return Some("routing");
    }
    if has(&["SpendingPolicy", "ScopeOracle", "PolicyEngine"]) {
        return Some("policy");
    }
    if ty
        && (name.ends_with("AccessPolicy")
            || name == "AccessPolicyStore"
            || has(&["ApiKey", "AdmissionGate"]))
    {
        return Some("access");
    }
    None
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// A CLI command that calls one RPC names that method, not a mechanism. Only
/// command definitions in the CLI are exempt; the same name in any other crate
/// is still classified.
/// A typed MCP tool's input or output shape: a schema the tool list
/// publishes, not a mechanism.
fn is_tool_shape(path: &str) -> bool {
    path.starts_with("crates/tenzro-node/src/mcp/tool_types")
}

fn is_cli_rpc_command(path: &str, keyword: &str, name: &str) -> bool {
    path.starts_with("crates/tenzro-cli/src/commands/")
        && keyword == "struct"
        && name.ends_with("RpcCmd")
}

#[test]
fn only_cli_command_definitions_are_exempt() {
    let name = "ProviderComputePriceFeedRpcCmd";
    assert!(is_cli_rpc_command(
        "crates/tenzro-cli/src/commands/provider.rs",
        "struct",
        name
    ));
    assert_eq!(
        concern_of("struct", name),
        Some("oracle"),
        "the name alone is still an oracle"
    );
    for path in [
        "crates/tenzro-node/src/price.rs",
        "crates/tenzro-cli/src/main.rs",
        "crates/tenzro-vm/src/commands/x.rs",
    ] {
        assert!(
            !is_cli_rpc_command(path, "struct", name),
            "{path} must stay classified"
        );
    }
    assert!(!is_cli_rpc_command(
        "crates/tenzro-cli/src/commands/provider.rs",
        "trait",
        name
    ));
}

fn scan_mechanisms(root: &Path) -> Vec<(String, String, String)> {
    let mut files = Vec::new();
    rust_files(&root.join("crates"), true, &mut files);
    let mut found = Vec::new();
    for f in files {
        let src = production_source(&f);
        let path = rel(root, &f);
        for line in src.lines() {
            for keyword in ["fn", "struct", "trait", "enum"] {
                let needle = format!("{keyword} ");
                let mut rest = line;
                while let Some(i) = rest.find(&needle) {
                    let before_ok =
                        i == 0 || !rest[..i].ends_with(|c: char| c.is_alphanumeric() || c == '_');
                    let after = &rest[i + needle.len()..];
                    let name = ident_after(after);
                    if before_ok
                        && !name.is_empty()
                        && !is_cli_rpc_command(&path, keyword, name)
                        && !is_tool_shape(&path)
                        && let Some(concern) = concern_of(keyword, name)
                    {
                        found.push((concern.to_string(), rel(root, &f), name.to_string()));
                    }
                    rest = after;
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Writes of `CF_TOKENS` / `CF_METADATA`: the column family is the first
/// argument of a `put`/`delete`, or the `cf` of a `WriteOp`.
fn cf_writes(compact: &str) -> usize {
    let mut n = 0;
    for cf in ["CF_TOKENS", "CF_METADATA"] {
        let mut from = 0;
        while let Some(i) = compact[from..].find(cf) {
            let at = from + i;
            let before = &compact[at.saturating_sub(64)..at];
            let before =
                before.trim_end_matches(|c: char| c.is_alphanumeric() || c == '_' || c == ':');
            let call = before.strip_suffix('(').map(|b| {
                let start = b
                    .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .map_or(0, |j| j + 1);
                &b[start..]
            });
            if matches!(
                call,
                Some("put" | "delete" | "put_cf" | "delete_cf" | "remove")
            ) || before.ends_with("cf:")
            {
                n += 1;
            }
            from = at + cf.len();
        }
    }
    n
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whether `text` names `ty` as a whole identifier.
fn mentions_type(text: &str, ty: &str) -> bool {
    text.match_indices(ty)
        .any(|(i, _)| !text[..i].ends_with(is_ident) && !text[i + ty.len()..].starts_with(is_ident))
}

/// End of the brace block whose body starts at `start`.
fn block_end(s: &str, start: usize) -> usize {
    let mut depth = 1usize;
    for (k, c) in s[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return start + k;
                }
            }
            _ => {}
        }
    }
    s.len()
}

/// The writers of `ty`: each `pub fn` in its own `impl` blocks taking `&self`
/// and returning `Result`.
fn writer_methods(root: &Path, file: &str, ty: &str) -> Vec<String> {
    let compact: String = production_source(&root.join(file))
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut out = Vec::new();
    let pat = format!("impl{ty}{{");
    let mut from = 0;
    while let Some(i) = compact[from..].find(&pat) {
        let start = from + i + pat.len();
        let end = block_end(&compact, start);
        let body = &compact[start..end];
        let mut f = 0;
        while let Some(j) = body[f..].find("pubfn") {
            let at = f + j + "pubfn".len();
            let name = ident_after(&body[at..]);
            let sig_end = body[at..].find('{').map_or(body.len(), |k| at + k);
            let sig = &body[at..sig_end];
            if sig.contains("(&self") && sig.contains("->Result<") {
                out.push(name.to_string());
            }
            f = at;
        }
        from = end;
    }
    out.sort();
    out.dedup();
    out
}

/// Value calls in one file's production source, per kind: calls of a
/// guarded type's writers on a receiver of that type.
///
/// Receivers of a type are found by type: names declared with it (`name:
/// ...Type...` in a field, parameter or `let`), names bound from an accessor
/// returning it (`let name = x.accessor()`, `Some(name) = x.accessor()`), and
/// accessor calls chained straight into a writer.
fn value_calls(
    source: &str,
    guarded: &[(&str, &str, Vec<String>)],
    accessors: &[(String, String)],
) -> BTreeMap<String, usize> {
    let mut bound: Vec<(String, String)> = Vec::new();
    for line in source.lines() {
        for (kind, ty, _) in guarded {
            let mut rest = line;
            while let Some(i) = rest.find(':') {
                let after = &rest[i + 1..];
                if after.starts_with(':') || rest[..i].ends_with(':') {
                    rest = after.trim_start_matches(':');
                    continue;
                }
                let name_end = rest[..i].trim_end();
                let start = name_end.rfind(|c: char| !is_ident(c)).map_or(0, |k| k + 1);
                let name = &name_end[start..];
                let ty_end = after.find([',', ';', '=', '{']).unwrap_or(after.len());
                if !name.is_empty() && mentions_type(&after[..ty_end], ty) {
                    bound.push((name.to_string(), kind.to_string()));
                }
                rest = after;
            }
        }
        for (acc, kind) in accessors {
            if !line.contains(&format!(".{acc}()")) {
                continue;
            }
            let lhs = line.split('=').next().unwrap_or("");
            for (i, _) in lhs.match_indices("Some(") {
                let name = ident_after(&lhs[i + 5..]);
                if !name.is_empty() {
                    bound.push((name.to_string(), kind.clone()));
                }
            }
            if let Some(i) = lhs.find("let ") {
                let name = ident_after(lhs[i + 4..].trim_start_matches("mut "));
                if !name.is_empty() {
                    bound.push((name.to_string(), kind.clone()));
                }
            }
        }
    }
    bound.sort();
    bound.dedup();

    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    // One call site counts once per kind, however many guarded types of that
    // kind name the same writer.
    let mut sites: std::collections::BTreeSet<(String, usize)> = std::collections::BTreeSet::new();
    for (kind, _, writers) in guarded {
        for w in writers {
            let call = format!(".{w}(");
            for (i, _) in compact.match_indices(&call) {
                let before = &compact[..i];
                let receiver_start = before.rfind(|c: char| !is_ident(c)).map_or(0, |k| k + 1);
                let receiver = &before[receiver_start..];
                let by_name = bound.iter().any(|(b, k)| b == receiver && k == kind);
                let by_accessor = accessors.iter().any(|(acc, k)| {
                    k == kind && {
                        let stmt = &before[before.rfind([';', '{', '}']).map_or(0, |k| k + 1)..];
                        stmt.contains(&format!(".{acc}()"))
                    }
                });
                if by_name || by_accessor {
                    sites.insert((kind.to_string(), i));
                }
            }
        }
    }
    let mut counts = BTreeMap::new();
    for (kind, _) in sites {
        *counts.entry(kind).or_insert(0) += 1;
    }
    counts
}

/// The guarded types with their writers, and the node accessors returning one.
fn guarded_with_accessors(
    root: &Path,
    files: &[PathBuf],
) -> (
    Vec<(&'static str, &'static str, Vec<String>)>,
    Vec<(String, String)>,
) {
    let guarded: Vec<_> = GUARDED
        .iter()
        .map(|(kind, file, ty)| (*kind, *ty, writer_methods(root, file, ty)))
        .collect();
    let mut accessors = Vec::new();
    for f in files {
        let compact: String = production_source(f)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        for (i, _) in compact.match_indices("fn") {
            // Whitespace is gone, so `pub fn` reads `pubfn`.
            let before = compact[..i].strip_suffix("pub").unwrap_or(&compact[..i]);
            if before.ends_with(is_ident) {
                continue;
            }
            let name = ident_after(&compact[i + 2..]);
            let sig = &compact[i + 2 + name.len()..];
            // A wrapped signature keeps a trailing comma: `(&self,)->`.
            let Some(head) = ["(&self)->", "(&self,)->"]
                .into_iter()
                .find(|h| sig.starts_with(h))
            else {
                continue;
            };
            let ret = &sig[head.len()..sig.find('{').unwrap_or(sig.len())];
            for (kind, ty, _) in &guarded {
                if mentions_type(ret, ty) {
                    accessors.push((name.to_string(), kind.to_string()));
                }
            }
        }
    }
    accessors.sort();
    accessors.dedup();
    (guarded, accessors)
}

fn scan_node_writes(root: &Path) -> BTreeMap<(String, String), usize> {
    let mut files = Vec::new();
    rust_files(&root.join("crates/tenzro-node/src"), false, &mut files);
    let (guarded, accessors) = guarded_with_accessors(root, &files);
    let mut counts = BTreeMap::new();
    for f in &files {
        let source = production_source(f);
        for (kind, n) in value_calls(&source, &guarded, &accessors) {
            counts.insert((rel(root, f), kind), n);
        }
        let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        let n = cf_writes(&compact);
        if n > 0 {
            counts.insert((rel(root, f), "cf".to_string()), n);
        }
    }
    counts
}

/// The deny-list matches a value call by its receiver's type: a node-side
/// payout written against the balance read model is caught whatever its
/// variable is called and however its arguments are spelled.
#[test]
fn a_value_call_is_matched_by_its_receivers_type() {
    let guarded = vec![(
        "bond",
        "ComputeBondManager",
        vec!["slash".to_string(), "withdraw".to_string()],
    )];
    let accessors = vec![("compute_bond_manager".to_string(), "bond".to_string())];

    let payout = "fn settle(node: &Node, job: &Job) {\n\
                  let Some(ledger) = node.compute_bond_manager() else { return };\n\
                  ledger.withdraw(&did, height)?;\n\
                  node.compute_bond_manager().unwrap().slash(&did, 1, \"sla\", height)?;\n}";
    assert_eq!(
        value_calls(payout, &guarded, &accessors).get("bond"),
        Some(&2)
    );
    let field = "struct Settler { bonds: Arc<ComputeBondManager> }\nfn pay(&self) { self.bonds.withdraw(&did, 1)?; }";
    assert_eq!(
        value_calls(field, &guarded, &accessors).get("bond"),
        Some(&1)
    );
    // A transfer on some other type is not a value call.
    let other = "fn send(client: &Client) { client.withdraw(a, b)?; }";
    assert!(value_calls(other, &guarded, &accessors).is_empty());
}

/// Native TNZO moves only in block execution: the balance read model has no
/// writer at all, so no node code can call one.
#[test]
fn the_balance_read_model_has_no_writer() {
    let writers = writer_methods(&root(), "crates/tenzro-token/src/tnzo.rs", "TnzoToken");
    assert!(
        writers.is_empty(),
        "TnzoToken must stay a read model: {writers:?}"
    );
}

/// Every listed mechanism and node write is classified: no open gap rows.
#[test]
fn no_gap_rows_remain() {
    const TAGS: &[&str] = &["OWNER", "REPLAY", "FLAG", "READ", "LOCAL", "GENESIS"];
    let tags = MECHANISMS
        .iter()
        .map(|m| m.3)
        .chain(NODE_WRITES.iter().map(|w| w.3));
    let open: Vec<&str> = tags
        .filter(|t| !TAGS.iter().any(|k| t.starts_with(k)))
        .collect();
    assert!(open.is_empty(), "unclassified rows: {open:?}");
}

#[test]
fn one_mechanism_per_concern() {
    let root = root();
    let found = scan_mechanisms(&root);
    let listed: Vec<(String, String, String)> = MECHANISMS
        .iter()
        .map(|(c, f, n, _)| (c.to_string(), f.to_string(), n.to_string()))
        .collect();
    let new: Vec<_> = found.iter().filter(|x| !listed.contains(x)).collect();
    let gone: Vec<_> = listed.iter().filter(|x| !found.contains(x)).collect();
    assert!(
        new.is_empty() && gone.is_empty(),
        "architecture drift: extend the concern's OWNER instead of adding a mechanism.\n\
         new definitions: {new:#?}\nlisted but gone (remove from MECHANISMS): {gone:#?}"
    );
}

#[test]
fn node_code_moves_no_value_outside_consensus() {
    let root = root();
    let found = scan_node_writes(&root);
    let listed: BTreeMap<(String, String), usize> = NODE_WRITES
        .iter()
        .map(|(f, k, n, _)| ((f.to_string(), k.to_string()), *n))
        .collect();
    let mut drift = Vec::new();
    for (key, n) in &found {
        let allowed = listed.get(key).copied().unwrap_or(0);
        if *n != allowed {
            drift.push(format!("{} {}: found {n}, listed {allowed}", key.0, key.1));
        }
    }
    for (key, n) in &listed {
        if !found.contains_key(key) {
            drift.push(format!("{} {}: found 0, listed {n}", key.0, key.1));
        }
    }
    assert!(
        drift.is_empty(),
        "value writes outside consensus changed; above the list is refused, below it shrink NODE_WRITES:\n{}",
        drift.join("\n")
    );
}

// ---- governed network parameters ------------------------------------------
//
// Every network policy or economic value is a governed parameter in
// `GOVERNED_PARAMS` (crates/tenzro-vm/src/governance.rs), read from chain
// state, and changed only by an enacted `parameter_change` proposal. The
// checks below keep it that way.

/// Constants in the consensus crates whose names read like policy but which
/// are not governed parameters, each with why. A new policy-like constant
/// fails `no_hard_coded_network_policy` until it is either registered in
/// `GOVERNED_PARAMS` (as its key or genesis value) or listed here.
const NOT_GOVERNED: &[(&str, &str, &str)] = &[
    (
        "crates/tenzro-vm/src/feature_gate.rs",
        "MIN_NOTICE_EPOCHS",
        "BOUND: epochs of notice a vote on a feature gate must give so every validator sees the new activation epoch before it applies; it is the safety margin of the gate itself, and a vote that could shorten it could switch a rule on under validators that have not yet seen it",
    ),
    (
        "crates/tenzro-vm/src/governance.rs",
        "MAX_OPERATOR_HISTORY_EPOCHS",
        "BOUND: size limit of the availability history one operator approval carries, so a proposal stays small; whether an operator qualifies is judged by the vote",
    ),
    (
        "crates/tenzro-vm/src/governance.rs",
        "MAX_RUNNING_COST_EPOCHS",
        "BOUND: size limit of the hourly span one sponsorship claim covers, so a claim is checked in bounded time; the amount is limited by the governed USD caps",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "MIN_PAR_BAND_BPS",
        "BOUND: least par band a SetSettlementAsset vote may give an entry; the band itself is set per asset by vote",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "MAX_PAR_BAND_BPS",
        "BOUND: greatest par band a SetSettlementAsset vote may give an entry",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "DEFAULT_PAR_BAND_BPS",
        "GENESIS: par band a new settlement asset entry starts with before the vote that installs it sets its own",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "MAX_EPOCH_INFLOW_CAP_UNITS",
        "BOUND: greatest epoch inflow cap a SetSettlementAsset vote may give an entry",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "DEFAULT_EPOCH_INFLOW_CAP_UNITS",
        "GENESIS: epoch inflow cap a new settlement asset entry starts with",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "MIN_TREASURY_SHARE_BPS",
        "BOUND: least treasury share target a SetSettlementAsset vote may give an entry",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "MAX_TREASURY_SHARE_BPS",
        "BOUND: greatest treasury share target a SetSettlementAsset vote may give an entry",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "DEFAULT_TREASURY_SHARE_BPS",
        "GENESIS: treasury share target a new settlement asset entry starts with",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "MAX_EXPOSURE_BPS",
        "BOUND: greatest treasury exposure ceiling a SetSettlementAsset vote may give an entry",
    ),
    (
        "crates/tenzro-types/src/settlement_asset.rs",
        "DEFAULT_EXPOSURE_BPS",
        "GENESIS: treasury exposure ceiling a new settlement asset entry starts with",
    ),
    (
        "crates/tenzro-vm/src/native/hardware_level.rs",
        "MAX_REWARD_WITH_LEVEL_BONUS_BPS",
        "BOUND: a joint rule keeps settlement rewards plus the hardware bonus at its cap below the fee, so the bonus never makes trading with oneself pay",
    ),
    (
        "crates/tenzro-vm/src/native/economy.rs",
        "NO_FEE",
        "PROTOCOL: the zero fee for a payment that already paid the network its share another way; the rate it stands in for is governed",
    ),
    (
        "crates/tenzro-vm/src/native/economy.rs",
        "KEPT_MEDIAN_EPOCHS",
        "DERIVED: the longest governed look-back window at its maximum, so no reader loses a median",
    ),
    (
        "crates/tenzro-vm/src/native/economy.rs",
        "MAX_RATE_PRUNED_EPOCHS",
        "BOUND: most epochs of rate medians one call deletes",
    ),
    (
        "crates/tenzro-vm/src/native/rewards.rs",
        "MAX_PRUNED_EPOCHS_PER_BLOCK",
        "BOUND: most reward epochs one block prunes",
    ),
    (
        "crates/tenzro-vm/src/native/agent_audit.rs",
        "MAX_PRUNED_EPOCHS_PER_BLOCK",
        "BOUND: most audit epochs one block prunes",
    ),
    (
        "crates/tenzro-vm/src/native/mod.rs",
        "MAX_SLA_SWEPT_EPOCHS",
        "BOUND: most SLA epochs one sweep deletes",
    ),
    (
        "crates/tenzro-vm/src/hot_state.rs",
        "HOT_STATE_MAX_MULTIPLIER",
        "LOCAL: execution cache sizing",
    ),
    (
        "crates/tenzro-vm/src/ledger.rs",
        "DEFAULT_BASE_FEE_BURN_BPS",
        "POLICY RECORD: adaptive burn config, set by an enacted policy_update",
    ),
    (
        "crates/tenzro-vm/src/native/compute_claim.rs",
        "MAX_CLAIM_EPOCHS",
        "BOUND: most epochs one compute claim scans",
    ),
    (
        "crates/tenzro-vm/src/native/treasury_reserve.rs",
        "MAX_SCAN_EPOCHS",
        "BOUND: most epochs one running-cost reserve boundary scans",
    ),
    (
        "crates/tenzro-vm/src/native/economy.rs",
        "MAX_ACTIVITY_REWARD_FEE_BPS",
        "BOUND: ceiling the governed activity reward share may reach",
    ),
    (
        "crates/tenzro-vm/src/native/role_stake.rs",
        "WALLET_PROVIDER_VERDICT_EPOCHS",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_BASE_FEE_BURN_BPS",
        "POLICY RECORD: adaptive burn config genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_LOCAL_FEE_BURN_BPS",
        "POLICY RECORD: adaptive burn config genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_NEUTRAL_BAND_BPS",
        "POLICY RECORD: supply targets genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_ROLLING_WINDOW_EPOCHS",
        "POLICY RECORD: supply targets genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_INFLATION_ALARM_BPS",
        "POLICY RECORD: supply targets genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_DEFLATION_ALARM_BPS",
        "POLICY RECORD: supply targets genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_TARGET_ANNUAL_SUPPLY_BPS",
        "POLICY RECORD: supply targets genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_GAIN_BPS_PER_PCT",
        "POLICY RECORD: supply targets genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_MAGNITUDE_CAP_NORMAL_BPS",
        "POLICY RECORD: supply targets genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_MAGNITUDE_CAP_ALARM_BPS",
        "POLICY RECORD: supply targets genesis",
    ),
    (
        "crates/tenzro-token/src/adaptive_burn.rs",
        "DEFAULT_AUTO_PROPOSAL_MIN_MAGNITUDE_BPS",
        "POLICY RECORD: supply targets genesis",
    ),
    (
        "crates/tenzro-token/src/fee_distribution.rs",
        "MAX_RECENT_FEE_RECORDS",
        "LOCAL: read-model buffer size",
    ),
    (
        "crates/tenzro-token/src/rewards.rs",
        "NETWORK_REWARDS_POOL",
        "GENESIS: supply allocation of the rewards pool",
    ),
    (
        "crates/tenzro-token/src/rewards.rs",
        "DEFAULT_REVENUE_PEG_BPS",
        "GENESIS: reward schedule record written at genesis",
    ),
    (
        "crates/tenzro-token/src/validator_registry.rs",
        "DEFAULT_MIN_VALIDATOR_SELF_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-token/src/validator_registry.rs",
        "DEFAULT_MIN_RPC_PROVIDER_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-token/src/validator_registry.rs",
        "DEFAULT_ACTIVATION_CHURN_BPS",
        "ROLE STAKE: validator registry policy, moving with the validator minimum",
    ),
    (
        "crates/tenzro-token/src/validator_registry.rs",
        "DEFAULT_EXIT_CHURN_BPS",
        "ROLE STAKE: validator registry policy, moving with the validator minimum",
    ),
    (
        "crates/tenzro-token/src/validator_registry.rs",
        "DEFAULT_REENTRY_COOLDOWN_EPOCHS",
        "ROLE STAKE: validator registry policy, moving with the validator minimum",
    ),
    (
        "crates/tenzro-token/src/validator_registry.rs",
        "RETIRED_SCHEME_GRACE_EPOCHS",
        "ROLE STAKE: validator registry policy, moving with the validator minimum; which key schemes are admitted is governed",
    ),
    (
        "crates/tenzro-types/src/bridge_route.rs",
        "MAX_WITHDRAWAL_FEE_RATE",
        "BOUND: largest fee rate a governed bridge route may declare",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "MIN_VALIDATOR_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "MIN_RPC_OPERATOR_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "MIN_ATTESTOR_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "MIN_WALLET_PROVIDER_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "MIN_EDGE_OPERATOR_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "MIN_TEE_PROVIDER_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "MIN_MODEL_PROVIDER_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "COMPUTE_STAKE_PER_ACCELERATOR",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "MIN_COMPUTE_PROVIDER_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "STORAGE_STAKE_PER_TB",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "MIN_STORAGE_PROVIDER_STAKE",
        "ROLE STAKE: moving with the role bonds",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "AGENT_BOND_POST",
        "PROTOCOL: gas schedule",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "AGENT_BOND_INCREASE",
        "PROTOCOL: gas schedule",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "AGENT_BOND_WITHDRAW",
        "PROTOCOL: gas schedule",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "COMPUTE_BOND_POST",
        "PROTOCOL: gas schedule",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "COMPUTE_BOND_INCREASE",
        "PROTOCOL: gas schedule",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "COMPUTE_BOND_WITHDRAW",
        "PROTOCOL: gas schedule",
    ),
    (
        "crates/tenzro-types/src/constants.rs",
        "COMPUTE_BOND_FINALIZE",
        "PROTOCOL: gas schedule",
    ),
    (
        "crates/tenzro-types/src/settlement_network.rs",
        "DEFAULT_FEE_RATIO",
        "LOCAL: a client's default for its own settlement route",
    ),
    (
        "crates/tenzro-types/src/transaction.rs",
        "MAX_RESERVE_FEED_STALENESS_SECS",
        "BOUND: longest staleness a governed reserve feed may declare",
    ),
];

const POLICY_WORDS: &[&str] = &[
    "_BPS",
    "_FEE",
    "SLASH",
    "PENALTY",
    "_STAKE",
    "BOND",
    "_WINDOW_MS",
    "_WINDOW_SECS",
    "COOLDOWN",
    "UNBONDING",
    "QUORUM",
    "THRESHOLD",
    "_CAP",
    "_MULTIPLE",
    "MULTIPLIER",
    "_REWARD",
    "_EPOCHS",
];

fn governed_params_table(root: &Path) -> String {
    let src = std::fs::read_to_string(root.join("crates/tenzro-vm/src/governance.rs"))
        .expect("governance.rs");
    let start = src
        .find("pub const GOVERNED_PARAMS")
        .expect("GOVERNED_PARAMS");
    let end = start + src[start..].find("\n];").expect("end of GOVERNED_PARAMS");
    src[start..end].to_string()
}

fn mentions_ident(text: &str, ident: &str) -> bool {
    text.match_indices(ident).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + ident.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

fn is_policy_name(name: &str) -> bool {
    if name.starts_with("SELECTOR_") || name.starts_with("GAS_") || name.starts_with("PARAM_") {
        return false;
    }
    if [
        "_PARAM", "_KEY", "_TOPIC", "_DOMAIN", "_OP", "_PREFIX", "_SLOT",
    ]
    .iter()
    .any(|s| name.ends_with(s))
    {
        return false;
    }
    if name.contains("CAPABILITY") || name.contains("CAPACITY") {
        return false;
    }
    POLICY_WORDS.iter().any(|w| name.contains(w))
}

/// Policy-like constants of the consensus crates: (file, name).
fn policy_constants(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for krate in ["tenzro-vm", "tenzro-token", "tenzro-types"] {
        let mut files = Vec::new();
        rust_files(
            &root.join("crates").join(krate).join("src"),
            true,
            &mut files,
        );
        for f in files {
            if f.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("_tests.rs"))
            {
                continue;
            }
            for line in production_source(&f).lines() {
                let t = line.trim_start();
                let rest = [
                    "pub const ",
                    "pub(crate) const ",
                    "pub(super) const ",
                    "const ",
                ]
                .iter()
                .find_map(|p| t.strip_prefix(p));
                let Some(rest) = rest else { continue };
                let name = ident_after(rest);
                if name.is_empty() || rest[name.len()..].trim_start().starts_with(": &str") {
                    continue;
                }
                if is_policy_name(name) {
                    out.push((rel(root, &f), name.to_string()));
                }
            }
        }
    }
    out
}

/// A policy value is a governed parameter or is listed with a reason; a
/// listed constant that no longer exists is removed from the list.
#[test]
fn no_hard_coded_network_policy() {
    let root = root();
    let table = governed_params_table(&root);
    let found = policy_constants(&root);
    let mut errors = Vec::new();
    for (file, name) in &found {
        if mentions_ident(&table, name) {
            continue;
        }
        if !NOT_GOVERNED.iter().any(|(f, n, _)| f == file && n == name) {
            errors.push(format!(
                "{file}: {name} looks like network policy; make it a governed parameter in GOVERNED_PARAMS \
                 (read with network_param) or list it in NOT_GOVERNED with why"
            ));
        }
    }
    for (file, name, _) in NOT_GOVERNED {
        if !found.iter().any(|(f, n)| f == file && n == name) {
            errors.push(format!("{file}: {name} is listed in NOT_GOVERNED but no longer exists there; remove the row"));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Every registered parameter is read by the code it governs; a parameter
/// nothing reads only looks governable.
#[test]
fn every_governed_parameter_is_read() {
    let root = root();
    let table = governed_params_table(&root);
    let mut sources = String::new();
    for krate in [
        "tenzro-vm",
        "tenzro-node",
        "tenzro-token",
        "tenzro-types",
        "tenzro-payments",
        // The CLI and SDK read the transfer ceiling and recipient guard from the chain.
        "tenzro-cli",
    ] {
        let mut files = Vec::new();
        rust_files(
            &root.join("crates").join(krate).join("src"),
            true,
            &mut files,
        );
        for f in files {
            if f.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("_tests.rs"))
            {
                continue;
            }
            let text = production_source(&f);
            let text = match text.find("pub const GOVERNED_PARAMS") {
                Some(i) => format!(
                    "{}{}",
                    &text[..i],
                    &text[i + text[i..].find("\n];").unwrap_or(0)..]
                ),
                None => text,
            };
            sources.push_str(&text);
            sources.push('\n');
        }
    }
    let mut unread = Vec::new();
    for entry in table.split("GovernedParam {").skip(1) {
        let Some(key) = entry
            .split("key:")
            .nth(1)
            .and_then(|k| k.split(',').next())
            .map(str::trim)
        else {
            continue;
        };
        let read = if let Some(lit) = key.strip_prefix('"') {
            let lit = lit.trim_end_matches('"');
            // A family of keys is read through its shared prefix.
            let prefix = lit.rsplit_once('.').map(|(p, _)| format!("\"{p}.\""));
            sources.contains(&format!("\"{lit}\"")) || prefix.is_some_and(|p| sources.contains(&p))
        } else {
            let ident = key.rsplit("::").next().unwrap_or(key);
            // Its definition plus at least one use.
            sources
                .match_indices(ident)
                .filter(|(i, _)| {
                    let before = sources[..*i].chars().next_back();
                    let after = sources[i + ident.len()..].chars().next();
                    !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
                })
                .count()
                >= 2
        };
        if !read {
            unread.push(key.to_string());
        }
    }
    assert!(
        unread.is_empty(),
        "governed parameters nothing reads: {unread:?}"
    );
}

/// Only enactment (the parameter schedule in tenzro-vm) and genesis write a
/// governed parameter; no RPC, CLI or node configuration can.
#[test]
fn only_governance_and_genesis_write_network_parameters() {
    let root = root();
    let allowed = [
        "crates/tenzro-vm/src/native/mod.rs",
        "crates/tenzro-node/src/genesis.rs",
    ];
    let mut files = Vec::new();
    rust_files(&root.join("crates"), true, &mut files);
    let mut writers = Vec::new();
    for f in files {
        let path = rel(&root, &f);
        if path.ends_with("_tests.rs") || allowed.contains(&path.as_str()) {
            continue;
        }
        let text = production_source(&f);
        if text.contains("governed_param_key(") || text.contains("\"governance_param:") {
            writers.push(path);
        }
    }
    assert!(
        writers.is_empty(),
        "code outside governance enactment and genesis touches governed parameter storage: {writers:?}"
    );
}
