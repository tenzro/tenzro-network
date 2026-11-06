//! An agent's authority is its consensus Terms and nothing else.
//!
//! Scans over the workspace source (unit-test modules excluded):
//!
//! - Second authority stores. No production code may define or consult an
//!   authority source other than the Terms in consensus state: node-side
//!   spending policies, scope oracles, delegation scopes kept in the identity
//!   registry, mandate stores, payment binders, or a DID-to-wallet index kept
//!   beside the identity record.
//! - Every authorization path asks the Terms. Each entry point where an agent
//!   pays, invokes, acts, or presents a web identity must call the Terms
//!   check named for it. Removing the call fails here.
//! - One root verification. Every approval a root gives, a human's passkey
//!   or a machine's TPM or Secure Enclave key, is checked by
//!   `verify_root_approval`; no second verifier sits beside it. The
//!   behaviour (a machine-rooted agent acts within its terms, is refused
//!   beyond them, halts when its root revokes it, and no machine approves
//!   for another machine's agent) is tested in the VM's agent terms.

use std::path::{Path, PathBuf};

/// Identifiers that name an authority source other than consensus Terms.
const SECOND_STORES: &[&str] = &[
    "SpendingPolicy",
    "ScopeOracle",
    "IdentityScopeOracle",
    "DelegationScopeValidator",
    "IdentityPaymentBinder",
    "SpendingPolicyResolver",
    "LifecycleStateResolver",
    "MandateStore",
    "mandate_store",
    "enforce_operation(",
    "update_delegation_scope(",
    "delegation_scope()",
    "identity_scope(",
    "set_spending_policy(",
    "get_spending_policy(",
    "record_spend(",
    "wallets_for_did(",
    "find_did_by_address(",
    "resolve_wallet_for_did_from(",
    "rebind_primary_wallet_id(",
    "wallet_index",
    "enforce_relay_spend_ceilings",
    "enforce_typed_tx_spend_ceilings",
    "check_kill_switch_authorization",
];

/// (file, function, the Terms check it must make).
const TERMS_PATHS: &[(&str, &str, &str)] = &[
    // Payments: the gateway behind x402, MPP and the HTTP 402 gates.
    (
        "crates/tenzro-payments/src/gateway.rs",
        "fn check_payer_identity",
        "gate.authorize(",
    ),
    // Intent-routed inference spends through the intent tier's budget gate.
    (
        "crates/tenzro-node/src/node.rs",
        "with_budget_gate(",
        "terms_gate::ChainTermsGate::new(",
    ),
    // The one payment decision, over consensus state.
    (
        "crates/tenzro-node/src/terms_gate.rs",
        "fn check_on",
        "check_agent_payment(",
    ),
    (
        "crates/tenzro-node/src/terms_gate.rs",
        "pub fn install",
        "set_terms_gate(",
    ),
    (
        "crates/tenzro-node/src/main.rs",
        "async fn run(",
        "terms_gate::install(",
    ),
    (
        "crates/tenzro-node/src/handle.rs",
        "async fn spawn_in_background_inner(",
        "terms_gate::install(",
    ),
    // Delegated agents' requests to node services.
    (
        "crates/tenzro-node/src/agent_guardrails.rs",
        "pub(crate) fn check_operation",
        "check_agent_status(",
    ),
    // Access tokens of delegated agents.
    (
        "crates/tenzro-node/src/agent_delegation.rs",
        "pub(crate) fn check_agent_token",
        "check_agent_status(",
    ),
    (
        "crates/tenzro-node/src/agent_delegation.rs",
        "pub(crate) fn check_agent_key_request",
        "check_agent_status(",
    ),
    // Web identity: signed agent HTTP keys come from the Terms.
    (
        "crates/tenzro-node/src/agent_http_signature.rs",
        "",
        "read_agent_terms(",
    ),
    // Agent payments: an agent pays only through an action held to its
    // terms, and its vouchers are honoured only for a node its terms assign,
    // before revocation; a serving node signs only what the ledger would
    // honour.
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub(super) fn act(",
        "check_agent_act(",
    ),
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub(super) fn act_for_plan(",
        "check_agent_act(",
    ),
    (
        "crates/tenzro-vm/src/native/payment_settlement.rs",
        "fn check_voucher(",
        "check_agent_voucher(",
    ),
    (
        "crates/tenzro-vm/src/native/payment_settlement.rs",
        "fn check_agent_voucher(",
        "read_agent_quarantine(",
    ),
    (
        "crates/tenzro-vm/src/native/payment_settlement.rs",
        "fn check_agent_voucher(",
        "verify_node_signature(",
    ),
    (
        "crates/tenzro-node/src/payment_channels.rs",
        "pub(crate) async fn agent_voucher(",
        "check_escrow_voucher(",
    ),
    (
        "crates/tenzro-node/src/payment_rails.rs",
        "fn check_signer(",
        "check_escrow_voucher(",
    ),
    // Web identity: the key directory is the terms' keys at this height.
    (
        "crates/tenzro-node/src/agent_http_signature.rs",
        "pub(crate) fn resolutions(",
        "read_agent_terms(",
    ),
    // Actions and the kill switch in consensus.
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub fn check_agent_act",
        "check_action(",
    ),
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub fn check_agent_payment",
        "check_limits(",
    ),
    (
        "crates/tenzro-vm/src/native/mod.rs",
        "fn require_agent_controller",
        "authorize_agent_controller(",
    ),
    (
        "crates/tenzro-vm/src/native/mod.rs",
        "fn authorize_agent_controller",
        "read_agent_terms(",
    ),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !matches!(
                name,
                "target" | "tests" | "benches" | "examples" | "node_modules"
            ) {
                rust_files(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Source without unit-test modules and without comment lines.
fn production_source(text: &str) -> String {
    // The first inline test module; a `#[cfg(test)] mod name;` declaration
    // is not one.
    let mut cut = text.len();
    for marker in ["#[cfg(test)]\nmod ", "#[cfg(test)]\npub mod "] {
        for (i, _) in text.match_indices(marker) {
            let line_end = text[i + marker.len()..]
                .find('\n')
                .map_or(text.len(), |e| i + marker.len() + e);
            if text[i..line_end].trim_end().ends_with('{') {
                cut = cut.min(i);
                break;
            }
        }
    }
    text[..cut]
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of the item whose header contains `header`: from the header to
/// the brace that closes it. An empty header is the whole file.
fn item_body<'a>(src: &'a str, header: &str) -> Option<&'a str> {
    if header.is_empty() {
        return Some(src);
    }
    let start = src.find(header)?;
    let open = start + src[start..].find('{')?;
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[start..open + i + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn no_authority_store_beside_consensus_terms() {
    let root = root();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    rust_files(&root.join("sdk/tenzro-sdk/src"), &mut files);
    let me = Path::new(file!()).file_name().unwrap();
    let mut hits = Vec::new();
    for f in files.iter().filter(|f| f.file_name() != Some(me)) {
        let src = production_source(&std::fs::read_to_string(f).unwrap_or_default());
        for (n, line) in src.lines().enumerate() {
            for id in SECOND_STORES {
                let at = line.find(id);
                let whole = at.is_some_and(|i| {
                    let before = line[..i].chars().last();
                    let after = line[i + id.len()..].chars().next();
                    !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                        && (id.ends_with('(')
                            || !after.is_some_and(|c| c.is_alphanumeric() || c == '_'))
                });
                if whole {
                    let rel = f.strip_prefix(&root).unwrap_or(f).display();
                    hits.push(format!("{rel}:{}: {id}", n + 1));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "agent authority must come only from consensus Terms; second stores found:\n{}",
        hits.join("\n")
    );
}

#[test]
fn every_authorization_path_asks_the_terms() {
    let root = root();
    let mut missing = Vec::new();
    for (file, header, call) in TERMS_PATHS {
        let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
        let src = production_source(&text);
        match item_body(&src, header) {
            Some(body) if body.contains(call) => {}
            Some(_) => missing.push(format!("{file} `{header}` does not call `{call}`")),
            None => missing.push(format!("{file} has no `{header}`")),
        }
    }
    assert!(
        missing.is_empty(),
        "authorization paths that skip the Terms:\n{}",
        missing.join("\n")
    );
}

/// (file, item, what it must contain): a node's relayer keys pay fees and
/// never move an agent's value. Value on another chain moves only under the
/// grant the agent's root issued, and a node signs an action only for an
/// agent it serves and within that grant.
const RELAYER_FEE_ONLY: &[(&str, &str, &str)] = &[
    (
        "crates/tenzro-bridge/src/evm_signer.rs",
        "pub async fn send_transaction(&self, to: &str, calldata: &[u8])",
        "encode_eip1559_transaction(",
    ),
    (
        "crates/tenzro-bridge/src/evm_signer.rs",
        "async fn encode_eip1559_transaction(",
        "rlp_encode_u128(&mut unsigned_fields, 0);",
    ),
    (
        "crates/tenzro-node/src/agent_delegation.rs",
        "pub(crate) async fn handle_sign_remote_action(",
        "grant.admits(&action",
    ),
    (
        "crates/tenzro-node/src/agent_delegation.rs",
        "pub(crate) async fn handle_sign_remote_action(",
        ".serving_node(&machine_did).is_none()",
    ),
    (
        "crates/tenzro-node/src/agent_delegation.rs",
        "pub(crate) async fn handle_sign_remote_action(",
        "check_agent_status(",
    ),
    (
        "crates/tenzro-types/src/remote_grant.rs",
        "pub fn admits(",
        "action.relay_refund > self.relay_fee_max",
    ),
];

#[test]
fn relayer_keys_pay_fees_only() {
    let root = root();
    let mut missing = Vec::new();
    for (file, header, needle) in RELAYER_FEE_ONLY {
        let src = production_source(&std::fs::read_to_string(root.join(file)).unwrap_or_default());
        match item_body(&src, header) {
            Some(body) if body.contains(needle) => {}
            Some(_) => missing.push(format!("{file} `{header}` lacks `{needle}`")),
            None => missing.push(format!("{file} has no `{header}`")),
        }
    }
    assert!(
        missing.is_empty(),
        "relayer keys must pay fees only:\n{}",
        missing.join("\n")
    );
}

/// (file, item, what it must call): every approval a root gives (terms,
/// step-up, agent governance, a DID's service entries, a machine root's governance ballot, the node's
/// pre-submission check) goes through
/// the one root verification, whatever the root is (any passkey of the
/// identity's keystore on chain, or a machine).
const ROOT_APPROVAL_PATHS: &[(&str, &str, &str)] = &[
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "fn verify_approval(",
        "verify_root_approval(",
    ),
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub(super) fn set_terms(",
        "verify_approval(",
    ),
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub fn check_agent_act",
        "verify_root_approval(",
    ),
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub fn verify_root_approval(",
        "check_passkey_root(",
    ),
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub fn verify_root_approval(",
        "machine_root_key(",
    ),
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub fn verify_root_approval(",
        "enrolled_pq_key(",
    ),
    (
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "pub fn verify_root_approval(",
        "verify_for_relying_party(",
    ),
    (
        "crates/tenzro-vm/src/native/did_services.rs",
        "pub fn apply(",
        "verify_root_approval(",
    ),
    (
        "crates/tenzro-node/src/agent_delegation.rs",
        "async fn approve_as_root(",
        "verify_root_approval(",
    ),
    (
        "crates/tenzro-vm/src/native/mod.rs",
        "fn machine_root_may_vote(",
        "verify_root_approval(",
    ),
];

/// Verifiers a second root-approval path would call directly.
const SECOND_ROOT_VERIFIERS: &[&str] = &[
    "verify_webauthn_assertion",
    "verify_controller_assertion",
    "check_root_passkey",
];

#[test]
fn every_root_approval_has_one_verification_path() {
    let root = root();
    let mut missing = Vec::new();
    for (file, header, call) in ROOT_APPROVAL_PATHS {
        let src = production_source(&std::fs::read_to_string(root.join(file)).unwrap_or_default());
        match item_body(&src, header) {
            Some(body) if body.contains(call) => {}
            Some(_) => missing.push(format!("{file} `{header}` does not call `{call}`")),
            None => missing.push(format!("{file} has no `{header}`")),
        }
    }
    for file in [
        "crates/tenzro-vm/src/native/agent_terms.rs",
        "crates/tenzro-node/src/agent_delegation.rs",
    ] {
        let src = production_source(&std::fs::read_to_string(root.join(file)).unwrap_or_default());
        for v in SECOND_ROOT_VERIFIERS {
            if src.contains(v) {
                missing.push(format!(
                    "{file} verifies a root approval with `{v}` beside verify_root_approval"
                ));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "root approvals outside the one path:\n{}",
        missing.join("\n")
    );
}

#[test]
fn the_scan_sees_a_second_store_and_a_skipped_check() {
    let planted = "fn pay() { registry.enforce_operation(did, \"payment\", None); }";
    assert!(
        SECOND_STORES
            .iter()
            .any(|id| production_source(planted).contains(id))
    );
    let gate = "fn check_payer_identity(&self) -> Result<()> { Ok(()) }";
    let body = item_body(gate, "fn check_payer_identity").unwrap();
    assert!(!body.contains("gate.authorize("));
    let tested = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn b() { x.enforce_operation(); }\n}";
    assert!(!production_source(tested).contains("enforce_operation("));
}
