//! The legacy sweep: the workspace carries no old paths, no unfinished code,
//! and no leftovers of removed subsystems.
//!
//! Features scheduled after the upgrade are held only as placeholders: a
//! declared, documented, tested refusal behind a governed flag or a catalog
//! status. Each one is named in [`PLACEHOLDERS`] with the files its marker may
//! appear in, so a placeholder cannot spread into a half-built feature.

#[path = "support/gate.rs"]
mod gate;

use std::collections::BTreeSet;

/// Placeholders for features scheduled after the upgrade: (name, marker,
/// files the marker may appear in).
const PLACEHOLDERS: &[(&str, &str, &[&str])] = &[
    (
        "planned media models",
        "MediaGenStatus::Planned",
        &[
            "crates/tenzro-catalog/src/lib.rs",
            "crates/tenzro-catalog/src/entry.rs",
        ],
    ),
    (
        "native media engine slot",
        "NATIVE_PIPELINES",
        &[
            "crates/tenzro-model/src/media_runtime.rs",
            "crates/tenzro-model/src/lib.rs",
        ],
    ),
];

/// Markers that never appear in non-test code.
const FORBIDDEN: &[&str] = &[
    "todo!(",
    "unimplemented!(",
    "#[deprecated",
    "allow(dead_code)",
    // The removed training stack and its Python trainer.
    "tenzro_training::",
    "training_service",
    "training_bridges",
    "training_blobs",
    "TrainingRuntime",
    // The removed out-of-process media hosts.
    "integrations/media_gen",
    "MediaGenBackend",
    "required_package",
    // The removed shared-secret access: API keys, service keys, the admin
    // token and the HMAC token secret.
    "X-Tenzro-Api-Key",
    "X-Tenzro-Admin-Token",
    "X-Tenzro-Service-Key",
    "x-tenzro-api-key",
    "x-tenzro-service-key",
    "TENZRO_ADMIN_TOKEN",
    "TENZRO_API_KEY",
    "TENZRO_SERVICE_KEYS",
    "createApiKey",
    "ApiKeyRecord",
    "admission_gate",
    "auth_secret",
    // SDK surface removed when the SDKs were finalized: software-key DPoP,
    // unused CAIP and DID string helpers, and signer storage and recovery
    // traits nothing implemented.
    "generateDpopKeyPair",
    "mintDpopProof",
    "computeJkt",
    "Ed25519Jwk",
    "DpopProofParams",
    "isTenzroCaip2",
    "buildTenzroCaip2",
    "parseTenzroCaip2",
    "isTenzroCaip10",
    "parseTenzroCaip19",
    "TENZRO_SLIP44_COIN_INDEX",
    "TENZRO_CAIP2_NAMESPACE",
    "parseTenzroDid",
    "isTenzroDid",
    "buildHumanDid",
    "buildAutonomousMachineDid",
    "buildDelegatedMachineDid",
    "ParsedTenzroDid",
    "TenzroDidClass",
    "KeyStorage",
    "RecoveryGuardian",
    "RecoveryProposal",
    "StorageCapabilities",
    // The separate AI packages; tenzro-sdk is the one TypeScript SDK.
    "@tenzro/ai-provider",
    "@tenzro/ai-react",
    "\"@tenzro/ai\"",
    // Single-URL network configs; clients find the network's operators on chain.
    "MAINNET_CONFIG",
    "TESTNET_CONFIG",
    "SdkConfig::testnet",
    "SdkConfig::mainnet",
];

fn sources() -> Vec<(String, String)> {
    gate::workspace_sources()
}

fn before_tests(text: &str) -> String {
    gate::before_tests(text)
}

fn non_test(text: &str) -> String {
    gate::non_test(text)
}

#[test]
fn no_forbidden_marker_appears_in_non_test_code() {
    let mut found = Vec::new();
    for (file, text) in sources() {
        let code = non_test(&text);
        for m in FORBIDDEN {
            if code.contains(m) {
                found.push(format!("{file}: {m}"));
            }
        }
        if before_tests(&text)
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|w| w == "TODO")
        {
            found.push(format!("{file}: TODO"));
        }
    }
    assert!(
        found.is_empty(),
        "legacy markers found:\n  {}",
        found.join("\n  ")
    );
}

#[test]
fn each_placeholder_stays_in_the_files_the_allow_list_names() {
    let sources = sources();
    let mut problems = Vec::new();
    for (name, marker, allowed) in PLACEHOLDERS {
        let mut seen_in_allowed = false;
        for (file, text) in &sources {
            if !non_test(text).contains(marker) {
                continue;
            }
            if allowed.contains(&file.as_str()) {
                seen_in_allowed = true;
            } else {
                problems.push(format!("{name}: {marker} appears in {file}"));
            }
        }
        if !seen_in_allowed {
            problems.push(format!(
                "{name}: {marker} is gone; drop it from the allow-list"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "placeholder sweep:\n  {}",
        problems.join("\n  ")
    );
}

/// Name segments that mark an old path, a compatibility layer or a migration.
const LEGACY_SEGMENTS: &[&str] = &[
    "deprecated",
    "deprecate",
    "legacy",
    "compat",
    "fallback",
    "fallbacks",
    "v1",
    "shim",
    "shims",
    "migration",
    "migrations",
    "migrate",
];

/// Names carrying a legacy segment that are not old paths: (name, file,
/// reason). External protocol versions that live networks still run are
/// declared here, one module each, version named per route.
const LEGACY_NAME_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "TokenTransferV1",
        "crates/tenzro-bridge/src/route/evm.rs",
        "CCIP wire struct, versioned by the CCIP protocol",
    ),
    (
        "MessageV1",
        "crates/tenzro-bridge/src/route/evm.rs",
        "CCIP wire struct, versioned by the CCIP protocol",
    ),
    (
        "read_v1_5",
        "crates/tenzro-bridge/src/route/evm.rs",
        "CCIP 1.5 lanes still run on live networks",
    ),
    (
        "refuse_v1_5",
        "crates/tenzro-bridge/src/route/evm.rs",
        "CCIP 1.5 lanes still run on live networks",
    ),
    (
        "encode_outbound_v1_6",
        "crates/tenzro-bridge/src/route/evm.rs",
        "CCIP 1.6 lanes",
    ),
    (
        "decode_outbound_v1_6",
        "crates/tenzro-bridge/src/route/evm.rs",
        "CCIP 1.6 lanes",
    ),
    (
        "message_id_v1_6",
        "crates/tenzro-bridge/src/route/evm.rs",
        "CCIP 1.6 lanes",
    ),
    (
        "V1_5",
        "crates/tenzro-types/src/bridge_route.rs",
        "CCIP version declared per route",
    ),
    (
        "V1_5",
        "crates/tenzro-node/src/mcp/tool_types_chain.rs",
        "CCIP version of a route, as the governance tool schema shows it",
    ),
    (
        "V1_6",
        "crates/tenzro-node/src/mcp/tool_types_chain.rs",
        "CCIP version of a route, as the governance tool schema shows it",
    ),
    (
        "V1_5",
        "crates/tenzro-node/src/mcp/tool_types_payments.rs",
        "CCIP version of a lane, as the bridge tool schema shows it",
    ),
    (
        "V1_6",
        "crates/tenzro-node/src/mcp/tool_types_payments.rs",
        "CCIP version of a lane, as the bridge tool schema shows it",
    ),
    (
        "V1_6",
        "crates/tenzro-types/src/bridge_route.rs",
        "CCIP version declared per route",
    ),
    (
        "HPKE_V1",
        "crates/tenzro-device-key/src/hpke.rs",
        "RFC 9180 suite label",
    ),
    (
        "POLICY_MIGRATE_MA",
        "crates/tenzro-tee/src/verify/snp.rs",
        "AMD SEV-SNP guest policy bit, refused",
    ),
    (
        "force_fallback_adapter",
        "crates/tenzro-model/src/moe_compute_wgpu.rs",
        "wgpu adapter request field",
    ),
    (
        "alpenglow_migration_succeeded",
        "crates/tenzro-vm/src/svm/full.rs",
        "Solana runtime feature state",
    ),
    (
        "Fallback",
        "crates/tenzro-vm/src/aa_validators.rs",
        "ERC-7579 module type 3",
    ),
    (
        "MODULE_TYPE_FALLBACK",
        "crates/tenzro-vm/src/erc7579.rs",
        "ERC-7579 module type 3",
    ),
];

/// Splits an identifier into lower-case segments (`snake_case` and
/// `camelCase`), joining `v` with the number after it.
fn segments(name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in name.split('_').filter(|p| !p.is_empty()) {
        let mut cur = String::new();
        let chars: Vec<char> = part.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            let boundary = !cur.is_empty()
                && ((c.is_ascii_uppercase()
                    && (cur.chars().last().is_some_and(|p| !p.is_ascii_uppercase())
                        || chars.get(i + 1).is_some_and(|n| n.is_ascii_lowercase())))
                    || (c.is_ascii_digit()
                        != cur.chars().last().is_some_and(|p| p.is_ascii_digit())));
            if boundary {
                out.push(std::mem::take(&mut cur).to_ascii_lowercase());
            }
            cur.push(c);
        }
        if !cur.is_empty() {
            out.push(cur.to_ascii_lowercase());
        }
    }
    let mut joined = Vec::new();
    let mut i = 0;
    while i < out.len() {
        if out[i] == "v"
            && out
                .get(i + 1)
                .is_some_and(|n| n.chars().all(|c| c.is_ascii_digit()))
        {
            joined.push(format!("v{}", out[i + 1]));
            i += 2;
        } else {
            joined.push(out[i].clone());
            i += 1;
        }
    }
    joined
}

fn ident_at(s: &str) -> &str {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    &s[..end]
}

/// Code with string literals blanked, so only names remain.
fn without_strings(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut in_str = false;
    let mut escape = false;
    for c in code.chars() {
        if in_str {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
                out.push('"');
            } else if c == '\n' {
                out.push('\n');
            }
            continue;
        }
        if c == '"' {
            in_str = true;
        }
        out.push(c);
    }
    out
}

/// Declared names in a source: items after a declaring keyword (`old` counts
/// here), plus fields and enum variants (where `old` is a before/after value,
/// not an old path).
fn declared_names(code: &str) -> Vec<(String, bool)> {
    const KEYWORDS: &[&str] = &[
        "fn",
        "struct",
        "enum",
        "trait",
        "type",
        "const",
        "static",
        "mod",
        "function",
        "class",
        "interface",
        "def",
    ];
    let mut out = Vec::new();
    for line in code.lines() {
        let words: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || c == '(' || c == '<')
            .collect();
        for w in words.windows(2) {
            if KEYWORDS.contains(&w[0]) {
                let id = ident_at(w[1]);
                if !id.is_empty() {
                    out.push((id.to_string(), true));
                }
            }
        }
        let mut t = line.trim_start();
        for vis in ["pub(crate) ", "pub(super) ", "pub ", "readonly "] {
            t = t.strip_prefix(vis).unwrap_or(t);
        }
        let id = ident_at(t);
        let rest = t[id.len()..].trim_start();
        if !id.is_empty()
            && !KEYWORDS.contains(&id)
            && (rest.starts_with(':') && !rest.starts_with("::") || rest.starts_with("?:"))
        {
            out.push((id.to_string(), false));
        }
        if id.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && (rest.starts_with(',')
                || rest.starts_with('(')
                || rest.starts_with('{')
                || rest.starts_with('='))
        {
            out.push((id.to_string(), false));
        }
    }
    out
}

#[test]
fn the_segmenter_reads_snake_and_camel_case() {
    assert_eq!(
        segments("encode_outbound_v1_6"),
        ["encode", "outbound", "v1", "6"]
    );
    assert_eq!(segments("TokenTransferV1"), ["token", "transfer", "v1"]);
    assert_eq!(segments("HPKE_V1"), ["hpke", "v1"]);
    assert_eq!(
        segments("InlineFallbackBackend"),
        ["inline", "fallback", "backend"]
    );
    assert_eq!(segments("old_epoch"), ["old", "epoch"]);
    assert!(!segments("threshold").contains(&"old".to_string()));
}

#[test]
fn no_item_is_named_for_an_old_path() {
    let mut found = BTreeSet::new();
    let mut allowed_seen = BTreeSet::new();
    for (file, text) in sources() {
        let code = without_strings(&non_test(&text));
        for (name, is_item) in declared_names(&code) {
            let segs = segments(&name);
            let legacy = segs.iter().any(|s| LEGACY_SEGMENTS.contains(&s.as_str()))
                || (is_item && segs.iter().any(|s| s == "old"));
            if !legacy {
                continue;
            }
            if LEGACY_NAME_ALLOWED
                .iter()
                .any(|(n, f, _)| *n == name && *f == file)
            {
                allowed_seen.insert(format!("{name}@{file}"));
                continue;
            }
            found.insert(format!("{file}: {name}"));
        }
    }
    let stale: Vec<String> = LEGACY_NAME_ALLOWED
        .iter()
        .map(|(n, f, _)| format!("{n}@{f}"))
        .filter(|k| !allowed_seen.contains(k))
        .collect();
    assert!(
        stale.is_empty(),
        "LEGACY_NAME_ALLOWED names nothing in its file any more: {stale:?}"
    );
    assert!(
        found.is_empty(),
        "{} names mark an old path, compatibility layer, fallback or migration:\n  {}",
        found.len(),
        found.into_iter().collect::<Vec<_>>().join("\n  ")
    );
}

#[test]
fn no_feature_flag_is_named_for_an_old_path() {
    let root = gate::repo_root();
    let mut manifests = vec![
        root.join("Cargo.toml"),
        root.join("sdk/tenzro-sdk/Cargo.toml"),
        root.join("sdk/tenzro-py/native/Cargo.toml"),
    ];
    for c in std::fs::read_dir(root.join("crates"))
        .expect("crates dir")
        .flatten()
    {
        manifests.push(c.path().join("Cargo.toml"));
    }
    let mut found = Vec::new();
    for m in manifests {
        let Ok(text) = std::fs::read_to_string(&m) else {
            continue;
        };
        let mut in_features = false;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_features = t == "[features]";
                continue;
            }
            if !in_features || t.starts_with('#') {
                continue;
            }
            let Some((name, _)) = t.split_once('=') else {
                continue;
            };
            let name = name.trim().trim_matches('"');
            let segs = segments(&name.replace('-', "_"));
            if segs
                .iter()
                .any(|s| LEGACY_SEGMENTS.contains(&s.as_str()) || s == "old")
            {
                found.push(format!(
                    "{}: {name}",
                    m.strip_prefix(&root).unwrap_or(&m).display()
                ));
            }
        }
    }
    assert!(
        found.is_empty(),
        "feature flags named for an old path:\n  {}",
        found.join("\n  ")
    );
}

/// `tenzro_`-prefixed names that are not methods: extension fields the node
/// adds to OpenAI-compatible response bodies.
const RESPONSE_FIELDS: &[&str] = &["tenzro_contentProvenance"];

/// Client surfaces and docs that name RPC methods.
const CALLERS: &[(&[&str], &[&str])] = &[
    (
        &[
            "crates/tenzro-cli/src",
            "crates/tenzro-node/src/mcp",
            "sdk/tenzro-sdk/src",
            "apps/tenzro-control/src-tauri/src",
        ],
        &[".rs"],
    ),
    (&["sdk/tenzro-py/tenzro", "skills"], &[".py"]),
    (
        &[
            "sdk/tenzro-ts-sdk/src",
            "sdk/tenzro-ts-sdk/packages",
            "apps/tenzro-control/src",
        ],
        &[".ts", ".tsx"],
    ),
    (
        &[
            "docs",
            "crates",
            "sdk/tenzro-ts-sdk",
            "sdk/tenzro-py",
            "skills",
        ],
        &[".md"],
    ),
];

#[test]
fn no_surface_or_doc_names_a_method_the_node_does_not_serve() {
    let methods = gate::rpc_methods();
    let placeholder = |m: &str| {
        PLACEHOLDERS
            .iter()
            .any(|(_, marker, _)| m.starts_with(marker))
    };
    let mut found = BTreeSet::new();
    for (dirs, exts) in CALLERS {
        for (file, text) in gate::files(dirs, exts) {
            let text = if file.ends_with(".md") {
                text.replace('`', "\"")
            } else {
                gate::before_tests(&text)
            };
            let names: BTreeSet<String> = if file.ends_with(".md") {
                text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .filter(|w| w.starts_with("tenzro_") && gate::is_rpc_name(w))
                    .map(str::to_string)
                    .collect()
            } else {
                gate::rpc_names_in(&file, &text)
            };
            for n in names {
                // `eth_` names are also served by every external EVM chain the
                // bridge and CLI read, so only the node's own namespace counts.
                if n.starts_with("tenzro_")
                    && !methods.contains(&n)
                    && !placeholder(&n)
                    && !RESPONSE_FIELDS.contains(&n.as_str())
                {
                    found.insert(format!("{file}: {n}"));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "{} references to methods the node does not serve (removed RPCs must be gone everywhere):\n  {}",
        found.len(),
        found.into_iter().collect::<Vec<_>>().join("\n  ")
    );
}

/// Names of removed surfaces: retired domains, removed flags, types, tools,
/// SDK calls and CLI commands. A client, doc or source that names one is
/// describing something the network no longer has.
const REMOVED_NAMES: &[&str] = &[
    // Domains that are not the network's.
    "network.tenzro.com",
    "tenzro.net",
    // The ecosystem MCP servers the node no longer runs.
    "solana-mcp.tenzro",
    "ethereum-mcp.tenzro",
    "lifi-mcp.tenzro",
    "layerzero-mcp.tenzro",
    // Agent runtime, swarms and the template marketplace.
    "SwarmManager",
    "create_swarm",
    "createSwarm",
    "Agent-Swarm Spec",
    "spawn_from_template",
    "registerAgentTemplate",
    "spawnAgentFromTemplate",
    // Spend and bond reads replaced by consensus state.
    "getAgentDailySpend",
    "ComputeBondManager",
    // The Python MCP and A2A packages; every node serves both.
    "integrations/mcp",
    "integrations/a2a",
    "tenzro_mcp_server",
    "tenzro_a2a_server",
    // Shared-secret and Hub credentials.
    "HF_TOKEN",
    "HS256",
    // x402 v1 headers and the AP2 mandate-pair path.
    "X-PAYMENT:",
    "feature = \"ap2\"",
    "EscrowResolver",
    // Server-created wallets, node-side signing, token creation and webhooks.
    "create_wallet",
    "createWallet",
    "wallet.signAndSend",
    "create_token",
    "register_webhook",
    "registerWebhook",
    // The upstream DID resolver: a node answers from its own state.
    "did_upstream_rpc",
    "RemoteDidResolutionBackend",
    "DidResolutionBackend",
    // CLI commands that are gone.
    "tenzro provider register",
    "tenzro agent create-swarm",
    "tenzro shell ",
    // Roles testnet v1 does not have, and their node-local registries.
    "DatabaseProvider",
    "CloudProvider",
    "CloudTier",
    "--cloud-tier",
    "SecureMintRegistry",
    "StableAssetRegistry",
    "tenzro_setSecureMintPolicy",
    "tenzro_mintStableAsset",
    "x402.org",
    // Applications that run in harnesses over the public surface: the task
    // market, refund-window purchases with their disputes and resolver
    // pool, and the training network.
    "TaskMarket",
    "task_market",
    "tenzro_listTasks",
    "tenzro_getTask",
    "EscrowAction",
    "RefundWindow",
    "tenzro_getPurchase",
    "tenzro_listResolvers",
    "TrainingOp",
    "tenzro_training_",
    "tenzro task ",
    "tenzro purchase ",
    "tenzro train ",
    // The reputation ledger: standing is read from bonds and SLA verdicts.
    "tenzro_getAgentReputation",
    "get_agent_reputation",
    "ReputationLedger",
    "AgentReputation",
    // Organization terms templates are kept by applications.
    "SetOrgTemplate",
    "set_org_template",
    // The media job market: a node renders; queues, workers and receipts
    // are kept by applications.
    "tenzro-media-gen",
    "tenzro_media_gen",
    "MediaGenRuntime",
    "MediaGenReceipt",
    "MediaGenTaskSpec",
    "tenzro_mediaGen_postJob",
    "tenzro_mediaGen_getJob",
    "tenzro_mediaGen_listJobs",
    "tenzro_mediaGen_cancelJob",
    "tenzro_mediaGen_listWorkers",
    "tenzro_mediaGen_getReceipt",
    "tenzro_mediaGen_fetchOutput",
    "tenzro_mediaGen_quote",
    "tenzro/media-gen",
    // Crates, apps and pools that are gone: the desktop app (the control app
    // replaced it), the agent kit and the workflow crate (agents and
    // workflows run in harnesses), and the liquid-staking pool.
    "tenzro-desktop",
    "tenzro-agent-kit",
    "tenzro-workflow",
    "workflow_receipt_template",
    "LiquidStakingPool",
    "liquid_staking",
    "stTNZO",
    "StakingManager",
    // The tenant file layer runs in harnesses beside a storage provider.
    "tenzro_uploadFile",
    "tenzro_listFiles",
    "tenzro_getFile",
    "tenzro_downloadFile",
    "tenzro_deleteFile",
    "tenzro_fileStorageUsage",
    "FilesClient",
    "storage_access",
    "tenzro files ",
    // The Travel Rule endpoint runs in harnesses.
    "TravelRuleStore",
    "trp_router",
    "payments.travel_rule",
];

/// Where [`REMOVED_NAMES`] are searched, besides the root documents.
const REMOVED_SCAN_DIRS: &[&str] = &[
    "sdk",
    "crates",
    "integrations",
    "skills",
    "apps/tenzro-control/src",
    "apps/tenzro-control/src-tauri/src",
    "docs",
    "scripts",
    "templates",
    "tools",
    "deploy",
    ".github",
];

/// Root files searched for [`REMOVED_NAMES`] and for paths to crates and apps.
const ROOT_FILES: &[&str] = &[
    "README.md",
    "CONTRIBUTING.md",
    "BENCHMARKS.md",
    "SECURITY.md",
    "Dockerfile",
    "Dockerfile.cuda",
    "Dockerfile.rocm",
    "Dockerfile.vulkan",
    ".dockerignore",
    ".gitignore",
    "deny.toml",
];

/// The dev tree's assistant instruction file, swept like a root file when it
/// is present (it never ships; stored reversed, so this file never reads as a
/// citation of it).
const ASSISTANT_FILE_REVERSED: &str = "dm.EDUALC";

/// The searched texts: the scan directories' sources and docs, and the root files.
fn scanned_texts() -> Vec<(String, String)> {
    let mut texts = gate::files(
        REMOVED_SCAN_DIRS,
        &[".rs", ".ts", ".tsx", ".py", ".md", ".sh", ".toml", ".yml"],
    );
    // Operator dashboards name the metrics a node exports.
    texts.extend(gate::files(&["deploy"], &[".json"]));
    let assistant_file: String = ASSISTANT_FILE_REVERSED.chars().rev().collect();
    for doc in ROOT_FILES.iter().copied().chain([assistant_file.as_str()]) {
        if let Ok(text) = std::fs::read_to_string(gate::repo_root().join(doc)) {
            texts.push((doc.to_string(), text));
        }
    }
    texts
}

#[test]
fn no_surface_names_a_removed_surface() {
    let mut found = Vec::new();
    for (file, text) in scanned_texts() {
        let text = if file.ends_with(".rs") {
            gate::before_tests(&text)
        } else {
            text
        };
        for name in REMOVED_NAMES {
            if text.contains(name) {
                found.push(format!("{file}: {name}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "removed surfaces named:\n  {}",
        found.join("\n  ")
    );
}

/// A path to a workspace crate or app (`crates/tenzro-...`, `apps/tenzro-...`)
/// named in a doc, script, build file or source: each must exist, so a
/// removed or renamed crate leaves no instructions behind.
#[test]
fn every_crate_and_app_path_named_exists() {
    let root = gate::repo_root();
    let mut found = BTreeSet::new();
    for (file, text) in scanned_texts() {
        for prefix in ["crates/tenzro-", "apps/tenzro-"] {
            let mut rest = text.as_str();
            while let Some(i) = rest.find(prefix) {
                let before = rest[..i].chars().next_back();
                let tail = &rest[i..];
                let end = tail[prefix.len()..]
                    .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
                    .map_or(tail.len(), |e| e + prefix.len());
                let path = tail[..end].trim_end_matches('-');
                rest = &tail[end..];
                if before.is_some_and(|c| {
                    c.is_ascii_alphanumeric()
                        || c == '/'
                        || c == '@'
                        || c == '-'
                        || c == '_'
                        || c == '.'
                }) {
                    continue;
                }
                if !root.join(path).exists() {
                    found.insert(format!("{file}: {path}"));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "paths to crates or apps that do not exist:\n  {}",
        found.into_iter().collect::<Vec<_>>().join("\n  ")
    );
}

/// Registered MCP tool names: the node's typed tools and its mirrored RPC
/// table.
fn mcp_tools() -> BTreeSet<String> {
    let root = gate::repo_root();
    let mut tools = BTreeSet::new();
    for (_, text) in gate::files(&["crates/tenzro-node/src/mcp"], &[".rs"]) {
        // A `#[tool]` / `#[tool(...)]` attribute, then the handler's `fn`;
        // `name = "..."` in the attribute overrides the function name.
        let mut attr: Option<String> = None;
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with("#[tool]") || l.starts_with("#[tool(") {
                attr = Some(String::new());
            }
            let Some(a) = attr.as_mut() else { continue };
            let sig = l.trim_start_matches("pub ").trim_start_matches("async ");
            if let Some(f) = sig.strip_prefix("fn ") {
                let name = match a.find("name = \"") {
                    Some(n) => a[n + 8..].split('"').next().unwrap_or("").to_string(),
                    None => f
                        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .next()
                        .unwrap_or("")
                        .to_string(),
                };
                tools.insert(name);
                attr = None;
            } else {
                a.push_str(l);
                a.push('\n');
            }
        }
    }
    let mirror = std::fs::read_to_string(root.join("crates/tenzro-node/src/mcp/rpc_tools.rs"))
        .expect("rpc_tools.rs");
    for line in mirror.lines() {
        if let Some(v) = line.trim().strip_prefix("name: \"") {
            tools.insert(v.split('"').next().unwrap_or("").to_string());
        }
    }
    assert!(
        tools.len() > 300,
        "MCP tool tables not found ({})",
        tools.len()
    );
    tools
}

/// Backticked snake_case names in `cell`.
fn tool_names(cell: &str) -> Vec<&str> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .filter(|w| {
            w.contains('_')
                && w.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        .collect()
}

#[test]
fn mcp_docs_name_only_registered_tools() {
    let root = gate::repo_root();
    let tools = mcp_tools();
    let mut found = Vec::new();
    // The server's own instructions list tools as `• name — ...`.
    let server = std::fs::read_to_string(root.join("crates/tenzro-node/src/mcp/server.rs"))
        .expect("server.rs");
    for line in server.lines() {
        if let Some(rest) = line.trim().strip_prefix("• ") {
            let name = rest.split(' ').next().unwrap_or("");
            if !tools.contains(name) {
                found.push(format!("mcp/server.rs instructions: {name}"));
            }
        }
    }
    // The node README's MCP tool table.
    let node =
        std::fs::read_to_string(root.join("crates/tenzro-node/README.md")).expect("node README");
    let start = node.find("## MCP Server").expect("node README MCP section");
    let section = &node[start..];
    let section = &section[..section[3..].find("\n## ").map_or(section.len(), |e| e + 3)];
    for line in section.lines().filter(|l| l.starts_with("| **")) {
        for name in tool_names(line) {
            if !tools.contains(name) {
                found.push(format!("crates/tenzro-node/README.md: {name}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "MCP docs name tools that are not registered:\n  {}",
        found.join("\n  ")
    );
}
