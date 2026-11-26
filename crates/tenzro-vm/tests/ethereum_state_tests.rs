//! Ethereum state tests run through the EVM executor.
//!
//! A state test names a pre-state, one transaction and, per rule set, the
//! state and logs the transaction must leave. Each case here is loaded into a
//! fresh [`StateAdapter`], executed by [`EvmExecutor`] exactly as a block
//! executes an EVM transaction, and compared account by account with the
//! expected post-state.
//!
//! Two things in the fixtures have no counterpart on this ledger and are
//! handled the same way for every case:
//!
//! - No fee is credited to a block beneficiary, so the beneficiary's balance
//!   is not compared.
//! - A case this ledger cannot express (a blob transaction, a balance or a
//!   value above 128 bits, an authorization whose signature does not fit the
//!   transaction format) is reported as not applicable and never as a pass.
//!
//! The block environment an EVM transaction sees on this ledger is narrower
//! than a fixture's: no beneficiary, no `PREVRANDAO` value and no blob fee
//! come from the block. A case that reads one of them is a recorded
//! mismatch, as is every case where the engine itself departs from the rule
//! set. `tests/state_tests_expected/` holds that record, one file per rule
//! set.
//!
//! The executor runs one of two engines ([`Rules`]): the first under Prague
//! until `feature.evm_osaka` is live, the second under Osaka from then on.
//! Each side is held against the fixtures of its own rule set.
//!
//! `the_vendored_sample_passes` runs a few fixtures kept beside this file.
//! `ethereum_state_tests` and `ethereum_state_tests_osaka` run a whole
//! fixture release each and are driven by `scripts/tests/evm-state-tests.sh`,
//! which fetches the pinned releases.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use sha3::{Digest, Keccak256};
use tenzro_vm::account_abstraction::{Eip7702Authorization, U256};
use tenzro_vm::precompiles::PrecompileRegistry;
use tenzro_vm::traits::VmState;
use tenzro_vm::{EvmExecutor, GasOracle, StateAdapter, VmConfig, VmTransaction, VmType};

/// The rule set a case runs under, which is also the engine that runs it.
#[derive(Debug, Clone, Copy)]
enum Rules {
    /// The first engine under Prague alone: `feature.evm_osaka` dormant.
    Prague,
    /// The engine of the Osaka rule set: `feature.evm_osaka` live.
    Osaka,
}

impl Rules {
    /// The name the fixtures give the rule set.
    fn fork(self) -> &'static str {
        match self {
            Rules::Prague => "Prague",
            Rules::Osaka => "Osaka",
        }
    }

    /// The governed gate that, live, puts the executor under this rule set.
    fn gate(self) -> &'static str {
        match self {
            Rules::Prague => tenzro_vm::evm::PRAGUE_ONLY_KEY,
            Rules::Osaka => tenzro_vm::evm::OSAKA_KEY,
        }
    }

    /// The record of this rule set's cases that are not a pass.
    fn expected(self) -> PathBuf {
        let file = match self {
            Rules::Prague => "prague.tsv",
            Rules::Osaka => "osaka.tsv",
        };
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/state_tests_expected")
            .join(file)
    }
}

/// What one case came to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Pass,
    /// The executor's result differs from the fixture's; the text says where.
    Mismatch(String),
    /// The ledger cannot express the case.
    NotApplicable(&'static str),
}

impl Outcome {
    fn label(&self) -> String {
        match self {
            Outcome::Pass => "PASS".into(),
            Outcome::Mismatch(why) => format!("MISMATCH:{why}"),
            Outcome::NotApplicable(why) => format!("NA:{why}"),
        }
    }
}

fn strip(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn bytes(v: &Value) -> Vec<u8> {
    let s = strip(v.as_str().unwrap_or(""));
    if s.len() % 2 == 1 {
        hex::decode(format!("0{s}")).expect("hex")
    } else {
        hex::decode(s).expect("hex")
    }
}

fn u256(v: &Value) -> U256 {
    let s = strip(v.as_str().unwrap_or(""));
    if s.is_empty() {
        U256::ZERO
    } else {
        U256::from_str_radix(s, 16).expect("hex quantity")
    }
}

fn word(v: U256) -> [u8; 32] {
    v.to_be_bytes::<32>()
}

fn address(v: &Value) -> [u8; 20] {
    let b = bytes(v);
    let mut out = [0u8; 20];
    out.copy_from_slice(&b);
    out
}

/// Why a case whose accounts or destination sit at a Tenzro precompile
/// address is not applicable: the network serves its own precompile there,
/// so the fixture's account is never reached.
const AT_TENZRO_PRECOMPILE: &str = "an account at a Tenzro precompile address";

/// Whether the network serves a precompile of its own at `addr`.
fn is_tenzro_precompile(addr: &[u8; 20]) -> bool {
    static TENZRO: std::sync::LazyLock<tenzro_vm::precompiles::PrecompileRegistry> =
        std::sync::LazyLock::new(tenzro_vm::precompiles::PrecompileRegistry::new);
    TENZRO.is_precompile(addr)
}

/// Loads a fixture account set into `state`. `Err` names what the ledger
/// cannot hold, or an account the network's own precompiles shadow.
fn load(state: &mut StateAdapter, accounts: &Value) -> Result<(), &'static str> {
    for (addr, account) in accounts.as_object().expect("accounts") {
        let addr = address(&Value::String(addr.clone()));
        if is_tenzro_precompile(&addr) {
            return Err(AT_TENZRO_PRECOMPILE);
        }
        let balance =
            u128::try_from(u256(&account["balance"])).map_err(|_| "balance above 128 bits")?;
        state.set_balance(&addr, balance);
        let nonce = u64::try_from(u256(&account["nonce"])).map_err(|_| "nonce above 64 bits")?;
        state.set_nonce(&addr, nonce);
        let code = bytes(&account["code"]);
        if !code.is_empty() {
            state.set_code(&addr, code);
        }
        for (key, value) in account["storage"].as_object().expect("storage") {
            let key = word(u256(&Value::String(key.clone())));
            state.set_storage(&addr, &key, word(u256(value)).to_vec());
        }
    }
    Ok(())
}

/// The transaction a case names, or why the ledger's transaction format
/// cannot carry it.
fn transaction(test: &Value, post: &Value) -> Result<VmTransaction, &'static str> {
    let tx = &test["transaction"];
    if tx.get("maxFeePerBlobGas").is_some() || tx.get("blobVersionedHashes").is_some() {
        return Err("blob transaction");
    }
    let index = |name: &str| post["indexes"][name].as_u64().expect("index") as usize;
    let (d, g, v) = (index("data"), index("gas"), index("value"));
    let base_fee = u256(&test["env"]["currentBaseFee"]);
    let price = match tx.get("gasPrice") {
        Some(price) => u256(price),
        None => u256(&tx["maxFeePerGas"])
            .min(base_fee.saturating_add(u256(&tx["maxPriorityFeePerGas"]))),
    };
    let to = bytes(&tx["to"]);
    if <[u8; 20]>::try_from(to.as_slice()).is_ok_and(|a| is_tenzro_precompile(&a)) {
        return Err(AT_TENZRO_PRECOMPILE);
    }
    let mut out = VmTransaction::new(
        bytes(&tx["sender"]),
        (!to.is_empty()).then_some(to),
        u128::try_from(u256(&tx["value"][v])).map_err(|_| "value above 128 bits")?,
        bytes(&tx["data"][d]),
        u64::try_from(u256(&tx["gasLimit"][g])).map_err(|_| "gas limit above 64 bits")?,
        u128::try_from(price).map_err(|_| "gas price above 128 bits")?,
        u64::try_from(u256(&tx["nonce"])).map_err(|_| "nonce above 64 bits")?,
        VmType::Evm,
        u64::try_from(u256(&test["config"]["chainid"])).map_err(|_| "chain id above 64 bits")?,
    );
    out.block_height = Some(
        u64::try_from(u256(&test["env"]["currentNumber"])).map_err(|_| "height above 64 bits")?,
    );
    let seconds = i64::try_from(u256(&test["env"]["currentTimestamp"]))
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .ok_or("timestamp above the ledger's range")?;
    out.block_timestamp_ms = Some(seconds);
    out.block_base_fee = Some(u128::try_from(base_fee).map_err(|_| "base fee above 128 bits")?);
    if let Some(list) = tx
        .get("accessLists")
        .and_then(|l| l.get(d))
        .and_then(Value::as_array)
    {
        for entry in list {
            let keys = entry["storageKeys"]
                .as_array()
                .expect("storage keys")
                .iter()
                .map(|k| word(u256(k)))
                .collect();
            out.access_list.push((address(&entry["address"]), keys));
        }
    }
    if let Some(list) = tx.get("authorizationList").and_then(Value::as_array) {
        for entry in list {
            let parity = u8::try_from(u256(entry.get("yParity").unwrap_or(&entry["v"])))
                .map_err(|_| "authorization parity above one byte")?;
            let mut signature = Vec::with_capacity(65);
            signature.extend_from_slice(&word(u256(&entry["r"])));
            signature.extend_from_slice(&word(u256(&entry["s"])));
            signature.push(parity);
            out.authorization_list.push(Eip7702Authorization {
                chain_id: u256(&entry["chainId"]),
                delegate_address: bytes(&entry["address"]),
                nonce: u64::try_from(u256(&entry["nonce"]))
                    .map_err(|_| "authorization nonce above 64 bits")?,
                signature,
            });
        }
    }
    Ok(out)
}

/// `keccak256(rlp(logs))`, the form a fixture states its logs in.
fn logs_hash(logs: &[tenzro_vm::types::Log]) -> [u8; 32] {
    let mut stream = rlp::RlpStream::new_list(logs.len());
    for log in logs {
        stream.begin_list(3);
        stream.append(&log.address);
        stream.begin_list(log.topics.len());
        for topic in &log.topics {
            stream.append(topic);
        }
        stream.append(&log.data);
    }
    Keccak256::digest(stream.out()).into()
}

/// Storage slots a fixture account names.
fn slots(account: Option<&Value>) -> BTreeSet<[u8; 32]> {
    account
        .and_then(|a| a["storage"].as_object())
        .map(|s| {
            s.keys()
                .map(|k| word(u256(&Value::String(k.clone()))))
                .collect()
        })
        .unwrap_or_default()
}

fn stored(state: &StateAdapter, addr: &[u8; 20], slot: &[u8; 32]) -> [u8; 32] {
    state
        .get_storage(addr, slot)
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .unwrap_or([0u8; 32])
}

/// Runs one case under `rules` and returns its outcome with a digest of
/// everything the executor produced (result, gas, logs and every account the
/// fixture names), so two engines can be compared case by case.
fn run_case(test: &Value, post: &Value, rules: Rules) -> (Outcome, [u8; 32]) {
    let mut digest = Keccak256::new();
    let mut state = StateAdapter::new();
    if let Err(why) = load(&mut state, &test["pre"]) {
        return (Outcome::NotApplicable(why), digest.finalize().into());
    }
    let tx = match transaction(test, post) {
        Ok(tx) => tx,
        Err(why) => return (Outcome::NotApplicable(why), digest.finalize().into()),
    };
    state.set_storage(
        &tenzro_vm::native::SYSTEM_ADDRESS,
        tenzro_vm::native::governed_param_key(rules.gate()).as_bytes(),
        0u64.to_le_bytes().to_vec(),
    );
    let config = VmConfig {
        max_gas_limit: u64::try_from(u256(&test["env"]["currentGasLimit"])).unwrap_or(u64::MAX),
        chain_id: tx.chain_id,
        ..VmConfig::default()
    };
    let executor = EvmExecutor::new(
        config,
        Arc::new(GasOracle::new()),
        Arc::new(PrecompileRegistry::new()),
    )
    .expect("executor");
    let result = executor.execute_with_revm(&tx, &mut state);

    let mut first_difference: Option<String> = None;
    let mut differ = |why: String| {
        first_difference.get_or_insert(why);
    };
    let expects_rejection = post.get("expectException").is_some();
    match &result {
        Ok(executed) => {
            digest.update([1, u8::from(executed.success)]);
            digest.update(executed.gas_used.to_be_bytes());
            let logs = logs_hash(&executed.logs);
            digest.update(logs);
            if expects_rejection {
                differ("executed, the fixture expects a rejection".into());
            } else if logs.as_slice() != bytes(&post["logs"]).as_slice() {
                differ("logs".into());
            }
        }
        Err(_) => {
            digest.update([0]);
            if !expects_rejection {
                differ("rejected, the fixture expects an execution".into());
            }
        }
    }

    let beneficiary = address(&test["env"]["currentCoinbase"]);
    let empty = serde_json::Map::new();
    let pre = test["pre"].as_object().expect("pre");
    let expected = post["state"].as_object().unwrap_or(&empty);
    let named: BTreeSet<&String> = pre.keys().chain(expected.keys()).collect();
    for name in named {
        let addr = address(&Value::String(name.clone()));
        let want = expected.get(name);
        let balance = state.get_balance(&addr);
        let nonce = state.get_nonce(&addr);
        let code = state.get_code(&addr).unwrap_or_default();
        digest.update(addr);
        digest.update(balance.to_be_bytes());
        digest.update(nonce.to_be_bytes());
        digest.update(Keccak256::digest(&code));
        let want_balance = want.map_or(U256::ZERO, |a| u256(&a["balance"]));
        if addr != beneficiary && U256::from(balance) != want_balance {
            differ(format!("balance of {name}"));
        }
        if U256::from(nonce) != want.map_or(U256::ZERO, |a| u256(&a["nonce"])) {
            differ(format!("nonce of {name}"));
        }
        if code != want.map_or(Vec::new(), |a| bytes(&a["code"])) {
            differ(format!("code of {name}"));
        }
        let mut keys = slots(pre.get(name));
        keys.extend(slots(want));
        for key in keys {
            let have = stored(&state, &addr, &key);
            digest.update(key);
            digest.update(have);
            let slot = format!("0x{}", hex::encode(key));
            let want_value = want
                .and_then(|a| a["storage"].as_object())
                .and_then(|s| {
                    s.iter()
                        .find(|(k, _)| word(u256(&Value::String((*k).clone()))) == key)
                        .map(|(_, v)| word(u256(v)))
                })
                .unwrap_or([0u8; 32]);
            if have != want_value {
                differ(format!("storage of {name} at {slot}"));
            }
        }
    }
    let outcome = match first_difference {
        Some(why) => Outcome::Mismatch(why),
        None => Outcome::Pass,
    };
    (outcome, digest.finalize().into())
}

/// One line per case: its id, its outcome and its digest.
type Outcomes = BTreeMap<String, (Outcome, [u8; 32])>;

fn fixture_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            fixture_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

/// Runs every case one fixture file holds for `rules`.
fn run_file(root: &Path, path: &Path, rules: Rules) -> Outcomes {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let fixture: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let file = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    let mut out = Outcomes::new();
    for (name, test) in fixture.as_object().expect("a fixture object") {
        let Some(cases) = test["post"].get(rules.fork()).and_then(Value::as_array) else {
            continue;
        };
        for (i, post) in cases.iter().enumerate() {
            let ran = std::panic::catch_unwind(|| run_case(test, post, rules));
            let result =
                ran.unwrap_or((Outcome::Mismatch("the executor panicked".into()), [0u8; 32]));
            out.insert(format!("{file}::{name}::{i}"), result);
        }
    }
    out
}

/// Runs every case under `root` that is stated for `rules`, on all cores.
fn run_tree(root: &Path, rules: Rules) -> Outcomes {
    let mut files = Vec::new();
    fixture_files(root, &mut files);
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let all = std::sync::Mutex::new(Outcomes::new());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(path) = files.get(i) else { break };
                    let outcomes = run_file(root, path, rules);
                    all.lock().expect("outcomes").extend(outcomes);
                }
            });
        }
    });
    all.into_inner().expect("outcomes")
}

fn render(outcomes: &Outcomes) -> String {
    outcomes
        .iter()
        .map(|(id, (outcome, digest))| {
            format!("{id}\t{}\t{}\n", outcome.label(), hex::encode(digest))
        })
        .collect()
}

fn sample() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/state_tests_sample")
}

#[test]
fn the_vendored_sample_passes() {
    let outcomes = run_tree(&sample(), Rules::Prague);
    assert!(
        outcomes.len() >= 4,
        "the sample holds {} cases",
        outcomes.len()
    );
    for (id, (outcome, _)) in &outcomes {
        assert_eq!(*outcome, Outcome::Pass, "{id}");
    }
}

/// None of the sample's cases touches what Osaka changed, so the engine of
/// that rule set must leave each of them exactly as Prague states it: the
/// same cases run with `feature.evm_osaka` live, read from their Prague
/// post-states.
#[test]
fn the_vendored_sample_passes_on_the_osaka_engine() {
    let root = sample();
    let mut files = Vec::new();
    fixture_files(&root, &mut files);
    let mut cases = 0;
    for path in &files {
        let text = std::fs::read_to_string(path).expect("a sample fixture");
        let fixture: Value = serde_json::from_str(&text).expect("a sample fixture");
        for (name, test) in fixture.as_object().expect("a fixture object") {
            let Some(posts) = test["post"].get("Prague").and_then(Value::as_array) else {
                continue;
            };
            for post in posts {
                let (outcome, _) = run_case(test, post, Rules::Osaka);
                assert_eq!(outcome, Outcome::Pass, "{name}");
                cases += 1;
            }
        }
    }
    assert!(cases >= 4, "the sample holds {cases} cases");
}

/// Runs the fixture release under the directory `dir_var` names and holds
/// the result against the recorded one, which lists every case of `rules`
/// that is not a pass, with its outcome. A case that stops passing, starts
/// passing or changes its outcome fails the test, so the file is rewritten
/// (`TENZRO_STATE_TESTS_WRITE=1`) only as a reviewed change.
/// `TENZRO_STATE_TESTS_OUTCOMES` names a file to receive every case's
/// outcome and digest, for comparing two engines case by case.
fn hold_against_the_record(rules: Rules, dir_var: &str) {
    let root = PathBuf::from(
        std::env::var(dir_var).unwrap_or_else(|_| panic!("{dir_var} names the fixtures")),
    );
    let outcomes = run_tree(&root, rules);
    assert!(
        !outcomes.is_empty(),
        "no {} case under {}",
        rules.fork(),
        root.display()
    );
    if let Ok(path) = std::env::var("TENZRO_STATE_TESTS_OUTCOMES") {
        let path = format!("{path}.{}", rules.fork().to_lowercase());
        std::fs::write(&path, render(&outcomes)).unwrap_or_else(|e| panic!("{path}: {e}"));
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut not_passing = String::new();
    for (id, (outcome, _)) in &outcomes {
        let kind = match outcome {
            Outcome::Pass => "pass",
            Outcome::Mismatch(why) => {
                let class = why.split(" of ").next().unwrap_or(why).to_string();
                *reasons.entry(format!("mismatch: {class}")).or_default() += 1;
                "mismatch"
            }
            Outcome::NotApplicable(why) => {
                *reasons.entry(format!("not applicable: {why}")).or_default() += 1;
                "not applicable"
            }
        };
        *counts.entry(kind).or_default() += 1;
        if *outcome != Outcome::Pass {
            not_passing.push_str(&format!("{id}\t{}\n", outcome.label()));
        }
    }
    println!(
        "state tests, {}: {} cases {counts:?}",
        rules.fork(),
        outcomes.len()
    );
    for (reason, n) in &reasons {
        println!("  {n:>6}  {reason}");
    }

    let expected_path = rules.expected();
    if std::env::var("TENZRO_STATE_TESTS_WRITE").is_ok() {
        std::fs::write(&expected_path, &not_passing).expect("write the expected outcomes");
        return;
    }
    let expected = std::fs::read_to_string(&expected_path).expect("the expected outcomes");
    let have: BTreeSet<&str> = not_passing.lines().collect();
    let want: BTreeSet<&str> = expected.lines().collect();
    let changed: Vec<&&str> = have.symmetric_difference(&want).take(40).collect();
    assert!(
        changed.is_empty(),
        "{} cases differ from {}, the first: {changed:#?}",
        have.symmetric_difference(&want).count(),
        expected_path.display()
    );
}

/// The Prague cases on the first engine, `feature.evm_osaka` dormant.
#[test]
#[ignore = "needs the Ethereum fixture release; run scripts/tests/evm-state-tests.sh"]
fn ethereum_state_tests() {
    hold_against_the_record(Rules::Prague, "TENZRO_STATE_TESTS_DIR");
}

/// The Osaka cases on the engine of that rule set, `feature.evm_osaka` live.
#[test]
#[ignore = "needs the Ethereum fixture release; run scripts/tests/evm-state-tests.sh"]
fn ethereum_state_tests_osaka() {
    hold_against_the_record(Rules::Osaka, "TENZRO_STATE_TESTS_OSAKA_DIR");
}
