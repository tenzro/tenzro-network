//! Renting hardware means someone else gets a shell on your machine.
//!
//! Roughly 3,950 lines across five files decide who. Until this file, none of
//! it had an integration test — the coverage was unit tests inside the modules,
//! which exercise each check in isolation and cannot see the seams between
//! them. The seams are where this class of system fails: a wallet list checked
//! at issuance but not at redemption, a revocation that leaves outstanding
//! grants live, a missing sandbox that falls through to the host.
//!
//! The design under test is three factors, each answering a different question:
//!
//! - a **service key** selects *which lease* — issued by the operator, or
//!   minted from a rental deposit whose paid term bounds it;
//! - a **passkey ceremony** against the renter's Tenzro wallet establishes
//!   *who they are*;
//! - the lease's operator-set `authorized_wallets` list decides *whether that
//!   wallet may*.
//!
//! A leaked service key alone therefore reaches nothing, which is the property
//! most of these tests are about.
//!
//! Two tests drive the real JSON-RPC surface end to end; the rest exercise the
//! `LeaseRegistry` directly, because the properties they check — single-use
//! grants, revocation atomicity, TTL expiry — are about state transitions that
//! an RPC round-trip would only obscure. `FakeKata` stands in for a
//! confinement backend, as the module's own tests do: what matters here is
//! whether a backend is configured at all, not what it launches.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::broadcast;

use tenzro_node::remote_access::{
    AccessChannel, AccessDenied, AccessLease, AccessScope, ConfinementBackend, ConfinementKind,
    DedicationMode, DeviceGrant, GRANT_TTL_MS, LeaseRegistry, LeaseStatus, NetworkGrant,
    RentalTerm, SandboxSession,
};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};

const SERVICE_KEY: &str = "operator-issued-service-key";
const WALLET: &str = "0xabc0000000000000000000000000000000000001";
const OTHER_WALLET: &str = "0xdef0000000000000000000000000000000000002";
const ADMIN_TOKEN: &str = "test-admin-token";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A confinement backend that exists but launches nothing.
///
/// Every test here cares whether a backend is *configured*, never what it
/// starts: the boundary between "no sandbox, so refuse" and "a sandbox, so
/// proceed" is the security property. A backend that returns an error on
/// `open` keeps the tests from depending on a Kata runtime being installed.
#[derive(Debug)]
struct FakeKata;

#[async_trait]
impl ConfinementBackend for FakeKata {
    fn kind(&self) -> ConfinementKind {
        ConfinementKind::KataVm
    }
    async fn open(&self, _lease: &AccessLease) -> Result<Box<dyn SandboxSession>, String> {
        Err("fixture backend does not launch".to_string())
    }
}

fn digest(key: &str) -> String {
    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(key.as_bytes()))
}

/// A shell-granting scope. `channels` names `Shell` explicitly: an empty
/// `channels` means endpoints-only, which needs no sandbox and would skip the
/// confinement checks these tests are about.
fn shell_scope() -> AccessScope {
    AccessScope {
        workspace: PathBuf::from("/workspace"),
        devices: vec![
            DeviceGrant::Cpu { cores: 4 },
            DeviceGrant::Accelerator { index: 0 },
            DeviceGrant::Memory { mib: 32_768 },
        ],
        network: NetworkGrant::None,
        max_session_secs: 3600,
        confinement: ConfinementKind::KataVm,
        reserved_slots: 0,
        models: Vec::new(),
        max_memory_bytes: None,
        sites: Vec::new(),
        databases: Vec::new(),
        storage_deals: Vec::new(),
        agents: Vec::new(),
        channels: vec![AccessChannel::Shell],
        dedication: DedicationMode::Partial,
        term: RentalTerm::Hourly,
    }
}

fn lease(expires_at_ms: u64) -> AccessLease {
    AccessLease {
        lease_id: "lease-integration".to_string(),
        rental_id: Some("rental-1".to_string()),
        renter_did: "did:tenzro:human:renter".to_string(),
        service_key_hash: digest(SERVICE_KEY),
        authorized_wallets: vec![WALLET.to_string()],
        scope: shell_scope(),
        expires_at_ms,
        status: LeaseStatus::Active,
        created_at_ms: 0,
    }
}

/// A registry with a confinement backend and one live lease.
fn registry_with_lease(now_ms: u64) -> (Arc<LeaseRegistry>, AccessLease) {
    let reg = Arc::new(LeaseRegistry::new(false));
    reg.set_confinement(Arc::new(FakeKata));
    let l = lease(now_ms + 60 * 60 * 1000);
    reg.open_lease(l.clone()).expect("lease opens");
    (reg, l)
}

// ---------------------------------------------------------------------------
// 1. A service key with no passkey ceremony reaches nothing
// ---------------------------------------------------------------------------

/// Holding the key establishes which lease is meant and nothing else.
///
/// This is the property that makes a leaked key survivable. `lease_for_service_key`
/// deliberately returns the lease rather than an authorization, and the only
/// way to a session is `redeem_grant`, which needs a grant only the ceremony
/// mints.
#[test]
fn a_service_key_alone_opens_no_session() {
    let now = 1_000_000;
    let (reg, l) = registry_with_lease(now);

    // The key resolves the lease — that much is by design.
    let resolved = reg
        .lease_for_service_key(SERVICE_KEY, now)
        .expect("key selects its lease");
    assert_eq!(resolved.lease_id, l.lease_id);

    // But nothing has been minted, so there is nothing to redeem. The grant id
    // is 32 random bytes; guessing is not the barrier, having gone through the
    // ceremony is.
    let denied = reg
        .redeem_grant(
            "0000000000000000000000000000000000000000000000000000000000000000",
            now,
        )
        .expect_err("a session opened with no ceremony");
    assert_eq!(denied, AccessDenied::NoGrant);

    // A key the operator never issued does not even select a lease.
    let denied = reg
        .lease_for_service_key("not-the-operators-key", now)
        .expect_err("an unissued key selected a lease");
    assert_eq!(denied, AccessDenied::NoLease);
}

// ---------------------------------------------------------------------------
// 2. Wallet list is enforced, and re-checked at redemption
// ---------------------------------------------------------------------------

/// A valid ceremony by the wrong wallet is still the wrong wallet.
///
/// The two claims are separate and the operator controls them separately:
/// "someone proved they hold wallet X" is the ceremony's business, "wallet X
/// may use this hardware" is the lease's.
#[test]
fn a_ceremony_by_an_unlisted_wallet_is_refused() {
    let now = 1_000_000;
    let (reg, l) = registry_with_lease(now);

    let denied = reg
        .mint_grant(&l, OTHER_WALLET, "grant-1".to_string(), now)
        .expect_err("an unlisted wallet was granted a session");
    assert_eq!(
        denied,
        AccessDenied::WalletNotAuthorized(OTHER_WALLET.to_string())
    );

    // The listed one works, so the refusal above is the list doing its job
    // rather than the gate refusing everything.
    reg.mint_grant(&l, WALLET, "grant-2".to_string(), now)
        .expect("the listed wallet was refused");
}

/// The list is re-read at redemption, not trusted from the grant.
///
/// A grant lives for two minutes. An operator who removes a wallet inside that
/// window has decided that wallet may no longer use their hardware, and a
/// grant minted a moment earlier must not outlive the decision. Checking only
/// at mint time would give every removal a two-minute hole.
#[test]
fn removing_a_wallet_invalidates_a_grant_already_minted_for_it() {
    let now = 1_000_000;
    let (reg, l) = registry_with_lease(now);

    reg.mint_grant(&l, WALLET, "grant-1".to_string(), now)
        .expect("grant mints");

    // The operator narrows the list. Re-opening replaces the record.
    let mut narrowed = l.clone();
    narrowed.authorized_wallets = vec![OTHER_WALLET.to_string()];
    reg.open_lease(narrowed).expect("lease re-opens");

    let denied = reg
        .redeem_grant("grant-1", now + 1_000)
        .expect_err("a grant survived its wallet being removed");
    assert_eq!(
        denied,
        AccessDenied::WalletNotAuthorized(WALLET.to_string())
    );
}

// ---------------------------------------------------------------------------
// 3. Revocation drops outstanding grants in the same action
// ---------------------------------------------------------------------------

/// Revoking is one action, not two.
///
/// An outstanding grant is a credential against the lease. If revocation left
/// grants live, revocation would have a window exactly as long as the grant
/// TTL — and the operator revoking is usually the one who has just discovered
/// they need to.
#[test]
fn revoking_a_lease_drops_every_outstanding_grant() {
    let now = 1_000_000;
    let (reg, l) = registry_with_lease(now);

    reg.mint_grant(&l, WALLET, "grant-a".to_string(), now)
        .expect("first grant mints");
    reg.mint_grant(&l, WALLET, "grant-b".to_string(), now)
        .expect("second grant mints");

    reg.revoke_lease(&l.lease_id).expect("lease revokes");

    for id in ["grant-a", "grant-b"] {
        let denied = reg
            .redeem_grant(id, now + 1_000)
            .err()
            .unwrap_or_else(|| panic!("grant {id} survived revocation"));
        // Dropped, not merely shadowed by the lease's own refusal: the grant
        // is gone from the map, so the reason is NoGrant rather than Revoked.
        assert_eq!(denied, AccessDenied::NoGrant, "grant {id}");
    }
}

/// The service key stops selecting a revoked lease at all.
#[test]
fn a_revoked_lease_is_unreachable_by_its_service_key() {
    let now = 1_000_000;
    let (reg, l) = registry_with_lease(now);
    reg.revoke_lease(&l.lease_id).expect("lease revokes");

    let denied = reg
        .lease_for_service_key(SERVICE_KEY, now)
        .expect_err("a revoked lease was still selectable");
    assert_eq!(denied, AccessDenied::Revoked(l.lease_id));
}

// ---------------------------------------------------------------------------
// 4. Grants are single-use and expire
// ---------------------------------------------------------------------------

/// One ceremony, one session.
///
/// The grant is removed on presentation whether or not it turns out to be
/// valid, so a replay fails on its second presentation even if the first one
/// raced with it.
#[test]
fn a_grant_is_spent_by_its_first_redemption() {
    let now = 1_000_000;
    let (reg, l) = registry_with_lease(now);
    reg.mint_grant(&l, WALLET, "grant-1".to_string(), now)
        .expect("grant mints");

    let (redeemed, grant) = reg.redeem_grant("grant-1", now).expect("first redemption");
    assert_eq!(redeemed.lease_id, l.lease_id);
    assert_eq!(grant.wallet, WALLET);

    let denied = reg
        .redeem_grant("grant-1", now)
        .expect_err("a grant was redeemed twice");
    assert_eq!(denied, AccessDenied::NoGrant);
}

/// A grant left in a shell history is worthless by the time anyone reads it.
#[test]
fn a_grant_dies_at_its_two_minute_ttl() {
    let now = 1_000_000;
    let (reg, l) = registry_with_lease(now);
    reg.mint_grant(&l, WALLET, "grant-1".to_string(), now)
        .expect("grant mints");

    // One millisecond inside the window still works…
    assert_eq!(GRANT_TTL_MS, 2 * 60 * 1000, "grant TTL changed");

    let denied = reg
        .redeem_grant("grant-1", now + GRANT_TTL_MS)
        .expect_err("a grant outlived its TTL");
    assert_eq!(denied, AccessDenied::NoGrant);
}

/// An expired *lease* refuses too, and says so distinctly from a revoked one —
/// the two mean different things to whoever is reading the audit trail.
#[test]
fn an_expired_lease_refuses_redemption() {
    let now = 1_000_000;
    let reg = Arc::new(LeaseRegistry::new(false));
    reg.set_confinement(Arc::new(FakeKata));
    let l = lease(now + 1_000);
    reg.open_lease(l.clone()).expect("lease opens");
    reg.mint_grant(&l, WALLET, "grant-1".to_string(), now)
        .expect("grant mints");

    let denied = reg
        .redeem_grant("grant-1", now + 2_000)
        .expect_err("a session started after the lease ended");
    assert_eq!(denied, AccessDenied::Expired(l.lease_id));
}

// ---------------------------------------------------------------------------
// 5. No confinement backend means refusal, not fall-through
// ---------------------------------------------------------------------------

/// A node with no sandbox refuses rather than dropping the renter on the host.
///
/// This is the single most important line in the module: the failure mode it
/// prevents is a misconfigured node handing out a shell on the operator's own
/// filesystem. `ConfinementBackend` has no default impl precisely so that
/// "unconfigured" cannot silently mean "unconfined".
#[test]
fn a_node_with_no_confinement_backend_refuses_the_session() {
    let now = 1_000_000;
    let reg = Arc::new(LeaseRegistry::new(false));
    // Deliberately no `set_confinement`.
    let l = lease(now + 60 * 60 * 1000);
    reg.open_lease(l.clone()).expect("lease opens");
    reg.mint_grant(&l, WALLET, "grant-1".to_string(), now)
        .expect("grant mints");

    let denied = reg
        .redeem_grant("grant-1", now)
        .expect_err("a session opened with no confinement boundary");
    assert_eq!(denied, AccessDenied::NoConfinement);
}

/// An endpoints-only lease is unaffected: it runs no tenant code on the host,
/// so demanding a sandbox for it would block a safe product on the absence of
/// a boundary it does not need.
#[test]
fn an_endpoints_only_lease_needs_no_sandbox() {
    let now = 1_000_000;
    let reg = Arc::new(LeaseRegistry::new(false));
    let mut l = lease(now + 60 * 60 * 1000);
    l.scope.channels = vec![AccessChannel::Endpoints];
    reg.open_lease(l.clone()).expect("lease opens");
    reg.mint_grant(&l, WALLET, "grant-1".to_string(), now)
        .expect("grant mints");

    reg.redeem_grant("grant-1", now)
        .expect("an endpoints-only lease was refused for want of a sandbox");
}

// ---------------------------------------------------------------------------
// 6. A TeeProvider node cannot open a lease at all
// ---------------------------------------------------------------------------

/// Interactive access invalidates the attestation posture the role claims.
///
/// A renter with a shell inside the enclave can read whatever it holds, so its
/// measurement stops meaning to a relying party what they take it to mean.
/// Refused at `open_lease` rather than at session time, so the node never
/// advertises a lease it cannot honestly serve.
#[test]
fn a_tee_provider_node_cannot_open_a_lease() {
    let reg = LeaseRegistry::new(true);
    reg.set_confinement(Arc::new(FakeKata));
    let err = reg
        .open_lease(lease(u64::MAX))
        .expect_err("a TeeProvider node opened a shell lease");
    assert!(
        err.contains("TeeProvider"),
        "refusal did not name the role that caused it: {err}"
    );
}

// ---------------------------------------------------------------------------
// 7. A session leaves a retrievable receipt naming the verifying wallet
// ---------------------------------------------------------------------------

/// The receipt is filed, not just logged.
///
/// The accountable party is the wallet that passkey-verified, not the lease's
/// renter DID: a lease may authorize several wallets, and the audit trail has
/// to say which one actually signed in.
#[tokio::test]
async fn a_filed_session_receipt_names_the_wallet_that_verified() {
    use tenzro_storage::da::{ReceiptEnvelope, ReceiptKind, ReceiptSummary, compute_commitment};
    use tenzro_types::primitives::Timestamp;

    let store: Arc<dyn tenzro_storage::KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
    let reg = LeaseRegistry::with_storage(store, false);
    reg.set_confinement(Arc::new(FakeKata));
    let l = lease(u64::MAX);
    reg.open_lease(l.clone()).expect("lease opens");

    let payload = serde_json::to_vec(&json!({
        "lease_id": l.lease_id,
        "wallet": WALLET,
        "ended": "closed",
    }))
    .expect("payload");
    let receipt = ReceiptEnvelope::inline(
        ReceiptKind::Lifecycle,
        ReceiptSummary {
            receipt_id: compute_commitment(&payload),
            payer: Some(WALLET.to_string()),
            payee: None,
            amount_wei: None,
            timestamp: Timestamp::new(0),
            principal_chain_summary: None,
        },
        payload,
    );
    reg.record_session_receipt(&l.lease_id, 1_000, &receipt)
        .expect("receipt files");

    let filed = reg.session_receipts(Some(&l.lease_id));
    assert_eq!(filed.len(), 1, "receipt was not retrievable after filing");
    assert_eq!(
        filed[0].inline_summary.payer.as_deref(),
        Some(WALLET),
        "receipt does not name the wallet that verified"
    );
    assert_eq!(
        filed[0].commitment, receipt.commitment,
        "the filed receipt is not the one that was produced"
    );

    // A different lease's scan does not see it — an operator auditing one
    // tenant should not be shown another's.
    assert!(
        reg.session_receipts(Some("lease-someone-else")).is_empty(),
        "a lease-scoped scan returned another lease's sessions"
    );
}

// ---------------------------------------------------------------------------
// The RPC surface
// ---------------------------------------------------------------------------

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    client: reqwest::Client,
}

impl TestNode {
    async fn boot() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        // The node reads the admin token once at construction.
        //
        // SAFETY: single-threaded at this point — the node, its runtime, and
        // the RPC server are all built after this line, and nextest gives each
        // test its own process.
        unsafe { std::env::set_var("TENZRO_ADMIN_TOKEN", ADMIN_TOKEN) };
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);

        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(
                async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await },
            );
        let addr = addr_rx.await.expect("bound address");

        Self {
            base_url: format!("http://{addr}"),
            shutdown,
            handle,
            _tmp: tmp,
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: &str, params: Value, admin: bool) -> Value {
        let mut req = self
            .client
            .post(&self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
        if admin {
            req = req.header("X-Tenzro-Admin-Token", ADMIN_TOKEN);
        }
        req.send()
            .await
            .expect("HTTP request")
            .json::<Value>()
            .await
            .expect("JSON parse")
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

/// The lease book is the operator's, and the admin gate says so.
///
/// A tenant who could enumerate leases would learn which wallets the operator
/// trusts on which hardware — the shape of every other tenant's arrangement.
#[tokio::test]
async fn the_lease_book_is_not_readable_without_the_admin_token() {
    let n = TestNode::boot().await;

    for method in ["tenzro_listAccessLeases", "tenzro_listShellSessionReceipts"] {
        let res = n.call(method, json!({}), false).await;
        assert!(
            res.get("error").is_some(),
            "{method} answered without the operator's admin token: {res}"
        );
    }

    // With the token it answers, so the refusals above are the gate rather
    // than the method being absent.
    let res = n.call("tenzro_listAccessLeases", json!({}), true).await;
    assert!(
        res.get("error").is_none(),
        "listAccessLeases refused the operator: {res}"
    );

    n.shutdown().await;
}

/// Opening a lease is the operator's call; signing in is not.
///
/// `tenzro_requestShellSession` is deliberately OPEN — the renter is not an
/// admin — and what protects it is that the service key on its own reaches
/// nothing. A key that selects no lease is refused before any ceremony is
/// created, so a renter is never sent to a browser to authenticate for
/// something that was never going to be granted.
#[tokio::test]
async fn an_unknown_service_key_is_refused_before_any_ceremony() {
    let n = TestNode::boot().await;

    let res = n
        .call(
            "tenzro_requestShellSession",
            json!({
                "service_key": "a-key-no-operator-ever-issued",
                "account_address": WALLET,
            }),
            false,
        )
        .await;
    assert!(
        res.get("error").is_some(),
        "an unissued service key started a sign-in ceremony: {res}"
    );

    // And opening a lease is refused without the operator's token, so a renter
    // cannot mint themselves the lease their key would then select.
    let res = n
        .call(
            "tenzro_openAccessLease",
            json!({
                "service_key": SERVICE_KEY,
                "authorized_wallets": [WALLET],
                "renter_did": "did:tenzro:human:renter",
                "scope": shell_scope(),
                "term_ms": 3_600_000u64,
            }),
            false,
        )
        .await;
    assert!(
        res.get("error").is_some(),
        "a lease was opened without the operator's admin token: {res}"
    );

    n.shutdown().await;
}
