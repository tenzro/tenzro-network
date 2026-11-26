//! The account a machine may announce.
//!
//! A provider, model or heartbeat announcement names an account: the one
//! paid for what the machine serves, and the key of its entry in every
//! peer's provider table. The announcement is signed by the machine's
//! identity key, which proves who sent it and nothing about whose account it
//! names. What ties an account to a machine is the chain: a machine identity
//! is registered with a wallet, and every node mirrors that record.
//!
//! So a receiver takes an announcement only when the account it names is the
//! wallet registered for the machine identity that signed it ([`check`]); a
//! machine naming any other account is dropped, and cannot replace another
//! operator's entry with its own endpoint. The chain records no identity as
//! controlling a machine, so an operator identity's wallet cannot be
//! verified by a peer and is not accepted.
//!
//! A node does not send what its peers drop ([`SenderGate`]): when the
//! account it is configured to be paid at is not its machine identity's
//! registered wallet, it announces nothing, and says so in its log and in
//! its health status.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tenzro_identity::IdentityRegistry;
use tenzro_types::primitives::Address;

use crate::health::HealthMonitor;

/// The health subsystem a refused announcement is reported under.
pub const HEALTH_SUBSYSTEM: &str = "announcements";

/// How often a node that does not announce says so again in its log.
const REFUSAL_LOG_EVERY: Duration = Duration::from_secs(600);

/// How long a resolved payee is used before it is resolved again. Resolving
/// reads every identity the node holds, and three announcements go out per
/// heartbeat; a payee that changes is announced within this interval.
const PAYEE_REFRESH: Duration = Duration::from_secs(30);

/// Why an announced account is not taken as the announcing machine's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unbound {
    /// This node has no identity registry to look the machine up in.
    NoRegistry,
    /// No identity is registered for the machine.
    NotRegistered,
    /// The machine's identity is registered with no wallet.
    NoWallet,
    /// The announcement names no readable account.
    NotAnAccount(String),
    /// The account is not the wallet registered for the machine.
    AnotherAccount {
        /// The wallet the machine's identity is registered with.
        registered: Address,
    },
}

impl std::fmt::Display for Unbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRegistry => write!(f, "no identity registry to look the machine up in"),
            Self::NotRegistered => write!(f, "the machine has no registered identity"),
            Self::NoWallet => write!(f, "the machine's identity is registered with no wallet"),
            Self::NotAnAccount(e) => write!(f, "the announcement names no account: {e}"),
            Self::AnotherAccount { registered } => write!(
                f,
                "the account is not the wallet registered for the machine identity ({registered})"
            ),
        }
    }
}

/// The wallet `registry` holds for the machine identity `machine_did`.
fn registered_wallet(registry: &IdentityRegistry, machine_did: &str) -> Result<Address, Unbound> {
    let identity = registry
        .resolve(machine_did)
        .map_err(|_| Unbound::NotRegistered)?;
    if identity.wallet_address == Address::default() {
        return Err(Unbound::NoWallet);
    }
    Ok(identity.wallet_address)
}

/// Whether `account`, as an announcement signed by `machine_did` names it,
/// is the wallet registered for that machine identity.
pub fn check(
    registry: Option<&IdentityRegistry>,
    machine_did: &str,
    account: &str,
) -> Result<(), Unbound> {
    let registry = registry.ok_or(Unbound::NoRegistry)?;
    let registered = registered_wallet(registry, machine_did)?;
    let announced = Address::from_hex(account).map_err(|e| Unbound::NotAnAccount(e.to_string()))?;
    if announced == registered {
        Ok(())
    } else {
        Err(Unbound::AnotherAccount { registered })
    }
}

/// Why a node holds back its announcements of an account.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    /// The machine identity is registered with `registered`, and the account
    /// is another one.
    AnotherAccount { registered: Address },
    /// The machine identity is registered with no wallet, so no account it
    /// names is taken.
    NoWallet,
}

/// Whether a node whose machine identity is `machine_did` holds back its
/// announcements of `account`: when the machine is registered and every
/// peer would drop them (another account than its registered wallet, or no
/// wallet registered at all). A machine that is not registered yet
/// announces as before; its peers decide.
fn refusal(
    registry: Option<&IdentityRegistry>,
    machine_did: &str,
    account: &str,
) -> Option<Refusal> {
    match check(registry, machine_did, account) {
        Err(Unbound::AnotherAccount { registered }) => Some(Refusal::AnotherAccount { registered }),
        Err(Unbound::NoWallet) => Some(Refusal::NoWallet),
        _ => None,
    }
}

/// Whether a refusal last logged at `last` is logged again at `now`.
fn log_due(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|at| now.duration_since(at) >= REFUSAL_LOG_EVERY)
}

/// The account a node is paid at as of now, read again for every
/// announcement: it can change after start (the machine's own identity
/// record arrives, or the operator identity is provisioned).
pub type PayeeSource = Arc<dyn Fn() -> Option<Address> + Send + Sync>;

/// Holds a node's announcements back while the account it would announce is
/// not its machine identity's registered wallet.
pub struct SenderGate {
    registry: Arc<RwLock<Option<Arc<IdentityRegistry>>>>,
    machine_did: String,
    payee: PayeeSource,
    /// The payee as last resolved, and when.
    resolved: Mutex<Option<(Instant, Option<Address>)>>,
    /// How long a resolved payee is used ([`PAYEE_REFRESH`]).
    payee_refresh: Duration,
    /// The operator identity the node's configuration names, if any.
    operator_did: Option<String>,
    health: Arc<HealthMonitor>,
    state: Mutex<GateState>,
}

#[derive(Default)]
struct GateState {
    refusing: bool,
    logged: Option<Instant>,
}

/// An account as announcements name it.
fn account_hex(account: &Address) -> String {
    format!("0x{}", hex::encode(account.as_bytes()))
}

impl SenderGate {
    /// A gate for the node whose machine identity is `machine_did` and that
    /// is paid at what `payee` says, configured with `operator_did`, reading
    /// the identity registry from `registry` and reporting to `health`.
    pub fn new(
        registry: Arc<RwLock<Option<Arc<IdentityRegistry>>>>,
        machine_did: String,
        payee: PayeeSource,
        operator_did: Option<String>,
        health: Arc<HealthMonitor>,
    ) -> Self {
        Self {
            registry,
            machine_did,
            payee,
            resolved: Mutex::new(None),
            payee_refresh: PAYEE_REFRESH,
            operator_did: operator_did
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty()),
            health,
            state: Mutex::new(GateState::default()),
        }
    }

    /// The account the node announces now, read from its payee: `None` when
    /// it announces nothing (see [`Self::may_announce`]), an empty string
    /// when it has no payee at all.
    pub fn announced_account(&self) -> Option<String> {
        let account = self
            .current_payee()
            .map(|a| account_hex(&a))
            .unwrap_or_default();
        self.may_announce(&account).then_some(account)
    }

    /// The payee, resolved again once [`PAYEE_REFRESH`] has passed since the
    /// last resolution.
    fn current_payee(&self) -> Option<Address> {
        let now = Instant::now();
        let mut resolved = self.resolved.lock();
        if let Some((at, payee)) = *resolved
            && now.duration_since(at) < self.payee_refresh
        {
            return payee;
        }
        let payee = (self.payee)();
        *resolved = Some((now, payee));
        payee
    }

    /// Whether the node announces `account` now. When it does not, the
    /// reason is logged at error (at the first refusal and then every
    /// [`REFUSAL_LOG_EVERY`]) and the [`HEALTH_SUBSYSTEM`] subsystem is
    /// reported degraded with it until the node announces again.
    pub fn may_announce(&self, account: &str) -> bool {
        let registry = self.registry.read().clone();
        let refused = refusal(registry.as_deref(), &self.machine_did, account);
        let mut state = self.state.lock();
        let Some(refused) = refused else {
            if state.refusing {
                *state = GateState::default();
                self.health.mark_healthy(HEALTH_SUBSYSTEM);
                tracing::info!(
                    account,
                    "This node announces again: the account is its machine identity's registered wallet"
                );
            }
            return true;
        };
        let reason = refusal_reason(
            account,
            &self.machine_did,
            self.operator_did.as_deref(),
            &refused,
        );
        if !state.refusing {
            self.health.mark_degraded(HEALTH_SUBSYSTEM, reason.clone());
        }
        state.refusing = true;
        let now = Instant::now();
        if log_due(state.logged, now) {
            state.logged = Some(now);
            tracing::error!(account, machine = %self.machine_did, "{reason}");
        }
        false
    }
}

/// What an operator is told when the node does not announce: the account it
/// would have announced, the wallet its machine identity is registered with
/// (or that it has none), and why, naming the configuration that led there.
fn refusal_reason(
    account: &str,
    machine_did: &str,
    operator_did: Option<&str>,
    refused: &Refusal,
) -> String {
    const UNCHANGED: &str = "Serving and settlement on this node are unchanged.";
    let registered = match refused {
        Refusal::NoWallet => {
            return format!(
                "This node does not announce itself to the network. Its machine identity \
                 {machine_did} is registered on chain with no wallet, and peers accept an \
                 announcement only for the wallet registered for the machine that signs it, so \
                 no account it could name ({account}) is taken. {UNCHANGED} A machine's wallet is \
                 set when its identity is registered and cannot be changed by registering again."
            );
        }
        Refusal::AnotherAccount { registered } => registered,
    };
    let why = match operator_did {
        Some(operator) if operator != machine_did => format!(
            "It is configured with operator_did = {operator} and paid at that identity's wallet \
             {account}, but the chain has no record yet by which an operator identity controls a \
             machine, so another identity's account cannot be announced. To be listed, leave \
             `operator_did` unset or set it to {machine_did}"
        ),
        _ => format!(
            "Its payee resolves to {account}, which is not that wallet (no operator_did is \
             configured: the payee is taken from the identities this node holds, read again for \
             every announcement). To be listed, set `operator_did` to {machine_did}"
        ),
    };
    format!(
        "This node does not announce itself to the network. Its machine identity {machine_did} \
         is registered on chain with the wallet {registered}, and peers accept an announcement \
         only for that wallet. {why}, which announces and is paid at {registered}. {UNCHANGED}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tenzro_identity::{TenzroDid, WalletBinding};

    /// The identity key of the machine the tests register.
    const MACHINE_KEY: [u8; 65] = [4; 65];

    /// The machine identity `MACHINE_KEY` derives.
    fn machine() -> String {
        tenzro_types::did_derivation::machine_did(&MACHINE_KEY)
    }

    fn account(n: u8) -> Address {
        let mut slot = [0u8; 32];
        slot[..20].copy_from_slice(&[n; 20]);
        Address::new(slot)
    }

    fn hex(account: &Address) -> String {
        format!("0x{}", hex::encode(account.as_bytes()))
    }

    /// A registry holding the machine registered with `wallet`.
    async fn registry_with(wallet: Address) -> Arc<IdentityRegistry> {
        let registry = IdentityRegistry::new();
        registry
            .register_autonomous_machine_with_binding(
                TenzroDid::parse(&machine()).unwrap(),
                WalletBinding {
                    wallet_id: "machine".into(),
                    address: wallet,
                    public_key: MACHINE_KEY.to_vec(),
                    pq_verifying_key: Vec::new(),
                },
                Vec::new(),
                HashMap::new(),
            )
            .await
            .unwrap();
        Arc::new(registry)
    }

    #[tokio::test]
    async fn only_the_wallet_registered_for_the_machine_is_its_account() {
        let registry = registry_with(account(1)).await;
        let r = Some(registry.as_ref());
        assert_eq!(check(r, &machine(), &hex(&account(1))), Ok(()));
        // The same account without the prefix is the same account.
        assert_eq!(
            check(r, &machine(), &hex::encode(account(1).as_bytes())),
            Ok(())
        );
        assert_eq!(
            check(r, &machine(), &hex(&account(2))),
            Err(Unbound::AnotherAccount {
                registered: account(1)
            }),
            "another operator's account"
        );
        assert!(matches!(
            check(r, &machine(), ""),
            Err(Unbound::NotAnAccount(_))
        ));
        assert!(matches!(
            check(r, &machine(), "not hex"),
            Err(Unbound::NotAnAccount(_))
        ));
        assert_eq!(
            check(r, "did:tenzro:machine:unknown", &hex(&account(1))),
            Err(Unbound::NotRegistered)
        );
        assert_eq!(
            check(None, &machine(), &hex(&account(1))),
            Err(Unbound::NoRegistry)
        );
    }

    #[tokio::test]
    async fn a_node_holds_back_only_what_its_peers_would_drop_for_the_account() {
        let registry = registry_with(account(1)).await;
        let r = Some(registry.as_ref());
        assert_eq!(refusal(r, &machine(), &hex(&account(1))), None);
        assert_eq!(
            refusal(r, &machine(), &hex(&account(2))),
            Some(Refusal::AnotherAccount {
                registered: account(1)
            })
        );
        // Not registered yet, or no account to name: announced as before.
        assert_eq!(
            refusal(r, "did:tenzro:machine:unknown", &hex(&account(2))),
            None
        );
        assert_eq!(refusal(None, &machine(), &hex(&account(2))), None);
        assert_eq!(refusal(r, &machine(), ""), None);
    }

    #[test]
    fn a_refusal_is_logged_at_once_and_then_at_the_interval() {
        let now = Instant::now();
        assert!(log_due(None, now));
        assert!(!log_due(
            Some(now),
            now + REFUSAL_LOG_EVERY - Duration::from_secs(1)
        ));
        assert!(log_due(Some(now), now + REFUSAL_LOG_EVERY));
    }

    /// A gate over the registry in `slot`, paid at what `payee` holds,
    /// resolving the payee on every call.
    fn gate_over(
        slot: Arc<RwLock<Option<Arc<IdentityRegistry>>>>,
        payee: Arc<Mutex<Option<Address>>>,
        operator_did: Option<&str>,
        health: Arc<HealthMonitor>,
    ) -> SenderGate {
        let mut gate = SenderGate::new(
            slot,
            machine(),
            Arc::new(move || *payee.lock()),
            operator_did.map(str::to_string),
            health,
        );
        gate.payee_refresh = Duration::ZERO;
        gate
    }

    #[tokio::test]
    async fn the_payee_is_resolved_once_per_refresh_interval() {
        let registry = registry_with(account(1)).await;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        let gate = SenderGate::new(
            Arc::new(RwLock::new(Some(registry))),
            machine(),
            Arc::new(move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(account(1))
            }),
            None,
            Arc::new(HealthMonitor::new()),
        );
        for _ in 0..3 {
            assert_eq!(gate.announced_account(), Some(hex(&account(1))));
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn the_gate_reports_a_refusal_in_health_until_the_node_announces_again() {
        let registry = registry_with(account(1)).await;
        let slot = Arc::new(RwLock::new(Some(registry)));
        let health = Arc::new(HealthMonitor::new());
        let payee = Arc::new(Mutex::new(Some(account(1))));
        let gate = gate_over(slot.clone(), payee.clone(), None, health.clone());

        assert_eq!(gate.announced_account(), Some(hex(&account(1))));
        assert!(
            health.list_subsystems().is_empty(),
            "a node that announces reports nothing"
        );

        let degraded = || {
            health.list_subsystems().iter().any(|(name, status, _)| {
                name == HEALTH_SUBSYSTEM
                    && matches!(status, crate::health::SubsystemStatus::Degraded { .. })
            })
        };
        *payee.lock() = Some(account(2));
        assert_eq!(gate.announced_account(), None);
        assert_eq!(gate.announced_account(), None);
        assert!(degraded(), "the refusal shows in the health status");

        // The payee is read again for every announcement: once it resolves
        // to the registered wallet the node announces again.
        *payee.lock() = Some(account(1));
        assert_eq!(gate.announced_account(), Some(hex(&account(1))));
        assert!(!degraded());

        // Before the registry is there the node announces as before.
        *slot.write() = None;
        *payee.lock() = Some(account(2));
        assert_eq!(gate.announced_account(), Some(hex(&account(2))));
    }

    #[test]
    fn the_reason_names_the_account_the_machine_the_wallet_and_the_cause() {
        let registered = Refusal::AnotherAccount {
            registered: account(1),
        };
        let operator = "did:tenzro:human:operator";
        let configured = refusal_reason(&hex(&account(2)), &machine(), Some(operator), &registered);
        for fact in [hex(&account(2)), machine(), account(1).to_string()] {
            assert!(configured.contains(&fact), "the reason names {fact}");
        }
        assert!(
            configured.contains(operator),
            "names the configured operator"
        );
        let inferred = refusal_reason(&hex(&account(2)), &machine(), None, &registered);
        assert!(inferred.contains("no operator_did is configured"));
        // Naming the machine itself as operator is not an operator identity.
        let own = refusal_reason(&hex(&account(2)), &machine(), Some(&machine()), &registered);
        assert!(own.contains("no operator_did is configured"));
        let no_wallet = refusal_reason(&hex(&account(2)), &machine(), None, &Refusal::NoWallet);
        assert!(no_wallet.contains("with no wallet") && no_wallet.contains(&machine()));
    }

    #[tokio::test]
    async fn a_machine_registered_with_no_wallet_does_not_announce_and_says_so() {
        let registry = registry_with(Address::default()).await;
        assert_eq!(
            refusal(Some(registry.as_ref()), &machine(), &hex(&account(1))),
            Some(Refusal::NoWallet)
        );
        let health = Arc::new(HealthMonitor::new());
        let gate = gate_over(
            Arc::new(RwLock::new(Some(registry))),
            Arc::new(Mutex::new(Some(account(1)))),
            None,
            health.clone(),
        );
        assert_eq!(gate.announced_account(), None);
        assert!(health.list_subsystems().iter().any(|(name, status, _)| {
            name == HEALTH_SUBSYSTEM
                && matches!(status, crate::health::SubsystemStatus::Degraded { reason } if reason.contains("with no wallet"))
        }));
    }
}
