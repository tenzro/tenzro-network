//! Who paid for a generation, kept beside its usage record.
//!
//! A usage record says what was served, by whom and at what cost; it is
//! written in a stored layout that cannot gain a field. The account that paid
//! and the delegation path behind it are known only once the call is settled,
//! so they are kept under their own key, `usage_payer:<record id>`, in the
//! node's metadata store, and read back wherever a generation is shown.
//!
//! A call is paid one of two ways: settled by the node itself
//! ([`Payer::from_settlement`]), or at the payment gate in front of an HTTP
//! route, which hands its verified payer to the route ([`paid_by`],
//! [`current`]).

use serde_json::Value;
use tenzro_identity::IdentityRegistry;
use tenzro_storage::KvStore;
use tenzro_types::primitives::Address;

use crate::node::TenzroNode;

const PREFIX: &str = "usage_payer:";

/// Who paid for one call, as far as it is known.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Payer {
    /// The account debited.
    pub(crate) address: Option<Address>,
    /// The payer's DID, when the payment named one.
    pub(crate) did: Option<String>,
}

impl Payer {
    /// The payer of a call this node settled, if anyone paid.
    pub(crate) fn from_settlement(settlement: &crate::rpc::SettlementOutcome) -> Option<Self> {
        settlement.payer().map(|a| Self {
            address: Some(*a),
            did: None,
        })
    }

    /// The payer the payment gate verified for a request.
    pub(crate) fn from_gate(paid: &tenzro_payments::middleware::PaidBy) -> Option<Self> {
        let address = Address::from_hex(&paid.payer_address).ok();
        let did = Some(paid.payer_did.clone()).filter(|d| !d.is_empty());
        (address.is_some() || did.is_some()).then_some(Self { address, did })
    }

    /// The payer as one string for a receipt summary: its account, else its DID.
    pub(crate) fn label(&self) -> Option<String> {
        self.address
            .map(|a| format!("0x{}", hex::encode(a.as_bytes())))
            .or_else(|| self.did.clone())
    }
}

tokio::task_local! {
    static PAID_BY: Option<Payer>;
}

/// Runs `serve` knowing who paid for the request it serves.
pub(crate) async fn paid_by<F>(payer: Option<Payer>, serve: F) -> F::Output
where
    F: std::future::Future,
{
    PAID_BY.scope(payer, serve).await
}

/// Who paid for the request being served, when the payment gate said.
pub(crate) fn current() -> Option<Payer> {
    PAID_BY.try_with(Clone::clone).ok().flatten()
}

fn key(record_id: &str) -> Vec<u8> {
    format!("{PREFIX}{record_id}").into_bytes()
}

/// The payer of a settled call as it is kept: its account, its DID (as the
/// payment named it, else the identity whose wallet the account is), and
/// that identity's delegation path at `height`.
fn describe(registry: Option<&IdentityRegistry>, height: u64, payer: &Payer) -> Value {
    let did = payer.did.clone().or_else(|| {
        let address = payer.address?;
        registry?
            .list_all()
            .into_iter()
            .find(|(_, identity)| identity.wallet_address == address)
            .map(|(did, _)| did)
    });
    let principal_chain = match (&did, registry) {
        (Some(did), Some(registry)) => {
            serde_json::to_value(registry.resolve_principal_chain(did, height))
                .unwrap_or(Value::Null)
        }
        _ => Value::Null,
    };
    serde_json::json!({
        "payer": payer.address.map(|a| format!("0x{}", hex::encode(a.as_bytes()))),
        "payer_did": did,
        "principal_chain": principal_chain,
    })
}

fn write(store: &dyn KvStore, record_id: &str, value: &Value) {
    let stored = store.put(
        tenzro_storage::CF_METADATA,
        &key(record_id),
        value.to_string().as_bytes(),
    );
    if let Err(e) = stored {
        tracing::warn!(
            record = %record_id,
            error = %e,
            "who paid for the generation was not stored"
        );
    }
}

fn read_from(store: &dyn KvStore, record_id: &str) -> Option<Value> {
    let bytes = store
        .get(tenzro_storage::CF_METADATA, &key(record_id))
        .ok()??;
    serde_json::from_slice(&bytes).ok()
}

/// Keeps who paid for the generation `record_id`.
pub(crate) fn record(node: &TenzroNode, record_id: &str, payer: &Payer) {
    let Some(store) = node.storage() else {
        return;
    };
    let registry = node.identity_registry().map(|r| r.as_ref());
    write(
        store.as_ref(),
        record_id,
        &describe(registry, node.chain_tip_height(), payer),
    );
}

/// Who paid for the generation `record_id`, if it was settled here.
pub(crate) fn read(node: &TenzroNode, record_id: &str) -> Option<Value> {
    read_from(node.storage()?.as_ref(), record_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_identity::{IdentityData, IdentityStatus, TenzroDid, TenzroIdentity};

    fn identity(did: &str, wallet: Address, data: IdentityData) -> TenzroIdentity {
        TenzroIdentity {
            did: TenzroDid::parse(did).expect("DID"),
            public_keys: Vec::new(),
            identity_data: data,
            status: IdentityStatus::Active,
            wallet_address: wallet,
            wallet_id: String::new(),
            pq_verifying_key: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: Default::default(),
        }
    }

    /// A settled call's payer is kept with its DID and the delegation path up
    /// to its controller, and read back by the record id.
    #[test]
    fn a_settled_generation_names_its_payer_and_the_chain_behind_it() {
        let human = format!("did:tenzro:human:{}", hex::encode([0x11u8; 32]));
        let agent = format!("did:tenzro:machine:{}", hex::encode([0x22u8; 32]));
        let agent_wallet = Address::new([0x22; 32]);
        let registry = IdentityRegistry::new();
        registry.upsert_identity_for_test(identity(
            &human,
            Address::new([0x11; 32]),
            IdentityData::Human {
                display_name: "Owner".into(),
                controlled_machines: vec![agent.clone()],
            },
        ));
        registry.upsert_identity_for_test(identity(
            &agent,
            agent_wallet,
            IdentityData::Machine {
                capabilities: Vec::new(),
                controller_did: Some(human.clone()),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
        ));
        let store = tenzro_storage::MemoryStore::new();
        let paid = Payer {
            address: Some(agent_wallet),
            did: None,
        };
        write(&store, "gen-1", &describe(Some(&registry), 77, &paid));

        let paid = read_from(&store, "gen-1").expect("kept");
        assert_eq!(paid["payer"], format!("0x{}", hex::encode([0x22u8; 32])));
        assert_eq!(paid["payer_did"], agent.as_str());
        assert_eq!(paid["principal_chain"]["actor"], agent.as_str());
        assert_eq!(paid["principal_chain"]["controller"]["did"], human.as_str());
        assert_eq!(paid["principal_chain"]["frozen_at_block"], 77);
        assert!(
            read_from(&store, "gen-2").is_none(),
            "another record has no payer"
        );
    }

    /// An account that is no registered identity's wallet is kept as an
    /// account alone.
    #[test]
    fn an_unknown_payer_is_kept_as_its_account_alone() {
        let registry = IdentityRegistry::new();
        let account = Payer {
            address: Some(Address::new([0x33; 32])),
            did: None,
        };
        let paid = describe(Some(&registry), 5, &account);
        assert_eq!(paid["payer"], format!("0x{}", hex::encode([0x33u8; 32])));
        assert!(paid["payer_did"].is_null());
        assert!(paid["principal_chain"].is_null());
        assert!(describe(None, 5, &account)["payer_did"].is_null());
    }

    /// The gate's payer reaches the code serving the request, and nothing
    /// outside it sees one.
    #[tokio::test]
    async fn the_gates_payer_is_known_while_its_request_is_served() {
        let gate = tenzro_payments::middleware::PaidBy {
            payer_did: "did:tenzro:human:payer".into(),
            payer_address: hex::encode([0x44u8; 32]),
        };
        let payer = Payer::from_gate(&gate).expect("a payer");
        assert_eq!(payer.address, Some(Address::new([0x44; 32])));
        assert_eq!(payer.did.as_deref(), Some("did:tenzro:human:payer"));
        assert_eq!(current(), None);
        let seen = paid_by(Some(payer.clone()), async { current() }).await;
        assert_eq!(seen, Some(payer));
        assert_eq!(current(), None);
        let nobody = tenzro_payments::middleware::PaidBy {
            payer_did: String::new(),
            payer_address: String::new(),
        };
        assert_eq!(Payer::from_gate(&nobody), None);
    }

    /// The DID a payment names is kept as it is, with its chain.
    #[test]
    fn a_payer_named_by_did_keeps_that_did() {
        let registry = IdentityRegistry::new();
        let paid = describe(
            Some(&registry),
            9,
            &Payer {
                address: None,
                did: Some("did:tenzro:machine:unregistered".into()),
            },
        );
        assert!(paid["payer"].is_null());
        assert_eq!(paid["payer_did"], "did:tenzro:machine:unregistered");
        assert_eq!(
            paid["principal_chain"]["actor"],
            "did:tenzro:machine:unregistered"
        );
    }
}
