//! Operators a platform node hosts.
//!
//! A node that serves models for several operators names, per model, the
//! operator whose model it is. A call to that model settles to that
//! operator's wallet as its identity on this node records it, never to the
//! node's own payee. When the operator's identity does not resolve to an
//! active identity with a wallet, the call is not settled to anyone else.

use serde::{Deserialize, Serialize};
use tenzro_identity::{IdentityRegistry, IdentityStatus};
use tenzro_types::primitives::Address;

/// One operator this node hosts and the models it serves through the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedOperator {
    /// The operator's DID. Its identity's wallet is paid for its models.
    pub operator_did: String,
    /// The model ids served for this operator.
    pub models: Vec<String>,
}

/// The operator `model` is hosted for, with the wallet a call to it settles
/// to: `None` when no hosted operator serves `model` (the node's own payee is
/// paid), `Some(Err)` when the operator's identity has no active entry with a
/// wallet in `registry`.
pub fn payee_for(
    registry: Option<&IdentityRegistry>,
    hosted: &[HostedOperator],
    model: &str,
) -> Option<Result<(String, Address), String>> {
    let operator = hosted
        .iter()
        .find(|o| o.models.iter().any(|m| m == model))?;
    let did = operator.operator_did.trim();
    Some(
        registry
            .and_then(|r| r.resolve(did).ok())
            .filter(|id| {
                id.status == IdentityStatus::Active && id.wallet_address != Address::default()
            })
            .map(|id| (did.to_string(), id.wallet_address))
            .ok_or_else(|| {
                format!(
                    "{model} is served for {did}, which has no active identity with a wallet on \
                     this node; the call is not settled"
                )
            }),
    )
}

/// Refuse a configuration that names a model for two operators, or an
/// operator with no DID.
pub fn validate(hosted: &[HostedOperator]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for o in hosted {
        if o.operator_did.trim().is_empty() {
            return Err("a hosted operator needs its operator_did".to_string());
        }
        for m in &o.models {
            if !seen.insert(m.as_str()) {
                return Err(format!("model {m} is hosted for more than one operator"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_identity::{IdentityData, TenzroDid, TenzroIdentity};

    fn human(registry: &IdentityRegistry, did: &str, wallet: u8) {
        registry.upsert_identity_for_test(TenzroIdentity {
            did: TenzroDid::parse(did).expect("did"),
            public_keys: Vec::new(),
            identity_data: IdentityData::Human {
                display_name: did.to_string(),
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([wallet; 32]),
            wallet_id: String::new(),
            pq_verifying_key: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: Default::default(),
        });
    }

    const A: &str = "did:tenzro:human:operator-a";
    const B: &str = "did:tenzro:human:operator-b";

    fn hosted() -> Vec<HostedOperator> {
        vec![
            HostedOperator {
                operator_did: A.into(),
                models: vec!["model-a".into()],
            },
            HostedOperator {
                operator_did: B.into(),
                models: vec!["model-b".into(), "model-b2".into()],
            },
        ]
    }

    /// Two operators behind one node are each paid to their own wallet for
    /// their own models; a model hosted for no one is paid to the node.
    #[test]
    fn two_operators_behind_one_node_are_each_paid_to_their_own_wallet() {
        let registry = IdentityRegistry::new();
        human(&registry, A, 0xa1);
        human(&registry, B, 0xb2);
        let hosted = hosted();
        let paid = |m: &str| payee_for(Some(&registry), &hosted, m);
        assert_eq!(
            paid("model-a").expect("hosted").expect("resolves"),
            (A.to_string(), Address::new([0xa1; 32]))
        );
        assert_eq!(
            paid("model-b2").expect("hosted").expect("resolves"),
            (B.to_string(), Address::new([0xb2; 32]))
        );
        assert!(paid("unhosted").is_none(), "the node's own payee is paid");
    }

    /// A hosted model whose operator does not resolve, or no longer has an
    /// active identity, is never settled to the node instead.
    #[test]
    fn an_operator_that_does_not_resolve_is_not_paid_through_the_node() {
        let registry = IdentityRegistry::new();
        human(&registry, A, 0xa1);
        let hosted = hosted();
        let e = payee_for(Some(&registry), &hosted, "model-b")
            .expect("hosted")
            .expect_err("operator b has no identity here");
        assert!(e.contains(B), "{e}");
        assert!(
            payee_for(None, &hosted, "model-a")
                .expect("hosted")
                .is_err()
        );
        registry.suspend(A).expect("suspend");
        assert!(
            payee_for(Some(&registry), &hosted, "model-a")
                .expect("hosted")
                .is_err()
        );
    }

    #[test]
    fn a_model_is_hosted_for_one_operator_only() {
        assert!(validate(&hosted()).is_ok());
        let mut twice = hosted();
        twice[1].models.push("model-a".into());
        assert!(validate(&twice).is_err());
        let mut nameless = hosted();
        nameless[0].operator_did = " ".into();
        assert!(validate(&nameless).is_err());
    }
}
