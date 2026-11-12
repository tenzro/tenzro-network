//! The roles a person can apply for and the stake each one bonds.

use tenzro_types::constants as c;

/// A role an applicant asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinRole {
    Validator,
    EdgeOperator,
    TeeProvider,
    RpcOperator,
    Attestor,
    WalletProvider,
    CatalogPublisher,
    ModelProvider,
    ComputeProvider,
    StorageProvider,
}

impl JoinRole {
    pub const ALL: [JoinRole; 10] = [
        JoinRole::Validator,
        JoinRole::EdgeOperator,
        JoinRole::TeeProvider,
        JoinRole::RpcOperator,
        JoinRole::Attestor,
        JoinRole::WalletProvider,
        JoinRole::CatalogPublisher,
        JoinRole::ModelProvider,
        JoinRole::ComputeProvider,
        JoinRole::StorageProvider,
    ];

    pub fn parse(s: &str) -> Option<JoinRole> {
        Some(
            match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
                "validator" => JoinRole::Validator,
                "edge" | "edge-operator" | "relay" => JoinRole::EdgeOperator,
                "tee" | "tee-provider" => JoinRole::TeeProvider,
                "rpc" | "rpc-operator" => JoinRole::RpcOperator,
                "attestor" => JoinRole::Attestor,
                "wallet" | "wallet-provider" => JoinRole::WalletProvider,
                "catalog" | "catalog-publisher" => JoinRole::CatalogPublisher,
                "ai" | "model" | "model-provider" => JoinRole::ModelProvider,
                "compute" | "compute-provider" => JoinRole::ComputeProvider,
                "storage" | "storage-provider" => JoinRole::StorageProvider,
                _ => return None,
            },
        )
    }

    /// The name used on the application form and in the status endpoint.
    pub fn slug(self) -> &'static str {
        match self {
            JoinRole::Validator => "validator",
            JoinRole::EdgeOperator => "edge-operator",
            JoinRole::TeeProvider => "tee-provider",
            JoinRole::RpcOperator => "rpc-operator",
            JoinRole::Attestor => "attestor",
            JoinRole::WalletProvider => "wallet-provider",
            JoinRole::CatalogPublisher => "catalog-publisher",
            JoinRole::ModelProvider => "model-provider",
            JoinRole::ComputeProvider => "compute-provider",
            JoinRole::StorageProvider => "storage-provider",
        }
    }

    /// How the role reads in a sentence.
    pub fn label(self) -> &'static str {
        match self {
            JoinRole::Validator => "validator",
            JoinRole::EdgeOperator => "edge operator",
            JoinRole::TeeProvider => "TEE provider",
            JoinRole::RpcOperator => "RPC operator",
            JoinRole::Attestor => "attestor",
            JoinRole::WalletProvider => "wallet provider",
            JoinRole::CatalogPublisher => "catalog publisher",
            JoinRole::ModelProvider => "model provider",
            JoinRole::ComputeProvider => "compute provider",
            JoinRole::StorageProvider => "storage provider",
        }
    }

    /// The `--role` value of `tenzro stake bond`, when the role bonds that way
    /// (a validator registers instead).
    pub fn bond_flag(self) -> Option<&'static str> {
        Some(match self {
            JoinRole::Validator => return None,
            JoinRole::EdgeOperator => "edge",
            JoinRole::TeeProvider => "tee",
            JoinRole::RpcOperator => "rpc",
            JoinRole::Attestor => "attestor",
            JoinRole::WalletProvider => "wallet",
            JoinRole::CatalogPublisher => "catalog",
            JoinRole::ModelProvider => "ai",
            JoinRole::ComputeProvider => "compute",
            JoinRole::StorageProvider => "storage",
        })
    }

    /// The minimum stake, in wei, from the protocol constants. The chain's
    /// governed value can be higher; callers that read it pass that instead.
    pub fn stake_minimum_wei(self) -> u128 {
        match self {
            JoinRole::Validator => c::MIN_VALIDATOR_STAKE,
            JoinRole::EdgeOperator => c::MIN_EDGE_OPERATOR_STAKE,
            JoinRole::TeeProvider => c::MIN_TEE_PROVIDER_STAKE,
            JoinRole::RpcOperator => c::MIN_RPC_OPERATOR_STAKE,
            JoinRole::Attestor => c::MIN_ATTESTOR_STAKE,
            JoinRole::WalletProvider => c::MIN_WALLET_PROVIDER_STAKE,
            JoinRole::CatalogPublisher => c::MIN_CATALOG_PUBLISHER_STAKE,
            JoinRole::ModelProvider => c::MIN_MODEL_PROVIDER_STAKE,
            JoinRole::ComputeProvider => c::MIN_COMPUTE_PROVIDER_STAKE,
            JoinRole::StorageProvider => c::MIN_STORAGE_PROVIDER_STAKE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimums_match_the_published_table() {
        let one = c::ONE_TNZO;
        let expect = [
            (JoinRole::Validator, 10_000),
            (JoinRole::EdgeOperator, 10_000),
            (JoinRole::TeeProvider, 10_000),
            (JoinRole::RpcOperator, 100_000),
            (JoinRole::Attestor, 100_000),
            (JoinRole::WalletProvider, 1_000),
            (JoinRole::CatalogPublisher, 1_000),
            (JoinRole::ModelProvider, 1_000),
            (JoinRole::ComputeProvider, 500),
            (JoinRole::StorageProvider, 100),
        ];
        for (r, tnzo) in expect {
            assert_eq!(r.stake_minimum_wei(), tnzo * one, "{}", r.slug());
        }
    }

    #[test]
    fn slugs_and_aliases_round_trip() {
        for r in JoinRole::ALL {
            assert_eq!(JoinRole::parse(r.slug()), Some(r));
        }
        assert_eq!(JoinRole::parse("ai"), Some(JoinRole::ModelProvider));
        assert_eq!(JoinRole::parse("nope"), None);
    }
}
