//! x402 payment protocol implementation (Coinbase)
//!
//! Implements the x402 specification for HTTP 402-based payments.

pub mod payment_required;
pub mod payment_payload;
pub mod facilitator;
pub mod facilitator_server;
pub mod server;
pub mod client;
pub mod coinbase;
pub mod local_facilitator;
pub mod receipt;
pub mod scheme;
pub mod bazaar;
pub mod offer;
pub mod erc7710;

pub use payment_required::{X402PaymentRequired, X402PaymentRequirement, X402_WIRE_VERSION};
pub use payment_payload::{ExactAuthorization, ExactSchemePayload, X402PaymentPayload};
pub use facilitator::X402Facilitator;
pub use facilitator_server::{
    facilitator_router, FacilitatorServerState, SupportedKind, SupportedResponse,
};
pub use server::X402PaymentServer;
pub use client::X402Client;
pub use coinbase::CdpFacilitatorClient;
pub use local_facilitator::LocalFacilitatorVerifier;
pub use receipt::{
    compute_settlement_commitment, validate_network_format, SettlementCommitmentInput,
    TenzroNetwork, X402SettlementReceiptBody, X402_RECEIPT_COMMITMENT_LEN, X402_RECEIPT_DOMAIN,
};
pub use scheme::{
    BatchSettlementBackend, CdpFacilitatorVerifier, DelegationVerifier, Eip3009Backend,
    Erc7710Backend, FacilitatorVerifier, Permit2Backend, SchemeBackend, SchemeRegistry,
    TenzroHybridBackend, UptoBackend, BATCH_SETTLEMENT_SCHEME, DEFAULT_SCHEME, UPTO_SCHEME,
};
pub use erc7710::{
    build_redeem_delegations_calldata, caveat_hash, compute_redemption_binding,
    decode_redemption_proof, delegation_hash, encode_erc20_transfer,
    evm_address_from_verifying_key, recover_signer, Caveat, CaveatEnforcerKind, Delegation,
    Erc7710DelegationVerifier, RedemptionContext, RedemptionProof, SignedDelegation,
    ERC20_TRANSFER_SELECTOR, ERC7710_PREIMAGE_DOMAIN, ROOT_AUTHORITY,
};
pub use bazaar::{
    DiscoveredListing, ResourceCatalog, ResourceCatalogStore, ResourceQuery,
    SellerReputationResolver, X402ResourceListing, BAZAAR_LISTING_DOMAIN,
};
pub use offer::{
    compute_offer_commitment, derive_payment_id, is_payment_id, IdempotencyLedger,
    IdempotencyStore, SignedOffer, OFFER_COMMITMENT_KEY, OFFER_SIGNER_KEY, OFFER_SIG_KEY,
    X402_OFFER_COMMITMENT_LEN, X402_OFFER_DOMAIN, X402_PAYMENT_ID_DOMAIN,
};
