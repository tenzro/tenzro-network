//! x402 payment protocol implementation (Coinbase)
//!
//! Implements the x402 specification for HTTP 402-based payments.

pub mod bazaar;
pub mod client;
pub mod coinbase;
pub mod erc7710;
pub mod facilitator;
pub mod facilitator_server;
pub mod local_facilitator;
pub mod offer;
pub mod payment_payload;
pub mod payment_required;
pub mod receipt;
pub mod scheme;
pub mod server;

pub use bazaar::{
    BAZAAR_LISTING_DOMAIN, DiscoveredListing, ResourceCatalog, ResourceCatalogStore, ResourceQuery,
    SellerReputationResolver, X402ResourceListing,
};
pub use client::X402Client;
pub use coinbase::CdpFacilitatorClient;
pub use erc7710::{
    Caveat, CaveatEnforcerKind, Delegation, ERC20_TRANSFER_SELECTOR, ERC7710_PREIMAGE_DOMAIN,
    Erc7710DelegationVerifier, ROOT_AUTHORITY, RedemptionContext, RedemptionProof,
    SignedDelegation, build_redeem_delegations_calldata, caveat_hash, compute_redemption_binding,
    decode_redemption_proof, delegation_hash, encode_erc20_transfer,
    evm_address_from_verifying_key, recover_signer,
};
pub use facilitator::X402Facilitator;
pub use facilitator_server::{
    FacilitatorServerState, SupportedKind, SupportedResponse, facilitator_router,
};
pub use local_facilitator::LocalFacilitatorVerifier;
pub use offer::{
    IdempotencyLedger, IdempotencyStore, OFFER_COMMITMENT_KEY, OFFER_SIG_KEY, OFFER_SIGNER_KEY,
    SignedOffer, X402_OFFER_COMMITMENT_LEN, X402_OFFER_DOMAIN, X402_PAYMENT_ID_DOMAIN,
    compute_offer_commitment, derive_payment_id, is_payment_id,
};
pub use payment_payload::{ExactAuthorization, ExactSchemePayload, X402PaymentPayload};
pub use payment_required::{X402_WIRE_VERSION, X402PaymentRequired, X402PaymentRequirement};
pub use receipt::{
    SettlementCommitmentInput, TenzroNetwork, X402_RECEIPT_COMMITMENT_LEN, X402_RECEIPT_DOMAIN,
    X402SettlementReceiptBody, compute_settlement_commitment, validate_network_format,
};
pub use scheme::{
    BATCH_SETTLEMENT_SCHEME, BatchSettlementBackend, CdpFacilitatorVerifier, DEFAULT_SCHEME,
    DelegationVerifier, Eip3009Backend, Erc7710Backend, FacilitatorVerifier, Permit2Backend,
    SchemeBackend, SchemeRegistry, TenzroHybridBackend, UPTO_SCHEME, UptoBackend,
};
pub use server::X402PaymentServer;
