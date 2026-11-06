//! x402: HTTP 402 payments.
//!
//! A 402 response carries `PAYMENT-REQUIRED`, the buyer retries with
//! `PAYMENT-SIGNATURE`, and the paid response carries `PAYMENT-RESPONSE`.
//! [`wire`] maps those headers onto the gateway's challenges and credentials;
//! [`facilitator`] verifies and settles for other resource servers
//! (`/verify`, `/settle`, `/supported`), and
//! [`coinbase::CdpFacilitatorClient`] calls a facilitator elsewhere.

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
pub mod wire;

pub use coinbase::{CdpFacilitatorClient, FacilitatorRequest, VerifyResponse};
pub use erc7710::{
    Caveat, CaveatEnforcerKind, Delegation, ERC20_TRANSFER_SELECTOR, ERC7710_REDEMPTION_DOMAIN,
    Erc7710DelegationVerifier, ROOT_AUTHORITY, RedemptionContext, RedemptionProof,
    SignedDelegation, build_redeem_delegations_calldata, caveat_hash, decode_redemption_proof,
    delegation_hash, encode_erc20_transfer, evm_address_from_verifying_key, recover_signer,
};
pub use facilitator::{
    AgentAccountNetwork, FacilitatorVerification, LedgerRecords, PAY_REF_KEY, PLAN_SCHEME,
    PROVEN_SCHEME, X402Facilitator,
};
pub use facilitator_server::{
    FacilitatorServerState, SupportedKind, SupportedResponse, facilitator_router,
};
pub use local_facilitator::LocalFacilitatorVerifier;
pub use offer::{
    OFFER_COMMITMENT_KEY, OFFER_SIG_KEY, OFFER_SIGNER_KEY, SignedOffer, X402_OFFER_COMMITMENT_LEN,
    X402_OFFER_DOMAIN, compute_offer_commitment,
};
pub use payment_payload::{ExactAuthorization, ExactSchemePayload, X402PaymentPayload};
pub use payment_required::{
    PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER, ResourceInfo,
    X402_WIRE_VERSION, X402PaymentRequired, X402PaymentRequirement,
};
pub use receipt::{PlanSettlement, X402SettlementResponse};
pub use scheme::{
    BATCH_SETTLEMENT_SCHEME, BatchSettlementBackend, CdpFacilitatorVerifier, DEFAULT_SCHEME,
    DelegationVerifier, Eip3009Backend, Erc7710Backend, FacilitatorVerifier, Permit2Backend,
    SchemeBackend, SchemeRegistry, TenzroHybridBackend, UPTO_SCHEME, UptoBackend,
};
pub use server::X402PaymentServer;
pub use wire::{
    CHALLENGE_ID_KEY, DVP_SCHEME, X402_PAYLOAD_KEY, credential_from_header,
    credential_from_payload, payment_required_for, requirement_for,
};
