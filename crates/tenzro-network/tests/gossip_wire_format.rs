//! Every gossip payload must survive the wire format it is actually sent over.
//!
//! Gossip is bincode (`NetworkMessage::to_bytes`), which is **not
//! self-describing**: there are no field names on the wire, so the decoder
//! reads fields positionally. Two serde attributes are therefore unsound here
//! and produce no compile error, no test failure in any JSON-based test, and
//! no error at serialization time:
//!
//! - `skip_serializing_if` — the field is omitted, the decoder still reads one
//!   at that position, and every subsequent byte shifts.
//! - `flatten` — bincode cannot represent it at all.
//!
//! The damage is silent and delayed. A skipped `Option` near the end of an
//! embedded struct corrupts an enum discriminant several fields later, so the
//! error names a type that is entirely innocent. In production this read as
//! `tag for enum is not valid, found 64` and took provider discovery to zero
//! across every node simultaneously, while blocks and transactions kept
//! flowing — so the network looked healthy.
//!
//! These tests round-trip each broadcast payload through the real envelope.
//! They are deliberately built from `Default`, because the default is exactly
//! the case that breaks: `skip_serializing_if = "Option::is_none"` only omits
//! bytes when the value *is* `None`, which is the common case in the field and
//! the one a hand-built fixture with every field populated would miss.

use tenzro_network::message::{MessagePayload, NetworkMessage, ProviderAnnouncementMessage};

/// Round-trip a payload through the exact path gossip uses.
fn round_trip(payload: MessagePayload, what: &str) {
    let msg = NetworkMessage::new(payload);
    let bytes = msg
        .to_bytes()
        .unwrap_or_else(|e| panic!("{what}: serialization failed: {e}"));

    // Serialization succeeding proves nothing — `skip_serializing_if` writes
    // happily and only the decoder notices. The decode is the assertion.
    NetworkMessage::from_bytes(&bytes).unwrap_or_else(|e| {
        panic!(
            "{what}: {} bytes did not decode: {e}\n\
             This is the bincode/`skip_serializing_if` trap — check that no \
             field on this payload, or on any struct it embeds, carries \
             `skip_serializing_if` or `flatten`.",
            bytes.len()
        )
    });
}

/// The payload whose corruption took provider discovery to zero.
///
/// Built from `Default` on purpose: `capacity.jurisdiction` is `None` in the
/// default, and `None` is precisely when the byte went missing.
#[test]
fn a_default_provider_announcement_survives_the_wire() {
    round_trip(
        MessagePayload::ProviderAnnouncement(ProviderAnnouncementMessage::default()),
        "ProviderAnnouncement (default)",
    );
}

/// A populated announcement round-trips too, so the test does not merely
/// prove the empty case.
#[test]
fn a_populated_provider_announcement_survives_the_wire() {
    let mut ann = ProviderAnnouncementMessage {
        iroh_endpoint_id: iroh::SecretKey::from_bytes(&[7; 32]).public().to_string(),
        provider_address: "0xabc".to_string(),
        provider_type: "ai".to_string(),
        served_models: vec!["qwen3.5-9b-mtp".to_string()],
        capabilities: vec!["inference".to_string()],
        status: "active".to_string(),
        ..Default::default()
    };
    // Nested defaults, so these stay assignments.
    ann.capacity.max_concurrent_requests = 8;
    ann.capacity.active_requests = 2;
    ann.trust_profile.identity_root = "tpm".to_string();
    // Signed by a hybrid identity, so the session certificate's composite
    // signature (both legs) crosses the wire.
    let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(std::sync::Arc::new(
        tenzro_crypto::composite::testing::TestHybridSigner::hybrid(7),
    ));
    tenzro_network::SignedAnnouncement::sign(&mut ann, "did:tenzro:machine:wire", &signer).unwrap();

    round_trip(
        MessagePayload::ProviderAnnouncement(ann),
        "ProviderAnnouncement (populated)",
    );
}

/// A declared jurisdiction must survive the wire too.
///
/// `AdvertisedCapacity.jurisdiction` is `None` on every node today, which is
/// the only reason `JurisdictionClaim`'s own skipped field was not a second
/// outage waiting behind the first. The first operator to declare a
/// jurisdiction would have found it. Populate it here so that stays fixed.
#[test]
fn a_declared_jurisdiction_survives_the_wire() {
    let mut ann = ProviderAnnouncementMessage::default();
    ann.capacity.jurisdiction = Some(tenzro_types::model::JurisdictionClaim {
        country: "DE".to_string(),
        blocs: vec!["EU".to_string(), "EEA".to_string()],
        // `None` is the case that omitted a byte — keep it that way.
        attestation_hash: None,
        declared_at: Default::default(),
    });

    round_trip(
        MessagePayload::ProviderAnnouncement(ann),
        "ProviderAnnouncement (jurisdiction declared)",
    );
}

/// The size delta is the whole tell. A payload that serializes to *fewer*
/// bytes than it decodes is the signature of a skipped field, so pin the
/// property directly rather than only observing the decode error it causes.
#[test]
fn serializing_an_announcement_writes_every_field_it_reads() {
    let bytes = NetworkMessage::new(MessagePayload::ProviderAnnouncement(
        ProviderAnnouncementMessage::default(),
    ))
    .to_bytes()
    .expect("serialize");

    let decoded = NetworkMessage::from_bytes(&bytes).expect("decode");
    let reencoded = decoded.to_bytes().expect("re-serialize");

    assert_eq!(
        bytes.len(),
        reencoded.len(),
        "encode/decode/encode changed length — a field is being written that \
         is not read back, or vice versa"
    );
    assert_eq!(
        bytes, reencoded,
        "round-trip was not byte-stable; the wire form is not canonical"
    );
}

/// Every transaction variant at its default field values, in declaration
/// order. `variant_index` below is an exhaustive match, so adding a variant
/// fails to compile until it is given an index, and the coverage assertion
/// then fails until it is given a fixture here.
fn every_transaction_variant_at_defaults() -> Vec<tenzro_types::transaction::TransactionType> {
    use tenzro_types::primitives::Address;
    use tenzro_types::settlement::{ProofType, ReleaseConditions, ServiceProof};
    use tenzro_types::transaction::TransactionType as T;
    let zero = Address::new([0u8; 32]);
    vec![
        T::Transfer { amount: 0 },
        T::ContractDeploy {
            code: Vec::new(),
            args: Vec::new(),
        },
        T::ContractCall { calls: Vec::new() },
        T::AgentRegister { config: Vec::new() },
        T::AgentExecute { task: Vec::new() },
        T::ModelInference {
            model_id: String::new(),
            input: Vec::new(),
        },
        T::TeeProviderRegister {
            attestation: Vec::new(),
            info: Vec::new(),
        },
        T::GovernancePropose {
            proposal: Vec::new(),
        },
        T::GovernanceVote {
            proposal_id: String::new(),
            vote: false,
            validator: Address::new([0u8; 32]),
            root_approval: None,
        },
        T::GovernanceVeto {
            proposal_id: String::new(),
        },
        T::GovernancePause { paused: false },
        T::GovernanceExecute {
            proposal_id: String::new(),
        },
        T::Funding { op: Vec::new() },
        T::CreateEscrow {
            payee: zero,
            amount: 0,
            asset_id: tenzro_types::asset::AssetId(String::new()),
            usd_e6: 0,
            expires_at: 0,
            release_conditions: ReleaseConditions::Timeout,
            reference: None,
        },
        T::ReleaseEscrow {
            escrow_id: [0u8; 32],
            proof: ServiceProof::new(ProofType::Cryptographic, Vec::new()),
        },
        T::RefundEscrow {
            escrow_id: [0u8; 32],
        },
        T::PauseAgent {
            agent_did: String::new(),
            controller_did: String::new(),
            reason_code: 0,
            reason_text: None,
            until: None,
        },
        T::QuarantineAgent {
            agent_did: String::new(),
            controller_did: String::new(),
            reason_code: 0,
            reason_text: None,
            evidence_hash: None,
        },
        T::TerminateAgent {
            agent_did: String::new(),
            controller_did: String::new(),
            reason_code: 0,
            slash_bps: 0,
            cascade: false,
        },
        T::PostAgentBond {
            agent_did: String::new(),
            controller_did: String::new(),
            amount: 0,
        },
        T::IncreaseAgentBond {
            agent_did: String::new(),
            amount: 0,
        },
        T::WithdrawAgentBond {
            agent_did: String::new(),
        },
        T::PostComputeBond {
            provider_did: String::new(),
            amount: 0,
        },
        T::IncreaseComputeBond {
            provider_did: String::new(),
            amount: 0,
        },
        T::WithdrawComputeBond {
            provider_did: String::new(),
        },
        T::FinalizeComputeBondWithdrawal {
            provider_did: String::new(),
        },
        T::PayInsuranceClaim {
            evidence: tenzro_types::insurance::InsuranceEvidence::ReconMismatch {
                adapter: tenzro_types::bridge_route::BridgeRouteAdapter::Ibc,
                chain: String::new(),
                position: 0,
            },
        },
        T::PayerSettle {
            payer: zero,
            payee: zero,
            amount: 0,
            payment_id: String::new(),
            authorization: tenzro_types::payment_authorization::PaymentAuthorization {
                resellers: Vec::new(),
                binding: Default::default(),
                public_key: Vec::new(),
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
                max_amount: 0,
                asset: String::new(),
            },
        },
        T::ClaimEscrow { claims: Vec::new() },
        T::ClaimEscrowPreimage {
            escrow_id: [0u8; 32],
            preimage: Vec::new(),
        },
        T::ClaimEscrowStream {
            escrow_id: [0u8; 32],
        },
        T::PostMeterBond {
            meter_public_key: Vec::new(),
            amount: 0,
            consent: tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        },
        T::WithdrawMeterBond {
            meter_id: [0u8; 32],
        },
        T::DisputeMeteredCharge {
            dispute: tenzro_types::metering::MeterDispute::OverCeiling {
                record: tenzro_types::metering::UsageRecord {
                    challenge_id: String::new(),
                    payer: String::new(),
                    ceiling: 0,
                    lines: Vec::new(),
                    measured_at_ms: 0,
                    commitments: Default::default(),
                    meter_key: String::new(),
                    signature: tenzro_types::account_signature::CompositeSignature::classical(
                        tenzro_types::account_signature::ClassicalProof::Raw {
                            signature: Vec::new(),
                        },
                    ),
                },
            },
        },
        T::TreasuryDeposit { amount: 0 },
        T::IncreaseValidatorStake { additional: 0 },
        T::RegisterValidator {
            ml_dsa_pubkey: Vec::new(),
            p256_pubkey: Vec::new(),
            node_key: [0u8; 32],
            proof_of_possession: Vec::new(),
            node_key_proof: Vec::new(),
            vrf_key: [0u8; 32],
            vrf_key_proof: Vec::new(),
            withdrawal_address: zero,
            self_stake: 0,
            metadata_uri: String::new(),
        },
        T::ReportCheckpointEquivocation {
            evidence: Vec::new(),
        },
        T::ExitValidator,
        T::UpdateValidatorMetadata {
            metadata_uri: None,
            tee_attestation_hash: None,
        },
        T::RegisterIdentity {
            did: String::new(),
            identity_type: String::new(),
            display_name: String::new(),
            controller_pubkey: Vec::new(),
            key_type: String::new(),
            wallet_id: String::new(),
            wallet_address: zero,
            pq_verifying_key: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
            proof: tenzro_types::identity::RegistrationProof::TpmQuote {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        },
        T::AttestZkProof { proof: Vec::new() },
        T::SlaAttest {
            epoch: 0,
            outcomes: Vec::new(),
        },
        T::ComputeClaim {
            op: tenzro_types::transaction::ComputeClaimOp::Offer {
                hardware_class: 0,
                region: String::new(),
                delivery_start_ms: 0,
                epochs: 0,
                strike_per_epoch: 0,
                collateral: 0,
                provider_did: String::new(),
                storage_descriptor: None,
                unit: None,
                units_per_epoch: 0,
            },
        },
        T::RecordCheckpointSigners {
            certificate: Vec::new(),
        },
        T::AgentAuditCommit {
            epoch: 0,
            root: Vec::new(),
            sessions: 0,
            entries_ref: String::new(),
            attestation: Vec::new(),
        },
        T::LiftAgentQuarantine {
            agent_did: String::new(),
            reason_text: None,
        },
        T::AgentAuditFlag {
            epoch: 0,
            findings: Vec::new(),
        },
        T::RevokeDelegatedAgent {
            agent_did: String::new(),
            controller_did: String::new(),
            approval_digest: [0u8; 32],
        },
        T::SetAgentTerms {
            terms: tenzro_types::agent_terms::AgentTerms {
                controller_did: String::new(),
                agent_name: String::new(),
                delegation_scope: Default::default(),
                capabilities: Vec::new(),
                serving_nodes: Vec::new(),
                min_distinct_operators: 1,
                expires_at_ms: None,
                trifecta_exception: false,
                auto_approve: None,
                credentials: Vec::new(),
            },
            rotate: None,
            approval: tenzro_types::agent_terms::AgentTermsApproval {
                account: Vec::new(),
                nonce: [0u8; 16],
                root_public_key: vec![4u8; 64],
                signature: tenzro_types::account_signature::CompositeSignature::hybrid(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: vec![5u8; 64],
                    },
                    vec![6u8; 3309],
                ),
            },
        },
        T::AgentAct {
            action: tenzro_types::agent_terms::AgentAction {
                asset: None,
                usd_e6: 0,
                payment: None,
                agent_did: String::new(),
                machine_did: String::new(),
                operation: String::new(),
                counterparty: String::new(),
                amount: 0,
                chain: String::new(),
                payment_protocol: None,
                model: None,
                calls: Vec::new(),
                escrow: None,
                remote_grant: None,
                ballot: None,
                veto_signal: None,
                nonce: 0,
                tainted: false,
                step_up: None,
            },
            signature: Vec::new(),
        },
        T::FeeRateSubmit {
            epoch: 0,
            commitment: [0u8; 32],
            reveal: None,
        },
        T::InferenceFault {
            op: tenzro_types::inference_verification::InferenceFaultOp::Attest {
                fault_id: String::new(),
                upheld: false,
            },
        },
        T::Bridge {
            op: tenzro_types::bridge_transfer::BridgeOp::SendMessage {
                target_chain: "ethereum".into(),
                payload: vec![1],
            },
        },
        T::Token {
            op: tenzro_types::token_op::TokenOp::SetHalted {
                token_id: [0; 32],
                halted: true,
                action: tenzro_types::token_policy::IssuerAction {
                    reason_code: 1,
                    evidence_hash: [1; 32],
                },
            },
        },
        T::Stake {
            op: tenzro_types::token::StakeOp::Withdraw {
                role: tenzro_types::NetworkRole::Rpc,
            },
        },
        T::RemoteGrantSettle {
            agent_did: String::new(),
            chain: String::new(),
            delivery: Vec::new(),
        },
        T::Payment {
            op: tenzro_types::settlement::PaymentOp::Receipt {
                receipt: tenzro_types::payment_authorization::DeliveryReceipt {
                    pay_ref: [0; 32],
                    body_digest: [0; 32],
                    inference_receipt: None,
                    delivered_at_ms: 0,
                    hardware: None,
                },
            },
        },
        T::GovernanceVetoSignal {
            proposal_id: String::new(),
            amount: 0,
        },
        T::GovernanceVetoWithdraw {
            proposal_id: String::new(),
            holder: zero,
        },
        T::GovernanceConcern {
            proposal_id: String::new(),
        },
        T::UpgradeReady {
            code_hash: String::new(),
            quote: vec![],
        },
        T::GovernanceSecurityDisclosure {
            proposal_id: String::new(),
            disclosure: vec![],
        },
        T::SettlementPlan {
            op: tenzro_types::settlement::PlanOp::Open {
                nonce: 1,
                quote_digest: [0; 32],
                split_hash: [0; 32],
                split: tenzro_types::split::SplitRule::sole(
                    tenzro_types::split::SplitRole::Payee,
                    tenzro_types::primitives::Address::new([1; 32]),
                ),
                legs: vec![tenzro_types::settlement::Leg {
                    kind: tenzro_types::settlement::LegKind::NativeTransfer {
                        amount: u128::MAX,
                        escrow_id: Some([2; 32]),
                    },
                    class_required: tenzro_types::settlement::LegClass::Native,
                    usd_e6: 0,
                    max_network_fee: 0,
                }],
                decide_deadline_ms: 0,
                agent: None,
                attribution: None,
            },
        },
        T::BeaconContribute {
            round: 0,
            proof: Vec::new(),
        },
        T::DaRetention {
            op: tenzro_types::da_retention::DaRetentionOp::Record {
                commitment: String::new(),
                class: tenzro_types::da_retention::DaObjectClass::Audit,
                size_bytes: 0,
            },
        },
        T::AccountKeys {
            op: tenzro_types::account_signature::AccountKeysOp::EnrollPqKey {
                ml_dsa_public_key: Vec::new(),
                possession: Vec::new(),
            },
        },
        T::KeystoreUpdate {
            update: tenzro_types::keystore::KeystoreUpdate {
                chain_id: 0,
                account: vec![0; 20],
                anchor: None,
                previous_commitment: vec![0; 32],
                op: tenzro_types::keystore::KeystoreOp::CancelRecovery,
                approvals: Vec::new(),
                possession: None,
            },
        },
        T::IdentityServices {
            op: tenzro_types::did_services::IdentityServiceOp {
                did: "did:tenzro:human:00".to_string(),
                version: 0,
                change: tenzro_types::did_services::DidServiceChange::Remove {
                    id: "inbox".to_string(),
                },
                approval: tenzro_types::agent_terms::AgentTermsApproval {
                    account: Vec::new(),
                    nonce: [0u8; 16],
                    root_public_key: vec![4u8; 64],
                    signature: tenzro_types::account_signature::CompositeSignature::classical(
                        tenzro_types::account_signature::ClassicalProof::Raw {
                            signature: vec![5u8; 64],
                        },
                    ),
                },
            },
        },
        T::ExternalEvm { raw: Vec::new() },
        T::ExternalSvm { raw: Vec::new() },
        T::RevokeIdentity {
            op: tenzro_types::identity::IdentityRevocationOp {
                did: "did:tenzro:human:00".to_string(),
                reason: String::new(),
                approver_did: "did:tenzro:human:00".to_string(),
                approval: tenzro_types::agent_terms::AgentTermsApproval {
                    account: Vec::new(),
                    nonce: [0u8; 16],
                    root_public_key: vec![4u8; 64],
                    signature: tenzro_types::account_signature::CompositeSignature::classical(
                        tenzro_types::account_signature::ClassicalProof::Raw {
                            signature: vec![5u8; 64],
                        },
                    ),
                },
            },
        },
        T::Registry {
            op: tenzro_types::transaction::RegistryOp::Retire { id: String::new() },
        },
        T::SetAgentTopUp {
            agent_did: String::new(),
            controller_did: String::new(),
            allowance: Some((u128::MAX, u64::MAX, u128::MAX, i64::MIN)),
        },
        T::TopUpAgent {
            agent_did: String::new(),
        },
        T::ReclaimAgentFunds {
            agent_did: String::new(),
            controller_did: String::new(),
            amount: Some(u128::MAX),
        },
        T::RotateValidatorKey {
            ml_dsa_pubkey: Vec::new(),
            p256_pubkey: Vec::new(),
            proof_of_possession: Vec::new(),
        },
        T::HardwareProof {
            op: tenzro_types::hardware_level::HardwareProofOp::Possession {
                epoch: u64::MAX,
                quote: vec![0xff; 1024],
                signature: vec![0xff; 64],
            },
        },
        T::RegisterValidatorMachine {
            machine_p256: Vec::new(),
            machine_ml_dsa: Vec::new(),
            p256_signature: Vec::new(),
            ml_dsa_signature: Vec::new(),
        },
        T::KeyRelease {
            op: tenzro_types::key_release::KeyReleaseOp::Revoke {
                model_id: "m".repeat(128),
                reason: "r".repeat(256),
            },
        },
        T::TrainingProof {
            op: tenzro_types::training_verification::TrainingProofOp::Settle {
                receipt_id: String::new(),
            },
        },
        T::AttachMachineAttestation {
            op: tenzro_types::identity::AttachMachineAttestationOp {
                did: String::new(),
                attestation: String::new(),
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        },
        T::SponsoredBond {
            op: tenzro_types::transaction::SponsoredBondOp::Release {
                validator: tenzro_types::primitives::Address::new([0u8; 32]),
            },
        },
        T::AccountOutflow { op: vec![1, 2, 3] },
    ]
}

/// Declaration index of each variant. Exhaustive on purpose: no wildcard arm.
fn variant_index(t: &tenzro_types::transaction::TransactionType) -> usize {
    use tenzro_types::transaction::TransactionType as T;
    match t {
        T::Transfer { .. } => 0,
        T::ContractDeploy { .. } => 1,
        T::ContractCall { .. } => 2,
        T::AgentRegister { .. } => 3,
        T::AgentExecute { .. } => 4,
        T::ModelInference { .. } => 5,
        T::TeeProviderRegister { .. } => 6,
        T::GovernancePropose { .. } => 7,
        T::GovernanceVote { .. } => 8,
        T::GovernanceVeto { .. } => 9,
        T::GovernancePause { .. } => 10,
        T::GovernanceExecute { .. } => 11,
        T::Funding { .. } => 12,
        T::CreateEscrow { .. } => 13,
        T::ReleaseEscrow { .. } => 14,
        T::RefundEscrow { .. } => 15,
        T::PauseAgent { .. } => 16,
        T::QuarantineAgent { .. } => 17,
        T::TerminateAgent { .. } => 18,
        T::PostAgentBond { .. } => 19,
        T::IncreaseAgentBond { .. } => 20,
        T::WithdrawAgentBond { .. } => 21,
        T::PostComputeBond { .. } => 22,
        T::IncreaseComputeBond { .. } => 23,
        T::WithdrawComputeBond { .. } => 24,
        T::FinalizeComputeBondWithdrawal { .. } => 25,
        T::PayInsuranceClaim { .. } => 26,
        T::PayerSettle { .. } => 27,
        T::ClaimEscrow { .. } => 28,
        T::ClaimEscrowPreimage { .. } => 29,
        T::ClaimEscrowStream { .. } => 30,
        T::PostMeterBond { .. } => 31,
        T::WithdrawMeterBond { .. } => 32,
        T::DisputeMeteredCharge { .. } => 33,
        T::TreasuryDeposit { .. } => 34,
        T::IncreaseValidatorStake { .. } => 35,
        T::RegisterValidator { .. } => 36,
        T::ReportCheckpointEquivocation { .. } => 37,
        T::ExitValidator => 38,
        T::UpdateValidatorMetadata { .. } => 39,
        T::RegisterIdentity { .. } => 40,
        T::AttestZkProof { .. } => 41,
        T::SlaAttest { .. } => 42,
        T::ComputeClaim { .. } => 43,
        T::RecordCheckpointSigners { .. } => 44,
        T::AgentAuditCommit { .. } => 45,
        T::LiftAgentQuarantine { .. } => 46,
        T::AgentAuditFlag { .. } => 47,
        T::RevokeDelegatedAgent { .. } => 48,
        T::SetAgentTerms { .. } => 49,
        T::AgentAct { .. } => 50,
        T::FeeRateSubmit { .. } => 51,
        T::InferenceFault { .. } => 52,
        T::Bridge { .. } => 53,
        T::Token { .. } => 54,
        T::Stake { .. } => 55,
        T::RemoteGrantSettle { .. } => 56,
        T::Payment { .. } => 57,
        T::GovernanceVetoSignal { .. } => 58,
        T::GovernanceVetoWithdraw { .. } => 59,
        T::GovernanceConcern { .. } => 60,
        T::UpgradeReady { .. } => 61,
        T::GovernanceSecurityDisclosure { .. } => 62,
        T::SettlementPlan { .. } => 63,
        T::BeaconContribute { .. } => 64,
        T::DaRetention { .. } => 65,
        T::AccountKeys { .. } => 66,
        T::KeystoreUpdate { .. } => 67,
        T::IdentityServices { .. } => 68,
        T::ExternalEvm { .. } => 69,
        T::ExternalSvm { .. } => 70,
        T::RevokeIdentity { .. } => 71,
        T::Registry { .. } => 72,
        T::SetAgentTopUp { .. } => 73,
        T::TopUpAgent { .. } => 74,
        T::ReclaimAgentFunds { .. } => 75,
        T::RotateValidatorKey { .. } => 76,
        T::HardwareProof { .. } => 77,
        T::RegisterValidatorMachine { .. } => 78,
        T::KeyRelease { .. } => 79,
        T::TrainingProof { .. } => 80,
        T::AttachMachineAttestation { .. } => 81,
        T::SponsoredBond { .. } => 82,
        T::AccountOutflow { .. } => 83,
    }
}

/// Number of `TransactionType` variants. Bump together with `variant_index`.
const TRANSACTION_VARIANT_COUNT: usize = 84;

fn signed_default_transaction(
    tx_type: tenzro_types::transaction::TransactionType,
) -> tenzro_types::transaction::SignedTransaction {
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    use tenzro_types::transaction::{SignedTransaction, Transaction};
    let tx = Transaction::new(
        ChainId::from(1337u64),
        Address::new([0u8; 32]),
        Address::new([0u8; 32]),
        Nonce::from(0u64),
        tx_type,
        0,
        0,
    );
    // The ML-DSA-65 leg's length is enforced at decode, so the fixture
    // carries a correctly sized (unverified) leg.
    SignedTransaction::new(
        tx,
        vec![0u8; 64],
        tenzro_types::account_signature::CompositeSignature {
            classical: tenzro_types::account_signature::ClassicalProof::Raw {
                signature: vec![0u8; 64],
            },
            pq: Some(vec![0u8; 3309]),
        },
    )
}

#[test]
fn the_fixture_list_covers_every_transaction_variant() {
    let fixtures = every_transaction_variant_at_defaults();
    let mut seen: Vec<usize> = fixtures.iter().map(variant_index).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen,
        (0..TRANSACTION_VARIANT_COUNT).collect::<Vec<_>>(),
        "every TransactionType variant needs a default-valued fixture"
    );
}

/// A transaction of every variant, with every optional field unset, survives
/// the gossip transaction topic.
#[test]
fn every_transaction_variant_at_defaults_survives_the_wire() {
    for tx_type in every_transaction_variant_at_defaults() {
        let what = format!("Transaction variant #{}", variant_index(&tx_type));
        let signed = signed_default_transaction(tx_type);
        let bytes = NetworkMessage::new(MessagePayload::Transaction(signed.clone()))
            .to_bytes()
            .unwrap_or_else(|e| panic!("{what}: serialization failed: {e}"));
        let decoded = NetworkMessage::from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("{what}: {} bytes did not decode: {e}", bytes.len()));
        match decoded.payload {
            MessagePayload::Transaction(back) => assert_eq!(
                back.transaction.tx_type, signed.transaction.tx_type,
                "{what}: decoded to a different transaction"
            ),
            _ => panic!("{what}: decoded to a different payload kind"),
        }
    }
}

/// The same transactions, carried inside a block on the gossip block topic:
/// one undecodable transaction makes the whole block undecodable.
#[test]
fn a_block_holding_every_transaction_variant_survives_the_wire() {
    use tenzro_types::block::{Block, BlockHeader};
    use tenzro_types::primitives::{Address, BlockHeight, Hash};
    let txs: Vec<_> = every_transaction_variant_at_defaults()
        .into_iter()
        .map(signed_default_transaction)
        .collect();
    let header = BlockHeader::new(
        BlockHeight::from(1u64),
        Hash::default(),
        Block::compute_tx_root(&txs),
        Hash::default(),
        Address::new([0u8; 32]),
    );
    let block = Block::new(header, txs);
    round_trip(
        MessagePayload::Block(block),
        "Block with every transaction variant",
    );
}

/// Builds values of any `Deserialize` type straight from its serde shape, so
/// every variant of `TransactionType` and of every enum nested in it (the op
/// enums: token, stake, bridge, payment, escrow, governance and
/// the rest) is produced without a hand-written fixture. A variant added
/// later is picked up automatically: the variant list comes from serde.
///
/// Two modes: `populated` (every `Option` is `Some`, every collection holds
/// entries) and empty (every `Option` is `None`, every collection is empty).
/// The empty mode is the one that catches `skip_serializing_if`.
///
/// Strings are parsed by some types (addresses, roles, amounts), so each
/// string position tries a list of candidates until the value builds.
mod fill {
    use serde::de::{self, DeserializeSeed, IntoDeserializer, Visitor};
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt;

    #[derive(Debug)]
    pub struct Error(pub String);
    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Error {}
    impl de::Error for Error {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            Error(msg.to_string())
        }
    }

    const MAX_DEPTH: usize = 24;

    fn candidates(populated: bool) -> Vec<String> {
        let hex32 = "07".repeat(32);
        let mut c = vec![
            "TNZO".to_string(),
            format!("0x{hex32}"),
            hex32,
            "7".to_string(),
            "0x07".to_string(),
            "validator".to_string(),
            "did:tenzro:human:0707".to_string(),
            "https://example.org/x".to_string(),
            "0707".to_string(),
            format!("02{}", "07".repeat(32)),
            format!("0x02{}", "07".repeat(32)),
            "07".repeat(20),
            format!("0x{}", "07".repeat(20)),
            "07".repeat(64),
            format!("0x{}", "07".repeat(64)),
            "07".repeat(256),
        ];
        if !populated {
            c.insert(0, String::new());
        }
        c
    }

    #[derive(Default, Clone)]
    struct Coverage {
        /// enum name -> which variants have been produced.
        covered: BTreeMap<&'static str, Vec<bool>>,
        /// (enum, variant) -> enums reachable beneath that variant.
        reach: BTreeMap<(&'static str, usize), BTreeSet<&'static str>>,
        progressed: bool,
    }

    #[derive(Default)]
    pub struct State {
        populated: bool,
        cov: Coverage,
        stack: Vec<(&'static str, usize)>,
        ctx: Vec<String>,
        strings: Vec<String>,
        string_choice: BTreeMap<String, usize>,
        last_string: Option<String>,
        any_at: Option<String>,
        enum_keys: BTreeMap<String, &'static str>,
    }

    impl State {
        fn enum_key(
            &mut self,
            name: &'static str,
            variants: &'static [&'static str],
        ) -> &'static str {
            let full = format!("{name}{{{}}}", variants.join(","));
            if let Some(k) = self.enum_keys.get(&full) {
                return k;
            }
            let distinct = !self
                .enum_keys
                .keys()
                .any(|k| k.split('{').next() == Some(name));
            let k: &'static str = if distinct {
                name
            } else {
                Box::leak(full.clone().into_boxed_str())
            };
            self.enum_keys.insert(full, k);
            k
        }

        fn incomplete(&self, name: &str) -> bool {
            self.cov
                .covered
                .get(name)
                .is_some_and(|v| v.iter().any(|c| !c))
        }

        fn choose(&mut self, name: &'static str, n: usize) -> usize {
            for (anc, var) in self.stack.clone() {
                self.cov.reach.entry((anc, var)).or_default().insert(name);
            }
            let cov = self
                .cov
                .covered
                .entry(name)
                .or_insert_with(|| vec![false; n]);
            if let Some(i) = cov.iter().position(|c| !c) {
                cov[i] = true;
                self.cov.progressed = true;
                return i;
            }
            (0..n)
                .find(|v| {
                    self.cov
                        .reach
                        .get(&(name, *v))
                        .is_some_and(|r| r.iter().any(|e| *e != name && self.incomplete(e)))
                })
                .unwrap_or(0)
        }

        fn path(&self) -> String {
            self.ctx.join(" > ")
        }
    }

    #[derive(Clone, Copy)]
    pub struct Filler<'a> {
        st: &'a RefCell<State>,
        depth: usize,
    }

    impl<'a> Filler<'a> {
        fn deeper(self) -> Self {
            Filler {
                st: self.st,
                depth: self.depth + 1,
            }
        }
        fn count(self) -> usize {
            if self.st.borrow().populated && self.depth < MAX_DEPTH {
                2
            } else {
                0
            }
        }
        fn scoped<T>(self, label: String, f: impl FnOnce() -> T) -> T {
            self.st.borrow_mut().ctx.push(label);
            let out = f();
            self.st.borrow_mut().ctx.pop();
            out
        }
    }

    struct Seq<'a> {
        f: Filler<'a>,
        left: usize,
        fields: Option<&'static [&'static str]>,
        at: usize,
    }
    impl<'de, 'a> de::SeqAccess<'de> for Seq<'a> {
        type Error = Error;
        fn next_element_seed<T: DeserializeSeed<'de>>(
            &mut self,
            seed: T,
        ) -> Result<Option<T::Value>, Error> {
            if self.left == 0 {
                return Ok(None);
            }
            self.left -= 1;
            let label = match self.fields {
                Some(fs) => format!(".{}", fs.get(self.at).copied().unwrap_or("?")),
                None => format!("[{}]", self.at),
            };
            self.at += 1;
            let f = self.f.deeper();
            f.scoped(label, || seed.deserialize(f)).map(Some)
        }
        fn size_hint(&self) -> Option<usize> {
            Some(self.left)
        }
    }

    struct Map<'a> {
        f: Filler<'a>,
        left: usize,
    }
    impl<'de, 'a> de::MapAccess<'de> for Map<'a> {
        type Error = Error;
        fn next_key_seed<K: DeserializeSeed<'de>>(
            &mut self,
            seed: K,
        ) -> Result<Option<K::Value>, Error> {
            if self.left == 0 {
                return Ok(None);
            }
            self.left -= 1;
            let f = self.f.deeper();
            f.scoped("{key}".into(), || seed.deserialize(f)).map(Some)
        }
        fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
            let f = self.f.deeper();
            f.scoped("{value}".into(), || seed.deserialize(f))
        }
    }

    struct Enum<'a> {
        f: Filler<'a>,
        idx: usize,
    }
    impl<'de, 'a> de::EnumAccess<'de> for Enum<'a> {
        type Error = Error;
        type Variant = Self;
        fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), Error> {
            let d: de::value::U32Deserializer<Error> = (self.idx as u32).into_deserializer();
            Ok((seed.deserialize(d)?, self))
        }
    }
    impl<'de, 'a> de::VariantAccess<'de> for Enum<'a> {
        type Error = Error;
        fn unit_variant(self) -> Result<(), Error> {
            Ok(())
        }
        fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
            seed.deserialize(self.f.deeper())
        }
        fn tuple_variant<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, Error> {
            v.visit_seq(Seq {
                f: self.f,
                left: len,
                fields: None,
                at: 0,
            })
        }
        fn struct_variant<V: Visitor<'de>>(
            self,
            fields: &'static [&'static str],
            v: V,
        ) -> Result<V::Value, Error> {
            v.visit_seq(Seq {
                f: self.f,
                left: fields.len(),
                fields: Some(fields),
                at: 0,
            })
        }
    }

    macro_rules! num {
        ($($m:ident $visit:ident $t:ty),*) => {$(
            fn $m<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
                // Empty values are zero, except a chain id, whose decoder
                // refuses anything below 1.
                let st = self.st.borrow();
                let low = if st.ctx.last().is_some_and(|c| c.ends_with("chain_id")) { 1 } else { 0 };
                v.$visit(if st.populated { 7 as $t } else { low as $t })
            }
        )*};
    }

    impl<'de, 'a> de::Deserializer<'de> for Filler<'a> {
        type Error = Error;

        fn is_human_readable(&self) -> bool {
            false
        }

        fn deserialize_any<V: Visitor<'de>>(self, _v: V) -> Result<V::Value, Error> {
            let mut st = self.st.borrow_mut();
            let p = st.path();
            st.any_at.get_or_insert(p);
            Err(Error(
                "calls deserialize_any, which the bincode gossip codec cannot serve \
                 (untagged / internally tagged / flatten / serde_json::Value)"
                    .into(),
            ))
        }

        num!(deserialize_i8 visit_i8 i8, deserialize_i16 visit_i16 i16,
             deserialize_i32 visit_i32 i32, deserialize_i64 visit_i64 i64,
             deserialize_i128 visit_i128 i128, deserialize_u8 visit_u8 u8,
             deserialize_u16 visit_u16 u16, deserialize_u32 visit_u32 u32,
             deserialize_u64 visit_u64 u64, deserialize_u128 visit_u128 u128,
             deserialize_f32 visit_f32 f32, deserialize_f64 visit_f64 f64);

        fn deserialize_bool<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            v.visit_bool(self.st.borrow().populated)
        }
        fn deserialize_char<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            v.visit_char('x')
        }
        fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            self.deserialize_string(v)
        }
        fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            let s = {
                let mut st = self.st.borrow_mut();
                // Elements of one collection share a choice: a type may
                // parse them all only after reading the last.
                let key = st
                    .ctx
                    .iter()
                    .map(|l| if l.starts_with('[') { "[]" } else { l.as_str() })
                    .collect::<Vec<_>>()
                    .join(" > ");
                let i = st.string_choice.get(&key).copied().unwrap_or(0);
                let s = st.strings[i.min(st.strings.len() - 1)].clone();
                st.last_string = Some(key);
                s
            };
            v.visit_string(s)
        }
        fn deserialize_bytes<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            // A fixed-length byte string such as a UUID (16 bytes) reads here.
            v.visit_byte_buf(vec![7u8; self.count().min(1) * 16])
        }
        fn deserialize_byte_buf<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            v.visit_byte_buf(vec![7u8; self.count() * 16])
        }
        fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            if self.count() > 0 {
                v.visit_some(self.deeper())
            } else {
                v.visit_none()
            }
        }
        fn deserialize_unit<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            v.visit_unit()
        }
        fn deserialize_unit_struct<V: Visitor<'de>>(
            self,
            _n: &'static str,
            v: V,
        ) -> Result<V::Value, Error> {
            v.visit_unit()
        }
        fn deserialize_newtype_struct<V: Visitor<'de>>(
            self,
            n: &'static str,
            v: V,
        ) -> Result<V::Value, Error> {
            let f = self.deeper();
            f.scoped(n.into(), || v.visit_newtype_struct(f))
        }
        fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            let left = self.count();
            v.visit_seq(Seq {
                f: self,
                left,
                fields: None,
                at: 0,
            })
        }
        fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, Error> {
            v.visit_seq(Seq {
                f: self,
                left: len,
                fields: None,
                at: 0,
            })
        }
        fn deserialize_tuple_struct<V: Visitor<'de>>(
            self,
            n: &'static str,
            len: usize,
            v: V,
        ) -> Result<V::Value, Error> {
            self.scoped(n.into(), || {
                v.visit_seq(Seq {
                    f: self,
                    left: len,
                    fields: None,
                    at: 0,
                })
            })
        }
        fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            let left = self.count().min(1);
            v.visit_map(Map { f: self, left })
        }
        fn deserialize_struct<V: Visitor<'de>>(
            self,
            n: &'static str,
            fields: &'static [&'static str],
            v: V,
        ) -> Result<V::Value, Error> {
            self.scoped(n.into(), || {
                v.visit_seq(Seq {
                    f: self,
                    left: fields.len(),
                    fields: Some(fields),
                    at: 0,
                })
            })
        }
        fn deserialize_enum<V: Visitor<'de>>(
            self,
            name: &'static str,
            variants: &'static [&'static str],
            v: V,
        ) -> Result<V::Value, Error> {
            // Two enums may share a type name (a gossip status and a
            // transaction status): coverage is keyed by name and variant list.
            let key = self.st.borrow_mut().enum_key(name, variants);
            let idx = self.st.borrow_mut().choose(key, variants.len());
            self.st.borrow_mut().stack.push((key, idx));
            let out = self.scoped(format!("{name}::{}", variants[idx]), || {
                v.visit_enum(Enum { f: self, idx })
            });
            self.st.borrow_mut().stack.pop();
            out
        }
        fn deserialize_identifier<V: Visitor<'de>>(self, _v: V) -> Result<V::Value, Error> {
            Err(Error("identifier requested outside an enum".into()))
        }
        fn deserialize_ignored_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            v.visit_unit()
        }
    }

    /// Values of `T` that between them produce every variant of every enum
    /// reachable from `T`, plus every position that could not be built.
    pub fn every_variant<T: de::DeserializeOwned>(populated: bool) -> (Vec<T>, Vec<String>) {
        let strings = candidates(populated);
        let st = RefCell::new(State {
            populated,
            strings,
            ..Default::default()
        });
        let mut out = Vec::new();
        let mut errors = Vec::new();
        let mut attempts = 0;
        loop {
            attempts += 1;
            assert!(attempts < 50_000, "value generation did not converge");
            let before = st.borrow().cov.clone();
            {
                let mut s = st.borrow_mut();
                s.cov.progressed = false;
                s.stack.clear();
                s.ctx.clear();
                s.last_string = None;
                s.any_at = None;
            }
            match T::deserialize(Filler { st: &st, depth: 0 }) {
                Ok(v) => out.push(v),
                Err(e) => {
                    let mut s = st.borrow_mut();
                    if let Some(at) = s.any_at.clone() {
                        errors.push(format!("{at}: {e}"));
                    } else if let Some(key) = s.last_string.clone() {
                        let n = s.strings.len();
                        let i = s.string_choice.entry(key.clone()).or_insert(0);
                        if *i + 1 < n {
                            *i += 1;
                            s.cov = before;
                            continue;
                        }
                        errors.push(format!("{key}: no candidate string accepted: {e}"));
                    } else {
                        errors.push(format!("{}: {e}", s.path()));
                    }
                }
            }
            if !st.borrow().cov.progressed {
                break;
            }
        }
        let st = st.into_inner();
        for (name, cov) in &st.cov.covered {
            for (i, c) in cov.iter().enumerate() {
                if !c {
                    errors.push(format!("{name}#{i}: never produced"));
                }
            }
        }
        (out, errors)
    }
}

/// Every variant of every op enum, populated and empty, survives the gossip
/// transaction topic, a gossip block, the JSON-RPC `tx_type` decode
/// (`serde_json::from_value::<TransactionType>`) and the stored-transaction
/// JSON decode (`serde_json::from_slice::<SignedTransaction>`).
#[test]
fn every_op_variant_survives_gossip_block_and_json_rpc() {
    use tenzro_types::transaction::{SignedTransaction, TransactionType};
    let mut failures = Vec::new();
    for populated in [true, false] {
        let mode = if populated { "populated" } else { "empty" };
        let (values, errors) = fill::every_variant::<TransactionType>(populated);
        failures.extend(errors.into_iter().map(|e| format!("[{mode}] build {e}")));

        let mut seen: Vec<usize> = values.iter().map(variant_index).collect();
        seen.sort_unstable();
        seen.dedup();
        if seen != (0..TRANSACTION_VARIANT_COUNT).collect::<Vec<_>>() {
            failures.push(format!(
                "[{mode}] TransactionType variants produced: {seen:?}"
            ));
        }

        let mut ok = Vec::new();
        for t in values {
            let what = format!("[{mode}] {:?}", t);
            let what = &what[..what.len().min(240)];
            let signed = signed_default_transaction(t.clone());

            match NetworkMessage::new(MessagePayload::Transaction(signed.clone()))
                .to_bytes()
                .map_err(|e| e.to_string())
                .and_then(|b| NetworkMessage::from_bytes(&b).map_err(|e| e.to_string()))
            {
                Ok(m) => match m.payload {
                    MessagePayload::Transaction(back) if back.transaction.tx_type == t => {}
                    _ => failures.push(format!("{what}: gossip decoded to a different value")),
                },
                Err(e) => failures.push(format!("{what}: gossip codec: {e}")),
            }

            match serde_json::to_value(&t).and_then(serde_json::from_value::<TransactionType>) {
                Ok(back) if back == t => {}
                Ok(_) => failures.push(format!(
                    "{what}: JSON-RPC tx_type decoded to a different value"
                )),
                Err(e) => failures.push(format!("{what}: JSON-RPC tx_type: {e}")),
            }

            match serde_json::to_vec(&signed)
                .and_then(|b| serde_json::from_slice::<SignedTransaction>(&b))
            {
                Ok(back) if back.transaction.tx_type == t => {}
                Ok(_) => failures.push(format!("{what}: stored JSON decoded to a different value")),
                Err(e) => failures.push(format!("{what}: stored JSON: {e}")),
            }
            ok.push(signed);
        }

        use tenzro_types::block::{Block, BlockHeader};
        use tenzro_types::primitives::{Address, BlockHeight, Hash};
        let header = BlockHeader::new(
            BlockHeight::from(1u64),
            Hash::default(),
            Block::compute_tx_root(&ok),
            Hash::default(),
            Address::new([0u8; 32]),
        );
        let block = Block::new(header, ok);
        if let Err(e) = NetworkMessage::new(MessagePayload::Block(block))
            .to_bytes()
            .map_err(|e| e.to_string())
            .and_then(|b| NetworkMessage::from_bytes(&b).map_err(|e| e.to_string()))
        {
            failures.push(format!("[{mode}] block of every op variant: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} wire failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every variant of every gossip message, and of every enum reachable from
/// it, populated and empty, decodes from the bytes gossip sends and encodes
/// back to the same bytes.
#[test]
fn every_gossip_message_variant_survives_the_wire() {
    let mut failures = Vec::new();
    for populated in [true, false] {
        let mode = if populated { "populated" } else { "empty" };
        let (values, errors) = fill::every_variant::<MessagePayload>(populated);
        failures.extend(errors.into_iter().map(|e| format!("[{mode}] build {e}")));
        let mut kinds: Vec<std::mem::Discriminant<MessagePayload>> = Vec::new();
        for payload in values {
            let d = std::mem::discriminant(&payload);
            if !kinds.contains(&d) {
                kinds.push(d);
            }
            // The filler cannot build a signed batch; the batched form has
            // its own round-trip tests (mod batched).
            if matches!(payload, MessagePayload::BatchedAnnouncement(_)) {
                continue;
            }
            let what = format!("[{mode}] {:?}", payload);
            let what = &what[..what.len().min(240)];
            let msg = NetworkMessage::new(payload);
            let bytes = match msg.to_bytes() {
                Ok(b) => b,
                Err(e) => {
                    failures.push(format!("{what}: encode: {e}"));
                    continue;
                }
            };
            match NetworkMessage::from_bytes(&bytes).and_then(|m| m.to_bytes()) {
                Ok(again) if again == bytes => {}
                Ok(_) => failures.push(format!("{what}: decoded to a different value")),
                Err(e) => failures.push(format!("{what}: decode: {e}")),
            }
        }
        if kinds.len() != MESSAGE_PAYLOAD_VARIANT_COUNT {
            failures.push(format!(
                "[{mode}] {} of {MESSAGE_PAYLOAD_VARIANT_COUNT} gossip message kinds produced",
                kinds.len()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} wire failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The number of `MessagePayload` variants; the exhaustive match below fails
/// to compile when one is added, so this count is updated with it.
const MESSAGE_PAYLOAD_VARIANT_COUNT: usize = {
    #[allow(dead_code)]
    fn exhaustive(p: &MessagePayload) {
        match p {
            MessagePayload::Block(_)
            | MessagePayload::BlockRequest(_)
            | MessagePayload::BlockResponse(_)
            | MessagePayload::Transaction(_)
            | MessagePayload::TransactionRequest(_)
            | MessagePayload::TransactionResponse(_)
            | MessagePayload::ModelRegistration(_)
            | MessagePayload::ProviderAnnouncement(_)
            | MessagePayload::ProviderHeartbeat(_)
            | MessagePayload::BlobAnnouncement(_)
            | MessagePayload::ShardReplication(_)
            | MessagePayload::Certificate(_)
            | MessagePayload::CompactCertificate(_)
            | MessagePayload::ValidatorEndpoint(_)
            | MessagePayload::Status(_)
            | MessagePayload::Ping
            | MessagePayload::Pong
            | MessagePayload::Custom { .. }
            | MessagePayload::BatchedAnnouncement(_) => {}
        }
    }
    19
};

// ---------------------------------------------------------------------------
// Batch-signed announcements
// ---------------------------------------------------------------------------

mod batched {
    use super::*;
    use std::sync::Arc;
    use tenzro_crypto::batch::{
        BatchParams, BatchRecordSigner, BatchService, RecordSignature, RecordSigner,
    };
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_network::{ProviderHeartbeatMessage, SignedAnnouncement};

    /// Signs through the batch service at once (a test has no ticker).
    struct Immediate(Arc<BatchService>);
    impl RecordSigner for Immediate {
        fn identity(&self) -> &tenzro_crypto::composite::CompositePublicKey {
            self.0.identity()
        }
        fn sign_record(&self, m: &[u8]) -> tenzro_crypto::Result<RecordSignature> {
            self.0
                .sign_now(m.to_vec(), tenzro_crypto::session::now_ms())
                .map(RecordSignature::batched)
        }
    }

    fn service(seed: u8) -> Arc<BatchService> {
        Arc::new(
            BatchService::new(
                Arc::new(TestHybridSigner::hybrid(seed)),
                BatchParams {
                    max_batch: 8,
                    flush_interval_ms: 1_000,
                },
                0,
            )
            .unwrap(),
        )
    }

    fn heartbeat() -> ProviderHeartbeatMessage {
        ProviderHeartbeatMessage {
            timestamp: tenzro_crypto::session::now_ms() as i64,
            ..Default::default()
        }
    }

    fn variant_index(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    #[test]
    fn an_unsigned_heartbeat_has_the_golden_bytes_and_variant_index() {
        let hb = ProviderHeartbeatMessage::default();
        let mut msg = NetworkMessage::new(MessagePayload::ProviderHeartbeat(hb));
        msg.message_id = "id".to_string();
        msg.timestamp = 7;
        let bytes = msg.to_bytes().unwrap();
        assert_eq!(variant_index(&bytes), 8, "ProviderHeartbeat keeps its index");
        assert_eq!(hex::encode(&bytes), GOLDEN_HEARTBEAT);
    }

    const GOLDEN_HEARTBEAT: &str = "080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000069640700000000000000";

    #[test]
    fn a_batched_announcement_round_trips_and_verifies() {
        let svc = service(3);
        let signer = Immediate(svc.clone());
        let mut hb = heartbeat();
        hb.sign("did:tenzro:machine:b", &signer).unwrap();
        assert!(hb.signature.is_some());

        let msg = NetworkMessage::new(MessagePayload::ProviderHeartbeat(hb));
        let bytes = msg.to_bytes().unwrap();
        assert_eq!(variant_index(&bytes), 18, "the batched form is the appended variant");

        let back = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(back.topic(), "tenzro/providers");
        let MessagePayload::ProviderHeartbeat(got) = back.payload else {
            panic!("decoding turns the batched form back into the heartbeat");
        };
        assert!(got.signature.is_some());
        got.verify(signer.identity()).expect("verifies");
        // Another identity does not.
        assert!(got.verify(service(4).identity()).is_err());
        // Byte-stable on re-encode.
        let again = NetworkMessage {
            payload: MessagePayload::ProviderHeartbeat(got),
            message_id: back.message_id,
            timestamp: back.timestamp,
        };
        assert_eq!(again.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn a_tampered_batched_announcement_is_refused() {
        let svc = service(5);
        let signer = Immediate(svc);
        let mut hb = heartbeat();
        hb.sign("did:tenzro:machine:t", &signer).unwrap();
        let bytes = NetworkMessage::new(MessagePayload::ProviderHeartbeat(hb))
            .to_bytes()
            .unwrap();
        let back = NetworkMessage::from_bytes(&bytes).unwrap();
        let MessagePayload::ProviderHeartbeat(mut got) = back.payload else {
            panic!()
        };
        got.timestamp += 1;
        assert!(got.verify(signer.identity()).is_err(), "changed field");
        let mut moved = got.clone();
        moved.timestamp -= 1;
        moved.machine_did = "did:tenzro:machine:other".to_string();
        assert!(moved.verify(signer.identity()).is_err(), "changed signer name");
    }

    #[test]
    fn the_node_batch_signer_form_works_over_the_service() {
        // BatchRecordSigner waits for a ticker; with a short wait and no
        // ticker it must fail, not hang or fall back to a software key.
        let svc = service(8);
        let signer = BatchRecordSigner::new(svc, std::time::Duration::from_millis(50));
        let mut hb = heartbeat();
        assert!(hb.sign("did:tenzro:machine:w", &signer).is_err());
    }
}
