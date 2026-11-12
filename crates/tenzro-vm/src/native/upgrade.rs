//! Protocol upgrade readiness and the security-fix disclosure.
//!
//! A validator's machine signals it runs the binary a protocol upgrade names
//! with an `UpgradeReady`: a TPM quote, by the attestation key recorded when
//! the validator's machine identity was admitted, over the binary's SHA-256
//! and the validator account. A protocol upgrade enacts only once validators
//! holding `upgrade.readiness_bps` of bonded stake have signalled, and it
//! activates `upgrade.activation_delay_blocks` after the block that enacted
//! it, a height every replica derives from the same block.
//!
//! The chain's protocol version lives in state ([`PROTOCOL_VERSION_KEY`]),
//! seeded by genesis and raised by an enacted upgrade at its activation
//! height, so every replica derives the same version for every height.
//!
//! A security fix is a protocol upgrade on the security-fix track. It rests
//! on an upheld fault, or on a commitment to a vulnerability its proposer
//! reveals after enactment. A commitment not revealed within
//! `governance.security_reveal_window_ms` of enactment costs the proposer
//! `governance.security_reveal_slash_bps` of its stake, through the one
//! protocol slash path, once anyone settles it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::staking::total_bonded;
use super::*;
use crate::governance::{
    ProposalAction, SECURITY_REVEAL_SLASH_BPS_PARAM, SECURITY_REVEAL_WINDOW_PARAM, SecurityBasis,
    UPGRADE_ACTIVATION_DELAY_PARAM, UPGRADE_READINESS_BPS_PARAM, UpgradeActivation,
    upgrade_ready_digest,
};

/// A validator machine's readiness: `selector || code_hash(32) || evidence`,
/// the evidence a JSON TPM quote.
pub const SELECTOR_UPGRADE_READY: [u8; 4] = [0x02, 0x00, 0x00, 0x0a];
/// Settle a security fix's commitment: `selector || proposal_id(32) ||
/// disclosure`. A disclosure reveals; an empty one claims the lapse.
pub const SELECTOR_SECURITY_DISCLOSURE: [u8; 4] = [0x02, 0x00, 0x00, 0x0b];

/// Gas for a readiness signal: a quote verification.
pub const GAS_UPGRADE_READY: u64 = 150_000;
/// Gas for settling a security fix's commitment.
pub const GAS_SECURITY_DISCLOSURE: u64 = 60_000;

/// Topic of the log an upgrade's activation is announced in.
pub const UPGRADE_SCHEDULED_TOPIC: &[u8] = b"UpgradeScheduled";

const ACTIVATION_KEY: &str = "upgrade_activation";

/// Storage key (in the system account) of the chain's protocol version.
pub const PROTOCOL_VERSION_KEY: &str = "network:protocol_version";
/// Topic of the log that announces the protocol version record after an
/// upgrade changed it, so nodes mirror it without reading state.
pub const PROTOCOL_VERSION_TOPIC: &[u8] = b"ProtocolVersionScheduled";

/// The chain's protocol version as consensus state holds it: the version in
/// force, and the one a scheduled upgrade raises it to at its activation
/// height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersionRecord {
    /// The version in force until `next` activates.
    pub version: u32,
    /// The scheduled raise, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<PendingProtocolVersion>,
}

/// A scheduled raise of the protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingProtocolVersion {
    /// The version from `activation_height` on.
    pub version: u32,
    /// First height at the new version.
    pub activation_height: u64,
}

impl ProtocolVersionRecord {
    /// The version at `height`.
    pub fn at(&self, height: u64) -> u32 {
        match self.next {
            Some(n) if height >= n.activation_height => n.version.max(self.version),
            _ => self.version,
        }
    }
}

/// The record genesis writes under [`PROTOCOL_VERSION_KEY`].
pub fn genesis_protocol_version(version: u32) -> Result<Vec<u8>> {
    serde_json::to_vec(&ProtocolVersionRecord {
        version,
        next: None,
    })
    .map_err(|e| VmError::Internal(format!("encode {PROTOCOL_VERSION_KEY}: {e}")))
}

/// The chain's protocol version record, if genesis recorded one.
pub fn read_protocol_version(state: &dyn VmState) -> Option<ProtocolVersionRecord> {
    funding::read_json(state, PROTOCOL_VERSION_KEY)
}

/// The chain's protocol version at `height`, or `None` when genesis recorded
/// none (a chain that predates the record is not range-checked).
pub fn protocol_version_at(state: &dyn VmState, height: u64) -> Option<u32> {
    read_protocol_version(state).map(|r| r.at(height))
}

/// One validator machine's readiness for a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadySignal {
    /// Hex validator account.
    pub validator: String,
    /// The machine identity whose attestation key quoted.
    pub machine_did: String,
    /// Hex PCR digest the quote reported.
    pub pcr_digest: String,
    /// Height of the block that recorded it.
    pub height: u64,
}

/// How far a binary's readiness has got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    /// Bonded stake of the validators that signalled, as it stands now.
    pub ready_stake: u128,
    /// All bonded stake.
    pub total_bonded: u128,
    /// The share required, in basis points.
    pub required_bps: u64,
    /// Every signal recorded.
    pub signals: Vec<ReadySignal>,
}

impl Readiness {
    /// Whether the ready share reaches the required one.
    pub fn met(&self) -> bool {
        self.total_bonded > 0
            && self.ready_stake.saturating_mul(10_000)
                >= self
                    .total_bonded
                    .saturating_mul(u128::from(self.required_bps))
    }

    /// The ready share, in basis points.
    pub fn ready_bps(&self) -> u64 {
        if self.total_bonded == 0 {
            return 0;
        }
        u64::try_from(self.ready_stake.saturating_mul(10_000) / self.total_bonded).unwrap_or(10_000)
    }
}

/// A security fix resting on a vulnerability commitment, and how it settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityCommitment {
    /// The proposal.
    pub proposal_id: String,
    /// Hex account that proposed it, whose stake answers for the reveal.
    pub proposer: String,
    /// Hex SHA-256 of the disclosure.
    pub commitment: String,
    /// Reveal deadline, set when the fix enacts.
    pub reveal_by_ms: Option<i64>,
    /// `revealed` or `slashed` once settled.
    pub settled: Option<String>,
}

fn signals_key(code_hash: &[u8]) -> String {
    format!("upgrade_ready:{}", hex::encode(code_hash))
}

fn commitment_key(proposal_id: &str) -> String {
    format!("security_fix:{proposal_id}")
}

fn refuse(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(msg.into())
}

/// Every readiness signal recorded for the binary `code_hash`.
pub fn ready_signals(state: &dyn VmState, code_hash: &[u8]) -> Vec<ReadySignal> {
    funding::read_json(state, &signals_key(code_hash)).unwrap_or_default()
}

/// The readiness of the binary `code_hash`, weighed by stake bonded now.
pub fn readiness(state: &dyn VmState, code_hash: &[u8]) -> Readiness {
    let signals = ready_signals(state, code_hash);
    let ready_stake = signals
        .iter()
        .filter_map(|s| hex::decode(&s.validator).ok())
        .map(|v| bonded_stake_of(state, &v))
        .fold(0u128, u128::saturating_add);
    Readiness {
        ready_stake,
        total_bonded: total_bonded(state),
        required_bps: network_param(state, UPGRADE_READINESS_BPS_PARAM),
        signals,
    }
}

/// The most recent upgrade activation, if one was scheduled.
pub fn read_upgrade_activation(state: &dyn VmState) -> Option<UpgradeActivation> {
    funding::read_json(state, ACTIVATION_KEY)
}

/// The security fix commitment of `proposal_id`, if it rests on one.
pub fn read_security_commitment(
    state: &dyn VmState,
    proposal_id: &str,
) -> Option<SecurityCommitment> {
    funding::read_json(state, &commitment_key(proposal_id))
}

/// Refuses to enact a protocol upgrade whose binary has not reached its
/// readiness share.
pub(super) fn require_readiness(state: &dyn VmState, action: &ProposalAction) -> Result<()> {
    let ProposalAction::PolicyUpdate {
        update: tenzro_types::token::PolicyUpdate::ProtocolUpgrade { code_hash, .. },
        ..
    } = action
    else {
        return Ok(());
    };
    let r = readiness(state, code_hash);
    if !r.met() {
        return Err(refuse(format!(
            "validators holding {} bps of bonded stake have quoted binary {}; {} bps must before it enacts",
            r.ready_bps(),
            hex::encode(code_hash),
            r.required_bps
        )));
    }
    Ok(())
}

/// Record an enacted upgrade's activation height and announce it.
pub(super) fn schedule(
    state: &mut dyn VmState,
    proposal_id: &str,
    version: &str,
    code_hash: &[u8],
    height: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let delay = network_param(state, UPGRADE_ACTIVATION_DELAY_PARAM);
    let activation = UpgradeActivation {
        proposal_id: proposal_id.to_string(),
        version: version.to_string(),
        code_hash: hex::encode(code_hash),
        readiness_met_height: height,
        activation_height: height.saturating_add(delay),
    };
    let blob = funding::write_json(state, ACTIVATION_KEY, &activation, changes)?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![UPGRADE_SCHEDULED_TOPIC.to_vec()],
        blob,
    ));
    schedule_protocol_version(state, &activation, height, changes, logs)
}

/// Raise the recorded protocol version to the one `activation` names, from
/// its activation height. A chain whose genesis recorded no version, and a
/// version string that names no number, leave things as they are, matching
/// how the block header takes its version. The version never goes back: a
/// raise already due folds in first, and a lower one names nothing new.
fn schedule_protocol_version(
    state: &mut dyn VmState,
    activation: &UpgradeActivation,
    enacted_at: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let (Some(mut record), Some(named)) = (
        read_protocol_version(state),
        activation.named_protocol_version(),
    ) else {
        return Ok(());
    };
    if let Some(due) = record.next
        && enacted_at >= due.activation_height
    {
        record.version = record.version.max(due.version);
        record.next = None;
    }
    let floor = record
        .next
        .map_or(record.version, |n| n.version.max(record.version));
    record.next = Some(PendingProtocolVersion {
        version: named.max(floor),
        activation_height: activation.activation_height,
    });
    let blob = funding::write_json(state, PROTOCOL_VERSION_KEY, &record, changes)?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![PROTOCOL_VERSION_TOPIC.to_vec()],
        blob,
    ));
    Ok(())
}

/// Admission of a security fix: its fault was upheld, and a guardian seat
/// does not originate it. A vulnerability commitment is recorded against the
/// proposer.
pub(super) fn admit_security_fix(
    state: &mut dyn VmState,
    proposer: &[u8],
    basis: &SecurityBasis,
) -> Result<()> {
    if guardian::load_seat(state, proposer).is_some() {
        return Err(refuse(
            "a governance guardian may not originate a security fix",
        ));
    }
    if let SecurityBasis::Fault { fault_id } = basis {
        let upheld = inference_fault::read_fault(state, fault_id).and_then(|f| f.upheld);
        if upheld != Some(true) {
            return Err(refuse(format!(
                "a security fix rests on an upheld fault; {fault_id} is not one"
            )));
        }
    }
    Ok(())
}

/// Record a security fix's vulnerability commitment once it has an id.
pub(super) fn record_commitment(
    state: &mut dyn VmState,
    proposal_id: &str,
    proposer: &[u8],
    basis: &SecurityBasis,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if let SecurityBasis::Vulnerability { commitment } = basis {
        let record = SecurityCommitment {
            proposal_id: proposal_id.to_string(),
            proposer: hex::encode(proposer),
            commitment: commitment.to_ascii_lowercase(),
            reveal_by_ms: None,
            settled: None,
        };
        funding::write_json(state, &commitment_key(proposal_id), &record, changes)?;
    }
    Ok(())
}

/// Start an enacted security fix's reveal window.
pub(super) fn start_reveal_window(
    state: &mut dyn VmState,
    proposal_id: &str,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let Some(mut record) = read_security_commitment(state, proposal_id) else {
        return Ok(());
    };
    let window = network_param(state, SECURITY_REVEAL_WINDOW_PARAM);
    record.reveal_by_ms = Some(now_ms.saturating_add(i64::try_from(window).unwrap_or(i64::MAX)));
    funding::write_json(state, &commitment_key(proposal_id), &record, changes)?;
    Ok(())
}

fn charge(tx: &VmTransaction, state: &mut dyn VmState, gas: u64) -> Result<Vec<StateChange>> {
    let cost = tx.gas_price.saturating_mul(u128::from(gas));
    let available = state.get_balance(&tx.from);
    if available < cost {
        return Err(VmError::InsufficientBalance {
            required: cost,
            available,
        });
    }
    Ok(charge_and_advance(tx, state, cost))
}

/// Handle an `UpgradeReady`.
pub(super) fn execute_upgrade_ready(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    gas_meter: &mut GasMeter,
) -> Result<ExecutionResult> {
    gas_meter.consume(GAS_UPGRADE_READY)?;
    if tx.data.len() <= 36 {
        return Err(refuse(
            "UpgradeReady is selector, code hash (32 bytes) and a TPM quote",
        ));
    }
    let code_hash: [u8; 32] = tx.data[4..36].try_into().expect("length checked");
    let evidence: tenzro_tee::tpm_attest::TpmEvidence = serde_json::from_slice(&tx.data[36..])
        .map_err(|e| refuse(format!("UpgradeReady quote does not decode: {e}")))?;

    if bonded_stake_of(state, &tx.from) == 0 {
        return Err(refuse(format!(
            "{} has no bonded stake; readiness is signalled by a validator",
            hex::encode(&tx.from)
        )));
    }
    let did = identity_of_wallet(state, &tx.from).ok_or_else(|| {
        refuse(format!(
            "validator {} has no registered machine identity",
            hex::encode(&tx.from)
        ))
    })?;
    if is_identity_revoked(state, &did) {
        return Err(refuse(format!("{did} is revoked")));
    }
    let admitted = funding::machine_attestation(state, &did).map_err(|e| {
        refuse(format!(
            "readiness needs the validator's TPM-attested machine: {e}"
        ))
    })?;
    let admitted_key = tenzro_tee::tpm_attest::attestation_key_sec1(&admitted.evidence)
        .map_err(|e| refuse(e.to_string()))?;
    let quoting_key = tenzro_tee::tpm_attest::attestation_key_sec1(&evidence)
        .map_err(|e| refuse(e.to_string()))?;
    if admitted_key != quoting_key {
        return Err(refuse(format!(
            "the quote is not by {did}'s admitted attestation key"
        )));
    }
    let quote = tenzro_tee::tpm_attest::verify_quote(
        &evidence,
        &upgrade_ready_digest(&code_hash, &tx.from),
    )
    .map_err(|e| refuse(format!("UpgradeReady quote refused: {e}")))?;

    let validator = hex::encode(&tx.from);
    let mut signals = ready_signals(state, &code_hash);
    if signals.iter().any(|s| s.validator == validator) {
        return Err(refuse(format!(
            "{validator} has already signalled readiness for this binary"
        )));
    }
    let mut changes = charge(tx, state, GAS_UPGRADE_READY)?;
    signals.push(ReadySignal {
        validator,
        machine_did: did,
        pcr_digest: hex::encode(&quote.pcr_digest),
        height: tx.block_height.unwrap_or_default(),
    });
    funding::write_json(state, &signals_key(&code_hash), &signals, &mut changes)?;

    let mut data = code_hash.to_vec();
    data.extend_from_slice(&tx.from);
    Ok(ExecutionResult::success(
        gas_meter.final_used(),
        Vec::new(),
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"UpgradeReady".to_vec()],
            data,
        )],
        changes,
    ))
}

/// Handle a security-fix disclosure: reveal the committed vulnerability, or,
/// with an empty disclosure past the deadline, slash the proposer.
pub(super) fn execute_security_disclosure(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    gas_meter: &mut GasMeter,
) -> Result<ExecutionResult> {
    gas_meter.consume(GAS_SECURITY_DISCLOSURE)?;
    if tx.data.len() < 36 {
        return Err(refuse(
            "a security disclosure is selector, proposal id (32 bytes) and the disclosure",
        ));
    }
    let proposal_id = hex::encode(&tx.data[4..36]);
    let disclosure = &tx.data[36..];
    if disclosure.len() > crate::governance::MAX_TEXT_LEN * 8 {
        return Err(refuse(
            "a disclosure is at most 4096 bytes; publish the full report and disclose its digest",
        ));
    }
    let mut record = read_security_commitment(state, &proposal_id).ok_or_else(|| {
        refuse(format!(
            "{proposal_id} is not a security fix resting on a commitment"
        ))
    })?;
    if let Some(how) = &record.settled {
        return Err(refuse(format!(
            "{proposal_id}'s commitment is already settled ({how})"
        )));
    }
    let reveal_by = record.reveal_by_ms.ok_or_else(|| {
        refuse(format!(
            "{proposal_id} has not enacted; its vulnerability is revealed after"
        ))
    })?;
    let now_ms = deterministic_now_ms(tx);
    if disclosure.is_empty() && now_ms <= reveal_by {
        return Err(refuse(format!(
            "{proposal_id}'s reveal window is open until {reveal_by}; nothing lapsed yet"
        )));
    }
    if !disclosure.is_empty() && hex::encode(Sha256::digest(disclosure)) != record.commitment {
        return Err(refuse("the disclosure does not hash to the commitment"));
    }

    let mut changes = charge(tx, state, GAS_SECURITY_DISCLOSURE)?;
    let (topic, data) = if disclosure.is_empty() {
        let proposer =
            hex::decode(&record.proposer).map_err(|e| VmError::Internal(e.to_string()))?;
        let bps = network_param(state, SECURITY_REVEAL_SLASH_BPS_PARAM);
        let taken = staking::slash_to_insurance(
            state,
            &proposer,
            staking::SlashedStake::Validator,
            bps.min(10_000) as u16,
            &mut changes,
        )?;
        record.settled = Some("slashed".into());
        let mut data = tx.data[4..36].to_vec();
        data.extend_from_slice(&proposer);
        data.extend_from_slice(&taken.to_le_bytes());
        (b"SecurityFixLapsed".to_vec(), data)
    } else {
        record.settled = Some("revealed".into());
        let mut data = tx.data[4..36].to_vec();
        data.extend_from_slice(disclosure);
        (b"SecurityFixRevealed".to_vec(), data)
    };
    funding::write_json(state, &commitment_key(&proposal_id), &record, &mut changes)?;
    Ok(ExecutionResult::success(
        gas_meter.final_used(),
        Vec::new(),
        vec![Log::new(SYSTEM_ADDRESS.to_vec(), vec![topic], data)],
        changes,
    ))
}
