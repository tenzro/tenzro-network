//! Confidential compute across providers, end to end: a workload that ran
//! outside Tenzro on Intel TDX, AMD SEV-SNP or an NVIDIA Hopper GPU is
//! attested with the vendor's own sample evidence, each completed unit
//! becomes a receipt committing to the verified attestation, and the payer's
//! vouchers over those receipts settle on chain per unit.
//!
//! Vectors, all vendor-published or from open-source verifiers, verified
//! against the vendors' roots:
//!
//! - TDX: a recorded production quote and its Intel PCS collateral, from the
//!   `dcap-qvl` crate's samples (MIT licence, Phala Network).
//! - SEV-SNP: a Milan guest report and its VCEK from the `virtee/sev`
//!   crate's test data (`tests/certs_data/report_milan.hex`,
//!   `vcek_milan.der`, Apache-2.0, commit a966d06d), checked through the
//!   ASK and ARK this crate pins.
//! - NVIDIA: an H100's signed measurements and device chain from NVIDIA's
//!   open-source local GPU verifier (github.com/NVIDIA/nvtrust, Apache-2.0),
//!   against the device identity root it ships, with NVIDIA's reference
//!   integrity manifests for its VBIOS and driver as the governed GPU
//!   reference values. The service states no licence for those, so they are
//!   fetched at test time by id and pinned by SHA-256, never committed.

use super::*;
use crate::VmType;
use crate::state_adapter::StateAdapter;
use sha2::{Digest, Sha256};
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
use tenzro_tee::confidential_job::{
    AttestedUnitReceipt, JobAttestationPolicy, JobEvidence, verify_job_evidence,
};
use tenzro_types::hardware_level::GpuReferenceValue;
use tenzro_types::key_release::GpuEvidence;
use tenzro_types::payment_authorization::{
    EscrowClaim, EscrowVoucher, escrow_voucher_preimage, receipt_chain_next,
};
use tenzro_types::price_card::WEI_PER_TNZO;
use tenzro_types::primitives::Address;
use tenzro_types::settlement::ReleaseConditions;
use tenzro_types::tee::{AttestationReport, TeeVendor};

const CHAIN: u64 = 1337;
const T0: i64 = 1_800_000_000_000;
const PROVIDER: [u8; 32] = [0x70; 32];
const UNIT_PRICE: u128 = 3 * WEI_PER_TNZO;
const UNITS: u64 = 4;

const TDX_QUOTE: &[u8] = include_bytes!("../../../tenzro-tee/testdata/tdx/tdx_quote");
const TDX_COLLATERAL: &str =
    include_str!("../../../tenzro-tee/testdata/tdx/tdx_quote_collateral.json");
/// Inside every validity window of the TDX collateral.
const TDX_NOW: u64 = 1_750_377_600;

const SNP_REPORT_HEX: &str = include_str!("../../../tenzro-tee/testdata/snp/report_milan.hex");
const SNP_VCEK: &[u8] = include_bytes!("../../../tenzro-tee/testdata/snp/vcek_milan.der");
/// Inside the VCEK's validity (2023-04-03 to 2030-04-03).
const SNP_NOW: u64 = 1_792_886_400;

const GPU_REPORT_HEX: &str =
    include_str!("../../../tenzro-tee/testdata/nvidia/hopper_attestation_report.hex");
const GPU_CHAIN: &str = include_str!("../../../tenzro-tee/testdata/nvidia/hopper_cert_chain.crt");
const GPU_ROOT: &str = include_str!("../../../tenzro-tee/testdata/nvidia/device_identity_ca.crt");
/// The requester nonce NVIDIA's sample answered.
const GPU_NONCE: &str = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
const GPU_NOW: u64 = 1_792_886_400;

/// A job: its evidence, the challenge it answered, and when it was attested.
struct Job {
    id: &'static str,
    vendor: TeeVendor,
    evidence: JobEvidence,
    challenge: Vec<u8>,
    now: u64,
}

fn tdx_job() -> Job {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert(
        tenzro_tee::verify::tdx::COLLATERAL_KEY.to_string(),
        TDX_COLLATERAL.to_string(),
    );
    // The challenge the verifier issued is what the TD put in REPORT_DATA,
    // the 64 bytes at offset 568 of a v4 TDX quote.
    let challenge = TDX_QUOTE[568..632].to_vec();
    Job {
        id: "job-tdx",
        vendor: TeeVendor::IntelTdx,
        evidence: JobEvidence::Cvm(AttestationReport {
            vendor: TeeVendor::IntelTdx,
            attestation_data: TDX_QUOTE.to_vec(),
            metadata,
            ..Default::default()
        }),
        challenge,
        now: TDX_NOW,
    }
}

fn snp_job() -> Job {
    let report = hex::decode(SNP_REPORT_HEX.trim()).unwrap();
    let ask =
        tenzro_tee::certs::pem_to_der(tenzro_tee::certs::get_amd_ask_for_product("Milan").unwrap())
            .unwrap();
    // REPORT_DATA, offset 0x50 of the report.
    let challenge = report[0x50..0x90].to_vec();
    Job {
        id: "job-snp",
        vendor: TeeVendor::AmdSevSnp,
        evidence: JobEvidence::Cvm(AttestationReport {
            vendor: TeeVendor::AmdSevSnp,
            attestation_data: report,
            certificates: vec![SNP_VCEK.to_vec(), ask],
            ..Default::default()
        }),
        challenge,
        now: SNP_NOW,
    }
}

fn gpu_job() -> Job {
    Job {
        id: "job-hopper",
        vendor: TeeVendor::NvidiaGpu,
        evidence: JobEvidence::Gpu(GpuEvidence {
            report: hex::decode(GPU_REPORT_HEX.trim()).unwrap(),
            chain: GPU_CHAIN.as_bytes().to_vec(),
        }),
        challenge: hex::decode(GPU_NONCE).unwrap(),
        now: GPU_NOW,
    }
}

fn tx(from: &[u8], data: Vec<u8>, nonce: u64, at: i64) -> VmTransaction {
    let mut t = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        5_000_000,
        0,
        nonce,
        VmType::Tenzro,
        CHAIN,
    );
    t.block_timestamp_ms = Some(at);
    t
}

async fn run(ex: &NativeExecutor, state: &mut StateAdapter, t: &VmTransaction) -> ExecutionResult {
    let r = ex.execute_transaction(t, state).await.expect("executes");
    assert!(r.success, "{:?}", r.revert_reason);
    r
}

/// Governance sets the GPU device root and, as GPU reference values, the
/// active measurements of NVIDIA's VBIOS and driver RIMs for the sample's
/// builds, fetched from NVIDIA's RIM service and pinned by hash.
fn govern_gpu(state: &mut StateAdapter) {
    use tenzro_tee::nvidia_rim::service;
    let rims = [
        tenzro_tee::nvidia_rim::reference_values(&service::fetch(service::H100_SAMPLE_VBIOS))
            .unwrap(),
        tenzro_tee::nvidia_rim::reference_values(&service::fetch(service::H100_SAMPLE_DRIVER))
            .unwrap(),
    ];
    let references: Vec<GpuReferenceValue> = tenzro_tee::nvidia_rim::combined(&rims)
        .into_iter()
        .map(|(index, values)| GpuReferenceValue {
            index,
            values: values.into_iter().map(hex::encode).collect(),
        })
        .collect();
    let mut changes = Vec::new();
    hardware_level::set_gpu_roots(state, &[GPU_ROOT.to_string()], &mut changes).unwrap();
    hardware_level::set_gpu_references(state, &references, &mut changes).unwrap();
}

/// The payer's side of one job: verify the attestation, turn each completed
/// unit into a receipt, chain them, and sign a cumulative voucher per unit.
/// Returns the voucher for everything verified, or the verification error.
fn pay_for_units(
    state: &StateAdapter,
    payer: &TestHybridSigner,
    escrow: [u8; 32],
    job: &Job,
) -> std::result::Result<(EscrowVoucher, Vec<AttestedUnitReceipt>), String> {
    let (roots, references) =
        super::key_release::gpu_governance(state).map_err(|e| e.to_string())?;
    let verified = verify_job_evidence(
        &job.evidence,
        &JobAttestationPolicy {
            challenge: &job.challenge,
            gpu_roots: &roots,
            gpu_references: &references,
            now: job.now,
        },
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(verified.vendor, job.vendor);
    let mut head = [0u8; 32];
    let mut receipts = Vec::new();
    let mut last = None;
    for unit in 0..UNITS {
        let output: [u8; 32] = Sha256::digest(format!("{}:{unit}", job.id)).into();
        let receipt = AttestedUnitReceipt::new(job.id, unit, &verified, &job.evidence, &output);
        head = receipt_chain_next(&head, &receipt.digest());
        let cumulative = UNIT_PRICE * u128::from(unit + 1);
        last = Some(EscrowVoucher {
            escrow_id: escrow,
            cumulative_amount: cumulative,
            binding: head,
            public_key: payer.public_key().p256.clone(),
            signature: payer
                .sign(
                    SignatureContext::EscrowVoucher,
                    &escrow_voucher_preimage(CHAIN, &escrow, cumulative, &head),
                )
                .unwrap(),
            agent: None,
            attribution: None,
        });
        receipts.push(receipt);
    }
    Ok((last.unwrap(), receipts))
}

async fn open_escrow(
    ex: &NativeExecutor,
    state: &mut StateAdapter,
    payer: &TestHybridSigner,
    nonce: u64,
) -> [u8; 32] {
    #[derive(serde::Serialize)]
    struct Create {
        payee: Address,
        amount: u128,
        asset_id: tenzro_types::asset::AssetId,
        expires_at: u64,
        release_conditions: ReleaseConditions,
    }
    let mut data = SELECTOR_ESCROW_CREATE.to_vec();
    data.extend(
        serde_json::to_vec(&Create {
            payee: Address::new(PROVIDER),
            amount: UNIT_PRICE * u128::from(UNITS),
            asset_id: tenzro_types::asset::AssetId::tnzo(),
            expires_at: (T0 + 3_600_000) as u64,
            release_conditions: ReleaseConditions::ProviderSignature,
        })
        .unwrap(),
    );
    let r = run(ex, state, &tx(payer.address().as_bytes(), data, nonce, T0)).await;
    r.output[..32].try_into().expect("escrow id")
}

/// One vendor's job, attested and settled per unit; a tampered copy of its
/// evidence earns nothing.
async fn attested_job_settles_per_unit(job: Job) {
    let ex = NativeExecutor::new(crate::config::VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    govern_gpu(&mut state);
    let payer = TestHybridSigner::hybrid(0x51);
    super::agent_terms::tests::enroll(&mut state, &payer);
    state.set_balance(payer.address().as_bytes(), 1_000_000 * WEI_PER_TNZO);
    state.set_balance(&PROVIDER, 1_000_000 * WEI_PER_TNZO);

    // The genuine evidence verifies, and every unit is vouchered.
    let escrow = open_escrow(&ex, &mut state, &payer, 0).await;
    let (voucher, receipts) = pay_for_units(&state, &payer, escrow, &job)
        .unwrap_or_else(|e| panic!("{:?} evidence refused: {e}", job.vendor));
    assert_eq!(receipts.len() as u64, UNITS);
    assert!(receipts.iter().all(|r| r.vendor == job.vendor));
    assert_eq!(
        receipts[0].evidence,
        hex::encode(job.evidence.digest()),
        "each receipt commits to the evidence"
    );

    // Tampered evidence: no receipt, no voucher.
    let mut tampered = job;
    match &mut tampered.evidence {
        JobEvidence::Cvm(r) => {
            let n = r.attestation_data.len();
            r.attestation_data[n / 3] ^= 1;
        }
        JobEvidence::Gpu(g) => {
            let n = g.report.len();
            g.report[n - 10] ^= 1;
        }
    }
    let escrow2 = open_escrow(&ex, &mut state, &payer, 1).await;
    assert!(
        pay_for_units(&state, &payer, escrow2, &tampered).is_err(),
        "tampered {:?} evidence is refused",
        tampered.vendor
    );

    // The provider claims exactly the attested units.
    let total = UNIT_PRICE * u128::from(UNITS);
    let mut greedy = EscrowClaim {
        voucher: voucher.clone(),
        amount: total + 1,
    };
    let mut data = SELECTOR_ESCROW_CLAIM.to_vec();
    data.extend(serde_json::to_vec(&serde_json::json!({ "claims": [greedy.clone()] })).unwrap());
    let r = ex
        .execute_transaction(&tx(&PROVIDER, data, 0, T0 + 10), &mut state)
        .await;
    assert!(
        !matches!(r, Ok(ref r) if r.success),
        "no more than the units"
    );
    greedy.amount = total;
    let mut data = SELECTOR_ESCROW_CLAIM.to_vec();
    data.extend(serde_json::to_vec(&serde_json::json!({ "claims": [greedy] })).unwrap());
    let before = state.get_balance(&PROVIDER);
    run(&ex, &mut state, &tx(&PROVIDER, data, 0, T0 + 10)).await;
    let (_, _, e) = read_escrow_record(&state, &escrow).unwrap();
    assert_eq!(e.claimed, total);
    assert!(state.get_balance(&PROVIDER) > before);
    let (_, _, untouched) = read_escrow_record(&state, &escrow2).unwrap();
    assert_eq!(
        untouched.claimed, 0,
        "the tampered job's escrow pays nothing"
    );
}

#[tokio::test]
async fn an_intel_tdx_job_is_verified_and_settled_per_unit() {
    attested_job_settles_per_unit(tdx_job()).await;
}

#[tokio::test]
async fn an_amd_sev_snp_job_is_verified_and_settled_per_unit() {
    attested_job_settles_per_unit(snp_job()).await;
}

#[tokio::test]
async fn an_nvidia_hopper_job_is_verified_and_settled_per_unit() {
    attested_job_settles_per_unit(gpu_job()).await;
}

/// A GPU whose measurements governance does not recognise earns nothing.
#[tokio::test]
async fn a_gpu_off_the_governed_reference_values_is_refused() {
    let ex = NativeExecutor::new(crate::config::VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    govern_gpu(&mut state);
    // The first measurement the sample reports, with one bit changed.
    let report = hex::decode(GPU_REPORT_HEX.trim()).unwrap();
    let (index, mut value) = tenzro_tee::nvidia_device::measurements(&report)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    value[0] ^= 1;
    let mut changes = Vec::new();
    hardware_level::set_gpu_references(
        &mut state,
        &[GpuReferenceValue {
            index,
            values: vec![hex::encode(value)],
        }],
        &mut changes,
    )
    .unwrap();
    let payer = TestHybridSigner::hybrid(0x52);
    super::agent_terms::tests::enroll(&mut state, &payer);
    state.set_balance(payer.address().as_bytes(), 1_000_000 * WEI_PER_TNZO);
    let escrow = open_escrow(&ex, &mut state, &payer, 0).await;
    let err = pay_for_units(&state, &payer, escrow, &gpu_job()).unwrap_err();
    assert!(err.contains("reference values"), "{err}");
}
