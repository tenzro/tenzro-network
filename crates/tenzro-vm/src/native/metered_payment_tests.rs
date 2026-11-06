//! Metered services paid end to end on chain state, with nothing in the
//! chain that knows what is being sold: a provider publishes a price card
//! per service as a generic registry entry (a language model, an embedder,
//! an image generator, a speech model, and a unit of work registered only
//! now, bandwidth); a payer reads each card back from the registry, streams
//! the service, pays each chunk with a cumulative voucher bound to the
//! receipts it received, and the provider claims exactly what the published
//! cards price the metered units at.

use super::*;
use crate::VmType;
use crate::state_adapter::StateAdapter;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
use tenzro_types::meter::unit;
use tenzro_types::meter::{UnitDef, Witness};
use tenzro_types::model::BillableUnits;
use tenzro_types::payment_authorization::{
    EscrowClaim, EscrowVoucher, escrow_voucher_preimage, receipt_chain_next,
};
use tenzro_types::price_card::{
    CARD_KIND, Denom, PriceCard, Rate, RateCard, WEI_PER_TNZO, card_entry_name,
};
use tenzro_types::primitives::Address;
use tenzro_types::registry::owned_id;
use tenzro_types::settlement::ReleaseConditions;
use tenzro_types::transaction::RegistryOp;

const CHAIN: u64 = 1337;
const T0: i64 = 1_800_000_000_000;
const PROVIDER: [u8; 32] = [0x70; 32];
const RICH: u128 = 1_000_000 * WEI_PER_TNZO;

fn tx(from: &[u8], data: Vec<u8>, nonce: u64, at: i64) -> VmTransaction {
    let mut t = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        5_000_000,
        // Free gas, so balances show exactly the value moved.
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

fn lines(entries: &[(&str, u128, u8)]) -> BTreeMap<String, Rate> {
    entries
        .iter()
        .map(|(k, p, e)| (k.to_string(), Rate::per(*p, *e)))
        .collect()
}

/// The four cards: a language model and an embedder priced in USD per
/// million tokens, an image model in TNZO per pixel-step, a speech model in
/// USD per thousand characters plus per second of audio.
fn cards() -> Vec<PriceCard> {
    let card = |model: &str, denom, l: BTreeMap<String, Rate>, min| PriceCard {
        model_id: model.into(),
        model_hash: hex::encode(Sha256::digest(model.as_bytes())),
        rates: RateCard {
            denom,
            lines: l,
            min_charge: min,
        },
    };
    vec![
        card(
            "qwen3-0.6b",
            Denom::NanoUsd,
            lines(&[
                (unit::INPUT_TOKENS, 50_000_000, 6),
                (unit::OUTPUT_TOKENS, 200_000_000, 6),
                ("input_tokens@ctx_gt_32k", 100_000_000, 6),
            ]),
            0,
        ),
        card(
            "embeddinggemma-300m",
            Denom::NanoUsd,
            lines(&[(unit::INPUT_TOKENS, 20_000_000, 6)]),
            0,
        ),
        card(
            "flux2-klein-4b",
            Denom::Wei,
            lines(&[(unit::PIXEL_STEPS, 2_000_000, 0)]),
            0,
        ),
        card(
            "kokoro-82m",
            Denom::NanoUsd,
            lines(&[
                (unit::CHARACTERS, 15_000_000, 3),
                (unit::AUDIO_OUT_MS, 1_000_000, 3),
            ]),
            1_000,
        ),
        // A relay sells bandwidth, a unit registered just below.
        card(
            "relay-eu-1",
            Denom::NanoUsd,
            lines(&[("bandwidth_bytes", 10_000_000, 9)]),
            0,
        ),
    ]
}

/// What each model streams: one meter per chunk.
fn streams() -> Vec<Vec<BillableUnits>> {
    let mut long = BillableUnits::new();
    long.set("input_tokens@ctx_gt_32k", 40_000).unwrap();
    vec![
        // A chat: the prompt, then output in chunks of 16 tokens; a second
        // call with a long prompt.
        std::iter::once(BillableUnits::tokens(812, 0))
            .chain((0..20).map(|_| BillableUnits::tokens(0, 16)))
            .chain(std::iter::once(long))
            .collect(),
        // Three embedding batches.
        vec![
            BillableUnits::tokens(4_096, 0),
            BillableUnits::tokens(1_024, 0),
            BillableUnits::tokens(77, 0),
        ],
        // Two images: 1024x1024 at 28 steps, 768x768 at 4 steps.
        vec![
            BillableUnits::new().with_pixel_steps(1024 * 1024 * 28),
            BillableUnits::new().with_pixel_steps(768 * 768 * 4),
        ],
        // Speech in sentences: characters spoken and audio produced, plus a
        // recorded-only latency the card does not price.
        (0..5)
            .map(|i| {
                let mut u = BillableUnits::new()
                    .with_characters(120 + i)
                    .with_audio_out_ms(6_400 + 10 * i as u64);
                u.set(unit::TTFT_MS, 90).unwrap();
                u
            })
            .collect(),
        // Bandwidth relayed in four bursts.
        (0..4)
            .map(|i| {
                let mut u = BillableUnits::new();
                u.set("bandwidth_bytes", 250_000_000 + i).unwrap();
                u
            })
            .collect(),
    ]
}

fn put(id: &str, kind: &str, data: Vec<u8>) -> Vec<u8> {
    let mut d = SELECTOR_REGISTRY.to_vec();
    d.extend(
        serde_json::to_vec(&RegistryOp::Put {
            id: id.into(),
            kind: kind.into(),
            anchor: "ee".repeat(32),
            data: hex::encode(data),
        })
        .unwrap(),
    );
    d
}

/// Whether `unit` is billable, as a payer's harness reads it: the units the
/// network's own engines meter, and any unit registered since, from its
/// registry entry.
fn billable(state: &dyn VmState, unit: &str) -> Option<bool> {
    tenzro_types::meter::genesis_units()
        .into_iter()
        .find(|u| u.id == unit)
        .map(|u| u.billable)
        .or_else(|| {
            registry::read_entry(state, unit)
                .filter(|e| e.kind == "unit")
                .and_then(|e| serde_json::from_slice::<UnitDef>(&e.data_bytes()?).ok())
                .map(|d| d.billable)
        })
}

/// The payer's voucher covering `cumulative`, bound to `binding`.
fn voucher(
    payer: &TestHybridSigner,
    escrow: [u8; 32],
    cumulative: u128,
    binding: [u8; 32],
) -> EscrowVoucher {
    EscrowVoucher {
        escrow_id: escrow,
        cumulative_amount: cumulative,
        binding,
        public_key: payer.public_key().p256.clone(),
        signature: payer
            .sign(
                SignatureContext::EscrowVoucher,
                &escrow_voucher_preimage(CHAIN, &escrow, cumulative, &binding),
            )
            .unwrap(),
        agent: None,
        attribution: None,
    }
}

#[tokio::test]
async fn services_and_a_new_unit_stream_and_settle_at_their_published_cards() {
    let ex = NativeExecutor::new(crate::config::VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let payer = TestHybridSigner::hybrid(0x51);
    super::agent_terms::tests::enroll(&mut state, &payer);
    let payer_addr = payer.address();
    state.set_balance(payer_addr.as_bytes(), RICH);
    state.set_balance(&PROVIDER, RICH);
    let rate = super::economy::read_fee_rate(&state).rate_nano_usd;

    // A developer registers a brand-new unit, bandwidth, whose metering
    // lives in its own harness module (the anchor). No code knows it.
    let def = UnitDef {
        id: "bandwidth_bytes".into(),
        scale: "bytes".into(),
        witness: Witness::Device,
        billable: true,
        max_per_call: 0,
        doc_hash: "11".repeat(32),
    };
    let developer = [0x72u8; 32];
    state.set_balance(&developer, RICH);
    run(
        &ex,
        &mut state,
        &tx(
            &developer,
            put("bandwidth_bytes", "unit", serde_json::to_vec(&def).unwrap()),
            0,
            T0,
        ),
    )
    .await;

    // The provider publishes one card per service under its own account.
    let mut provider_nonce = 0;
    for card in cards() {
        let id = owned_id(&Address::new(PROVIDER), &card_entry_name(&card.model_id));
        let data = put(&id, CARD_KIND, serde_json::to_vec(&card).unwrap());
        run(&ex, &mut state, &tx(&PROVIDER, data, provider_nonce, T0)).await;
        provider_nonce += 1;
    }

    let mut claims = Vec::new();
    let mut expected = Vec::new();
    for (i, (card, chunks)) in cards().into_iter().zip(streams()).enumerate() {
        // The payer reads the card back from the registry, as a router would.
        let id = owned_id(&Address::new(PROVIDER), &card_entry_name(&card.model_id));
        let entry = registry::read_entry(&state, &id).unwrap();
        assert_eq!(entry.owner, Address::new(PROVIDER));
        let published: PriceCard = serde_json::from_slice(&entry.data_bytes().unwrap()).unwrap();
        assert_eq!(published, card);
        let lock = 50 * WEI_PER_TNZO;
        #[derive(serde::Serialize)]
        struct Create {
            payee: Address,
            amount: u128,
            asset_id: tenzro_types::asset::AssetId,
            expires_at: u64,
            release_conditions: ReleaseConditions,
        }
        let payload = Create {
            payee: Address::new(PROVIDER),
            amount: lock,
            asset_id: tenzro_types::asset::AssetId::tnzo(),
            expires_at: (T0 + 3_600_000) as u64,
            release_conditions: ReleaseConditions::ProviderSignature,
        };
        let mut data = SELECTOR_ESCROW_CREATE.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        let r = run(
            &ex,
            &mut state,
            &tx(payer_addr.as_bytes(), data, i as u64, T0 + 2),
        )
        .await;
        let escrow: [u8; 32] = r.output[..32].try_into().expect("escrow id");

        // Stream: after each chunk the payer prices the whole meter so far
        // on the card and signs the cumulative charge, bound to the receipt
        // chain it holds. It signs only what it counted itself.
        let mut meter = BillableUnits::new();
        let mut head = [0u8; 32];
        let mut last = None;
        let mut paid = 0u128;
        for (n, chunk) in chunks.iter().enumerate() {
            meter.accumulate(chunk);
            let receipt: [u8; 32] = Sha256::digest(format!("{}:{n}", card.model_id)).into();
            head = receipt_chain_next(&head, &receipt);
            let owed = card
                .rates
                .charge_wei(&meter, |u| billable(&state, u), rate)
                .unwrap();
            assert!(owed >= paid, "a cumulative charge never falls");
            paid = owed;
            last = Some(voucher(&payer, escrow, owed, head));
        }
        expected.push((escrow, paid));
        claims.push(EscrowClaim {
            voucher: last.unwrap(),
            amount: paid,
        });
    }

    // Nothing was charged for the recorded-only latency, and the speech
    // card's minimum did not apply to a call worth more.
    let speech = &expected[3];
    assert!(speech.1 > 1_000);

    // A voucher whose binding was swapped is not the payer's signature.
    let mut forged = claims[0].clone();
    forged.voucher.binding = [9u8; 32];
    let mut data = SELECTOR_ESCROW_CLAIM.to_vec();
    data.extend(serde_json::to_vec(&serde_json::json!({ "claims": [forged] })).unwrap());
    let r = ex
        .execute_transaction(&tx(&PROVIDER, data, provider_nonce, T0 + 10), &mut state)
        .await;
    assert!(
        !matches!(r, Ok(ref r) if r.success),
        "a rebound voucher is refused"
    );

    // A claim above the voucher is refused.
    let mut greedy = claims[1].clone();
    greedy.amount += 1;
    let mut data = SELECTOR_ESCROW_CLAIM.to_vec();
    data.extend(serde_json::to_vec(&serde_json::json!({ "claims": [greedy] })).unwrap());
    let r = ex
        .execute_transaction(&tx(&PROVIDER, data, provider_nonce, T0 + 10), &mut state)
        .await;
    assert!(
        !matches!(r, Ok(ref r) if r.success),
        "a claim above the voucher is refused"
    );

    // The provider claims all four in one transaction, at the metered cost.
    let mut data = SELECTOR_ESCROW_CLAIM.to_vec();
    data.extend(serde_json::to_vec(&serde_json::json!({ "claims": claims })).unwrap());
    run(
        &ex,
        &mut state,
        &tx(&PROVIDER, data, provider_nonce, T0 + 10),
    )
    .await;
    for (escrow, paid) in &expected {
        let (_, _, e) = read_escrow_record(&state, escrow).unwrap();
        assert_eq!(e.claimed, *paid);
    }

    // The amounts are the cards' arithmetic, checked by hand for two of them.
    // Embeddings: 5,197 tokens at $0.02 per million is 103,940 nano-USD.
    let embed_nano = 5_197u128 * 20_000_000 / 1_000_000;
    assert_eq!(expected[1].1, (embed_nano * WEI_PER_TNZO).div_ceil(rate));
    // Bandwidth, a unit no code knows: 1,000,000,006 bytes at one cent per
    // gigabyte is 10,000,001 nano-USD, rounded up.
    let bw_nano = (1_000_000_006u128 * 10_000_000).div_ceil(1_000_000_000);
    assert_eq!(expected[4].1, (bw_nano * WEI_PER_TNZO).div_ceil(rate));
    // Images: 2 wei per pixel-step.
    assert_eq!(
        expected[2].1,
        2_000_000 * (1024 * 1024 * 28 + 768 * 768 * 4)
    );
}
