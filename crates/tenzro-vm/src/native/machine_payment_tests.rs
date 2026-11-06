//! Payment records, multi-asset settlement, agent payments and agent
//! vouchers, at the level of the settlement functions.

use super::super::{derive_bond_vault_address, derive_escrow_id, governed_param_key};
use super::*;
use crate::state_adapter::StateAdapter;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
use tenzro_types::agent_terms::{
    AgentAction, AgentEscrow, AgentPayment, AgentTerms, AssetLimit, OP_PAY, ServingNode,
    TermsScope, agent_wallet,
};
use tenzro_types::payment_authorization::{
    AgentVoucherSigner, AppMargin, DeliveryReceipt, EscrowClaim, Quote, QuotedAsset, TNZO_ASSET,
};
use tenzro_types::settlement::ReleaseConditions;

/// A claim of the voucher's whole amount, as a payee that metered it all would make.
fn check_whole(
    chain_id: u64,
    now_ms: i64,
    voucher: &EscrowVoucher,
    state: &dyn VmState,
) -> Result<CheckedClaim> {
    check_voucher(chain_id, now_ms, voucher, voucher.cumulative_amount, state)
}

const CHAIN: u64 = 1337;
const AGENT: &str = "did:tenzro:agent:buyer";
const MACHINE: &str = "did:tenzro:machine:serving";
const OTHER_MACHINE: &str = "did:tenzro:machine:other";
/// One USD at the genesis rate (0.1 USD per TNZO) is 10 TNZO.
const ONE_USD_WEI: u128 = 10_000_000_000_000_000_000;

struct Payer {
    key: TestHybridSigner,
}

impl Payer {
    /// A payer holding a P-256 key and no ML-DSA-65 key, such as a thief of
    /// the P-256 key alone.
    fn p256_only(seed: u8) -> Self {
        Self {
            key: TestHybridSigner::p256_only(seed),
        }
    }
    /// A payer whose ML-DSA-65 key is enrolled in `state`.
    fn enrolled(seed: u8, state: &mut StateAdapter) -> Self {
        let key = TestHybridSigner::hybrid(seed);
        let pk = key.public_key().clone();
        crate::account_keys::set_enrolled_pq_key(state, &pk.p256, pk.pq.unwrap(), &mut Vec::new());
        Self { key }
    }
    fn address(&self) -> Address {
        self.key.address()
    }
    fn authorize_resold(
        &self,
        payment_id: &str,
        payee: &Address,
        max: u128,
        asset: &str,
        binding: PaymentBinding,
        resellers: Vec<tenzro_types::payment_authorization::ResellerLeg>,
    ) -> PaymentAuthorization {
        let preimage =
            tenzro_types::payment_authorization::payment_authorization_preimage_with_resellers(
                CHAIN,
                payment_id,
                &self.address(),
                payee,
                max,
                asset,
                &binding,
                &resellers,
            );
        PaymentAuthorization {
            public_key: self.key.public_key().p256.clone(),
            signature: self
                .key
                .sign(SignatureContext::PaymentAuthorization, &preimage)
                .unwrap(),
            max_amount: max,
            asset: asset.into(),
            binding,
            resellers,
        }
    }
    fn authorize(
        &self,
        payment_id: &str,
        payee: &Address,
        max: u128,
        asset: &str,
        binding: PaymentBinding,
    ) -> PaymentAuthorization {
        let preimage = tenzro_types::payment_authorization::payment_authorization_preimage(
            CHAIN,
            payment_id,
            &self.address(),
            payee,
            max,
            asset,
            &binding,
        );
        PaymentAuthorization {
            resellers: Vec::new(),
            public_key: self.key.public_key().p256.clone(),
            signature: self
                .key
                .sign(SignatureContext::PaymentAuthorization, &preimage)
                .unwrap(),
            max_amount: max,
            asset: asset.into(),
            binding,
        }
    }
}

fn binding(usd_e6: u64) -> PaymentBinding {
    PaymentBinding {
        request_digest: [0x11; 32],
        quote_digest: [0x22; 32],
        usd_e6,
        app_margin: None,
    }
}

/// A token the payer issued, holding `supply`, as a `0x` asset string,
/// permitted as a USD settlement asset and priced at par.
fn token(state: &mut StateAdapter, issuer: &[u8], supply: u128) -> ([u8; 32], String) {
    let (id, asset) = unlisted_token(state, issuer, supply);
    permit(state, &asset, "USDX", "USD");
    crate::native::economy::write_symbol_rate_for_tests(state, "USDX", 0, 1_000_000_000);
    (id, asset)
}

/// Installs the registry entry for `asset` with the genesis limits.
fn permit(state: &mut StateAdapter, asset: &str, symbol: &str, currency: &str) {
    crate::native::settlement_asset::install_for_test(
        state,
        &tenzro_types::settlement_asset::SettlementAsset::new(asset, symbol, currency, 6),
    );
}

/// A token the payer issued, holding `supply`, with no registry entry.
fn unlisted_token(state: &mut StateAdapter, issuer: &[u8], supply: u128) -> ([u8; 32], String) {
    let spec = crate::token_ledger::TokenRecord {
        name: "Dollar".into(),
        symbol: "USDX".into(),
        decimals: 6,
        total_supply: supply,
        creator: Vec::new(),
        max_supply: None,
        powers: tenzro_types::token_policy::PowerManifest::NONE,
        policy: tenzro_types::token_policy::TokenPolicy::default(),
        council: None,
        reserve_backing: None,
        pending: None,
    };
    let id = crate::token_ledger::create(state, issuer, &spec, &mut Vec::new()).unwrap();
    (id, format!("0x{}", hex::encode(id)))
}

/// Sets the settlement fee to nothing, for tests of what a payment moves
/// rather than what it costs.
fn no_settlement_fee(state: &mut StateAdapter) {
    for key in [
        crate::native::economy::SETTLEMENT_FEE_PARAM,
        crate::native::economy::MIN_SETTLEMENT_FEE_PARAM,
    ] {
        crate::native::set_governed_param_for_test(state, key, 0);
    }
}

fn native<'a>(
    payer: &Address,
    payee: &Address,
    asset: &'a str,
    amount: u128,
    b: PaymentBinding,
    id: &'a str,
) -> NativePayment<'a> {
    NativePayment {
        payer: Box::leak(Box::new(*payer)),
        payee: Box::leak(Box::new(*payee)),
        asset,
        amount,
        binding: b,
        nonce: id,
        agent_did: None,
        relayer: None,
        resellers: &[],
    }
}

#[test]
fn a_payment_in_a_token_pays_its_fee_in_the_token_and_never_touches_the_payees_tnzo() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(1, &mut state);
    let payee = Address::new([0x99; 32]);
    let (id, asset) = token(&mut state, payer.address().as_bytes(), 1_000_000);

    let b = binding(2_000_000);
    let auth = payer.authorize("pay-1", &payee, 500_000, &asset, b);
    verify_payment_authorization(
        &state,
        CHAIN,
        "pay-1",
        &payer.address(),
        &payee,
        400_000,
        &auth,
        0,
    )
    .unwrap();
    let mut changes = Vec::new();
    let out = settle_native(
        &mut state,
        CHAIN,
        7,
        &native(&payer.address(), &payee, &asset, 400_000, b, "pay-1"),
        &mut changes,
    )
    .unwrap();

    // The signed price (2 USD) is above what 0.4 USDX is worth, so the fee
    // is charged on the signed price, in the token, out of the amount.
    let fee = tenzro_types::split::fee_allocation(
        2_000_000,
        &FeeParams {
            min_fee: 1,
            ..crate::native::economy::fee_params(&state)
        },
    );
    assert!(fee.fee > 0);
    assert_eq!(out.record.fee, fee.fee);
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payee.as_bytes()),
        400_000 - fee.fee
    );
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payer.address().as_bytes()),
        600_000
    );
    assert_eq!(
        crate::token_ledger::balance(
            &state,
            &id,
            super::super::derive_treasury_address().as_bytes()
        ),
        fee.treasury + fee.burn
    );
    assert_eq!(
        crate::token_ledger::balance(
            &state,
            &id,
            crate::native::insurance::pool_address().as_bytes()
        ),
        fee.insurance
    );
    assert_eq!(
        state.get_balance(payee.as_bytes()),
        0,
        "the payee holds no TNZO"
    );
    let r = &out.record.settled;
    assert_eq!(r.fee_asset, asset);
    assert_eq!(r.payout_asset, asset);
    assert_eq!(r.value_units, 2_000_000);
    assert_eq!(r.unit.basket, "USD");
    // At par and 0.10 USD per TNZO, one micro-unit is 1e13 base units.
    assert_eq!(r.fee_tnzo_eq, fee.fee * 10_000_000_000_000);
    assert_eq!(r.burn_eq, fee.burn * 10_000_000_000_000);

    let reference = pay_ref(CHAIN, &payee, &b, "pay-1");
    let record = read_payment(&state, &reference).expect("the record is in state");
    assert_eq!(record.class, RecordClass::Native);
    assert_eq!(record.asset, asset);
    assert_eq!(record.binding, b);
    assert_eq!(read_payment_by_id(&state, "pay-1").unwrap(), record);
}

#[test]
fn a_payees_standing_rule_divides_every_payment_it_receives_in_the_same_execution() {
    use tenzro_types::split::{
        SPLIT_RULE_VERSION, SplitBasis, SplitLine, SplitRecipient, SplitRole, SplitRule,
    };
    let mut state = StateAdapter::new();
    no_settlement_fee(&mut state);
    let payer = Payer::enrolled(1, &mut state);
    let payee = Address::new([0x99; 32]);
    let (a, b_) = (Address::new([0xa1; 32]), Address::new([0xb2; 32]));
    let (id, asset) = token(&mut state, payer.address().as_bytes(), 1_000_000);
    state.set_balance(payee.as_bytes(), ONE_USD_WEI);
    let line = |recipient: SplitRecipient, basis: SplitBasis| SplitLine {
        role: SplitRole::Licensor,
        recipient,
        basis,
        cap: None,
    };
    let rule = |lines: Vec<SplitLine>| PaymentOp::SetSplit {
        rule: Some(SplitRule {
            version: SPLIT_RULE_VERSION,
            lines,
        }),
    };
    let rest = || line(SplitRecipient::Address(payee), SplitBasis::Remainder);

    let bad = [
        // No remainder line.
        rule(vec![line(SplitRecipient::Address(a), SplitBasis::Bps(100))]),
        // Basis points above the whole.
        rule(vec![
            line(SplitRecipient::Address(a), SplitBasis::Bps(6_000)),
            line(SplitRecipient::Address(b_), SplitBasis::Bps(5_000)),
            rest(),
        ]),
        // A standing rule has no leg submitter, and every DID must resolve.
        rule(vec![
            line(SplitRecipient::LegSubmitter, SplitBasis::Bps(100)),
            rest(),
        ]),
        rule(vec![
            line(
                SplitRecipient::DidDerived("did:tenzro:human:nobody".into()),
                SplitBasis::Bps(100),
            ),
            rest(),
        ]),
    ];
    for op in bad {
        assert!(
            apply_payment_op(&mut state, CHAIN, 7, payee.as_bytes(), &op, &mut Vec::new()).is_err()
        );
    }
    let set = rule(vec![
        line(SplitRecipient::Address(a), SplitBasis::Bps(2_500)),
        line(SplitRecipient::Address(b_), SplitBasis::Bps(333)),
        rest(),
    ]);
    apply_payment_op(
        &mut state,
        CHAIN,
        7,
        payee.as_bytes(),
        &set,
        &mut Vec::new(),
    )
    .unwrap();

    let b = binding(2_000_000);
    settle_native(
        &mut state,
        CHAIN,
        8,
        &native(&payer.address(), &payee, &asset, 400_001, b, "pay-1"),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        crate::token_ledger::balance(&state, &id, a.as_bytes()),
        100_000
    );
    assert_eq!(
        crate::token_ledger::balance(&state, &id, b_.as_bytes()),
        13_320
    );
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payee.as_bytes()),
        400_001 - 100_000 - 13_320
    );

    apply_payment_op(
        &mut state,
        CHAIN,
        9,
        payee.as_bytes(),
        &PaymentOp::SetSplit { rule: None },
        &mut Vec::new(),
    )
    .unwrap();
    assert!(read_split(&state, payee.as_bytes()).is_none());
}

#[test]
fn the_payee_refunds_part_of_a_payment_and_never_more_than_it_paid() {
    let mut state = StateAdapter::new();
    no_settlement_fee(&mut state);
    let payer = Payer::enrolled(1, &mut state);
    let payee = Address::new([0x99; 32]);
    let (id, asset) = token(&mut state, payer.address().as_bytes(), 1_000_000);
    state.set_balance(payee.as_bytes(), ONE_USD_WEI);
    let b = binding(2_000_000);
    settle_native(
        &mut state,
        CHAIN,
        7,
        &native(&payer.address(), &payee, &asset, 400_000, b, "pay-1"),
        &mut Vec::new(),
    )
    .unwrap();
    let reference = pay_ref(CHAIN, &payee, &b, "pay-1");
    let refund = |amount| PaymentOp::Refund {
        pay_ref: reference,
        amount,
    };

    let outsider = Address::new([0x55; 32]);
    assert!(
        apply_payment_op(
            &mut state,
            CHAIN,
            8,
            outsider.as_bytes(),
            &refund(1),
            &mut Vec::new()
        )
        .is_err()
    );

    apply_payment_op(
        &mut state,
        CHAIN,
        8,
        payee.as_bytes(),
        &refund(150_000),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payee.as_bytes()),
        250_000
    );
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payer.address().as_bytes()),
        750_000
    );
    assert_eq!(read_payment(&state, &reference).unwrap().refunded, 150_000);

    let over = apply_payment_op(
        &mut state,
        CHAIN,
        9,
        payee.as_bytes(),
        &refund(250_001),
        &mut Vec::new(),
    );
    assert!(over.is_err(), "refunds stop at what the payment paid");
    apply_payment_op(
        &mut state,
        CHAIN,
        9,
        payee.as_bytes(),
        &refund(250_000),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(read_payment(&state, &reference).unwrap().refunded, 400_000);
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payer.address().as_bytes()),
        1_000_000
    );
}

#[test]
fn a_fee_in_kind_counts_as_treasury_revenue_and_insurance_credit_at_its_tnzo_equivalent() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x98; 32]);
    let (_, asset) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    let p = native(
        &payer.address(),
        &payee,
        &asset,
        10_000_000,
        binding(0),
        "rev",
    );
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    let fee = tenzro_types::split::fee_allocation(
        10_000_000,
        &FeeParams {
            min_fee: 1,
            ..crate::native::economy::fee_params(&state)
        },
    );
    assert!(fee.treasury > 0 && fee.insurance > 0);
    // At par and 0.10 USD per TNZO one smallest unit is 1e13 base units.
    let epoch = crate::native::params_epoch(&state);
    assert_eq!(
        crate::native::treasury_reserve::read_flows(&state, epoch).revenue,
        fee.treasury * 10_000_000_000_000
    );
    assert_eq!(
        crate::native::insurance::read_totals(&state).from_fees,
        fee.insurance * 10_000_000_000_000
    );
}

#[test]
fn a_token_payment_is_valued_by_its_rate_whatever_price_it_signed() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x98; 32]);
    let (_, asset) = token(&mut state, payer.address().as_bytes(), 10_000_000);
    // An unsigned price is no longer needed: the rate values the payment.
    let p = native(
        &payer.address(),
        &payee,
        &asset,
        1_000_000,
        binding(0),
        "unpriced",
    );
    let unpriced = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    assert_eq!(unpriced.record.settled.value_units, 1_000_000);
    // An understated price cannot lower the fee.
    let p = native(
        &payer.address(),
        &payee,
        &asset,
        1_000_000,
        binding(1),
        "low",
    );
    let low = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    assert_eq!(low.record.fee, unpriced.record.fee);
    assert_eq!(low.record.settled.value_units, 1_000_000);
    // An overstated one raises it, never past the amount.
    let p = native(
        &payer.address(),
        &payee,
        &asset,
        1_000_000,
        binding(3_000_000),
        "high",
    );
    let high = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    assert!(high.record.fee > low.record.fee);
    assert_eq!(high.record.settled.value_units, 3_000_000);
    // A fee the amount cannot carry is refused.
    let p = native(
        &payer.address(),
        &payee,
        &asset,
        10,
        binding(u64::MAX),
        "absurd",
    );
    let err = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new())
        .map(|_| ())
        .unwrap_err();
    assert!(err.to_string().contains("exceed"), "{err}");
}

#[test]
fn a_token_settles_no_more_per_epoch_than_its_inflow_cap() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x98; 32]);
    let (id, asset) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    let mut entry = tenzro_types::settlement_asset::SettlementAsset::new(&asset, "USDX", "USD", 6);
    entry.epoch_inflow_cap_units = 5;
    crate::native::settlement_asset::install_for_test(&mut state, &entry);
    let pay = |state: &mut StateAdapter, amount: u128, n: &str| {
        let p = native(&payer.address(), &payee, &asset, amount, binding(0), n);
        settle_native(state, CHAIN, 7, &p, &mut Vec::new()).map(|_| ())
    };
    pay(&mut state, 3_000_000, "c-1").unwrap();
    pay(&mut state, 2_000_000, "c-2").unwrap();
    let err = pay(&mut state, 1, "c-3").unwrap_err().to_string();
    assert!(err.contains("inflow cap"), "{err}");
    assert_eq!(
        crate::native::settlement_asset::read_epoch_inflow(&state, &id),
        5_000_000
    );
}

#[test]
fn a_payment_settles_whatever_share_of_the_treasury_its_asset_holds() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x98; 32]);
    let (id, asset) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    let mut entry = tenzro_types::settlement_asset::SettlementAsset::new(&asset, "USDX", "USD", 6);
    entry.max_treasury_share_bps = tenzro_types::settlement_asset::MIN_TREASURY_SHARE_BPS;
    crate::native::settlement_asset::install_for_test(&mut state, &entry);
    // The treasury's stable holdings are this asset alone, far over its share.
    for n in ["s-1", "s-2"] {
        let p = native(&payer.address(), &payee, &asset, 10_000_000, binding(0), n);
        settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    }
    assert!(
        crate::token_ledger::balance(
            &state,
            &id,
            super::super::derive_treasury_address().as_bytes()
        ) > 0
    );
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
    /// Per asset, what the payer is debited equals what the payee, the app,
    /// the treasury and the insurance pool are credited, whatever the
    /// amount, decimals, signed price and margin; no TNZO moves.
    #[test]
    fn a_fee_in_kind_conserves_the_asset(
        amount in 1u128..1_000_000_000_000_000_000u128,
        decimals in 0u8..=18,
        usd_e6 in 0u64..10_000_000_000,
        margin_bps in 0u32..=500,
    ) {
        let mut state = StateAdapter::new();
        let payer = Payer::enrolled(4, &mut state);
        let payee = Address::new([0x96; 32]);
        let app = Address::new([0x95; 32]);
        let spec = crate::token_ledger::TokenRecord {
            name: "Dollar".into(),
            symbol: "USDX".into(),
            decimals,
            total_supply: u128::MAX / 4,
            creator: Vec::new(),
            max_supply: None,
            powers: tenzro_types::token_policy::PowerManifest::NONE,
            policy: tenzro_types::token_policy::TokenPolicy::default(),
            council: None,
            reserve_backing: None,
            pending: None,
        };
        let id = crate::token_ledger::create(&mut state, payer.address().as_bytes(), &spec, &mut Vec::new()).unwrap();
        let asset = format!("0x{}", hex::encode(id));
        let mut entry = tenzro_types::settlement_asset::SettlementAsset::new(&asset, "USDX", "USD", decimals);
        entry.epoch_inflow_cap_units = tenzro_types::settlement_asset::MAX_EPOCH_INFLOW_CAP_UNITS;
        crate::native::settlement_asset::install_for_test(&mut state, &entry);
        crate::native::economy::write_symbol_rate_for_tests(&mut state, "USDX", 0, 1_000_000_000);
        let mut b = binding(usd_e6);
        if margin_bps > 0 {
            b.app_margin = Some(AppMargin { app_wallet: app, margin_bps });
        }
        let bal = |s: &StateAdapter, a: &[u8]| crate::token_ledger::balance(s, &id, a);
        let tnzo_before = state.get_balance(payee.as_bytes());
        let before = bal(&state, payer.address().as_bytes());
        let p = native(&payer.address(), &payee, &asset, amount, b, "prop");
        match settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()) {
            Ok(out) => {
                let debit = before - bal(&state, payer.address().as_bytes());
                let credited = bal(&state, payee.as_bytes())
                    + bal(&state, app.as_bytes())
                    + bal(&state, super::super::derive_treasury_address().as_bytes())
                    + bal(&state, crate::native::insurance::pool_address().as_bytes());
                proptest::prop_assert_eq!(debit, amount);
                proptest::prop_assert_eq!(credited, amount);
                proptest::prop_assert_eq!(bal(&state, payee.as_bytes()) + out.record.fee + out.margin, amount);
                proptest::prop_assert_eq!(state.get_balance(payee.as_bytes()), tnzo_before);
            }
            Err(e) => {
                // Only a fee the amount cannot carry, or a value past the
                // inflow cap, is refused; the transaction then reverts.
                let e = e.to_string();
                proptest::prop_assert!(e.contains("exceed") || e.contains("inflow cap"), "{}", e);
            }
        }
    }
}

#[test]
fn a_usd_priced_tnzo_payment_stays_within_what_its_price_buys() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(3, &mut state);
    let payee = Address::new([0x97; 32]);
    state.set_balance(payer.address().as_bytes(), 100 * ONE_USD_WEI);
    let b = binding(1_000_000);
    let over = native(
        &payer.address(),
        &payee,
        TNZO_ASSET,
        ONE_USD_WEI + 1,
        b,
        "over",
    );
    assert!(settle_native(&mut state, CHAIN, 7, &over, &mut Vec::new()).is_err());
    let exact = native(
        &payer.address(),
        &payee,
        TNZO_ASSET,
        ONE_USD_WEI,
        b,
        "exact",
    );
    settle_native(&mut state, CHAIN, 7, &exact, &mut Vec::new()).unwrap();
    assert_eq!(
        state.get_balance(payer.address().as_bytes()),
        99 * ONE_USD_WEI
    );
}

#[test]
fn the_signature_covers_the_request_the_quote_the_price_and_the_asset() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(4, &mut state);
    let payee = Address::new([0x96; 32]);
    let auth = payer.authorize("p", &payee, 100, TNZO_ASSET, binding(5));
    verify_payment_authorization(&state, CHAIN, "p", &payer.address(), &payee, 100, &auth, 0)
        .unwrap();
    for tamper in [
        |a: &mut PaymentAuthorization| a.binding.request_digest = [0; 32],
        |a: &mut PaymentAuthorization| a.binding.quote_digest = [9; 32],
        |a: &mut PaymentAuthorization| a.binding.usd_e6 = 6,
        |a: &mut PaymentAuthorization| a.asset = format!("0x{}", "00".repeat(32)),
        |a: &mut PaymentAuthorization| a.max_amount = 101,
    ] {
        let mut a = auth.clone();
        tamper(&mut a);
        assert!(
            verify_payment_authorization(&state, CHAIN, "p", &payer.address(), &payee, 100, &a, 0)
                .is_err()
        );
    }
    assert!(
        verify_payment_authorization(&state, CHAIN, "p", &payer.address(), &payee, 101, &auth, 0)
            .is_err()
    );
}

#[test]
fn a_reference_and_a_payment_id_settle_once() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(5, &mut state);
    state.set_balance(payer.address().as_bytes(), 1_000);
    let payee = Address::new([0x95; 32]);
    let other = Address::new([0x94; 32]);
    let p = native(&payer.address(), &payee, TNZO_ASSET, 10, binding(0), "once");
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    assert!(settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).is_err());
    let elsewhere = native(&payer.address(), &other, TNZO_ASSET, 10, binding(0), "once");
    assert!(settle_native(&mut state, CHAIN, 7, &elsewhere, &mut Vec::new()).is_err());
    // A payment that names no request is refused.
    let unbound = PaymentBinding::default();
    let p = native(&payer.address(), &payee, TNZO_ASSET, 10, unbound, "unbound");
    assert!(settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).is_err());
}

#[test]
fn the_payee_lists_delivery_receipts_on_its_record() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(6, &mut state);
    state.set_balance(payer.address().as_bytes(), 1_000);
    let payee = Address::new([0x93; 32]);
    let b = binding(0);
    settle_native(
        &mut state,
        CHAIN,
        7,
        &native(&payer.address(), &payee, TNZO_ASSET, 10, b, "r"),
        &mut Vec::new(),
    )
    .unwrap();
    let reference = pay_ref(CHAIN, &payee, &b, "r");
    let receipt = DeliveryReceipt {
        pay_ref: reference,
        body_digest: [7; 32],
        inference_receipt: Some([8; 32]),
        delivered_at_ms: 9,
        hardware: None,
    };
    let op = PaymentOp::Receipt {
        receipt: receipt.clone(),
    };
    assert!(
        apply_payment_op(
            &mut state,
            CHAIN,
            9,
            payer.address().as_bytes(),
            &op,
            &mut Vec::new()
        )
        .is_err()
    );
    apply_payment_op(&mut state, CHAIN, 9, payee.as_bytes(), &op, &mut Vec::new()).unwrap();
    assert!(
        apply_payment_op(&mut state, CHAIN, 9, payee.as_bytes(), &op, &mut Vec::new()).is_err()
    );
    let record = read_payment(&state, &reference).unwrap();
    assert_eq!(record.receipts, vec![hex::encode(receipt.digest())]);
}

/// A receipt naming the hardware that served it is listed only when that
/// level and type are what the chain attests for the payee: a payee with no
/// attested hardware cannot claim a TPM at level 1.
#[test]
fn a_receipt_claiming_a_level_without_its_attestation_is_refused() {
    use tenzro_types::hardware_level::{HardwareKind, HardwareLevel, HardwareStamp};
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(8, &mut state);
    state.set_balance(payer.address().as_bytes(), 1_000);
    let payee = Address::new([0x94; 32]);
    let b = binding(0);
    settle_native(
        &mut state,
        CHAIN,
        7,
        &native(&payer.address(), &payee, TNZO_ASSET, 10, b, "h"),
        &mut Vec::new(),
    )
    .unwrap();
    let reference = pay_ref(CHAIN, &payee, &b, "h");
    let claimed = DeliveryReceipt {
        pay_ref: reference,
        body_digest: [7; 32],
        inference_receipt: None,
        delivered_at_ms: 9,
        hardware: Some(HardwareStamp {
            level: HardwareLevel::L1,
            kind: HardwareKind::Tpm2,
            scheme: "ecdsa-p256".into(),
            ..Default::default()
        }),
    };
    let op = PaymentOp::Receipt { receipt: claimed };
    assert!(
        apply_payment_op(&mut state, CHAIN, 9, payee.as_bytes(), &op, &mut Vec::new()).is_err()
    );
    assert!(
        read_payment(&state, &reference)
            .unwrap()
            .receipts
            .is_empty()
    );
    // The stamp the chain derives (no identity: level 0, software) is listed.
    let (derived, _, _) = crate::native::hardware_level::derive(&state, payee.as_bytes(), 9);
    let honest = DeliveryReceipt {
        pay_ref: reference,
        body_digest: [7; 32],
        inference_receipt: None,
        delivered_at_ms: 9,
        hardware: Some(derived),
    };
    let op = PaymentOp::Receipt {
        receipt: honest.clone(),
    };
    apply_payment_op(&mut state, CHAIN, 9, payee.as_bytes(), &op, &mut Vec::new()).unwrap();
    assert_eq!(
        read_payment(&state, &reference).unwrap().receipts,
        vec![hex::encode(honest.digest())]
    );
}

#[test]
fn a_quote_binds_price_licence_and_request_into_the_record() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(7, &mut state);
    state.set_balance(payer.address().as_bytes(), 10 * ONE_USD_WEI);
    let payee = Address::new([0x92; 32]);
    let quote = Quote {
        payee,
        request_digest: [0x33; 32],
        usd_e6: 100_000,
        accepts: vec![QuotedAsset {
            asset: TNZO_ASSET.into(),
            max_amount: ONE_USD_WEI,
        }],
        licence: "licence-a".into(),
        content_usage: "train-ai=n".into(),
        lines: Vec::new(),
        expires_at_ms: 1_000,
        hardware: None,
    };
    let b = quote.binding();
    let amount = super::usd_e6_to_wei(&state, quote.usd_e6);
    settle_native(
        &mut state,
        CHAIN,
        7,
        &native(&payer.address(), &payee, TNZO_ASSET, amount, b, "q"),
        &mut Vec::new(),
    )
    .unwrap();
    let record = read_payment(&state, &pay_ref(CHAIN, &payee, &b, "q")).unwrap();
    assert_eq!(record.binding.quote_digest, quote.digest());
    assert_eq!(record.binding.request_digest, quote.request_digest);
    // A different licence is a different quote, so a different record.
    let mut other = quote.clone();
    other.licence = "licence-b".into();
    assert_ne!(other.digest(), record.binding.quote_digest);
}

#[test]
fn an_attested_payment_is_labelled_capped_and_never_takes_a_native_reference() {
    let mut state = StateAdapter::new();
    let attestor = [0xaa; 32];
    let payee = Address::new([0x91; 32]);
    let b = binding(5_000_000);
    let payment = AttestedPayment {
        rail: "card".into(),
        payer: "card-holder-digest".into(),
        payee,
        asset: "USD".into(),
        amount: 500,
        binding: b,
        nonce: "n-1".into(),
    };
    let op = PaymentOp::Attested {
        payment: payment.clone(),
    };
    assert!(apply_payment_op(&mut state, CHAIN, 9, &attestor, &op, &mut Vec::new()).is_err());
    crate::native::role_stake::bond_role_for_test(
        &mut state,
        &attestor,
        tenzro_types::network::NetworkRole::Attestor,
        tenzro_types::constants::MIN_ATTESTOR_STAKE,
    );
    let recorded = apply_payment_op(&mut state, CHAIN, 9, &attestor, &op, &mut Vec::new()).unwrap();
    assert!(apply_payment_op(&mut state, CHAIN, 9, &attestor, &op, &mut Vec::new()).is_err());
    let attested_ref: [u8; 32] = recorded.data[..32].try_into().unwrap();
    let attested = read_payment(&state, &attested_ref).expect("the attested record is in state");
    assert_eq!(attested.class, RecordClass::Attested);
    assert_eq!(attested.settled.fee_asset, "USD");
    assert_eq!(attested.settled.value_units, 5_000_000);
    assert_eq!(attested.settled.unit.basket, "USD");
    assert_eq!(attested.settled.payout_asset, "USD");

    // A native payment with the same binding and nonce still settles: the
    // attested record sits under its own reference.
    let payer = Payer::enrolled(8, &mut state);
    state.set_balance(payer.address().as_bytes(), 100 * ONE_USD_WEI);
    let p = native(&payer.address(), &payee, TNZO_ASSET, ONE_USD_WEI, b, "n-1");
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    let record = read_payment_by_id(&state, "n-1").unwrap();
    assert_eq!(record.class, RecordClass::Native);

    // Over the cap: refused.
    let mut big = payment.clone();
    big.nonce = "n-2".into();
    big.binding.usd_e6 = DEFAULT_ATTESTED_CAP_USD_E6 + 1;
    assert!(
        apply_payment_op(
            &mut state,
            CHAIN,
            9,
            &attestor,
            &PaymentOp::Attested { payment: big },
            &mut Vec::new()
        )
        .is_err()
    );

    // Disabled by governance: refused.
    state.set_storage(
        &SYSTEM_ADDRESS,
        governed_param_key(ATTESTED_ENABLED_PARAM).as_bytes(),
        0u64.to_le_bytes().to_vec(),
    );
    let mut later = payment;
    later.nonce = "n-3".into();
    assert!(
        apply_payment_op(
            &mut state,
            CHAIN,
            9,
            &attestor,
            &PaymentOp::Attested { payment: later },
            &mut Vec::new()
        )
        .is_err()
    );
}

#[test]
fn a_payment_no_agent_account_reported_is_refused() {
    let mut state = StateAdapter::new();
    let op = PaymentOp::Proven {
        agent_did: "did:tenzro:agent:none".into(),
        chain: "eip155:8453".into(),
        delivery: vec![1, 2, 3],
    };
    assert!(apply_payment_op(&mut state, CHAIN, 9, &[1; 32], &op, &mut Vec::new()).is_err());
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

fn node_key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn serving(machine: &str, key: &SigningKey) -> ServingNode {
    let point = key.verifying_key().to_sec1_point(false);
    ServingNode {
        machine_did: machine.into(),
        operator_did: "did:tenzro:human:op".into(),
        dpop_public_key: hex::encode(&point.as_bytes()[1..]),
        ..Default::default()
    }
}

/// An agent whose terms allow paying and opening channels up to `daily`
/// wei a day, with `asset_limits`, served by `MACHINE`.
fn agent(state: &mut StateAdapter, daily: u128, asset_limits: Vec<AssetLimit>) -> SigningKey {
    let key = node_key(7);
    let terms = AgentTerms {
        controller_did: "did:tenzro:human:controller".into(),
        agent_name: "buyer".into(),
        delegation_scope: TermsScope {
            max_daily_spend: Some(daily.to_string()),
            allowed_operations: vec![OP_PAY.into(), "create_escrow".into()],
            asset_limits,
            ..Default::default()
        },
        capabilities: vec![],
        serving_nodes: vec![serving(MACHINE, &key)],
        min_distinct_operators: 1,
        expires_at_ms: None,
        trifecta_exception: false,
        auto_approve: None,
        credentials: Vec::new(),
    };
    crate::native::economy::count_wei_as_units_for_tests(state);
    super::super::agent_terms::store_terms_unapproved(
        state,
        AGENT,
        &super::super::agent_terms::StoredAgentTerms {
            terms,
            root: tenzro_types::agent_terms::RootKind::Passkey,
            version: 1,
            approval_digest: String::new(),
            updated_at_ms: 0,
            renewed_at_ms: None,
        },
    );
    state.set_balance(derive_bond_vault_address(AGENT).as_bytes(), u128::MAX / 4);
    key
}

fn act_as(
    state: &mut StateAdapter,
    key: &SigningKey,
    mut action: AgentAction,
    at: i64,
) -> std::result::Result<(), String> {
    action.nonce = super::super::agent_terms::read_agent_act_nonce(state, AGENT);
    let sig: p256::ecdsa::Signature = key.sign_prehash(&action.digest()).unwrap();
    super::super::agent_terms::act(state, CHAIN, &action, &sig.to_bytes(), at)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn action(operation: &str, payee: &Address, amount: u128) -> AgentAction {
    AgentAction {
        agent_did: AGENT.into(),
        machine_did: MACHINE.into(),
        operation: operation.into(),
        counterparty: hex::encode(payee.as_bytes()),
        amount,
        asset: None,
        usd_e6: 0,
        payment: None,
        chain: "tenzro".into(),
        payment_protocol: None,
        model: None,
        calls: Vec::new(),
        escrow: None,
        remote_grant: None,
        nonce: 0,
        tainted: false,
        step_up: None,
        ballot: None,
        veto_signal: None,
    }
}

fn pay(payee: &Address, amount: u128, id: &str) -> AgentAction {
    let mut a = action(OP_PAY, payee, amount);
    a.payment = Some(AgentPayment {
        payment_id: id.into(),
        request_digest: [0x44; 32],
        quote_digest: [0x55; 32],
    });
    a
}

#[test]
fn an_agent_pays_from_its_wallet_only_within_its_terms() {
    let mut state = StateAdapter::new();
    let key = agent(&mut state, 1_000, Vec::new());
    let wallet = agent_wallet(AGENT);
    state.set_balance(&wallet, 5_000);
    let payee = Address::new([0x81; 32]);

    act_as(&mut state, &key, pay(&payee, 600, "a-1"), 1_000).unwrap();
    let record = read_payment_by_id(&state, "a-1").unwrap();
    assert_eq!(record.agent_did.as_deref(), Some(AGENT));
    assert_eq!(record.payer, hex::encode(wallet));
    assert_eq!(state.get_balance(&wallet), 4_400);

    // The day's cap counts the payment: a second one past it is refused.
    let err = act_as(&mut state, &key, pay(&payee, 500, "a-2"), 2_000).unwrap_err();
    assert!(err.contains("daily limit"), "{err}");
    // A node the terms do not assign cannot sign for the agent.
    let mut stranger = pay(&payee, 10, "a-3");
    stranger.machine_did = OTHER_MACHINE.into();
    assert!(act_as(&mut state, &node_key(9), stranger, 2_000).is_err());
    // Revoked: nothing more.
    impose_revocation(&mut state, 3_000);
    assert!(act_as(&mut state, &key, pay(&payee, 10, "a-4"), 4_000).is_err());
}

/// What a facilitator settles a `proven` x402 demand on: the record the
/// ledger writes when an agent pays within its Terms, and none past them.
#[test]
fn an_agent_payment_within_its_terms_leaves_the_record_a_proven_demand_is_met_by() {
    let mut state = StateAdapter::new();
    let key = agent(&mut state, 1_000, Vec::new());
    state.set_balance(&agent_wallet(AGENT), 5_000);
    let payee = Address::new([0x81; 32]);

    act_as(&mut state, &key, pay(&payee, 600, "x402-1"), 1_000).unwrap();
    let record = read_payment_by_id(&state, "x402-1").unwrap();
    assert_eq!(record.payee, payee);
    assert_eq!(record.amount, 600);
    assert_eq!(record.agent_did.as_deref(), Some(AGENT));
    assert_eq!(record.payer, hex::encode(agent_wallet(AGENT)));
    let pay_ref = hex::decode(&record.pay_ref).unwrap();
    assert_eq!(
        read_payment(&state, &pay_ref.try_into().unwrap()).map(|r| r.amount),
        Some(600)
    );

    // Past its terms the act is refused, so no record exists to answer with.
    let refused = act_as(&mut state, &key, pay(&payee, 500, "x402-2"), 2_000).unwrap_err();
    assert!(refused.contains("daily limit"), "{refused}");
    assert!(read_payment_by_id(&state, "x402-2").is_none());
}

#[test]
fn an_agent_pays_in_a_listed_token_counted_at_its_usd_price() {
    let mut state = StateAdapter::new();
    no_settlement_fee(&mut state);
    let wallet = agent_wallet(AGENT);
    let (id, asset) = token(&mut state, &wallet, 1_000_000);
    let payee = Address::new([0x82; 32]);
    state.set_balance(payee.as_bytes(), ONE_USD_WEI);

    // Not listed in the terms: refused.
    let key = agent(&mut state, 2_000_000, Vec::new());
    let mut a = pay(&payee, 1_000, "t-1");
    a.asset = Some(asset.clone());
    a.usd_e6 = 1_000_000;
    assert!(
        act_as(&mut state, &key, a.clone(), 1_000)
            .unwrap_err()
            .contains("asset")
    );

    let key = agent(
        &mut state,
        2_000_000,
        vec![AssetLimit {
            min_counterparty_kyc_tier: 0,
            asset: asset.clone(),
            max_per_tx: None,
            max_per_day: "5000".into(),
        }],
    );
    act_as(&mut state, &key, a, 1_000).unwrap();
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payee.as_bytes()),
        1_000
    );
    // One USD counted against the two-USD daily cap: a second dollar fits, a
    // third does not.
    let mut b = pay(&payee, 1_000, "t-2");
    b.asset = Some(asset.clone());
    b.usd_e6 = 1_000_000;
    act_as(&mut state, &key, b, 1_000).unwrap();
    let mut c = pay(&payee, 1_000, "t-3");
    c.asset = Some(asset);
    c.usd_e6 = 1_000_000;
    assert!(
        act_as(&mut state, &key, c, 1_000)
            .unwrap_err()
            .contains("daily limit")
    );
}

fn impose_revocation(state: &mut StateAdapter, at_ms: i64) {
    let q = super::super::agent_audit::AgentQuarantine {
        controller_did: "did:tenzro:human:controller".into(),
        by: "controller".into(),
        reason_code: 1,
        evidence_hash: None,
        at_ms,
        revoked: true,
    };
    super::super::agent_audit::impose(state, AGENT, &q, &mut Vec::new(), &mut Vec::new()).unwrap();
}

fn agent_voucher(
    key: &SigningKey,
    machine: &str,
    escrow_id: [u8; 32],
    cumulative: u128,
    as_of_ms: u64,
) -> EscrowVoucher {
    let signer = AgentVoucherSigner {
        agent_did: AGENT.into(),
        machine_did: machine.into(),
        as_of_ms,
    };
    let sig: p256::ecdsa::Signature = key
        .sign_prehash(&agent_voucher_digest(
            CHAIN, &escrow_id, cumulative, &[0u8; 32], &signer,
        ))
        .unwrap();
    EscrowVoucher {
        binding: [0u8; 32],
        escrow_id,
        cumulative_amount: cumulative,
        public_key: Vec::new(),
        signature: tenzro_crypto::composite::CompositeSignature::classical(
            tenzro_crypto::composite::ClassicalProof::Raw {
                signature: sig.to_bytes().to_vec(),
            },
        ),
        agent: Some(signer),
        attribution: None,
    }
}

/// Open a channel from the agent's wallet to `payee` and return its id.
fn open_channel(
    state: &mut StateAdapter,
    key: &SigningKey,
    payee: &Address,
    amount: u128,
    asset: Option<(String, u64)>,
) -> [u8; 32] {
    let nonce = super::super::agent_terms::read_agent_act_nonce(state, AGENT);
    let mut a = action("create_escrow", payee, amount);
    a.escrow = Some(AgentEscrow::Create {
        expires_at_ms: 1_000_000,
        release_conditions: ReleaseConditions::ProviderSignature,
        reference: None,
    });
    if let Some((asset, usd)) = asset {
        a.asset = Some(asset);
        a.usd_e6 = usd;
    }
    act_as(state, key, a, 1_000).unwrap();
    derive_escrow_id(&Address::new(agent_wallet(AGENT)), nonce)
}

#[test]
fn a_serving_node_signs_an_agents_vouchers_until_revocation() {
    let mut state = StateAdapter::new();
    let key = agent(&mut state, 10_000, Vec::new());
    state.set_balance(&agent_wallet(AGENT), 10_000);
    let payee = Address::new([0x83; 32]);
    let escrow_id = open_channel(&mut state, &key, &payee, 1_000, None);
    // The lock was debited from the day's cap at open.
    assert_eq!(
        super::super::agent_terms::read_agent_spent(&state, AGENT, 1_000),
        1_000
    );

    let ok = agent_voucher(&key, MACHINE, escrow_id, 300, 1_500);
    let claim = check_whole(CHAIN, 2_000, &ok, &state).unwrap();
    assert_eq!(claim.payout, 300);

    // A node the terms do not assign, a wrong key, or a future date: refused.
    assert!(
        check_whole(
            CHAIN,
            2_000,
            &agent_voucher(&key, OTHER_MACHINE, escrow_id, 300, 1_500),
            &state
        )
        .is_err()
    );
    assert!(
        check_whole(
            CHAIN,
            2_000,
            &agent_voucher(&node_key(9), MACHINE, escrow_id, 300, 1_500),
            &state
        )
        .is_err()
    );
    let ahead = 2_000 + DEFAULT_VOUCHER_FRESHNESS_MS + 1;
    assert!(
        check_whole(
            CHAIN,
            2_000,
            &agent_voucher(&key, MACHINE, escrow_id, 300, ahead),
            &state
        )
        .is_err()
    );
    // Beyond the lock: refused.
    assert!(
        check_whole(
            CHAIN,
            2_000,
            &agent_voucher(&key, MACHINE, escrow_id, 1_001, 1_500),
            &state
        )
        .is_err()
    );

    // Revoked at 3000: a voucher signed before still pays, one signed after
    // does not.
    impose_revocation(&mut state, 3_000);
    check_whole(
        CHAIN,
        4_000,
        &agent_voucher(&key, MACHINE, escrow_id, 400, 2_999),
        &state,
    )
    .unwrap();
    assert!(
        check_whole(
            CHAIN,
            4_000,
            &agent_voucher(&key, MACHINE, escrow_id, 400, 3_000),
            &state
        )
        .is_err()
    );
}

#[test]
fn an_agent_channel_in_a_token_pays_out_in_the_token_and_its_fee_in_kind() {
    let mut state = StateAdapter::new();
    let wallet = agent_wallet(AGENT);
    let (id, asset) = token(&mut state, &wallet, 10_000);
    let key = agent(
        &mut state,
        10 * ONE_USD_WEI,
        vec![AssetLimit {
            min_counterparty_kyc_tier: 0,
            asset: asset.clone(),
            max_per_tx: None,
            max_per_day: "5000".into(),
        }],
    );
    let payee = Address::new([0x84; 32]);
    state.set_balance(payee.as_bytes(), ONE_USD_WEI);
    let escrow_id = open_channel(&mut state, &key, &payee, 2_000, Some((asset, 2_000)));
    assert_eq!(crate::token_ledger::balance(&state, &id, &wallet), 8_000);

    let v = agent_voucher(&key, MACHINE, escrow_id, 500, 1_500);
    let claim = check_whole(CHAIN, 2_000, &v, &state).unwrap();
    let settled = pay_from_vault(
        &mut state,
        &escrow_id,
        &claim.escrow,
        payee.as_bytes(),
        claim.payout,
        2_000,
        &Default::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert!(settled.fee > 0);
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payee.as_bytes()),
        500 - settled.fee
    );
    assert_eq!(
        state.get_balance(payee.as_bytes()),
        ONE_USD_WEI,
        "no TNZO is taken"
    );
}

#[test]
fn a_key_voucher_cannot_draw_on_an_agents_channel() {
    let mut state = StateAdapter::new();
    let key = agent(&mut state, 10_000, Vec::new());
    state.set_balance(&agent_wallet(AGENT), 10_000);
    let escrow_id = open_channel(&mut state, &key, &Address::new([0x85; 32]), 1_000, None);
    let payer = Payer::enrolled(9, &mut state);
    let v = EscrowVoucher {
        binding: [0u8; 32],
        escrow_id,
        cumulative_amount: 100,
        public_key: payer.key.public_key().p256.clone(),
        signature: payer
            .key
            .sign(
                SignatureContext::EscrowVoucher,
                &escrow_voucher_preimage(CHAIN, &escrow_id, 100, &[0u8; 32]),
            )
            .unwrap(),
        agent: None,
        attribution: None,
    };
    assert!(check_whole(CHAIN, 2_000, &v, &state).is_err());
}

/// A voucher's attribution is the payer's: one added or changed after the
/// payer signed is refused, and one naming an identity that is not
/// registered is refused even when signed.
#[test]
fn a_voucher_attribution_is_signed_by_the_payer_and_names_a_registered_identity() {
    use tenzro_types::payment_authorization::attributed_voucher_preimage;
    use tenzro_types::settlement::CallAttribution;
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(11, &mut state);
    state.set_balance(payer.address().as_bytes(), 1_000 * ONE_USD_WEI);
    let payload = super::super::CreateEscrowPayload {
        payee: Address::new([0x86; 32]),
        amount: ONE_USD_WEI,
        asset_id: tenzro_types::asset::AssetId::tnzo(),
        usd_e6: 0,
        expires_at: 1_000_000,
        release_conditions: ReleaseConditions::Timeout,
        reference: None,
    };
    let (escrow_id, _, _) = super::super::lock_escrow(
        &mut state,
        payer.address().as_bytes(),
        0,
        &payload,
        0,
        1_000,
    )
    .unwrap();
    let app = CallAttribution {
        app_did: Some("did:tenzro:human:dana".into()),
        ..Default::default()
    };
    let signed = |attribution: Option<&CallAttribution>| {
        payer
            .key
            .sign(
                SignatureContext::EscrowVoucher,
                &attributed_voucher_preimage(
                    escrow_voucher_preimage(CHAIN, &escrow_id, 100, &[0u8; 32]),
                    attribution,
                ),
            )
            .unwrap()
    };
    let voucher = |signature, attribution: Option<CallAttribution>| EscrowVoucher {
        binding: [0u8; 32],
        escrow_id,
        cumulative_amount: 100,
        public_key: payer.key.public_key().p256.clone(),
        signature,
        agent: None,
        attribution,
    };
    // Signed without it, carried with it: refused.
    assert!(
        check_whole(
            CHAIN,
            2_000,
            &voucher(signed(None), Some(app.clone())),
            &state
        )
        .is_err()
    );
    // Signed with it, naming an unregistered identity: refused.
    let attributed = voucher(signed(Some(&app)), Some(app.clone()));
    assert!(check_whole(CHAIN, 2_000, &attributed, &state).is_err());
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: "did:tenzro:human:dana".into(),
        identity_type: "human".into(),
        display_name: String::new(),
        controller_pubkey: Vec::new(),
        key_type: "p256".into(),
        wallet_id: String::new(),
        wallet_address: Address::new([0x87; 32]),
        pq_verifying_key: Vec::new(),
        metadata: Default::default(),
        proof: tenzro_types::identity::RegistrationProof::Hardware {
            signature: tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        },
    };
    state.set_storage(
        &SYSTEM_ADDRESS,
        &super::super::identity_storage_key("did:tenzro:human:dana"),
        serde_json::to_vec(&record).unwrap(),
    );
    assert_eq!(
        check_whole(CHAIN, 2_000, &attributed, &state)
            .unwrap()
            .payout,
        100
    );
    // The same voucher without its attribution no longer verifies.
    assert!(check_whole(CHAIN, 2_000, &voucher(signed(Some(&app)), None), &state).is_err());
}

/// A payer with an ML-DSA-65 key enrolled in state cannot be debited on its
/// P-256 key alone, and an ML-DSA-65 leg under any other key is refused.
#[test]
fn a_stolen_p256_key_alone_cannot_authorize_a_payment_from_an_enrolled_account() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(6, &mut state);
    let payee = Address::new([0x97; 32]);
    let honest = payer.authorize("p", &payee, 100, TNZO_ASSET, binding(5));
    assert!(honest.signature.pq.is_some());
    verify_payment_authorization(
        &state,
        CHAIN,
        "p",
        &payer.address(),
        &payee,
        100,
        &honest,
        0,
    )
    .unwrap();

    // The thief holds the same P-256 key and no ML-DSA-65 key.
    let thief = Payer::p256_only(6);
    assert_eq!(thief.address(), payer.address());
    let stripped = thief.authorize("p", &payee, 100, TNZO_ASSET, binding(5));
    assert!(
        verify_payment_authorization(
            &state,
            CHAIN,
            "p",
            &payer.address(),
            &payee,
            100,
            &stripped,
            0
        )
        .is_err()
    );

    // A leg from the thief's own ML-DSA-65 key does not stand in for the enrolled one.
    let mut grafted = stripped.clone();
    grafted.signature.pq = Payer {
        key: TestHybridSigner::hybrid(8),
    }
    .authorize("p", &payee, 100, TNZO_ASSET, binding(5))
    .signature
    .pq;
    assert!(
        verify_payment_authorization(
            &state,
            CHAIN,
            "p",
            &payer.address(),
            &payee,
            100,
            &grafted,
            0
        )
        .is_err()
    );

    // An account with no ML-DSA-65 key enrolled is refused too: the leg is
    // required whether or not a key is enrolled.
    assert!(
        verify_payment_authorization(
            &StateAdapter::new(),
            CHAIN,
            "p",
            &payer.address(),
            &payee,
            100,
            &stripped,
            0
        )
        .is_err()
    );
}

#[test]
fn a_token_payment_counts_against_the_unit_cap_however_low_its_declared_price() {
    let mut state = StateAdapter::new();
    no_settlement_fee(&mut state);
    let wallet = agent_wallet(AGENT);
    let (id, asset) = token(&mut state, &wallet, 1_000_000);
    state.set_balance(&wallet, 10 * ONE_USD_WEI);
    let payee = Address::new([0x84; 32]);
    state.set_balance(payee.as_bytes(), ONE_USD_WEI);
    let key = agent(
        &mut state,
        2 * ONE_USD_WEI,
        vec![AssetLimit {
            min_counterparty_kyc_tier: 0,
            asset: asset.clone(),
            max_per_tx: None,
            max_per_day: "5000".into(),
        }],
    );

    // The proposer states the price; one micro-dollar for the asset's whole
    // daily limit. The asset's own limit lets it through.
    let mut cheap = pay(&payee, 5_000, "p-1");
    cheap.asset = Some(asset);
    cheap.usd_e6 = 1;
    act_as(&mut state, &key, cheap, 1_000).unwrap();
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payee.as_bytes()),
        5_000
    );
    // The whole daily allowance in the asset is the terms' whole daily
    // spend: nothing in TNZO is left for the day.
    let err = act_as(&mut state, &key, pay(&payee, ONE_USD_WEI, "p-2"), 1_000).unwrap_err();
    assert!(err.contains("daily limit"), "{err}");
}

/// Six agent channels, each paid call by call with vouchers that run one
/// call's ceiling ahead of what was spent: the payee's claims are exactly
/// what the calls cost, and once the escrows expire the agent's wallet gets
/// back everything else, the last voucher's headroom included.
#[tokio::test]
async fn channels_settle_at_the_metered_cost_and_the_payer_gets_the_rest() {
    let mut state = StateAdapter::new();
    let key = agent(&mut state, 100_000, Vec::new());
    let wallet = agent_wallet(AGENT);
    state.set_balance(&wallet, 10_000);
    let payee = Address::new([0x85; 32]);
    let (lock, ceiling) = (1_000u128, 100u128);
    let costs: [&[u128]; 6] = [
        &[7, 11, 13],
        &[50],
        &[1, 2, 3, 4],
        &[90, 9],
        &[33, 33, 33],
        &[64],
    ];
    let mut claims = Vec::new();
    let mut ids = Vec::new();
    for calls in costs {
        let id = open_channel(&mut state, &key, &payee, lock, None);
        let (mut spent, mut last) = (0u128, None);
        for cost in calls {
            last = Some(agent_voucher(&key, MACHINE, id, spent + ceiling, 1_500));
            spent += cost;
        }
        claims.push(EscrowClaim {
            voucher: last.unwrap(),
            amount: spent,
        });
        ids.push((id, spent));
    }
    assert_eq!(state.get_balance(&wallet), 10_000 - 6 * lock);

    use crate::traits::VmExecutor as _;
    let executor = NativeExecutor::new(crate::config::VmConfig::default()).unwrap();
    let mut data = super::super::SELECTOR_ESCROW_CLAIM.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&serde_json::json!({ "claims": claims })).unwrap());
    let mut tx = VmTransaction::new(
        payee.as_bytes().to_vec(),
        None,
        0,
        data,
        1_000_000,
        0,
        0,
        crate::VmType::Tenzro,
        CHAIN,
    );
    tx.block_timestamp_ms = Some(2_000);
    let r = executor.execute_transaction(&tx, &mut state).await.unwrap();
    assert!(r.success, "the claim executes: {:?}", r.revert_reason);
    for (id, spent) in &ids {
        let (_, _, escrow) = super::super::read_escrow_record(&state, id).unwrap();
        assert_eq!(
            escrow.claimed, *spent,
            "each channel pays its metered cost, not its last voucher"
        );
    }

    // Past expiry the agent refunds each escrow: the wallet gets lock - spent back from every one.
    let before = state.get_balance(&wallet);
    for (id, _) in &ids {
        super::super::refund_escrow(&mut state, id, &wallet, 1_000_001).unwrap();
    }
    let refunded: u128 = ids.iter().map(|(_, spent)| lock - spent).sum();
    assert_eq!(state.get_balance(&wallet), before + refunded);
}

/// Submit a `PayerSettle` from an unrelated account and report whether it
/// executed.
async fn submit_payer_settle(state: &mut StateAdapter, payload: PayerSettle<'_>) -> bool {
    use crate::traits::VmExecutor as _;
    let executor = NativeExecutor::new(crate::config::VmConfig::default()).unwrap();
    let mut data = super::super::SELECTOR_PAYER_SETTLE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&payload).unwrap());
    let mut tx = VmTransaction::new(
        vec![0x5a; 32],
        None,
        0,
        data,
        1_000_000,
        0,
        0,
        crate::VmType::Tenzro,
        CHAIN,
    );
    tx.block_timestamp_ms = Some(1_000);
    matches!(executor.execute_transaction(&tx, state).await, Ok(r) if r.success)
}

/// An `PayerSettle` payload as a submitter sends it, with any fields of its
/// own in `extra`.
#[derive(serde::Serialize)]
struct PayerSettle<'a> {
    payer: Address,
    payee: &'a Address,
    amount: u128,
    payment_id: &'a str,
    authorization: &'a PaymentAuthorization,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

fn payer_settle<'a>(
    payer: &Payer,
    payee: &'a Address,
    amount: u128,
    id: &'a str,
    authorization: &'a PaymentAuthorization,
) -> PayerSettle<'a> {
    PayerSettle {
        payer: payer.address(),
        payee,
        amount,
        payment_id: id,
        authorization,
        extra: serde_json::Map::new(),
    }
}

/// A payer that signed no developer margin pays none, whatever the
/// submitter of the settlement names.
#[tokio::test]
async fn a_settlement_pays_no_margin_the_payer_did_not_sign() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(21, &mut state);
    let payee = Address::new([0x71; 32]);
    let wallet = Address::new([0x72; 32]);
    let amount = 1_000_000u128;
    state.set_balance(payer.address().as_bytes(), 10 * amount);
    let auth = payer.authorize("m-1", &payee, amount, TNZO_ASSET, binding(0));

    let mut named = payer_settle(&payer, &payee, amount, "m-1", &auth);
    named
        .extra
        .insert("app_wallet".into(), serde_json::json!(wallet));
    named
        .extra
        .insert("margin_bps".into(), serde_json::json!(1_000));
    assert!(!submit_payer_settle(&mut state, named).await);

    let mut added = auth.clone();
    added.binding.app_margin = Some(AppMargin {
        app_wallet: wallet,
        margin_bps: 1_000,
    });
    assert!(
        !submit_payer_settle(
            &mut state,
            payer_settle(&payer, &payee, amount, "m-1", &added)
        )
        .await
    );
    assert_eq!(state.get_balance(payer.address().as_bytes()), 10 * amount);
    assert_eq!(state.get_balance(wallet.as_bytes()), 0);

    assert!(
        submit_payer_settle(
            &mut state,
            payer_settle(&payer, &payee, amount, "m-1", &auth)
        )
        .await
    );
    assert_eq!(state.get_balance(wallet.as_bytes()), 0);
    assert_eq!(state.get_balance(payer.address().as_bytes()), 9 * amount);
}

/// The margin the payer signed is paid to exactly the wallet it signed, and
/// no submitter can move it elsewhere or past the governed cap.
#[tokio::test]
async fn a_signed_margin_is_paid_to_the_signed_wallet() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(22, &mut state);
    let payee = Address::new([0x73; 32]);
    let wallet = Address::new([0x74; 32]);
    let other = Address::new([0x75; 32]);
    let amount = 11 * ONE_USD_WEI;
    state.set_balance(payer.address().as_bytes(), 10 * amount);
    let signed = PaymentBinding {
        app_margin: Some(AppMargin {
            app_wallet: wallet,
            margin_bps: 1_000,
        }),
        ..binding(0)
    };
    let auth = payer.authorize("m-2", &payee, amount, TNZO_ASSET, signed);

    let mut moved = auth.clone();
    moved.binding.app_margin = Some(AppMargin {
        app_wallet: other,
        margin_bps: 1_000,
    });
    assert!(
        !submit_payer_settle(
            &mut state,
            payer_settle(&payer, &payee, amount, "m-2", &moved)
        )
        .await
    );
    let mut raised = auth.clone();
    raised.binding.app_margin = Some(AppMargin {
        app_wallet: wallet,
        margin_bps: 1_500,
    });
    assert!(
        !submit_payer_settle(
            &mut state,
            payer_settle(&payer, &payee, amount, "m-2", &raised)
        )
        .await
    );

    assert!(
        submit_payer_settle(
            &mut state,
            payer_settle(&payer, &payee, amount, "m-2", &auth)
        )
        .await
    );
    // amount * 1_000 / 11_000: the margin is inside the signed amount.
    assert_eq!(state.get_balance(wallet.as_bytes()), ONE_USD_WEI);
    assert_eq!(state.get_balance(other.as_bytes()), 0);
    assert_eq!(state.get_balance(payer.address().as_bytes()), 9 * amount);
    let payee_got = state.get_balance(payee.as_bytes());
    assert!(payee_got > 0 && payee_got <= amount - ONE_USD_WEI);

    let over_cap = PaymentBinding {
        app_margin: Some(AppMargin {
            app_wallet: wallet,
            margin_bps: 10_000,
        }),
        ..binding(0)
    };
    let auth = payer.authorize("m-3", &payee, amount, TNZO_ASSET, over_cap);
    assert!(
        !submit_payer_settle(
            &mut state,
            payer_settle(&payer, &payee, amount, "m-3", &auth)
        )
        .await
    );
    assert_eq!(state.get_balance(wallet.as_bytes()), ONE_USD_WEI);
}

/// Once the agent is revoked, its node's signature dated before the
/// revocation pays only while that date is still fresh: a key that signs
/// after the revocation cannot backdate its way into the escrow.
#[test]
fn a_backdated_voucher_does_not_pay_after_revocation() {
    let mut state = StateAdapter::new();
    let key = agent(&mut state, 10_000, Vec::new());
    state.set_balance(&agent_wallet(AGENT), 10_000);
    let payee = Address::new([0x85; 32]);
    let escrow_id = open_channel(&mut state, &key, &payee, 1_000, None);
    impose_revocation(&mut state, 3_000);
    let an_hour_on = 3_000 + 3_600_000;
    assert!(
        check_whole(
            CHAIN,
            an_hour_on,
            &agent_voucher(&key, MACHINE, escrow_id, 1_000, 2_999),
            &state
        )
        .is_err()
    );
    // Inside the freshness window a voucher signed before revocation pays.
    check_whole(
        CHAIN,
        3_000 + DEFAULT_VOUCHER_FRESHNESS_MS as i64 - 2,
        &agent_voucher(&key, MACHINE, escrow_id, 400, 2_999),
        &state,
    )
    .unwrap();
}

/// Execute a `PayerSettle` from an unrelated account and return its result.
async fn execute_payer_settle(
    state: &mut StateAdapter,
    payload: PayerSettle<'_>,
) -> crate::types::ExecutionResult {
    use crate::traits::VmExecutor as _;
    let executor = NativeExecutor::new(crate::config::VmConfig::default()).unwrap();
    let mut data = super::super::SELECTOR_PAYER_SETTLE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&payload).unwrap());
    let mut tx = VmTransaction::new(
        vec![0x5a; 32],
        None,
        0,
        data,
        1_000_000,
        0,
        0,
        crate::VmType::Tenzro,
        CHAIN,
    );
    tx.block_timestamp_ms = Some(1_000);
    executor.execute_transaction(&tx, state).await.unwrap()
}

/// A settlement to a bonded inference provider declares on its result what
/// it burned and the treasury leg it paid, and both match what the treasury
/// and the record show.
#[tokio::test]
async fn a_payer_settlement_declares_its_burn_and_treasury_leg() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(23, &mut state);
    let payee = Address::new([0x76; 32]);
    let did = "did:tenzro:human:provider";
    state.set_storage(
        &SYSTEM_ADDRESS,
        super::super::identity_wallet_index_key(payee.as_bytes()).as_bytes(),
        did.as_bytes().to_vec(),
    );
    let bond = serde_json::json!({
        "op": "Posted",
        "provider_address": hex::encode(payee.as_bytes()),
        "amount": (u128::MAX / 4).to_string(),
    });
    state.set_storage(
        &SYSTEM_ADDRESS,
        super::super::compute_bond_storage_key(did).as_bytes(),
        serde_json::to_vec(&bond).unwrap(),
    );
    state.set_storage(
        &SYSTEM_ADDRESS,
        governed_param_key(super::super::economy::TREASURY_LEG_INFERENCE_PARAM).as_bytes(),
        1_000u64.to_le_bytes().to_vec(),
    );
    let amount = 100 * ONE_USD_WEI;
    state.set_balance(payer.address().as_bytes(), 2 * amount);
    let treasury = super::super::derive_treasury_address();
    let before = state.get_balance(treasury.as_bytes());
    let fee =
        tenzro_types::split::fee_allocation(amount, &super::super::economy::fee_params(&state));
    let leg = tenzro_types::split::bps_of(amount - fee.fee, 1_000);
    assert!(leg > 0 && fee.burn > 0);

    let auth = payer.authorize("leg-1", &payee, amount, TNZO_ASSET, binding(0));
    let result = execute_payer_settle(
        &mut state,
        payer_settle(&payer, &payee, amount, "leg-1", &auth),
    )
    .await;
    assert!(result.success, "{:?}", result.revert_reason);
    assert_eq!(result.treasury_leg, Some(leg));
    assert_eq!(result.supply_change, -(fee.burn as i128));
    assert_eq!(
        state.get_balance(treasury.as_bytes()) - before,
        fee.treasury + leg
    );
    let pay_ref = tenzro_types::payment_authorization::pay_ref(CHAIN, &payee, &binding(0), "leg-1");
    let record = read_payment(&state, &pay_ref).expect("record");
    assert_eq!(record.fee, fee.fee + leg);
}

/// An agent's Terms — its spend cap and its revoked standing — are held even
/// when its own wallet pays through the generic `PayerSettle` a
/// self-sovereign key can sign, not only through the `AgentAct`/`OP_PAY`
/// path `an_agent_pays_from_its_wallet_only_within_its_terms` above covers.
/// Whatever registered the payer's address as this agent's identity — the
/// same reverse index `tenzro_identityRegister` writes for a human or
/// machine wallet — is what makes a generic settlement answerable to the
/// agent's terms at all; once it is, a loop of calls cannot walk past the
/// cap one call at a time, and the very next call after a revocation lands
/// is refused however small and however far under the cap it is. The same
/// `payment_id` resubmitted is refused and never charges twice.
#[tokio::test]
async fn a_generic_settlement_from_an_agents_registered_wallet_is_held_to_its_terms() {
    let mut state = StateAdapter::new();
    agent(&mut state, 1_000, Vec::new());
    let payer = Payer::enrolled(31, &mut state);
    state.set_balance(payer.address().as_bytes(), 10_000);
    state.set_storage(
        &SYSTEM_ADDRESS,
        super::super::identity_wallet_index_key(payer.address().as_bytes()).as_bytes(),
        AGENT.as_bytes().to_vec(),
    );
    let payee = Address::new([0x91; 32]);

    // Within the cap: settles, and the spend is recorded against the agent.
    let auth = payer.authorize("g-1", &payee, 600, TNZO_ASSET, binding(0));
    assert!(
        submit_payer_settle(&mut state, payer_settle(&payer, &payee, 600, "g-1", &auth)).await,
        "a within-cap settlement from a registered agent wallet was refused"
    );
    assert_eq!(state.get_balance(payer.address().as_bytes()), 10_000 - 600);

    // The same call again, same payment_id: refused, and not charged twice.
    assert!(
        !submit_payer_settle(&mut state, payer_settle(&payer, &payee, 600, "g-1", &auth)).await
    );
    assert_eq!(state.get_balance(payer.address().as_bytes()), 10_000 - 600);

    // A second, distinct call that would carry the day's total past the cap: refused.
    let auth2 = payer.authorize("g-2", &payee, 500, TNZO_ASSET, binding(0));
    assert!(
        !submit_payer_settle(&mut state, payer_settle(&payer, &payee, 500, "g-2", &auth2)).await,
        "a call past the agent's daily cap was not refused"
    );
    assert_eq!(
        state.get_balance(payer.address().as_bytes()),
        10_000 - 600,
        "the refused over-cap call moved funds anyway"
    );

    // A call that stays under the remaining budget still settles.
    let auth3 = payer.authorize("g-3", &payee, 400, TNZO_ASSET, binding(0));
    assert!(
        submit_payer_settle(&mut state, payer_settle(&payer, &payee, 400, "g-3", &auth3)).await
    );
    assert_eq!(
        state.get_balance(payer.address().as_bytes()),
        10_000 - 600 - 400
    );

    // Revoked: the very next call is refused, however small and under cap.
    impose_revocation(&mut state, 2_000);
    let auth4 = payer.authorize("g-4", &payee, 1, TNZO_ASSET, binding(0));
    assert!(
        !submit_payer_settle(&mut state, payer_settle(&payer, &payee, 1, "g-4", &auth4)).await,
        "a call after revocation was not refused"
    );
    assert_eq!(
        state.get_balance(payer.address().as_bytes()),
        10_000 - 600 - 400
    );
}

/// A payer with no registered identity pays exactly as before: the new
/// agent-terms gate on `PayerSettle` never fires for an ordinary wallet.
#[tokio::test]
async fn an_unregistered_payer_settles_without_any_agent_terms_check() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(32, &mut state);
    let payee = Address::new([0x92; 32]);
    state.set_balance(payer.address().as_bytes(), 10_000);
    let auth = payer.authorize("u-1", &payee, 9_999, TNZO_ASSET, binding(0));
    assert!(
        submit_payer_settle(
            &mut state,
            payer_settle(&payer, &payee, 9_999, "u-1", &auth)
        )
        .await
    );
}

#[test]
fn a_token_payment_settles_only_in_an_enabled_asset_on_its_peg() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(1, &mut state);
    let payee = Address::new([0x99; 32]);
    let (id, asset) = unlisted_token(&mut state, payer.address().as_bytes(), 1_000_000);
    state.set_balance(payee.as_bytes(), ONE_USD_WEI);
    let pay = |state: &mut StateAdapter, n: &str| {
        settle_native(
            state,
            CHAIN,
            7,
            &native(
                &payer.address(),
                &payee,
                &asset,
                400_000,
                binding(400_000),
                n,
            ),
            &mut Vec::new(),
        )
        .map(|_| ())
        .unwrap_err()
        .to_string()
    };

    let err = pay(&mut state, "p-unlisted");
    assert!(err.contains("not a permitted settlement asset"), "{err}");

    let mut entry = tenzro_types::settlement_asset::SettlementAsset::new(&asset, "USDX", "USD", 6);
    entry.enabled = false;
    crate::native::settlement_asset::install_for_test(&mut state, &entry);
    crate::native::economy::write_symbol_rate_for_tests(&mut state, "USDX", 0, 1_000_000_000);
    let err = pay(&mut state, "p-disabled");
    assert!(err.contains("disabled"), "{err}");

    entry.enabled = true;
    crate::native::settlement_asset::install_for_test(&mut state, &entry);
    // Validators price the token 2% under par; the band is 1%.
    crate::native::economy::write_symbol_rate_for_tests(&mut state, "USDX", 1, 980_000_000);
    let err = pay(&mut state, "p-off-peg");
    assert!(err.contains("off its USD peg"), "{err}");

    // Nothing moved and nothing was recorded by any refusal.
    assert_eq!(
        crate::token_ledger::balance(&state, &id, payer.address().as_bytes()),
        1_000_000
    );
    assert_eq!(state.get_balance(payee.as_bytes()), ONE_USD_WEI);
    assert!(read_payment_by_id(&state, "p-off-peg").is_none());
}

#[test]
fn a_tnzo_payment_needs_no_settlement_asset_entry() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(1, &mut state);
    let payee = Address::new([0x99; 32]);
    state.set_balance(payer.address().as_bytes(), ONE_USD_WEI);
    // An off-peg, disabled entry elsewhere does not touch TNZO.
    let mut other = tenzro_types::settlement_asset::SettlementAsset::new(
        &format!("0x{}", hex::encode([0x77; 32])),
        "USDX",
        "USD",
        6,
    );
    other.enabled = false;
    crate::native::settlement_asset::install_for_test(&mut state, &other);
    let out = settle_native(
        &mut state,
        CHAIN,
        7,
        &native(
            &payer.address(),
            &payee,
            TNZO_ASSET,
            ONE_USD_WEI / 2,
            binding(0),
            "p-tnzo",
        ),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        state.get_balance(payee.as_bytes()),
        ONE_USD_WEI / 2 - out.record.fee
    );
}

/// Pays one whole token per action until the daily limit refuses one,
/// moving the TNZO rate `move_bps` after the fiftieth payment; returns how
/// many payments passed.
fn unit_payments_until_refused(move_bps: i64) -> (usize, String) {
    let mut state = StateAdapter::new();
    let wallet = agent_wallet(AGENT);
    let (_, asset) = token(&mut state, &wallet, 1_000_000_000);
    let payee = Address::new([0x83; 32]);
    let key = agent(
        &mut state,
        100_000_000,
        vec![AssetLimit {
            min_counterparty_kyc_tier: 0,
            asset: asset.clone(),
            max_per_tx: None,
            max_per_day: "1000000000".into(),
        }],
    );
    for n in 0..200 {
        if n == 50 {
            let rate = (100_000_000i128 * (10_000 + i128::from(move_bps)) / 10_000) as u128;
            crate::native::economy::write_rate_for_tests(&mut state, 1, rate, rate);
        }
        let mut a = pay(&payee, 1_000_000, &format!("u-{n}"));
        a.asset = Some(asset.clone());
        a.usd_e6 = 1_000_000;
        if let Err(e) = act_as(&mut state, &key, a, 1_000 + n as i64) {
            return (n, e);
        }
    }
    (200, String::new())
}

#[test]
fn a_hundred_unit_daily_limit_refuses_the_hundred_and_first_unit_whatever_the_tnzo_rate_does() {
    for move_bps in [0, 500, -500] {
        let (passed, err) = unit_payments_until_refused(move_bps);
        assert_eq!(passed, 100, "rate moved {move_bps} bps: {err}");
        assert!(err.contains("daily limit"), "{err}");
    }
}

#[test]
fn a_tnzo_payment_counts_against_the_unit_limits_at_the_rate_in_force() {
    let mut state = StateAdapter::new();
    let payee = Address::new([0x84; 32]);
    // Two units a day; at the genesis 0.10 USD per TNZO one unit is 10 TNZO.
    let key = agent(&mut state, 2_000_000, Vec::new());
    crate::native::economy::write_rate_for_tests(&mut state, 0, 100_000_000, 100_000_000);
    state.set_balance(&agent_wallet(AGENT), 100 * ONE_USD_WEI);
    act_as(&mut state, &key, pay(&payee, ONE_USD_WEI, "n-1"), 1_000).unwrap();
    assert_eq!(
        super::super::agent_terms::read_agent_spent(&state, AGENT, 1_000),
        1_000_000
    );
    // TNZO doubles: the next 10 TNZO are worth two units and pass the cap.
    crate::native::economy::write_rate_for_tests(&mut state, 1, 200_000_000, 200_000_000);
    let err = act_as(&mut state, &key, pay(&payee, ONE_USD_WEI, "n-2"), 1_001).unwrap_err();
    assert!(err.contains("daily limit"), "{err}");
    act_as(&mut state, &key, pay(&payee, ONE_USD_WEI / 2, "n-3"), 1_002).unwrap();
}

#[test]
fn a_token_that_may_not_settle_is_refused_by_the_terms_check_by_name() {
    let mut state = StateAdapter::new();
    let wallet = agent_wallet(AGENT);
    let (_, asset) = token(&mut state, &wallet, 1_000_000_000);
    let payee = Address::new([0x85; 32]);
    let key = agent(
        &mut state,
        100_000_000,
        vec![AssetLimit {
            min_counterparty_kyc_tier: 0,
            asset: asset.clone(),
            max_per_tx: None,
            max_per_day: "1000000000".into(),
        }],
    );
    crate::native::economy::write_symbol_rate_for_tests(&mut state, "USDX", 1, 900_000_000);
    let mut a = pay(&payee, 1_000_000, "off-peg");
    a.asset = Some(asset);
    a.usd_e6 = 1_000_000;
    let err = act_as(&mut state, &key, a, 1_000).unwrap_err();
    assert!(err.contains("off its USD peg"), "{err}");
}

/// A second USD settlement asset, `supply` of it held by the treasury.
fn treasury_stable(
    state: &mut StateAdapter,
    symbol: &str,
    currency: &str,
    rate: u128,
    supply: u128,
) -> ([u8; 32], String) {
    let spec = crate::token_ledger::TokenRecord {
        name: symbol.into(),
        symbol: symbol.into(),
        decimals: 6,
        total_supply: supply,
        creator: Vec::new(),
        max_supply: None,
        powers: tenzro_types::token_policy::PowerManifest::NONE,
        policy: tenzro_types::token_policy::TokenPolicy::default(),
        council: None,
        reserve_backing: None,
        pending: None,
    };
    let id = crate::token_ledger::create(
        state,
        super::super::derive_treasury_address().as_bytes(),
        &spec,
        &mut Vec::new(),
    )
    .unwrap();
    let asset = format!("0x{}", hex::encode(id));
    permit(state, &asset, symbol, currency);
    crate::native::economy::write_symbol_rate_for_tests(state, symbol, 0, rate);
    (id, asset)
}

fn prefer(state: &mut StateAdapter, payee: &Address, assets: &[&str]) -> Result<Log> {
    apply_payment_op(
        state,
        CHAIN,
        7,
        payee.as_bytes(),
        &PaymentOp::SetPayoutAssets {
            assets: assets.iter().map(|a| a.to_string()).collect(),
        },
        &mut Vec::new(),
    )
}

#[test]
fn a_payee_is_paid_out_in_the_asset_it_lists_at_the_lower_of_par_and_the_rates_less_the_spread() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x71; 32]);
    let (x, usdx) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    // USDY sits 0.5% under par: par is the lower amount.
    let (y, usdy) = treasury_stable(&mut state, "USDY", "USD", 995_000_000, 50_000_000);
    prefer(&mut state, &payee, &[&usdy]).unwrap();
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        10_000_000,
        binding(0),
        "swap-1",
    );
    let out = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    // The credit waits in the payout escrow until the epoch closes.
    assert_eq!(
        crate::token_ledger::balance(&state, &y, payee.as_bytes()),
        0
    );
    close(&mut state, 0);
    let credit = 10_000_000 - out.record.fee;
    let spread = crate::native::payout_swap::DEFAULT_SPREAD_BPS as u128;
    let expected = credit - (credit * spread).div_ceil(10_000);
    let treasury = super::super::derive_treasury_address();
    assert_eq!(
        crate::token_ledger::balance(&state, &x, payee.as_bytes()),
        0
    );
    assert_eq!(
        crate::token_ledger::balance(&state, &y, payee.as_bytes()),
        expected
    );
    assert_eq!(
        crate::token_ledger::balance(&state, &y, treasury.as_bytes()),
        50_000_000 - expected
    );
    assert_eq!(out.record.settled.payout_asset, usdx);
    assert_eq!(out.record.settled.fee_asset, usdx);
}

/// Closes `epoch` for the payout swap fill.
fn close(state: &mut StateAdapter, epoch: u64) -> Vec<Log> {
    let mut logs = Vec::new();
    crate::native::payout_swap::fill_epoch(state, epoch, 8, &mut Vec::new(), &mut logs).unwrap();
    logs
}

#[test]
fn a_payout_swap_pays_from_the_asset_most_over_its_treasury_share() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x72; 32]);
    let (x, usdx) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    let (y, usdy) = treasury_stable(&mut state, "USDY", "USD", 1_000_000_000, 50_000_000);
    // The payee takes either. The treasury holds only USDY: far over its
    // 50% target, so the payout comes from USDY.
    prefer(&mut state, &payee, &[&usdx, &usdy]).unwrap();
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        1_000_000,
        binding(0),
        "re-1",
    );
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    close(&mut state, 0);
    assert!(crate::token_ledger::balance(&state, &y, payee.as_bytes()) > 0);
    assert_eq!(
        crate::token_ledger::balance(&state, &x, payee.as_bytes()),
        0
    );
    // With USDX now held well over target too, but USDY back under it, the
    // arrival asset is kept.
    let mut entry = tenzro_types::settlement_asset::SettlementAsset::new(&usdy, "USDY", "USD", 6);
    entry.max_treasury_share_bps = tenzro_types::settlement_asset::MAX_TREASURY_SHARE_BPS;
    crate::native::settlement_asset::install_for_test(&mut state, &entry);
    let treasury = super::super::derive_treasury_address();
    let usdy_held = crate::token_ledger::balance(&state, &y, treasury.as_bytes());
    move_asset(
        &mut state,
        &x,
        payer.address().as_bytes(),
        treasury.as_bytes(),
        usdy_held + 10_000_000,
        0,
        &mut Vec::new(),
    )
    .unwrap();
    let before_y = crate::token_ledger::balance(&state, &y, payee.as_bytes());
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        1_000_000,
        binding(0),
        "re-2",
    );
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    assert_eq!(
        crate::token_ledger::balance(&state, &y, payee.as_bytes()),
        before_y
    );
    assert!(crate::token_ledger::balance(&state, &x, payee.as_bytes()) > 0);
}

#[test]
fn a_payout_the_treasury_cannot_make_is_refused_with_its_reason_unless_the_arrival_is_accepted() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x73; 32]);
    let (_, usdx) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    // The treasury holds too little USDY.
    let (_, usdy) = treasury_stable(&mut state, "USDY", "USD", 1_000_000_000, 10);
    prefer(&mut state, &payee, &[&usdy]).unwrap();
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        1_000_000,
        binding(0),
        "no-1",
    );
    let err = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new())
        .map(|_| ())
        .unwrap_err();
    assert!(
        err.to_string().contains("the treasury holds 10 of USDY"),
        "{err}"
    );
    // Off its peg: refused by name.
    crate::native::economy::write_symbol_rate_for_tests(&mut state, "USDY", 1, 900_000_000);
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        1_000_000,
        binding(0),
        "no-2",
    );
    let err = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new())
        .map(|_| ())
        .unwrap_err();
    assert!(err.to_string().contains("off its USD peg"), "{err}");
    // Accepting the arrival asset too, the payment settles in it.
    prefer(&mut state, &payee, &[&usdy, &usdx]).unwrap();
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        1_000_000,
        binding(0),
        "no-3",
    );
    let out = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    assert_eq!(out.record.settled.payout_asset, usdx);
}

/// Two payees ask for swaps worth $1 and $3 against a $2 cap, in either
/// order: each is filled half, the rest carried, and the order changes
/// nothing.
fn swaps_in_order(first_small: bool) -> Vec<u128> {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let small = Address::new([0x74; 32]);
    let large = Address::new([0x77; 32]);
    let (x, usdx) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    let (y, usdy) = treasury_stable(&mut state, "USDY", "USD", 1_000_000_000, 90_000_000);
    crate::native::set_governed_param_for_test(
        &mut state,
        crate::native::payout_swap::EPOCH_CAP_PARAM,
        2,
    );
    prefer(&mut state, &small, &[&usdy]).unwrap();
    prefer(&mut state, &large, &[&usdy]).unwrap();
    let mut order = vec![(small, 1_001_002u128, "s"), (large, 3_003_006, "l")];
    if !first_small {
        order.reverse();
    }
    for (payee, amount, id) in order {
        let p = native(&payer.address(), &payee, &usdx, amount, binding(0), id);
        settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    }
    let book = crate::native::payout_swap::read_book(&state);
    assert_eq!(book.len(), 2);
    let asked: Vec<u128> = [small, large]
        .iter()
        .map(|a| {
            book.iter()
                .find(|r| r.payee == hex::encode(a.as_bytes()))
                .unwrap()
                .credit
        })
        .collect();
    let logs = close(&mut state, 0);
    assert_eq!(
        logs[0].topics[0],
        crate::native::payout_swap::PAYOUT_SWAPS_FILLED_TOPIC.to_vec()
    );
    // Half of each request is filled, the rest carried.
    let carried = crate::native::payout_swap::read_book(&state);
    assert_eq!(carried.len(), 2);
    for (a, want) in [small, large].iter().zip(&asked) {
        let left = carried
            .iter()
            .find(|r| r.payee == hex::encode(a.as_bytes()))
            .unwrap()
            .credit;
        assert!(left.abs_diff(want / 2) <= 3, "{left} of {want}");
    }
    let (epoch, value) = crate::native::payout_swap::read_last_fill(&state).unwrap();
    assert_eq!(epoch, 0);
    assert!(value <= 2_000_000 && value + 2 >= 2_000_000, "{value}");
    let out: Vec<u128> = [small, large]
        .iter()
        .flat_map(|a| {
            [
                crate::token_ledger::balance(&state, &y, a.as_bytes()),
                crate::token_ledger::balance(&state, &x, a.as_bytes()),
            ]
        })
        .collect();
    // Past the carry window the remainder is paid in the arrival asset.
    crate::native::set_governed_param_for_test(
        &mut state,
        crate::native::payout_swap::CARRY_PARAM,
        1,
    );
    crate::native::set_governed_param_for_test(
        &mut state,
        crate::native::payout_swap::EPOCH_CAP_PARAM,
        0,
    );
    close(&mut state, 1);
    assert!(crate::native::payout_swap::read_book(&state).is_empty());
    for (a, want) in [small, large].iter().zip(&asked) {
        let x_held = crate::token_ledger::balance(&state, &x, a.as_bytes());
        assert!(x_held.abs_diff(want / 2) <= 3, "{x_held} of {want}");
    }
    let escrow = crate::native::payout_swap::escrow_address();
    assert_eq!(
        crate::token_ledger::balance(&state, &x, escrow.as_bytes()),
        0
    );
    out
}

#[test]
fn payout_swaps_over_the_epoch_cap_fill_pro_rata_at_close_whatever_the_order() {
    let a = swaps_in_order(true);
    let b = swaps_in_order(false);
    assert_eq!(a, b, "the order of requests changed what each payee got");
    assert!(a[0] > 0 && a[2] > 0);
    // The large request got three times the small one.
    assert!(a[2].abs_diff(3 * a[0]) <= a[0] / 1_000, "{a:?}");
}

/// The reward caps are settled at the epoch's close from the work recorded
/// through it: the order work arrived in changes no coupon.
#[test]
fn reward_caps_fill_pro_rata_whatever_order_the_work_arrived_in() {
    use tenzro_token::rewards::{
        MINT_MULT_ONE_PPM, MintPolicy, MintingSchedule, WorkClass, WorkRecord, settle_epoch,
    };
    let schedule = MintingSchedule::for_epoch_ms(86_400_000).unwrap();
    let policy = MintPolicy {
        base_tnzo_per_year: 60_000_000,
        decay_bps_per_year: 1_500,
        floor_tnzo_per_year: 10_000_000,
        mult_ppm: MINT_MULT_ONE_PPM,
        validator_bps: 4_500,
        provider_bps: 4_000,
        ecosystem_bps: 1_500,
        revenue_peg_bps: 5_000,
        validator_base_rights: 0,
        withheld_rights: 0,
    };
    let mut work: Vec<WorkRecord> = (1..=40u8)
        .map(|i| WorkRecord {
            address: Address::new([i; 32]),
            class: if i % 2 == 0 {
                WorkClass::InferenceServed
            } else {
                WorkClass::ConsensusVote
            },
            weight: u128::from(i) * 1_000_003,
        })
        .collect();
    let settle = |w: &[WorkRecord]| {
        let (summary, mut coupons) = settle_epoch(
            &schedule,
            &policy,
            0,
            3,
            w,
            tenzro_types::primitives::Timestamp::new(0),
        );
        coupons.sort_by_key(|c| (format!("{:?}", c.bucket), c.address.0));
        (
            serde_json::to_value(summary).unwrap(),
            serde_json::to_value(coupons).unwrap(),
        )
    };
    let forward = settle(&work);
    work.reverse();
    assert_eq!(settle(&work), forward);
    work.rotate_left(17);
    assert_eq!(settle(&work), forward);
}

#[test]
fn a_suspended_asset_is_never_swapped_out_of_the_treasury_and_the_payee_keeps_the_arrival() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x76; 32]);
    let (x, usdx) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    // The treasury holds only USDY: far over its target, so a payout would
    // come from it.
    let (y, usdy) = treasury_stable(&mut state, "USDY", "USD", 1_000_000_000, 50_000_000);
    prefer(&mut state, &payee, &[&usdy, &usdx]).unwrap();
    let rules = crate::native::settlement_asset::BreakerRules::read(&state);
    for e in 1..=rules.suspend_epochs {
        crate::native::settlement_asset::observe_rate(
            &mut state,
            "USDY",
            e,
            900_000_000,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
    }
    // Back at par, still suspended: nothing leaves the treasury in USDY.
    crate::native::economy::write_symbol_rate_for_tests(&mut state, "USDY", 9, 1_000_000_000);
    let treasury = super::super::derive_treasury_address();
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        1_000_000,
        binding(0),
        "susp-1",
    );
    let out = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    assert_eq!(out.record.settled.payout_asset, usdx);
    assert_eq!(
        crate::token_ledger::balance(&state, &y, treasury.as_bytes()),
        50_000_000
    );
    assert_eq!(
        crate::token_ledger::balance(&state, &y, payee.as_bytes()),
        0
    );
    assert!(crate::token_ledger::balance(&state, &x, payee.as_bytes()) > 0);
    // A payment in the suspended asset itself is refused by name.
    prefer(&mut state, &payee, &[]).unwrap();
    let p = native(
        &payer.address(),
        &payee,
        &usdy,
        1_000_000,
        binding(0),
        "susp-2",
    );
    let err = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new())
        .map(|_| ())
        .unwrap_err();
    assert!(
        err.to_string().contains("suspended by its peg breaker"),
        "{err}"
    );
}

#[test]
fn a_payout_swap_that_would_pass_the_arrival_assets_exposure_ceiling_does_not_run() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x78; 32]);
    let (_, usdx) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    let (_, usdy) = treasury_stable(&mut state, "USDY", "USD", 1_000_000_000, 50_000_000);
    let mut entry = tenzro_types::settlement_asset::SettlementAsset::new(&usdx, "USDX", "USD", 6);
    entry.max_treasury_share_bps = 1_000;
    entry.max_exposure_bps = 1_001;
    crate::native::settlement_asset::install_for_test(&mut state, &entry);
    prefer(&mut state, &payee, &[&usdy]).unwrap();
    // 10 USDX against 50 USDY would make USDX a sixth of the treasury.
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        10_000_000,
        binding(0),
        "exp-1",
    );
    let err = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new())
        .map(|_| ())
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("over its exposure ceiling of 1001 bps"),
        "{err}"
    );
    // Small enough to stay under it, the swap runs.
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        1_000_000,
        binding(0),
        "exp-2",
    );
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
}

#[test]
fn a_payout_list_names_settlement_assets_only() {
    let mut state = StateAdapter::new();
    let payee = Address::new([0x75; 32]);
    let (_, usdx) = token(&mut state, &[1; 32], 1);
    let unknown = format!("0x{}", hex::encode([0x66; 32]));
    assert!(prefer(&mut state, &payee, &[&unknown]).is_err());
    assert!(prefer(&mut state, &payee, &[&usdx, &usdx]).is_err());
    let nine: Vec<&str> = std::iter::repeat_n(usdx.as_str(), 9).collect();
    assert!(prefer(&mut state, &payee, &nine).is_err());
    prefer(&mut state, &payee, &[&usdx]).unwrap();
    assert_eq!(
        crate::native::payout_swap::read_payout_assets(&state, payee.as_bytes()).len(),
        1
    );
    prefer(&mut state, &payee, &[]).unwrap();
    assert!(crate::native::payout_swap::read_payout_assets(&state, payee.as_bytes()).is_empty());
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]
    /// The treasury never pays out more value than it receives at the rates
    /// in force, whatever the two rates, decimals, currencies and spread.
    #[test]
    fn a_payout_swap_never_pays_out_more_value_than_it_takes_in(
        amount in 1u128..1_000_000_000_000_000u128,
        from_rate in 990_000_000u128..=1_010_000_000,
        to_rate in 990_000_000u128..=1_300_000_000,
        from_dec in 0u8..=18,
        to_dec in 0u8..=18,
        same_leg in proptest::bool::ANY,
        spread in 0u64..=100,
    ) {
        let mut state = StateAdapter::new();
        crate::native::set_governed_param_for_test(&mut state, crate::native::payout_swap::SPREAD_PARAM, spread);
        let entry = |sym: &str, cur: &str, dec: u8| tenzro_types::settlement_asset::SettlementAsset {
            decimals: dec,
            ..tenzro_types::settlement_asset::SettlementAsset::new(&format!("0x{}", "11".repeat(32)), sym, cur, dec)
        };
        let from = crate::native::settlement_asset::Permitted { asset: entry("AAA", "USD", from_dec), rate_nano_usd: from_rate, rate_epoch: None };
        let to = crate::native::settlement_asset::Permitted {
            asset: entry("BBB", if same_leg { "USD" } else { "EUR" }, to_dec),
            rate_nano_usd: to_rate,
            rate_epoch: None,
        };
        let out = crate::native::payout_swap::quote_out(&state, &from, &to, amount);
        // Value in and out, nano-USD scaled by both decimals.
        let value_in = revm::primitives::U256::from(amount) * revm::primitives::U256::from(from_rate) * revm::primitives::U256::from(10u8).pow(revm::primitives::U256::from(to_dec));
        let value_out = revm::primitives::U256::from(out) * revm::primitives::U256::from(to_rate) * revm::primitives::U256::from(10u8).pow(revm::primitives::U256::from(from_dec));
        proptest::prop_assert!(value_out <= value_in);
    }
}

/// A payment relayed by `relayer`, which fronted `gas` wei of gas.
fn relayed<'a>(base: NativePayment<'a>, relayer: &'a [u8], gas: u128) -> NativePayment<'a> {
    NativePayment {
        relayer: Some(Relayer {
            account: relayer,
            gas_wei: gas,
        }),
        ..base
    }
}

#[test]
fn a_relayer_is_reimbursed_in_kind_at_most_the_gas_it_fronted_and_the_treasury_share() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let payee = Address::new([0x76; 32]);
    let relayer = [0x77u8; 32];
    let (x, usdx) = token(&mut state, payer.address().as_bytes(), 1_000_000_000);
    let treasury = super::super::derive_treasury_address();

    // Small gas: the gas value binds. 1e15 wei at 0.10 USD per TNZO is
    // 100 micro-units: 100 smallest units at par.
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        100_000_000,
        binding(0),
        "r-1",
    );
    let out = settle_native(
        &mut state,
        CHAIN,
        7,
        &relayed(p, &relayer, 1_000_000_000_000_000),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(out.reimbursed, 100);
    assert_eq!(crate::token_ledger::balance(&state, &x, &relayer), 100);

    // Large gas: the treasury share binds, at the governed bps of it.
    crate::native::set_governed_param_for_test(&mut state, super::RELAY_REIMBURSE_PARAM, 5_000);
    let before = crate::token_ledger::balance(&state, &x, treasury.as_bytes());
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        100_000_000,
        binding(0),
        "r-2",
    );
    let out = settle_native(
        &mut state,
        CHAIN,
        7,
        &relayed(p, &relayer, u128::MAX / 4),
        &mut Vec::new(),
    )
    .unwrap();
    let fee = tenzro_types::split::fee_allocation(
        100_000_000,
        &FeeParams {
            min_fee: 1,
            ..crate::native::economy::fee_params(&state)
        },
    );
    assert_eq!(out.reimbursed, fee.treasury / 2);
    assert_eq!(
        crate::token_ledger::balance(&state, &x, treasury.as_bytes()) - before,
        fee.treasury + fee.burn - fee.treasury / 2
    );

    // The payer relaying its own payment, or a TNZO payment, is not
    // reimbursed.
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        100_000_000,
        binding(0),
        "r-3",
    );
    let out = settle_native(
        &mut state,
        CHAIN,
        7,
        &relayed(p, payer.address().as_bytes(), 1_000_000_000_000_000),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(out.reimbursed, 0);
    state.set_balance(payer.address().as_bytes(), 10 * ONE_USD_WEI);
    let p = native(
        &payer.address(),
        &payee,
        TNZO_ASSET,
        ONE_USD_WEI,
        binding(0),
        "r-4",
    );
    let out = settle_native(
        &mut state,
        CHAIN,
        7,
        &relayed(p, &relayer, 1_000_000_000_000_000),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(out.reimbursed, 0);
}

fn resold(
    reseller: [u8; 32],
    commission_bps: u32,
) -> tenzro_types::payment_authorization::ResellerLeg {
    tenzro_types::payment_authorization::ResellerLeg {
        reseller: Address::new(reseller),
        commission_bps,
    }
}

fn leg_fee(state: &StateAdapter, amount: u128) -> u128 {
    tenzro_types::split::fee_allocation(
        amount,
        &FeeParams {
            min_fee: 1,
            ..crate::native::economy::fee_params(state)
        },
    )
    .fee
}

#[test]
fn a_reseller_quote_pays_the_operator_its_full_price_and_the_reseller_only_its_commission() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let operator = Address::new([0x61; 32]);
    let reseller = [0x62u8; 32];
    let (id, asset) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    // 10 USDX operator price, a 10% commission on top: 11 USDX signed.
    let price = 10_000_000u128;
    let amount = super::amount_with_leg(price, 1_000).unwrap();
    assert_eq!(amount, 11_000_000);
    let mut p = native(
        &payer.address(),
        &operator,
        &asset,
        amount,
        binding(0),
        "rs-1",
    );
    let legs = [resold(reseller, 1_000)];
    p.resellers = &legs;
    let out = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    let bal = |a: &[u8]| crate::token_ledger::balance(&state, &id, a);
    assert_eq!(bal(operator.as_bytes()), price - leg_fee(&state, price));
    assert_eq!(bal(&reseller), 1_000_000 - leg_fee(&state, 1_000_000));
    // The receipt shows each leg, with the operator price and the commission.
    let legs = &out.record.settled.legs;
    assert_eq!(legs.len(), 2, "{legs:?}");
    assert_eq!((legs[0].role.as_str(), legs[0].amount), ("operator", price));
    assert_eq!(legs[0].account, hex::encode(operator.as_bytes()));
    assert_eq!(
        (legs[1].role.as_str(), legs[1].amount),
        ("reseller", 1_000_000)
    );
    assert_eq!(legs[1].account, hex::encode(reseller));
    assert_eq!(legs[1].commission_bps, Some(1_000));
    assert_eq!(out.record.fee, legs.iter().map(|l| l.fee).sum::<u128>());
    // The reseller earns no reward weight from its leg.
    assert!(
        crate::native::rewards::pending_work(&state, 0)
            .iter()
            .all(|w| *w.address.as_bytes() != reseller),
        "a reseller leg earns no weight"
    );
}

#[test]
fn every_payment_record_lists_its_legs() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let operator = Address::new([0x63; 32]);
    let (_, asset) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    let p = native(
        &payer.address(),
        &operator,
        &asset,
        1_000_000,
        binding(0),
        "direct",
    );
    let out = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    let legs = &out.record.settled.legs;
    assert_eq!(legs.len(), 1);
    assert_eq!(
        (legs[0].role.as_str(), legs[0].amount),
        ("operator", 1_000_000)
    );
}

#[test]
fn two_resellers_settle_on_equal_terms() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let operator = Address::new([0x64; 32]);
    let (a, b_) = ([0x65u8; 32], [0x66u8; 32]);
    let (id, asset) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    let price = 10_000_000u128;
    let amount = super::amount_with_leg(price, 1_000).unwrap();
    let mut p = native(
        &payer.address(),
        &operator,
        &asset,
        amount,
        binding(0),
        "rs-2",
    );
    let legs = [resold(a, 500), resold(b_, 500)];
    p.resellers = &legs;
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    let bal = |x: &[u8]| crate::token_ledger::balance(&state, &id, x);
    assert_eq!(bal(&a), bal(&b_));
    assert_eq!(bal(&a), 500_000 - leg_fee(&state, 500_000));
    assert_eq!(bal(operator.as_bytes()), price - leg_fee(&state, price));
}

#[test]
fn reseller_legs_stop_at_the_governed_number_per_call() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let operator = Address::new([0x67; 32]);
    let (_, asset) = token(&mut state, payer.address().as_bytes(), 100_000_000);
    crate::native::set_governed_param_for_test(&mut state, super::MAX_RESELLER_LEGS_PARAM, 1);
    let mut p = native(
        &payer.address(),
        &operator,
        &asset,
        11_000_000,
        binding(0),
        "rs-3",
    );
    let legs = [resold([0x68; 32], 500), resold([0x69; 32], 500)];
    p.resellers = &legs;
    let err = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new())
        .map(|_| ())
        .unwrap_err();
    assert!(err.to_string().contains("reseller legs"), "{err}");
}

#[test]
fn a_commission_above_the_buyers_cap_is_refused() {
    let mut state = StateAdapter::new();
    let key = agent(&mut state, u128::MAX / 4, Vec::new());
    let _ = key;
    let mut stored = super::super::agent_terms::read_agent_terms(&state, AGENT).unwrap();
    stored.terms.delegation_scope.max_commission_bps = Some(500);
    super::super::agent_terms::store_terms_unapproved(&mut state, AGENT, &stored);
    let wallet = Address::new(agent_wallet(AGENT));
    let operator = Address::new([0x6a; 32]);
    let (_, asset) = token(&mut state, wallet.as_bytes(), 100_000_000);
    let mut p = native(&wallet, &operator, &asset, 11_000_000, binding(0), "cap-1");
    p.agent_did = Some(AGENT);
    let over = [resold([0x6b; 32], 1_000)];
    p.resellers = &over;
    let err = settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new())
        .map(|_| ())
        .unwrap_err();
    assert!(err.to_string().contains("commission"), "{err}");
    let within = [resold([0x6b; 32], 500)];
    p.resellers = &within;
    p.nonce = "cap-2";
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
}

#[test]
fn a_commission_changed_after_the_payer_signed_is_refused() {
    let mut state = StateAdapter::new();
    let payer = Payer::enrolled(2, &mut state);
    let operator = Address::new([0x6c; 32]);
    let asset = format!("0x{}", hex::encode([0x5c; 32]));
    let mut auth = payer.authorize_resold(
        "ch-1",
        &operator,
        11_000,
        &asset,
        binding(0),
        vec![resold([0x6d; 32], 1_000)],
    );
    let check = |auth: &PaymentAuthorization| {
        verify_payment_authorization(
            &state,
            CHAIN,
            "ch-1",
            &payer.address(),
            &operator,
            11_000,
            auth,
            0,
        )
    };
    check(&auth).unwrap();
    auth.resellers[0].commission_bps = 2_000;
    assert!(check(&auth).is_err(), "a raised commission");
    auth.resellers[0].commission_bps = 1_000;
    auth.resellers[0].reseller = Address::new([0x6e; 32]);
    assert!(check(&auth).is_err(), "a redirected commission");
    auth.resellers.clear();
    assert!(check(&auth).is_err(), "a dropped commission");
}

/// `key`'s P-256 signature over the action, then `pq`'s ML-DSA-65 signature.
fn act_as_pq(
    state: &mut StateAdapter,
    key: &SigningKey,
    pq: &tenzro_crypto::pq::MlDsaSigningKey,
    mut action: AgentAction,
    at: i64,
) -> std::result::Result<(), String> {
    action.nonce = super::super::agent_terms::read_agent_act_nonce(state, AGENT);
    let digest = action.digest();
    let p256: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
    let mut sig = p256.to_bytes().to_vec();
    sig.extend_from_slice(&pq.sign(
        tenzro_types::account_signature::AGENT_NODE_PQ_CONTEXT,
        &digest,
    ));
    super::super::agent_terms::act(state, CHAIN, &action, &sig, at)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// An agent whose controller required the ML-DSA leg: its serving node's
/// actions and vouchers pay only with the node's ML-DSA-65 signature beside
/// the P-256 one, by the key on chain for that node, so a break of the
/// node's P-256 key moves nothing from the agent's wallet.
#[test]
fn an_agent_that_requires_the_ml_dsa_leg_pays_only_with_its_nodes_ml_dsa_signature() {
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::account_signature::AGENT_NODE_PQ_CONTEXT;
    let mut state = StateAdapter::new();
    let key = agent(&mut state, 10_000, Vec::new());
    state.set_balance(&agent_wallet(AGENT), 10_000);
    let payee = Address::new([0x86; 32]);
    // Not required yet: P-256 alone pays, and opens a channel.
    act_as(&mut state, &key, pay(&payee, 10, "pq-1"), 1_000).unwrap();
    let escrow_id = open_channel(&mut state, &key, &payee, 1_000, None);

    let node_pq = MlDsaSigningKey::generate();
    super::super::agent_terms::require_agent_node_pq_keys(
        &mut state,
        AGENT,
        &[(MACHINE.to_string(), node_pq.verifying_key_bytes().to_vec())],
        &mut Vec::new(),
    );
    assert!(crate::account_keys::pq_required(
        &state,
        &agent_wallet(AGENT)
    ));

    // P-256 alone, or with an ML-DSA-65 signature by another key: refused.
    assert!(act_as(&mut state, &key, pay(&payee, 10, "pq-2"), 1_100).is_err());
    assert!(
        act_as_pq(
            &mut state,
            &key,
            &MlDsaSigningKey::generate(),
            pay(&payee, 10, "pq-3"),
            1_200
        )
        .is_err()
    );
    act_as_pq(&mut state, &key, &node_pq, pay(&payee, 10, "pq-4"), 1_300).unwrap();

    let plain = agent_voucher(&key, MACHINE, escrow_id, 300, 1_500);
    assert!(check_whole(CHAIN, 2_000, &plain, &state).is_err());
    let digest = agent_voucher_digest(
        CHAIN,
        &escrow_id,
        300,
        &[0u8; 32],
        plain.agent.as_ref().unwrap(),
    );
    let mut forged = plain.clone();
    forged.signature.pq = Some(MlDsaSigningKey::generate().sign(AGENT_NODE_PQ_CONTEXT, &digest));
    assert!(check_whole(CHAIN, 2_000, &forged, &state).is_err());
    let mut hybrid = plain;
    hybrid.signature.pq = Some(node_pq.sign(AGENT_NODE_PQ_CONTEXT, &digest));
    assert_eq!(
        check_whole(CHAIN, 2_000, &hybrid, &state).unwrap().payout,
        300
    );
}

/// The controller requires the ML-DSA leg for its agent with both legs, from
/// the wallet its identity is registered with, naming every serving node of
/// the terms with its proof of possession; anyone else, a missing node or a
/// bad proof is refused.
#[test]
fn only_the_controller_requires_its_agents_ml_dsa_leg_naming_every_serving_node() {
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::account_signature::{
        AGENT_NODE_PQ_POSSESSION_CONTEXT, AccountKeysOp, AgentNodePqKey,
        agent_node_pq_possession_message,
    };
    let mut state = StateAdapter::new();
    let _ = agent(&mut state, 10_000, Vec::new());
    let controller = Payer::enrolled(21, &mut state);
    let stranger = Payer::enrolled(22, &mut state);
    state.set_storage(
        &SYSTEM_ADDRESS,
        format!(
            "identity_wallet:{}",
            hex::encode(controller.address().as_bytes())
        )
        .as_bytes(),
        b"did:tenzro:human:controller".to_vec(),
    );
    let node_pq = MlDsaSigningKey::generate();
    let key = node_pq.verifying_key_bytes().to_vec();
    let node = |possession: Vec<u8>| AgentNodePqKey {
        machine_did: MACHINE.into(),
        ml_dsa_public_key: key.clone(),
        possession,
    };
    let proof = node_pq.sign(
        AGENT_NODE_PQ_POSSESSION_CONTEXT,
        &agent_node_pq_possession_message(AGENT, MACHINE, &key),
    );
    let tx = |payer: &Payer, op: &AccountKeysOp| {
        let mut data = crate::account_keys::SELECTOR_ACCOUNT_KEYS.to_vec();
        data.extend_from_slice(&serde_json::to_vec(op).unwrap());
        let digest = [0x5a; 32];
        let mut tx = VmTransaction::new(
            payer.address().as_bytes().to_vec(),
            Some(SYSTEM_ADDRESS.to_vec()),
            0,
            data,
            200_000,
            1,
            0,
            crate::VmType::Tenzro,
            CHAIN,
        );
        tx.signature = Some(
            payer
                .key
                .sign(SignatureContext::Transaction, &digest)
                .unwrap(),
        );
        tx.public_key = Some(payer.key.public_key().p256.clone());
        tx.signing_digest = Some(digest.to_vec());
        tx
    };
    let op = |nodes: Vec<AgentNodePqKey>| AccountKeysOp::RequireAgentPqLeg {
        agent_did: AGENT.into(),
        nodes,
    };
    let apply = |state: &mut StateAdapter, payer: &Payer, op: &AccountKeysOp| {
        crate::account_keys::apply(state, &tx(payer, op), op).map(|_| ())
    };

    assert!(apply(&mut state, &stranger, &op(vec![node(proof.clone())])).is_err());
    let bad = node_pq.sign(AGENT_NODE_PQ_POSSESSION_CONTEXT, b"something else");
    assert!(apply(&mut state, &controller, &op(vec![node(bad)])).is_err());
    let mut other = node(proof.clone());
    other.machine_did = OTHER_MACHINE.into();
    assert!(apply(&mut state, &controller, &op(vec![other])).is_err());
    assert!(!crate::account_keys::pq_required(
        &state,
        &agent_wallet(AGENT)
    ));

    apply(&mut state, &controller, &op(vec![node(proof)])).unwrap();
    assert!(crate::account_keys::pq_required(
        &state,
        &agent_wallet(AGENT)
    ));
}

/// Reward schedule of one-day epochs and a 1 USD monthly validator cost, so
/// a small stable payment's fee covers it.
fn cover_world(state: &mut StateAdapter) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        crate::native::rewards::REWARD_SCHEDULE_KEY.as_bytes(),
        crate::native::rewards::genesis_reward_schedule(86_400_000).unwrap(),
    );
    super::super::set_governed_param_for_test(
        state,
        crate::native::rewards::VALIDATOR_BASE_COST_PARAM,
        1,
    );
}

/// Closes reward epoch 0 with `validator` its only consensus worker.
fn close_epoch_zero(state: &mut StateAdapter, validator: &Address) {
    crate::native::rewards::begin_block(state, 0, validator, 1_000).unwrap();
    crate::native::rewards::begin_block(state, 1, validator, 86_401_000).unwrap();
}

/// The stable fee a paid settlement leaves the treasury pays the validators'
/// running cost in that asset when the epoch closes, before any base reward:
/// the base the burn would pay is then zero.
#[test]
fn validators_running_cost_is_paid_from_stable_fees_before_any_base_reward() {
    let mut state = StateAdapter::new();
    cover_world(&mut state);
    let payer = Payer::enrolled(3, &mut state);
    let payee = Address::new([0x91; 32]);
    let validator = Address::new([0x92; 32]);
    let (x, usdx) = token(&mut state, payer.address().as_bytes(), 1_000_000_000);
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        100_000_000,
        binding(0),
        "cover-1",
    );
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    close_epoch_zero(&mut state, &validator);
    let cover = crate::native::validator_cover::read_cover(&state, 0);
    let each = crate::native::validator_cover::cost_each_e6(&state, 365);
    assert!(each > 0);
    assert_eq!(cover.validators, 1);
    assert_eq!(cover.need_e6, each);
    assert_eq!(cover.paid_e6, each, "{cover:?}");
    assert_eq!(
        crate::token_ledger::balance(&state, &x, validator.as_bytes()),
        each,
        "paid in the asset the fee was paid in, at par"
    );
    assert_eq!(
        crate::native::rewards::validator_base_rights(&state, 0, 1, 365),
        0,
        "nothing left for the base to pay"
    );
}

/// Stable assets the treasury holds that no paid fee brought in never pay a
/// validator: with no settlement, the reserve stays empty and the cover pays
/// nothing, whatever the treasury holds.
#[test]
fn the_cover_is_filled_only_by_stable_fees_from_paid_usage() {
    let mut state = StateAdapter::new();
    cover_world(&mut state);
    let validator = Address::new([0x93; 32]);
    let (y, _) = treasury_stable(&mut state, "USDY", "USD", 1_000_000_000, 50_000_000_000);
    close_epoch_zero(&mut state, &validator);
    let cover = crate::native::validator_cover::read_cover(&state, 0);
    assert_eq!(cover.paid_e6, 0);
    assert_eq!(cover.filled_e6, 0);
    assert_eq!(
        crate::token_ledger::balance(&state, &y, validator.as_bytes()),
        0
    );
    assert_eq!(
        crate::token_ledger::balance(
            &state,
            &y,
            super::super::derive_treasury_address().as_bytes()
        ),
        50_000_000_000
    );
}

/// A fee booked in an asset its peg breaker then suspended stays with the
/// treasury and pays nobody: the shortfall is recorded, and no other asset
/// or issuance stands in for it.
#[test]
fn a_suspended_asset_pays_no_validator_and_nothing_stands_in_for_it() {
    let mut state = StateAdapter::new();
    cover_world(&mut state);
    let payer = Payer::enrolled(4, &mut state);
    let payee = Address::new([0x94; 32]);
    let validator = Address::new([0x95; 32]);
    let (x, usdx) = token(&mut state, payer.address().as_bytes(), 1_000_000_000);
    let (y, _) = treasury_stable(&mut state, "USDY", "USD", 1_000_000_000, 50_000_000_000);
    let p = native(
        &payer.address(),
        &payee,
        &usdx,
        100_000_000,
        binding(0),
        "cover-2",
    );
    settle_native(&mut state, CHAIN, 7, &p, &mut Vec::new()).unwrap();
    let rules = crate::native::settlement_asset::BreakerRules::read(&state);
    for e in 1..=rules.suspend_epochs {
        crate::native::settlement_asset::observe_rate(
            &mut state,
            "USDX",
            e,
            900_000_000,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
    }
    close_epoch_zero(&mut state, &validator);
    let cover = crate::native::validator_cover::read_cover(&state, 0);
    assert_eq!(cover.paid_e6, 0, "{cover:?}");
    assert!(cover.need_e6 > 0);
    assert_eq!(
        crate::token_ledger::balance(&state, &x, validator.as_bytes()),
        0
    );
    assert_eq!(
        crate::token_ledger::balance(&state, &y, validator.as_bytes()),
        0
    );
}
