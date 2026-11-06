# The TNZO/USD fee rate: where it comes from and how it fails

Fees are governed USD prices paid in TNZO. This note is for operators and
validators: where the USD-to-TNZO conversion happens, what sets the rate, what
happens when reports are missing, late or manipulated, and what to watch.

## One conversion, one rate

Every USD-denominated fee converts to TNZO in one function,
`usd_to_wei` in `crates/tenzro-vm/src/native/economy.rs`, at the rate
`read_fee_rate` returns from consensus state. Nothing outside chain state is
read at execution time.

| Where | What converts |
|---|---|
| `tenzro-vm` `ledger.rs` (`block_base_fee`, resource base fees) | the per-gas base fee and each lane's resource base fee, governed in atto-USD |
| `tenzro-vm` `native/economy.rs` (`posted_fee`, `fee_params`) | identity registration, verification and inference settlement prices; the least settlement fee |
| `tenzro-vm` `native/economy.rs` (`amount_in_tnzo`) | amounts named in another asset, through that asset's validator rate and the TNZO rate |
| `tenzro-vm` `native/payment_settlement.rs`, `native/rewards.rs` | USD-denominated settlement and reward amounts |
| `tenzro-node` `inference_pricing.rs` (`tnzo_usd_nano`) | provider price cards in `nano_usd`; the card converts with its own arithmetic but at the `read_fee_rate` rate, so it holds with every other fee |
| `tenzro-node` `fee_market_rpc.rs`, `rpc.rs` (`tenzro_getFeeRate`), `rpc_integrations.rs` | read-only answers at the consensus rate |

These are not consensus inputs and never price a fee:

- `listing_tnzo_usd_micro` in the node configuration: an operator's declared
  listing rate, echoed in fiat-denominated model listings only.
- `tenzro-payments` `micropayment_route`: the caller passes a price to choose a
  rail; with none it settles on the home chain.
- `tenzro-econsim`: simulated prices for the economic model.

## What sets the rate

`fees.usd_rate_mode` chooses the source.

- **0, governance.** The rate is `fees.tnzo_usd_nano`. Validators' reports are
  still sealed, opened and recorded, as a published shadow.
- **1, validators.** Each bonded validator seals its rates for a closed hourly
  epoch and opens them an hour later; each report is the median of at least two
  independent providers. The stake-weighted median of the opened reports, kept
  inside the band between the `fees.usd_rate_quantile_low_bps` and
  `fees.usd_rate_quantile_high_bps` quantiles and moved by at most
  `fees.usd_rate_max_change_bps` per epoch, becomes the rate. It starts from
  the governance rate, so switching modes never jumps.

Layering: the reported values, their aggregation and the bounds are protocol,
because every validator must compute the same rate. Which providers a validator
reads (`fee_rate_sources` in its configuration) and how it fetches them is the
operator's choice; the chain only checks that a report names at least
`fees.usd_rate_min_sources` distinct providers per symbol (two at genesis). A
report naming fewer is refused when opened, and an opened report below the count
in force when its epoch is tallied is not counted.

## Failure modes

| Case | What the chain does | What is visible |
|---|---|---|
| Reports missing entirely | the rate stays at the last frozen median; fees go on at it | `tenzro_getFeeRate` `age_epochs` grows; `held` turns true once it exceeds `fees.usd_rate_max_age_epochs` |
| Reports from too little stake (below `fees.usd_rate_stale_quorum_bps`) | the epoch is not counted; the rate stays | a `FeeRateHeld` log with `reason: below_quorum`, the stake that opened and the rate kept |
| Quorum missed but a majority still reports | the rate stays until `fees.usd_rate_stale_epochs` epochs leave it further than `fees.usd_rate_stale_gap_bps` from that majority's median, then moves toward it at the per-epoch bound | `FeeRateFinalized` with `quorum: false` and the stale-epoch count |
| A minority reports a manipulated price | the band ignores it: a third of stake or less can neither move nor hold the rate | `FeeRateFinalized`; `tenzro_getFeeRate` `last_report` shows median and applied rate |
| Everyone reports a manipulated price | the rate moves at most `fees.usd_rate_max_change_bps` per epoch | as above; governance can set `fees.usd_rate_frozen` while it decides |
| Governance hold (`fees.usd_rate_frozen = 1`) | medians are recorded, the rate does not move | a `FeeRateHeld` log with `reason: governance_hold` each epoch |
| Reports disagree (a broken or moved source venue) | an epoch whose band quantiles spread wider than `fees.usd_rate_breaker_spread_bps`, or whose TNZO median sits further than `fees.usd_rate_breaker_gap_bps` from the governance rate, holds the rate; its median is recorded | a `FeeRateHeld` log with `reason: dispersion` |
| Disagreement persists | after `fees.usd_rate_breaker_epochs` such epochs in a row the governance rate is in force; it stays until governance sets `fees.usd_rate_mode` to 1 again, which needs the security ratio like any switch to validator mode | a `FeeRateBreakerTripped` log; `tenzro_getFeeRate` `mode` reads `governance` |
| A validator seals a report and never opens it | when the epoch is tallied it forfeits `fees.usd_rate_unopened_slash_bps` of its validator bond to the insurance pool, once | a `FeeRateUnopened` log with the validator and the amount |

The rate is never zero and never comes from outside chain state. A held rate is
the last good rate, not a guess.

## What to watch

- `tenzro_getFeeRate`: `mode`, `rate_nano_usd`, `epoch`, `age_epochs`,
  `max_age_epochs`, `held`. With `{"symbol": "ETH"}` the same for another asset.
  `held: true` in validator mode means fees are priced at an old rate: check
  that validators are reporting (their `fee_rate_sources` reach two providers)
  and that the reporting stake reaches the quorum.
- `FeeRateHeld` logs from the system address: each epoch the rate did not move
  because too little stake opened or governance holds it.
- `FeeRateFinalized` logs: each frozen median, the rate applied, whether the
  quorum was met.

## Governed values

| Parameter | Genesis | Meaning |
|---|---|---|
| `fees.usd_rate_mode` | 0 | 0 governance rate, 1 validator median |
| `fees.tnzo_usd_nano` | 100000000 | governance rate, nano-USD per TNZO |
| `fees.usd_rate_max_change_bps` | 100 | most the rate moves per epoch |
| `fees.usd_rate_quorum_bps` | 6666 | stake that must open for a median to count |
| `fees.usd_rate_quantile_low_bps`, `fees.usd_rate_quantile_high_bps` | 3334, 6666 | the band the rate may move into |
| `fees.usd_rate_stale_epochs`, `fees.usd_rate_stale_gap_bps`, `fees.usd_rate_stale_quorum_bps` | 6, 300, 5001 | when a majority short of the quorum may still move a far-off rate |
| `fees.usd_rate_max_age_epochs` | 24 | epochs without a newer median before the rate is reported held |
| `fees.usd_rate_frozen` | 0 | 1 holds the rate |
| `fees.usd_rate_min_sources` | 2 | independent sources each report must quote per symbol |
| `fees.usd_rate_breaker_spread_bps`, `fees.usd_rate_breaker_gap_bps`, `fees.usd_rate_breaker_epochs` | 500, 5000, 3 | the dispersion breaker: spread and governance-rate gap that hold an epoch, and how many in a row fall back to the governance rate |
| `fees.usd_rate_unopened_slash_bps` | 10 | bond forfeited for a sealed report never opened |

Loosening any of the rate bounds above (and every other capture guard) needs
yes votes of three quarters of all eligible stake, as a large spend does;
tightening keeps the standard bars.

All are listed with their bounds in [GOVERNANCE_PARAMS.md](../GOVERNANCE_PARAMS.md).

## Tests

- `cargo test -p tenzro-vm --lib native::economy::` covers missing reports,
  the maximum age, manipulated reports and the governance hold at the tally,
  the source count, the dispersion breaker and its fallback, and the forfeit
  for an unopened report.
- `cargo test -p tenzro-sim --test rate_fallback` runs twenty-one validators
  through missing, withheld and manipulated reports on a full ledger.
- `cargo test -p tenzro-sim --test rate_staleness` covers withholding by a
  third and by more than a third.
