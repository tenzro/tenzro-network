# Bridge fee in TNZO

A cross-chain transfer owes a fee in the destination chain's native asset.
`tenzro_quoteBridgeFeeInTnzo` states that fee in TNZO.

## One rate pipeline

Every USD rate the protocol uses comes from one consensus pipeline:

1. Each closed epoch (one hour), a bonded validator submits a
   `FeeRateSubmit` transaction carrying one quote per symbol and provider
   (`TNZO`, `ETH`, `SOL`, ...). A symbol needs quotes from at least two
   independent providers in one report.
2. The VM freezes a symbol's stake-weighted median once validators holding
   two thirds of bonded stake have reported it, and moves the rate in force
   by at most the governed bound per epoch.
3. The TNZO rate prices gas in validator mode; the other symbols convert
   amounts named in other assets, such as a destination chain's native fee.

A validator chooses its providers in its node configuration
(`fee_rate_sources`, each with a `symbol`). Aggregator price feeds and
signed Data Streams reports are inputs to that report, never a second
pipeline. A Data Streams report counts only with the signatures required by
the stream's signer set, which governance installs on chain
(`ProposalAction::SetRateStream { stream: { feed_id, symbol, signers,
threshold } }`, reversed by `RemoveRateStream`); no operator configuration
names the signers, and a stream counts only for the symbol its set names.

## The quote

The node reads the committed rates from chain state, so every node quotes
the same amount for the same state:

`tnzo_wei = ceil(native_fee * native_rate * 10^18 / (10^native_decimals * tnzo_rate))`

The quote carries both rates, the epoch the native rate was committed for,
and a 60-second validity window; its id is a SHA-256 over all of them. A
quote is refused while validators have not priced the destination's native
asset.

Surfaces: RPC `tenzro_quoteBridgeFeeInTnzo`, CLI `tenzro bridge-fee quote`,
MCP `quote_bridge_fee_in_tnzo`, SDKs `BridgeFeeClient.quote`.
