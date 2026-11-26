//! A validator's inputs to consensus prices: signs what this node's router
//! observed and shares it over gossip, and reports fee rates and the compute
//! price index.
//!
//! The compute price index is reported through the same sealed-then-opened
//! rate oracle as the fee rate, one symbol per hardware class
//! ([`tenzro_vm::native::economy::compute_index_symbol`]), in nano-USD per
//! compute-hour: the chain holds the
//! stake-weighted, bounded median of the validators' readings of what routed
//! calls actually cost. Only calls a router served and metered are observed,
//! so no reward or fee paid outside a served call enters it.
//!
//! The observation window itself lives in [`crate::compute_observations`].
//!
//! The node key is derived from the machine's hardware root for each
//! signature, so signing never runs on the routing path: the router hands a
//! draft to a bounded queue and a background task signs, admits and gossips.

use std::sync::Arc;

use crate::compute_observations::{
    ObservationDraft, ObservationError, ObservationSink, ObservationWindow, SignedObservation,
};
use tenzro_network::{MessagePayload, NetworkMessage, NetworkService, TenzroNetworkService};
use tenzro_types::hardware::HardwareClass;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Gossip topic observations travel on.
pub const COMPUTE_OBSERVATIONS_TOPIC: &str = "tenzro/compute-observations";

/// Outbound observations waiting to be gossiped. Past this, new observations
/// are still recorded locally but not shared, so a burst of routed calls
/// cannot grow memory without bound.
const OUTBOUND_QUEUE: usize = 4096;

/// How often expired observations are dropped.
const PRUNE_INTERVAL_SECS: u64 = 300;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Queues each routed call's observation for the signing task.
pub struct NodeObservationSink {
    drafts: mpsc::Sender<(ObservationDraft, i64)>,
}

impl ObservationSink for NodeObservationSink {
    fn observe(&self, draft: ObservationDraft) {
        if self.drafts.try_send((draft, now_ms())).is_err() {
            debug!("compute observation queue full; observation dropped");
        }
    }
}

/// Sign one observation with the node key, admit it to the local window, and
/// return it when it should be gossiped. Only what the local window admitted
/// is shared: a non-validator's observations are refused everywhere.
fn sign_and_admit(
    window: &ObservationWindow,
    keys: &crate::keygen::NodeKeys,
    draft: ObservationDraft,
    observed_at_ms: i64,
) -> Option<SignedObservation> {
    let signed = keys
        .ed25519_signer()
        .map_err(|e| e.to_string())
        .and_then(|signer| {
            SignedObservation::sign(draft, observed_at_ms, &signer).map_err(|e| e.to_string())
        });
    let obs = match signed {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "could not sign compute observation");
            return None;
        }
    };
    match window.ingest(obs.clone(), now_ms()) {
        Ok(_) => Some(obs),
        Err(ObservationError::NotValidator) => None,
        Err(e) => {
            debug!(error = %e, "local compute observation not admitted");
            None
        }
    }
}

/// Start the gossip publisher, the gossip subscriber and the pruning tick, and
/// return the sink the router reports into.
pub fn spawn(
    window: Arc<ObservationWindow>,
    keys: crate::keygen::NodeKeys,
    network: Arc<TenzroNetworkService>,
) -> Arc<NodeObservationSink> {
    let (tx, mut rx) = mpsc::channel::<(ObservationDraft, i64)>(OUTBOUND_QUEUE);

    let net_out = network.clone();
    let sign_window = window.clone();
    tokio::spawn(async move {
        while let Some((draft, observed_at_ms)) = rx.recv().await {
            let window = sign_window.clone();
            let keys = keys.clone();
            let admitted = tokio::task::spawn_blocking(move || {
                sign_and_admit(&window, &keys, draft, observed_at_ms)
            })
            .await
            .ok()
            .flatten();
            let Some(obs) = admitted else {
                continue;
            };
            let data = match bincode::serialize(&obs) {
                Ok(d) => d,
                Err(e) => {
                    warn!(error = %e, "compute observation serialize failed");
                    continue;
                }
            };
            let msg = NetworkMessage::new(MessagePayload::Custom {
                topic: COMPUTE_OBSERVATIONS_TOPIC.to_string(),
                data,
            });
            if let Err(e) = net_out.broadcast(COMPUTE_OBSERVATIONS_TOPIC, msg).await {
                debug!(error = %e, "compute observation broadcast failed");
            }
        }
    });

    let inbound_window = window.clone();
    tokio::spawn(async move {
        let mut sub = match network.subscribe(COMPUTE_OBSERVATIONS_TOPIC).await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "could not subscribe to {}", COMPUTE_OBSERVATIONS_TOPIC);
                return;
            }
        };
        while let Some(msg) = sub.recv().await {
            let MessagePayload::Custom { data, .. } = msg.payload else {
                continue;
            };
            let Ok(obs) = tenzro_network::wire::decode_bounded::<SignedObservation>(
                &data,
                tenzro_iroh::gossip::MAX_GOSSIP_MESSAGE,
            ) else {
                continue;
            };
            if let Err(e) = inbound_window.ingest(obs, now_ms()) {
                debug!(error = %e, "gossiped compute observation not admitted");
            }
        }
    });

    let prune_window = window.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(PRUNE_INTERVAL_SECS));
        loop {
            tick.tick().await;
            prune_window.prune(now_ms());
        }
    });

    Arc::new(NodeObservationSink { drafts: tx })
}

/// A decimal USD price (`"0.1234"`) in nano-USD, truncated past nine
/// decimals. `None` for anything that is not a plain positive decimal.
fn usd_to_nano(price: &str) -> Option<u128> {
    let (whole, frac) = price.trim().split_once('.').unwrap_or((price.trim(), ""));
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let mut frac = frac.chars().take(9).collect::<String>();
    while frac.len() < 9 {
        frac.push('0');
    }
    let nano = whole
        .checked_mul(1_000_000_000)?
        .checked_add(frac.parse().ok()?)?;
    (nano > 0).then_some(nano)
}

/// A configured rate source, ready to read.
enum RateReader {
    Json {
        url: String,
        pointer: String,
    },
    Aggregator {
        feeds: tenzro_bridge::ChainlinkFeedClient,
        address: String,
    },
    Stream {
        client: tenzro_bridge::data_streams::DataStreamsClient,
        feed_id: [u8; 32],
        max_age_secs: u64,
    },
}

fn hex_bytes<const N: usize>(field: &str, text: &str) -> Result<[u8; N], String> {
    hex::decode(text.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{field} is not {N} bytes of hex"))
}

impl RateReader {
    fn new(feed: &crate::config::FeeRateFeed) -> Result<Self, String> {
        use crate::config::FeeRateFeed;
        Ok(match feed {
            FeeRateFeed::Json { url, pointer } => Self::Json {
                url: url.clone(),
                pointer: pointer.clone(),
            },
            FeeRateFeed::Aggregator { rpc_url, address } => Self::Aggregator {
                feeds: tenzro_bridge::ChainlinkFeedClient::new(rpc_url.clone()),
                address: address.clone(),
            },
            FeeRateFeed::DataStream {
                url,
                feed_id,
                client_id,
                secret_env,
                max_age_secs,
            } => {
                let secret =
                    std::env::var(secret_env).map_err(|_| format!("{secret_env} is not set"))?;
                Self::Stream {
                    client: tenzro_bridge::data_streams::DataStreamsClient::new(
                        url.clone(),
                        client_id.clone(),
                        secret,
                    ),
                    feed_id: hex_bytes::<32>("feed_id", feed_id)?,
                    max_age_secs: *max_age_secs,
                }
            }
        })
    }

    /// The source's USD rate for `symbol` in nano-USD, or why it has none.
    /// A stream's report counts only under the signer set governance
    /// installed for it in `state`, and only for the symbol that set prices.
    async fn read(
        &self,
        http: &reqwest::Client,
        state: Option<&tenzro_vm::StateAdapter>,
        symbol: &str,
    ) -> Result<u128, String> {
        match self {
            Self::Json { url, pointer } => {
                let body: serde_json::Value = http
                    .get(url)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?
                    .error_for_status()
                    .map_err(|e| e.to_string())?
                    .json()
                    .await
                    .map_err(|e| e.to_string())?;
                let value = body
                    .pointer(pointer)
                    .ok_or_else(|| format!("no value at {pointer}"))?;
                let text = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    other => return Err(format!("not a price: {other}")),
                };
                usd_to_nano(&text).ok_or_else(|| format!("not a price: {text}"))
            }
            Self::Aggregator { feeds, address } => {
                if feeds.get_registration(address).is_none() {
                    feeds
                        .register_feed(address.clone(), "major")
                        .await
                        .map_err(|e| e.to_string())?;
                }
                let reading = feeds.read_feed(address).await.map_err(|e| e.to_string())?;
                aggregator_to_nano(reading.answer, reading.decimals)
                    .ok_or_else(|| format!("not a price: {}", reading.answer))
            }
            Self::Stream {
                client,
                feed_id,
                max_age_secs,
            } => {
                let oracles = governed_stream_signers(state, feed_id, symbol)?;
                let full = client
                    .latest_full_report(feed_id)
                    .await
                    .map_err(|e| e.to_string())?;
                let report =
                    tenzro_bridge::data_streams::verify_full_report(&full, feed_id, &oracles)
                        .map_err(|e| e.to_string())?;
                let now = u64::try_from(now_ms() / 1000).unwrap_or(0);
                report
                    .nano_usd(now, *max_age_secs)
                    .map_err(|e| e.to_string())
            }
        }
    }
}

/// The signer set governance installed for stream `feed_id`, provided it
/// prices `symbol`.
fn governed_stream_signers(
    state: Option<&tenzro_vm::StateAdapter>,
    feed_id: &[u8; 32],
    symbol: &str,
) -> Result<tenzro_bridge::secp256k1_multisig::ValidatorSet, String> {
    let state = state.ok_or("chain state is not readable")?;
    let set = tenzro_vm::native::economy::read_rate_stream(state, feed_id).ok_or_else(|| {
        format!(
            "no signer set is installed for stream {}",
            hex::encode(feed_id)
        )
    })?;
    stream_signers_for(&set, symbol)
}

fn stream_signers_for(
    set: &tenzro_types::RateStreamSigners,
    symbol: &str,
) -> Result<tenzro_bridge::secp256k1_multisig::ValidatorSet, String> {
    if !set.symbol.eq_ignore_ascii_case(symbol.trim()) {
        return Err(format!(
            "stream prices {}, configured for {symbol}",
            set.symbol
        ));
    }
    Ok(tenzro_bridge::secp256k1_multisig::ValidatorSet::new(
        set.signers.iter().map(|s| s.0).collect(),
        set.threshold,
        "rate stream signers",
    ))
}

/// An aggregator answer with `decimals` decimals, in nano-USD.
fn aggregator_to_nano(answer: i128, decimals: u8) -> Option<u128> {
    let answer = u128::try_from(answer).ok().filter(|a| *a > 0)?;
    let nano = if decimals >= 9 {
        answer / 10u128.checked_pow(u32::from(decimals) - 9)?
    } else {
        answer.checked_mul(10u128.pow(9 - u32::from(decimals)))?
    };
    (nano > 0).then_some(nano)
}

/// One quote per symbol and provider: the median (lower middle) of the
/// rates read from the sources sharing its name, so a provider configured
/// twice still counts once. Symbols fewer than two providers answered are
/// dropped, so no single provider ever sets a rate.
fn quotes_by_provider(rates: Vec<(String, String, u128)>) -> Vec<tenzro_types::FeeRateQuote> {
    let mut by: std::collections::BTreeMap<(String, String), Vec<u128>> = Default::default();
    for (symbol, name, rate) in rates {
        by.entry((
            symbol.trim().to_ascii_uppercase(),
            name.trim().to_ascii_lowercase(),
        ))
        .or_default()
        .push(rate);
    }
    let mut providers: std::collections::BTreeMap<String, usize> = Default::default();
    for (symbol, _) in by.keys() {
        *providers.entry(symbol.clone()).or_default() += 1;
    }
    by.into_iter()
        .filter(|((symbol, _), _)| {
            providers[symbol] >= tenzro_vm::native::economy::MIN_RATE_SOURCES
        })
        .map(|((symbol, source), mut r)| {
            r.sort_unstable();
            tenzro_types::FeeRateQuote {
                symbol,
                source,
                rate_nano_usd: r[(r.len() - 1) / 2],
            }
        })
        .collect()
}

/// `quotes` without the symbols fewer than `min_sources` sources quote: the
/// chain refuses the opening of a report when any one symbol falls short,
/// and a report left unopened forfeits part of the reporter's stake.
fn openable(
    quotes: Vec<tenzro_types::FeeRateQuote>,
    min_sources: usize,
) -> Vec<tenzro_types::FeeRateQuote> {
    let mut count: std::collections::BTreeMap<String, usize> = Default::default();
    for q in &quotes {
        *count.entry(q.symbol.clone()).or_default() += 1;
    }
    quotes
        .into_iter()
        .filter(|q| count[&q.symbol] >= min_sources)
        .collect()
}

/// Every class with a compute price index.
const INDEXED_CLASSES: [HardwareClass; 4] = [
    HardwareClass::Cpu,
    HardwareClass::ConsumerGpu,
    HardwareClass::DatacenterGpu,
    HardwareClass::MultiAccelerator,
];

const WEI_PER_TNZO: u128 = tenzro_types::price_card::WEI_PER_TNZO;

/// `wei_per_second` as nano-USD per compute-hour at `tnzo_nano_usd` nano-USD
/// per TNZO; `None` when it overflows or rounds to zero.
pub(crate) fn compute_hour_nano_usd(wei_per_second: u128, tnzo_nano_usd: u128) -> Option<u128> {
    let per_hour = wei_per_second.checked_mul(3600)?;
    let whole = (per_hour / WEI_PER_TNZO).checked_mul(tnzo_nano_usd)?;
    let part = (per_hour % WEI_PER_TNZO).checked_mul(tnzo_nano_usd)? / WEI_PER_TNZO;
    let nano = whole.checked_add(part)?;
    (nano > 0).then_some(nano)
}

/// The compute price index quotes `window` supports, at most `room` of them:
/// for each indexed class, one quote per attested provider (the lower middle
/// of its models' prices), the provider's address as the source. A class is
/// left out unless at least `min_sources` providers price it, and when room
/// runs short only the providers nearest the middle are kept, so every symbol
/// passes the check the chain applies when the report is opened.
pub(crate) fn index_quotes(
    window: &crate::compute_observations::ObservationWindow,
    tnzo_nano_usd: u128,
    min_sources: usize,
    mut room: usize,
    now_ms: i64,
) -> Vec<tenzro_types::FeeRateQuote> {
    let mut out = Vec::new();
    for class in INDEXED_CLASSES {
        let Some(symbol) = tenzro_vm::native::economy::compute_index_symbol(class) else {
            continue;
        };
        let mut by: std::collections::BTreeMap<String, Vec<u128>> = Default::default();
        for c in window.index(class, None, now_ms).constituents {
            if let Some(rate) = compute_hour_nano_usd(c.price_per_compute_second_wei, tnzo_nano_usd)
            {
                by.entry(hex::encode(c.provider.as_bytes()))
                    .or_default()
                    .push(rate);
            }
        }
        let mut rates: Vec<(u128, String)> = by
            .into_iter()
            .map(|(source, mut r)| {
                r.sort_unstable();
                (r[(r.len() - 1) / 2], source)
            })
            .collect();
        rates.sort();
        let keep = rates.len().min(room);
        if keep < min_sources {
            continue;
        }
        let skip = (rates.len() - keep) / 2;
        for (rate, source) in rates.into_iter().skip(skip).take(keep) {
            out.push(tenzro_types::FeeRateQuote {
                symbol: symbol.to_string(),
                source,
                rate_nano_usd: rate,
            });
        }
        room -= keep;
    }
    out
}

/// On a validator, report for each epoch as it closes the USD rates its
/// configured sources give, one quote per symbol and answering provider (a
/// symbol with fewer than two answering providers is left out), and the
/// compute price index its observation window supports ([`index_quotes`]).
pub fn spawn_fee_rate_reporter(node: Arc<crate::node::TenzroNode>) {
    let configured = node.config().fee_rate_sources.clone();
    if !node.config().roles.is_validator() {
        return;
    }
    let mut providers: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        Default::default();
    for s in &configured {
        providers
            .entry(s.symbol.trim().to_ascii_uppercase())
            .or_default()
            .insert(s.name.trim().to_ascii_lowercase());
    }
    if !configured.is_empty()
        && !providers
            .values()
            .any(|p| p.len() >= tenzro_vm::native::economy::MIN_RATE_SOURCES)
    {
        warn!(
            providers = providers.len(),
            "fee rate reporting needs sources from at least two providers; reporting the compute index only"
        );
    }
    let mut sources = Vec::with_capacity(configured.len());
    for s in configured
        .iter()
        .take(tenzro_vm::native::economy::MAX_RATE_QUOTES)
    {
        match RateReader::new(&s.feed) {
            Ok(r) => sources.push((s.symbol.clone(), s.name.clone(), r)),
            Err(e) => warn!(source = %s.name, error = %e, "fee rate source not usable"),
        }
    }
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "fee rate reporter could not start");
                return;
            }
        };
        let epoch_ms = tenzro_vm::native::MARKET_EPOCH_MS;
        // The rates sealed last hour, opened with this hour's report.
        let mut sealed: Option<(u64, tenzro_types::FeeRateReveal)> = None;
        loop {
            let now = now_ms();
            let next = (now / epoch_ms + 1) * epoch_ms + 60_000;
            tokio::time::sleep(std::time::Duration::from_millis((next - now).max(0) as u64)).await;

            let closed = (now_ms() / epoch_ms - 1).max(0) as u64;
            let state = crate::rpc::chain_state_of(&node);
            let mut rates = Vec::new();
            for (symbol, name, reader) in &sources {
                match reader.read(&client, state.as_ref(), symbol).await {
                    Ok(rate) => rates.push((symbol.clone(), name.clone(), rate)),
                    Err(e) => warn!(source = %name, %symbol, error = %e, "rate source failed"),
                }
            }
            let Some(state) = state.as_ref() else {
                warn!(epoch = closed, "no chain state to report rates against");
                continue;
            };
            use tenzro_vm::native::economy;
            let min_sources = economy::rate_min_sources_at_opening(state);
            let mut quotes = openable(quotes_by_provider(rates), min_sources);
            quotes.extend(index_quotes(
                node.compute_observations(),
                economy::read_fee_rate(state).rate_nano_usd,
                min_sources,
                economy::MAX_RATE_QUOTES.saturating_sub(quotes.len()),
                now_ms(),
            ));
            if quotes.is_empty() {
                if sources.is_empty() {
                    debug!(epoch = closed, "nothing to report this epoch");
                } else {
                    warn!(epoch = closed, "too few rate sources answered");
                }
                continue;
            }
            let Some(from) = node.ledger_submitter().map(|s| s.address()) else {
                warn!("fee rate reporting needs this node's validator account");
                continue;
            };
            let mut salt = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
            let commitment = tenzro_types::fee_rate_commitment(
                from.as_bytes(),
                closed,
                &salt,
                quotes
                    .iter()
                    .map(|q| (q.symbol.as_str(), q.source.as_str(), q.rate_nano_usd)),
            );
            let reveal = sealed
                .take()
                .filter(|(e, _)| *e + 1 == closed)
                .map(|(_, r)| r);
            sealed = Some((closed, tenzro_types::FeeRateReveal { quotes, salt }));
            let tx = tenzro_types::TransactionType::FeeRateSubmit {
                epoch: closed,
                commitment,
                reveal,
            };
            match crate::rpc::submit_as_validator(
                &node,
                tx,
                tenzro_vm::native::economy::GAS_FEE_RATE_SUBMIT,
            )
            .await
            {
                Ok(_) => debug!(epoch = closed, "reported the fee rate"),
                Err(e) => {
                    warn!(epoch = closed, error = %e.message, "could not report the fee rate")
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn usd_prices_convert_to_nano() {
        assert_eq!(super::usd_to_nano("0.1"), Some(100_000_000));
        assert_eq!(super::usd_to_nano("12.3456789012"), Some(12_345_678_901));
        assert_eq!(super::usd_to_nano("0"), None);
        assert_eq!(super::usd_to_nano("-1"), None);
    }

    #[test]
    fn aggregator_answers_convert_to_nano() {
        assert_eq!(super::aggregator_to_nano(12_345_678, 8), Some(123_456_780));
        assert_eq!(
            super::aggregator_to_nano(1_000_000_000_000_000_000, 18),
            Some(1_000_000_000)
        );
        assert_eq!(super::aggregator_to_nano(5, 6), Some(5_000));
        assert_eq!(super::aggregator_to_nano(0, 8), None);
        assert_eq!(super::aggregator_to_nano(-1, 8), None);
    }

    #[test]
    fn one_provider_counts_once_however_many_feeds_it_has() {
        let t = |n: &str, r| ("tnzo".to_string(), n.to_string(), r);
        let quotes = super::quotes_by_provider(vec![
            t("Chainlink", 100),
            t("chainlink", 300),
            t("chainlink", 200),
            t("exchange-a", 110),
            ("ETH".into(), "chainlink".into(), 9),
        ]);
        assert_eq!(quotes.len(), 2);
        assert_eq!(quotes[0].source, "chainlink");
        assert!(quotes.iter().all(|q| q.symbol == "TNZO"));
        assert_eq!(quotes[0].rate_nano_usd, 200);
        assert_eq!(quotes[1].rate_nano_usd, 110);
        // Feeds from one provider alone never make a report.
        let alone = super::quotes_by_provider(vec![t("chainlink", 1), t("chainlink", 2)]);
        assert!(alone.is_empty());
    }

    #[test]
    fn rate_sources_parse_by_kind() {
        let sources: Vec<crate::config::FeeRateSource> = serde_json::from_value(serde_json::json!([
            {"name": "exchange-a", "symbol": "ETH", "kind": "json", "url": "https://a.example.org/p", "pointer": "/usd"},
            {"name": "chainlink", "kind": "aggregator", "rpc_url": "https://rpc.example.org", "address": "0x01"},
            {"name": "chainlink", "kind": "data_stream", "url": "https://streams.example.org",
             "feed_id": "0x00", "client_id": "c", "secret_env": "STREAMS_SECRET",
             "max_age_secs": 60}
        ]))
        .unwrap();
        assert!(matches!(
            sources[1].feed,
            crate::config::FeeRateFeed::Aggregator { .. }
        ));
        assert_eq!(sources[0].symbol, "ETH");
        assert_eq!(sources[1].symbol, "TNZO");
        assert!(super::RateReader::new(&sources[0].feed).is_ok());
        // A stream whose secret is not in the environment is not usable.
        assert!(super::RateReader::new(&sources[2].feed).is_err());
    }

    #[test]
    fn a_stream_counts_only_for_the_symbol_its_governed_set_prices() {
        let set = tenzro_types::RateStreamSigners {
            feed_id: [7; 32],
            symbol: "ETH".into(),
            signers: vec![
                tenzro_types::RateStreamSigner([1; 20]),
                tenzro_types::RateStreamSigner([2; 20]),
            ],
            threshold: 2,
        };
        assert!(super::stream_signers_for(&set, "eth").is_ok());
        assert!(super::stream_signers_for(&set, "TNZO").is_err());
        assert!(super::governed_stream_signers(None, &[7; 32], "ETH").is_err());
    }

    /// A compute claim's epoch is a billing epoch; both count market epochs,
    /// so they must be the same hour.
    #[test]
    fn billing_and_market_epochs_are_the_same_length() {
        assert_eq!(
            crate::node::BILLING_EPOCH_INTERVAL_SECS as i64 * 1000,
            tenzro_vm::native::MARKET_EPOCH_MS
        );
    }

    fn window_with(prices: &[(u8, u128)]) -> crate::compute_observations::ObservationWindow {
        use crate::compute_observations::{ObservationDraft, ObservationWindow, SignedObservation};
        use tenzro_crypto::signatures::Ed25519SignerImpl;
        use tenzro_types::hardware::HardwareClass;
        let w = ObservationWindow::new();
        w.set_observer_filter(std::sync::Arc::new(|_| true));
        let observers = [
            Ed25519SignerImpl::generate().unwrap(),
            Ed25519SignerImpl::generate().unwrap(),
        ];
        for (p, price) in prices {
            for (i, s) in observers.iter().enumerate() {
                let draft = ObservationDraft {
                    model_id: "qwen3-8b".into(),
                    provider: tenzro_types::primitives::Address::new([*p; 32]),
                    hardware_class: HardwareClass::DatacenterGpu,
                    region: "SG".into(),
                    success: true,
                    latency_ms: 1000,
                    price_wei: *price,
                    input_tokens: 10,
                    output_tokens: 10,
                };
                let obs = SignedObservation::sign(draft, NOW - i as i64, s).unwrap();
                w.ingest(obs, NOW).unwrap();
            }
        }
        w
    }

    const NOW: i64 = 1_800_000_000_000;
    /// 0.10 USD per TNZO.
    const TNZO_NANO_USD: u128 = 100_000_000;

    #[test]
    fn compute_seconds_convert_to_nano_usd_per_hour() {
        // 1e15 wei/s is 3.6 TNZO an hour, 0.36 USD at 0.10 USD per TNZO.
        assert_eq!(
            super::compute_hour_nano_usd(1_000_000_000_000_000, TNZO_NANO_USD),
            Some(360_000_000)
        );
        assert_eq!(super::compute_hour_nano_usd(1, TNZO_NANO_USD), None);
        assert_eq!(super::compute_hour_nano_usd(u128::MAX, TNZO_NANO_USD), None);
    }

    /// Two attested providers make an index the chain's opening check
    /// accepts, priced per compute-hour; one provider makes none.
    #[test]
    fn the_index_is_reported_only_when_the_chain_would_open_it() {
        let two = window_with(&[(1, 1_000_000_000_000_000), (2, 3_000_000_000_000_000)]);
        let quotes = super::index_quotes(&two, TNZO_NANO_USD, 2, 64, NOW);
        assert_eq!(quotes.len(), 2);
        assert!(quotes.iter().all(|q| q.symbol == "IDXDCGPU"));
        assert_eq!(quotes[0].rate_nano_usd, 360_000_000);
        assert_eq!(quotes[1].rate_nano_usd, 1_080_000_000);
        tenzro_vm::native::economy::check_rate_report(&quotes, 2, None).unwrap();

        // A raised source count leaves the symbol out rather than sealing a
        // report its opening would refuse.
        assert!(super::index_quotes(&two, TNZO_NANO_USD, 3, 64, NOW).is_empty());

        let one = window_with(&[(1, 1_000_000_000_000_000)]);
        assert!(super::index_quotes(&one, TNZO_NANO_USD, 2, 64, NOW).is_empty());
    }

    /// Short of room, the providers nearest the middle are kept, and a class
    /// that cannot keep enough is left out.
    #[test]
    fn short_room_keeps_the_middle_providers() {
        let w = window_with(&[
            (1, 1_000_000_000_000_000),
            (2, 2_000_000_000_000_000),
            (3, 3_000_000_000_000_000),
            (4, 4_000_000_000_000_000),
            (5, 5_000_000_000_000_000),
        ]);
        let quotes = super::index_quotes(&w, TNZO_NANO_USD, 2, 3, NOW);
        let rates: Vec<u128> = quotes.iter().map(|q| q.rate_nano_usd).collect();
        assert_eq!(rates, vec![720_000_000, 1_080_000_000, 1_440_000_000]);
        assert!(super::index_quotes(&w, TNZO_NANO_USD, 2, 1, NOW).is_empty());
    }

    /// A fee-rate symbol fewer sources quote than the opening needs is left
    /// out, so it cannot take the index quotes down with it.
    #[test]
    fn a_short_symbol_is_left_out_of_the_report() {
        let q = |symbol: &str, source: &str| tenzro_types::FeeRateQuote {
            symbol: symbol.into(),
            source: source.into(),
            rate_nano_usd: 1_000,
        };
        let kept = super::openable(vec![q("TNZO", "a"), q("TNZO", "b"), q("ETH", "a")], 2);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|k| k.symbol == "TNZO"));
        tenzro_vm::native::economy::check_rate_report(&kept, 2, None).unwrap();
    }
}
