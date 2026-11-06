//! Signed price reports in the Data Streams format, read as one TNZO/USD
//! rate source.
//!
//! A full report is `abi.encode(bytes32[3] reportContext, bytes reportData,
//! bytes32[] rs, bytes32[] ss, bytes32 rawVs)`. The DON's oracles sign
//! `keccak256(keccak256(reportData) || reportContext)`; a report is accepted
//! only when `threshold` distinct oracles from the configured signer set
//! signed it. `reportData` is read in schema v3 (crypto streams): feed id,
//! valid-from, observation time, native and LINK fees, expiry, and the
//! benchmark, bid and ask prices with 18 decimals.
//!
//! The report is fetched from the streams REST endpoint
//! (`GET /api/v1/reports/latest?feedID=`), authenticated with the
//! operator's API client id and HMAC-SHA256 secret.

use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

use crate::error::{BridgeError, Result};
use crate::route::canonical::Reader;
use crate::secp256k1_multisig::{ValidatorSet, recover_address};

/// Report schema this reader accepts: the first two bytes of a v3 feed id.
pub const REPORT_SCHEMA_V3: [u8; 2] = [0x00, 0x03];
/// Most signatures one report may carry.
const MAX_SIGNATURES: usize = 31;
/// Prices in a v3 report carry 18 decimals.
const PRICE_DECIMALS_SCALE: u128 = 1_000_000_000_000_000_000;

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("stream report: {}", what.into()))
}

/// A verified v3 report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamReport {
    /// The stream it belongs to.
    pub feed_id: [u8; 32],
    /// Earliest time the report is valid for, unix seconds.
    pub valid_from: u32,
    /// When the price was observed, unix seconds.
    pub observed_at: u32,
    /// Last second the report may be used.
    pub expires_at: u32,
    /// Benchmark price, 18 decimals.
    pub price: u128,
}

impl StreamReport {
    /// The price in nano-USD, refused when the report has expired, is older
    /// than `max_age_secs`, or claims a future observation.
    pub fn nano_usd(&self, now_secs: u64, max_age_secs: u64) -> Result<u128> {
        if u64::from(self.expires_at) < now_secs {
            return Err(bad("expired"));
        }
        if u64::from(self.observed_at) > now_secs {
            return Err(bad("observed in the future"));
        }
        if now_secs - u64::from(self.observed_at) > max_age_secs {
            return Err(bad(format!("older than {max_age_secs} s")));
        }
        let nano = self.price / (PRICE_DECIMALS_SCALE / 1_000_000_000);
        if nano == 0 {
            return Err(bad("price below one nano-USD"));
        }
        Ok(nano)
    }
}

fn uint_word(w: [u8; 32], bits: usize) -> Result<u128> {
    let unused = (256 - bits) / 8;
    if w[..unused].iter().any(|b| *b != 0) {
        return Err(bad("value wider than its field"));
    }
    if w[..16].iter().any(|b| *b != 0) {
        return Err(bad("value out of range"));
    }
    Ok(u128::from_be_bytes(w[16..].try_into().expect("16 bytes")))
}

/// A positive `int192` that fits in `u128`. Negative prices are refused.
fn positive_int192(w: [u8; 32]) -> Result<u128> {
    if w[0] & 0x80 != 0 {
        return Err(bad("negative price"));
    }
    uint_word(w, 192)
}

fn read_v3(data: &[u8], feed_id: &[u8; 32]) -> Result<StreamReport> {
    let mut r = Reader::new(data);
    let id = r.word()?;
    if &id != feed_id {
        return Err(bad("report is for another feed"));
    }
    if id[..2] != REPORT_SCHEMA_V3 {
        return Err(bad("not a schema v3 report"));
    }
    let valid_from = r.abi_u32()?;
    let observed_at = r.abi_u32()?;
    uint_word(r.word()?, 192)?;
    uint_word(r.word()?, 192)?;
    let expires_at = r.abi_u32()?;
    let price = positive_int192(r.word()?)?;
    positive_int192(r.word()?)?;
    positive_int192(r.word()?)?;
    r.finish()?;
    if valid_from > observed_at || observed_at > expires_at {
        return Err(bad("timestamps out of order"));
    }
    Ok(StreamReport {
        feed_id: id,
        valid_from,
        observed_at,
        expires_at,
        price,
    })
}

fn word_array(r: &mut Reader<'_>) -> Result<Vec<[u8; 32]>> {
    let n = r.abi_offset()?;
    if n > MAX_SIGNATURES {
        return Err(bad(format!("{n} signatures; at most {MAX_SIGNATURES}")));
    }
    (0..n).map(|_| r.word()).collect()
}

/// Verify `full_report` for `feed_id` against the oracle set `oracles` and
/// return its v3 contents.
pub fn verify_full_report(
    full_report: &[u8],
    feed_id: &[u8; 32],
    oracles: &ValidatorSet,
) -> Result<StreamReport> {
    let mut r = Reader::new(full_report);
    let context = [r.word()?, r.word()?, r.word()?];
    let o_data = r.abi_offset()?;
    let o_rs = r.abi_offset()?;
    let o_ss = r.abi_offset()?;
    let raw_vs = r.word()?;
    r.abi_expect_tail(0, o_data)?;
    let data = r.abi_bytes(32 * 16)?;
    r.abi_expect_tail(0, o_rs)?;
    let rs = word_array(&mut r)?;
    r.abi_expect_tail(0, o_ss)?;
    let ss = word_array(&mut r)?;
    r.finish()?;
    if rs.len() != ss.len() {
        return Err(bad("r and s counts differ"));
    }

    let mut h = Keccak256::new();
    h.update(Keccak256::digest(&data));
    for c in &context {
        h.update(c);
    }
    let digest: [u8; 32] = h.finalize().into();
    let signatures: Vec<([u8; 20], [u8; 65])> = rs
        .iter()
        .zip(&ss)
        .enumerate()
        .filter_map(|(i, (r, s))| {
            let mut sig = [0u8; 65];
            sig[..32].copy_from_slice(r);
            sig[32..64].copy_from_slice(s);
            sig[64] = raw_vs[i];
            recover_address(&digest, &sig).map(|a| (a, sig))
        })
        .collect();
    oracles.verify_quorum(&digest, &signatures)?;
    read_v3(&data, feed_id)
}

/// Reads the latest report of a stream from its REST endpoint.
pub struct DataStreamsClient {
    base_url: String,
    client_id: String,
    secret: String,
    http: reqwest::Client,
}

impl DataStreamsClient {
    /// A client for `base_url` authenticating as `client_id` with `secret`.
    pub fn new(base_url: impl Into<String>, client_id: String, secret: String) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client_id,
            secret,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client build"),
        }
    }

    /// The headers that authenticate `GET path` at `timestamp_ms`.
    pub fn auth_headers(&self, path: &str, timestamp_ms: u64) -> [(String, String); 3] {
        let body_hash = hex::encode(Sha256::digest(b""));
        let to_sign = format!("GET {path} {body_hash} {} {timestamp_ms}", self.client_id);
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret.as_bytes())
            .expect("HMAC takes a key of any length");
        mac.update(to_sign.as_bytes());
        [
            ("Authorization".into(), self.client_id.clone()),
            ("X-Authorization-Timestamp".into(), timestamp_ms.to_string()),
            (
                "X-Authorization-Signature-SHA256".into(),
                hex::encode(mac.finalize().into_bytes()),
            ),
        ]
    }

    /// The latest full report for `feed_id`, unverified.
    pub async fn latest_full_report(&self, feed_id: &[u8; 32]) -> Result<Vec<u8>> {
        let path = format!("/api/v1/reports/latest?feedID=0x{}", hex::encode(feed_id));
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut req = self.http.get(format!("{}{path}", self.base_url));
        for (k, v) in self.auth_headers(&path, now_ms) {
            req = req.header(k, v);
        }
        let body: serde_json::Value = req
            .send()
            .await
            .map_err(|e| BridgeError::AdapterError(format!("stream endpoint: {e}")))?
            .error_for_status()
            .map_err(|e| BridgeError::AdapterError(format!("stream endpoint: {e}")))?
            .json()
            .await
            .map_err(|e| BridgeError::AdapterError(format!("stream endpoint: {e}")))?;
        let full = body
            .pointer("/report/fullReport")
            .and_then(|v| v.as_str())
            .ok_or_else(|| bad("response has no report.fullReport"))?;
        hex::decode(full.trim_start_matches("0x")).map_err(|_| bad("fullReport is not hex"))
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    use super::*;
    use crate::route::evm::{Field, abi_bytes, abi_tuple};

    const NOW: u64 = 1_800_000_000;

    fn key(i: u8) -> SigningKey {
        let mut b = [0u8; 32];
        b[0] = 0x21;
        b[31] = i;
        SigningKey::from_bytes((&b).into()).unwrap()
    }

    fn address(k: &SigningKey) -> [u8; 20] {
        let p = k.verifying_key().to_sec1_point(false);
        let h: [u8; 32] = Keccak256::digest(&p.as_bytes()[1..]).into();
        h[12..].try_into().unwrap()
    }

    fn feed() -> [u8; 32] {
        let mut f = [0x5a; 32];
        f[..2].copy_from_slice(&REPORT_SCHEMA_V3);
        f
    }

    fn w(v: u128) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[16..].copy_from_slice(&v.to_be_bytes());
        x
    }

    fn data(price: u128, observed: u32) -> Vec<u8> {
        [
            feed(),
            w(u128::from(observed)),
            w(u128::from(observed)),
            w(1),
            w(2),
            w(u128::from(observed) + 3_600),
            w(price),
            w(price),
            w(price),
        ]
        .concat()
    }

    fn full(data: &[u8], signers: &[SigningKey]) -> Vec<u8> {
        let context = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut h = Keccak256::new();
        h.update(Keccak256::digest(data));
        for c in &context {
            h.update(c);
        }
        let digest: [u8; 32] = h.finalize().into();
        let mut rs = w(signers.len() as u128).to_vec();
        let mut ss = rs.clone();
        let mut vs = [0u8; 32];
        for (i, k) in signers.iter().enumerate() {
            let (sig, rec): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
                k.sign_prehash(&digest).unwrap();
            let b = sig.to_bytes();
            rs.extend_from_slice(&b[..32]);
            ss.extend_from_slice(&b[32..]);
            vs[i] = rec.to_byte();
        }
        abi_tuple(&[
            Field::Word(context[0]),
            Field::Word(context[1]),
            Field::Word(context[2]),
            Field::Tail(abi_bytes(data)),
            Field::Tail(rs),
            Field::Tail(ss),
            Field::Word(vs),
        ])
    }

    fn oracles() -> ValidatorSet {
        ValidatorSet::new((1..=4).map(|i| address(&key(i))).collect(), 2, "streams")
    }

    #[test]
    fn a_report_signed_by_a_quorum_yields_its_price() {
        let report = full(
            &data(123_000_000_000_000_000, NOW as u32 - 10),
            &[key(1), key(2)],
        );
        let r = verify_full_report(&report, &feed(), &oracles()).unwrap();
        assert_eq!(r.nano_usd(NOW, 60).unwrap(), 123_000_000);
        assert!(r.nano_usd(NOW, 5).is_err(), "too old for the bound");
    }

    #[test]
    fn too_few_or_foreign_signatures_are_refused() {
        let d = data(1, NOW as u32);
        assert!(verify_full_report(&full(&d, &[key(1)]), &feed(), &oracles()).is_err());
        assert!(verify_full_report(&full(&d, &[key(1), key(9)]), &feed(), &oracles()).is_err());
        assert!(verify_full_report(&full(&d, &[key(1), key(1)]), &feed(), &oracles()).is_err());
    }

    #[test]
    fn altered_data_another_feed_or_a_negative_price_are_refused() {
        let report = full(&data(5, NOW as u32), &[key(1), key(2)]);
        // The price word of reportData: after the 7-word head and its length.
        let mut altered = report.clone();
        altered[7 * 32 + 32 + 6 * 32 + 31] ^= 1;
        assert!(verify_full_report(&altered, &feed(), &oracles()).is_err());
        assert!(verify_full_report(&report, &[9u8; 32], &oracles()).is_err());

        let mut negative = data(5, NOW as u32);
        negative[6 * 32] = 0xff;
        let report = full(&negative, &[key(1), key(2)]);
        assert!(verify_full_report(&report, &feed(), &oracles()).is_err());
    }

    #[test]
    fn requests_are_signed_over_method_path_body_client_and_time() {
        let c = DataStreamsClient::new(
            "https://streams.example.org",
            "client".into(),
            "secret".into(),
        );
        let h = c.auth_headers("/api/v1/reports/latest?feedID=0x01", 1_700_000_000_000);
        assert_eq!(h[0].1, "client");
        assert_eq!(h[1].1, "1700000000000");
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(
            format!(
                "GET /api/v1/reports/latest?feedID=0x01 {} client 1700000000000",
                hex::encode(Sha256::digest(b""))
            )
            .as_bytes(),
        );
        assert_eq!(h[2].1, hex::encode(mac.finalize().into_bytes()));
    }
}
