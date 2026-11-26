//! Vendor collateral an attester has already fetched.
//!
//! The collateral a verifier needs beside a quote or report (Intel's TCB
//! info, QE identity and CRLs; AMD's VCEK and ASK) is the same for every
//! attestation a machine makes until the vendor reissues it. It is fetched
//! once and attached to each report from memory, so a machine keeps
//! producing evidence while the vendor's service is unreachable or limits
//! its requests. An entry is served only before the time its issuer says a
//! newer one is due; a verifier refuses collateral past that time.

use std::collections::HashMap;
use std::hash::Hash;

use parking_lot::Mutex;

/// Collateral by what it was issued for, each with the last second it is
/// served at (`None`: it does not go stale).
pub(crate) struct CollateralCache<K, V> {
    entries: Mutex<HashMap<K, (V, Option<u64>)>>,
}

impl<K: Eq + Hash, V: Clone> CollateralCache<K, V> {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The entry for `key`, unless it is stale at `now`; a stale entry is
    /// dropped.
    pub(crate) fn get(&self, key: &K, now: u64) -> Option<V> {
        let mut entries = self.entries.lock();
        let (value, not_after) = entries.get(key)?;
        if not_after.is_some_and(|t| now > t) {
            entries.remove(key);
            return None;
        }
        Some(value.clone())
    }

    pub(crate) fn put(&self, key: K, value: V, not_after: Option<u64>) {
        self.entries.lock().insert(key, (value, not_after));
    }
}

/// The last second Intel's `collateral` is current: the one before the
/// earliest next-update time of its TCB info, its QE identity and its two
/// CRLs (a verifier refuses a CRL from its next-update time on). `None` when
/// any of the four does not state one, and the collateral is then not kept.
#[cfg(feature = "intel-tdx")]
pub(crate) fn tdx_not_after(collateral: &dcap_qvl::QuoteCollateralV3) -> Option<u64> {
    use der::Decode;
    use x509_cert::crl::CertificateList;
    let json_next = |text: &str| -> Option<u64> {
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        let next = chrono::DateTime::parse_from_rfc3339(v.get("nextUpdate")?.as_str()?).ok()?;
        u64::try_from(next.timestamp()).ok()
    };
    let crl_next = |der: &[u8]| -> Option<u64> {
        let crl = CertificateList::from_der(der).ok()?;
        Some(crl.tbs_cert_list.next_update?.to_unix_duration().as_secs())
    };
    [
        json_next(&collateral.tcb_info)?,
        json_next(&collateral.qe_identity)?,
        crl_next(&collateral.pck_crl)?,
        crl_next(&collateral.root_ca_crl)?,
    ]
    .into_iter()
    .min()?
    .checked_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_served_until_its_issuer_says_a_newer_one_is_due() {
        let cache = CollateralCache::new();
        cache.put("fmspc", vec![1u8], Some(100));
        cache.put("chip", vec![2u8], None);
        assert_eq!(cache.get(&"fmspc", 100), Some(vec![1]));
        assert_eq!(cache.get(&"fmspc", 101), None);
        // Dropped, not served again at an earlier clock reading.
        assert_eq!(cache.get(&"fmspc", 50), None);
        assert_eq!(cache.get(&"chip", u64::MAX), Some(vec![2]));
        assert_eq!(cache.get(&"other", 0), None);
    }

    /// The recorded Intel collateral is kept exactly as long as a verifier
    /// accepts it: accepted at its last second, refused the second after.
    #[cfg(feature = "intel-tdx")]
    #[test]
    fn recorded_intel_collateral_is_kept_while_a_verifier_accepts_it() {
        const QUOTE: &[u8] = include_bytes!("../testdata/tdx/tdx_quote");
        const COLLATERAL: &[u8] = include_bytes!("../testdata/tdx/tdx_quote_collateral.json");
        let collateral: dcap_qvl::QuoteCollateralV3 = serde_json::from_slice(COLLATERAL).unwrap();
        let last = tdx_not_after(&collateral).unwrap();
        let verify = |now| {
            dcap_qvl::verify::QuoteVerifier::new_prod()
                .with_config::<dcap_qvl::configs::RingConfig>()
                .verify(QUOTE, &collateral, now)
        };
        verify(last).unwrap();
        verify(last + 1).unwrap_err();

        let mut unstated = collateral.clone();
        unstated.tcb_info = "{}".into();
        assert_eq!(tdx_not_after(&unstated), None);
    }
}
