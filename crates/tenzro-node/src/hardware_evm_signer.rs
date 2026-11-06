//! Builds EVM transaction signers from hardware signer configuration.
//!
//! Every EVM key the node signs with (bridge adapters, the x402 relayer, the
//! ERC-8004 mirror) lives in a hardware device reached through
//! [`tenzro_wallet::pluggable_signer::PluggableSigner`]. This module turns a
//! [`HardwareSignerConfig`] into that device handle and wraps it in an
//! [`EvmTransactionSigner`]. It never reads, derives or stores a private key.

use std::sync::Arc;

use tenzro_bridge::evm_signer::EvmTransactionSigner;
use tenzro_wallet::pluggable_signer::PluggableSigner;

use crate::config::HardwareSignerConfig;

/// BIP-32 hardened-derivation flag.
const HARDENED: u32 = 0x8000_0000;

/// Parse `m/44'/60'/0'/0/0` into BIP-32 indices.
pub fn parse_derivation_path(path: &str) -> Result<Vec<u32>, String> {
    let mut parts = path.trim().split('/');
    if parts.next() != Some("m") {
        return Err(format!("derivation path '{path}' must start with 'm/'"));
    }
    let indices: Vec<u32> = parts
        .map(|p| {
            let (digits, hardened) = match p.strip_suffix('\'').or_else(|| p.strip_suffix('h')) {
                Some(d) => (d, true),
                None => (p, false),
            };
            let index: u32 = digits
                .parse()
                .map_err(|_| format!("'{p}' in '{path}' is not a derivation index"))?;
            if index >= HARDENED {
                return Err(format!("index {index} in '{path}' is out of range"));
            }
            Ok(if hardened { index | HARDENED } else { index })
        })
        .collect::<Result<_, _>>()?;
    if indices.is_empty() {
        return Err(format!("derivation path '{path}' names no key"));
    }
    Ok(indices)
}

/// The device handle a configuration names.
fn device(cfg: &HardwareSignerConfig) -> Result<Arc<dyn PluggableSigner>, String> {
    let path = parse_derivation_path(&cfg.derivation_path)?;
    match cfg.device_kind.to_ascii_lowercase().as_str() {
        "gridplus" => {
            let device_id = cfg
                .device_id
                .clone()
                .ok_or("a GridPlus signer needs device_id")?;
            let wallet_uuid = cfg
                .wallet_uuid
                .clone()
                .ok_or("a GridPlus signer needs wallet_uuid")?;
            Ok(Arc::new(
                tenzro_wallet::pluggable_signer::gridplus::GridPlusSigner::new(
                    device_id,
                    wallet_uuid,
                    path,
                ),
            ))
        }
        #[cfg(feature = "ledger-signer")]
        "ledger" => Ok(Arc::new(
            tenzro_wallet::pluggable_signer::ledger::LedgerSigner::new(path),
        )),
        #[cfg(feature = "trezor-signer")]
        "trezor" => Ok(Arc::new(
            tenzro_wallet::pluggable_signer::trezor::TrezorSigner::new(path),
        )),
        kind @ ("ledger" | "trezor") => Err(format!(
            "this build has no {kind} transport; rebuild tenzro-node with the \
             '{kind}-signer' feature"
        )),
        other => Err(format!(
            "unknown hardware signer '{other}'; expected ledger, trezor or gridplus"
        )),
    }
}

/// An EVM signer for `chain_id` over the device `cfg` names.
pub async fn build(
    cfg: &HardwareSignerConfig,
    chain_id: u64,
    rpc_url: String,
) -> Result<EvmTransactionSigner, String> {
    let device = device(cfg)?;
    EvmTransactionSigner::from_hardware(device, chain_id, rpc_url)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A stand-in hardware device for node unit tests: a `GenericSigner`
    //! whose closure signs with a fixed in-memory key. Test code only.

    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{RecoveryId, Signature, SigningKey};
    use tenzro_wallet::pluggable_signer::GenericSigner;

    /// An EVM signer over a test device, pointed at an unreachable RPC.
    pub async fn test_signer() -> Arc<EvmTransactionSigner> {
        let sk = SigningKey::from_bytes((&[1u8; 32]).into()).expect("valid scalar");
        let pk = sk.verifying_key().to_sec1_point(true).as_bytes().to_vec();
        let device = Arc::new(GenericSigner::new(pk, move |hash| {
            let (sig, rec): (Signature, RecoveryId) = sk
                .sign_prehash(hash)
                .map_err(|e| tenzro_wallet::WalletError::SignatureFailed(e.to_string()))?;
            let mut out = sig.to_bytes().to_vec();
            out.push(rec.to_byte());
            Ok(out)
        }));
        Arc::new(
            EvmTransactionSigner::from_hardware(device, 1337, "http://127.0.0.1:1".into())
                .await
                .expect("test device"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_standard_ethereum_path_parses_with_hardened_indices() {
        assert_eq!(
            parse_derivation_path("m/44'/60'/0'/0/7").unwrap(),
            vec![44 | HARDENED, 60 | HARDENED, HARDENED, 0, 7]
        );
        assert_eq!(
            parse_derivation_path("m/44h/60h/0h/0/0").unwrap()[0],
            44 | HARDENED
        );
    }

    #[test]
    fn malformed_paths_are_refused() {
        for bad in ["44'/60'", "m", "m/x", "m/2147483648", ""] {
            assert!(parse_derivation_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_devices_and_missing_gridplus_pairing_are_refused() {
        let mut cfg = HardwareSignerConfig {
            device_kind: "yubikey".into(),
            derivation_path: "m/44'/60'/0'/0/0".into(),
            device_id: None,
            wallet_uuid: None,
        };
        assert!(device(&cfg).is_err());
        cfg.device_kind = "gridplus".into();
        assert!(device(&cfg).is_err());
        cfg.device_id = Some("dev".into());
        cfg.wallet_uuid = Some("wallet".into());
        assert!(device(&cfg).is_ok());
    }
}
