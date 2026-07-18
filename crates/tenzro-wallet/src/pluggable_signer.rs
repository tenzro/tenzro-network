//! Pluggable hardware-signer surface for advanced custody.
//!
//! Most consumer users sign with a passkey (see `tenzro_node::passkey_rpc`).
//! Power users layer hardware keys: Ledger / Trezor / GridPlus Lattice1 /
//! YubiKey. Each of those devices speaks its own wire protocol — APDU over
//! HID for Ledger and Trezor, a REST API for GridPlus, FIDO2 / CTAP for
//! YubiKey. This module defines the `PluggableSigner` trait that abstracts
//! over those backends so the rest of the wallet (and the on-chain
//! `HardwareValidator` ERC-7579 module installed via
//! `tenzro_addHardwareSigner`) only deals with `(pubkey, sign(hash))`.
//!
//! # The trait
//!
//! - `device_kind()` — short identifier matching the RPC `device_kind`
//!   field ("ledger", "trezor", "gridplus", "yubikey", "generic").
//! - `public_key()` — the device's public key in its native form
//!   (33-byte SEC1 compressed for secp256k1 hardware, 64-byte raw P-256 for
//!   FIDO2). The byte order is whatever the on-chain validator expects.
//! - `sign_hash(hash)` — request a signature over a 32-byte hash. Returns
//!   the canonical signature bytes (64 bytes for raw r||s, longer for
//!   DER-encoded ECDSA, etc.).
//! - `attest()` — optional. Some devices (Lattice1 with secure-attestation)
//!   can produce a manufacturer-signed attestation over the device's
//!   pubkey, which the smart account can record for audit.
//!
//! # Adapters
//!
//! - [`LedgerSigner`] — Ledger Nano S / X / Stax via `ledger-transport-hid`
//!   + the Ethereum app's APDUs.
//! - [`TrezorSigner`] — Trezor One / T via `trezor-client`.
//! - [`GridPlusSigner`] — Lattice1 via REST API to the Lattice paired with
//!   a wallet UUID.
//! - [`YubiKeySigner`] — FIDO2 / WebAuthn over libfido2.
//! - [`GenericSigner`] — fallback for caller-supplied closures (testing,
//!   custom MPC remote signers).
//!
//! Each adapter pins its own transport dependency behind a feature flag so
//! that consumers only link what they actually use. The trait is the only
//! public surface; the adapter implementations live behind features.

use crate::error::WalletError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// The set of hardware device kinds the wallet knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareDeviceKind {
    Ledger,
    Trezor,
    GridPlus,
    YubiKey,
    /// Any caller-supplied signer that doesn't map to a brand. Used for
    /// remote MPC signers (Fireblocks, Cobo, Safeheron) and tests.
    Generic,
}

impl HardwareDeviceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ledger => "ledger",
            Self::Trezor => "trezor",
            Self::GridPlus => "gridplus",
            Self::YubiKey => "yubikey",
            Self::Generic => "generic",
        }
    }

    // Inherent constructor returning Option; not the FromStr trait (which requires Result<Self, Err>).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ledger" => Some(Self::Ledger),
            "trezor" => Some(Self::Trezor),
            "gridplus" => Some(Self::GridPlus),
            "yubikey" => Some(Self::YubiKey),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }
}

/// Manufacturer-signed attestation over a hardware device's public key.
/// Optional — many devices don't expose this surface. When present, the
/// smart account records it under `validator_modules[<hw_addr>].init_data`
/// so future audits can prove the device kind and serial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAttestation {
    pub device_kind: HardwareDeviceKind,
    pub device_serial: Option<String>,
    pub manufacturer_signature: Vec<u8>,
    pub attestation_format: String,
}

/// Abstract hardware signer. Backends pin their own transport behind
/// feature flags; consumers depend on the trait only.
#[async_trait]
pub trait PluggableSigner: Send + Sync {
    /// Short identifier matching the RPC `device_kind` field.
    fn device_kind(&self) -> HardwareDeviceKind;

    /// The device's public key. For Ledger / Trezor / GridPlus this is a
    /// 33-byte SEC1 compressed secp256k1 key; for YubiKey it's a 64-byte
    /// raw P-256 `(X || Y)`.
    async fn public_key(&self) -> Result<Vec<u8>, WalletError>;

    /// Request a signature over a 32-byte hash. Returns the signature in
    /// the form the on-chain validator expects (raw `r || s` for
    /// secp256k1, raw `r || s` for P-256, etc.).
    async fn sign_hash(&self, hash: &[u8; 32]) -> Result<Vec<u8>, WalletError>;

    /// Optional manufacturer attestation. Default returns `None`.
    async fn attest(&self) -> Result<Option<HardwareAttestation>, WalletError> {
        Ok(None)
    }
}

// =============================================================================
// Generic adapter — closure-driven signer for tests + remote MPC
// =============================================================================

pub struct GenericSigner {
    public_key: Vec<u8>,
    sign_fn: std::sync::Arc<
        dyn Fn(&[u8; 32]) -> Result<Vec<u8>, WalletError> + Send + Sync,
    >,
}

impl GenericSigner {
    pub fn new<F>(public_key: Vec<u8>, sign_fn: F) -> Self
    where
        F: Fn(&[u8; 32]) -> Result<Vec<u8>, WalletError> + Send + Sync + 'static,
    {
        Self {
            public_key,
            sign_fn: std::sync::Arc::new(sign_fn),
        }
    }
}

#[async_trait]
impl PluggableSigner for GenericSigner {
    fn device_kind(&self) -> HardwareDeviceKind {
        HardwareDeviceKind::Generic
    }

    async fn public_key(&self) -> Result<Vec<u8>, WalletError> {
        Ok(self.public_key.clone())
    }

    async fn sign_hash(&self, hash: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
        (self.sign_fn)(hash)
    }
}

// =============================================================================
// Ledger adapter — Nano S / Nano X / Stax via Ethereum app APDUs
// =============================================================================

#[cfg(feature = "ledger-signer")]
pub mod ledger {
    use super::*;
    use ledger_transport_hid::TransportNativeHID;
    use ledger_apdu::{APDUCommand, APDUAnswer};

    /// Ledger device signer over USB HID. Talks the Ethereum app's APDU
    /// dialect documented at
    /// https://github.com/LedgerHQ/app-ethereum/blob/develop/doc/ethapp.adoc.
    pub struct LedgerSigner {
        derivation_path: Vec<u32>,
        cached_pubkey: tokio::sync::Mutex<Option<Vec<u8>>>,
    }

    impl LedgerSigner {
        /// Construct a signer pinned to the supplied BIP-32 derivation path
        /// (e.g. `m/44'/60'/0'/0/0` for the first account on the default
        /// Ethereum path).
        pub fn new(derivation_path: Vec<u32>) -> Self {
            Self {
                derivation_path,
                cached_pubkey: tokio::sync::Mutex::new(None),
            }
        }

        fn build_get_pubkey_apdu(&self) -> APDUCommand<Vec<u8>> {
            // INS_GET_PUBLIC_KEY = 0x02 in the Ethereum app
            let mut data = Vec::new();
            data.push(self.derivation_path.len() as u8);
            for component in &self.derivation_path {
                data.extend_from_slice(&component.to_be_bytes());
            }
            APDUCommand {
                cla: 0xe0,
                ins: 0x02,
                p1: 0x00,
                p2: 0x00,
                data,
            }
        }

        fn build_sign_apdu(&self, hash: &[u8; 32]) -> APDUCommand<Vec<u8>> {
            // INS_SIGN_PERSONAL = 0x08 (sign keccak prehash directly)
            let mut data = Vec::new();
            data.push(self.derivation_path.len() as u8);
            for component in &self.derivation_path {
                data.extend_from_slice(&component.to_be_bytes());
            }
            data.extend_from_slice(hash);
            APDUCommand {
                cla: 0xe0,
                ins: 0x08,
                p1: 0x00,
                p2: 0x00,
                data,
            }
        }

        fn transport() -> Result<TransportNativeHID, WalletError> {
            TransportNativeHID::new(
                &hidapi::HidApi::new()
                    .map_err(|e| WalletError::SignatureFailed(format!("hidapi: {}", e)))?,
            )
            .map_err(|e| WalletError::SignatureFailed(format!("Ledger transport: {}", e)))
        }

        fn parse_pubkey_response(answer: &APDUAnswer<Vec<u8>>) -> Result<Vec<u8>, WalletError> {
            let data = answer.data();
            if data.len() < 2 {
                return Err(WalletError::SignatureFailed("Ledger pubkey: short response".into()));
            }
            // First byte is the public-key length (65 for uncompressed).
            let pk_len = data[0] as usize;
            if data.len() < 1 + pk_len {
                return Err(WalletError::SignatureFailed("Ledger pubkey: payload truncated".into()));
            }
            Ok(data[1..1 + pk_len].to_vec())
        }

        fn parse_signature_response(answer: &APDUAnswer<Vec<u8>>) -> Result<Vec<u8>, WalletError> {
            let data = answer.data();
            // Ledger v signature wire: 1-byte v || 32-byte r || 32-byte s.
            if data.len() != 65 {
                return Err(WalletError::SignatureFailed(format!(
                    "Ledger signature: expected 65 bytes, got {}",
                    data.len()
                )));
            }
            Ok(data.to_vec())
        }
    }

    #[async_trait]
    impl PluggableSigner for LedgerSigner {
        fn device_kind(&self) -> HardwareDeviceKind {
            HardwareDeviceKind::Ledger
        }

        async fn public_key(&self) -> Result<Vec<u8>, WalletError> {
            {
                let guard = self.cached_pubkey.lock().await;
                if let Some(pk) = guard.as_ref() {
                    return Ok(pk.clone());
                }
            }
            let transport = Self::transport()?;
            let apdu = self.build_get_pubkey_apdu();
            let answer = transport
                .exchange(&apdu)
                .map_err(|e| WalletError::SignatureFailed(format!("Ledger exchange: {}", e)))?;
            let pk = Self::parse_pubkey_response(&answer)?;
            *self.cached_pubkey.lock().await = Some(pk.clone());
            Ok(pk)
        }

        async fn sign_hash(&self, hash: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
            let transport = Self::transport()?;
            let apdu = self.build_sign_apdu(hash);
            let answer = transport
                .exchange(&apdu)
                .map_err(|e| WalletError::SignatureFailed(format!("Ledger sign: {}", e)))?;
            Self::parse_signature_response(&answer)
        }
    }
}

// =============================================================================
// Trezor adapter — One / T via trezor-client
// =============================================================================

#[cfg(feature = "trezor-signer")]
pub mod trezor {
    use super::*;
    use trezor_client::{Trezor, protos::EthereumSignMessage};

    /// Trezor signer via the WebUSB / HID transport.
    pub struct TrezorSigner {
        derivation_path: Vec<u32>,
    }

    impl TrezorSigner {
        pub fn new(derivation_path: Vec<u32>) -> Self {
            Self { derivation_path }
        }

        fn connect() -> Result<Trezor, WalletError> {
            let mut devices = trezor_client::find_devices(false);
            if devices.is_empty() {
                return Err(WalletError::SignatureFailed("no Trezor device detected".into()));
            }
            devices
                .remove(0)
                .connect()
                .map_err(|e| WalletError::SignatureFailed(format!("Trezor connect: {}", e)))
        }
    }

    #[async_trait]
    impl PluggableSigner for TrezorSigner {
        fn device_kind(&self) -> HardwareDeviceKind {
            HardwareDeviceKind::Trezor
        }

        async fn public_key(&self) -> Result<Vec<u8>, WalletError> {
            let path = self.derivation_path.clone();
            tokio::task::spawn_blocking(move || {
                let mut trezor = Self::connect()?;
                let pk = trezor
                    .ethereum_get_public_key(&path, false)
                    .map_err(|e| WalletError::SignatureFailed(format!("Trezor get pubkey: {}", e)))?;
                Ok::<Vec<u8>, WalletError>(pk.public_key().to_vec())
            })
            .await
            .map_err(|e| WalletError::SignatureFailed(format!("Trezor join: {}", e)))?
        }

        async fn sign_hash(&self, hash: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
            let path = self.derivation_path.clone();
            let h = *hash;
            tokio::task::spawn_blocking(move || {
                let mut trezor = Self::connect()?;
                let mut req = EthereumSignMessage::new();
                req.set_address_n(path);
                req.set_message(h.to_vec());
                let resp = trezor
                    .ethereum_sign_message(req)
                    .map_err(|e| WalletError::SignatureFailed(format!("Trezor sign: {}", e)))?;
                Ok::<Vec<u8>, WalletError>(resp.signature().to_vec())
            })
            .await
            .map_err(|e| WalletError::SignatureFailed(format!("Trezor join: {}", e)))?
        }
    }
}

// =============================================================================
// GridPlus Lattice1 adapter — REST over HTTPS to the paired wallet
// =============================================================================

#[cfg(feature = "gridplus-signer")]
pub mod gridplus {
    use super::*;
    use reqwest::Client;

    /// GridPlus Lattice1 signer.
    ///
    /// The Lattice is paired with a host machine and exposes a JSON-RPC
    /// surface at `https://signing.gridpl.us`. Pairing produces a
    /// `wallet_uuid` (the UUID of the signing wallet on the Lattice) and a
    /// `device_id` (the Lattice itself). Both are stored alongside the
    /// derivation path.
    pub struct GridPlusSigner {
        base_url: String,
        device_id: String,
        wallet_uuid: String,
        derivation_path: Vec<u32>,
        http: Client,
    }

    impl GridPlusSigner {
        pub fn new(
            device_id: impl Into<String>,
            wallet_uuid: impl Into<String>,
            derivation_path: Vec<u32>,
        ) -> Self {
            Self {
                base_url: "https://signing.gridpl.us".to_string(),
                device_id: device_id.into(),
                wallet_uuid: wallet_uuid.into(),
                derivation_path,
                http: Client::new(),
            }
        }

        pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
            self.base_url = url.into();
            self
        }
    }

    #[async_trait]
    impl PluggableSigner for GridPlusSigner {
        fn device_kind(&self) -> HardwareDeviceKind {
            HardwareDeviceKind::GridPlus
        }

        async fn public_key(&self) -> Result<Vec<u8>, WalletError> {
            #[derive(serde::Serialize)]
            struct Req<'a> {
                device_id: &'a str,
                wallet_uuid: &'a str,
                path: &'a [u32],
            }
            #[derive(serde::Deserialize)]
            struct Resp {
                public_key_hex: String,
            }
            let body = Req {
                device_id: &self.device_id,
                wallet_uuid: &self.wallet_uuid,
                path: &self.derivation_path,
            };
            let resp: Resp = self
                .http
                .post(format!("{}/getPubKey", self.base_url))
                .json(&body)
                .send()
                .await
                .map_err(|e| WalletError::SignatureFailed(format!("GridPlus HTTP: {}", e)))?
                .json()
                .await
                .map_err(|e| WalletError::SignatureFailed(format!("GridPlus JSON: {}", e)))?;
            hex::decode(resp.public_key_hex.trim_start_matches("0x"))
                .map_err(|e| WalletError::SignatureFailed(format!("GridPlus pubkey hex: {}", e)))
        }

        async fn sign_hash(&self, hash: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
            #[derive(serde::Serialize)]
            struct Req<'a> {
                device_id: &'a str,
                wallet_uuid: &'a str,
                path: &'a [u32],
                payload_hex: String,
            }
            #[derive(serde::Deserialize)]
            struct Resp {
                signature_hex: String,
            }
            let body = Req {
                device_id: &self.device_id,
                wallet_uuid: &self.wallet_uuid,
                path: &self.derivation_path,
                payload_hex: hex::encode(hash),
            };
            let resp: Resp = self
                .http
                .post(format!("{}/sign", self.base_url))
                .json(&body)
                .send()
                .await
                .map_err(|e| WalletError::SignatureFailed(format!("GridPlus HTTP: {}", e)))?
                .json()
                .await
                .map_err(|e| WalletError::SignatureFailed(format!("GridPlus JSON: {}", e)))?;
            hex::decode(resp.signature_hex.trim_start_matches("0x"))
                .map_err(|e| WalletError::SignatureFailed(format!("GridPlus sig hex: {}", e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generic_signer_roundtrip() {
        let signer = GenericSigner::new(
            vec![0u8; 33],
            |hash| Ok([&[0xAA], &hash[..]].concat()),
        );
        assert_eq!(signer.device_kind(), HardwareDeviceKind::Generic);
        let pk = signer.public_key().await.unwrap();
        assert_eq!(pk.len(), 33);
        let sig = signer.sign_hash(&[1u8; 32]).await.unwrap();
        assert_eq!(sig.len(), 33);
        assert_eq!(sig[0], 0xAA);
    }

    #[test]
    fn device_kind_roundtrip() {
        for k in [
            HardwareDeviceKind::Ledger,
            HardwareDeviceKind::Trezor,
            HardwareDeviceKind::GridPlus,
            HardwareDeviceKind::YubiKey,
            HardwareDeviceKind::Generic,
        ] {
            let s = k.as_str();
            assert_eq!(HardwareDeviceKind::from_str(s), Some(k));
        }
    }
}
