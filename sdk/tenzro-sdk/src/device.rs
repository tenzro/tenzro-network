//! Devices bound to a Tenzro identity, and machine ownership.
//!
//! A Tenzro identity links devices the way a platform account does, except the
//! link is not a platform account. No Apple, Google or Microsoft sign-in is an
//! identity authority here: what the node trusts is a WebAuthn attestation it
//! verifies to a vendor root it pins, so "hardware-bound" is a fact the device
//! proved rather than a claim its cloud account made.
//!
//! A wallet cannot sit behind one device. [`DeviceClient::wallet_readiness`]
//! reports whether a second bound device exists yet, and names the remedy when
//! it does not.

use crate::error::SdkResult;
use crate::passkey_client::{CustodyChallengeParams, CustodyChallengeResponse, CustodyOperation};
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// A WebAuthn assertion from a device bound to an identity, over a custody
/// challenge's `webauthn_challenge`. Every field is base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAssertion {
    /// The asserting credential's id.
    pub credential_id: String,
    /// `authenticatorData`.
    pub authenticator_data_b64: String,
    /// `clientDataJSON`.
    pub client_data_json_b64: String,
    /// The DER signature.
    pub signature_b64: String,
}

/// A `tenzro_bindDevice` request: a WebAuthn registration over a
/// `bind_device` challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindDeviceRequest {
    /// The identity the device joins.
    pub identity_did: String,
    /// The device's label; the challenge's target.
    pub label: String,
    /// The attestation object from `navigator.credentials.create()`, base64.
    pub attestation_object_b64: String,
    /// The registration's `clientDataJSON`, base64.
    pub client_data_json_b64: String,
    /// The answered challenge.
    pub challenge_id: String,
    /// An assertion from a device already bound; required for every device
    /// after the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<DeviceAssertion>,
}

/// One bound device, as the node graded its attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundDevice {
    /// The credential id.
    pub credential_id: String,
    /// The label it was bound with.
    #[serde(default)]
    pub label: String,
    /// Authenticator model, hex.
    #[serde(default)]
    pub aaguid: Option<String>,
    /// Whether the key is proven to live in hardware.
    #[serde(default)]
    pub hardware_bound: Option<bool>,
    /// `packed`, `tpm`, `apple`, `none` and so on.
    pub attestation_format: String,
    /// The key protection tier the attestation proved.
    pub key_protection: String,
    /// Whether the attestation chain reached a pinned vendor root.
    pub chain_verified: bool,
    /// Whether the credential may sync to a cloud account.
    pub backup_eligible: bool,
    /// Whether it has.
    #[serde(default)]
    pub backed_up: Option<bool>,
    /// The authenticator's signature counter.
    #[serde(default)]
    pub sign_count: Option<u64>,
    /// When it was bound, Unix milliseconds.
    #[serde(default)]
    pub bound_at_ms: Option<u64>,
}

/// `tenzro_listBoundDevices`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundDevices {
    /// The identity.
    pub identity_did: String,
    /// Devices bound.
    pub count: u64,
    /// Distinct custody roots among them.
    pub independent_roots: u64,
    /// Devices whose key is proven to be in hardware.
    pub hardware_bound_count: u64,
    /// Whether a wallet may be created.
    pub wallet_ready: bool,
    /// Why not, when it may not.
    pub wallet_blocker: Option<String>,
    /// The devices.
    pub devices: Vec<BoundDevice>,
}

/// `tenzro_revokeBoundDevice`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRevocation {
    /// The identity.
    pub identity_did: String,
    /// The unbound credential.
    pub credential_id: String,
    /// Whether it was bound.
    pub removed: bool,
    /// Sessions it had authorised, now ended.
    pub sessions_ended: u64,
    /// Devices still bound.
    pub devices_remaining: u64,
    /// Distinct custody roots among them.
    pub independent_roots: u64,
    /// Whether a wallet may still be created.
    pub wallet_ready: bool,
}

/// `tenzro_walletReadiness`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletReadiness {
    /// The identity.
    pub identity_did: String,
    /// Whether a wallet may be created.
    pub ready: bool,
    /// Why not.
    pub blocker: Option<String>,
    /// What to do: `bind_second_device` or `bind_independent_device`.
    pub remedy: Option<String>,
    /// Devices bound.
    pub bound_devices: u64,
    /// Distinct custody roots.
    pub independent_roots: u64,
    /// Devices proven to be hardware-bound.
    pub hardware_bound_devices: u64,
}

/// Who authorises a machine transfer.
#[derive(Debug, Clone)]
pub enum TransferAuthority {
    /// The current controller, by an assertion from one of its bound devices.
    Controller {
        /// The controller DID.
        controller_did: String,
        /// The assertion over the challenge.
        authorization: DeviceAssertion,
    },
    /// The machine itself, by its registered key's signature over the
    /// challenge digest (hex), for a machine nobody delegated.
    MachineKey {
        /// The signature, hex.
        machine_signature_hex: String,
    },
}

/// Device-binding and machine-ownership client.
#[derive(Clone)]
pub struct DeviceClient {
    rpc: Arc<RpcClient>,
}

impl DeviceClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// The single-use custody challenge a device change answers:
    /// `bind_device` for `(identity_did, label)`, `revoke_device` for
    /// `(identity_did, credential_id)`, `transfer_machine_ownership` for
    /// `(machine_did, new_owner_did)`. A registration (binding) signs
    /// `challenge_hex` as its WebAuthn challenge; an assertion from a bound
    /// device signs `webauthn_challenge`.
    pub async fn challenge(
        &self,
        operation: CustodyOperation,
        account_did: &str,
        target: &str,
    ) -> SdkResult<CustodyChallengeResponse> {
        self.rpc
            .call(
                "tenzro_createCustodyChallenge",
                serde_json::to_value(CustodyChallengeParams {
                    account_address: hex::encode(account_did.as_bytes()),
                    operation,
                    target_hex: Some(hex::encode(target.as_bytes())),
                })?,
            )
            .await
    }

    /// Bind a device to an identity from a WebAuthn registration made over a
    /// `bind_device` challenge for `(identity_did, label)`.
    ///
    /// The node parses and grades the attestation against the vendor roots
    /// it pins: a device whose key is not in hardware, or whose credential can
    /// sync to a cloud account, is refused with the reason. The first device
    /// must be the identity's own passkey; another needs `authorization`, an
    /// assertion from a device already bound.
    pub async fn bind_device(&self, request: &BindDeviceRequest) -> SdkResult<BoundDevice> {
        self.rpc
            .call("tenzro_bindDevice", serde_json::to_value(request)?)
            .await
    }

    /// The devices that can authenticate as an identity, with what each one
    /// proved about its hardware.
    pub async fn list_bound_devices(&self, identity_did: &str) -> SdkResult<BoundDevices> {
        self.rpc
            .call(
                "tenzro_listBoundDevices",
                serde_json::json!({ "identity_did": identity_did }),
            )
            .await
    }

    /// Unbind a device and end every session it authorised, in one action.
    /// `authorization` is an assertion from a bound device over a
    /// `revoke_device` challenge for `(identity_did, credential_id)`.
    pub async fn revoke_bound_device(
        &self,
        identity_did: &str,
        credential_id: &str,
        challenge_id: &str,
        authorization: &DeviceAssertion,
    ) -> SdkResult<DeviceRevocation> {
        self.rpc
            .call(
                "tenzro_revokeBoundDevice",
                serde_json::json!({
                    "identity_did": identity_did,
                    "credential_id": credential_id,
                    "challenge_id": challenge_id,
                    "authorization": authorization,
                }),
            )
            .await
    }

    /// Whether a wallet may be created for this identity, and if not, why.
    ///
    /// Read before offering wallet creation so the user is told what to do,
    /// "scan the pairing QR with your phone", rather than shown a button that
    /// fails. A wallet cannot sit behind a single device.
    pub async fn wallet_readiness(
        &self,
        identity_did: &str,
        this_device_credential_id: Option<&str>,
    ) -> SdkResult<WalletReadiness> {
        self.rpc
            .call(
                "tenzro_walletReadiness",
                serde_json::json!({
                    "identity_did": identity_did,
                    "this_device_credential_id": this_device_credential_id,
                }),
            )
            .await
    }

    /// Move a machine to another identity, answering a
    /// `transfer_machine_ownership` challenge for `(machine_did,
    /// new_owner_did)`.
    ///
    /// [`TransferAuthority::Controller`] carries an assertion from a device
    /// bound to the controller of a machine a party delegated;
    /// [`TransferAuthority::MachineKey`] the machine's own signature over the
    /// challenge, for a machine nobody delegated. The two are not
    /// interchangeable: holding the hardware cannot take a machine that has an
    /// accountable party.
    pub async fn transfer_machine_ownership(
        &self,
        machine_did: &str,
        new_owner_did: &str,
        challenge_id: &str,
        authority: &TransferAuthority,
    ) -> SdkResult<Value> {
        let mut params = serde_json::json!({
            "machine_did": machine_did,
            "new_owner_did": new_owner_did,
            "challenge_id": challenge_id,
        });
        match authority {
            TransferAuthority::Controller {
                controller_did,
                authorization,
            } => {
                params["authority"] = "controller".into();
                params["controller_did"] = controller_did.as_str().into();
                params["authorization"] = serde_json::to_value(authorization)?;
            }
            TransferAuthority::MachineKey {
                machine_signature_hex,
            } => {
                params["authority"] = "machine_key".into();
                params["machine_signature_hex"] = machine_signature_hex.as_str().into();
            }
        }
        self.rpc
            .call("tenzro_transferMachineOwnership", params)
            .await
    }

    /// The rails a payment can settle on, and what the smallest worthwhile
    /// payment is on each.
    ///
    /// Read this before declaring a settlement asset. Supporting x402 and being
    /// able to carry a micropayment are different properties: Base speaks x402
    /// and still cannot carry a one-cent charge without ~10% overhead.
    pub async fn settlement_networks(&self) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_settlementNetworks", serde_json::json!({}))
            .await
    }

    /// Ask where a specific charge would settle: accumulate below the
    /// micro-settlement floor, settle on the Tenzro Ledger, settle on a
    /// secondary rail, or no viable rail for the payee's asset.
    ///
    /// `tnzo_micro_usd` is needed to compare a TNZO amount against a rail's
    /// fee. Omit it and the node settles on the home chain rather than routing
    /// real money on a guessed exchange rate.
    pub async fn route_payment(
        &self,
        amount_wei: &str,
        asset: Option<&str>,
        tnzo_micro_usd: Option<u64>,
    ) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_settlementNetworks",
                serde_json::json!({
                    "amount_wei": amount_wei,
                    "asset": asset,
                    "tnzo_micro_usd": tnzo_micro_usd,
                }),
            )
            .await
    }
}
