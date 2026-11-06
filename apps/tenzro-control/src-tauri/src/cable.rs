//! FIDO caBLE (Cloud-Assisted BLE, a.k.a. "hybrid transport") — cross-device
//! passkey ceremonies driven by `webauthn-authenticator-rs`.
//!
//! Spec §15.10.4: the desktop runs `connect_cable_authenticator()`, the
//! authenticator side (the user's phone) scans the QR string we emit, the two
//! peers complete a Noise handshake over a tunnel server + BLE advertisement,
//! and we receive a CTAP2 assertion. The private key never leaves the phone's
//! Secure Enclave / StrongBox / TEE.
//!
//! This module hides the lifecycle behind a two-call Tauri shape:
//!  1. `device_start_cross_device_link` returns `{session_id, qr_url}`
//!     immediately. The frontend renders `qr_url` and shows it to the user.
//!  2. `device_complete_cross_device_link(session_id, challenge, rp_id)`
//!     awaits the actual CTAP2 GetAssertion that the phone delivers, then
//!     returns the raw `authenticator_data || signature || client_data_json`
//!     so the JS wallet layer can place it in a passkey signature.
//!
//! The CTAP2 ceremony itself happens on a background `spawn_blocking` task —
//! `webauthn-authenticator-rs`'s `AuthenticatorBackend::perform_auth` is a sync
//! trait method, so we must keep it off the async runtime's worker threads.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use url::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::cable::connect_cable_authenticator;
use webauthn_authenticator_rs::error::WebauthnCError;
use webauthn_authenticator_rs::types::{CableRequestType, CableState, EnrollSampleStatus};
use webauthn_authenticator_rs::ui::UiCallback;
use webauthn_authenticator_rs::AuthenticatorBackend;
use webauthn_rs_proto::{
    AllowCredentials, PublicKeyCredential, PublicKeyCredentialRequestOptions,
    UserVerificationPolicy,
};

/// Maximum time we wait for the phone to scan the QR + complete CTAP2.
/// FIDO caBLE in practice is a 30–60s ceremony.
const CABLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Sent into the channel by `TauriUiCallback::cable_qr_code` when the
/// underlying authenticator emits the QR URL.
#[derive(Debug, Clone)]
pub enum UiEvent {
    QrCode(String),
    QrDismissed,
    StatusUpdate(String),
    NeedsTouch,
    Processing,
}

/// A `UiCallback` implementation that funnels every authenticator UI signal
/// into a tokio mpsc channel. The Tauri command side `recv()`s from this to
/// extract the QR URL synchronously without blocking the CTAP IO.
#[derive(Debug)]
pub struct TauriUiCallback {
    tx: mpsc::UnboundedSender<UiEvent>,
}

impl TauriUiCallback {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<UiEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

impl UiCallback for TauriUiCallback {
    fn request_pin(&self) -> Option<String> {
        // caBLE does not solicit a PIN from the desktop — the phone collects
        // user verification (biometric / PIN) locally. Returning None tells
        // the authenticator stack the desktop has nothing to contribute.
        None
    }

    fn request_touch(&self) {
        let _ = self.tx.send(UiEvent::NeedsTouch);
    }

    fn fingerprint_enrollment_feedback(
        &self,
        _remaining_samples: u32,
        _feedback: Option<EnrollSampleStatus>,
    ) {
        // Not applicable to caBLE GetAssertion.
    }

    fn cable_qr_code(&self, _request_type: CableRequestType, url: String) {
        let _ = self.tx.send(UiEvent::QrCode(url));
    }

    fn dismiss_qr_code(&self) {
        let _ = self.tx.send(UiEvent::QrDismissed);
    }

    fn cable_status_update(&self, state: CableState) {
        let _ = self.tx.send(UiEvent::StatusUpdate(format!("{:?}", state)));
    }

    fn processing(&self) {
        let _ = self.tx.send(UiEvent::Processing);
    }
}

/// The opaque CTAP2 assertion blob we hand back to JS once the phone signs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CableAssertion {
    pub credential_id_hex: String,
    pub authenticator_data_hex: String,
    pub signature_hex: String,
    pub client_data_json: String,
    /// Optional user-handle (uuid) — present iff the credential is
    /// discoverable / resident on the authenticator.
    pub user_handle_hex: Option<String>,
}

/// Internal request the foreground command sends into a session task once it
/// has the challenge + rp_id from the JS side.
struct AuthRequest {
    challenge: Vec<u8>,
    rp_id: String,
    allow_credential_ids: Vec<Vec<u8>>,
    timeout_ms: u32,
    respond_to: oneshot::Sender<Result<CableAssertion, String>>,
}

/// One outstanding caBLE session. Holds the request sender (so the
/// `complete` call can forward auth params).
struct Session {
    request_tx: oneshot::Sender<AuthRequest>,
}

/// Tauri-state-friendly session registry. Keyed by UUID `session_id`.
pub struct CableSessionManager {
    sessions: Mutex<HashMap<String, Session>>,
}

impl CableSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Start a caBLE GetAssertion ceremony. Spawns a background tokio task
    /// that calls `connect_cable_authenticator` + waits for the phone, then
    /// blocks on a oneshot for the eventual `AuthRequest` carrying the
    /// challenge. Returns `(session_id, qr_url)` as soon as the QR is up.
    pub async fn start(&self) -> Result<(String, String), String> {
        let session_id = Uuid::new_v4().to_string();
        let (request_tx, request_rx) = oneshot::channel::<AuthRequest>();
        let (cb, mut ui_rx) = TauriUiCallback::new();

        // QR-arrival signal: the connect task pushes the URL through here.
        let (qr_tx, qr_rx) = oneshot::channel::<Result<String, String>>();

        let session_id_for_task = session_id.clone();
        tauri::async_runtime::spawn(async move {
            tracing::info!(session_id = %session_id_for_task, "caBLE: spawning connect task");

            // The authenticator handle is borrowed-from-`cb`, so we keep `cb`
            // pinned in this task for its entire lifetime.
            let cb = cb;
            let connect_fut = connect_cable_authenticator(CableRequestType::GetAssertion, &cb);

            // Race the connect future against the timeout while listening
            // for the cable_qr_code event so we can hand the URL back to the
            // command before the phone has scanned anything.
            tokio::pin!(connect_fut);

            let mut qr_tx = Some(qr_tx);

            // Pump UI events until either: (a) connect_fut resolves with
            // an authenticator, (b) timeout, or (c) the channel closes.
            let auth = loop {
                tokio::select! {
                    biased;

                    res = &mut connect_fut => {
                        match res {
                            Ok(a) => break a,
                            Err(e) => {
                                let msg = format!("connect_cable_authenticator failed: {:?}", e);
                                if let Some(tx) = qr_tx.take() {
                                    let _ = tx.send(Err(msg.clone()));
                                }
                                tracing::error!(session_id = %session_id_for_task, "{}", msg);
                                return;
                            }
                        }
                    }

                    evt = ui_rx.recv() => {
                        match evt {
                            Some(UiEvent::QrCode(url)) => {
                                tracing::info!(session_id = %session_id_for_task, "caBLE: QR URL emitted");
                                if let Some(tx) = qr_tx.take() {
                                    let _ = tx.send(Ok(url));
                                }
                            }
                            Some(UiEvent::QrDismissed) => {
                                tracing::debug!(session_id = %session_id_for_task, "caBLE: QR dismissed");
                            }
                            Some(UiEvent::StatusUpdate(s)) => {
                                tracing::debug!(session_id = %session_id_for_task, status = %s, "caBLE: state");
                            }
                            Some(UiEvent::NeedsTouch) | Some(UiEvent::Processing) => {}
                            None => {
                                // Channel closed before connect resolved
                                tracing::warn!(session_id = %session_id_for_task, "caBLE: UI channel closed");
                            }
                        }
                    }

                    _ = tokio::time::sleep(CABLE_TIMEOUT) => {
                        let msg = format!("caBLE timed out after {:?}", CABLE_TIMEOUT);
                        if let Some(tx) = qr_tx.take() {
                            let _ = tx.send(Err(msg.clone()));
                        }
                        tracing::warn!(session_id = %session_id_for_task, "{}", msg);
                        return;
                    }
                }
            };

            // Phone connected. Wait for the foreground `complete` call to
            // deliver the auth parameters (challenge, rp_id, credential ids).
            let req = match request_rx.await {
                Ok(r) => r,
                Err(_) => {
                    tracing::warn!(session_id = %session_id_for_task, "caBLE: complete-call dropped");
                    return;
                }
            };

            // `perform_auth` is a sync trait method, but the `auth` handle
            // borrows from `cb`, so we cannot move it onto a `spawn_blocking`
            // thread. Run it directly on this task — the call is short-lived
            // (a single CTAP2 GetAssertion round-trip over the established
            // tunnel) and the tokio runtime will recover if it briefly blocks.
            let AuthRequest {
                challenge,
                rp_id,
                allow_credential_ids,
                timeout_ms,
                respond_to,
            } = req;

            let mut auth = auth;
            let result: Result<CableAssertion, String> = (|| -> Result<CableAssertion, String> {
                let origin = Url::parse(&format!("https://{}", rp_id))
                    .map_err(|e| format!("invalid rp_id: {}", e))?;

                let allow_credentials: Vec<AllowCredentials> = allow_credential_ids
                    .into_iter()
                    .map(|id| AllowCredentials {
                        type_: "public-key".to_string(),
                        id,
                        transports: None,
                    })
                    .collect();

                let options = PublicKeyCredentialRequestOptions {
                    challenge,
                    timeout: Some(timeout_ms),
                    rp_id: rp_id.clone(),
                    allow_credentials,
                    user_verification: UserVerificationPolicy::Required,
                    hints: None,
                    extensions: None,
                };

                let cred: PublicKeyCredential = auth
                    .perform_auth(origin, options, timeout_ms)
                    .map_err(|e: WebauthnCError| format!("perform_auth failed: {:?}", e))?;

                let user_handle_hex = cred
                    .response
                    .user_handle
                    .as_ref()
                    .map(hex::encode);

                Ok(CableAssertion {
                    credential_id_hex: hex::encode(&cred.raw_id),
                    authenticator_data_hex: hex::encode(&cred.response.authenticator_data),
                    signature_hex: hex::encode(&cred.response.signature),
                    client_data_json: String::from_utf8(cred.response.client_data_json.clone())
                        .map_err(|e| format!("clientDataJSON not UTF-8: {}", e))?,
                    user_handle_hex,
                })
            })();

            let _ = respond_to.send(result);
        });

        // Block (asynchronously) until the spawned task emits the QR URL.
        let qr_url = match qr_rx.await {
            Ok(Ok(url)) => url,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err("caBLE connect task exited before emitting QR".into()),
        };

        // Stash the request_tx for the matching `complete` call.
        {
            let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
            sessions.insert(session_id.clone(), Session { request_tx });
        }

        Ok((session_id, qr_url))
    }

    /// Complete the ceremony by delivering the actual auth parameters and
    /// awaiting the CTAP2 assertion the phone signs.
    pub async fn complete(
        &self,
        session_id: &str,
        challenge: Vec<u8>,
        rp_id: String,
        allow_credential_ids: Vec<Vec<u8>>,
    ) -> Result<CableAssertion, String> {
        // Yank the session out of the map atomically — we own the request_tx
        // from here on.
        let session = {
            let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
            sessions.remove(session_id).ok_or_else(|| {
                format!("no active caBLE session for id {}", session_id)
            })?
        };

        let (respond_tx, respond_rx) = oneshot::channel::<Result<CableAssertion, String>>();

        session
            .request_tx
            .send(AuthRequest {
                challenge,
                rp_id,
                allow_credential_ids,
                timeout_ms: 60_000,
                respond_to: respond_tx,
            })
            .map_err(|_| "caBLE connect task no longer alive".to_string())?;

        match respond_rx.await {
            Ok(r) => r,
            Err(_) => Err("caBLE connect task dropped the response channel".into()),
        }
    }

    /// Discard a session without completing it (user cancelled the QR).
    pub fn cancel(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        sessions.remove(session_id);
        Ok(())
    }
}

impl Default for CableSessionManager {
    fn default() -> Self {
        Self::new()
    }
}
