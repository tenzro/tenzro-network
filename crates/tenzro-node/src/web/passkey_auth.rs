//! Browser-launch passkey ceremony endpoints.
//!
//! Serves the WebAuthn half of the CLI login flow (gcloud-style device
//! authorization): `tenzro passkey login` creates a pending session over
//! JSON-RPC, opens `/auth/passkey?session=<id>` in the user's browser, the
//! page below runs `navigator.credentials.create()` / `get()` against the
//! session's challenge and posts the ceremony outcome back, and the CLI
//! polls `tenzro_getPasskeySession` until the session is terminal.
//!
//! Three endpoints on the public Web API (port 8080):
//!
//! - `GET  /auth/passkey` — HTML+JS ceremony page. Reads the session id
//!   from the `session` query parameter client-side. When the query
//!   parameter is present and well-formed, the server also renders an
//!   inline SVG QR code of the page's own URL so the user can hand the
//!   ceremony off to a phone (where the passkey usually lives). This is
//!   safe because the session is only claimed single-use at the
//!   completion POST — any number of devices may *view* the session;
//!   the first to complete wins and the page polls session state so the
//!   other devices learn the outcome.
//! - `GET  /auth/passkey/session/:id` — ceremony parameters for the page:
//!   kind, challenge, and (for `add`/`sign`) the account's enrolled
//!   credential ids so the page can populate
//!   `excludeCredentials`/`allowCredentials`. Never exposes CLI-supplied
//!   secrets (ML-DSA signatures stay server-side).
//! - `POST /auth/passkey/session/:id/complete` — accepts the browser
//!   payload and drives `passkey_rpc::complete_passkey_session`, which
//!   claims the session single-use and executes the underlying
//!   enroll/add/sign handler.
//!
//! The session id itself is the capability: 32 random bytes, 10-minute
//! TTL, single-use claim — the same trust model as an OAuth device code.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde_json::{Value, json};

use base64::Engine as _;

use super::handlers::WebState;
use crate::rpc::JsonRpcError;

/// Map a JSON-RPC error from the passkey layer onto an HTTP response.
fn rpc_error_response(e: JsonRpcError) -> Response {
    let status = match e.code {
        -32404 => StatusCode::NOT_FOUND,
        -32602 => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": e.message, "code": e.code }))).into_response()
}

fn node_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "node not attached to web server" })),
    )
        .into_response()
}

/// `GET /auth/passkey/session/:id` — ceremony parameters for the browser
/// page. Includes the challenge (the page needs it to run the ceremony)
/// and, for `add`/`sign` sessions, the enrolled credential ids on the
/// target account. Excludes everything else in `params` — in particular
/// a pre-signed ML-DSA signature never crosses to the browser.
pub async fn session_info(
    State(state): State<Arc<WebState>>,
    Path(session_id): Path<String>,
) -> Response {
    let Some(node) = state.node.as_ref() else {
        return node_unavailable();
    };
    let Some(store) = node.passkey_sessions() else {
        return node_unavailable();
    };
    let session = match store.get(&session_id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return rpc_error_response(JsonRpcError {
                code: -32404,
                message: "Unknown or swept auth session".to_string(),
                data: None,
            });
        }
        Err(e) => return rpc_error_response(e),
    };

    let mut info = json!({
        "session_id": session.session_id,
        "kind": session.kind,
        "status": session.status,
        "challenge_b64": session.challenge_b64,
        "expires_at_ms": session.expires_at_ms,
        "display_name": session.params.get("display_name"),
        "account_address": session.params.get("account_address"),
        "label": session.params.get("label"),
    });

    // Enrolled credential ids for allowCredentials (sign) /
    // excludeCredentials (add).
    if let Some(account_hex) = session
        .params
        .get("account_address")
        .and_then(Value::as_str)
        && let (Some(validator), Ok(account)) = (
            node.webauthn_validator(),
            hex::decode(account_hex.trim_start_matches("0x")),
        )
    {
        let ids: Vec<String> = validator
            .list_credentials(&account)
            .iter()
            .map(hex::encode)
            .collect();
        info["credential_ids_hex"] = json!(ids);

        // Adding a device is a custody change, so the page needs a second
        // challenge: the one an *already-enrolled* credential must sign to
        // prove the person adding the device owns the account. Issued here
        // rather than by the page so the digest is the node's, not the
        // browser's — a challenge a caller chose themselves proves nothing.
        //
        // The target is bound at completion time (the new credential id is
        // not known until `create()` runs), so this challenge is issued
        // against an empty target and the handler re-derives it. See
        // `CustodyOperation::AddPasskey`.
        if matches!(session.kind, crate::passkey_rpc::AuthSessionKind::Add) {
            let (challenge_id, digest) = node.custody_challenges().issue(
                &account,
                crate::passkey_rpc::CustodyOperation::AddPasskey,
                &[],
            );
            info["custody_challenge_id"] = json!(challenge_id);
            info["custody_challenge_b64"] =
                json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest));
        }
    }

    (StatusCode::OK, Json(info)).into_response()
}

/// `POST /auth/passkey/session/:id/complete` — browser posts the ceremony
/// outcome. Claims the session (single-use) and runs the underlying
/// enroll/add/sign handler; the result is persisted on the session row for
/// the CLI poller and also returned here so the page can render it.
pub async fn session_complete(
    State(state): State<Arc<WebState>>,
    Path(session_id): Path<String>,
    Json(payload): Json<Value>,
) -> Response {
    let Some(node) = state.node.as_ref() else {
        return node_unavailable();
    };
    match crate::passkey_rpc::complete_passkey_session(node, &session_id, payload).await {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({ "status": "completed", "result": result })),
        )
            .into_response(),
        Err(e) => rpc_error_response(e),
    }
}

/// `GET /auth/passkey` — the ceremony page. Session-specific ceremony
/// data is fetched client-side from the session-info endpoint using the
/// `session` query parameter; the server-side templating is the
/// device-handoff QR code (rendered when a well-formed session id is
/// present so the user can continue the ceremony on a phone) and the
/// WebAuthn RP ID.
///
/// The RP ID is injected server-side rather than derived in the page,
/// because no client-side heuristic gets it right: "last two labels" is
/// correct for `tenzro.xyz` and wrong for `network.tenzro.com`. It must
/// also match what the server verifies against
/// (`WebAuthnRelyingParty::RegistrableDomain`), and a credential minted
/// under the wrong RP ID is unusable rather than merely misconfigured.
/// Falls back to `location.hostname` (the browser default) when the node
/// has no registrable-domain RP ID configured.
pub async fn passkey_page(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    Query(query): Query<HashMap<String, String>>,
) -> Html<String> {
    let rp_id_block = {
        let configured = state
            .node
            .as_ref()
            .and_then(|node| node.webauthn_validator())
            .and_then(|v| match v.relying_party() {
                tenzro_crypto::webauthn::WebAuthnRelyingParty::RegistrableDomain { rp_id } => {
                    Some(rp_id.clone())
                }
                // An exact-origin policy pins one host, which is what
                // `location.hostname` already yields — no override needed.
                tenzro_crypto::webauthn::WebAuthnRelyingParty::Origin(_) => None,
            });
        match configured {
            Some(rp_id) => format!(
                "<script>window.__TENZRO_RP_ID = {};</script>",
                serde_json::Value::String(rp_id)
            ),
            None => String::new(),
        }
    };

    let qr_block = query
        .get("session")
        .filter(|sid| sid.len() == 64 && sid.bytes().all(|b| b.is_ascii_hexdigit()))
        .and_then(|sid| {
            let url = format!(
                "{}/auth/passkey?session={}",
                super::oauth::derive_base_url(&headers),
                sid
            );
            qrcode::QrCode::new(url.as_bytes()).ok()
        })
        .map(|code| {
            let svg = code
                .render::<qrcode::render::svg::Color>()
                .min_dimensions(168, 168)
                .quiet_zone(true)
                // `currentColor` for the modules and `transparent` for the
                // quiet zone lets one server-rendered SVG stay scannable in
                // both themes. The previous fixed pair was a light-on-dark
                // inversion that vanished against a light background — and an
                // unscannable QR silently breaks the phone hand-off, which is
                // the only path a user without a local authenticator has.
                .dark_color(qrcode::render::svg::Color("currentColor"))
                .light_color(qrcode::render::svg::Color("transparent"))
                .build();
            format!(
                "<div id=\"qr\">{}<p>Or scan with your phone to continue there.</p></div>",
                svg
            )
        })
        .unwrap_or_default();
    Html(
        PASSKEY_PAGE_HTML
            .replace("<!--QR-->", &qr_block)
            .replace("<!--RPID-->", &rp_id_block),
    )
}

const PASSKEY_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tenzro Passkey</title>
<style>
  /* Tenzro design language, ported from apps/tenzro-control/src/index.css.
     Monochrome with one indigo accent; 0px radius throughout is a deliberate
     brand choice, not an oversight. Fonts degrade to the system stack rather
     than fetching Geist — this page is served by a node that may have no
     outbound network, and a blocked font request must not delay a security
     ceremony. */
  :root {
    color-scheme: light dark;
    --bg: #ffffff;
    --fg: #0a0c12;
    --muted: #f2f3f5;
    --muted-fg: #5b6070;
    --border: #e3e5ea;
    --accent: #6b79aa;
    --ok: #2f7d55;
    --err: #b4331f;
    --radius: 0px;
    --font-sans: "Geist", ui-sans-serif, system-ui, -apple-system, sans-serif;
    --font-mono: "Geist Mono", ui-monospace, SFMono-Regular, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #000000;
      --fg: #ffffff;
      --muted: #14171f;
      --muted-fg: #8a8f9e;
      --border: #1c2030;
      --ok: #4ade80;
      --err: #f87171;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center;
    justify-content: center; padding: 1.5rem;
    background: var(--bg); color: var(--fg);
    font-family: var(--font-sans);
    -webkit-font-smoothing: antialiased;
  }
  .card {
    max-width: 26rem; width: 100%; padding: 2rem; border-radius: var(--radius);
    border: 1px solid var(--border); background: var(--bg);
  }
  .eyebrow {
    font-family: var(--font-mono); font-size: 0.6875rem; font-weight: 500;
    text-transform: uppercase; letter-spacing: 0.18em; color: var(--muted-fg);
    margin: 0 0 0.75rem;
  }
  h1 {
    font-size: 1.25rem; margin: 0 0 0.5rem; font-weight: 500;
    letter-spacing: -0.02em;
  }
  p { font-size: 0.9rem; line-height: 1.5; color: var(--muted-fg); margin: 0.5rem 0; }
  code {
    font-family: var(--font-mono); font-size: 0.8rem;
    color: var(--fg); word-break: break-all;
  }
  button {
    margin-top: 1.25rem; width: 100%; padding: 0.7rem 1rem;
    border-radius: var(--radius);
    border: 1px solid var(--fg); background: var(--fg); color: var(--bg);
    font-family: var(--font-sans); font-size: 0.9rem; font-weight: 500;
    cursor: pointer;
  }
  button:hover:not(:disabled) { opacity: 0.9; }
  button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  button:disabled { opacity: 0.4; cursor: default; }
  .ok { color: var(--ok); }
  .err { color: var(--err); }
  #qr { margin-top: 1.5rem; text-align: center; }
  #qr svg {
    border-radius: var(--radius); border: 1px solid var(--border);
    background: var(--bg); max-width: 100%; height: auto;
  }
  #qr p { font-size: 0.8rem; }
</style>
</head>
<body>
<div class="card">
  <p class="eyebrow">Tenzro</p>
  <h1 id="title">Passkey</h1>
  <p id="msg">Loading session&hellip;</p>
  <p id="detail"></p>
  <button id="go" hidden></button>
  <!--QR-->
</div>
<!--RPID-->
<script>
(() => {
  const $ = (id) => document.getElementById(id);
  const msg = (t, cls) => { const el = $('msg'); el.textContent = t; el.className = cls || ''; };
  const detail = (t) => { $('detail').innerHTML = t; };

  const b64urlToBytes = (s) => {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64 + '='.repeat((4 - b64.length % 4) % 4);
    return Uint8Array.from(atob(pad), (c) => c.charCodeAt(0));
  };
  const hexToBytes = (h) => {
    const s = h.replace(/^0x/, '');
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  };
  const bytesToHex = (buf) =>
    Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  const bytesToArray = (buf) => Array.from(new Uint8Array(buf));

  // The RP ID scopes the credential. Injected by the server when the node
  // uses a registrable-domain policy, so a passkey created while onboarding
  // one node authenticates at every other node under the same domain; when
  // absent, omitting rp.id/rpId lets the browser default to this exact
  // host, which is the correct behaviour for an origin-pinned node.
  const RP_ID = window.__TENZRO_RP_ID || null;
  const withRpId = (opts) => (RP_ID ? Object.assign({ rpId: RP_ID }, opts) : opts);

  const sessionId = new URLSearchParams(location.search).get('session');
  if (!sessionId) { msg('Missing session parameter in the URL.', 'err'); return; }
  if (!window.PublicKeyCredential) {
    msg('This browser does not support WebAuthn passkeys.', 'err'); return;
  }

  const infoUrl = `/auth/passkey/session/${encodeURIComponent(sessionId)}`;

  const extractP256 = (cred) => {
    // response.getPublicKey() returns SPKI DER; the SEC1 point is the
    // trailing 65 bytes and must start with 0x04 (uncompressed).
    const spki = new Uint8Array(cred.response.getPublicKey());
    const sec1 = spki.slice(spki.length - 65);
    if (sec1[0] !== 0x04) throw new Error('unexpected public-key encoding (want uncompressed P-256)');
    return bytesToHex(sec1);
  };

  const run = async (info) => {
    const challenge = b64urlToBytes(info.challenge_b64);
    if (info.kind === 'enroll' || info.kind === 'add') {
      const name = info.kind === 'add'
        ? (info.label || info.account_address || 'Tenzro account')
        : (info.display_name || 'Tenzro account');
      const opts = {
        challenge,
        rp: RP_ID ? { name: 'Tenzro', id: RP_ID } : { name: 'Tenzro' },
        user: {
          id: hexToBytes(info.session_id).slice(0, 16),
          name,
          displayName: name,
        },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        timeout: 120000,
      };
      if (info.kind === 'add' && Array.isArray(info.credential_ids_hex)) {
        opts.excludeCredentials = info.credential_ids_hex.map((h) => ({
          type: 'public-key', id: hexToBytes(h),
        }));
      }
      // Adding a device to an existing account is a custody change, so it
      // takes two ceremonies, in this order:
      //
      //   1. `get()` from a credential ALREADY on the account — proof the
      //      person doing this is the owner. Done first, so a user who cannot
      //      satisfy it is not asked to create a credential that would then
      //      be thrown away.
      //   2. `create()` for the new device.
      //
      // Without step 1 an add needed only the account address, which is a
      // public identifier — that was an unauthenticated takeover of any
      // account whose address you knew.
      let authorization = null;
      if (info.kind === 'add') {
        if (!info.custody_challenge_b64 || !info.custody_challenge_id) {
          throw new Error('this node did not issue a custody challenge; cannot add a device safely');
        }
        if (!Array.isArray(info.credential_ids_hex) || !info.credential_ids_hex.length) {
          throw new Error('no existing passkey on this account to authorise the addition');
        }
        msg('Confirm with a device already on this account…');
        const proof = await navigator.credentials.get({
          publicKey: withRpId({
            challenge: b64urlToBytes(info.custody_challenge_b64),
            allowCredentials: info.credential_ids_hex.map((h) => ({
              type: 'public-key', id: hexToBytes(h),
            })),
            userVerification: 'required',
            timeout: 120000,
          }),
        });
        const pr = proof.response;
        authorization = {
          challenge_id: info.custody_challenge_id,
          credential_id_hex: bytesToHex(proof.rawId),
          assertion: {
            authenticator_data: bytesToArray(pr.authenticatorData),
            client_data_json: bytesToArray(pr.clientDataJSON),
            signature: bytesToArray(pr.signature),
            user_handle: pr.userHandle ? bytesToArray(pr.userHandle) : null,
          },
        };
        msg('Now register the new device…');
      }
      const cred = await navigator.credentials.create({ publicKey: opts });
      const out = {
        credential_id_hex: bytesToHex(cred.rawId),
        passkey_public_key_hex: extractP256(cred),
      };
      if (authorization) out.authorization = authorization;
      return out;
    }
    // sign — the challenge IS the op hash.
    const opts = withRpId({
      challenge,
      userVerification: 'required',
      timeout: 120000,
    });
    if (Array.isArray(info.credential_ids_hex) && info.credential_ids_hex.length) {
      opts.allowCredentials = info.credential_ids_hex.map((h) => ({
        type: 'public-key', id: hexToBytes(h),
      }));
    }
    const cred = await navigator.credentials.get({ publicKey: opts });
    const r = cred.response;
    return {
      credential_id_hex: bytesToHex(cred.rawId),
      assertion: {
        authenticator_data: bytesToArray(r.authenticatorData),
        client_data_json: bytesToArray(r.clientDataJSON),
        signature: bytesToArray(r.signature),
        user_handle: r.userHandle ? bytesToArray(r.userHandle) : null,
      },
    };
  };

  // Another device (a phone that scanned the QR) may complete the
  // ceremony first. Poll session state so this page can report the
  // outcome instead of failing a doomed local attempt.
  let localDone = false;
  let poller = null;
  const stopPolling = () => { if (poller) { clearInterval(poller); poller = null; } };
  const hideQr = () => { const q = $('qr'); if (q) q.hidden = true; };
  const startPolling = () => {
    poller = setInterval(async () => {
      try {
        const res = await fetch(infoUrl);
        if (!res.ok) return;
        const s = await res.json();
        if (localDone || s.status === 'pending' || s.status === 'in_flight') return;
        stopPolling();
        hideQr();
        $('go').hidden = true;
        if (s.status === 'completed') {
          msg('Completed on another device. You can return to your terminal.', 'ok');
        } else {
          msg(`Session ${s.status} — start a new one from the CLI.`, 'err');
        }
      } catch (_) { /* transient network error — keep polling */ }
    }, 2500);
  };

  const start = async () => {
    const res = await fetch(infoUrl);
    const info = await res.json();
    if (!res.ok) throw new Error(info.error || `session lookup failed (${res.status})`);
    if (info.status !== 'pending') {
      hideQr();
      throw new Error(`session is ${info.status} — start a new one from the CLI`);
    }
    startPolling();

    const verbs = {
      enroll: 'Create a passkey to open your new Tenzro account.',
      add: `Add a passkey to account ${info.account_address || ''}.`,
      sign: `Approve the operation on account ${info.account_address || ''}.`,
    };
    msg(verbs[info.kind] || 'Ready.');
    const go = $('go');
    go.hidden = false;
    go.textContent = info.kind === 'sign' ? 'Use passkey to approve' : 'Create passkey';
    go.onclick = async () => {
      go.disabled = true;
      msg('Waiting for your authenticator…');
      try {
        const payload = await run(info);
        msg('Submitting to the node…');
        const done = await fetch(`${infoUrl}/complete`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const body = await done.json();
        if (!done.ok) throw new Error(body.error || `completion failed (${done.status})`);
        localDone = true;
        stopPolling();
        hideQr();
        msg('Done. You can return to your terminal.', 'ok');
        const acct = body.result && (body.result.account_address || body.result.accountAddress);
        if (acct) detail(`Account: <code>${acct}</code>`);
        go.hidden = true;
      } catch (e) {
        msg(e.message || String(e), 'err');
        go.disabled = false;
      }
    };
  };

  start().catch((e) => msg(e.message || String(e), 'err'));
})();
</script>
</body>
</html>
"#;
