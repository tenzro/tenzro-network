//! HTML template for the OAuth authorization page.
//! Matches the Tenzro website design language: olive monochromatic OKLCH palette,
//! Inter font, sharp borders (no radius), minimal and geometric.

/// What the consent page shows and the passkey ceremony it runs.
pub struct ConsentPage<'a> {
    /// `client_name` from the client's metadata document.
    pub client_name: &'a str,
    /// The client's metadata document URL, shown so the user sees which
    /// host is asking, not only the name it chose for itself.
    pub client_id: &'a str,
    pub scope: &'a str,
    pub session_token: &'a str,
    /// base64url challenge the passkey signs.
    pub challenge_b64: &'a str,
    /// WebAuthn relying party ID for `navigator.credentials.get`.
    pub rp_id: &'a str,
}

/// Renders the OAuth consent page. Approving runs a WebAuthn assertion with
/// user verification over the request's challenge and posts it with the
/// form; denying posts no credential.
pub fn render_authorize_page(page: &ConsentPage<'_>) -> String {
    let scope_tags: String = page
        .scope
        .split_whitespace()
        .map(|s| format!(r#"<span class="scope-tag">{}</span>"#, html_escape(s)))
        .collect::<Vec<_>>()
        .join("\n                        ");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize — Tenzro Network</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, sans-serif;
            background: oklch(0.988 0.001 106.5);
            color: oklch(0.200 0.020 106.5);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
        }}
        ::selection {{
            background-color: oklch(0.640 0.080 106.5 / 0.25);
        }}
        .container {{
            width: 100%;
            max-width: 440px;
        }}
        .card {{
            background: oklch(0.970 0.002 106.5);
            border: 1px solid oklch(0.930 0.006 106.5);
            padding: 2.5rem;
        }}
        .logo {{
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 2rem;
        }}
        .logo span {{
            color: oklch(0.530 0.075 106.5);
        }}
        h1 {{
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            letter-spacing: -0.01em;
        }}
        .subtitle {{
            color: oklch(0.440 0.060 106.5);
            font-size: 0.875rem;
            margin-bottom: 2rem;
            line-height: 1.6;
        }}
        .subtitle strong {{
            color: oklch(0.200 0.020 106.5);
        }}
        .info-box {{
            background: oklch(0.988 0.001 106.5);
            border: 1px solid oklch(0.930 0.006 106.5);
            padding: 1rem 1.25rem;
            margin-bottom: 1.5rem;
            font-size: 0.8125rem;
            color: oklch(0.440 0.060 106.5);
            line-height: 1.6;
        }}
        .detail {{
            border-top: 1px solid oklch(0.930 0.006 106.5);
            padding-top: 1.25rem;
            margin-bottom: 1.5rem;
        }}
        .detail-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }}
        .detail-label {{
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: oklch(0.440 0.060 106.5);
        }}
        .detail-value {{
            font-size: 0.875rem;
            font-weight: 500;
        }}
        .scopes {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}
        .scope-tag {{
            font-size: 0.75rem;
            font-weight: 500;
            padding: 0.25rem 0.75rem;
            border: 1px solid oklch(0.880 0.012 106.5);
            background: oklch(0.988 0.001 106.5);
        }}
        .actions {{
            display: flex;
            gap: 0.75rem;
            margin-top: 1.5rem;
        }}
        .btn {{
            flex: 1;
            padding: 0.75rem 1.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            font-family: inherit;
            cursor: pointer;
            border: none;
            transition: background-color 200ms, border-color 200ms;
        }}
        .btn-primary {{
            background: oklch(0.200 0.020 106.5);
            color: oklch(0.988 0.001 106.5);
        }}
        .btn-primary:hover {{
            background: oklch(0.280 0.030 106.5);
        }}
        .btn-secondary {{
            background: oklch(0.988 0.001 106.5);
            color: oklch(0.200 0.020 106.5);
            border: 1px solid oklch(0.880 0.012 106.5);
        }}
        .btn-secondary:hover {{
            background: oklch(0.970 0.002 106.5);
        }}
        .footer {{
            text-align: center;
            margin-top: 1.5rem;
            font-size: 0.75rem;
            color: oklch(0.440 0.060 106.5);
        }}
        .footer a {{
            color: oklch(0.530 0.075 106.5);
            text-decoration: none;
        }}
        .footer a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="logo">tenzro<span>.</span></div>
            <h1>Authorize Application</h1>
            <p class="subtitle">
                <strong>{client_name}</strong> is requesting access to your
                Tenzro Network account.
            </p>

            <div class="info-box">
                Sign in with the passkey enrolled on your Tenzro account to
                approve. The application gets its own identity acting on your
                behalf, which you can revoke at any time.
            </div>

            <div class="detail">
                <div class="detail-row">
                    <span class="detail-label">Application</span>
                    <span class="detail-value">{client_name}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Client</span>
                    <span class="detail-value">{client_id}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Permissions</span>
                    <div class="scopes">
                        {scope_tags}
                    </div>
                </div>
            </div>

            <form id="consent" method="POST" action="/authorize">
                <input type="hidden" name="session_token" value="{session_token}" />
                <input type="hidden" name="action" id="action" value="deny" />
                <input type="hidden" name="credential_id" id="credential_id" />
                <input type="hidden" name="authenticator_data" id="authenticator_data" />
                <input type="hidden" name="client_data_json" id="client_data_json" />
                <input type="hidden" name="signature" id="signature" />
                <label class="detail-label" for="account_address">Account address</label>
                <input class="detail-value" type="text" name="account_address" id="account_address"
                       placeholder="0x..." autocomplete="username webauthn" />
                <label class="detail-label" for="ml_dsa_signature">ML-DSA-65 signature from your device</label>
                <input class="detail-value" type="text" name="ml_dsa_signature" id="ml_dsa_signature"
                       placeholder="hex, over challenge {challenge_b64}" autocomplete="off" />
                <div class="actions">
                    <button type="submit" id="deny" class="btn btn-secondary">Deny</button>
                    <button type="button" id="approve" class="btn btn-primary">Sign in with passkey</button>
                </div>
            </form>
        </div>
        <div class="footer">
            Tenzro Network &mdash; Testnet &middot;
            <a href="https://www.tenzro.com">tenzro.com</a>
        </div>
    </div>
    <script>
    (function () {{
        const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        const unb64 = (s) => Uint8Array.from(
            atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
        const form = document.getElementById('consent');
        document.getElementById('approve').addEventListener('click', async () => {{
            try {{
                const cred = await navigator.credentials.get({{
                    publicKey: {{
                        challenge: unb64('{challenge_b64}'),
                        rpId: '{rp_id}',
                        userVerification: 'required',
                        timeout: 120000,
                    }},
                }});
                document.getElementById('credential_id').value = b64(cred.rawId);
                document.getElementById('authenticator_data').value =
                    b64(cred.response.authenticatorData);
                document.getElementById('client_data_json').value =
                    b64(cred.response.clientDataJSON);
                document.getElementById('signature').value = b64(cred.response.signature);
                document.getElementById('action').value = 'approve';
                form.submit();
            }} catch (e) {{
                alert('Passkey sign-in did not complete: ' + e.message);
            }}
        }});
    }})();
    </script>
</body>
</html>"#,
        client_name = html_escape(page.client_name),
        client_id = html_escape(page.client_id),
        session_token = html_escape(page.session_token),
        challenge_b64 = js_token(page.challenge_b64),
        rp_id = js_token(page.rp_id),
        scope_tags = scope_tags,
    )
}

/// Keep only characters that are safe inside a single-quoted JavaScript
/// string in an HTML script block. Both inputs (a base64url challenge and
/// an RP ID) are made of these characters when well-formed.
fn js_token(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect()
}

/// Escapes HTML special characters to prevent XSS.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
