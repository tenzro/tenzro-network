//! HTML template for the OAuth authorization page.
//! Matches the Tenzro website design language: olive monochromatic OKLCH palette,
//! Inter font, sharp borders (no radius), minimal and geometric.

/// Renders the OAuth authorization page.
pub fn render_authorize_page(
    client_name: &str,
    scope: &str,
    session_token: &str,
) -> String {
    let scope_tags: String = scope
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
                A Tenzro identity and wallet will be provisioned for you
                automatically if you don't have one yet. You'll receive
                100 testnet TNZO to get started.
            </div>

            <div class="detail">
                <div class="detail-row">
                    <span class="detail-label">Application</span>
                    <span class="detail-value">{client_name}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Permissions</span>
                    <div class="scopes">
                        {scope_tags}
                    </div>
                </div>
            </div>

            <form method="POST" action="/authorize">
                <input type="hidden" name="session_token" value="{session_token}" />
                <div class="actions">
                    <button type="submit" name="action" value="deny" class="btn btn-secondary">Deny</button>
                    <button type="submit" name="action" value="approve" class="btn btn-primary">Approve</button>
                </div>
            </form>
        </div>
        <div class="footer">
            Tenzro Network &mdash; Testnet &middot;
            <a href="https://www.tenzro.com">tenzro.com</a>
        </div>
    </div>
</body>
</html>"#,
        client_name = html_escape(client_name),
        session_token = html_escape(session_token),
        scope_tags = scope_tags,
    )
}

/// Escapes HTML special characters to prevent XSS.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
