//! The interface boundary between this CLI/wallet and the website's join-form
//! backend. The CLI only READS status; the form page writes applications and
//! the Tenzro team moves them along on the website side.
//!
//! # What the website must implement (schema version 1)
//!
//! ```text
//! GET {status_endpoint_base}/status?wallet=0x<64 hex>&role=<role slug>
//!     Accept: application/json
//!
//! 200 OK
//! {
//!   "schema": 1,
//!   "wallet": "0x<64 hex>",          // echo of the query, lowercase
//!   "role": "validator",             // a role slug (see onboarding::role)
//!   "state": "under_review",         // applied | under_review | approved | declined
//!                                    // ("funded" is also accepted and means the
//!                                    //  team has sent the stake)
//!   "application_id": "app_...",     // optional, opaque, for support
//!   "updated_at": "2026-11-09T10:00:00Z",   // optional, RFC 3339
//!   "message": "text"                // optional; shown to the applicant verbatim,
//!                                    // so it must follow the public wording rule
//! }
//!
//! 404 Not Found    no application for this wallet and role (empty body ok)
//! anything else    treated as "status unavailable"
//! ```
//!
//! Rules for the website side:
//!
//! * `staked` and `serving` are NOT served here: the CLI reads them from the
//!   chain and ignores them from the website.
//! * The response must carry no personal data (no name, email, hardware).
//!   Anyone who knows a wallet address can ask; an address is public, but the
//!   existence of an application for it is not secret-grade. If that is not
//!   acceptable, the website can require an `application_id` (add it as a
//!   query parameter; the CLI keeps the id from the form's receipt in
//!   `~/.tenzro/config.json`, `application.application_id`) in a later schema.
//! * Replies should be fast (the CLI waits 5 seconds, once) and cacheable for
//!   a few seconds at most.
//!
//! # What the CLI does with failure
//!
//! A timeout, a DNS failure, a non-200/404 status or an unparseable body is
//! [`Lookup::Unavailable`]: the CLI falls back to the last status it kept
//! locally plus what the chain says. The reason is logged at debug level and
//! is never printed to the person.

use std::time::Duration;

use super::foundation_config::status_endpoint_base;
use super::state::ApplicationState;

/// What the website reports for one application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStatus {
    pub state: ApplicationState,
    pub application_id: Option<String>,
    pub updated_at: Option<String>,
    pub message: Option<String>,
}

/// The outcome of one lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Found(RemoteStatus),
    /// The website has no application for this wallet and role.
    NotFound,
    /// The website could not be asked or did not answer sensibly.
    Unavailable,
}

/// Anything the CLI can ask for application status. The HTTP client is one
/// implementation; tests use [`StubStatusSource`].
pub trait StatusSource {
    fn lookup(
        &self,
        wallet: &str,
        role_slug: &str,
    ) -> impl std::future::Future<Output = Lookup> + Send;
}

/// Normalise an address for the query and the echo check.
fn norm(addr: &str) -> String {
    format!(
        "0x{}",
        addr.trim().trim_start_matches("0x").to_ascii_lowercase()
    )
}

/// Interpret one HTTP answer. Pure.
pub fn parse_response(http_status: u16, body: &str, wallet: &str, role_slug: &str) -> Lookup {
    if http_status == 404 {
        return Lookup::NotFound;
    }
    if http_status != 200 {
        return Lookup::Unavailable;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return Lookup::Unavailable;
    };
    if v.get("schema").and_then(|x| x.as_u64()) != Some(1) {
        return Lookup::Unavailable;
    }
    // A reply about some other wallet or role must not be taken as ours.
    if v.get("wallet").and_then(|x| x.as_str()).map(norm) != Some(norm(wallet)) {
        return Lookup::Unavailable;
    }
    if v.get("role").and_then(|x| x.as_str()) != Some(role_slug) {
        return Lookup::Unavailable;
    }
    let Some(state) = v
        .get("state")
        .and_then(|x| x.as_str())
        .and_then(ApplicationState::parse)
    else {
        return Lookup::Unavailable;
    };
    // The website speaks only for the review steps and the team's transfer.
    // `staked` / `serving` / `not_applied` from it are not a valid answer.
    if !matches!(
        state,
        ApplicationState::Applied
            | ApplicationState::UnderReview
            | ApplicationState::Approved
            | ApplicationState::Funded
            | ApplicationState::Declined
    ) {
        return Lookup::Unavailable;
    }
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    Lookup::Found(RemoteStatus {
        state,
        application_id: s("application_id"),
        updated_at: s("updated_at"),
        message: s("message"),
    })
}

/// The HTTP implementation.
pub struct HttpStatusSource {
    base: String,
}

impl HttpStatusSource {
    /// `TENZRO_JOIN_STATUS_URL` or the configured default.
    pub fn from_env() -> Self {
        let base = std::env::var("TENZRO_JOIN_STATUS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| status_endpoint_base().to_string());
        HttpStatusSource {
            base: base.trim_end_matches('/').to_string(),
        }
    }
}

impl StatusSource for HttpStatusSource {
    async fn lookup(&self, wallet: &str, role_slug: &str) -> Lookup {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(_) => return Lookup::Unavailable,
        };
        let url = format!("{}/status", self.base);
        let resp = client
            .get(&url)
            .query(&[("wallet", norm(wallet).as_str()), ("role", role_slug)])
            .header("accept", "application/json")
            .send()
            .await;
        match resp {
            Ok(r) => {
                let code = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                parse_response(code, &body, wallet, role_slug)
            }
            Err(e) => {
                tracing_debug(&format!("join status lookup failed: {e}"));
                Lookup::Unavailable
            }
        }
    }
}

fn tracing_debug(msg: &str) {
    if std::env::var_os("TENZRO_DEBUG_ONBOARDING").is_some() {
        eprintln!("[onboarding] {msg}");
    }
}

/// A fixed answer, for tests and for running the flow before the website
/// exists (`TENZRO_JOIN_STATUS_STUB=under_review`).
pub struct StubStatusSource(pub Lookup);

impl StubStatusSource {
    /// Build a stub from a state name; `none` is a 404, `unavailable` an outage.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(StubStatusSource(match name {
            "none" | "not_found" => Lookup::NotFound,
            "unavailable" => Lookup::Unavailable,
            n => Lookup::Found(RemoteStatus {
                state: ApplicationState::parse(n)?,
                application_id: None,
                updated_at: None,
                message: None,
            }),
        }))
    }
}

impl StatusSource for StubStatusSource {
    async fn lookup(&self, _wallet: &str, _role_slug: &str) -> Lookup {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: &str = "0xabababababababababababababababababababababababababababababababab";

    fn body(state: &str) -> String {
        format!(
            r#"{{"schema":1,"wallet":"{W}","role":"validator","state":"{state}","application_id":"app_1"}}"#
        )
    }

    #[test]
    fn a_good_answer_is_found() {
        match parse_response(200, &body("under_review"), W, "validator") {
            Lookup::Found(r) => {
                assert_eq!(r.state, ApplicationState::UnderReview);
                assert_eq!(r.application_id.as_deref(), Some("app_1"));
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn not_found_is_an_answer_and_everything_else_is_an_outage() {
        assert_eq!(parse_response(404, "", W, "validator"), Lookup::NotFound);
        for code in [500, 502, 429, 301, 403] {
            assert_eq!(
                parse_response(code, &body("approved"), W, "validator"),
                Lookup::Unavailable
            );
        }
        assert_eq!(
            parse_response(200, "<html>", W, "validator"),
            Lookup::Unavailable
        );
    }

    #[test]
    fn a_reply_about_someone_else_is_refused() {
        let other = format!("0x{}", "cd".repeat(32));
        assert_eq!(
            parse_response(200, &body("approved"), &other, "validator"),
            Lookup::Unavailable
        );
        assert_eq!(
            parse_response(200, &body("approved"), W, "storage-provider"),
            Lookup::Unavailable
        );
    }

    #[test]
    fn the_website_cannot_claim_chain_states() {
        for s in ["staked", "serving", "not_applied", "banana"] {
            assert_eq!(
                parse_response(200, &body(s), W, "validator"),
                Lookup::Unavailable,
                "{s}"
            );
        }
    }

    #[test]
    fn wrong_schema_version_is_unavailable() {
        let b = body("approved").replace("\"schema\":1", "\"schema\":2");
        assert_eq!(parse_response(200, &b, W, "validator"), Lookup::Unavailable);
    }
}
