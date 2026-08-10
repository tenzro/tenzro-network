//! Small error type for the wallet/oauth web surface.
//!
//! Returning `Result<T, axum::http::Response>` from helpers triggers
//! `clippy::result_large_err` because `Response` is ~144 bytes — every
//! `Ok` return path pays that on the stack. We carry the *inputs* to a
//! response (status code, RFC 6749/9449 error code, human description)
//! and only materialize a `Response` when the error reaches the public
//! handler boundary via `IntoResponse`.
//!
//! Wire shape matches the existing `WalletError` / `OAuthError` JSON
//! body: `{ "error": <code>, "error_description": <description> }`.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Carries the data needed to build an OAuth/wallet-style error
/// response without paying the cost of materializing the `Response`
/// in every `Result` Err variant.
///
/// `code` is `&'static str` because every callsite passes a literal
/// (matches RFC 6749 §5.2 token-error and the wallet surface's fixed
/// vocabulary). `description` is owned because it's almost always
/// formatted from runtime values (`format!("invalid_b64: {}", e)`).
#[derive(Debug, Clone)]
pub struct WalletApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub description: String,
}

impl WalletApiError {
    pub fn new(status: StatusCode, code: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            code,
            description: description.into(),
        }
    }
}

#[derive(Serialize)]
struct WalletApiErrorBody<'a> {
    error: &'a str,
    error_description: &'a str,
}

impl IntoResponse for WalletApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(WalletApiErrorBody {
                error: self.code,
                error_description: &self.description,
            }),
        )
            .into_response()
    }
}
