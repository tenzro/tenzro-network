//! `wasi:http` serving path for `function`-class apps.
//!
//! A `function` app is a component that exports the `wasi:http/proxy`
//! world — the same shape Fastly Compute, Fermyon Spin, and wasmCloud
//! use. Given a component that exports `wasi:http/incoming-handler`,
//! [`HttpComponent`] pre-links it once and then serves one HTTP request
//! per [`HttpComponent::serve`] call.
//!
//! The request/response bodies are `hyper` 1.x types so the node's
//! axum edge can hand a decoded request straight through and stream the
//! response back over the `tenzro/http` bi-stream without a second
//! serialization hop.

use std::time::Duration;

use wasmtime::component::{Component, Linker};
use wasmtime::Store;
use wasmtime_wasi_http::p2::bindings::ProxyPre;
use wasmtime_wasi_http::p2::body::{HyperIncomingBody, HyperOutgoingBody};
use wasmtime_wasi_http::p2::WasiHttpView;

/// Outward-facing request scheme handed to [`HttpComponent::serve`].
/// Re-exported so callers need no direct `wasmtime-wasi-http` dependency.
pub use wasmtime_wasi_http::p2::bindings::http::types::Scheme;

use crate::capabilities::SkillCapabilities;
use crate::engine::WasmEngine;
use crate::error::{WasmError, WasmResult};
use crate::wasi_state::WasiState;

/// Body type accepted by [`HttpComponent::serve`].
///
/// A boxed `http_body::Body<Data = Bytes, Error = ErrorCode>` — the same
/// type the WASI-HTTP host stores internally. The node's edge decodes an
/// inbound `tenzro/http` frame into a `hyper::Request` and boxes the
/// request bytes into this type via [`incoming_body_from_bytes`], so no
/// live hyper connection is required to synthesize a request.
pub type IncomingBody = HyperIncomingBody;

/// Response body handed back by [`HttpComponent::serve`]. The component
/// writes into it incrementally; the edge streams it to the caller.
pub type OutgoingBody = HyperOutgoingBody;

/// A function invocation's response, fully buffered.
///
/// Returned by [`HttpComponent::serve_buffered`] so the node's ingress
/// edge can serialize it to raw HTTP/1.1 without touching `hyper` or
/// `http` types directly.
#[derive(Debug, Clone)]
pub struct FunctionResponse {
    /// HTTP status code the guest produced.
    pub status: u16,
    /// Response header pairs (name, value), UTF-8 values only.
    pub headers: Vec<(String, String)>,
    /// Fully-collected response body.
    pub body: bytes::Bytes,
}

/// Box a fully-buffered request body into the [`IncomingBody`] type
/// [`HttpComponent::serve`] expects. Used by the ingress edge, which has
/// already read the entire request off the `tenzro/http` bi-stream.
pub fn incoming_body_from_bytes(bytes: bytes::Bytes) -> IncomingBody {
    use http_body_util::{BodyExt, Full};
    Full::new(bytes)
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed_unsync()
}

/// A pre-linked `wasi:http` component ready to serve requests.
///
/// Construction compiles the linker and produces a [`ProxyPre`] once.
/// Each [`serve`](Self::serve) call builds a fresh [`Store`] from the
/// component's declared capabilities, so no state leaks between
/// requests — `wasi:http` is request-scoped by design (see the crate
/// docs for the companion-component pattern when cross-request state is
/// required).
pub struct HttpComponent {
    engine: WasmEngine,
    pre: ProxyPre<WasiState>,
    capabilities: SkillCapabilities,
    fuel_limit: u64,
    deadline: Duration,
}

impl HttpComponent {
    /// Compiles and pre-links a component that exports the
    /// `wasi:http/proxy` world.
    ///
    /// Fails with [`WasmError::InvalidComponent`] if the bytes are not a
    /// valid component or do not export the proxy world's incoming
    /// handler.
    pub fn compile(
        engine: &WasmEngine,
        bytes: &[u8],
        capabilities: SkillCapabilities,
        fuel_limit: u64,
        deadline: Duration,
    ) -> WasmResult<Self> {
        let component = Component::new(engine.inner(), bytes)
            .map_err(|e| WasmError::InvalidComponent(format!("wasmtime rejected component: {e:#}")))?;

        let mut linker: Linker<WasiState> = Linker::new(engine.inner());
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(|e| WasmError::Wasmtime(format!("adding wasi:cli/io to linker: {e:#}")))?;
        wasmtime_wasi_http::p2::add_to_linker_async(&mut linker)
            .map_err(|e| WasmError::Wasmtime(format!("adding wasi:http to linker: {e:#}")))?;

        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(|e| WasmError::InvalidComponent(format!("pre-instantiation failed: {e:#}")))?;
        let pre = ProxyPre::new(instance_pre).map_err(|e| {
            WasmError::InvalidComponent(format!(
                "component does not export the wasi:http/proxy world: {e:#}"
            ))
        })?;

        Ok(Self {
            engine: engine.clone(),
            pre,
            capabilities,
            fuel_limit,
            deadline,
        })
    }

    /// Serve one HTTP request through the component.
    ///
    /// `scheme` is the outward-facing scheme (`https` at the edge). The
    /// request body streams into the guest; the returned response body
    /// streams back out. A guest trap, fuel exhaustion, or deadline
    /// overrun surfaces as the corresponding [`WasmError`].
    pub async fn serve(
        &self,
        scheme: Scheme,
        request: hyper::Request<IncomingBody>,
    ) -> WasmResult<hyper::Response<OutgoingBody>> {
        let state = WasiState::from_capabilities(&self.capabilities);
        let mut store = Store::new(self.engine.inner(), state);

        // Fuel + wall-clock bounds. The engine's epoch ticker (driven by
        // the host) trips `epoch_deadline` after `deadline`.
        store
            .set_fuel(self.fuel_limit)
            .map_err(|e| WasmError::Wasmtime(format!("setting fuel: {e:#}")))?;
        let epoch_ticks = self.deadline.as_millis().max(1) as u64;
        store.set_epoch_deadline(epoch_ticks);

        // The guest writes its response through a oneshot outparam. We
        // build the incoming-request and response-outparam resources
        // against the store's WASI-HTTP table, then drive the handler.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req_resource = store
            .data_mut()
            .http()
            .new_incoming_request(scheme, request)
            .map_err(|e| WasmError::Wasmtime(format!("building incoming request: {e:#}")))?;
        let out_resource = store
            .data_mut()
            .http()
            .new_response_outparam(tx)
            .map_err(|e| WasmError::Wasmtime(format!("building response outparam: {e:#}")))?;

        let proxy = self
            .pre
            .instantiate_async(&mut store)
            .await
            .map_err(Self::classify_trap)?;

        proxy
            .wasi_http_incoming_handler()
            .call_handle(&mut store, req_resource, out_resource)
            .await
            .map_err(Self::classify_trap)?;

        // The handler resolves the outparam with either a response or an
        // error code. `rx` errors only if the guest dropped the outparam
        // without ever writing to it.
        match rx.await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(code)) => Err(WasmError::HostContractViolation(format!(
                "guest returned wasi:http error code: {code:?}"
            ))),
            Err(_) => Err(WasmError::HostContractViolation(
                "guest handler returned without producing a response".into(),
            )),
        }
    }

    /// Serve one request expressed as raw HTTP/1.1 parts and return the
    /// response fully buffered.
    ///
    /// This is the seam the node's `tenzro/http` ingress edge uses: it has
    /// already read the complete request off the bi-stream, so it hands the
    /// method, request-target, header pairs, and body bytes here and gets
    /// back a [`FunctionResponse`] it can serialize straight to the wire —
    /// no `hyper`, `http`, or `wasmtime-wasi-http` types cross the crate
    /// boundary. `scheme_https` selects `https` (edge default) vs `http`.
    ///
    /// The response body is capped at `max_response_bytes`; a guest that
    /// streams more trips [`WasmError::HostContractViolation`].
    pub async fn serve_buffered(
        &self,
        scheme_https: bool,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: bytes::Bytes,
        max_response_bytes: usize,
    ) -> WasmResult<FunctionResponse> {
        use http_body_util::BodyExt as _;

        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(target);
        for (k, v) in headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let request = builder
            .body(incoming_body_from_bytes(body))
            .map_err(|e| WasmError::HostContractViolation(format!("building request: {e}")))?;

        let scheme = if scheme_https { Scheme::Https } else { Scheme::Http };
        let response = self.serve(scheme, request).await?;

        let (parts, out_body) = response.into_parts();
        let status = parts.status.as_u16();
        let resp_headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();

        let collected = out_body
            .collect()
            .await
            .map_err(|e| WasmError::HostContractViolation(format!("reading response body: {e}")))?
            .to_bytes();
        if collected.len() > max_response_bytes {
            return Err(WasmError::HostContractViolation(format!(
                "response body {} bytes exceeds cap {max_response_bytes}",
                collected.len()
            )));
        }

        Ok(FunctionResponse {
            status,
            headers: resp_headers,
            body: collected,
        })
    }

    /// Maps a wasmtime error into the fuel / deadline / trap variants.
    fn classify_trap(err: wasmtime::Error) -> WasmError {
        // Wasmtime surfaces resource-limit traps as `wasmtime::Trap`
        // values wrapped in the anyhow chain.
        if let Some(trap) = err.downcast_ref::<wasmtime::Trap>() {
            match trap {
                wasmtime::Trap::OutOfFuel => {
                    return WasmError::FuelExhausted { consumed: 0 };
                }
                wasmtime::Trap::Interrupt => {
                    return WasmError::DeadlineExceeded {
                        elapsed: Duration::ZERO,
                    };
                }
                _ => return WasmError::Trap(format!("{trap:?}")),
            }
        }
        WasmError::Trap(format!("{err:#}"))
    }
}

impl std::fmt::Debug for HttpComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpComponent")
            .field("fuel_limit", &self.fuel_limit)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}
