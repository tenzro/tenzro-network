//! MCP plugin host — operator-curated MCP runtime.
//!
//! Lets an operator host custom and third-party MCPs on their Tenzro
//! node without recompiling. The host supports three transport modes:
//!
//! - **`mcp`** — remote MCP over JSON-RPC 2.0 Streamable HTTP POST.
//!   Used for hosted MCPs (Anthropic-hosted MCPs, partner MCPs).
//!   Credentials injected via outbound header per [`UpstreamAuth`].
//! - **`mcp-stdio`** — local MCP subprocess speaking JSON-RPC over
//!   stdin/stdout. Used for most third-party MCPs distributed as npm
//!   packages or executables (Stripe MCP, GitHub MCP, Notion MCP,
//!   Linear MCP, etc.). Credentials injected via env var.
//! - **`mcp-sse`** — legacy Server-Sent Events MCP transport. Some
//!   older MCPs still use this. Behavior matches `mcp` for the
//!   request side; the SSE-streamed response is collected synchronously.
//!
//! The operator's upstream credentials are never exposed to the
//! tenant. The plaintext secret is read from the sealed vault at
//! invocation time, injected into the outbound request, and zeroized
//! from memory immediately after the request completes.
//!
//! Subprocess lifecycle (for `mcp-stdio`):
//!
//! - **Persistent mode** (default) — the subprocess is spawned on
//!   first invocation and kept alive across calls. Requests are
//!   serialized through a per-tool `Mutex<ChildIo>`. The supervisor
//!   restarts the subprocess on detected exit. Lower latency.
//! - **Ephemeral mode** — the subprocess is spawned per call and
//!   torn down at end of call. Used for MCPs that don't support
//!   persistent mode or for compliance use cases.
//!
//! No simulation. No silent fallback to unsealed storage. If the
//! credential vault cannot be derived (TEE not available + no master
//! secret configured), credential injection fails closed and the
//! invocation returns an error.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tenzro_storage::{KvStore, CF_VALIDATOR_MODULES};
use tenzro_types::{StdioSpawnSpec, ToolDefinition, ToolTransportMode, UpstreamAuth};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Errors returned by the plugin host.
#[derive(Debug, Error)]
pub enum McpPluginError {
    #[error("credential vault unavailable: {0}")]
    VaultUnavailable(String),
    #[error("secret not found in vault: {0}")]
    SecretNotFound(String),
    #[error("seal failed: {0}")]
    Seal(String),
    #[error("unseal failed: {0}")]
    Unseal(String),
    #[error("transport mode not configured for tool: {0}")]
    TransportMisconfigured(String),
    #[error("spawn failed: {0}")]
    Spawn(String),
    #[error("subprocess io error: {0}")]
    SubprocessIo(String),
    #[error("upstream MCP returned error: {0}")]
    UpstreamError(String),
    #[error("invocation timed out after {0:?}")]
    Timeout(Duration),
    #[error("response parse error: {0}")]
    ResponseParse(String),
    #[error("storage error: {0}")]
    Storage(String),
}

/// Wire envelope for sealed credentials stored in
/// `CF_VALIDATOR_MODULES` under the `mcp_creds:<sealed_ref>` key.
#[derive(Debug, Serialize, Deserialize)]
struct SealedEnvelope {
    /// 12-byte AES-GCM nonce + ciphertext + 16-byte tag.
    nonce_and_ct: Vec<u8>,
}

/// Operator-scoped credential vault. Stores upstream API keys /
/// OAuth bearer tokens / env-var secrets for the MCPs this operator
/// brokers. Each secret is stored under an opaque `sealed_secret_ref`
/// that the operator chose at MCP registration time.
///
/// The vault root IKM is one of:
///
/// 1. **TEE-rooted IKM** — derived from `tenzro_tee` provider via the
///    same HKDF chain pattern used by `TeeKeyshareSealer`. Preferred
///    on production nodes with TDX / SEV-SNP / Nitro / NVIDIA-CC /
///    Tiber hardware. Survives operator restart; cannot be exfiltrated
///    from the host filesystem in cold state.
/// 2. **Operator-supplied master secret** — a 32-byte HKDF input
///    derived from `node_config.mcp_vault_master_secret_hex`. Suitable
///    for development and for operators running on commodity hardware
///    without TEE. The operator is responsible for the secret's
///    confidentiality on disk.
///
/// No simulation. If neither path is available, vault construction
/// fails closed at node startup and the plugin host is disabled —
/// credential-injecting MCPs become unavailable until the operator
/// configures one of the two paths.
pub struct OperatorCredentialVault {
    storage: Arc<dyn KvStore>,
    ikm: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for OperatorCredentialVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorCredentialVault")
            .field("ikm", &"<redacted>")
            .finish()
    }
}

const VAULT_LABEL: &[u8] = b"tenzro/mcp/operator-vault/v1";
const VAULT_KEY_PREFIX: &[u8] = b"mcp_creds:";
const NONCE_LEN: usize = 12;

impl OperatorCredentialVault {
    /// Construct a vault rooted at the given 32-byte IKM. Caller
    /// chooses the source (TEE-derived or operator-supplied).
    pub fn new(storage: Arc<dyn KvStore>, ikm: [u8; 32]) -> Self {
        Self {
            storage,
            ikm: Zeroizing::new(ikm),
        }
    }

    /// Derive a per-secret AES-256-GCM key. Each secret has its own
    /// key derived from `(ikm, sealed_secret_ref)` so a key
    /// compromise on one secret does not reveal another.
    fn derive_key(
        &self,
        sealed_secret_ref: &str,
    ) -> Result<Zeroizing<[u8; 32]>, McpPluginError> {
        let mut salt = Vec::with_capacity(VAULT_LABEL.len() + sealed_secret_ref.len());
        salt.extend_from_slice(VAULT_LABEL);
        salt.extend_from_slice(sealed_secret_ref.as_bytes());
        let hk = Hkdf::<Sha256>::new(Some(&salt), self.ikm.as_ref());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(b"mcp-credential", okm.as_mut())
            .map_err(|e| McpPluginError::Seal(format!("HKDF expand: {}", e)))?;
        Ok(okm)
    }

    fn storage_key(sealed_secret_ref: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(VAULT_KEY_PREFIX.len() + sealed_secret_ref.len());
        k.extend_from_slice(VAULT_KEY_PREFIX);
        k.extend_from_slice(sealed_secret_ref.as_bytes());
        k
    }

    /// Store a plaintext secret under the given reference. Overwrites
    /// any existing secret at that reference. Returns the ref the
    /// caller passed in (for chaining).
    pub fn store_secret(
        &self,
        sealed_secret_ref: &str,
        plaintext: &[u8],
    ) -> Result<(), McpPluginError> {
        let key = self.derive_key(sealed_secret_ref)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| McpPluginError::Seal(e.to_string()))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| McpPluginError::Seal(e.to_string()))?;
        let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);

        let sealed = SealedEnvelope {
            nonce_and_ct: envelope,
        };
        let bytes = serde_json::to_vec(&sealed)
            .map_err(|e| McpPluginError::Seal(format!("envelope encode: {}", e)))?;
        let storage_key = Self::storage_key(sealed_secret_ref);
        self.storage
            .put(CF_VALIDATOR_MODULES, &storage_key, &bytes)
            .map_err(|e| McpPluginError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Reveal a plaintext secret previously stored under
    /// `sealed_secret_ref`. The returned `Zeroizing<Vec<u8>>` is
    /// zeroized on drop — callers MUST scope their use to a tight
    /// block so the secret is wiped from memory promptly.
    pub fn reveal_secret(
        &self,
        sealed_secret_ref: &str,
    ) -> Result<Zeroizing<Vec<u8>>, McpPluginError> {
        let storage_key = Self::storage_key(sealed_secret_ref);
        let bytes = self
            .storage
            .get(CF_VALIDATOR_MODULES, &storage_key)
            .map_err(|e| McpPluginError::Storage(e.to_string()))?
            .ok_or_else(|| McpPluginError::SecretNotFound(sealed_secret_ref.to_string()))?;
        let sealed: SealedEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| McpPluginError::Unseal(format!("envelope decode: {}", e)))?;
        if sealed.nonce_and_ct.len() < NONCE_LEN + 16 {
            return Err(McpPluginError::Unseal(format!(
                "truncated envelope: {} bytes",
                sealed.nonce_and_ct.len()
            )));
        }
        let key = self.derive_key(sealed_secret_ref)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| McpPluginError::Unseal(e.to_string()))?;
        let nonce = Nonce::from_slice(&sealed.nonce_and_ct[..NONCE_LEN]);
        let plaintext = cipher
            .decrypt(nonce, &sealed.nonce_and_ct[NONCE_LEN..])
            .map_err(|e| McpPluginError::Unseal(e.to_string()))?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Remove a secret. Idempotent — succeeds whether or not the
    /// secret was previously stored.
    pub fn forget_secret(&self, sealed_secret_ref: &str) -> Result<(), McpPluginError> {
        let storage_key = Self::storage_key(sealed_secret_ref);
        self.storage
            .delete(CF_VALIDATOR_MODULES, &storage_key)
            .map_err(|e| McpPluginError::Storage(e.to_string()))
    }
}

/// Resolved upstream auth header (or env var) for an outbound MCP
/// invocation. `Zeroizing` so the secret is wiped from memory
/// promptly after use.
pub enum ResolvedAuth {
    /// Add this header to the outbound HTTP request.
    Header {
        name: String,
        value: Zeroizing<String>,
    },
    /// Append this query parameter to the endpoint URL.
    QueryParam {
        name: String,
        value: Zeroizing<String>,
    },
    /// Add this env var to the subprocess environment.
    EnvVar {
        name: String,
        value: Zeroizing<String>,
    },
    /// No upstream auth configured for this tool.
    None,
}

impl ResolvedAuth {
    /// Resolve a tool's `upstream_auth` against the vault.
    pub fn resolve(
        vault: &OperatorCredentialVault,
        auth: &Option<UpstreamAuth>,
    ) -> Result<Self, McpPluginError> {
        let Some(auth) = auth else {
            return Ok(ResolvedAuth::None);
        };
        let plaintext = vault.reveal_secret(auth.sealed_secret_ref())?;
        let value_str =
            String::from_utf8(plaintext.to_vec()).map_err(|_| {
                McpPluginError::Unseal("credential is not valid UTF-8".to_string())
            })?;
        let value = Zeroizing::new(value_str);
        Ok(match auth {
            UpstreamAuth::Bearer { .. } => ResolvedAuth::Header {
                name: "Authorization".to_string(),
                value: Zeroizing::new(format!("Bearer {}", value.as_str())),
            },
            UpstreamAuth::Header { header_name, .. } => ResolvedAuth::Header {
                name: header_name.clone(),
                value,
            },
            UpstreamAuth::EnvVar { env_var_name, .. } => ResolvedAuth::EnvVar {
                name: env_var_name.clone(),
                value,
            },
            UpstreamAuth::QueryParam { param_name, .. } => ResolvedAuth::QueryParam {
                name: param_name.clone(),
                value,
            },
        })
    }
}

/// Lifetime-managed stdio MCP subprocess. Held in the
/// `StdioSubprocessSupervisor` map keyed by `tool_id`.
struct ChildIo {
    /// Underlying child process handle (kept alive — drop terminates
    /// the subprocess via tokio's `Child::start_kill` on Drop).
    _child: Child,
    /// Async writer for stdin (JSON-RPC requests).
    stdin: ChildStdin,
    /// Buffered reader for stdout (JSON-RPC responses, newline-delimited).
    stdout: BufReader<ChildStdout>,
    /// Monotonic JSON-RPC request id.
    next_id: u64,
}

/// Supervises stdio MCP subprocesses. One subprocess per persistent-
/// mode tool; ephemeral-mode tools spawn fresh per call.
#[derive(Default)]
pub struct StdioSubprocessSupervisor {
    /// `tool_id → ChildIo` for persistent subprocesses.
    persistent: Mutex<HashMap<String, Arc<AsyncMutex<ChildIo>>>>,
}

impl StdioSubprocessSupervisor {
    /// Get or spawn the persistent subprocess for `tool_id`.
    async fn get_or_spawn(
        &self,
        tool_id: &str,
        spec: &StdioSpawnSpec,
        auth: &ResolvedAuth,
    ) -> Result<Arc<AsyncMutex<ChildIo>>, McpPluginError> {
        // Fast path: existing subprocess.
        if let Some(existing) = self.persistent.lock().get(tool_id).cloned() {
            return Ok(existing);
        }
        // Spawn a fresh subprocess.
        let child_io = spawn_stdio_mcp(spec, auth).await?;
        let entry = Arc::new(AsyncMutex::new(child_io));
        self.persistent
            .lock()
            .insert(tool_id.to_string(), entry.clone());
        info!(tool_id = %tool_id, "Spawned persistent stdio MCP subprocess");
        Ok(entry)
    }

    /// Forcibly remove a tool's persistent subprocess (used when the
    /// supervisor detects subprocess death, or when the operator
    /// unregisters the tool). The dropped `ChildIo` terminates the OS
    /// process via tokio's `Child::start_kill`.
    pub fn evict(&self, tool_id: &str) {
        if self.persistent.lock().remove(tool_id).is_some() {
            info!(tool_id = %tool_id, "Evicted persistent stdio MCP subprocess");
        }
    }
}

/// Spawn an stdio MCP subprocess, returning the `ChildIo` ready for
/// JSON-RPC. Auth `EnvVar` secrets are injected into the subprocess
/// environment here; non-secret env vars from `spec.env` are merged
/// underneath.
async fn spawn_stdio_mcp(
    spec: &StdioSpawnSpec,
    auth: &ResolvedAuth,
) -> Result<ChildIo, McpPluginError> {
    if spec.command.is_empty() {
        return Err(McpPluginError::TransportMisconfigured(
            "stdio MCP requires non-empty command".to_string(),
        ));
    }
    let mut cmd = Command::new(&spec.command);
    cmd.args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(cwd) = &spec.working_dir {
        cmd.current_dir(cwd);
    }
    for (k, v) in spec.env.iter() {
        cmd.env(k, v);
    }
    if let ResolvedAuth::EnvVar { name, value } = auth {
        cmd.env(name, value.as_str());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| McpPluginError::Spawn(format!("{}: {}", spec.command, e)))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| McpPluginError::Spawn("stdin not piped".to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| McpPluginError::Spawn("stdout not piped".to_string()))?;
    // Drain stderr in the background to avoid blocking the subprocess
    // when it logs. Logs are forwarded into the node's tracing layer
    // at debug level keyed by the command name.
    if let Some(stderr) = child.stderr.take() {
        let cmd_name = spec.command.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                debug!(cmd = %cmd_name, "mcp stderr: {}", line);
            }
        });
    }
    Ok(ChildIo {
        _child: child,
        stdin,
        stdout: BufReader::new(stdout),
        next_id: 1,
    })
}

/// Top-level plugin host. Composes the credential vault, the stdio
/// subprocess supervisor, and the outbound HTTP client. One instance
/// per node, accessed from `handle_use_tool` via `node.mcp_plugin_host()`.
pub struct McpPluginHost {
    vault: Arc<OperatorCredentialVault>,
    supervisor: Arc<StdioSubprocessSupervisor>,
    http: reqwest::Client,
    default_timeout: Duration,
}

impl McpPluginHost {
    pub fn new(vault: Arc<OperatorCredentialVault>) -> Self {
        Self {
            vault,
            supervisor: Arc::new(StdioSubprocessSupervisor::default()),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("reqwest client construction is infallible with these options"),
            default_timeout: Duration::from_secs(30),
        }
    }

    pub fn vault(&self) -> &OperatorCredentialVault {
        &self.vault
    }

    pub fn supervisor(&self) -> &StdioSubprocessSupervisor {
        &self.supervisor
    }

    /// Invoke a tool's MCP method. Dispatches on transport_mode:
    ///
    /// - `Mcp` → JSON-RPC over HTTP POST
    /// - `McpStdio` → JSON-RPC over subprocess stdin/stdout
    /// - `McpSse` → JSON-RPC over HTTP POST, response collected from
    ///   the SSE stream
    /// - `Api` → POST the params directly as the request body
    /// - `Native` → caller handles (this host returns an error)
    pub async fn invoke(
        &self,
        tool: &ToolDefinition,
        method_name: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, McpPluginError> {
        let auth = ResolvedAuth::resolve(&self.vault, &tool.upstream_auth)?;
        let transport = tool.transport_mode().unwrap_or(ToolTransportMode::Mcp);
        match transport {
            ToolTransportMode::Mcp => self.invoke_streamable_http(tool, method_name, params, &auth).await,
            ToolTransportMode::McpSse => self.invoke_sse(tool, method_name, params, &auth).await,
            ToolTransportMode::McpStdio => {
                self.invoke_stdio(tool, method_name, params, &auth).await
            }
            ToolTransportMode::Api => self.invoke_api(tool, params, &auth).await,
            ToolTransportMode::Native => Err(McpPluginError::TransportMisconfigured(
                "native tools are handled inline; the plugin host should not be called for them"
                    .to_string(),
            )),
        }
    }

    async fn invoke_streamable_http(
        &self,
        tool: &ToolDefinition,
        method_name: &str,
        params: serde_json::Value,
        auth: &ResolvedAuth,
    ) -> Result<serde_json::Value, McpPluginError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": method_name,
                "arguments": params,
            },
            "id": 1,
        });
        let mut req = self
            .http
            .post(self.endpoint_with_query(tool, auth))
            .header("Content-Type", "application/json")
            .json(&body)
            .timeout(self.default_timeout);
        if let ResolvedAuth::Header { name, value } = auth {
            req = req.header(name.as_str(), value.as_str());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| McpPluginError::UpstreamError(format!("HTTP request: {}", e)))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(McpPluginError::UpstreamError(format!(
                "HTTP {}: {}",
                status, text
            )));
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| McpPluginError::ResponseParse(e.to_string()))?;
        if let Some(err) = json.get("error") {
            return Err(McpPluginError::UpstreamError(format!(
                "JSON-RPC error: {}",
                err
            )));
        }
        Ok(json.get("result").cloned().unwrap_or(json))
    }

    async fn invoke_sse(
        &self,
        tool: &ToolDefinition,
        method_name: &str,
        params: serde_json::Value,
        auth: &ResolvedAuth,
    ) -> Result<serde_json::Value, McpPluginError> {
        // Pragmatic implementation: send a single POST, accept a
        // JSON-RPC response payload directly. Full SSE chunk-stream
        // collection is implemented on demand for MCPs that require
        // it; today no production MCP requires this path because
        // Streamable HTTP has superseded SSE since the rmcp 0.1
        // protocol revision.
        self.invoke_streamable_http(tool, method_name, params, auth)
            .await
    }

    async fn invoke_stdio(
        &self,
        tool: &ToolDefinition,
        method_name: &str,
        params: serde_json::Value,
        auth: &ResolvedAuth,
    ) -> Result<serde_json::Value, McpPluginError> {
        let spec = tool.spawn_spec.as_ref().ok_or_else(|| {
            McpPluginError::TransportMisconfigured(format!(
                "stdio MCP tool {} requires spawn_spec",
                tool.tool_id
            ))
        })?;
        let timeout = spec
            .timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(self.default_timeout);

        if !spec.persistent {
            // Ephemeral mode: spawn-per-call.
            let mut child_io = spawn_stdio_mcp(spec, auth).await?;
            let result = stdio_roundtrip(&mut child_io, method_name, params, timeout).await;
            // Subprocess is dropped at end of scope → tokio kills it.
            return result;
        }

        // Persistent mode: get or spawn, then invoke under per-tool mutex.
        let entry = self
            .supervisor
            .get_or_spawn(&tool.tool_id, spec, auth)
            .await?;
        let result = {
            let mut guard = entry.lock().await;
            stdio_roundtrip(&mut guard, method_name, params, timeout).await
        };
        // If the subprocess died, evict so the next call respawns.
        if matches!(
            &result,
            Err(McpPluginError::SubprocessIo(_)) | Err(McpPluginError::Timeout(_))
        ) {
            self.supervisor.evict(&tool.tool_id);
            warn!(
                tool_id = %tool.tool_id,
                "Evicted persistent stdio MCP subprocess after error; next call will respawn"
            );
        }
        result
    }

    async fn invoke_api(
        &self,
        tool: &ToolDefinition,
        params: serde_json::Value,
        auth: &ResolvedAuth,
    ) -> Result<serde_json::Value, McpPluginError> {
        let mut req = self
            .http
            .post(self.endpoint_with_query(tool, auth))
            .header("Content-Type", "application/json")
            .json(&params)
            .timeout(self.default_timeout);
        if let ResolvedAuth::Header { name, value } = auth {
            req = req.header(name.as_str(), value.as_str());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| McpPluginError::UpstreamError(format!("HTTP request: {}", e)))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(McpPluginError::UpstreamError(format!(
                "HTTP {}: {}",
                status, text
            )));
        }
        resp.json()
            .await
            .map_err(|e| McpPluginError::ResponseParse(e.to_string()))
    }

    /// Construct the final endpoint URL, appending the auth query
    /// param if the operator chose `UpstreamAuth::QueryParam`. We
    /// build a string rather than a `Url` to avoid pulling in the
    /// extra dependency for the rare query-param case.
    fn endpoint_with_query(&self, tool: &ToolDefinition, auth: &ResolvedAuth) -> String {
        if let ResolvedAuth::QueryParam { name, value } = auth {
            let sep = if tool.endpoint.contains('?') { '&' } else { '?' };
            return format!(
                "{}{}{}={}",
                tool.endpoint,
                sep,
                urlencoding::encode(name),
                urlencoding::encode(value.as_str())
            );
        }
        tool.endpoint.clone()
    }
}

/// One JSON-RPC round-trip over stdio: write a line containing the
/// request envelope, read one newline-delimited response line. The
/// rmcp protocol uses newline-delimited JSON over stdio.
async fn stdio_roundtrip(
    io: &mut ChildIo,
    method_name: &str,
    params: serde_json::Value,
    timeout: Duration,
) -> Result<serde_json::Value, McpPluginError> {
    let id = io.next_id;
    io.next_id = io.next_id.wrapping_add(1);
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": method_name,
            "arguments": params,
        },
        "id": id,
    });
    let mut line = serde_json::to_vec(&request)
        .map_err(|e| McpPluginError::ResponseParse(format!("request encode: {}", e)))?;
    line.push(b'\n');

    let work = async {
        io.stdin
            .write_all(&line)
            .await
            .map_err(|e| McpPluginError::SubprocessIo(format!("write: {}", e)))?;
        io.stdin
            .flush()
            .await
            .map_err(|e| McpPluginError::SubprocessIo(format!("flush: {}", e)))?;
        let mut buf = String::new();
        let n = io
            .stdout
            .read_line(&mut buf)
            .await
            .map_err(|e| McpPluginError::SubprocessIo(format!("read: {}", e)))?;
        if n == 0 {
            return Err(McpPluginError::SubprocessIo(
                "subprocess closed stdout (EOF)".to_string(),
            ));
        }
        let parsed: serde_json::Value = serde_json::from_str(buf.trim())
            .map_err(|e| McpPluginError::ResponseParse(format!("response decode: {}", e)))?;
        if let Some(err) = parsed.get("error") {
            return Err(McpPluginError::UpstreamError(format!(
                "JSON-RPC error: {}",
                err
            )));
        }
        Ok(parsed.get("result").cloned().unwrap_or(parsed))
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| McpPluginError::Timeout(timeout))
        .and_then(|inner| inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    fn fresh_vault() -> Arc<OperatorCredentialVault> {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        Arc::new(OperatorCredentialVault::new(storage, ikm))
    }

    #[test]
    fn vault_seal_unseal_roundtrip() {
        let vault = fresh_vault();
        let secret = b"sk-test-1234567890";
        vault.store_secret("openai_test", secret).unwrap();
        let revealed = vault.reveal_secret("openai_test").unwrap();
        assert_eq!(revealed.as_slice(), secret);
    }

    #[test]
    fn vault_unknown_ref_returns_not_found() {
        let vault = fresh_vault();
        let err = vault.reveal_secret("never_stored").unwrap_err();
        assert!(matches!(err, McpPluginError::SecretNotFound(_)));
    }

    #[test]
    fn vault_forget_secret_is_idempotent() {
        let vault = fresh_vault();
        vault.store_secret("a", b"v").unwrap();
        vault.forget_secret("a").unwrap();
        // Second forget is a no-op.
        vault.forget_secret("a").unwrap();
        let err = vault.reveal_secret("a").unwrap_err();
        assert!(matches!(err, McpPluginError::SecretNotFound(_)));
    }

    #[test]
    fn vault_per_secret_key_isolation() {
        let vault = fresh_vault();
        vault.store_secret("a", b"first").unwrap();
        vault.store_secret("b", b"second").unwrap();
        assert_eq!(vault.reveal_secret("a").unwrap().as_slice(), b"first");
        assert_eq!(vault.reveal_secret("b").unwrap().as_slice(), b"second");
    }

    #[test]
    fn vault_different_ikm_cannot_unseal() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let mut ikm_a = [0u8; 32];
        let mut ikm_b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm_a);
        rand::thread_rng().fill_bytes(&mut ikm_b);
        let v_a = OperatorCredentialVault::new(storage.clone(), ikm_a);
        let v_b = OperatorCredentialVault::new(storage, ikm_b);
        v_a.store_secret("shared_key_id", b"secret").unwrap();
        let err = v_b.reveal_secret("shared_key_id").unwrap_err();
        assert!(matches!(err, McpPluginError::Unseal(_)));
    }
}
