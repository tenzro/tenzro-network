//! The operator assistant: a chat surface answering questions about *this*
//! node, streamed from a model the operator is already serving.
//!
//! Two decisions shape this module.
//!
//! First, generation runs against the in-process [`ModelRuntime`] rather
//! than JSON-RPC. `tenzro_chat` returns a finished result, so a chat driven
//! through it sits silent for the length of a generation and then prints
//! everything at once. `generate_chat_stream` hands back tokens as they are
//! sampled, which is the only version of this that reads as a conversation.
//!
//! Second, the assistant is grounded by a snapshot rather than by tool
//! calls. The models an operator can realistically run on a laptop are
//! small, and small models call tools badly. So every turn opens with a
//! system prompt carrying the node's actual state — height, peers, roles,
//! custody, balance, models, schedule, prices — and the model reads facts
//! instead of fetching them. It cannot answer a question the snapshot does
//! not cover, which is the honest failure mode.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use tenzro_model::{ChatMessage, GenerationConfig, ModelRuntime};

use crate::state::AppState;

/// One turn of the conversation as the UI holds it.
#[derive(Debug, Clone, Deserialize)]
pub struct AssistantMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantRequest {
    /// Echoed back on every event and accepted by [`cancel`]. Generated
    /// when the caller leaves it out.
    #[serde(default)]
    pub request_id: Option<String>,
    /// Which served model to generate with. Defaults to whichever model is
    /// loaded.
    #[serde(default)]
    pub model_id: Option<String>,
    pub messages: Vec<AssistantMessage>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

/// What the frontend receives over the channel. `Start` always arrives
/// first and one of `Done` / `Error` always arrives last, so the UI can
/// drive a spinner off the pair without tracking token counts.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AssistantEvent {
    #[serde(rename_all = "camelCase")]
    Start { request_id: String, model_id: String },
    Token { text: String },
    #[serde(rename_all = "camelCase")]
    Done {
        request_id: String,
        input_tokens: u32,
        output_tokens: u32,
        tokens_per_second: f64,
        /// True when the operator stopped generation part-way.
        cancelled: bool,
    },
    #[serde(rename_all = "camelCase")]
    Error { request_id: String, message: String },
}

/// Stream a reply. Returns once generation has finished, been cancelled, or
/// failed — the caller learns which from the final event, not the return
/// value, so a model error does not surface as a failed Tauri command.
pub async fn chat(
    req: AssistantRequest,
    on_event: Channel<AssistantEvent>,
    state: &AppState,
) -> Result<(), String> {
    let request_id = req
        .request_id
        .filter(|id| !id.trim().is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());

    let runtime = runtime_arc(state)
        .await
        .ok_or_else(|| "node is still starting — try again in a moment".to_string())?;

    let model_id = match resolve_model(&req.model_id, &runtime) {
        Ok(id) => id,
        Err(message) => {
            let _ = on_event.send(AssistantEvent::Error { request_id, message });
            return Ok(());
        }
    };

    let mut config = GenerationConfig::default();
    if let Some(t) = req.temperature {
        config.temperature = t.clamp(0.0, 2.0);
    }
    if let Some(m) = req.max_tokens {
        config.max_tokens = m.clamp(1, 4096);
    }

    let mut messages = Vec::with_capacity(req.messages.len() + 1);
    messages.push(ChatMessage::new("system", system_prompt(state).await));
    for m in req.messages {
        messages.push(ChatMessage::new(m.role, m.content));
    }

    let token = CancellationToken::new();
    state
        .inflight
        .lock()
        .await
        .insert(request_id.clone(), token.clone());

    let _ = on_event.send(AssistantEvent::Start {
        request_id: request_id.clone(),
        model_id: model_id.clone(),
    });

    let (tx, mut rx) = mpsc::channel::<String>(64);
    let gen_model = model_id.clone();
    let generation = tokio::spawn(async move {
        runtime
            .generate_chat_stream(&gen_model, &messages, &config, tx, None)
            .await
    });

    let mut cancelled = false;
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                cancelled = true;
                break;
            }
            next = rx.recv() => match next {
                Some(text) => {
                    let _ = on_event.send(AssistantEvent::Token { text });
                }
                None => break,
            },
        }
    }

    // Dropping the receiver is what stops a running generation: the sampling
    // loop notices the closed channel on its next token and breaks. Aborting
    // the task above would not, because the serial path runs on a blocking
    // thread the runtime cannot preempt.
    drop(rx);

    let outcome = generation.await;
    state.inflight.lock().await.remove(&request_id);

    match outcome {
        Ok(Ok(result)) => {
            let _ = on_event.send(AssistantEvent::Done {
                request_id,
                input_tokens: result.input_tokens,
                output_tokens: result.output_tokens,
                tokens_per_second: result.tokens_per_second,
                cancelled,
            });
        }
        Ok(Err(e)) => {
            warn!(model_id = %model_id, "assistant generation failed: {}", e);
            let _ = on_event.send(AssistantEvent::Error {
                request_id,
                message: e.to_string(),
            });
        }
        Err(e) => {
            warn!("assistant generation task panicked: {}", e);
            let _ = on_event.send(AssistantEvent::Error {
                request_id,
                message: "generation stopped unexpectedly".to_string(),
            });
        }
    }

    Ok(())
}

/// Stop a generation the operator no longer wants. Unknown ids are not an
/// error — the turn may have finished between the click and this call.
pub async fn cancel(request_id: String, state: &AppState) -> Result<(), String> {
    if let Some(token) = state.inflight.lock().await.remove(&request_id) {
        info!(request_id = %request_id, "cancelling assistant generation");
        token.cancel();
    }
    Ok(())
}

async fn runtime_arc(state: &AppState) -> Option<Arc<ModelRuntime>> {
    let guard = state.node.read().await;
    guard.as_ref()?.node().model_runtime_arc()
}

fn resolve_model(requested: &Option<String>, runtime: &ModelRuntime) -> Result<String, String> {
    if let Some(id) = requested.as_ref().filter(|id| !id.trim().is_empty()) {
        return Ok(id.clone());
    }
    runtime.list_loaded().into_iter().next().ok_or_else(|| {
        "no model is loaded — serve one from the Models screen to use the assistant".to_string()
    })
}

/* --------------------------------------------------------------------- */
/* grounding                                                             */
/* --------------------------------------------------------------------- */

/// Assemble the system prompt from live node state.
async fn system_prompt(state: &AppState) -> String {
    let cfg = crate::config::get();
    let mut s = String::with_capacity(1024);

    s.push_str(
        "You are the assistant built into Tenzro Control, the desktop app for running a Tenzro \
         node. You answer the operator's questions about their own node and about running one.\n\n\
         The facts below are a live snapshot of this machine. Answer from them. If the snapshot \
         does not cover something, say so plainly rather than guessing. Keep answers short.\n\n\
         CURRENT NODE STATE\n",
    );

    match crate::node::node_status(state).await {
        Some(st) => {
            s.push_str(&format!(
                "- status: {} ({})\n- roles: {}\n- block height: {}\n- peers: {}\n- uptime: {}\n",
                st.state,
                st.connectivity,
                if st.roles.is_empty() { "none" } else { st.roles.as_str() },
                st.block_height,
                st.peer_count,
                format_uptime(st.uptime_secs),
            ));
            s.push_str(&format!(
                "- confidential compute hardware: {}\n",
                if st.tee_capable { "present" } else { "not present" }
            ));
        }
        None => s.push_str("- status: not running\n"),
    }

    match crate::wallet::status(state).await {
        Ok(w) if w.exists => {
            s.push_str(&format!(
                "\nWALLET\n- address: {}\n- custody: {}\n- balance: {}\n",
                w.display_address,
                custody_label(&w.custody),
                w.balance_display,
            ));
            let unmet: Vec<&str> = w
                .gates
                .iter()
                .filter(|g| !g.met)
                .map(|g| g.label.as_str())
                .collect();
            if !unmet.is_empty() {
                s.push_str(&format!(
                    "- roles the balance does not yet cover: {}\n",
                    unmet.join(", ")
                ));
            }
        }
        _ => s.push_str("\nWALLET\n- no wallet set up yet\n"),
    }

    s.push_str("\nMODELS\n");
    if cfg.models.is_empty() {
        s.push_str("- none selected to serve\n");
    } else {
        let catalog = tenzro_model::catalog::get_model_catalog();
        for id in &cfg.models {
            let downloaded = catalog
                .iter()
                .find(|e| &e.id == id)
                .map(|e| crate::rpc::on_disk(e).0)
                .unwrap_or(false);
            s.push_str(&format!(
                "- {} ({})\n",
                id,
                if downloaded { "downloaded" } else { "not downloaded" }
            ));
        }
    }
    if let Some(runtime) = runtime_arc(state).await {
        let loaded = runtime.list_loaded();
        s.push_str(&format!(
            "- loaded in memory now: {}\n",
            if loaded.is_empty() { "none".to_string() } else { loaded.join(", ") }
        ));
    }

    s.push_str("\nAVAILABILITY\n");
    if cfg.availability.always_on {
        s.push_str("- always on\n");
    } else if cfg.availability.windows.is_empty() {
        s.push_str("- no serving windows set, so the node is not scheduled to serve\n");
    } else {
        for w in &cfg.availability.windows {
            s.push_str(&format!("- {:02}:00-{:02}:00 on {}\n", w.start_hour, w.end_hour, days_label(&w.days)));
        }
    }
    s.push_str(&format!(
        "- serving right now: {}\n",
        if crate::config::serving_now() { "yes" } else { "no" }
    ));

    s.push_str(&format!(
        "\nPRICING\n- inference input: {} per token\n- inference output: {} per token\n\
         - storage offered: {} GB\n",
        crate::wallet::format_tnzo(cfg.ai_pricing.input_price_per_token_wei),
        crate::wallet::format_tnzo(cfg.ai_pricing.output_price_per_token_wei),
        cfg.storage_pricing.capacity_gb,
    ));

    s
}

fn custody_label(custody: &crate::config::Custody) -> &'static str {
    match custody {
        crate::config::Custody::None => "none",
        crate::config::Custody::Hardware => "this machine's TPM or Secure Enclave key",
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

/// Weekday numbers as the config stores them (0 = Monday) rendered for a
/// model to read. An empty list means every day.
fn days_label(days: &[u8]) -> String {
    const NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    if days.is_empty() {
        return "every day".to_string();
    }
    days.iter()
        .filter_map(|d| NAMES.get(*d as usize).copied())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_reads_at_the_right_scale() {
        assert_eq!(format_uptime(0), "0m");
        assert_eq!(format_uptime(90), "1m");
        assert_eq!(format_uptime(3_700), "1h 1m");
        assert_eq!(format_uptime(90_000), "1d 1h");
    }

    #[test]
    fn empty_day_list_means_every_day() {
        assert_eq!(days_label(&[]), "every day");
        assert_eq!(days_label(&[0, 4]), "Mon, Fri");
        assert_eq!(days_label(&[9]), "");
    }
}
