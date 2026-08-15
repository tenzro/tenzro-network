//! Streaming stop-sequence and reasoning-span handling.
//!
//! Backend-free: this is pure text bookkeeping over decoded pieces, so it
//! compiles and runs without a bundled backend. It accumulates decoded token
//! pieces, splits reasoning spans (`<think>` … `</think>`) from visible text,
//! detects stop sequences (which may span several tokens), and — when the
//! caller is streaming — releases bytes only once they can no longer turn out
//! to be the leading part of a stop sequence or a reasoning marker.

/// Byte length of the longest stop sequence that `text` ends with, or `None`
/// when no stop sequence matched. The caller truncates by that many bytes so
/// the delimiter never reaches the client.
pub fn matched_stop_len(text: &str, stop: &[String]) -> Option<usize> {
    stop.iter()
        .filter(|s| !s.is_empty() && text.ends_with(s.as_str()))
        .map(|s| s.len())
        .max()
}

/// Reasoning-span markers. Ordinary text, not special tokens, so they arrive
/// split across pieces like anything else.
const THINK_OPEN: &str = "<think>";
const THINK_CLOSE: &str = "</think>";

/// Length of the longest suffix of `s` that is a strict prefix of `marker`.
///
/// Those bytes cannot be classified yet: `<thi` is either the start of a marker
/// or four literal characters, and only the next piece decides. Holding them is
/// the same trick the stop-sequence path uses.
fn dangling_prefix(s: &str, marker: &str) -> usize {
    let max = s.len().min(marker.len() - 1);
    (1..=max)
        .rev()
        .find(|&k| {
            s.is_char_boundary(s.len() - k) && s.as_bytes()[s.len() - k..] == marker.as_bytes()[..k]
        })
        .unwrap_or(0)
}

/// Accumulates decoded token pieces, detects stop sequences, and — when the
/// caller is streaming — releases bytes only once they can no longer turn out
/// to be the leading part of a stop sequence.
///
/// A stop sequence may span several tokens, so the last `hold` bytes are kept
/// back until either more text disambiguates them or generation ends. With no
/// stop sequences configured `hold` is zero and every piece is released the
/// moment it is decoded.
pub struct StopStream {
    /// Text the caller is meant to see: reasoning spans removed.
    text: String,
    /// The model's reasoning, accumulated separately.
    reasoning: String,
    /// Bytes decoded but not yet classified, because they could still turn out
    /// to be the leading part of a `<think>` / `</think>` marker.
    pending: String,
    emitted: usize,
    hold: usize,
    stop: Vec<String>,
    hit: bool,
    in_think: bool,
}

impl StopStream {
    /// Build a stream that trims the given stop sequences.
    pub fn new(stop: Vec<String>) -> Self {
        let hold = stop
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.len())
            .max()
            .unwrap_or(0);
        Self {
            text: String::new(),
            reasoning: String::new(),
            pending: String::new(),
            emitted: 0,
            hold,
            stop,
            hit: false,
            in_think: false,
        }
    }

    /// Absorb one decoded piece. Returns `false` when the stream receiver has
    /// been dropped, which the generation loops treat as "stop generating".
    pub fn push(&mut self, piece: &str, tx: Option<&tokio::sync::mpsc::Sender<String>>) -> bool {
        self.pending.push_str(piece);
        self.classify();
        if let Some(n) = matched_stop_len(&self.text, &self.stop) {
            self.text.truncate(self.text.len() - n);
            self.emitted = self.emitted.min(self.text.len());
            self.hit = true;
        }
        self.release(tx)
    }

    /// Move settled bytes out of `pending` into either the visible text or the
    /// reasoning buffer, leaving behind only what a marker could still claim.
    fn classify(&mut self) {
        loop {
            if self.in_think {
                if let Some(i) = self.pending.find(THINK_CLOSE) {
                    self.reasoning.push_str(&self.pending[..i]);
                    self.pending.drain(..i + THINK_CLOSE.len());
                    self.in_think = false;
                    continue;
                }
                let keep = dangling_prefix(&self.pending, THINK_CLOSE);
                let take = self.pending.len() - keep;
                self.reasoning.push_str(&self.pending[..take]);
                self.pending.drain(..take);
                return;
            }

            if let Some(i) = self.pending.find(THINK_OPEN) {
                self.text.push_str(&self.pending[..i]);
                self.pending.drain(..i + THINK_OPEN.len());
                self.in_think = true;
                continue;
            }

            // A close with no open: the chat template opened the block in the
            // prompt, so the model's output starts mid-thought. Everything so
            // far was reasoning — reclaimable only while nothing has been
            // streamed yet, since bytes already sent cannot be recalled.
            if let Some(i) = self.pending.find(THINK_CLOSE) {
                self.text.push_str(&self.pending[..i]);
                self.pending.drain(..i + THINK_CLOSE.len());
                if self.emitted == 0 {
                    self.reasoning.push_str(&self.text);
                    self.text.clear();
                }
                continue;
            }

            let keep = dangling_prefix(&self.pending, THINK_OPEN)
                .max(dangling_prefix(&self.pending, THINK_CLOSE));
            let take = self.pending.len() - keep;
            self.text.push_str(&self.pending[..take]);
            self.pending.drain(..take);
            return;
        }
    }

    fn release(&mut self, tx: Option<&tokio::sync::mpsc::Sender<String>>) -> bool {
        let Some(tx) = tx else { return true };
        let mut boundary = if self.hit {
            self.text.len()
        } else {
            self.text.len().saturating_sub(self.hold)
        };
        while boundary > self.emitted && !self.text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        if boundary <= self.emitted {
            return true;
        }
        let chunk = self.text[self.emitted..boundary].to_string();
        self.emitted = boundary;
        tx.blocking_send(chunk).is_ok()
    }

    /// Whether a stop sequence has been matched.
    pub fn hit_stop(&self) -> bool {
        self.hit
    }

    /// Release anything still held back, then hand over the visible text and
    /// the reasoning span the model produced, if any.
    pub fn finish_parts(
        mut self,
        tx: Option<&tokio::sync::mpsc::Sender<String>>,
    ) -> (String, Option<String>) {
        let leftover = std::mem::take(&mut self.pending);
        if self.in_think {
            self.reasoning.push_str(&leftover);
        } else if !THINK_OPEN.starts_with(&leftover) && !THINK_CLOSE.starts_with(&leftover) {
            self.text.push_str(&leftover);
        }
        self.hit = true;
        self.release(tx);
        let reasoning = self.reasoning.trim().to_string();
        (self.text, (!reasoning.is_empty()).then_some(reasoning))
    }
}
