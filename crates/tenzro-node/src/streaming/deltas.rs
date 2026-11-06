//! The ordered deltas a local `/v1/chat/completions` stream emits.
//!
//! The engine delivers a generation on two channels: the answer on the token
//! channel and the reasoning on the reasoning channel, each as it is
//! produced. [`ChatDeltas`] merges them, reasoning first whenever both have
//! something waiting, so a thinking model's trace reaches the caller while
//! the model is still thinking rather than on the terminal chunk.

use tokio::sync::mpsc::Receiver;

/// One piece of a streamed completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatDelta {
    /// Rides on the chunk's `delta.reasoning_content`.
    Reasoning(String),
    /// Rides on the chunk's `delta.content`.
    Content(String),
}

/// Merges a generation's answer and reasoning channels.
///
/// The stream ends when the answer channel closes, which happens when the
/// generation returns; reasoning still queued at that point is drained, but a
/// reasoning sender kept alive elsewhere never holds the stream open.
///
/// Reasoning that is only whitespace so far is held back: a template that
/// renders an empty think block with thinking off would otherwise stream a
/// blank trace. It is released in front of the first visible reasoning.
pub struct ChatDeltas {
    content: Receiver<String>,
    reasoning: Receiver<String>,
    held: String,
    streamed: String,
    content_closed: bool,
}

impl ChatDeltas {
    pub fn new(content: Receiver<String>, reasoning: Receiver<String>) -> Self {
        Self {
            content,
            reasoning,
            held: String::new(),
            streamed: String::new(),
            content_closed: false,
        }
    }

    /// The next delta, `None` once the generation has finished.
    pub async fn next(&mut self) -> Option<ChatDelta> {
        loop {
            let piece = if self.content_closed {
                self.reasoning.try_recv().ok()?
            } else {
                tokio::select! {
                    biased;
                    Some(piece) = self.reasoning.recv() => piece,
                    content = self.content.recv() => match content {
                        Some(text) => return Some(ChatDelta::Content(text)),
                        None => {
                            self.content_closed = true;
                            continue;
                        }
                    },
                }
            };
            if let Some(delta) = self.reasoning_delta(piece) {
                return Some(delta);
            }
        }
    }

    fn reasoning_delta(&mut self, piece: String) -> Option<ChatDelta> {
        if self.streamed.is_empty() && piece.trim().is_empty() {
            self.held.push_str(&piece);
            return None;
        }
        let mut text = std::mem::take(&mut self.held);
        text.push_str(&piece);
        self.streamed.push_str(&text);
        Some(ChatDelta::Reasoning(text))
    }

    /// Reasoning for the terminal chunk: the finished result's trace, when
    /// none was streamed (a path that only learns it once generation ends).
    pub fn unstreamed_reasoning(&self, thinking: Option<&str>) -> Option<String> {
        if !self.streamed.is_empty() {
            return None;
        }
        thinking
            .filter(|t| !t.trim().is_empty())
            .map(str::to_string)
    }

    /// The reasoning streamed so far, exactly as the caller received it.
    pub fn streamed_reasoning(&self) -> &str {
        &self.streamed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::channel;

    async fn collect(mut deltas: ChatDeltas) -> (Vec<ChatDelta>, ChatDeltas) {
        let mut out = Vec::new();
        while let Some(d) = deltas.next().await {
            out.push(d);
        }
        (out, deltas)
    }

    /// A think block streams as reasoning deltas that all arrive before the
    /// first content delta, the order a model produces them in.
    #[tokio::test]
    async fn reasoning_deltas_precede_the_first_content_delta() {
        let (ctx, crx) = channel(256);
        let (rtx, rrx) = channel(256);
        let producer = tokio::spawn(async move {
            for piece in ["Two plus", " two", " is four."] {
                rtx.send(piece.to_string()).await.unwrap();
            }
            for piece in ["The answer", " is 4."] {
                ctx.send(piece.to_string()).await.unwrap();
            }
        });
        let (deltas, rest) = collect(ChatDeltas::new(crx, rrx)).await;
        producer.await.unwrap();
        let first_content = deltas
            .iter()
            .position(|d| matches!(d, ChatDelta::Content(_)))
            .unwrap();
        assert_eq!(
            deltas[..first_content],
            [
                ChatDelta::Reasoning("Two plus".into()),
                ChatDelta::Reasoning(" two".into()),
                ChatDelta::Reasoning(" is four.".into()),
            ]
        );
        assert!(
            deltas[first_content..]
                .iter()
                .all(|d| matches!(d, ChatDelta::Content(_)))
        );
        assert_eq!(rest.streamed_reasoning(), "Two plus two is four.");
        assert_eq!(
            rest.unstreamed_reasoning(Some("Two plus two is four.")),
            None
        );
    }

    /// Reasoning is delivered while generation is still running: the first
    /// delta is readable before the producer has sent any content.
    #[tokio::test]
    async fn reasoning_is_readable_before_generation_ends() {
        let (ctx, crx) = channel(256);
        let (rtx, rrx) = channel(256);
        let mut deltas = ChatDeltas::new(crx, rrx);
        rtx.send("thinking".to_string()).await.unwrap();
        assert_eq!(
            deltas.next().await,
            Some(ChatDelta::Reasoning("thinking".into()))
        );
        ctx.send("done".to_string()).await.unwrap();
        drop(ctx);
        assert_eq!(deltas.next().await, Some(ChatDelta::Content("done".into())));
        assert_eq!(deltas.next().await, None);
        drop(rtx);
    }

    /// A reasoning sender that outlives the generation does not hold the
    /// stream open, and reasoning already queued is still delivered.
    #[tokio::test]
    async fn stream_ends_with_the_answer_channel() {
        let (ctx, crx) = channel(256);
        let (rtx, rrx) = channel(256);
        rtx.send("late".to_string()).await.unwrap();
        drop(ctx);
        let (deltas, _) = collect(ChatDeltas::new(crx, rrx)).await;
        assert_eq!(deltas, [ChatDelta::Reasoning("late".into())]);
        drop(rtx);
    }

    /// Whitespace-only reasoning is never streamed; leading whitespace is
    /// released with the first visible reasoning.
    #[tokio::test]
    async fn blank_reasoning_is_held_back() {
        let (ctx, crx) = channel(256);
        let (rtx, rrx) = channel(256);
        rtx.send("\n\n".to_string()).await.unwrap();
        ctx.send("Hi".to_string()).await.unwrap();
        drop((ctx, rtx));
        let (deltas, rest) = collect(ChatDeltas::new(crx, rrx)).await;
        assert_eq!(deltas, [ChatDelta::Content("Hi".into())]);
        assert_eq!(rest.streamed_reasoning(), "");
        assert_eq!(rest.unstreamed_reasoning(Some("\n\n")), None);

        let (ctx, crx) = channel(256);
        let (rtx, rrx) = channel(256);
        rtx.send("\n".to_string()).await.unwrap();
        rtx.send("hmm".to_string()).await.unwrap();
        drop((ctx, rtx));
        let (deltas, _) = collect(ChatDeltas::new(crx, rrx)).await;
        assert_eq!(deltas, [ChatDelta::Reasoning("\nhmm".into())]);
    }

    /// A path that only learns the reasoning at the end carries it on the
    /// terminal chunk.
    #[tokio::test]
    async fn unstreamed_reasoning_rides_on_the_terminal_chunk() {
        let (ctx, crx) = channel(256);
        let (_rtx, rrx) = channel::<String>(256);
        ctx.send("answer".to_string()).await.unwrap();
        drop(ctx);
        let (_, rest) = collect(ChatDeltas::new(crx, rrx)).await;
        assert_eq!(
            rest.unstreamed_reasoning(Some("why")),
            Some("why".to_string())
        );
    }
}
