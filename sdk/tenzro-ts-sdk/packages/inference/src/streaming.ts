import type { RpcClient } from "@tenzro/core";
import {
  ChatStreamAssembler,
  type ChatCompletion,
  type ChatRequest,
  type ChatStreamEvent,
} from './chat';
import { SseDecoder } from "@tenzro/core";

// ── Types ──

/** SSE connection handle. */
export interface SseConnection {
  /** SSE endpoint URL */
  url: string;
  /** Abort controller for closing the connection */
  abort: AbortController;
}

/** A real-time event from the node. */
export interface StreamEvent {
  /** Event type (e.g., "block", "transaction", "settlement") */
  type: string;
  /** Event data */
  data: unknown;
  /** Event timestamp */
  timestamp?: string;
}

// ── Client ──

/**
 * Client for streaming and real-time operations.
 *
 * Streams chat from the node's `POST /v1/chat/completions` and opens SSE
 * connections to A2A/MCP servers.
 */
export class StreamingClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Stream a chat completion as typed events: reasoning, content, tool-call
   * deltas, finish and usage, in arrival order. An error the node reports,
   * before or during the stream, is thrown as {@link ApiError}.
   *
   * @example
   * ```typescript
   * const request = { model: "qwen3.5-4b", messages: [{ role: "user", content: "Hello!" }] };
   * for await (const event of client.streaming.chatStream(request)) {
   *   if (event.type === "content") process.stdout.write(event.text);
   * }
   * ```
   */
  async *chatStream(request: ChatRequest, signal?: AbortSignal): AsyncGenerator<ChatStreamEvent> {
    yield* this.run(request, new ChatStreamAssembler(), signal);
  }

  /**
   * Stream a chat completion, calling `onEvent` for each event, and return
   * the assembled completion.
   */
  async chat(
    request: ChatRequest,
    onEvent?: (event: ChatStreamEvent) => void,
    signal?: AbortSignal,
  ): Promise<ChatCompletion> {
    const assembler = new ChatStreamAssembler();
    for await (const event of this.run(request, assembler, signal)) {
      onEvent?.(event);
    }
    return assembler.completion();
  }

  private async *run(
    request: ChatRequest,
    assembler: ChatStreamAssembler,
    signal?: AbortSignal,
  ): AsyncGenerator<ChatStreamEvent> {
    const response = await this.rpc.postStream(
      '/v1/chat/completions',
      { ...request, stream: true },
      signal,
    );
    if (!response.body) {
      throw new Error('Response body is null; streaming not supported');
    }
    const reader = response.body.getReader();
    const decoder = new SseDecoder();
    try {
      while (true) {
        const { done, value } = await reader.read();
        const frames = done ? decoder.finish() : decoder.push(value);
        for (const frame of frames) {
          yield* assembler.push(frame.data);
          if (assembler.done) return;
        }
        if (done) return;
      }
    } finally {
      await reader.cancel().catch(() => undefined);
    }
  }

  /**
   * Open an SSE connection to an A2A or MCP endpoint.
   *
   * @param endpoint - Full URL of the SSE endpoint
   * @param onMessage - Callback for each event whose data is JSON
   * @returns SSE connection handle with abort controller
   */
  async openSseConnection(
    endpoint: string,
    onMessage?: (event: StreamEvent) => void,
  ): Promise<SseConnection> {
    const abort = new AbortController();

    if (onMessage) {
      // Start reading SSE in the background
      fetch(endpoint, {
        headers: { Accept: 'text/event-stream' },
        signal: abort.signal,
      })
        .then(async (response) => {
          if (!response.ok || !response.body) return;
          const reader = response.body.getReader();
          const decoder = new SseDecoder();
          const deliver = (frames: { data: string }[]) => {
            for (const frame of frames) {
              try {
                onMessage(JSON.parse(frame.data));
              } catch {
                // Skip non-JSON
              }
            }
          };
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) {
                deliver(decoder.finish());
                break;
              }
              deliver(decoder.push(value));
            }
          } finally {
            reader.releaseLock();
          }
        })
        .catch(() => {
          // Connection closed
        });
    }

    return { url: endpoint, abort };
  }
}
