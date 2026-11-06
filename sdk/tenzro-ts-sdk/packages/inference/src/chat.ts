import { ApiError } from "@tenzro/core";
/**
 * The node's chat completion contract: the request `POST /v1/chat/completions`
 * accepts, and the adaptor that turns its streamed chunks into typed events.
 *
 * The node splits reasoning from the answer and assembles tool calls on its
 * side, so the adaptor reads fields and never parses model markup.
 */

import type { ChatMessage } from "./provider";

/** Reasoning budget levels the node accepts. */
export type ReasoningEffort = "low" | "medium" | "high" | "xhigh";

/** A function the model may call. */
export interface ChatTool {
  type: "function";
  function: {
    name: string;
    description?: string;
    /** JSON Schema of the arguments. */
    parameters?: Record<string, unknown>;
  };
}

/** A tool call the model made. */
export interface ToolCall {
  /** Echoed back as `tool_call_id` on the tool's reply. */
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

/** A chat completion request. */
export interface ChatRequest {
  /** Model id, as listed by `GET /v1/models`. */
  model: string;
  messages: ChatMessage[];
  tools?: ChatTool[];
  /** `"none"`, `"auto"`, `"required"`, or a named function. */
  tool_choice?: "none" | "auto" | "required" | { type: "function"; function: { name: string } };
  temperature?: number;
  max_tokens?: number;
  reasoning_effort?: ReasoningEffort;
  /** Whether the model may think before answering. Unset keeps the node's per-model default. */
  enable_thinking?: boolean;
  /** `include_usage` appends a final chunk carrying the token counts. */
  stream_options?: { include_usage?: boolean };
  /** Provider machine addresses (hex or base58) the request may or may not be served by. */
  provider?: { only?: string[]; ignore?: string[] };
}

/** Token counts for one completion. */
export interface Usage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

/** One piece of a streamed completion, in arrival order. */
export type ChatStreamEvent =
  | { type: "reasoning"; text: string }
  | { type: "content"; text: string }
  | { type: "tool_call"; index: number; id?: string; name?: string; arguments: string }
  | { type: "finish"; finish_reason: string; native_finish_reason?: string }
  | { type: "usage"; usage: Usage; cost_wei?: string };

/** A finished completion, assembled from its stream. */
export interface ChatCompletion {
  id: string | null;
  model: string | null;
  /** The answer. */
  content: string;
  /** The reasoning, empty when the model did not think. */
  reasoning: string;
  /** Tool calls in index order. */
  tool_calls: ToolCall[];
  finish_reason: string | null;
  native_finish_reason: string | null;
  usage: Usage | null;
  /** Cost in wei, as a decimal string. */
  cost_wei: string | null;
}

function nonEmpty(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/**
 * Turns the `data` payloads of a chat stream into {@link ChatStreamEvent}s and
 * accumulates the {@link ChatCompletion} they add up to.
 */
export class ChatStreamAssembler {
  private id: string | null = null;
  private model: string | null = null;
  private content = "";
  private reasoning = "";
  private readonly toolCalls = new Map<number, ToolCall>();
  private finishReason: string | null = null;
  private nativeFinishReason: string | null = null;
  private usage: Usage | null = null;
  private costWei: string | null = null;
  private finished = false;

  /** Whether the `[DONE]` terminator has arrived. */
  get done(): boolean {
    return this.finished;
  }

  /**
   * Absorb one event's `data` and return the events it carries. Throws
   * {@link ApiError} for an error frame or a payload that is not a chunk.
   */
  push(data: string): ChatStreamEvent[] {
    if (data === "[DONE]") {
      this.finished = true;
      return [];
    }
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(data) as Record<string, unknown>;
    } catch (e) {
      throw new ApiError(`stream frame is not JSON: ${String(e)}`, "invalid_response", "malformed_frame");
    }
    const err = ApiError.fromBody(frame);
    if (err) throw err;
    if (this.id === null && typeof frame.id === "string") this.id = frame.id;
    if (this.model === null && typeof frame.model === "string") this.model = frame.model;

    const events: ChatStreamEvent[] = [];
    const choice = Array.isArray(frame.choices)
      ? (frame.choices[0] as Record<string, unknown> | undefined)
      : undefined;
    if (choice) {
      const delta = (choice.delta ?? {}) as Record<string, unknown>;
      const reasoning = nonEmpty(delta.reasoning_content);
      if (reasoning !== undefined) {
        this.reasoning += reasoning;
        events.push({ type: "reasoning", text: reasoning });
      }
      const content = nonEmpty(delta.content);
      if (content !== undefined) {
        this.content += content;
        events.push({ type: "content", text: content });
      }
      if (Array.isArray(delta.tool_calls)) {
        for (const call of delta.tool_calls) events.push(this.absorbToolCall(call));
      }
      if (typeof choice.finish_reason === "string") {
        this.finishReason = choice.finish_reason;
        this.nativeFinishReason =
          typeof choice.native_finish_reason === "string" ? choice.native_finish_reason : null;
        const ev: ChatStreamEvent = { type: "finish", finish_reason: choice.finish_reason };
        if (this.nativeFinishReason !== null) ev.native_finish_reason = this.nativeFinishReason;
        events.push(ev);
      }
    }
    if (typeof frame.usage === "object" && frame.usage !== null) {
      const u = frame.usage as Record<string, unknown>;
      if (
        typeof u.prompt_tokens !== "number" ||
        typeof u.completion_tokens !== "number" ||
        typeof u.total_tokens !== "number"
      ) {
        throw new ApiError("usage is malformed", "invalid_response", "malformed_frame");
      }
      const usage: Usage = {
        prompt_tokens: u.prompt_tokens,
        completion_tokens: u.completion_tokens,
        total_tokens: u.total_tokens,
      };
      const costWei = typeof frame.cost_wei === "string" ? frame.cost_wei : null;
      const same =
        this.usage !== null &&
        this.usage.prompt_tokens === usage.prompt_tokens &&
        this.usage.completion_tokens === usage.completion_tokens &&
        this.usage.total_tokens === usage.total_tokens &&
        this.costWei === costWei;
      if (!same) {
        this.usage = usage;
        this.costWei = costWei;
        const ev: ChatStreamEvent = { type: "usage", usage };
        if (costWei !== null) ev.cost_wei = costWei;
        events.push(ev);
      }
    }
    return events;
  }

  private absorbToolCall(call: unknown): ChatStreamEvent {
    const c = (call ?? {}) as Record<string, unknown>;
    if (typeof c.index !== "number") {
      throw new ApiError("tool call delta has no index", "invalid_response", "malformed_frame");
    }
    const fn = (c.function ?? {}) as Record<string, unknown>;
    const id = typeof c.id === "string" ? c.id : undefined;
    const name = typeof fn.name === "string" ? fn.name : undefined;
    const args = typeof fn.arguments === "string" ? fn.arguments : "";
    let entry = this.toolCalls.get(c.index);
    if (!entry) {
      entry = { id: "", type: "function", function: { name: "", arguments: "" } };
      this.toolCalls.set(c.index, entry);
    }
    if (id !== undefined) entry.id = id;
    if (name !== undefined) entry.function.name = name;
    entry.function.arguments += args;
    const ev: ChatStreamEvent = { type: "tool_call", index: c.index, arguments: args };
    if (id !== undefined) ev.id = id;
    if (name !== undefined) ev.name = name;
    return ev;
  }

  /** The completion the stream added up to. */
  completion(): ChatCompletion {
    return {
      id: this.id,
      model: this.model,
      content: this.content,
      reasoning: this.reasoning,
      tool_calls: [...this.toolCalls.entries()]
        .sort(([a], [b]) => a - b)
        .map(([, call]) => ({ ...call, function: { ...call.function } })),
      finish_reason: this.finishReason,
      native_finish_reason: this.nativeFinishReason,
      usage: this.usage,
      cost_wei: this.costWei,
    };
  }
}
