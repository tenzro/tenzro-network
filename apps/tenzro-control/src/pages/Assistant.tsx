import * as React from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeSanitize from "rehype-sanitize";
import { Button, ErrorBox, Micro, Select, Spinner, TextArea } from "@/components/ui";
import { PageHeader } from "@/components/Shell";
import { cn } from "@/lib/cn";
import {
  api,
  Channel,
  errorText,
  type AssistantEvent,
  type AssistantMessage,
} from "@/lib/api";

interface Turn {
  role: "user" | "assistant";
  content: string;
  /// Set on the assistant turn once generation ends, so the operator can see
  /// what the reply cost without opening a log.
  footer?: string;
  failed?: boolean;
}

/// The node shapes `tenzro_listModelEndpoints`, so read it defensively.
function servedIds(raw: unknown): string[] {
  const container = raw as { endpoints?: unknown } | null;
  const arr = Array.isArray(raw)
    ? raw
    : Array.isArray(container?.endpoints)
      ? (container.endpoints as unknown[])
      : [];
  const out: string[] = [];
  for (const entry of arr) {
    const id = (entry as { model_id?: unknown } | null)?.model_id;
    if (typeof id === "string" && !out.includes(id)) out.push(id);
  }
  return out;
}

export function Assistant() {
  const [turns, setTurns] = React.useState<Turn[]>([]);
  const [draft, setDraft] = React.useState("");
  const [models, setModels] = React.useState<string[]>([]);
  const [modelId, setModelId] = React.useState("");
  const [requestId, setRequestId] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const bottom = React.useRef<HTMLDivElement | null>(null);

  React.useEffect(() => {
    let live = true;
    api
      .rpcCall({ method: "tenzro_listModelEndpoints", params: {} })
      .then((raw) => {
        if (!live) return;
        const ids = servedIds(raw);
        setModels(ids);
        setModelId((current) => (current === "" ? (ids[0] ?? "") : current));
      })
      .catch(() => {
        /* the picker is a convenience; the node resolves a model on its own */
      });
    return () => {
      live = false;
    };
  }, []);

  React.useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth" });
  }, [turns]);

  async function send() {
    const text = draft.trim();
    if (text === "" || requestId !== null) return;

    const history: AssistantMessage[] = [
      ...turns
        .filter((t) => !t.failed)
        .map((t) => ({ role: t.role, content: t.content })),
      { role: "user", content: text },
    ];

    setTurns((prev) => [
      ...prev,
      { role: "user", content: text },
      { role: "assistant", content: "" },
    ]);
    setDraft("");
    setError(null);

    const id = crypto.randomUUID();
    setRequestId(id);

    const channel = new Channel<AssistantEvent>();
    channel.onmessage = (event) => {
      setTurns((prev) => {
        const next = [...prev];
        const last = next.length - 1;
        if (last < 0 || next[last].role !== "assistant") return prev;

        switch (event.kind) {
          case "token":
            next[last] = { ...next[last], content: next[last].content + event.text };
            break;
          case "done":
            next[last] = {
              ...next[last],
              content:
                next[last].content === "" && event.cancelled
                  ? "(stopped)"
                  : next[last].content,
              footer: `${event.outputTokens} tokens · ${event.tokensPerSecond.toFixed(1)}/s${
                event.cancelled ? " · stopped" : ""
              }`,
            };
            break;
          case "error":
            next[last] = { ...next[last], content: event.message, failed: true };
            break;
          case "start":
            break;
        }
        return next;
      });

      if (event.kind === "done" || event.kind === "error") setRequestId(null);
    };

    try {
      await api.assistantChat(
        {
          requestId: id,
          modelId: modelId === "" ? undefined : modelId,
          messages: history,
        },
        channel,
      );
    } catch (e) {
      setError(errorText(e));
      setRequestId(null);
      setTurns((prev) => prev.slice(0, -1));
    }
  }

  async function stop() {
    if (!requestId) return;
    try {
      await api.assistantCancel(requestId);
    } catch (e) {
      setError(errorText(e));
    }
  }

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void send();
    }
  };

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        eyebrow="Operator"
        title="Assistant"
        actions={
          models.length > 1 ? (
            <Select value={modelId} onChange={(e) => setModelId(e.currentTarget.value)}>
              {models.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </Select>
          ) : undefined
        }
      />

      <div className="flex-1 overflow-y-auto px-10 py-8">
        <div className="mx-auto flex max-w-3xl flex-col gap-6">
          {error && <ErrorBox message={error} />}

          {turns.length === 0 && (
            <div className="flex flex-col gap-3 border border-border bg-card p-6">
              <Micro>What this can answer</Micro>
              <p className="text-sm leading-relaxed text-muted-foreground">
                Every question is answered from a live snapshot of this node — its
                height, peers, roles, wallet, models, schedule and prices. Ask what
                the node is doing, why a role is dormant, or what a setting means. It
                cannot reach outside that snapshot, and it will say so when a question
                falls outside it.
              </p>
            </div>
          )}

          {turns.map((t, i) => (
            <TurnView key={i} turn={t} streaming={requestId !== null && i === turns.length - 1} />
          ))}

          <div ref={bottom} />
        </div>
      </div>

      <div className="border-t border-border px-10 py-5">
        <div className="mx-auto flex max-w-3xl items-end gap-3">
          <TextArea
            rows={2}
            value={draft}
            placeholder="Ask about this node…"
            onChange={(e) => setDraft(e.currentTarget.value)}
            onKeyDown={onKeyDown}
            className="flex-1 resize-none"
          />
          {requestId ? (
            <Button onClick={() => void stop()}>Stop</Button>
          ) : (
            <Button variant="primary" onClick={() => void send()} disabled={draft.trim() === ""}>
              Send
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

function TurnView({ turn, streaming }: { turn: Turn; streaming: boolean }) {
  if (turn.role === "user") {
    return (
      <div className="flex flex-col gap-2">
        <Micro>You</Micro>
        <p className="whitespace-pre-wrap text-sm leading-relaxed">{turn.content}</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <Micro>Assistant</Micro>
      {turn.content === "" && streaming ? (
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          <Spinner />
          Thinking…
        </div>
      ) : (
        <div
          className={cn(
            "tnz-prose text-sm leading-relaxed",
            turn.failed && "text-destructive",
          )}
        >
          <Markdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize]}>
            {turn.content}
          </Markdown>
        </div>
      )}
      {turn.footer && (
        <span className="font-mono text-[10px] text-muted-foreground">{turn.footer}</span>
      )}
    </div>
  );
}
