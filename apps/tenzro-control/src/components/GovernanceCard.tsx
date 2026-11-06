import * as React from "react";
import { Badge, Card, Micro } from "@/components/ui";
import { api, errorText } from "@/lib/api";
import { describeHeld, heldLevers, type HeldLever, type LeversRead } from "@/lib/governance";

const REFRESH_MS = 5 * 60_000;

/** Unwraps the JSON-RPC envelope the console returns. */
async function readLevers(): Promise<LeversRead> {
  const envelope = (await api.rpcCall({ method: "tenzro_listLevers", params: {} })) as {
    result?: LeversRead;
    error?: { message?: string };
  };
  if (envelope.error || !envelope.result) throw new Error(envelope.error?.message ?? "the node returned no levers");
  return envelope.result;
}

/// Which network features governance or the protocol guardians are holding,
/// from `tenzro governance levers`.
export function GovernanceCard() {
  const [held, setHeld] = React.useState<HeldLever[] | null>(null);
  const [epoch, setEpoch] = React.useState<number | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    try {
      const read = await readLevers();
      setHeld(heldLevers(read));
      setEpoch(read.epoch);
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  React.useEffect(() => {
    void load();
    const t = setInterval(() => void load(), REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);

  return (
    <Card>
      <div className="flex items-center justify-between gap-4">
        <Micro>Governance</Micro>
        {epoch !== null && <Micro>Epoch {epoch}</Micro>}
      </div>
      {error && <p className="mt-4 text-sm text-destructive">{error}</p>}
      {!held && !error && <p className="mt-4 text-sm text-muted-foreground">Reading the node.</p>}
      {held && held.length === 0 && (
        <p className="mt-4 text-sm text-muted-foreground">Every governed feature is running.</p>
      )}
      {held && held.length > 0 && (
        <div className="mt-4 flex flex-col divide-y divide-border">
          {held.map((h) => (
            <div key={h.key} className="flex items-start justify-between gap-4 py-3">
              <div className="min-w-0">
                <div className="font-mono text-sm">{h.key}</div>
                <div className="text-xs leading-relaxed text-muted-foreground">{describeHeld(h)}</div>
              </div>
              <Badge tone={h.cause === "guardian" ? "bad" : "warn"}>
                {h.state === "retired" ? "Retired" : h.cause === "guardian" ? "Guardian pause" : "Paused"}
              </Badge>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
