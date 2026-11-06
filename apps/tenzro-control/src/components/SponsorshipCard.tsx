import * as React from "react";
import { platform } from "@tauri-apps/plugin-os";
import { Badge, Card, Micro, Row } from "@/components/ui";
import { api, errorText } from "@/lib/api";
import { formatTnzo } from "@/lib/format";
import {
  assess,
  platformOf,
  readSponsorship,
  type Assessment,
  type Level,
  type Read,
  type SponsorshipInputs,
} from "@/lib/sponsorship";

const REFRESH_MS = 5 * 60_000;

const TONE: Record<Level, "good" | "bad" | "warn" | "neutral"> = {
  pass: "good",
  fail: "bad",
  warn: "warn",
  todo: "neutral",
};

const LABEL: Record<Level, string> = {
  pass: "Met",
  fail: "Blocked",
  warn: "Note",
  todo: "To do",
};

/** Unwraps the JSON-RPC envelope the console returns; null on any failure. */
const read: Read = async (method, params) => {
  try {
    const envelope = (await api.rpcCall({ method, params })) as { result?: unknown; error?: unknown };
    return envelope.error ? null : (envelope.result ?? null);
  } catch {
    return null;
  }
};

/// Where this operator stands against sponsorship: the same reads and the
/// same criteria as `tenzro sponsor check`.
export function SponsorshipCard() {
  const [inputs, setInputs] = React.useState<SponsorshipInputs | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    try {
      setInputs(await readSponsorship(read, { platform: platformOf(platform()) }));
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

  const verdict: Assessment | null = inputs ? assess(inputs) : null;

  return (
    <Card>
      <div className="flex items-center justify-between gap-4">
        <Micro>Sponsorship</Micro>
        {verdict && (
          <Badge tone={verdict.approved ? "good" : verdict.readyToApply ? "neutral" : "warn"}>
            {verdict.approved ? "Approved" : verdict.readyToApply ? "Ready to apply" : "Not yet"}
          </Badge>
        )}
      </div>
      {error && <p className="mt-4 text-sm text-destructive">{error}</p>}
      {!verdict && !error && <p className="mt-4 text-sm text-muted-foreground">Reading the node.</p>}
      {verdict && inputs && (
        <>
          <div className="mt-4 flex flex-col divide-y divide-border">
            {verdict.criteria.map((c) => (
              <div key={c.label} className="flex items-start justify-between gap-4 py-3">
                <div className="min-w-0">
                  <div className="text-sm">{c.label}</div>
                  <div className="text-xs leading-relaxed text-muted-foreground">{c.detail}</div>
                </div>
                <Badge tone={TONE[c.level]}>{LABEL[c.level]}</Badge>
              </div>
            ))}
          </div>
          <div className="mt-2 flex flex-col divide-y divide-border">
            <Row label="Paid so far" value={formatTnzo(inputs.receivedWei)} />
            <Row label="Sponsored validator bond" value={formatTnzo(inputs.sponsoredBondedWei)} />
          </div>
          {verdict.readyToApply && (
            <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
              Approval is a governance proposal that an account holding bonded stake files. Run
              `tenzro sponsor apply` on this machine to prepare the exact command for a proposer.
            </p>
          )}
        </>
      )}
    </Card>
  );
}
