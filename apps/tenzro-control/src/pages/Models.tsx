import * as React from "react";
import { Badge, Button, Card, ErrorBox, Meter, Micro, Spinner } from "@/components/ui";
import { PageHeader } from "@/components/Shell";
import { cn } from "@/lib/cn";
import {
  api,
  errorText,
  type BudgetReadout,
  type ModelBudgetEntry,
  type ModelDownloadStatus,
} from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { sellsModels } from "@/lib/roles";

/// `tenzro_listModelEndpoints` is shaped by the node, not by Control, so read
/// it defensively rather than pinning a type to it.
function servedIds(raw: unknown): Set<string> {
  const container = raw as { endpoints?: unknown } | null;
  const arr = Array.isArray(raw)
    ? raw
    : Array.isArray(container?.endpoints)
      ? (container.endpoints as unknown[])
      : [];
  const out = new Set<string>();
  for (const entry of arr) {
    const id = (entry as { model_id?: unknown } | null)?.model_id;
    if (typeof id === "string") out.add(id);
  }
  return out;
}

export function Models() {
  const [budget, setBudget] = React.useState<BudgetReadout | null>(null);
  const [selected, setSelected] = React.useState<string[]>([]);
  const [storageGb, setStorageGb] = React.useState(0);
  const [served, setServed] = React.useState<Set<string>>(new Set());
  /// A local-only operator loads the same models but announces none of them,
  /// so the serve call has to ask for private visibility.
  const [offersToNetwork, setOffersToNetwork] = React.useState(false);
  const [progress, setProgress] = React.useState<ModelDownloadStatus[]>([]);
  const [pending, setPending] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    try {
      const config = await api.getConfig();
      setSelected(config.models);
      setStorageGb(config.storage_pricing.capacity_gb);
      setOffersToNetwork(sellsModels(config.roles));
      const [b, endpoints] = await Promise.all([
        api.modelBudget(config.models, config.storage_pricing.capacity_gb),
        api.rpcCall({ method: "tenzro_listModelEndpoints", params: {} }).catch(() => null),
      ]);
      setBudget(b);
      setServed(servedIds(endpoints));
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const downloading = progress.some((p) => p.status === "downloading");

  React.useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const p = await api.downloadProgress();
        if (!live) return;
        setProgress(p);
      } catch {
        /* progress is advisory; a failed poll is not worth surfacing */
      }
    };
    void tick();
    const t = setInterval(() => void tick(), downloading ? 2_000 : 10_000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [downloading]);

  const act = async (id: string, fn: () => Promise<unknown>) => {
    setPending(id);
    setError(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setPending(null);
    }
  };

  const toggleSelected = (id: string) => {
    const next = selected.includes(id)
      ? selected.filter((m) => m !== id)
      : [...selected, id];
    void act(id, async () => {
      await api.setModels(next);
      setSelected(next);
      setBudget(await api.modelBudget(next, storageGb));
    });
  };

  return (
    <div>
      <PageHeader
        eyebrow="Catalogue"
        title="Models"
        actions={
          <Button onClick={() => void refresh()} disabled={pending !== null}>
            Refresh
          </Button>
        }
      />

      <div className="flex flex-col gap-4 px-10 py-8">
        {error && <ErrorBox message={error} />}

        {budget ? (
          <Card>
            <div className="grid gap-8 sm:grid-cols-2">
              <BudgetPanel
                title="Memory"
                available={budget.ram_available_gb}
                total={budget.ram_total_gb}
                used={budget.ram_total_gb - budget.ram_available_gb}
                parts={[
                  ["System reserve", budget.ram_reserved_gb],
                  ["Selected models", budget.ram_selected_gb],
                ]}
              />
              <BudgetPanel
                title="Disk"
                available={budget.disk_available_gb}
                total={budget.disk_total_gb}
                used={budget.disk_total_gb - budget.disk_available_gb}
                parts={[
                  ["System reserve", budget.disk_reserved_gb],
                  ["Model downloads", budget.disk_downloads_gb],
                  ["Storage pledge", budget.disk_storage_gb],
                ]}
              />
            </div>
          </Card>
        ) : (
          <Card>
            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <Spinner />
              Reading the catalogue…
            </div>
          </Card>
        )}

        {budget && (
          <div className="flex flex-col border border-border">
            {budget.models.map((m, i) => (
              <ModelRow
                key={m.id}
                entry={m}
                first={i === 0}
                selected={selected.includes(m.id)}
                serving={served.has(m.id)}
                offersToNetwork={offersToNetwork}
                progress={progress.find((p) => p.model_id === m.id) ?? null}
                busy={pending === m.id}
                onToggle={() => toggleSelected(m.id)}
                onServe={(visibility) => void act(m.id, () => api.serveModel(m.id, visibility))}
                onStop={() => void act(m.id, () => api.stopModel(m.id))}
                onUnload={() => void act(m.id, () => api.offloadModel(m.id))}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function BudgetPanel({
  title,
  available,
  total,
  used,
  parts,
}: {
  title: string;
  available: number;
  total: number;
  used: number;
  parts: [string, number][];
}) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-baseline justify-between">
        <Micro>{title}</Micro>
        <span className="font-mono text-sm">
          {available} GB free of {total}
        </span>
      </div>
      <Meter used={used} total={total} />
      <div className="flex flex-col gap-1">
        {parts.map(([label, value]) => (
          <div key={label} className="flex items-baseline justify-between text-xs">
            <span className="text-muted-foreground">{label}</span>
            <span className="font-mono text-muted-foreground">{value} GB</span>
          </div>
        ))}
      </div>
    </div>
  );
}

type Visibility = "network" | "gated" | "private";

const VISIBILITY_OPTIONS: { id: Visibility; label: string; hint: string }[] = [
  { id: "network", label: "Network", hint: "Announced — any caller may invoke it by paying" },
  { id: "gated", label: "Gated", hint: "Not announced — reachable only with an API key" },
  { id: "private", label: "Private", hint: "This machine only, never announced" },
];

function ModelRow({
  entry,
  first,
  selected,
  serving,
  offersToNetwork,
  progress,
  busy,
  onToggle,
  onServe,
  onStop,
  onUnload,
}: {
  entry: ModelBudgetEntry;
  first: boolean;
  selected: boolean;
  serving: boolean;
  offersToNetwork: boolean;
  progress: ModelDownloadStatus | null;
  busy: boolean;
  onToggle: () => void;
  onServe: (visibility: Visibility) => void;
  onStop: () => void;
  onUnload: () => void;
}) {
  const selectable = selected || entry.fit === "fits";
  const isDownloading = progress?.status === "downloading";
  const [visibility, setVisibility] = React.useState<Visibility>(
    offersToNetwork ? "network" : "private",
  );

  return (
    <div
      className={cn(
        "flex flex-col gap-4 px-5 py-4",
        !first && "border-t border-border",
        selected ? "bg-brand-soft" : "bg-card",
      )}
    >
      <div className="flex items-start gap-4">
        <button
          type="button"
          onClick={onToggle}
          disabled={!selectable || busy}
          title={
            selected
              ? "Remove from this node"
              : offersToNetwork
                ? "Offer this model"
                : "Keep this model on this machine"
          }
          className={cn(
            "mt-1 h-3 w-3 flex-shrink-0 border",
            selected ? "border-brand bg-brand" : "border-border",
            selectable ? "hover:border-muted-foreground" : "cursor-not-allowed opacity-40",
          )}
        />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm">{entry.name}</span>
            {entry.vision && <Badge>Vision</Badge>}
            {entry.moe && <Badge>MoE</Badge>}
            {entry.downloaded && <Badge tone="good">On disk</Badge>}
            {serving && (
              <Badge tone="good">{offersToNetwork ? "Serving" : "Running"}</Badge>
            )}
          </div>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {entry.description}
          </p>
          {entry.reason && <p className="mt-1 text-xs text-destructive">{entry.reason}</p>}
          {progress?.error && (
            <p className="mt-1 text-xs text-destructive">{progress.error}</p>
          )}
        </div>

        <div className="flex flex-shrink-0 flex-col items-end gap-0.5 font-mono text-[11px] text-muted-foreground">
          <span>{entry.parameters}</span>
          <span>{entry.quantization}</span>
          <span>{formatBytes(entry.size_bytes)}</span>
          <span>{entry.min_ram_gb} GB RAM</span>
        </div>
      </div>

      {isDownloading && progress && (
        <div className="flex flex-col gap-2">
          <Meter used={progress.progress_percent} total={100} />
          <div className="flex justify-between font-mono text-[10px] text-muted-foreground">
            <span>
              {formatBytes(progress.downloaded_bytes)} of {formatBytes(progress.total_bytes)}
            </span>
            <span>{Math.round(progress.progress_percent)}%</span>
          </div>
        </div>
      )}

      {entry.downloaded && !serving && (
        <div className="flex items-center gap-1" role="radiogroup" aria-label="Visibility">
          {VISIBILITY_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              type="button"
              role="radio"
              aria-checked={visibility === opt.id}
              title={opt.hint}
              onClick={() => setVisibility(opt.id)}
              className={cn(
                "border px-2 py-1 font-mono text-[10px] uppercase tracking-wide transition-colors",
                visibility === opt.id
                  ? "border-brand bg-brand-soft text-foreground"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}

      <div className="flex items-center gap-2">
        {!serving && (
          <Button variant="primary" onClick={() => onServe(visibility)} busy={busy}>
            {visibility === "private" ? "Run" : "Serve"}
          </Button>
        )}
        {serving && (
          <Button onClick={onStop} busy={busy}>
            {offersToNetwork ? "Stop serving" : "Stop"}
          </Button>
        )}
        {entry.downloaded && (
          <Button variant="ghost" onClick={onUnload} busy={busy}>
            Free memory
          </Button>
        )}
      </div>
    </div>
  );
}
