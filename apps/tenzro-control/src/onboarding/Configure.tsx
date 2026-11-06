import * as React from "react";
import { Badge, Card, Empty, Meter, Micro, Spinner } from "@/components/ui";
import { cn } from "@/lib/cn";
import { api, errorText, type BudgetReadout, type ModelBudgetEntry } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { runsModels } from "@/lib/roles";
import { Step } from "./Step";

export function Configure({
  roles,
  models,
  onModels,
  storagePledgeGb,
  onStoragePledge,
  maxStorageGb,
  onBack,
  onNext,
}: {
  roles: string[];
  models: string[];
  onModels: (ids: string[]) => void;
  storagePledgeGb: number;
  onStoragePledge: (gb: number) => void;
  maxStorageGb: number;
  onBack: () => void;
  onNext: () => void;
}) {
  const wantsModels = runsModels(roles);
  const wantsStorage = roles.includes("storage");

  const [budget, setBudget] = React.useState<BudgetReadout | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let live = true;
    api
      .modelBudget(models, storagePledgeGb)
      .then((b) => live && setBudget(b))
      .catch((e) => live && setError(errorText(e)));
    return () => {
      live = false;
    };
  }, [models, storagePledgeGb]);

  const toggle = (entry: ModelBudgetEntry) => {
    if (models.includes(entry.id)) {
      onModels(models.filter((m) => m !== entry.id));
    } else if (entry.fit === "fits") {
      onModels([...models, entry.id]);
    }
  };

  return (
    <Step
      index={3}
      eyebrow="Step four"
      title="Set what you commit"
      description="Memory and disk are shared between everything this machine offers. The figures below move as you choose, so you can see what is left before you commit."
      error={error}
      onBack={onBack}
      onNext={onNext}
      footerNote={
        wantsModels
          ? `${models.length} model${models.length === 1 ? "" : "s"} selected`
          : `${storagePledgeGb} GB pledged`
      }
    >
      <div className="flex flex-col gap-4">
        {budget ? (
          <Card>
            <div className="grid gap-8 sm:grid-cols-2">
              <Budgets
                title="Memory"
                unit="GB"
                total={budget.ram_total_gb}
                used={budget.ram_total_gb - budget.ram_available_gb}
                available={budget.ram_available_gb}
                parts={[
                  ["System reserve", budget.ram_reserved_gb],
                  ["Selected models", budget.ram_selected_gb],
                ]}
              />
              <Budgets
                title="Disk"
                unit="GB"
                total={budget.disk_total_gb}
                used={budget.disk_total_gb - budget.disk_available_gb}
                available={budget.disk_available_gb}
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
              Working out what fits…
            </div>
          </Card>
        )}

        {wantsStorage && (
          <Card>
            <div className="flex items-baseline justify-between">
              <Micro>Storage pledge</Micro>
              <span className="font-mono text-sm">{storagePledgeGb} GB</span>
            </div>
            <input
              type="range"
              min={0}
              max={Math.max(maxStorageGb, 0)}
              step={1}
              value={Math.min(storagePledgeGb, maxStorageGb)}
              onChange={(e) => onStoragePledge(Number(e.currentTarget.value))}
              className="mt-4 w-full accent-[var(--brand)]"
            />
            <div className="mt-2 flex justify-between text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
              <span>0 GB</span>
              <span>{maxStorageGb} GB free to pledge</span>
            </div>
          </Card>
        )}

        {wantsModels && budget && (
          <div className="flex flex-col gap-2">
            <Micro>Catalogue</Micro>
            {budget.models.length === 0 ? (
              <Empty>No models in the catalogue.</Empty>
            ) : (
              <div className="flex flex-col border border-border">
                {budget.models.map((m, i) => (
                  <ModelRow
                    key={m.id}
                    entry={m}
                    selected={models.includes(m.id)}
                    onToggle={() => toggle(m)}
                    first={i === 0}
                  />
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </Step>
  );
}

function Budgets({
  title,
  unit,
  total,
  used,
  available,
  parts,
}: {
  title: string;
  unit: string;
  total: number;
  used: number;
  available: number;
  parts: [string, number][];
}) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-baseline justify-between">
        <Micro>{title}</Micro>
        <span className="font-mono text-sm">
          {available} {unit} free of {total}
        </span>
      </div>
      <Meter used={used} total={total} />
      <div className="flex flex-col gap-1">
        {parts.map(([label, value]) => (
          <div key={label} className="flex items-baseline justify-between text-xs">
            <span className="text-muted-foreground">{label}</span>
            <span className="font-mono text-muted-foreground">
              {value} {unit}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ModelRow({
  entry,
  selected,
  onToggle,
  first,
}: {
  entry: ModelBudgetEntry;
  selected: boolean;
  onToggle: () => void;
  first: boolean;
}) {
  const selectable = selected || entry.fit === "fits";

  return (
    <button
      type="button"
      onClick={onToggle}
      disabled={!selectable}
      className={cn(
        "flex items-start gap-4 px-4 py-3 text-left transition-colors",
        !first && "border-t border-border",
        selected ? "bg-brand-soft" : "bg-card",
        selectable ? "hover:bg-accent" : "cursor-not-allowed opacity-40",
      )}
    >
      <span
        className={cn(
          "mt-1 h-3 w-3 flex-shrink-0 border",
          selected ? "border-brand bg-brand" : "border-border",
        )}
      />

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm">{entry.name}</span>
          {entry.vision && <Badge>Vision</Badge>}
          {entry.moe && <Badge>MoE</Badge>}
          {entry.downloaded && <Badge tone="good">On disk</Badge>}
        </div>
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{entry.description}</p>
        {entry.reason && <p className="mt-1 text-xs text-destructive">{entry.reason}</p>}
      </div>

      <div className="flex flex-shrink-0 flex-col items-end gap-0.5 font-mono text-[11px] text-muted-foreground">
        <span>{entry.parameters}</span>
        <span>{entry.quantization}</span>
        <span>{formatBytes(entry.size_bytes)}</span>
        <span>{entry.min_ram_gb} GB RAM</span>
      </div>
    </button>
  );
}
