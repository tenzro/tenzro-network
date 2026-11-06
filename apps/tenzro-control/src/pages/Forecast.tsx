import * as React from "react";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorBox,
  Field,
  Input,
  Row,
  Spinner,
} from "@/components/ui";
import { PageHeader } from "@/components/Shell";
import { cn } from "@/lib/cn";
import {
  api,
  errorText,
  type ForecastCatalogEntry,
  type ForecastResult,
  type LoadedForecaster,
} from "@/lib/api";
import { formatBytes } from "@/lib/format";

export function Forecast() {
  const [catalog, setCatalog] = React.useState<ForecastCatalogEntry[] | null>(null);
  const [loaded, setLoaded] = React.useState<Map<string, LoadedForecaster>>(new Map());
  const [error, setError] = React.useState<string | null>(null);
  const [expanded, setExpanded] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    try {
      const [cat, list] = await Promise.all([api.forecastCatalog(), api.forecastList()]);
      setCatalog(cat.models);
      const held = new Set(list.models.map((m) => m.model_id));
      setLoaded(
        new Map(
          cat.models
            .filter((e) => held.has(e.id))
            .map((e) => [
              e.id,
              { model_id: e.id, context_length: e.context_length, max_horizon: e.max_horizon },
            ]),
        ),
      );
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <div>
      <PageHeader
        eyebrow="Timeseries"
        title="Forecast"
        actions={<Button onClick={() => void refresh()}>Refresh</Button>}
      />

      <div className="flex flex-col gap-4 px-10 py-8">
        {error && <ErrorBox message={error} />}

        <p className="max-w-2xl text-sm text-muted-foreground">
          Load fetches and verifies the files the catalog entry names, matching{" "}
          <code className="font-mono">tenzro forecast load</code> on the CLI.
        </p>

        {!catalog && (
          <Card>
            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <Spinner />
              Reading the forecast catalogue…
            </div>
          </Card>
        )}

        {catalog && catalog.length === 0 && <Empty>No forecast models in the catalogue.</Empty>}

        {catalog && catalog.length > 0 && (
          <div className="flex flex-col border border-border">
            {catalog.map((entry, i) => (
              <ForecastRow
                key={entry.id}
                entry={entry}
                first={i === 0}
                loadedAs={loaded.get(entry.id) ?? null}
                expanded={expanded === entry.id}
                onToggleExpand={() => setExpanded(expanded === entry.id ? null : entry.id)}
                onChanged={refresh}
                onError={setError}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ForecastRow({
  entry,
  first,
  loadedAs,
  expanded,
  onToggleExpand,
  onChanged,
  onError,
}: {
  entry: ForecastCatalogEntry;
  first: boolean;
  loadedAs: LoadedForecaster | null;
  expanded: boolean;
  onToggleExpand: () => void;
  onChanged: () => Promise<void>;
  onError: (message: string) => void;
}) {
  const [busy, setBusy] = React.useState(false);

  const load = async () => {
    setBusy(true);
    onError("");
    try {
      await api.forecastLoad({ modelId: entry.id });
      await onChanged();
    } catch (e) {
      onError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const unload = async () => {
    setBusy(true);
    onError("");
    try {
      await api.forecastUnload(entry.id);
      await onChanged();
    } catch (e) {
      onError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={cn("flex flex-col gap-4 px-5 py-4", !first && "border-t border-border")}>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm">{entry.name}</span>
            <Badge>{entry.family}</Badge>
            {loadedAs && <Badge tone="good">Loaded</Badge>}
          </div>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {entry.description}
          </p>
        </div>
        <div className="flex flex-shrink-0 flex-col items-end gap-0.5 font-mono text-[11px] text-muted-foreground">
          <span>{entry.parameters}</span>
          <span>{formatBytes(entry.size_bytes)}</span>
          <span>ctx {entry.context_length} · horizon {entry.max_horizon}</span>
        </div>
      </div>

      {!loadedAs ? (
        <div className="flex items-end gap-2">
          <Button variant="primary" onClick={() => void load()} busy={busy}>
            Load
          </Button>
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <Button variant="ghost" onClick={onToggleExpand}>
            {expanded ? "Hide run panel" : "Run a forecast"}
          </Button>
          <Button onClick={() => void unload()} busy={busy}>
            Unload
          </Button>
        </div>
      )}

      {expanded && loadedAs && (
        <RunPanel model={loadedAs} onError={onError} />
      )}

      <p className="font-mono text-[10px] text-muted-foreground">
        {entry.hf_repo}/{entry.hf_filename}{entry.license ? ` · ${entry.license}` : ""}
      </p>
    </div>
  );
}

function RunPanel({
  model,
  onError,
}: {
  model: LoadedForecaster;
  onError: (message: string) => void;
}) {
  const [context, setContext] = React.useState("");
  const [horizon, setHorizon] = React.useState(Math.min(10, model.max_horizon));
  const [quantiles, setQuantiles] = React.useState("0.1,0.5,0.9");
  const [busy, setBusy] = React.useState(false);
  const [result, setResult] = React.useState<ForecastResult | null>(null);

  const run = async () => {
    const history = context
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map(Number);
    if (history.some((n) => Number.isNaN(n)) || history.length === 0) {
      onError("Context must be a comma- or space-separated list of numbers.");
      return;
    }
    const quantileLevels = quantiles
      .split(",")
      .map((s) => Number(s.trim()))
      .filter((n) => !Number.isNaN(n));

    setBusy(true);
    onError("");
    setResult(null);
    try {
      const res = await api.forecastRun({
        modelId: model.model_id,
        history,
        horizon,
        quantiles: quantileLevels,
      });
      setResult(res);
    } catch (e) {
      onError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-3 border border-border bg-secondary p-4">
      <Field
        label="Context series"
        hint={`Most-recent-last, comma or space separated. Up to ${model.context_length} points.`}
      >
        <textarea
          value={context}
          onChange={(e) => setContext(e.target.value)}
          rows={2}
          placeholder="10.1, 10.4, 10.2, 10.8, …"
          className="w-full resize-none border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground"
        />
      </Field>
      <div className="flex items-end gap-3">
        <Field label="Horizon" className="w-32">
          <Input
            type="number"
            min={1}
            max={model.max_horizon}
            value={horizon}
            onChange={(e) => setHorizon(Number(e.target.value))}
          />
        </Field>
        <Field label="Quantiles" className="flex-1">
          <Input value={quantiles} onChange={(e) => setQuantiles(e.target.value)} />
        </Field>
        <Button variant="primary" onClick={() => void run()} busy={busy}>
          Run
        </Button>
      </div>

      {result && (
        <div className="flex flex-col gap-1 border-t border-border pt-3">
          <Row
            label="Point forecast"
            value={result.point.map((v) => v.toFixed(3)).join(", ")}
          />
          <Row label="Generated in" value={`${result.generation_time_ms} ms`} />
        </div>
      )}
    </div>
  );
}
