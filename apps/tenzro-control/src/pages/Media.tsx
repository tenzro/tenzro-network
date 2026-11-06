import * as React from "react";
import { Button, Card, ErrorBox, Field, Input, Select, Spinner } from "@/components/ui";
import { PageHeader } from "@/components/Shell";
import {
  api,
  errorText,
  type MediaCatalogEntry,
  type MediaGenKind,
  type MediaOutput,
} from "@/lib/api";

const KIND_LABELS: Record<MediaGenKind, string> = {
  text2image: "Text → Image",
  image2image: "Image → Image",
  text2video: "Text → Video",
  image2video: "Image → Video",
  text2audio: "Text → Audio",
};

export function Media() {
  const [catalog, setCatalog] = React.useState<MediaCatalogEntry[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    try {
      setCatalog((await api.mediaCatalog()).models);
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
        eyebrow="Generative media"
        title="Media"
        actions={<Button onClick={() => void refresh()}>Refresh</Button>}
      />

      <div className="flex flex-col gap-4 px-10 py-8">
        {error && <ErrorBox message={error} />}

        <p className="max-w-2xl text-sm text-muted-foreground">
          Renders run on this node with the media models it has loaded, or on a provider serving
          the model. Each render is seeded, so the same request renders the same output again.
        </p>

        {!catalog ? (
          <Card>
            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <Spinner />
              Reading the media catalogue…
            </div>
          </Card>
        ) : (
          <RenderForm catalog={catalog} onError={setError} />
        )}
      </div>
    </div>
  );
}

function RenderForm({
  catalog,
  onError,
}: {
  catalog: MediaCatalogEntry[];
  onError: (message: string) => void;
}) {
  const [kind, setKind] = React.useState<MediaGenKind>("text2image");
  const modelsForKind = React.useMemo(
    () => catalog.filter((m) => m.kinds.includes(kind)),
    [catalog, kind],
  );
  const [modelId, setModelId] = React.useState(modelsForKind[0]?.id ?? "");
  const [prompt, setPrompt] = React.useState("");
  const [width, setWidth] = React.useState(1024);
  const [height, setHeight] = React.useState(1024);
  const [steps, setSteps] = React.useState(4);
  const [guidanceScale, setGuidanceScale] = React.useState(3.5);
  const [seed, setSeed] = React.useState(() => Math.floor(Math.random() * 2 ** 31));
  const [output, setOutput] = React.useState<MediaOutput | null>(null);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    setModelId(modelsForKind[0]?.id ?? "");
  }, [modelsForKind]);

  const render = async () => {
    if (!modelId) {
      onError("No model fits this kind.");
      return;
    }
    if (!prompt.trim()) {
      onError("Enter a prompt first.");
      return;
    }
    setBusy(true);
    onError("");
    try {
      setOutput(
        await api.mediaRender({ kind, modelId, prompt, width, height, steps, guidanceScale, seed }),
      );
    } catch (e) {
      onError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <div className="flex flex-col gap-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Kind">
            <Select value={kind} onChange={(e) => setKind(e.target.value as MediaGenKind)}>
              {Object.entries(KIND_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </Select>
          </Field>
          <Field
            label="Model"
            hint={modelsForKind.length === 0 ? "Nothing in the catalogue offers this kind." : undefined}
          >
            <Select value={modelId} onChange={(e) => setModelId(e.target.value)}>
              {modelsForKind.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name} ({m.vram_gb} GB)
                </option>
              ))}
            </Select>
          </Field>
        </div>

        <Field label="Prompt">
          <textarea
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            rows={2}
            className="w-full resize-none border border-border bg-secondary px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground"
            placeholder="a lighthouse on a rocky cliff at sunset, photorealistic"
          />
        </Field>

        <div className="grid grid-cols-5 gap-4">
          <Field label="Width">
            <Input type="number" value={width} onChange={(e) => setWidth(Number(e.target.value))} />
          </Field>
          <Field label="Height">
            <Input type="number" value={height} onChange={(e) => setHeight(Number(e.target.value))} />
          </Field>
          <Field label="Steps">
            <Input type="number" value={steps} onChange={(e) => setSteps(Number(e.target.value))} />
          </Field>
          <Field label="Seed">
            <Input type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} />
          </Field>
          <Field label="Guidance">
            <Input
              type="number"
              step="0.1"
              value={guidanceScale}
              onChange={(e) => setGuidanceScale(Number(e.target.value))}
            />
          </Field>
        </div>

        <div className="flex items-center gap-3">
          {output?.cost_wei && (
            <span className="font-mono text-xs text-muted-foreground">
              {output.cost_wei} attoTNZO
            </span>
          )}
          <Button
            variant="primary"
            onClick={() => void render()}
            busy={busy}
            disabled={!modelId || !prompt.trim()}
            className="ml-auto"
          >
            Render
          </Button>
        </div>

        {output && (
          <div className="border border-border bg-secondary p-2">
            {output.mime.startsWith("video/") ? (
              <video src={output.data_url} controls className="max-h-96 w-full" />
            ) : output.mime.startsWith("audio/") ? (
              <audio src={output.data_url} controls className="w-full" />
            ) : (
              <img src={output.data_url} alt="" className="max-h-96 w-full object-contain" />
            )}
          </div>
        )}
      </div>
    </Card>
  );
}
