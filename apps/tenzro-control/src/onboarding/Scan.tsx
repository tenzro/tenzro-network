import * as React from "react";
import { Card, Micro, Spinner, Stat } from "@/components/ui";
import { api, errorText, type CapabilityReadout } from "@/lib/api";
import { roleLabel } from "@/lib/roles";
import { Step } from "./Step";

const GPU_LABEL: Record<CapabilityReadout["gpu_class"], string> = {
  None: "CPU only",
  AppleSilicon: "Apple Silicon",
  Cuda: "NVIDIA CUDA",
  Rocm: "AMD ROCm",
  IntelOrIntegrated: "Integrated",
};

export function Scan({
  hardware,
  onScanned,
  onNext,
}: {
  hardware: CapabilityReadout | null;
  onScanned: (h: CapabilityReadout) => void;
  onNext: () => void;
}) {
  const [error, setError] = React.useState<string | null>(null);
  const scanned = React.useRef(false);

  // The probe decides every verdict, so the two lists here are only a
  // partition of what it returned — nothing is re-derived.
  const available = hardware?.roles.filter((c) => c.available) ?? [];
  const unavailable = hardware?.roles.filter((c) => !c.available) ?? [];

  React.useEffect(() => {
    if (scanned.current || hardware) return;
    scanned.current = true;
    api
      .scanHardware()
      .then(onScanned)
      .catch((e) => setError(errorText(e)));
  }, [hardware, onScanned]);

  return (
    <Step
      index={0}
      eyebrow="Step one"
      title="What this machine can do"
      description="Control reads the memory, cores, accelerator and free disk on this machine, then only offers roles it can actually carry."
      error={error}
      onNext={hardware ? onNext : undefined}
      nextDisabled={!hardware}
    >
      {!hardware && !error && (
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          <Spinner />
          Reading hardware…
        </div>
      )}

      {hardware && (
        <div className="flex flex-col gap-4">
          <Card>
            <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
              <Stat label="Memory" value={`${hardware.ram_gb} GB`} />
              <Stat label="Cores" value={hardware.physical_cores} sub="physical" />
              <Stat label="Accelerator" value={GPU_LABEL[hardware.gpu_class]} sub={hardware.gpu} />
              <Stat label="Free disk" value={`${hardware.free_disk_gb} GB`} />
            </div>
          </Card>

          <Card>
            <Micro>Available to you</Micro>
            <div className="mt-4 flex flex-col gap-3">
              {available.map((c) => (
                <Capability key={c.role} ok title={roleLabel(c.role)} detail={c.detail} />
              ))}
            </div>
          </Card>

          {unavailable.length > 0 && (
            <Card>
              <Micro>Not on this machine</Micro>
              <div className="mt-4 flex flex-col gap-3">
                {unavailable.map((c) => (
                  <Capability
                    key={c.role}
                    ok={false}
                    title={roleLabel(c.role)}
                    detail={c.detail}
                  />
                ))}
              </div>
            </Card>
          )}
        </div>
      )}
    </Step>
  );
}

function Capability({ ok, title, detail }: { ok: boolean; title: string; detail: string }) {
  return (
    <div className="flex gap-3">
      <span className={`mt-1.5 h-1.5 w-1.5 flex-shrink-0 ${ok ? "bg-brand" : "bg-border"}`} />
      <div>
        <div className="text-sm text-foreground">{title}</div>
        <div className="text-xs text-muted-foreground">{detail}</div>
      </div>
    </div>
  );
}
