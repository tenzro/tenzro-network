import * as React from "react";
import { Badge, Card, ErrorBox, Micro, Row, Stat } from "@/components/ui";
import { PageHeader } from "@/components/Shell";
import { GovernanceCard } from "@/components/GovernanceCard";
import { SponsorshipCard } from "@/components/SponsorshipCard";
import {
  api,
  errorText,
  type ControlConfig,
  type NodeStatusView,
  type WalletStatusView,
} from "@/lib/api";
import { describeGate, formatUptime, hourLabel, DAY_NAMES } from "@/lib/format";
import { roleLabel } from "@/lib/roles";

export function Dashboard({ status }: { status: NodeStatusView | null }) {
  const [config, setConfig] = React.useState<ControlConfig | null>(null);
  const [wallet, setWallet] = React.useState<WalletStatusView | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    try {
      const [c, w] = await Promise.all([api.getConfig(), api.walletStatus()]);
      setConfig(c);
      setWallet(w);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  React.useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 15_000);
    return () => clearInterval(t);
  }, [load]);

  const roles = config?.roles ?? [];
  const gates = (wallet?.gates ?? []).filter((g) => roles.includes(g.role));

  return (
    <div>
      <PageHeader eyebrow="Node" title="Dashboard" />

      <div className="flex flex-col gap-4 px-10 py-8">
        {error && <ErrorBox message={error} />}

        <Card>
          <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
            <Stat
              label="Block"
              value={status ? status.block_height.toLocaleString("en-US") : "—"}
            />
            <Stat label="Peers" value={status ? status.peer_count : "—"} />
            <Stat
              label="Uptime"
              value={status ? formatUptime(status.uptime_secs) : "—"}
            />
            <Stat
              label="State"
              value={status ? status.state : "starting"}
            />
          </div>
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <div className="flex items-center justify-between gap-4">
              <Micro>Wallet</Micro>
              <Badge tone={wallet?.custody === "hardware" ? "good" : "neutral"}>
                {wallet?.custody === "hardware" ? "Hardware key" : "None"}
              </Badge>
            </div>
            <div className="mt-4 flex flex-col divide-y divide-border">
              <Row label="Address" value={wallet?.display_address ?? "—"} />
              <Row
                label="DID"
                value={<span className="break-all text-xs">{wallet?.did ?? "—"}</span>}
              />
              <Row label="Balance" value={wallet?.balance_display ?? "—"} />
            </div>
          </Card>

          <Card>
            <Micro>Roles</Micro>
            {roles.length === 0 ? (
              <p className="mt-4 text-sm text-muted-foreground">No roles configured.</p>
            ) : (
              <div className="mt-4 flex flex-col divide-y divide-border">
                {roles.map((r) => {
                  const readout = describeGate(gates.find((g) => g.role === r));
                  return (
                    <div key={r} className="flex items-center justify-between gap-4 py-3">
                      <div className="min-w-0">
                        <div className="text-sm">{roleLabel(r)}</div>
                        {readout.detail && (
                          <div className="text-xs text-muted-foreground">{readout.detail}</div>
                        )}
                      </div>
                      <Badge tone={readout.tone}>{readout.label}</Badge>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>

        <SponsorshipCard />
        <GovernanceCard />

        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <Micro>Hours</Micro>
            {!config || config.availability.always_on ? (
              <p className="mt-4 text-sm text-muted-foreground">
                Always on. Work is accepted whenever the machine is awake.
              </p>
            ) : config.availability.windows.length === 0 ? (
              <p className="mt-4 text-sm text-destructive">
                On a schedule with no windows, so no work is being accepted.
              </p>
            ) : (
              <div className="mt-4 flex flex-col divide-y divide-border">
                {config.availability.windows.map((w, i) => (
                  <div key={i} className="flex items-baseline justify-between gap-4 py-2">
                    <span className="font-mono text-sm">
                      {hourLabel(w.start_hour)} — {hourLabel(w.end_hour)}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {w.days.length === 0
                        ? "Every day"
                        : w.days.map((d) => DAY_NAMES[d]).join(", ")}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card>
            <Micro>Machine</Micro>
            <div className="mt-4 flex flex-col divide-y divide-border">
              <Row
                label="Enclave"
                value={status?.tee_capable ? "Available" : "None detected"}
              />
              <Row label="Content transport" value={status?.iroh_enabled ? "On" : "Off"} />
              <Row label="Models selected" value={config?.models.length ?? 0} />
              <Row
                label="Storage pledged"
                value={`${config?.storage_pricing.capacity_gb ?? 0} GB`}
              />
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
