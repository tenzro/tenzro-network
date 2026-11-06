import * as React from "react";
import { Badge, Button, Card, Micro, Row } from "@/components/ui";
import {
  api,
  errorText,
  type Availability,
  type BudgetReadout,
  type WalletStatusView,
} from "@/lib/api";
import { DAY_NAMES, describeGate, formatTnzo, hourLabel } from "@/lib/format";
import { roleLabel, runsModels, sellsModels } from "@/lib/roles";
import { Step } from "./Step";
import type { PricingState } from "./Pricing";

export function Review({
  roles,
  models,
  storagePledgeGb,
  availability,
  pricing,
  onDropRole,
  onBack,
  onFinish,
  busy,
  error,
}: {
  roles: string[];
  models: string[];
  storagePledgeGb: number;
  availability: Availability;
  pricing: PricingState;
  onDropRole: (role: string) => void;
  onBack: () => void;
  onFinish: () => void;
  busy?: boolean;
  error?: string | null;
}) {
  const wantsModels = runsModels(roles);
  const wantsAi = sellsModels(roles);
  const wantsStorage = roles.includes("storage");
  const wantsCompute = roles.includes("compute");

  const [wallet, setWallet] = React.useState<WalletStatusView | null>(null);
  const [budget, setBudget] = React.useState<BudgetReadout | null>(null);
  const [localError, setLocalError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let live = true;
    Promise.all([api.walletStatus(), api.modelBudget(models, storagePledgeGb)])
      .then(([w, b]) => {
        if (!live) return;
        setWallet(w);
        setBudget(b);
      })
      .catch((e) => live && setLocalError(errorText(e)));
    return () => {
      live = false;
    };
  }, [models, storagePledgeGb]);

  // Nothing is staked yet at this point in onboarding, so `met` is false
  // everywhere and says nothing. What matters is whether the balance would
  // carry the stake once the operator posts it.
  const underfunded = (wallet?.gates ?? []).filter(
    (g) => roles.includes(g.role) && !g.met && !g.can_stake,
  );

  const modelNames = models.map(
    (id) => budget?.models.find((m) => m.id === id)?.name ?? id,
  );

  return (
    <Step
      index={6}
      eyebrow="Last step"
      title="Check it over"
      description="This is what the node will do once it starts. Everything here can be changed later from settings."
      error={error ?? localError}
      busy={busy}
      onBack={onBack}
      onNext={onFinish}
      nextLabel="Start the node"
      footerNote={
        underfunded.length > 0
          ? "Roles below their stake requirement stay dormant until the wallet is funded and the stake is posted."
          : undefined
      }
    >
      <div className="flex flex-col gap-4">
        {underfunded.length > 0 && (
          <div className="flex flex-col gap-4 border border-destructive bg-destructive/10 p-6">
            <Micro>Stake shortfall</Micro>
            <p className="text-sm leading-relaxed text-muted-foreground">
              The network admits a role once its stake is bonded. You can start anyway —
              the node runs, and you can fund the wallet and post the stake from the
              Wallet page whenever you are ready.
            </p>
            <div className="flex flex-col divide-y divide-border">
              {underfunded.map((g) => (
                <div key={g.role} className="flex items-center justify-between gap-4 py-3">
                  <div className="min-w-0">
                    <div className="text-sm">{g.label}</div>
                    <div className="font-mono text-xs text-muted-foreground">
                      {g.shortfall_display} short of {g.required_display}
                    </div>
                  </div>
                  <Button variant="ghost" onClick={() => onDropRole(g.role)} disabled={busy}>
                    Drop role
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}

        {roles.includes("validator") && (
          <Card>
            <Micro>Validator registration</Micro>
            <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
              Starting the node registers it as a validator on its own once the account below
              holds the self-stake and a little TNZO for gas. Nothing is posted from the Wallet
              page for this role.
            </p>
            <div className="mt-4 flex flex-col divide-y divide-border">
              <Row
                label="Self-stake"
                value={wallet?.gates.find((g) => g.role === "validator")?.required_display ?? "—"}
              />
              <Row
                label="Still needed"
                value={wallet?.gates.find((g) => g.role === "validator")?.shortfall_display ?? "—"}
              />
              <Row
                label="Send TNZO to"
                value={
                  <span className="break-all text-xs">
                    {wallet?.stake_account.address || wallet?.address || "—"}
                  </span>
                }
              />
            </div>
            <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
              Once it is funded, restart the node from Settings and it registers on that start;
              the Dashboard shows the result. With no TNZO to send, the Sponsorship panel on the
              Dashboard shows whether the bond can be covered.
            </p>
          </Card>
        )}

        <Card>
          <Micro>Wallet</Micro>
          <div className="mt-4 flex flex-col divide-y divide-border">
            <Row label="Address" value={wallet?.display_address ?? "—"} />
            <Row label="Custody" value={wallet?.custody === "hardware" ? "Hardware key" : "None"} />
            <Row label="Balance" value={wallet?.balance_display ?? "—"} />
          </div>
        </Card>

        <Card>
          <Micro>Roles</Micro>
          <div className="mt-4 flex flex-wrap gap-2">
            {roles.map((r) => {
              // Nothing is staked during onboarding, so a role counts as
              // in reach when the balance would cover its minimum.
              const readout = describeGate(wallet?.gates.find((g) => g.role === r));
              const reachable = readout.status === "active" || readout.status === "ready";
              return (
                <Badge key={r} tone={reachable ? "good" : "warn"}>
                  {roleLabel(r)}
                </Badge>
              );
            })}
          </div>
        </Card>

        {wantsModels && (
          <Card>
            <Micro>Models</Micro>
            {modelNames.length === 0 ? (
              <p className="mt-4 text-sm text-muted-foreground">
                No models selected. You can add them from the Models page once the node is
                running.
              </p>
            ) : (
              <div className="mt-4 flex flex-col divide-y divide-border">
                {modelNames.map((name) => (
                  <div key={name} className="py-2 text-sm">
                    {name}
                  </div>
                ))}
              </div>
            )}
            {budget && (
              <div className="mt-4 font-mono text-[11px] text-muted-foreground">
                {budget.ram_selected_gb} GB memory reserved, {budget.disk_downloads_gb} GB on
                disk
              </div>
            )}
          </Card>
        )}

        {wantsStorage && (
          <Card>
            <Micro>Storage</Micro>
            <div className="mt-4 flex flex-col divide-y divide-border">
              <Row label="Pledged" value={`${storagePledgeGb} GB`} />
              <Row label="Floor" value={`${formatTnzo(pricing.storageMinWei)} / GB-month`} />
              <Row label="Ceiling" value={`${formatTnzo(pricing.storageMaxWei)} / GB-month`} />
            </div>
          </Card>
        )}

        {wantsAi && (
          <Card>
            <Micro>Inference rates</Micro>
            <div className="mt-4 flex flex-col divide-y divide-border">
              <Row label="Input" value={`${formatTnzo(pricing.inputWei)} / token`} />
              <Row label="Output" value={`${formatTnzo(pricing.outputWei)} / token`} />
            </div>
          </Card>
        )}

        {wantsCompute && (
          <Card>
            <Micro>Compute</Micro>
            <div className="mt-4 flex flex-col divide-y divide-border">
              <Row label="Rental" value={`${formatTnzo(pricing.computeHourWei)} / hour`} />
            </div>
          </Card>
        )}

        <Card>
          <Micro>Hours</Micro>
          {availability.always_on ? (
            <p className="mt-4 text-sm text-muted-foreground">
              Always on. The node accepts work whenever the machine is awake.
            </p>
          ) : (
            <div className="mt-4 flex flex-col divide-y divide-border">
              {availability.windows.map((w, i) => (
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
      </div>
    </Step>
  );
}
