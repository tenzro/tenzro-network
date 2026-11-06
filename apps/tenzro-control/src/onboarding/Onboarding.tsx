import * as React from "react";
import {
  api,
  errorText,
  type Availability as AvailabilityConfig,
  type CapabilityReadout,
  type WalletStatusView,
} from "@/lib/api";
import { runsModels } from "@/lib/roles";
import { Scan } from "./Scan";
import { Roles } from "./Roles";
import { Wallet } from "./Wallet";
import { Configure } from "./Configure";
import { Availability } from "./Availability";
import { Pricing, type PricingState } from "./Pricing";
import { Review } from "./Review";

type StepKey =
  | "scan"
  | "roles"
  | "wallet"
  | "configure"
  | "availability"
  | "pricing"
  | "review";

export function Onboarding({ onDone }: { onDone: () => void }) {
  const [current, setCurrent] = React.useState<StepKey>("scan");
  const [hardware, setHardware] = React.useState<CapabilityReadout | null>(null);
  const [wallet, setWallet] = React.useState<WalletStatusView | null>(null);

  const [roles, setRoles] = React.useState<string[]>([]);
  const [models, setModels] = React.useState<string[]>([]);
  const [storagePledgeGb, setStoragePledgeGb] = React.useState(0);
  const [availability, setAvailability] = React.useState<AvailabilityConfig>({
    always_on: true,
    windows: [],
  });
  const [pricing, setPricing] = React.useState<PricingState>({
    inputWei: "0",
    outputWei: "0",
    storageMinWei: "0",
    storageMaxWei: "0",
    computeHourWei: "0",
  });

  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let live = true;
    Promise.all([api.getConfig(), api.walletStatus()])
      .then(([c, w]) => {
        if (!live) return;
        setWallet(w);
        if (c.roles.length > 0) setRoles(c.roles);
        if (c.models.length > 0) setModels(c.models);
        setStoragePledgeGb(c.storage_pricing.capacity_gb);
        setAvailability(c.availability);
        setPricing({
          inputWei: String(c.ai_pricing.input_price_per_token_wei),
          outputWei: String(c.ai_pricing.output_price_per_token_wei),
          storageMinWei: String(c.storage_pricing.min_rate_wei),
          storageMaxWei: String(c.storage_pricing.max_rate_wei),
          computeHourWei: String(c.compute_pricing.rate_per_hour_wei),
        });
      })
      .catch((e) => live && setError(errorText(e)));
    return () => {
      live = false;
    };
  }, []);

  const needsConfigure = runsModels(roles) || roles.includes("storage");

  const sequence = React.useMemo<StepKey[]>(
    () => [
      "scan",
      "roles",
      "wallet",
      ...(needsConfigure ? (["configure"] as StepKey[]) : []),
      "availability",
      "pricing",
      "review",
    ],
    [needsConfigure],
  );

  const go = (delta: number) => {
    const i = sequence.indexOf(current);
    const next = sequence[Math.min(Math.max(i + delta, 0), sequence.length - 1)];
    setError(null);
    setCurrent(next);
  };

  const onScanned = React.useCallback((h: CapabilityReadout) => setHardware(h), []);

  const dropRole = (role: string) => {
    const next = roles.filter((r) => r !== role);
    setRoles(next);
    if (next.length === 0) setCurrent("roles");
  };

  async function finish() {
    setBusy(true);
    setError(null);
    try {
      await api.setRoles(roles);
      await api.setModels(models);
      await api.setAvailability(availability);
      await api.setAiPricing(pricing.inputWei, pricing.outputWei);
      await api.setStoragePricing(
        storagePledgeGb,
        pricing.storageMinWei,
        pricing.storageMaxWei,
      );
      await api.setComputePricing(pricing.computeHourWei);
      await api.completeOnboarding();
      onDone();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  switch (current) {
    case "scan":
      return <Scan hardware={hardware} onScanned={onScanned} onNext={() => go(1)} />;

    case "roles":
      return (
        <Roles
          hardware={hardware}
          gates={wallet?.gates ?? []}
          selected={roles}
          onChange={setRoles}
          onBack={() => go(-1)}
          onNext={() => go(1)}
        />
      );

    case "wallet":
      return (
        <Wallet
          wallet={wallet}
          onWallet={setWallet}
          onBack={() => go(-1)}
          onNext={() => go(1)}
        />
      );

    case "configure":
      return (
        <Configure
          roles={roles}
          models={models}
          onModels={setModels}
          storagePledgeGb={storagePledgeGb}
          onStoragePledge={setStoragePledgeGb}
          maxStorageGb={hardware?.offerable_storage_gb ?? 0}
          onBack={() => go(-1)}
          onNext={() => go(1)}
        />
      );

    case "availability":
      return (
        <Availability
          value={availability}
          onChange={setAvailability}
          onBack={() => go(-1)}
          onNext={() => go(1)}
        />
      );

    case "pricing":
      return (
        <Pricing
          roles={roles}
          value={pricing}
          onChange={setPricing}
          onBack={() => go(-1)}
          onNext={() => go(1)}
        />
      );

    case "review":
      return (
        <Review
          roles={roles}
          models={models}
          storagePledgeGb={storagePledgeGb}
          availability={availability}
          pricing={pricing}
          onDropRole={dropRole}
          onBack={() => go(-1)}
          onFinish={finish}
          busy={busy}
          error={error}
        />
      );
  }
}
