import * as React from "react";
import qrcode from "qrcode-generator";
import {
  Badge,
  Button,
  Card,
  ErrorBox,
  Field,
  Input,
  Micro,
  Row,
  Spinner,
  TextArea,
} from "@/components/ui";
import { PageHeader } from "@/components/Shell";
import { cn } from "@/lib/cn";
import {
  api,
  errorText,
  type Availability,
  type CableSessionStart,
  type CapabilityReadout,
  type ControlConfig,
  type ServingWindow,
  type WalletStatusView,
} from "@/lib/api";
import {
  DAY_NAMES,
  describeGate,
  formatTnzo,
  hourLabel,
  randomPrehashHex,
  tnzoToWei,
  weiToTnzoInput,
} from "@/lib/format";
import { ROLES, hardwareBlock, roleLabel, sellsModels, type RoleDef } from "@/lib/roles";

const EXCLUSIVE = ROLES.filter((r) => r.exclusive).map((r) => r.id);

/// The enclave key onboarding created. Every device check in this page
/// addresses that same key, so the label has to match Wallet.tsx exactly.
const DEVICE_LABEL = "tenzro-control";

/// The relying party a phone authenticator is asked about during the
/// cross-device check. Passkeys are scoped to an RP, so a phone that holds
/// no Tenzro credential will decline — which is the answer the check is
/// looking for.
const RP_ID = "tenzro.com";

const HOURS = Array.from({ length: 24 }, (_, h) => h);

function shortHex(hex: string): string {
  return hex.length > 16 ? `${hex.slice(0, 8)}…${hex.slice(-8)}` : hex;
}

export function Settings({ onOpenModels }: { onOpenModels: () => void }) {
  const [config, setConfig] = React.useState<ControlConfig | null>(null);
  const [wallet, setWallet] = React.useState<WalletStatusView | null>(null);
  const [hardware, setHardware] = React.useState<CapabilityReadout | null>(null);
  const [dataDir, setDataDir] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState<string | null>(null);

  const [aiIn, setAiIn] = React.useState("");
  const [aiOut, setAiOut] = React.useState("");
  const [capacity, setCapacity] = React.useState("");
  const [storeMin, setStoreMin] = React.useState("");
  const [storeMax, setStoreMax] = React.useState("");
  const [computeHour, setComputeHour] = React.useState("");
  const [reserveGb, setReserveGb] = React.useState("");
  const [residentGb, setResidentGb] = React.useState("");
  const [onDemandGb, setOnDemandGb] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      const [c, w, dir] = await Promise.all([
        api.getConfig(),
        api.walletStatus(),
        api.nodeDataDir(),
      ]);
      setConfig(c);
      setWallet(w);
      setDataDir(dir);
      setAiIn(weiToTnzoInput(c.ai_pricing.input_price_per_token_wei));
      setAiOut(weiToTnzoInput(c.ai_pricing.output_price_per_token_wei));
      setCapacity(String(c.storage_pricing.capacity_gb));
      setStoreMin(weiToTnzoInput(c.storage_pricing.min_rate_wei));
      setStoreMax(weiToTnzoInput(c.storage_pricing.max_rate_wei));
      setComputeHour(weiToTnzoInput(c.compute_pricing.rate_per_hour_wei));
      setReserveGb(c.memory.reserve_gb === null ? "" : String(c.memory.reserve_gb));
      setResidentGb(c.memory.resident_ceiling_gb === null ? "" : String(c.memory.resident_ceiling_gb));
      setOnDemandGb(c.memory.on_demand_ceiling_gb === null ? "" : String(c.memory.on_demand_ceiling_gb));
    } catch (e) {
      setError(errorText(e));
    }
    try {
      setHardware(await api.scanHardware());
    } catch {
      /* the scan only gates the role list; without it nothing is blocked */
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const save = async (section: string, fn: () => Promise<ControlConfig>) => {
    setSaving(section);
    setError(null);
    try {
      setConfig(await fn());
    } catch (e) {
      setError(errorText(e));
    } finally {
      setSaving(null);
    }
  };

  if (!config) {
    return (
      <div>
        <PageHeader eyebrow="Node" title="Settings" />
        <div className="px-10 py-8">
          {error ? (
            <ErrorBox message={error} />
          ) : (
            <Card>
              <div className="flex items-center gap-3 text-sm text-muted-foreground">
                <Spinner />
                Reading this node's configuration…
              </div>
            </Card>
          )}
        </div>
      </div>
    );
  }

  const roles = config.roles;
  const availability = config.availability;
  const wantsAi = sellsModels(roles);
  const wantsStorage = roles.includes("storage");
  const wantsCompute = roles.includes("compute");

  const toggleRole = (role: RoleDef) => {
    const next = roles.includes(role.id)
      ? roles.filter((r) => r !== role.id)
      : role.exclusive
        ? [role.id]
        : [...roles.filter((r) => !EXCLUSIVE.includes(r)), role.id];
    void save(`role:${role.id}`, () => api.setRoles(next));
  };

  const setAvailability = (next: Availability) =>
    void save("hours", () => api.setAvailability(next));

  const patchWindow = (index: number, patch: Partial<ServingWindow>) =>
    setAvailability({
      ...availability,
      windows: availability.windows.map((w, i) => (i === index ? { ...w, ...patch } : w)),
    });

  const toggleDay = (index: number, day: number) => {
    const w = availability.windows[index];
    const days = w.days.includes(day)
      ? w.days.filter((d) => d !== day)
      : [...w.days, day].sort();
    patchWindow(index, { days });
  };

  const saveAiPricing = () => {
    const input = tnzoToWei(aiIn);
    const output = tnzoToWei(aiOut);
    if (input === null || output === null) {
      setError("Rates must be plain decimal numbers with at most 18 decimal places.");
      return;
    }
    void save("ai-pricing", () => api.setAiPricing(input, output));
  };

  const saveStorage = () => {
    const min = tnzoToWei(storeMin);
    const max = tnzoToWei(storeMax);
    const gb = Number.parseInt(capacity, 10);
    if (min === null || max === null) {
      setError("Rates must be plain decimal numbers with at most 18 decimal places.");
      return;
    }
    if (!Number.isFinite(gb) || gb < 0) {
      setError("The pledge must be a whole number of gigabytes.");
      return;
    }
    if (BigInt(min) > BigInt(max)) {
      setError("The floor rate is above the ceiling rate.");
      return;
    }
    void save("storage-pricing", () => api.setStoragePricing(gb, min, max));
  };

  const saveCompute = () => {
    const rate = tnzoToWei(computeHour);
    if (rate === null) {
      setError("Rates must be plain decimal numbers with at most 18 decimal places.");
      return;
    }
    void save("compute-pricing", () => api.setComputePricing(rate));
  };

  const parseGbField = (raw: string, label: string): number | null | undefined => {
    if (raw.trim() === "") return null;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 0) {
      setError(`${label} must be a whole number of GiB, or blank for the node's own default.`);
      return undefined;
    }
    return n;
  };

  const saveMemory = () => {
    const reserve = parseGbField(reserveGb, "Reserve");
    if (reserve === undefined) return;
    const resident = parseGbField(residentGb, "Resident ceiling");
    if (resident === undefined) return;
    const onDemand = parseGbField(onDemandGb, "On-demand ceiling");
    if (onDemand === undefined) return;
    void save("memory", () =>
      api.setMemoryConfig({
        reserveGb: reserve,
        residentCeilingGb: resident,
        onDemandCeilingGb: onDemand,
      }),
    );
  };

  return (
    <div>
      <PageHeader
        eyebrow="Node"
        title="Settings"
        actions={
          <Button onClick={() => void load()} disabled={saving !== null}>
            Reload
          </Button>
        }
      />

      <div className="flex flex-col gap-4 px-10 py-8">
        {error && <ErrorBox message={error} />}

        <Card className="flex flex-col gap-5">
          <div className="flex flex-col gap-1">
            <Micro>Roles</Micro>
            <p className="text-xs leading-relaxed text-muted-foreground">
              What this machine offers the network, or whether it keeps to itself. Changes
              take effect at the next restart of the node.
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            {ROLES.map((role) => {
              const on = roles.includes(role.id);
              const blocked = hardwareBlock(role.id, hardware);
              const stake = describeGate(wallet?.gates.find((g) => g.role === role.id));
              return (
                <button
                  key={role.id}
                  type="button"
                  onClick={() => toggleRole(role)}
                  disabled={(!on && blocked !== null) || saving !== null}
                  className={cn(
                    "flex flex-col gap-2 border p-4 text-left transition-colors",
                    on ? "border-brand bg-brand-soft" : "border-border bg-card",
                    !on && blocked !== null
                      ? "cursor-not-allowed opacity-40"
                      : "hover:border-muted-foreground",
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm">{role.title}</span>
                    {on && <Badge tone="good">On</Badge>}
                  </div>
                  <p className="text-xs leading-relaxed text-muted-foreground">{role.blurb}</p>
                  {blocked && <p className="text-xs text-destructive">{blocked}</p>}
                  {on && stake.detail && (
                    <p className="text-xs text-muted-foreground">{stake.detail}</p>
                  )}
                </button>
              );
            })}
          </div>
        </Card>

        <Card className="flex flex-col gap-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex flex-col gap-1">
              <Micro>Hours</Micro>
              <p className="text-xs leading-relaxed text-muted-foreground">
                When work is accepted. Outside these hours the node stays connected
                but turns callers away.
              </p>
            </div>
            <div className="flex flex-shrink-0 gap-2">
              <Button
                variant={availability.always_on ? "primary" : "secondary"}
                onClick={() => setAvailability({ ...availability, always_on: true })}
                disabled={saving !== null}
              >
                Always on
              </Button>
              <Button
                variant={availability.always_on ? "secondary" : "primary"}
                onClick={() =>
                  setAvailability({
                    always_on: false,
                    windows:
                      availability.windows.length > 0
                        ? availability.windows
                        : [{ start_hour: 22, end_hour: 7, days: [] }],
                  })
                }
                disabled={saving !== null}
              >
                On a schedule
              </Button>
            </div>
          </div>

          {availability.always_on ? (
            <p className="text-sm text-muted-foreground">
              Work is accepted whenever the machine is awake.
            </p>
          ) : (
            <div className="flex flex-col gap-4">
              {availability.windows.length === 0 && (
                <p className="text-sm text-destructive">
                  A schedule with no windows accepts no work at all.
                </p>
              )}

              {availability.windows.map((w, i) => (
                <div key={i} className="flex flex-col gap-3 border border-border p-4">
                  <div className="flex flex-wrap items-end gap-3">
                    <Field label="From" className="w-28">
                      <select
                        className="h-9 w-full border border-border bg-secondary px-3 text-sm"
                        value={w.start_hour}
                        onChange={(e) =>
                          patchWindow(i, { start_hour: Number(e.currentTarget.value) })
                        }
                      >
                        {HOURS.map((h) => (
                          <option key={h} value={h}>
                            {hourLabel(h)}
                          </option>
                        ))}
                      </select>
                    </Field>
                    <Field label="To" className="w-28">
                      <select
                        className="h-9 w-full border border-border bg-secondary px-3 text-sm"
                        value={w.end_hour}
                        onChange={(e) =>
                          patchWindow(i, { end_hour: Number(e.currentTarget.value) })
                        }
                      >
                        {HOURS.map((h) => (
                          <option key={h} value={h}>
                            {hourLabel(h)}
                          </option>
                        ))}
                      </select>
                    </Field>
                    <div className="ml-auto">
                      <Button
                        variant="ghost"
                        onClick={() =>
                          setAvailability({
                            ...availability,
                            windows: availability.windows.filter((_, idx) => idx !== i),
                          })
                        }
                        disabled={saving !== null}
                      >
                        Remove
                      </Button>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {DAY_NAMES.map((name, day) => {
                      const on = w.days.length === 0 || w.days.includes(day);
                      return (
                        <button
                          key={name}
                          type="button"
                          onClick={() => toggleDay(i, day)}
                          disabled={saving !== null}
                          className={cn(
                            "border px-3 py-1 text-[11px] uppercase tracking-[0.14em] transition-colors",
                            on
                              ? "border-brand bg-brand-soft text-foreground"
                              : "border-border text-muted-foreground hover:border-muted-foreground",
                          )}
                        >
                          {name}
                        </button>
                      );
                    })}
                  </div>

                  {w.start_hour === w.end_hour && (
                    <p className="text-xs text-destructive">
                      This window starts and ends at the same hour, so it never opens.
                    </p>
                  )}
                  {w.start_hour > w.end_hour && (
                    <p className="text-xs text-muted-foreground">
                      Runs past midnight into the next day.
                    </p>
                  )}
                </div>
              ))}

              <div>
                <Button
                  onClick={() =>
                    setAvailability({
                      ...availability,
                      windows: [...availability.windows, { start_hour: 9, end_hour: 17, days: [] }],
                    })
                  }
                  disabled={saving !== null}
                >
                  Add a window
                </Button>
              </div>
            </div>
          )}
        </Card>

        {wantsAi && (
          <Card className="flex flex-col gap-5">
            <div className="flex flex-col gap-1">
              <Micro>Inference rates</Micro>
              <p className="text-xs leading-relaxed text-muted-foreground">
                Charged per token, paid in TNZO and settled on-chain.
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Input" hint={`Callers pay ${formatTnzo(tnzoToWei(aiIn) ?? "0")} per token.`}>
                <Input
                  inputMode="decimal"
                  value={aiIn}
                  onChange={(e) => setAiIn(e.currentTarget.value)}
                />
              </Field>
              <Field
                label="Output"
                hint={`Callers pay ${formatTnzo(tnzoToWei(aiOut) ?? "0")} per token.`}
              >
                <Input
                  inputMode="decimal"
                  value={aiOut}
                  onChange={(e) => setAiOut(e.currentTarget.value)}
                />
              </Field>
            </div>
            <div>
              <Button
                variant="primary"
                onClick={saveAiPricing}
                busy={saving === "ai-pricing"}
                disabled={saving !== null}
              >
                Save rates
              </Button>
            </div>
          </Card>
        )}

        {wantsStorage && (
          <Card className="flex flex-col gap-5">
            <div className="flex flex-col gap-1">
              <Micro>Storage</Micro>
              <p className="text-xs leading-relaxed text-muted-foreground">
                The disk you pledge and what you charge for it, per gigabyte-month.
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-3">
              <Field
                label="Pledge"
                hint={
                  hardware ? `Up to ${hardware.offerable_storage_gb} GB is spare.` : "Gigabytes."
                }
              >
                <Input
                  inputMode="numeric"
                  value={capacity}
                  onChange={(e) => setCapacity(e.currentTarget.value)}
                />
              </Field>
              <Field
                label="Floor"
                hint={`You will not accept less than ${formatTnzo(tnzoToWei(storeMin) ?? "0")}.`}
              >
                <Input
                  inputMode="decimal"
                  value={storeMin}
                  onChange={(e) => setStoreMin(e.currentTarget.value)}
                />
              </Field>
              <Field
                label="Ceiling"
                hint={`Your asking rate is ${formatTnzo(tnzoToWei(storeMax) ?? "0")}.`}
              >
                <Input
                  inputMode="decimal"
                  value={storeMax}
                  onChange={(e) => setStoreMax(e.currentTarget.value)}
                />
              </Field>
            </div>
            <div>
              <Button
                variant="primary"
                onClick={saveStorage}
                busy={saving === "storage-pricing"}
                disabled={saving !== null}
              >
                Save storage
              </Button>
            </div>
          </Card>
        )}

        {wantsCompute && (
          <Card className="flex flex-col gap-5">
            <div className="flex flex-col gap-1">
              <Micro>Accelerator rental</Micro>
              <p className="text-xs leading-relaxed text-muted-foreground">
                What a renter pays for an hour of your cards. They bring their own work; you are
                not serving models for them.
              </p>
            </div>
            <Field
              label="Rate"
              hint={`A renter pays ${formatTnzo(tnzoToWei(computeHour) ?? "0")} an hour.`}
            >
              <Input
                inputMode="decimal"
                value={computeHour}
                onChange={(e) => setComputeHour(e.currentTarget.value)}
              />
            </Field>
            <div>
              <Button
                variant="primary"
                onClick={saveCompute}
                busy={saving === "compute-pricing"}
                disabled={saving !== null}
              >
                Save rate
              </Button>
            </div>
          </Card>
        )}

        <Card className="flex flex-col gap-4">
          <div className="flex items-center justify-between gap-4">
            <Micro>Models</Micro>
            <Button onClick={onOpenModels}>Open the catalogue</Button>
          </div>
          <p className="text-sm text-muted-foreground">
            {config.models.length === 0
              ? "No models are selected, so this node answers no inference calls."
              : `${config.models.length} model${config.models.length === 1 ? "" : "s"} selected. Downloads, serving and memory are managed from the catalogue.`}
          </p>
        </Card>

        <Card className="flex flex-col gap-5">
          <div className="flex flex-col gap-1">
            <Micro>Memory budget</Micro>
            <p className="text-xs leading-relaxed text-muted-foreground">
              How this node splits memory between always-resident models (chat, embeddings,
              forecasting) and on-demand pipelines (image and video generation) that load per
              job and evict afterward. Blank uses the node's own default — the physical RAM it
              detects, minus a 16 GiB reserve, split 60/40 between the two tiers. Takes effect on
              the next restart.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Reserve" hint="Held back for the OS, RocksDB, and the service surfaces.">
              <Input
                inputMode="numeric"
                placeholder="16"
                value={reserveGb}
                onChange={(e) => setReserveGb(e.currentTarget.value)}
              />
            </Field>
            <Field label="Resident ceiling" hint="Language models, embeddings, forecasting.">
              <Input
                inputMode="numeric"
                placeholder="auto"
                value={residentGb}
                onChange={(e) => setResidentGb(e.currentTarget.value)}
              />
            </Field>
            <Field label="On-demand ceiling" hint="Image and video generation.">
              <Input
                inputMode="numeric"
                placeholder="auto"
                value={onDemandGb}
                onChange={(e) => setOnDemandGb(e.currentTarget.value)}
              />
            </Field>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="primary"
              onClick={saveMemory}
              busy={saving === "memory"}
              disabled={saving !== null}
            >
              Save
            </Button>
            <Button onClick={() => void api.restartNode()} disabled={saving !== null}>
              Restart node
            </Button>
          </div>
        </Card>

        <WalletCard wallet={wallet} />

        <DeviceCard />

        <AdvancedCard dataDir={dataDir} />
      </div>
    </div>
  );
}

function WalletCard({ wallet }: { wallet: WalletStatusView | null }) {
  return (
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
        {wallet?.staked_role && (
          <Row
            label="Staked"
            value={`${wallet.staked_display} as ${roleLabel(wallet.staked_role)}`}
          />
        )}
        <Row
          label="Signed by"
          value={wallet?.stake_account.signer === "secure-enclave" ? "Secure Enclave" : wallet?.stake_account.signer === "tpm" ? "TPM" : "—"}
        />
      </div>
      {wallet?.exists && !wallet.staked_role && (
        <p className="mt-4 text-xs text-muted-foreground">
          A role stays dormant until its stake is bonded, which you post from the
          Wallet page. Each role has its own bond, and the node keeps running
          either way.
        </p>
      )}
    </Card>
  );
}

/// The two possession checks. Neither enrols anything: they ask the key
/// material already on this device, and on a phone, to answer a fresh
/// random challenge, which is the only way to tell a live key from a
/// remembered one.
function DeviceCard() {
  const [localBusy, setLocalBusy] = React.useState(false);
  const [localResult, setLocalResult] = React.useState<string | null>(null);
  const [localError, setLocalError] = React.useState<string | null>(null);

  const [session, setSession] = React.useState<CableSessionStart | null>(null);
  const [qrSrc, setQrSrc] = React.useState<string | null>(null);
  const [cableBusy, setCableBusy] = React.useState(false);
  const [cableResult, setCableResult] = React.useState<string | null>(null);
  const [cableError, setCableError] = React.useState<string | null>(null);

  async function checkLocalKey() {
    setLocalBusy(true);
    setLocalError(null);
    setLocalResult(null);
    const prehash = randomPrehashHex();
    try {
      const classical = await api.deviceSignWithPasskey(DEVICE_LABEL, prehash);
      try {
        const hybrid = await api.deviceSignHybridWithPasskey(DEVICE_LABEL, prehash);
        setLocalResult(
          `The P-256 key answered with ${classical.length / 2} bytes, and the ` +
            `ML-DSA-65 key added ${hybrid.ml_dsa_signature_hex.length / 2} more.`,
        );
      } catch (e) {
        // Classical succeeded, so the P-256 key is intact and it is the
        // post-quantum key alone that did not answer.
        setLocalError(
          `The P-256 key answered, but the post-quantum key did not: ${errorText(e)}`,
        );
      }
    } catch (e) {
      setLocalError(errorText(e));
    } finally {
      setLocalBusy(false);
    }
  }

  async function checkPhone() {
    setCableBusy(true);
    setCableError(null);
    setCableResult(null);
    let started: CableSessionStart | null = null;
    try {
      started = await api.deviceStartCrossDeviceLink();
      setSession(started);
      const qr = qrcode(0, "M");
      qr.addData(started.qr_url);
      qr.make();
      setQrSrc(qr.createDataURL(6, 2));

      const assertion = await api.deviceCompleteCrossDeviceLink({
        session_id: started.session_id,
        challenge_hex: randomPrehashHex(),
        rp_id: RP_ID,
        allow_credential_ids_hex: [],
      });
      setCableResult(
        `Credential ${shortHex(assertion.credential_id_hex)} answered with a ` +
          `${assertion.signature_hex.length / 2}-byte signature.`,
      );
    } catch (e) {
      setCableError(errorText(e));
    } finally {
      setSession(null);
      setQrSrc(null);
      setCableBusy(false);
    }
  }

  async function abortPhoneCheck() {
    if (!session) return;
    try {
      await api.deviceCancelCrossDeviceLink(session.session_id);
    } catch {
      /* the session ends on its own once the check resolves */
    }
    setSession(null);
  }

  return (
    <Card className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <Micro>Devices</Micro>
        <p className="text-xs leading-relaxed text-muted-foreground">
          Confirm the keys that sign for this node are still reachable. Nothing is
          enrolled or changed by either check.
        </p>
      </div>

      <div className="flex flex-col gap-3 border border-border p-4">
        <div className="flex items-center justify-between gap-4">
          <span className="text-sm">This device</span>
          <Button onClick={() => void checkLocalKey()} busy={localBusy}>
            Check
          </Button>
        </div>
        <p className="text-xs leading-relaxed text-muted-foreground">
          Signs a fresh random value with this device's P-256 key and its
          post-quantum key.
        </p>
        {localResult && <p className="text-xs text-muted-foreground">{localResult}</p>}
        {localError && <ErrorBox message={localError} />}
      </div>

      <div className="flex flex-col gap-3 border border-border p-4">
        <div className="flex items-center justify-between gap-4">
          <span className="text-sm">A phone</span>
          {session ? (
            <Button onClick={() => void abortPhoneCheck()}>Cancel</Button>
          ) : (
            <Button onClick={() => void checkPhone()} busy={cableBusy}>
              Check
            </Button>
          )}
        </div>
        <p className="text-xs leading-relaxed text-muted-foreground">
          Shows a code to scan with a phone holding a {RP_ID} passkey. A phone with
          no such passkey will decline, which is a valid answer.
        </p>
        {qrSrc && (
          <div className="flex flex-col items-center gap-3 py-2">
            <img src={qrSrc} alt="Scan this with your phone" className="h-44 w-44" />
            <span className="text-xs text-muted-foreground">
              Waiting for the phone to answer…
            </span>
          </div>
        )}
        {cableResult && <p className="text-xs text-muted-foreground">{cableResult}</p>}
        {cableError && <ErrorBox message={cableError} />}
      </div>
    </Card>
  );
}

function AdvancedCard({ dataDir }: { dataDir: string }) {
  const [restarting, setRestarting] = React.useState(false);
  const [confirmReset, setConfirmReset] = React.useState(false);
  const [resetting, setResetting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const [method, setMethod] = React.useState("tenzro_getNodeStatus");
  const [params, setParams] = React.useState("{}");
  const [output, setOutput] = React.useState<string | null>(null);
  const [rpcBusy, setRpcBusy] = React.useState(false);
  const [rpcError, setRpcError] = React.useState<string | null>(null);

  async function reveal() {
    setError(null);
    try {
      await api.revealDataDir();
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function restart() {
    setRestarting(true);
    setError(null);
    try {
      await api.restartNode();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setRestarting(false);
    }
  }

  async function reset() {
    setResetting(true);
    setError(null);
    try {
      await api.resetLocalChain();
      setConfirmReset(false);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setResetting(false);
    }
  }

  async function send() {
    let parsed: unknown;
    try {
      parsed = JSON.parse(params.trim() === "" ? "{}" : params);
    } catch {
      setRpcError("Parameters must be valid JSON.");
      return;
    }
    setRpcBusy(true);
    setRpcError(null);
    setOutput(null);
    try {
      const result = await api.rpcCall({
        method: method.trim(),
        params: parsed,
      });
      setOutput(JSON.stringify(result, null, 2));
    } catch (e) {
      setRpcError(errorText(e));
    } finally {
      setRpcBusy(false);
    }
  }

  return (
    <Card className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <Micro>Advanced</Micro>
        <p className="text-xs leading-relaxed text-muted-foreground">
          Direct access to the node running inside this app.
        </p>
      </div>

      {error && <ErrorBox message={error} />}

      <div className="flex flex-col divide-y divide-border">
        <Row
          label="Data directory"
          value={
            <span className="flex items-center gap-3">
              <span className="break-all text-xs">{dataDir || "—"}</span>
              <button
                type="button"
                disabled={dataDir === ""}
                onClick={() => void reveal()}
                className="flex-shrink-0 text-[10px] uppercase tracking-[0.14em] text-muted-foreground hover:text-foreground disabled:opacity-40"
              >
                Open
              </button>
            </span>
          }
        />
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">
        The operator admin token lives in control.json in the app's config
        directory. This window never receives it: node changes go through the
        app's own controls, and the console below serves read-only methods.
      </p>

      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={() => void restart()} busy={restarting}>
          Restart the node
        </Button>
        {confirmReset ? (
          <>
            <Button variant="destructive" onClick={() => void reset()} busy={resetting}>
              Confirm — erase local chain data
            </Button>
            <Button variant="ghost" onClick={() => setConfirmReset(false)}>
              Keep it
            </Button>
          </>
        ) : (
          <Button variant="destructive" onClick={() => setConfirmReset(true)}>
            Reset local chain data
          </Button>
        )}
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">
        Resetting deletes this machine's copy of the chain and re-syncs from the
        network. Your identity, wallet and settings are untouched.
      </p>

      <div className="flex flex-col gap-4 border border-border p-4">
        <Micro>Call the node directly</Micro>
        <div className="flex flex-col gap-3">
          <Field label="Method">
            <Input value={method} onChange={(e) => setMethod(e.currentTarget.value)} />
          </Field>
          <Field label="Parameters" hint="JSON. An empty object is fine.">
            <TextArea
              rows={3}
              value={params}
              onChange={(e) => setParams(e.currentTarget.value)}
              className="font-mono text-xs"
            />
          </Field>
          <div>
            <Button
              variant="primary"
              onClick={() => void send()}
              busy={rpcBusy}
              disabled={method.trim() === ""}
            >
              Send
            </Button>
          </div>
        </div>
        {rpcError && <ErrorBox message={rpcError} />}
        {output && (
          <pre className="max-h-80 overflow-auto border border-border bg-secondary p-3 font-mono text-xs">
            {output}
          </pre>
        )}
      </div>
    </Card>
  );
}
