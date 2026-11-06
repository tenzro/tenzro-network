import * as React from "react";
import { Badge, Card, Field, Input, Micro, Spinner } from "@/components/ui";
import { cn } from "@/lib/cn";
import { api, errorText, type PricingBracketView } from "@/lib/api";
import { formatTnzo, tnzoToWei, weiToTnzoInput } from "@/lib/format";
import { sellsModels } from "@/lib/roles";
import { Step } from "./Step";

const BRACKET_BLURB: Record<string, string> = {
  economy: "Undercut the network to win volume while you build a reputation.",
  standard: "Sit near the middle of the network. A reasonable default.",
  premium: "Charge above the middle. Fewer calls, more per call.",
};

export interface PricingState {
  inputWei: string;
  outputWei: string;
  storageMinWei: string;
  storageMaxWei: string;
  computeHourWei: string;
}

export function Pricing({
  roles,
  value,
  onChange,
  onBack,
  onNext,
}: {
  roles: string[];
  value: PricingState;
  onChange: (next: PricingState) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const wantsAi = sellsModels(roles);
  const wantsStorage = roles.includes("storage");
  const wantsCompute = roles.includes("compute");

  const [brackets, setBrackets] = React.useState<PricingBracketView[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const seeded = React.useRef(false);

  React.useEffect(() => {
    api
      .pricingBrackets()
      .then((list) => {
        setBrackets(list);
        if (seeded.current) return;
        seeded.current = true;
        // An unpriced node would never be routed to, so start on the middle
        // bracket rather than at zero.
        if (wantsAi && BigInt(value.inputWei || "0") === 0n) {
          const b = list.find((x) => x.id === "standard") ?? list[0];
          if (b) {
            onChange({
              ...value,
              inputWei: b.input_price_per_token_wei,
              outputWei: b.output_price_per_token_wei,
            });
          }
        }
      })
      .catch((e) => setError(errorText(e)));
  }, []);

  const setStorage = (which: "min" | "max", text: string) => {
    const wei = tnzoToWei(text);
    if (wei === null) return;
    onChange(which === "min" ? { ...value, storageMinWei: wei } : { ...value, storageMaxWei: wei });
  };

  const setHourly = (text: string) => {
    const wei = tnzoToWei(text);
    if (wei === null) return;
    onChange({ ...value, computeHourWei: wei });
  };

  const inverted =
    wantsStorage && BigInt(value.storageMinWei || "0") > BigInt(value.storageMaxWei || "0");

  return (
    <Step
      index={5}
      eyebrow="Step six"
      title="What you charge"
      description="Callers pay in TNZO and settle on-chain. You can change these at any time from settings."
      error={error}
      onBack={onBack}
      onNext={onNext}
      nextDisabled={inverted}
      footerNote={inverted ? "The floor rate is above the ceiling rate." : undefined}
    >
      <div className="flex flex-col gap-4">
        {wantsAi && (
          <div className="flex flex-col gap-2">
            <Micro>Inference</Micro>
            {!brackets ? (
              <Card>
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
                  <Spinner />
                  Reading network rates…
                </div>
              </Card>
            ) : (
              <div className="grid gap-3 sm:grid-cols-3">
                {brackets.map((b) => {
                  const active = value.inputWei === b.input_price_per_token_wei;
                  return (
                    <button
                      key={b.id}
                      type="button"
                      onClick={() =>
                        onChange({
                          ...value,
                          inputWei: b.input_price_per_token_wei,
                          outputWei: b.output_price_per_token_wei,
                        })
                      }
                      className={cn(
                        "flex flex-col gap-3 border p-5 text-left transition-colors",
                        active
                          ? "border-brand bg-brand-soft"
                          : "border-border bg-card hover:border-muted-foreground",
                      )}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-medium capitalize">{b.id}</span>
                        {active && <Badge tone="good">Selected</Badge>}
                      </div>
                      <p className="text-xs leading-relaxed text-muted-foreground">
                        {BRACKET_BLURB[b.id] ?? ""}
                      </p>
                      <div className="mt-auto flex flex-col gap-1 pt-2 font-mono text-[11px] text-muted-foreground">
                        <span>in {b.input_display} / token</span>
                        <span>out {b.output_display} / token</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {wantsStorage && (
          <Card className="flex flex-col gap-5">
            <Micro>Storage, per gigabyte-month</Micro>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label="Floor"
                hint={`You will not accept less than ${formatTnzo(value.storageMinWei)}.`}
              >
                <Input
                  inputMode="decimal"
                  defaultValue={weiToTnzoInput(value.storageMinWei)}
                  onChange={(e) => setStorage("min", e.currentTarget.value)}
                />
              </Field>
              <Field
                label="Ceiling"
                hint={`Your asking rate is ${formatTnzo(value.storageMaxWei)}.`}
              >
                <Input
                  inputMode="decimal"
                  defaultValue={weiToTnzoInput(value.storageMaxWei)}
                  onChange={(e) => setStorage("max", e.currentTarget.value)}
                />
              </Field>
            </div>
          </Card>
        )}

        {wantsCompute && (
          <Card className="flex flex-col gap-5">
            <Micro>Accelerator rental, per hour</Micro>
            <Field
              label="Rate"
              hint={`A renter pays ${formatTnzo(value.computeHourWei)} for an hour of your cards. They bring their own work; you are not serving models for them.`}
            >
              <Input
                inputMode="decimal"
                defaultValue={weiToTnzoInput(value.computeHourWei)}
                onChange={(e) => setHourly(e.currentTarget.value)}
              />
            </Field>
          </Card>
        )}

        {!wantsAi && !wantsStorage && !wantsCompute && (
          <Card>
            <p className="text-sm text-muted-foreground">
              Nothing you chose is priced by you. Models you run for yourself are not sold, and
              validating is paid from transaction fees at rates the network sets.
            </p>
          </Card>
        )}
      </div>
    </Step>
  );
}
