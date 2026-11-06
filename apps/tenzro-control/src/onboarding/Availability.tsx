import { Button, Card, Micro, Select } from "@/components/ui";
import { cn } from "@/lib/cn";
import type { Availability as AvailabilityConfig, ServingWindow } from "@/lib/api";
import { DAY_NAMES, hourLabel } from "@/lib/format";
import { Step } from "./Step";

const HOURS = Array.from({ length: 24 }, (_, h) => h);

export function Availability({
  value,
  onChange,
  onBack,
  onNext,
}: {
  value: AvailabilityConfig;
  onChange: (next: AvailabilityConfig) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const setWindows = (windows: ServingWindow[]) => onChange({ ...value, windows });

  const patch = (i: number, next: Partial<ServingWindow>) =>
    setWindows(value.windows.map((w, j) => (i === j ? { ...w, ...next } : w)));

  const toggleDay = (i: number, day: number) => {
    const w = value.windows[i];
    const days = w.days.includes(day) ? w.days.filter((d) => d !== day) : [...w.days, day].sort();
    patch(i, { days });
  };

  const empty = !value.always_on && value.windows.length === 0;

  return (
    <Step
      index={4}
      eyebrow="Step five"
      title="When you serve"
      description="Outside these hours the node stays connected but stops accepting work, so the machine is yours again."
      onBack={onBack}
      onNext={onNext}
      nextDisabled={empty}
      footerNote={empty ? "Add a window, or switch to always on." : undefined}
    >
      <div className="flex flex-col gap-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <ModeCard
            active={value.always_on}
            onClick={() => onChange({ ...value, always_on: true })}
            title="Always on"
            blurb="Accept work whenever the machine is awake. Highest earnings."
          />
          <ModeCard
            active={!value.always_on}
            onClick={() =>
              onChange({
                always_on: false,
                windows:
                  value.windows.length > 0
                    ? value.windows
                    : [{ start_hour: 22, end_hour: 7, days: [] }],
              })
            }
            title="On a schedule"
            blurb="Only accept work inside the hours you choose."
          />
        </div>

        {!value.always_on && (
          <div className="flex flex-col gap-3">
            {value.windows.map((w, i) => (
              <Card key={i} className="flex flex-col gap-4">
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <Micro>From</Micro>
                    <Select
                      className="w-24"
                      value={w.start_hour}
                      onChange={(e) => patch(i, { start_hour: Number(e.currentTarget.value) })}
                    >
                      {HOURS.map((h) => (
                        <option key={h} value={h}>
                          {hourLabel(h)}
                        </option>
                      ))}
                    </Select>
                    <Micro>To</Micro>
                    <Select
                      className="w-24"
                      value={w.end_hour}
                      onChange={(e) => patch(i, { end_hour: Number(e.currentTarget.value) })}
                    >
                      {HOURS.map((h) => (
                        <option key={h} value={h}>
                          {hourLabel(h)}
                        </option>
                      ))}
                    </Select>
                  </div>

                  <Button
                    variant="ghost"
                    onClick={() => setWindows(value.windows.filter((_, j) => j !== i))}
                  >
                    Remove
                  </Button>
                </div>

                <div className="flex flex-col gap-2">
                  <Micro>Days</Micro>
                  <div className="flex flex-wrap gap-1.5">
                    {DAY_NAMES.map((name, d) => {
                      const on = w.days.length === 0 || w.days.includes(d);
                      return (
                        <button
                          key={name}
                          type="button"
                          onClick={() => toggleDay(i, d)}
                          className={cn(
                            "border px-3 py-1 text-[10px] uppercase tracking-[0.14em] transition-colors",
                            on
                              ? "border-brand bg-brand-soft text-foreground"
                              : "border-border text-muted-foreground hover:text-foreground",
                          )}
                        >
                          {name}
                        </button>
                      );
                    })}
                  </div>
                  {w.days.length === 0 && (
                    <span className="text-xs text-muted-foreground">Every day.</span>
                  )}
                  {w.start_hour === w.end_hour && (
                    <span className="text-xs text-destructive">
                      Start and end are the same hour, so this window never opens.
                    </span>
                  )}
                  {w.start_hour > w.end_hour && (
                    <span className="text-xs text-muted-foreground">
                      Runs past midnight into the next day.
                    </span>
                  )}
                </div>
              </Card>
            ))}

            <Button
              onClick={() =>
                setWindows([...value.windows, { start_hour: 9, end_hour: 17, days: [] }])
              }
            >
              Add window
            </Button>
          </div>
        )}
      </div>
    </Step>
  );
}

function ModeCard({
  active,
  onClick,
  title,
  blurb,
}: {
  active: boolean;
  onClick: () => void;
  title: string;
  blurb: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex flex-col gap-2 border p-5 text-left transition-colors",
        active ? "border-brand bg-brand-soft" : "border-border bg-card hover:border-muted-foreground",
      )}
    >
      <span className="text-sm font-medium">{title}</span>
      <span className="text-xs leading-relaxed text-muted-foreground">{blurb}</span>
    </button>
  );
}
