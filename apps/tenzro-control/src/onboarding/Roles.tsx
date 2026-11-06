import { Badge, Micro } from "@/components/ui";
import { cn } from "@/lib/cn";
import type { CapabilityReadout, RoleStakeGate } from "@/lib/api";
import { ROLES, hardwareBlock, type RoleDef } from "@/lib/roles";
import { Step } from "./Step";

const EXCLUSIVE = ROLES.filter((r) => r.exclusive).map((r) => r.id);

export function Roles({
  hardware,
  gates,
  selected,
  onChange,
  onBack,
  onNext,
}: {
  hardware: CapabilityReadout | null;
  gates: RoleStakeGate[];
  selected: string[];
  onChange: (roles: string[]) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const toggle = (role: RoleDef) => {
    if (selected.includes(role.id)) {
      onChange(selected.filter((r) => r !== role.id));
    } else if (role.exclusive) {
      onChange([role.id]);
    } else {
      onChange([...selected.filter((r) => !EXCLUSIVE.includes(r)), role.id]);
    }
  };

  return (
    <Step
      index={1}
      eyebrow="Step two"
      title="Choose what you offer"
      description="Pick as many as you like, or keep the machine to yourself. Most roles have a stake requirement your wallet has to meet before the network admits you — you set the wallet up next."
      onBack={onBack}
      onNext={onNext}
      nextDisabled={selected.length === 0}
      footerNote={
        selected.length === 0 ? "Select at least one role." : `${selected.length} selected`
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        {ROLES.map((role) => {
          const gate = gates.find((g) => g.role === role.id);
          const blocked = hardwareBlock(role.id, hardware);
          const isSelected = selected.includes(role.id);

          return (
            <button
              key={role.id}
              type="button"
              disabled={blocked !== null}
              onClick={() => toggle(role)}
              className={cn(
                "flex flex-col gap-3 border p-5 text-left transition-colors",
                blocked
                  ? "cursor-not-allowed border-border bg-card opacity-40"
                  : isSelected
                    ? "border-brand bg-brand-soft"
                    : "border-border bg-card hover:border-muted-foreground",
              )}
            >
              <div className="flex items-start justify-between gap-3">
                <span className="text-sm font-medium">{role.title}</span>
                {isSelected && <Badge tone="good">Selected</Badge>}
              </div>

              <p className="text-xs leading-relaxed text-muted-foreground">{role.blurb}</p>
              <p className="text-xs leading-relaxed text-muted-foreground">{role.earns}</p>

              <div className="mt-auto flex flex-col gap-1 pt-2">
                {gate && (
                  <div className="flex items-baseline justify-between gap-2">
                    <Micro>Stake</Micro>
                    <span className="font-mono text-xs text-foreground">
                      {gate.required_display}
                      {role.scaled && "+"}
                    </span>
                  </div>
                )}
                {role.stakeNote && (
                  <span className="text-[11px] text-muted-foreground">{role.stakeNote}</span>
                )}
                {blocked && <span className="text-[11px] text-destructive">{blocked}</span>}
              </div>
            </button>
          );
        })}
      </div>
    </Step>
  );
}
