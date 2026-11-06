import * as React from "react";
import { Button, ErrorBox } from "@/components/ui";
import { TitleBar } from "@/components/TitleBar";
import { cn } from "@/lib/cn";

export const STEP_LABELS = [
  "Hardware",
  "Roles",
  "Wallet",
  "Configure",
  "Availability",
  "Pricing",
  "Review",
] as const;

export function Step({
  index,
  eyebrow,
  title,
  description,
  error,
  children,
  onBack,
  onNext,
  nextLabel = "Continue",
  nextDisabled,
  busy,
  footerNote,
}: {
  index: number;
  eyebrow: string;
  title: string;
  description?: React.ReactNode;
  error?: string | null;
  children: React.ReactNode;
  onBack?: () => void;
  onNext?: () => void;
  nextLabel?: string;
  nextDisabled?: boolean;
  busy?: boolean;
  footerNote?: React.ReactNode;
}) {
  return (
    <div className="relative flex min-h-screen flex-col">
      {/* Sized by the frame rather than by content, so the glow has an area
          to bloom into; behind the step, and never in the way of a click. */}
      <div className="tnz-ambient pointer-events-none absolute inset-0 -z-10" />
      <TitleBar />

      <div className="mx-auto flex w-full max-w-3xl flex-1 flex-col px-10 pb-10">
        <div className="flex items-center gap-1.5 pt-2">
          {STEP_LABELS.map((label, i) => (
            <div
              key={label}
              title={label}
              className={cn(
                "h-0.5 flex-1 transition-colors",
                i < index ? "bg-brand" : i === index ? "bg-foreground" : "bg-border",
              )}
            />
          ))}
        </div>

        <div className="pt-10">
          <div className="tnz-eyebrow">{eyebrow}</div>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight">{title}</h1>
          {description && (
            <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted-foreground">
              {description}
            </p>
          )}
        </div>

        <div className="flex-1 pt-8">{children}</div>

        {error && <ErrorBox className="mt-6" message={error} />}

        <div className="mt-8 flex items-center justify-between gap-4">
          <div className="text-xs text-muted-foreground">{footerNote}</div>
          <div className="flex items-center gap-2">
            {onBack && (
              <Button variant="ghost" onClick={onBack} disabled={busy}>
                Back
              </Button>
            )}
            {onNext && (
              <Button variant="primary" onClick={onNext} disabled={nextDisabled} busy={busy}>
                {nextLabel}
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
