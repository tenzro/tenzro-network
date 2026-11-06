import * as React from "react";
import { cn } from "@/lib/cn";

/* --------------------------------------------------------------------- */
/* text                                                                   */
/* --------------------------------------------------------------------- */

export function Eyebrow({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("tnz-eyebrow", className)}>{children}</div>;
}

export function Micro({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn("text-[10px] uppercase tracking-[0.14em] text-muted-foreground", className)}>
      {children}
    </span>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("font-mono text-muted-foreground", className)}>{children}</span>;
}

/* --------------------------------------------------------------------- */
/* surfaces                                                               */
/* --------------------------------------------------------------------- */

export function Card({
  children,
  className,
  ...rest
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("border border-border bg-card p-6", className)} {...rest}>
      {children}
    </div>
  );
}

export function Divider({ className }: { className?: string }) {
  return <div className={cn("h-px w-full bg-border", className)} />;
}

/* --------------------------------------------------------------------- */
/* buttons                                                                */
/* --------------------------------------------------------------------- */

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "destructive";
  busy?: boolean;
};

export function Button({
  variant = "secondary",
  busy = false,
  className,
  disabled,
  children,
  ...rest
}: ButtonProps) {
  const base =
    "inline-flex items-center justify-center gap-2 px-4 h-9 text-xs uppercase tracking-[0.14em] transition-colors disabled:opacity-40 disabled:cursor-not-allowed";
  const variants = {
    primary: "bg-primary text-primary-foreground hover:opacity-90",
    secondary: "bg-secondary text-foreground border border-border hover:bg-accent",
    ghost: "text-muted-foreground hover:text-foreground",
    destructive: "border border-destructive text-destructive hover:bg-destructive/10",
  } as const;

  return (
    <button
      className={cn(base, variants[variant], className)}
      disabled={disabled || busy}
      {...rest}
    >
      {busy && <Spinner />}
      {children}
    </button>
  );
}

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block h-3 w-3 animate-spin border border-current border-t-transparent",
        className,
      )}
    />
  );
}

/* --------------------------------------------------------------------- */
/* inputs                                                                 */
/* --------------------------------------------------------------------- */

export function Field({
  label,
  hint,
  children,
  className,
}: {
  label: string;
  hint?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <label className={cn("flex flex-col gap-2", className)}>
      <Micro>{label}</Micro>
      {children}
      {hint && <span className="text-xs text-muted-foreground">{hint}</span>}
    </label>
  );
}

export function Input({ className, ...rest }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-9 w-full border border-border bg-secondary px-3 text-sm text-foreground placeholder:text-muted-foreground",
        className,
      )}
      {...rest}
    />
  );
}

export function TextArea({
  className,
  ...rest
}: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        "w-full resize-none border border-border bg-secondary px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground",
        className,
      )}
      {...rest}
    />
  );
}

export function Select({
  className,
  children,
  ...rest
}: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "h-9 w-full border border-border bg-secondary px-3 text-sm text-foreground",
        className,
      )}
      {...rest}
    >
      {children}
    </select>
  );
}

/* --------------------------------------------------------------------- */
/* status                                                                 */
/* --------------------------------------------------------------------- */

export function Badge({
  children,
  tone = "neutral",
  className,
}: {
  children: React.ReactNode;
  tone?: "neutral" | "good" | "warn" | "bad";
  className?: string;
}) {
  const tones = {
    neutral: "border-border text-muted-foreground",
    good: "border-brand text-brand",
    warn: "border-border text-foreground",
    bad: "border-destructive text-destructive",
  } as const;
  return (
    <span
      className={cn(
        "inline-flex items-center border px-2 py-0.5 text-[10px] uppercase tracking-[0.14em]",
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Stat({
  label,
  value,
  sub,
  className,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-1", className)}>
      <Micro>{label}</Micro>
      <div className="font-mono text-lg text-foreground">{value}</div>
      {sub && <div className="text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

export function Row({
  label,
  value,
  className,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-baseline justify-between gap-4 py-2", className)}>
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="font-mono text-sm text-foreground">{value}</span>
    </div>
  );
}

export function Meter({
  used,
  total,
  className,
}: {
  used: number;
  total: number;
  className?: string;
}) {
  const pct = total > 0 ? Math.min(100, Math.max(0, (used / total) * 100)) : 0;
  return (
    <div className={cn("h-1 w-full bg-secondary", className)}>
      <div className="h-full bg-brand transition-[width]" style={{ width: `${pct}%` }} />
    </div>
  );
}

export function ErrorBox({ message, className }: { message: string; className?: string }) {
  return (
    <div
      className={cn(
        "border border-destructive bg-destructive/10 px-4 py-3 text-sm text-destructive",
        className,
      )}
    >
      {message}
    </div>
  );
}

export function Empty({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("py-12 text-center text-sm text-muted-foreground", className)}>
      {children}
    </div>
  );
}
