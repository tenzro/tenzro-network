import * as React from "react";
import { ChatCircle, ChartLine, Cube, Gauge, Gear, ImageSquare, Wallet } from "@phosphor-icons/react";
import { cn } from "@/lib/cn";
import { TitleBar } from "@/components/TitleBar";
import type { NodeStatusView } from "@/lib/api";

export type PageId =
  | "dashboard"
  | "wallet"
  | "models"
  | "forecast"
  | "media"
  | "assistant"
  | "settings";

const NAV: { id: PageId; label: string; icon: React.ElementType }[] = [
  { id: "dashboard", label: "Dashboard", icon: Gauge },
  { id: "wallet", label: "Wallet", icon: Wallet },
  { id: "models", label: "Models", icon: Cube },
  { id: "forecast", label: "Forecast", icon: ChartLine },
  { id: "media", label: "Media", icon: ImageSquare },
  { id: "assistant", label: "Assistant", icon: ChatCircle },
  { id: "settings", label: "Settings", icon: Gear },
];

/// Colour of the connectivity dot. `connecting` and `syncing` are both
/// transient, but only `connected` means the node is doing its job.
function dotClass(connectivity: string | undefined): string {
  switch (connectivity) {
    case "connected":
      return "bg-brand";
    case "syncing":
      return "bg-foreground";
    default:
      return "bg-muted-foreground";
  }
}

export function Shell({
  page,
  onNavigate,
  status,
  children,
}: {
  page: PageId;
  onNavigate: (page: PageId) => void;
  status: NodeStatusView | null;
  children: React.ReactNode;
}) {
  return (
    <div className="flex h-screen flex-col bg-background text-foreground">
      <TitleBar />
      <div className="flex min-h-0 flex-1">
        <nav className="flex w-56 flex-shrink-0 flex-col border-r border-border">
          <div className="px-6 pb-6 pt-4">
            <div className="text-sm font-semibold tracking-tight">Tenzro Control</div>
            <div className="mt-1 flex items-center gap-2">
              <span className={cn("h-1.5 w-1.5", dotClass(status?.connectivity))} />
              <span className="text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                {status ? status.connectivity : "starting"}
              </span>
            </div>
          </div>

          <div className="flex flex-col">
            {NAV.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => onNavigate(id)}
                className={cn(
                  "flex items-center gap-3 border-l-2 px-6 py-2.5 text-left text-sm transition-colors",
                  id === page
                    ? "border-brand bg-secondary text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon size={16} weight="regular" />
                {label}
              </button>
            ))}
          </div>

          <div className="mt-auto px-6 py-4">
            {status && (
              <div className="flex flex-col gap-1 font-mono text-[10px] text-muted-foreground">
                <span>block {status.block_height.toLocaleString("en-US")}</span>
                <span>
                  {status.peer_count} peer{status.peer_count === 1 ? "" : "s"}
                </span>
              </div>
            )}
          </div>
        </nav>

        <main className="min-w-0 flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  actions,
}: {
  eyebrow: string;
  title: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-end justify-between gap-6 border-b border-border px-10 py-8">
      <div>
        <div className="tnz-eyebrow">{eyebrow}</div>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight">{title}</h1>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
