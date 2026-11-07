import * as React from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { platform } from "@tauri-apps/plugin-os";
import { cn } from "@/lib/cn";

/// Minimize / maximize / close glyphs drawn to the exact Windows 11 caption
/// button spec (10x10 hairline, centered in a 46x32 hit target) rather than
/// reused from the Phosphor set used everywhere else — Phosphor's rounded
/// weights read as an obviously-not-native window control at this size, and
/// this is the one place the app borrows the host OS's own shape language
/// instead of its own.
function MinimizeGlyph() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
      <path d="M0 5H10" stroke="currentColor" />
    </svg>
  );
}

function MaximizeGlyph() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
      <rect x="0.5" y="0.5" width="9" height="9" stroke="currentColor" />
    </svg>
  );
}

function RestoreGlyph() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
      {/* Back square's top + right edges only — the front square below never
          crosses them, so no fill-based cutout is needed to keep them from
          visually merging into one shape. */}
      <path d="M2.5 0.5H9.5V7.5" stroke="currentColor" />
      <rect x="0.5" y="2.5" width="7" height="7" stroke="currentColor" />
    </svg>
  );
}

function CloseGlyph() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
      <path d="M0 0L10 10M10 0L0 10" stroke="currentColor" />
    </svg>
  );
}

function CaptionButton({
  onClick,
  label,
  variant,
  children,
}: {
  onClick: () => void;
  label: string;
  variant?: "close";
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      data-tauri-drag-region={false}
      onClick={onClick}
      className={cn(
        "flex h-8 w-[46px] items-center justify-center text-foreground/80 transition-colors",
        variant === "close" ? "hover:bg-destructive hover:text-destructive-foreground" : "hover:bg-secondary",
      )}
    >
      {children}
    </button>
  );
}

/// The window's top strip. On Windows, `decorations: false`
/// (tauri.windows.conf.json) leaves no native titlebar at all, so this draws
/// one — drag region, app name, and Windows 11-spec caption buttons. On
/// every other platform the OS is left to draw its own (macOS's real
/// traffic lights come free from `titleBarStyle: Overlay` in the base
/// config), and this renders just the drag strip behind them.
export function TitleBar() {
  // `platform()` reads a value the IPC bridge injects before the page's own
  // JS runs — genuinely synchronous, not just fast, so this is safe to seed
  // state with directly and never flashes the wrong chrome on first paint.
  const [isWindows] = React.useState(() => platform() === "windows");
  const [isMaximized, setIsMaximized] = React.useState(false);

  React.useEffect(() => {
    if (!isWindows) return;
    const win = getCurrentWindow();
    let unlisten: (() => void) | undefined;
    win.isMaximized().then(setIsMaximized);
    win.onResized(() => {
      win.isMaximized().then(setIsMaximized);
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, [isWindows]);

  if (!isWindows) {
    // macOS gets its traffic lights for free from `titleBarStyle: Overlay`
    // in the base tauri.conf.json — this is just the drag strip behind them.
    return <div className="title-drag-region" data-tauri-drag-region />;
  }

  const win = getCurrentWindow();

  return (
    <div
      data-tauri-drag-region
      className="flex h-8 w-full flex-shrink-0 items-center justify-between border-b border-border"
    >
      <div data-tauri-drag-region className="flex h-full flex-1 items-center px-3">
        <span className="text-xs font-medium tracking-tight text-muted-foreground">
          Tenzro Control
        </span>
      </div>
      <div className="flex h-full items-stretch">
        <CaptionButton onClick={() => void win.minimize()} label="Minimize">
          <MinimizeGlyph />
        </CaptionButton>
        <CaptionButton onClick={() => void win.toggleMaximize()} label={isMaximized ? "Restore" : "Maximize"}>
          {isMaximized ? <RestoreGlyph /> : <MaximizeGlyph />}
        </CaptionButton>
        <CaptionButton onClick={() => void win.close()} label="Close" variant="close">
          <CloseGlyph />
        </CaptionButton>
      </div>
    </div>
  );
}
