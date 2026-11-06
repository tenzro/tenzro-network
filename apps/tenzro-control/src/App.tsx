import * as React from "react";
import { Shell, type PageId } from "@/components/Shell";
import { TitleBar } from "@/components/TitleBar";
import { Onboarding } from "@/onboarding/Onboarding";
import { Assistant } from "@/pages/Assistant";
import { Dashboard } from "@/pages/Dashboard";
import { Forecast } from "@/pages/Forecast";
import { Media } from "@/pages/Media";
import { Models } from "@/pages/Models";
import { Settings } from "@/pages/Settings";
import { Wallet } from "@/pages/Wallet";
import { ErrorBox, Spinner } from "@/components/ui";
import { api, errorText, type NodeStatusView } from "@/lib/api";

export default function App() {
  const [onboarded, setOnboarded] = React.useState<boolean | null>(null);
  const [status, setStatus] = React.useState<NodeStatusView | null>(null);
  const [page, setPage] = React.useState<PageId>("dashboard");
  const [error, setError] = React.useState<string | null>(null);

  const readConfig = React.useCallback(async () => {
    try {
      const config = await api.getConfig();
      setOnboarded(config.onboarded);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  React.useEffect(() => {
    void readConfig();
  }, [readConfig]);

  // The node boots alongside the window, so the first few polls legitimately
  // come back null. Keep the last good reading rather than blanking the shell.
  React.useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const next = await api.nodeStatus();
        if (live && next) setStatus(next);
      } catch {
        /* a dropped poll says nothing the next one won't say better */
      }
    };
    void tick();
    const t = setInterval(() => void tick(), 4_000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);

  if (error !== null && onboarded === null) {
    return (
      <div className="flex h-screen flex-col bg-background text-foreground">
        <TitleBar />
        <div className="flex flex-1 items-center justify-center px-10">
          <div className="w-full max-w-md">
            <ErrorBox message={error} />
          </div>
        </div>
      </div>
    );
  }

  if (onboarded === null) {
    return (
      <div className="flex h-screen flex-col bg-background text-foreground">
        <TitleBar />
        <div className="flex flex-1 items-center justify-center gap-3 text-sm text-muted-foreground">
          <Spinner />
          Starting the node…
        </div>
      </div>
    );
  }

  // Onboarding steps carry their own full-height frame, drag region and
  // ambient backdrop, so they are rendered without the shell around them.
  if (!onboarded) {
    return <Onboarding onDone={() => void readConfig()} />;
  }

  return (
    <Shell page={page} onNavigate={setPage} status={status}>
      {page === "dashboard" && <Dashboard status={status} />}
      {page === "wallet" && <Wallet />}
      {page === "models" && <Models />}
      {page === "forecast" && <Forecast />}
      {page === "media" && <Media />}
      {page === "assistant" && <Assistant />}
      {page === "settings" && <Settings onOpenModels={() => setPage("models")} />}
    </Shell>
  );
}
