import { currentEnv, resolveState, stakeGap, type ApplicationState } from "@/lib/onboarding";

/// The initial-phase "apply to the Tenzro team" message for a role the wallet
/// cannot yet stake: the same lines `tenzro join` and `tenzro doctor` print
/// (see lib/onboarding.ts). Renders nothing outside the initial phase or once
/// the wallet holds the stake, so the caller falls back to its own readout.
///
/// `reported` is the application state from the website's status endpoint.
/// The wallet has no way to ask it yet (the webview's CSP allows only IPC, so
/// it needs a Rust command in src-tauri); until that exists the state comes
/// from the chain alone and a person who has applied sees the first-step text
/// until the funds land.
export function ApplicationNotice({
  roleLabel,
  requiredWei,
  balanceWei,
  staked,
  account,
  reported = null,
}: {
  roleLabel: string;
  requiredWei: string;
  balanceWei: string | null;
  staked: boolean;
  account: string;
  reported?: ApplicationState | null;
}) {
  const required = BigInt(requiredWei);
  const balance = balanceWei === null ? null : BigInt(balanceWei);
  const state = resolveState({
    reported,
    balanceMeetsMinimum: balance === null ? null : balance >= required,
    chainStaked: staked,
    chainServing: null,
  });
  const lines = stakeGap({ roleLabel, requiredWei: required, balanceWei: balance, account, state }, currentEnv());
  if (!lines) return null;
  return (
    <div className="flex flex-col gap-2 text-xs leading-relaxed text-muted-foreground" data-testid="application-notice">
      {lines.map(([kind, text], i) =>
        kind === "heading" ? (
          <p key={i} className="font-medium text-foreground">
            {text}
          </p>
        ) : kind === "command" ? (
          <code key={i} className="select-all break-all rounded bg-muted px-2 py-1 font-mono text-foreground">
            {text}
          </code>
        ) : (
          <p key={i}>{text}</p>
        ),
      )}
    </div>
  );
}
