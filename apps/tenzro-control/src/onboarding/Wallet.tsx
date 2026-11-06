import * as React from "react";
import { Badge, Card, Field, Input, Micro, Row } from "@/components/ui";
import { api, errorText, type WalletStatusView } from "@/lib/api";
import { Step } from "./Step";

export function Wallet({
  wallet,
  onWallet,
  onBack,
  onNext,
}: {
  wallet: WalletStatusView | null;
  onWallet: (w: WalletStatusView) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const [displayName, setDisplayName] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const exists = wallet?.exists ?? false;

  async function create() {
    const name = displayName.trim();
    if (!name) {
      setError("Give this identity a name so you can recognise it later.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const next = await api.walletUseHardwareKey(name);
      onWallet(next);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Step
      index={2}
      eyebrow="Step three"
      title="Your wallet and identity"
      description="Earnings settle to this wallet, and the stake that admits you to a role is held in it. The signing key never leaves this machine."
      error={error}
      busy={busy}
      onBack={onBack}
      onNext={exists ? onNext : create}
      nextLabel={exists ? "Continue" : "Create"}
      nextDisabled={!exists && displayName.trim().length === 0}
    >
      {exists && wallet ? (
        <Card>
          <div className="flex items-center justify-between">
            <Micro>Identity</Micro>
            <Badge tone="good">Hardware key</Badge>
          </div>
          <div className="mt-4 flex flex-col divide-y divide-border">
            <Row label="Address" value={wallet.display_address} />
            <Row label="DID" value={<span className="break-all text-xs">{wallet.did}</span>} />
            <Row label="Balance" value={wallet.balance_display} />
            <Row label="Signed by" value={wallet.stake_account.signer === "secure-enclave" ? "Secure Enclave" : "TPM"} />
          </div>
        </Card>
      ) : (
        <div className="flex flex-col gap-4">
          <Card>
            <Micro>This machine's hardware key</Micro>
            <ul className="mt-3 flex flex-col gap-2">
              {[
                "The wallet is the account of the key this machine's TPM or Secure Enclave holds; it cannot be exported.",
                "Every transaction is signed inside that hardware and settles on the network.",
                "A machine without such hardware has no wallet here: there is no software key.",
              ].map((p) => (
                <li key={p} className="flex gap-2 text-xs leading-relaxed text-muted-foreground">
                  <span className="mt-1.5 h-1 w-1 flex-shrink-0 bg-border" />
                  {p}
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <Field
              label="Name"
              hint="Shown on your identity record. A machine name works well."
            >
              <Input
                value={displayName}
                onChange={(e) => setDisplayName(e.currentTarget.value)}
                placeholder="Studio Mac"
                autoFocus
              />
            </Field>
          </Card>
        </div>
      )}
    </Step>
  );
}
