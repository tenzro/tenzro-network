import * as React from "react";
import qrcode from "qrcode-generator";
import { Badge, Button, Card, ErrorBox, Field, Input, Micro, Row, Stat } from "@/components/ui";
import { PageHeader } from "@/components/Shell";
import {
  api,
  errorText,
  type RoleStakeGate,
  type SendReceipt,
  type WalletStatusView,
} from "@/lib/api";
import { describeGate, tnzoToWei, weiToTnzoInput } from "@/lib/format";
import { roleLabel } from "@/lib/roles";

/// The two address widths the ledger accepts, as hex character counts.
/// Mirrors `parse_recipient` on the Rust side so a bad address is caught
/// before it costs a round trip.
function recipientError(raw: string): string | null {
  const text = raw.trim();
  if (text === "") return null;
  const hex = text.startsWith("0x") ? text.slice(2) : text;
  if (!/^[0-9a-fA-F]*$/.test(hex)) return "Addresses are hexadecimal.";
  if (hex.length !== 40 && hex.length !== 64) {
    return `Addresses are 40 or 64 hex characters. This one has ${hex.length}.`;
  }
  return null;
}

export function Wallet() {
  const [wallet, setWallet] = React.useState<WalletStatusView | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    try {
      setWallet(await api.walletStatus());
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  React.useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 15_000);
    return () => clearInterval(t);
  }, [load]);

  const gates = wallet?.gates ?? [];

  return (
    <div>
      <PageHeader eyebrow="Account" title="Wallet" />

      <div className="flex flex-col gap-4 px-10 py-8">
        {error && <ErrorBox message={error} />}

        <Card>
          <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
            <Stat label="Balance" value={wallet?.balance_display ?? "—"} sub="TNZO" />
            <Stat
              label="Staked"
              value={wallet?.staked_display ?? "—"}
              sub={
                wallet?.staked_role
                  ? roleLabel(wallet.staked_role)
                  : "Nothing bonded"
              }
            />
            <Stat
              label="Custody"
              value={wallet?.custody === "hardware" ? "Hardware key" : "None"}
              sub={
                wallet?.custody === "hardware"
                  ? wallet.stake_account.signer === "secure-enclave"
                    ? "Secure Enclave"
                    : "TPM"
                  : "Not set up"
              }
            />
            <Stat label="Address" value={wallet?.display_address ?? "—"} />
          </div>
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Receive wallet={wallet} />
          <Send wallet={wallet} onSent={() => void load()} />
        </div>

        <Card>
          <Micro>Stake</Micro>
          <p className="mt-3 max-w-2xl text-xs leading-relaxed text-muted-foreground">
            A role is admitted once its bond is posted. Each role has its own bond,
            locked in chain state and returned after its unbonding period. Bonds are
            signed by {stakeSignerText(wallet?.stake_account.signer)}.
          </p>
          {wallet?.stake_account.address && (
            <div className="mt-3 font-mono text-xs text-muted-foreground">
              {`Operator account ${wallet.stake_account.address} · ${wallet.stake_balance_display} TNZO`}
            </div>
          )}
          <div className="mt-6 flex flex-col gap-3">
            {gates.map((gate) => (
              <StakeRow
                key={gate.role}
                gate={gate}
                wallet={wallet}
                onChanged={setWallet}
              />
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

/* --------------------------------------------------------------------- */
/* receive                                                                */
/* --------------------------------------------------------------------- */

function Receive({ wallet }: { wallet: WalletStatusView | null }) {
  const [copied, setCopied] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const address = wallet?.address ?? "";

  const qrSrc = React.useMemo(() => {
    if (!address) return null;
    const qr = qrcode(0, "M");
    qr.addData(address);
    qr.make();
    return qr.createDataURL(5, 2);
  }, [address]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(address);
      setCopied(true);
      setTimeout(() => setCopied(false), 2_000);
    } catch {
      // The full address is on screen either way, so a refused clipboard
      // is an inconvenience rather than a dead end.
      setError("Could not reach the clipboard. The address above is selectable.");
    }
  }

  return (
    <Card className="flex flex-col">
      <Micro>Receive</Micro>

      {!wallet?.exists ? (
        <p className="mt-4 text-sm text-muted-foreground">
          No account yet. One is provisioned during setup.
        </p>
      ) : (
        <>
          <div className="mt-5 flex items-start gap-5">
            {qrSrc && (
              <img
                src={qrSrc}
                alt="This wallet's address as a QR code"
                className="h-28 w-28 flex-shrink-0 border border-border bg-white"
              />
            )}
            <div className="flex min-w-0 flex-1 flex-col gap-3">
              <div className="break-all font-mono text-xs leading-relaxed text-foreground">
                {address}
              </div>
              <div>
                <Button onClick={() => void copy()}>{copied ? "Copied" : "Copy"}</Button>
              </div>
            </div>
          </div>

          <div className="mt-5 flex flex-col gap-1 border-t border-border pt-4">
            <Row
              label="DID"
              value={<span className="break-all text-xs">{wallet.did || "—"}</span>}
            />
          </div>

          {error && <ErrorBox className="mt-4" message={error} />}
        </>
      )}
    </Card>
  );
}

/* --------------------------------------------------------------------- */
/* send                                                                   */
/* --------------------------------------------------------------------- */

function Send({
  wallet,
  onSent,
}: {
  wallet: WalletStatusView | null;
  onSent: () => void;
}) {
  const [to, setTo] = React.useState("");
  const [amount, setAmount] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [receipt, setReceipt] = React.useState<SendReceipt | null>(null);

  const addressProblem = recipientError(to);
  const amountWei = amount.trim() === "" ? null : tnzoToWei(amount);
  const overBalance =
    amountWei !== null &&
    wallet !== null &&
    BigInt(amountWei) > BigInt(wallet.balance_wei);

  const amountProblem =
    amount.trim() === ""
      ? null
      : amountWei === null
        ? "Enter a plain decimal amount."
        : BigInt(amountWei) === 0n
          ? "Amount must be greater than zero."
          : overBalance
            ? "More than the balance."
            : null;

  const ready =
    wallet?.exists === true &&
    to.trim() !== "" &&
    addressProblem === null &&
    amountWei !== null &&
    amountProblem === null;

  async function submit() {
    if (!ready || amountWei === null) return;
    setBusy(true);
    setError(null);
    setReceipt(null);
    try {
      const r = await api.walletSend(to.trim(), amountWei);
      setReceipt(r);
      setTo("");
      setAmount("");
      onSent();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="flex flex-col gap-5">
      <div className="flex items-center justify-between gap-4">
        <Micro>Send</Micro>
        {wallet?.custody === "hardware" && <Badge tone="neutral">Signs on this device</Badge>}
      </div>

      <Field label="To" hint={addressProblem ?? "A 20- or 32-byte address, in hex."}>
        <Input
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="0x…"
          spellCheck={false}
          autoComplete="off"
          disabled={!wallet?.exists || busy}
        />
      </Field>

      <Field
        label="Amount"
        hint={amountProblem ?? `Available ${wallet?.balance_display ?? "—"} TNZO`}
      >
        <Input
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          placeholder="0.0"
          inputMode="decimal"
          spellCheck={false}
          autoComplete="off"
          disabled={!wallet?.exists || busy}
        />
      </Field>

      {wallet?.custody === "hardware" && (
        <p className="text-xs leading-relaxed text-muted-foreground">
          The transaction is signed inside this machine's secure hardware and settles on the network.
        </p>
      )}

      <div>
        <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!ready}>
          Send
        </Button>
      </div>

      {error && <ErrorBox message={error} />}

      {receipt && (
        <div className="flex flex-col divide-y divide-border border-t border-border pt-2">
          <Row label="Sent" value={`${receipt.amount_display} TNZO`} />
          <Row
            label="To"
            value={<span className="break-all text-xs">{receipt.to}</span>}
          />
          <Row
            label="Transaction"
            value={<span className="break-all text-xs">{receipt.reference}</span>}
          />
        </div>
      )}
    </Card>
  );
}

/* --------------------------------------------------------------------- */
/* stake                                                                  */
/* --------------------------------------------------------------------- */

function stakeSignerText(signer: string | undefined): string {
  if (signer === "tpm") return "this machine's TPM";
  if (signer === "secure-enclave") return "this machine's Secure Enclave";
  return "a TPM or Secure Enclave, which this machine does not have";
}

function StakeRow({
  gate,
  wallet,
  onChanged,
}: {
  gate: RoleStakeGate;
  wallet: WalletStatusView | null;
  onChanged: (next: WalletStatusView) => void;
}) {
  const readout = describeGate(gate);
  const bonded = gate.staked_wei !== "0";
  const unbonding = wallet?.unbonding_roles.includes(gate.role) ?? false;
  const unlocksAt = unbonding && wallet?.unbonding_at_ms ? new Date(wallet.unbonding_at_ms) : null;
  const withdrawable = unlocksAt !== null && unlocksAt.getTime() <= Date.now();

  const [amount, setAmount] = React.useState(() => weiToTnzoInput(gate.required_wei));
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const amountWei = tnzoToWei(amount);
  const canSign = Boolean(wallet?.stake_account.address);

  async function run(action: () => Promise<WalletStatusView>) {
    if (!wallet?.stake_account.address) return;
    setBusy(true);
    setError(null);
    try {
      onChanged(await action());
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-4 border border-border p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="text-sm">{gate.label}</div>
          <div className="mt-1 font-mono text-xs text-muted-foreground">
            {gate.required_display} TNZO minimum
          </div>
        </div>
        <Badge tone={readout.tone}>{readout.label}</Badge>
      </div>

      {bonded && (
        <div className="flex items-center justify-between gap-4">
          <div className="text-xs text-muted-foreground">
            {`${gate.staked_display} TNZO bonded for this role.`}
          </div>
          <Button
            variant="destructive"
            onClick={() => void run(() => api.stakeUnbond(gate.role, gate.staked_wei))}
            busy={busy}
            disabled={!canSign}
          >
            Unbond
          </Button>
        </div>
      )}

      {unlocksAt && (
        <div className="flex items-center justify-between gap-4">
          <div className="text-xs text-muted-foreground">
            {`Unbonding stake unlocks ${unlocksAt.toLocaleDateString("en-US", {
              month: "short",
              day: "numeric",
              year: "numeric",
            })}.`}
          </div>
          <Button
            onClick={() => void run(() => api.stakeWithdraw(gate.role))}
            busy={busy}
            disabled={!withdrawable || !canSign}
          >
            Withdraw
          </Button>
        </div>
      )}

      {!bonded && gate.can_stake && (
        <div className="flex items-end gap-3">
          <Field label="Amount" className="flex-1">
            <Input
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              inputMode="decimal"
              spellCheck={false}
              autoComplete="off"
              disabled={busy}
            />
          </Field>
          <Button
            variant="primary"
            onClick={() => amountWei && void run(() => api.stakeBond(gate.role, amountWei))}
            busy={busy}
            disabled={amountWei === null || !canSign}
          >
            Stake
          </Button>
        </div>
      )}

      {!bonded && !gate.can_stake && (
        <p className="text-xs leading-relaxed text-muted-foreground">{readout.detail}</p>
      )}

      {error && <ErrorBox message={error} />}
    </div>
  );
}
