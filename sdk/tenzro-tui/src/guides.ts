// Runbooks as data. A step has the shape of a step in Tenzro Control's setup
// plan (`control_setupPlan`), so any Control client can show one. The console
// runs none of them: `what` names the command a person runs, and a step's
// state is only ever something the console read from the node.

import type { Alert } from "./alerts.js";
import type { Snapshot } from "./data.js";
import { stopChecks } from "./stop.js";

export interface Step {
  id: string;
  title: string;
  what: string;
  why: string;
  gate: "free" | "os_permission" | "passkey";
  skippable: boolean;
  caution: string | null;
  state: "pending" | "running" | "done" | "failed" | "skipped";
  progress: number | null;
  result: string | null;
}

export interface Runbook {
  id: "genesis" | "validator" | "upgrade";
  title: string;
  steps: Step[];
}

type Read = (snap: Snapshot, alerts: Alert[]) => { state: Step["state"]; result: string } | null;

interface Written extends Omit<Step, "state" | "progress" | "result" | "skippable" | "caution"> {
  skippable?: boolean;
  caution?: string;
  /** What the console can see of this step on the node it is pointed at. */
  read?: Read;
}

const running: Read = (snap) => {
  if (snap.status.state !== "ok") return null;
  const st = snap.status.value;
  const up = st.state === "Running" && st.health_status === "Healthy";
  return { state: up ? "done" : "pending", result: `this node is ${st.state}, ${st.health_status}, at height ${st.block_height}` };
};

const caughtUp: Read = (snap) => {
  if (snap.syncing.state !== "ok") return null;
  return snap.syncing.value ? { state: "running", result: "this node is still replaying the chain" } : { state: "done", result: "this node is at the tip" };
};

const headroom: Read = (snap, alerts) => {
  if (snap.status.state !== "ok" || snap.validators.state !== "ok") return null;
  const q = stopChecks(snap, alerts).find((c) => c.id === "quorum");
  return q ? { state: q.ok ? "done" : "failed", result: q.text } : null;
};

const WRITTEN: { id: Runbook["id"]; title: string; steps: Written[] }[] = [
  {
    id: "genesis",
    title: "Genesis assembly",
    steps: [
      {
        id: "genesis.init",
        title: "Create each founding validator's data directory",
        what: "On each founding validator's own machine: tenzro-node init --data-dir /var/lib/tenzro",
        why: "The consensus key is made in that machine's TPM 2.0 or Secure Enclave and never leaves it, so this cannot be done for it elsewhere.",
        gate: "os_permission",
        caution: "A machine that holds its key in another machine's TPM through a key holder cannot be a founding validator; it joins after genesis.",
      },
      {
        id: "genesis.entry",
        title: "Print each validator's genesis entry",
        what: "On the same machine: tenzro-node validator-entry --data-dir /var/lib/tenzro --stake <STAKE>",
        why: "The entry carries the validator's address, public keys, stake and the proofs its hardware signs; it names no network address.",
        gate: "os_permission",
      },
      {
        id: "genesis.collect",
        title: "Collect every entry into one genesis.toml",
        what: "Put every validator's entry into a single genesis.toml (schema version 1).",
        why: "The file is the chain's starting state; its validator set is exactly the entries in it.",
        gate: "free",
      },
      {
        id: "genesis.roles",
        title: "Bond a role for a founding node that serves others",
        what: "For a founding node that is an SDK seed, add a [[role_stakes]] table with its address, role = \"rpc\" and its public endpoint.",
        why: "It then appears in the on-chain operator list like any other operator.",
        gate: "free",
        skippable: true,
      },
      {
        id: "genesis.distribute",
        title: "Place the same genesis.toml on every validator",
        what: "Copy the one file to every validator, typically to /var/lib/tenzro/genesis.toml.",
        why: "Every validator must load the same genesis.",
        gate: "os_permission",
        caution: "A node refuses to start on a genesis whose entries' proofs do not verify, or that names no validators.",
      },
      {
        id: "genesis.start",
        title: "Start the validators and see the chain advance",
        what: "Start each validator's node service, then watch the height on the Overview screen of each.",
        why: "A running, healthy process is not enough: the height and the finalized height advancing is the sign that the set agrees.",
        gate: "os_permission",
        read: running,
      },
    ],
  },
  {
    id: "validator",
    title: "Validator entry after genesis",
    steps: [
      {
        id: "validator.genesis",
        title: "Get the network's genesis.toml",
        what: "Place the network's genesis.toml on the machine, typically at /var/lib/tenzro/genesis.toml.",
        why: "A joining node replays the chain from block 0 with the same genesis before it takes part.",
        gate: "os_permission",
      },
      {
        id: "validator.replay",
        title: "Start the node and let it replay the chain",
        what: "Start the node service and wait until it is at the tip.",
        why: "A validator never joins by snapshot: it checks every block itself first.",
        gate: "os_permission",
        read: caughtUp,
      },
      {
        id: "validator.register",
        title: "Register as a validator",
        what: "On the machine: tenzro validator keys --stake <STAKE> prints its keys and proofs; pass them to tenzro validator register (--help lists the options; add --tpm-key-holder <SOCKET> when the key is held in another machine's TPM).",
        why: "Registration bonds the stake and names the hardware-held consensus key the set will expect signatures from.",
        gate: "os_permission",
        caution: "Through a key holder every signature is a round trip to the holder, and a grant lasts at most the holder's limit.",
      },
      {
        id: "validator.active",
        title: "See the registration become active",
        what: "Watch the Validators screen until the new address is listed as Active.",
        why: "A registered validator signs only once the set has taken it in.",
        gate: "free",
      },
    ],
  },
  {
    id: "upgrade",
    title: "Upgrade window",
    steps: [
      {
        id: "upgrade.headroom",
        title: "Check the set can lose one validator",
        what: "Press S on the validator to be updated first and read the checks; leave without typing STOP.",
        why: "During the update that validator signs nothing; quorum plus one must remain without it.",
        gate: "free",
        read: headroom,
      },
      {
        id: "upgrade.canary",
        title: "Update one validator that does not serve the public endpoint",
        what: "On that machine set the new image digest in /var/lib/tenzro-bin/tenzro-run, then: docker stop tenzro-node",
        why: "One machine shows whether the new build follows the chain before the rest depend on it.",
        gate: "os_permission",
        caution: "Do not use systemctl restart for this: it does not replace the running container. docker stop lets the service start it again on the new digest.",
      },
      {
        id: "upgrade.verify",
        title: "Verify from a neighbouring validator",
        what: "On another validator, see that its peer count returns to what it was and its height keeps advancing.",
        why: "A container reported healthy is not enough: the chain advancing is the real signal.",
        gate: "free",
        read: running,
      },
      {
        id: "upgrade.sweep",
        title: "Update the remaining validators one at a time",
        what: "Repeat the update on each remaining validator, waiting about 30 seconds and re-checking between them.",
        why: "Old and new binaries run side by side during the window; one at a time keeps quorum throughout.",
        gate: "os_permission",
      },
      {
        id: "upgrade.activate",
        title: "Switch on what the release ships dormant",
        what: "When every validator runs the new build, propose and vote the release's activation parameters through governance.",
        why: "A change to what a block executes to stays off until the set agrees to an epoch for it, so old and new binaries never disagree.",
        gate: "passkey",
        skippable: true,
      },
    ],
  },
];

/** Every runbook, each step's state filled from what the console can read; a step it cannot see is `pending`. */
export function runbooks(snap: Snapshot, alerts: Alert[]): Runbook[] {
  return WRITTEN.map((book) => ({
    id: book.id,
    title: book.title,
    steps: book.steps.map(({ read, ...s }) => {
      const seen = read ? read(snap, alerts) : null;
      return { ...s, skippable: s.skippable ?? false, caution: s.caution ?? null, state: seen?.state ?? "pending", progress: null, result: seen?.result ?? null };
    }),
  }));
}
