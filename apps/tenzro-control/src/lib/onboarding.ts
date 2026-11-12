// Initial-phase onboarding for the wallet: the same states and the same words
// as the CLI (`tenzro join`, `tenzro setup`, `tenzro stake bond`, `tenzro
// doctor`), which build them in crates/tenzro-cli/src/onboarding/.
//
// Two things keep this from drifting from the Rust:
//  - the values a person fills in (contact channels, join link, reply-time
//    text, default phase) are read from the SAME json file the CLI compiles in,
//    crates/tenzro-cli/src/onboarding/foundation_config.json;
//  - onboarding.test.ts replays onboarding-fixtures.json, which a CLI unit test
//    generates from the Rust builder, and requires identical lines.
//
// Wording rule: the initial phase is run by the Tenzro founders and core
// developers / the Tenzro team. Never an individual.

import config from "../../../../crates/tenzro-cli/src/onboarding/foundation_config.json";

export type Phase = "foundation" | "open-stake";

export type ApplicationState =
  | "not_applied"
  | "applied"
  | "under_review"
  | "approved"
  | "funded"
  | "staked"
  | "serving"
  | "declined";

export const LADDER: ApplicationState[] = ["applied", "under_review", "approved", "funded", "staked", "serving"];

const LABEL: Record<ApplicationState, string> = {
  not_applied: "not applied yet",
  applied: "applied",
  under_review: "under review",
  approved: "approved",
  funded: "funded",
  staked: "staked",
  serving: "serving",
  declined: "not approved",
};

export type LineKind = "heading" | "text" | "command";
export type Line = [LineKind, string];

export interface MsgEnv {
  phase: Phase;
  join_link: string;
  contacts: string[];
  reply_time: string;
}

/** The settings as filled in foundation_config.json. */
export function currentEnv(): MsgEnv {
  return {
    phase: config.default_phase === "open-stake" ? "open-stake" : "foundation",
    join_link: config.join_link,
    contacts: config.foundation_contact_channels.map(([label, value]) => `${label}: ${value}`),
    reply_time: config.expected_reply_time,
  };
}

export function stakeInPlace(s: ApplicationState): boolean {
  return s === "staked" || s === "serving";
}

/** The ladder as one line with the current rung bracketed. */
export function ladderLine(state: ApplicationState): string {
  const line = LADDER.map((s) => (s === state ? `[${LABEL[s]}]` : LABEL[s])).join(" > ");
  if (state === "not_applied") return `Status: not applied yet (${line})`;
  if (state === "declined") return `Status: not approved (${line})`;
  return `Status: ${line}`;
}

export interface Evidence {
  /** What the website reported, or the last record kept. */
  reported: ApplicationState | null;
  balanceMeetsMinimum: boolean | null;
  chainStaked: boolean | null;
  chainServing: boolean | null;
}

/** Where the user actually is. Same rules as the CLI's `state::resolve`. */
export function resolveState(ev: Evidence): ApplicationState {
  const staked = ev.chainStaked === true;
  if (staked && ev.chainServing === true) return "serving";
  if (staked) return "staked";
  if (ev.balanceMeetsMinimum === true) return "funded";
  // A report is never believed past `funded`: the chain decides the rest.
  const reported = ev.reported === "staked" || ev.reported === "serving" ? "funded" : ev.reported;
  return reported ?? "not_applied";
}

const WEI = 10n ** 18n;

/** `10000 TNZO`, `0.5 TNZO`: no thousands separators, as the CLI prints it. */
export function plainTnzo(wei: bigint): string {
  const whole = wei / WEI;
  const rest = wei % WEI;
  if (rest === 0n) return `${whole} TNZO`;
  const micro = (wei + 500_000_000_000n) / 1_000_000_000_000n;
  return `${micro / 1_000_000n}.${(micro % 1_000_000n).toString().padStart(6, "0")} TNZO`;
}

export interface GapInput {
  roleLabel: string;
  requiredWei: bigint;
  /** null when the balance could not be read; never carries the reason. */
  balanceWei: bigint | null;
  account: string;
  state: ApplicationState;
}

/**
 * The initial-phase message, or null when none applies: another phase, the
 * wallet already holds the stake, or the stake is already bonded.
 */
export function stakeGap(input: GapInput, env: MsgEnv): Line[] | null {
  const met = input.balanceWei !== null && input.balanceWei >= input.requiredWei;
  if (env.phase !== "foundation" || met || stakeInPlace(input.state)) return null;
  const need = plainTnzo(input.requiredWei);
  const role = input.roleLabel;
  const held =
    input.balanceWei === null
      ? "The balance could not be checked just now."
      : `This wallet holds ${plainTnzo(input.balanceWei)}.`;
  const out: Line[] = [["heading", `You need ${need} to run the ${role} role. ${held}`]];
  out.push(["text", ladderLine(input.state)]);
  const contacts = (): void => {
    out.push(["text", "Questions? Contact the Tenzro team:"]);
    for (const c of env.contacts) out.push(["command", c]);
  };
  switch (input.state) {
    case "not_applied":
      out.push([
        "text",
        `Why: the ${role} role bonds ${need} as its stake. In the initial phase of Tenzro Network the ` +
          "Tenzro founders and core developers run the network, review each application, decide " +
          "eligibility, and send the stake to approved applicants. There is nothing to buy first, and " +
          "applying does not guarantee approval.",
      ]);
      out.push(["text", `How to apply: fill in the form at ${env.join_link} and give this wallet address:`]);
      out.push(["command", input.account]);
      contacts();
      out.push(["text", `Expected reply: ${env.reply_time}`]);
      out.push([
        "text",
        "Run the same command again at any time. It carries on from wherever your application is.",
      ]);
      break;
    case "applied":
    case "under_review": {
      const what =
        input.state === "applied"
          ? "The Tenzro team has received your application"
          : "The Tenzro team is reviewing your application";
      out.push([
        "text",
        `${what} for the ${role} role. Nothing more is needed from you right now. If approved, the ` +
          `team sends ${need} to this wallet:`,
      ]);
      out.push(["command", input.account]);
      out.push(["text", `Expected reply: ${env.reply_time}`]);
      contacts();
      out.push(["text", "Run the same command again to check; it continues from here."]);
      break;
    }
    case "approved":
      out.push([
        "text",
        `Approved. The Tenzro team sends ${need} to this wallet after approval. Nothing more is needed ` +
          "from you; once it arrives, run the same command again and it carries on to staking:",
      ]);
      out.push(["command", input.account]);
      out.push([
        "text",
        `If it has not arrived and the expected time has passed (${env.reply_time}), contact the team:`,
      ]);
      for (const c of env.contacts) out.push(["command", c]);
      break;
    case "funded":
      out.push([
        "text",
        "The Tenzro team has recorded this wallet as funded, but the balance does not show it yet. " +
          "Run the same command again in a few minutes. If it still does not show, contact the team:",
      ]);
      for (const c of env.contacts) out.push(["command", c]);
      break;
    case "declined":
      out.push(["text", "The Tenzro team did not approve this application, so no stake will be sent for it."]);
      contacts();
      break;
    default:
      return null;
  }
  return out;
}
