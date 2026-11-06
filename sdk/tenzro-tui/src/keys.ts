// The single table every key comes from: dispatch, footer hints and the help
// overlay all read it, so the three can never disagree. One key, one action.

export type Action =
  | "screen:overview"
  | "screen:wallet"
  | "screen:models"
  | "screen:validators"
  | "screen:governance"
  | "next"
  | "prev"
  | "down"
  | "up"
  | "refresh"
  | "edit"
  | "help"
  | "quit"
  | "close";

export interface Binding {
  action: Action;
  /** Keys as shown to the person, one string each. */
  keys: string[];
  label: string;
  /** Short form for the footer; omitted when the help overlay is enough. */
  hint?: string;
}

export const SCREENS = [
  { id: "overview", title: "Overview", key: "1", action: "screen:overview" },
  { id: "wallet", title: "Wallet", key: "2", action: "screen:wallet" },
  { id: "models", title: "Models", key: "3", action: "screen:models" },
  { id: "validators", title: "Validators", key: "4", action: "screen:validators" },
  { id: "governance", title: "Governance", key: "5", action: "screen:governance" },
] as const;

export type ScreenId = (typeof SCREENS)[number]["id"];

export const BINDINGS: Binding[] = [
  { action: "screen:overview", keys: ["1"], label: "Overview: node, chain, peers" },
  { action: "screen:wallet", keys: ["2"], label: "Wallet: balance of one account" },
  { action: "screen:models", keys: ["3"], label: "Models: what this node holds and serves" },
  { action: "screen:validators", keys: ["4"], label: "Validators: the registered set" },
  { action: "screen:governance", keys: ["5"], label: "Governance: proposals and tallies" },
  { action: "next", keys: ["Tab", "Right"], label: "Next screen", hint: "Tab next" },
  { action: "prev", keys: ["Shift-Tab", "Left"], label: "Previous screen" },
  { action: "down", keys: ["Down", "j"], label: "Move down in a list", hint: "Up/Down move" },
  { action: "up", keys: ["Up", "k"], label: "Move up in a list" },
  { action: "refresh", keys: ["r"], label: "Refresh now (it also refreshes every 5 s)", hint: "r refresh" },
  { action: "edit", keys: ["e"], label: "Wallet: choose the account to show", hint: "e account" },
  { action: "help", keys: ["?"], label: "Show or hide this help", hint: "? help" },
  { action: "close", keys: ["Esc"], label: "Close help or cancel an edit" },
  { action: "quit", keys: ["q", "Ctrl-C"], label: "Quit and restore the terminal", hint: "q quit" },
];

/** Normalised key name from an input event. */
export function keyName(input: string, key: { tab?: boolean; shift?: boolean; leftArrow?: boolean; rightArrow?: boolean; upArrow?: boolean; downArrow?: boolean; escape?: boolean; ctrl?: boolean; return?: boolean }): string {
  if (key.ctrl && input === "c") return "Ctrl-C";
  if (key.tab && key.shift) return "Shift-Tab";
  if (key.tab) return "Tab";
  if (key.leftArrow) return "Left";
  if (key.rightArrow) return "Right";
  if (key.upArrow) return "Up";
  if (key.downArrow) return "Down";
  if (key.escape) return "Esc";
  if (key.return) return "Enter";
  return input;
}

export function actionFor(name: string): Action | null {
  for (const b of BINDINGS) if (b.keys.includes(name)) return b.action;
  return null;
}

/** Problems with the table itself: a key bound twice, or two actions with one label. */
export function bindingProblems(table: Binding[] = BINDINGS): string[] {
  const out: string[] = [];
  const seen = new Map<string, Action>();
  const labels = new Map<string, Action>();
  for (const b of table) {
    for (const k of b.keys) {
      const prior = seen.get(k);
      if (prior && prior !== b.action) out.push(`key ${k} is bound to ${prior} and ${b.action}`);
      seen.set(k, b.action);
    }
    const lp = labels.get(b.label);
    if (lp && lp !== b.action) out.push(`label "${b.label}" is used by ${lp} and ${b.action}`);
    labels.set(b.label, b.action);
  }
  return out;
}
