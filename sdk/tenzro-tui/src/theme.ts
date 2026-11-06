// One palette, matching the Tenzro site: a near-black ground (the terminal's
// own) and a single periwinkle accent. Status is always a word first and a
// colour second, so NO_COLOR and monochrome terminals lose nothing.

export interface Theme {
  color: boolean;
  accent: string | undefined;
  ok: string | undefined;
  warn: string | undefined;
  bad: string | undefined;
  /** Secondary text. Never below 4.5:1 on black, so it is a light grey, not "dim". */
  muted: string | undefined;
}

export function colorEnabled(env: NodeJS.ProcessEnv = process.env, flagNoColor = false): boolean {
  if (flagNoColor) return false;
  // https://no-color.org: present and non-empty disables colour.
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== "") return false;
  if (env.TERM === "dumb") return false;
  return true;
}

export function makeTheme(color: boolean): Theme {
  if (!color) {
    return { color, accent: undefined, ok: undefined, warn: undefined, bad: undefined, muted: undefined };
  }
  return {
    color,
    accent: "#8a9bc7",
    ok: "#7cc4a4",
    warn: "#e0b567",
    bad: "#e48a8a",
    muted: "#9aa0ad",
  };
}
