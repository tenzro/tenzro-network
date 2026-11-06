import React, { useCallback, useEffect, useRef, useState } from "react";
import { Box, Text, useApp, useInput, useWindowSize } from "ink";
import { emptySnapshot, headline, type Snapshot, type Source } from "./data.js";
import { BINDINGS, SCREENS, actionFor, keyName, type ScreenId } from "./keys.js";
import { Governance, Models, Overview, Validators, Wallet, rowCount, type ScreenProps } from "./screens.js";
import { Heading, Muted, ThemeContext, Word, type Tone } from "./ui.js";
import { ageText, isAddress } from "./format.js";
import type { Theme } from "./theme.js";

export const MIN_COLS = 80;
export const MIN_ROWS = 24;

const TONE: Record<string, Tone> = { OK: "ok", WATCH: "warn", DOWN: "bad", UNKNOWN: "warn" };

export interface AppProps {
  source: Source;
  theme: Theme;
  initialAccount: string | null;
  refreshMs?: number;
  /** Fixed size for tests; otherwise the terminal's own, followed live. */
  size?: { columns: number; rows: number };
}

export function App({ source, theme, initialAccount, refreshMs = 5000, size }: AppProps) {
  const { exit } = useApp();
  const win = useWindowSize();
  const columns = size?.columns ?? win.columns;
  const rows = size?.rows ?? win.rows;

  const [snap, setSnap] = useState<Snapshot>(emptySnapshot);
  const snapRef = useRef(snap);
  const [screen, setScreenState] = useState<ScreenId>("overview");
  // Keys can arrive in one chunk, before a re-render: handlers read the screen from here.
  const screenRef = useRef<ScreenId>("overview");
  const setScreen = (s: ScreenId) => {
    screenRef.current = s;
    setScreenState(s);
  };
  const [sel, setSel] = useState<Record<string, number>>({});
  const [help, setHelp] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const [chosen, setChosen] = useState<string | null>(initialAccount);
  const [now, setNow] = useState(Date.now());
  const busy = useRef(false);

  const payee = snap.status.state === "ok" ? snap.status.value.payee : snap.status.state === "error" ? (snap.status.last?.value.payee ?? null) : null;
  const account = chosen ?? payee ?? null;
  const accountSource = chosen ? "chosen" : payee ? "payee" : "none";
  const accountRef = useRef(account);
  accountRef.current = account;

  const refresh = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    try {
      const next = await source.collect(accountRef.current, snapRef.current);
      snapRef.current = next;
      setSnap(next);
    } finally {
      busy.current = false;
    }
  }, [source]);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), refreshMs);
    return () => clearInterval(t);
  }, [refresh, refreshMs]);
  // A new account (or the payee arriving with the first answer) is fetched at once.
  useEffect(() => {
    if (account) void refresh();
  }, [account, refresh]);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 2000);
    return () => clearInterval(t);
  }, []);

  const moveSel = (d: number) => {
    const count = rowCount(screenRef.current, snapRef.current);
    setSel((s) => ({ ...s, [screenRef.current]: Math.max(0, Math.min(Math.max(0, count - 1), (s[screenRef.current] ?? 0) + d)) }));
  };
  const goto = (delta: number) => {
    const i = SCREENS.findIndex((s) => s.id === screenRef.current);
    setScreen(SCREENS[(i + delta + SCREENS.length) % SCREENS.length]!.id);
    setHelp(false);
  };

  useInput((input, key) => {
    if (editing !== null) {
      if (key.escape) {
        setEditing(null);
        setEditError(null);
      } else if (key.return) {
        const v = editing.trim();
        if (v === "") {
          setChosen(null);
          setEditing(null);
          setEditError(null);
        } else if (isAddress(v)) {
          setChosen(v);
          setEditing(null);
          setEditError(null);
        } else {
          setEditError("That is not an account address: 0x followed by 40 or 64 hex digits.");
        }
      } else if (key.backspace || key.delete) {
        setEditing((e) => (e ?? "").slice(0, -1));
      } else if (!key.ctrl && !key.meta && input) {
        setEditing((e) => (e ?? "") + input.replace(/[\r\n]/g, ""));
      }
      return;
    }
    // Fast key repeat or a paste arrives as one chunk: act on each character.
    if (input.length > 1 && !key.ctrl && !key.meta && !key.escape) {
      for (const ch of input) handleKey(ch, key);
      return;
    }
    handleKey(input, key);
  });

  function handleKey(input: string, key: Parameters<typeof keyName>[1]) {
    const act = actionFor(keyName(input, key));
    switch (act) {
      case "quit":
        exit();
        return;
      case "help":
        setHelp((h) => !h);
        return;
      case "close":
        setHelp(false);
        return;
      case "refresh":
        void refresh();
        return;
      case "next":
        goto(1);
        return;
      case "prev":
        goto(-1);
        return;
      case "down":
        moveSel(1);
        return;
      case "up":
        moveSel(-1);
        return;
      case "edit":
        if (screenRef.current === "wallet") {
          setEditing(chosen ?? "");
          setHelp(false);
        }
        return;
      default:
        if (act && act.startsWith("screen:")) {
          setScreen(act.slice(7) as ScreenId);
          setHelp(false);
        }
    }
  }

  if (columns < MIN_COLS || rows < MIN_ROWS) {
    return (
      <ThemeContext.Provider value={theme}>
        <Box flexDirection="column">
          <Heading>Terminal too small</Heading>
          <Text>{`This console needs at least ${MIN_COLS}x${MIN_ROWS}; this window is ${columns}x${rows}.`}</Text>
          <Muted>Make the window larger, or run with --plain for a text report.</Muted>
        </Box>
      </ThemeContext.Provider>
    );
  }

  const h = headline(snap);
  const bodyHeight = rows - 5;
  const props: ScreenProps = { snap, now, width: columns, height: bodyHeight, selected: sel[screen] ?? 0, account, accountSource };
  const updated = snap.at ? `updated ${ageText(now - snap.at)}` : "waiting";
  const footer = editing !== null ? "Enter confirm  Esc cancel  empty Enter = node payee" : help ? "Esc close help  q quit" : BINDINGS.filter((b) => b.hint).map((b) => b.hint).join("  ");

  let body: React.ReactNode;
  if (help) body = <HelpView />;
  else if (editing !== null) {
    body = (
      <Box flexDirection="column">
        <Heading>Choose the account to show</Heading>
        <Text>
          {"> "}
          {editing}
          <Text inverse> </Text>
        </Text>
        {editError ? <Word tone="bad">{editError}</Word> : <Muted>Paste or type an address, then press Enter.</Muted>}
      </Box>
    );
  } else {
    body =
      screen === "overview" ? <Overview {...props} /> : screen === "wallet" ? <Wallet {...props} /> : screen === "models" ? <Models {...props} /> : screen === "validators" ? <Validators {...props} /> : <Governance {...props} />;
  }

  return (
    <ThemeContext.Provider value={theme}>
      <Box flexDirection="column" width={columns} height={rows}>
        <Box>
          <Text bold color={theme.accent}>
            TENZRO
          </Text>
          <Text> </Text>
          <Muted>{source.url}</Muted>
          <Box flexGrow={1} />
          <Word tone={TONE[h.word] ?? "plain"}>{h.word}</Word>
        </Box>
        <Box>
          {SCREENS.map((s) => (
            <Box key={s.id} marginRight={2}>
              {s.id === screen ? (
                <Text bold inverse color={theme.accent}>{` ${s.key} ${s.title} `}</Text>
              ) : (
                <Text>{` ${s.key} ${s.title} `}</Text>
              )}
            </Box>
          ))}
        </Box>
        <Text color={theme.muted} wrap="truncate-end">{h.word === "OK" ? "─".repeat(columns) : fitReason(h.reason, columns)}</Text>
        <Box flexGrow={1} flexDirection="column" overflow="hidden" height={bodyHeight}>
          {body}
        </Box>
        <Text color={theme.muted}>{"─".repeat(columns)}</Text>
        <Box>
          <Box flexShrink={1}>
            <Text color={theme.muted} wrap="truncate-end">{footer}</Text>
          </Box>
          <Box flexGrow={1} />
          <Box flexShrink={0} marginLeft={1}>
            <Muted>{updated}</Muted>
          </Box>
        </Box>
      </Box>
    </ThemeContext.Provider>
  );
}

function fitReason(reason: string, cols: number): string {
  const s = reason.length > cols ? reason.slice(0, cols - 3) + "..." : reason;
  return s;
}

function HelpView() {
  return (
    <Box flexDirection="column">
      <Heading>Keys</Heading>
      {BINDINGS.map((b) => (
        <Box key={b.action}>
          <Box width={18} flexShrink={0}>
            <Text bold>{b.keys.join(" or ")}</Text>
          </Box>
          <Text>{b.label}</Text>
        </Box>
      ))}
      <Box marginTop={1} flexDirection="column">
        <Heading>Status words</Heading>
        <Text>
          <Word tone="ok">OK</Word> running and healthy.  <Word tone="warn">WATCH</Word> degraded, catching up or short of disk.
        </Text>
        <Text>
          <Word tone="bad">DOWN</Word> the node did not answer.  <Word tone="warn">UNKNOWN</Word> nothing heard yet.
        </Text>
      </Box>
    </Box>
  );
}
