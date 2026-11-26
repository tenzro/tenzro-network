import React, { useCallback, useEffect, useRef, useState } from "react";
import { Box, Text, useApp, useInput, useWindowSize } from "ink";
import { acknowledge, adopt, alertSource, noAlerts, openAlerts, step, worstUnacknowledged, type Alert, type AlertEvent, type AlertState } from "./alerts.js";
import { emptySnapshot, headline, type Snapshot, type Source } from "./data.js";
import { HelperAbsent, HelperError, type Helper } from "./helper.js";
import { BINDINGS, SCREENS, actionFor, keyName, paletteMatches, type Action, type ScreenId } from "./keys.js";
import { runbooks, type Runbook } from "./guides.js";
import { readShared, writeShared } from "./shared.js";
import { stopAllowed, stopChecks, stopConsequence, type StopCheck } from "./stop.js";
import { Governance, Health, Logs, Models, Overview, Peers, Settings, Validators, Wallet, rowCount, type ScreenProps } from "./screens.js";
import { Heading, Muted, StaleAfterContext, ThemeContext, TypedConfirm, Word, type Tone } from "./ui.js";
import { ageText, isAddress } from "./format.js";
import type { Theme } from "./theme.js";

export const MIN_COLS = 80;
export const MIN_ROWS = 24;

const TONE: Record<string, Tone> = { OK: "ok", WATCH: "warn", DOWN: "bad", UNKNOWN: "warn" };

/** Most entries the session log keeps; older ones are dropped. */
const MAX_EVENTS = 500;

/** Snapshots kept for replay: an hour at the usual refresh. */
const MAX_HISTORY = 720;

/** The word a person types to stop the node. */
const STOP_WORD = "STOP";

interface Stopping {
  checks: StopCheck[];
  phase: "asking" | "blocked" | "confirm" | "working" | "done";
  typed: string;
  error: string | null;
  result: string;
}

export interface AppProps {
  source: Source;
  theme: Theme;
  initialAccount: string | null;
  refreshMs?: number;
  /** The operator's local helper, when the console may ask it to act. */
  helper?: Helper | null;
  /** A word kept in the header for the whole session, such as REHEARSAL. */
  banner?: string;
  /** The file of acknowledgements this console shares with others that name it. */
  shared?: string | null;
  /** Fixed size for tests; otherwise the terminal's own, followed live. */
  size?: { columns: number; rows: number };
}

export function App({ source, theme, initialAccount, refreshMs = 5000, helper = null, banner, shared = null, size }: AppProps) {
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
  const staleAfter = 3 * refreshMs;
  const started = useRef(Date.now());
  const alertRef = useRef<AlertState>(noAlerts);
  const [alertState, setAlertState] = useState<AlertState>(noAlerts);
  const [events, setEvents] = useState<AlertEvent[]>([]);
  const [acking, setAcking] = useState<{ key: string; title: string; text: string } | null>(null);
  const [ackError, setAckError] = useState<string | null>(null);
  const [stopping, setStopping] = useState<Stopping | null>(null);
  const [palette, setPalette] = useState<{ text: string; index: number } | null>(null);
  const [runbook, setRunbook] = useState<{ id: Runbook["id"]; index: number } | null>(null);
  const log = (added: AlertEvent[]) => {
    if (added.length > 0) setEvents((e) => [...added.slice().reverse(), ...e].slice(0, MAX_EVENTS));
  };
  const alerts = openAlerts(alertState, snap.at || started.current, now, staleAfter);
  const alertsRef = useRef(alerts);
  alertsRef.current = alerts;
  // Replay: every screen is drawn from a snapshot the console saw earlier, with the alerts open then.
  const history = useRef<{ snap: Snapshot; alerts: Alert[] }[]>([]);
  const [replay, setReplay] = useState<number | null>(null);
  const past = replay !== null ? history.current[replay] : undefined;
  const view = past ? { snap: past.snap, alerts: past.alerts, now: past.snap.at } : { snap, alerts, now };
  const viewRef = useRef(view);
  viewRef.current = view;
  const eventsRef = useRef(events);
  eventsRef.current = events;

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
      const stepped = step(alertRef.current, next, Date.now(), staleAfter);
      if (shared) stepped.state = adopt(stepped.state, readShared(shared));
      alertRef.current = stepped.state;
      setAlertState(stepped.state);
      log(stepped.events);
      history.current.push({ snap: next, alerts: openAlerts(stepped.state, next.at, next.at, staleAfter) });
      if (history.current.length > MAX_HISTORY) {
        history.current.shift();
        setReplay((r) => (r === null ? null : Math.max(0, r - 1)));
      }
    } finally {
      busy.current = false;
    }
  }, [source, staleAfter, shared]);

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
    const count = rowCount(screenRef.current, viewRef.current.snap, viewRef.current.alerts, eventsRef.current);
    setSel((s) => ({ ...s, [screenRef.current]: Math.max(0, Math.min(Math.max(0, count - 1), (s[screenRef.current] ?? 0) + d)) }));
  };
  const goto = (delta: number) => {
    const i = SCREENS.findIndex((s) => s.id === screenRef.current);
    setScreen(SCREENS[(i + delta + SCREENS.length) % SCREENS.length]!.id);
    setHelp(false);
  };

  useInput((input, key) => {
    if (acking !== null) {
      if (key.escape) {
        setAcking(null);
        setAckError(null);
      } else if (key.return) {
        const done = acknowledge(alertRef.current, acking.key, acking.text, Date.now());
        const ack = typeof done === "string" ? null : done.state.tracks[acking.key]?.ack;
        const unshared = typeof done !== "string" && shared && ack ? writeShared(shared, acking.key, { level: done.event.level, reason: ack.reason, at: ack.at }) : null;
        if (typeof done === "string" || unshared) {
          setAckError(typeof done === "string" ? done : unshared);
        } else {
          alertRef.current = done.state;
          setAlertState(done.state);
          log([done.event]);
          setAcking(null);
          setAckError(null);
        }
      } else if (key.backspace || key.delete) {
        setAcking((a) => (a ? { ...a, text: a.text.slice(0, -1) } : a));
      } else if (!key.ctrl && !key.meta && input) {
        setAcking((a) => (a ? { ...a, text: a.text + input.replace(/[\r\n]/g, "") } : a));
      }
      return;
    }
    if (stopping !== null) {
      if (stopping.phase === "working" || stopping.phase === "asking") return;
      if (key.escape || stopping.phase !== "confirm") {
        if (key.escape || key.return) setStopping(null);
      } else if (key.return) {
        if (stopping.typed === STOP_WORD) void stopNode();
        else setStopping({ ...stopping, error: `Nothing was stopped: that was not ${STOP_WORD}.` });
      } else if (key.backspace || key.delete) {
        setStopping((s) => (s ? { ...s, typed: s.typed.slice(0, -1), error: null } : s));
      } else if (!key.ctrl && !key.meta && input) {
        // A fast run of keys arrives as several events in one tick: each applies to the text the one before left.
        const added = input.replace(/[\r\n]/g, "");
        setStopping((s) => (s ? { ...s, typed: [...added].reduce((t, ch) => (ch === "\x7f" || ch === "\b" ? t.slice(0, -1) : t + ch), s.typed), error: null } : s));
      }
      return;
    }
    if (runbook !== null) {
      const steps = runbooks(viewRef.current.snap, viewRef.current.alerts).find((b) => b.id === runbook.id)?.steps.length ?? 0;
      if (key.escape) setRunbook(null);
      else if (key.downArrow || input === "j") setRunbook({ ...runbook, index: Math.min(runbook.index + 1, Math.max(0, steps - 1)) });
      else if (key.upArrow || input === "k") setRunbook({ ...runbook, index: Math.max(0, runbook.index - 1) });
      return;
    }
    if (palette !== null) {
      const found = paletteMatches(palette.text);
      if (key.escape) {
        setPalette(null);
      } else if (key.return) {
        const pick = found[Math.min(palette.index, found.length - 1)];
        setPalette(null);
        if (pick) runAction(pick.action);
      } else if (key.downArrow) {
        setPalette({ ...palette, index: Math.min(palette.index + 1, Math.max(0, found.length - 1)) });
      } else if (key.upArrow) {
        setPalette({ ...palette, index: Math.max(0, palette.index - 1) });
      } else if (key.backspace || key.delete) {
        setPalette({ text: palette.text.slice(0, -1), index: 0 });
      } else if (!key.ctrl && !key.meta && input) {
        setPalette({ text: palette.text + input.replace(/[\r\n]/g, ""), index: 0 });
      }
      return;
    }
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

  /** Ask the helper to stop the node; without a helper, say what to run. */
  async function stopNode() {
    const byHand = `Nothing was stopped. To stop it, run as this node's operator: tenzro-node graceful-exit --rpc-url ${source.url}`;
    setStopping((s) => (s ? { ...s, phase: "working" } : s));
    let result: string;
    if (!helper) {
      result = byHand;
    } else {
      try {
        const done = await helper.call<{ service?: string; reason?: string }>("control_service", { action: "stop" });
        result = `The helper answered: the node service is ${done.service ?? "in an unknown state"}${done.reason ? ` (${done.reason})` : ""}.`;
      } catch (e) {
        if (e instanceof HelperAbsent) result = `The helper (tenzro control) is not running. ${byHand}`;
        else if (e instanceof HelperError) result = `Nothing was stopped. The helper refused: ${e.shown}`;
        else result = `It is not known whether the node stopped: ${e instanceof Error ? e.message : String(e)}`;
      }
    }
    setStopping((s) => (s ? { ...s, phase: "done", result } : s));
    void refresh();
  }

  function handleKey(input: string, key: Parameters<typeof keyName>[1]) {
    runAction(actionFor(keyName(input, key)));
  }

  function runAction(act: Action | null) {
    // In replay the screens show the past: nothing may be decided from it.
    if (replay !== null && (act === "stop" || act === "acknowledge" || act === "edit" || act === "refresh")) return;
    switch (act) {
      case "replay:back":
        if (history.current.length > 1) setReplay((r) => Math.max(0, (r ?? history.current.length - 1) - 1));
        setHelp(false);
        return;
      case "replay:forward":
        setReplay((r) => (r === null || r + 1 >= history.current.length - 1 ? null : r + 1));
        return;
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
      case "stop": {
        const checks = stopChecks(snapRef.current, alertsRef.current);
        const witnesses = source.witnesses;
        // Other operators are asked only once this node's own checks pass.
        if (witnesses && stopAllowed(checks)) {
          setStopping({ checks, phase: "asking", typed: "", error: null, result: "" });
          void witnesses(snapRef.current)
            .catch((): StopCheck => ({ id: "peers", ok: false, text: "The other operators could not be asked." }))
            .then((peers) => {
              const all = [...checks, peers];
              setStopping((s) => (s && s.phase === "asking" ? { ...s, checks: all, phase: stopAllowed(all) ? "confirm" : "blocked" } : s));
            });
        } else {
          setStopping({ checks, phase: stopAllowed(checks) ? "confirm" : "blocked", typed: "", error: null, result: "" });
        }
        setHelp(false);
        return;
      }
      case "palette":
        setPalette({ text: "", index: 0 });
        setHelp(false);
        return;
      case "acknowledge": {
        const cur = screenRef.current === "health" ? alertsRef.current[sel.health ?? 0] : undefined;
        // The console's own blindness is not something to accept and move on from.
        if (cur && alertRef.current.tracks[cur.key]) {
          setAcking({ key: cur.key, title: cur.title, text: "" });
          setHelp(false);
        }
        return;
      }
      default:
        if (act && act.startsWith("runbook:")) {
          setRunbook({ id: act.slice(8) as Runbook["id"], index: 0 });
          setHelp(false);
        }
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

  const h = headline(view.snap);
  const bodyHeight = rows - 5;
  const props: ScreenProps = {
    snap: view.snap,
    now: view.now,
    width: columns,
    height: bodyHeight,
    selected: Math.min(sel[screen] ?? 0, Math.max(0, rowCount(screen, view.snap, view.alerts, events) - 1)),
    account,
    accountSource,
    alerts: view.alerts,
    alertSource: alertSource(view.snap),
    events,
    settings: { url: source.url, refreshMs, color: theme.color },
  };
  const worst = worstUnacknowledged(view.alerts);
  const replayLine = past ? `REPLAY ${new Date(past.snap.at).toISOString().slice(11, 19)} UTC, ${replay! + 1} of ${history.current.length}: what the console saw then. ] steps forward to now.` : null;
  // Every tab in full when the row fits; otherwise the others are cut to four letters.
  const fullTabs = SCREENS.reduce((n, s) => n + s.title.length + 6, 0) <= columns;
  const tabTitle = (s: (typeof SCREENS)[number]) => (fullTabs || s.id === screen ? s.title : s.title.slice(0, 4));
  const updated = snap.at ? `updated ${ageText(now - snap.at)}` : "waiting";
  const footer = runbook !== null ? "Up/Down step  Esc close" : stopping !== null ? (stopping.phase === "confirm" ? "Enter confirm  Esc leave" : stopping.phase === "working" || stopping.phase === "asking" ? "working..." : "Esc or Enter close") : palette !== null ? "Type to filter  Up/Down move  Enter choose  Esc close" : acking !== null ? "Enter acknowledge  Esc cancel" : editing !== null ? "Enter confirm  Esc cancel  empty Enter = node payee" : help ? "Esc close help  q quit" : BINDINGS.filter((b) => b.hint).map((b) => b.hint).join("  ");

  let body: React.ReactNode;
  if (help) body = <HelpView />;
  else if (runbook !== null) {
    const book = runbooks(view.snap, view.alerts).find((b) => b.id === runbook.id)!;
    const cur = book.steps[Math.min(runbook.index, book.steps.length - 1)]!;
    body = (
      <Box flexDirection="column">
        <Heading>{`Runbook: ${book.title}`}</Heading>
        <Muted>The console runs none of these steps. It shows what to do and what it can read.</Muted>
        {book.steps.map((s, i) => (
          <Text key={s.id} inverse={s.id === cur.id} wrap="truncate-end">
            {`${s.id === cur.id ? "> " : "  "}${i + 1}. ${s.state.toUpperCase().padEnd(7)} ${s.title}${s.skippable ? " (may be skipped)" : ""}`}
          </Text>
        ))}
        <Box marginTop={1} flexDirection="column">
          <Text>{"Do:   " + cur.what}</Text>
          <Text>{"Why:  " + cur.why}</Text>
          {cur.caution ? <Word tone="warn">{"Care: " + cur.caution}</Word> : null}
          <Muted>{"Needs: " + (cur.gate === "free" ? "nothing special" : cur.gate === "passkey" ? "the operator's passkey" : "the machine's own permissions")}</Muted>
          {cur.result ? <Muted>{"Seen: " + cur.result}</Muted> : null}
        </Box>
      </Box>
    );
  } else if (stopping !== null) {
    body = (
      <Box flexDirection="column">
        <Heading>Planned stop of this node</Heading>
        {stopping.checks.map((c) => (
          <Text key={c.id} wrap="truncate-end">
            <Word tone={c.ok ? "ok" : "bad"}>{c.ok ? "ok" : "NO"}</Word>
            {"  " + c.text}
          </Text>
        ))}
        <Box marginTop={1} flexDirection="column">
          {stopping.phase === "asking" ? <Muted>Asking other operators how the network looks to them...</Muted> : null}
          {stopping.phase === "blocked" ? <Word tone="bad">The stop is blocked until every line above says ok. Nothing was stopped.</Word> : null}
          {stopping.phase === "confirm" ? (
            <>
              <Text>{stopConsequence(snap)}</Text>
              <Muted>Validators are counted as registered Active, not as up right now, and without their stake:</Muted>
              <Muted>the spare over quorum may be smaller than the line above says.</Muted>
              <TypedConfirm word={STOP_WORD} typed={stopping.typed} error={stopping.error} />
            </>
          ) : null}
          {stopping.phase === "working" ? <Muted>Asking the helper to stop the node...</Muted> : null}
          {stopping.phase === "done" ? <Text>{stopping.result}</Text> : null}
        </Box>
      </Box>
    );
  } else if (palette !== null) {
    const found = paletteMatches(palette.text);
    const at = Math.min(palette.index, Math.max(0, found.length - 1));
    const room = Math.max(1, bodyHeight - 3);
    const first = Math.min(Math.max(0, at - room + 1), Math.max(0, found.length - room));
    body = (
      <Box flexDirection="column">
        <Heading>Find a screen or an action</Heading>
        <Text>
          {"> "}
          {palette.text}
          <Text inverse> </Text>
        </Text>
        {found.length === 0 ? <Muted>Nothing matches.</Muted> : null}
        {found.slice(first, first + room).map((b, i) => (
          <Text key={b.action} inverse={first + i === at} wrap="truncate-end">
            {(first + i === at ? "> " : "  ") + b.label}
          </Text>
        ))}
      </Box>
    );
  } else if (acking !== null) {
    body = (
      <Box flexDirection="column">
        <Heading>Acknowledge an alert</Heading>
        <Text wrap="truncate-end">{acking.title}</Text>
        <Text>
          {"> "}
          {acking.text}
          <Text inverse> </Text>
        </Text>
        {ackError ? <Word tone="bad">{ackError}</Word> : <Muted>Type why this is known and accepted, then press Enter. It stays open until it clears.</Muted>}
      </Box>
    );
  } else if (editing !== null) {
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
    const Screen = { overview: Overview, wallet: Wallet, models: Models, validators: Validators, governance: Governance, health: Health, peers: Peers, logs: Logs, settings: Settings }[screen];
    body = <Screen {...props} />;
  }

  return (
    <ThemeContext.Provider value={theme}>
      <StaleAfterContext.Provider value={3 * refreshMs}>
      <Box flexDirection="column" width={columns} height={rows}>
        <Box>
          <Text bold color={theme.accent}>
            TENZRO
          </Text>
          <Text> </Text>
          <Muted>{source.url}</Muted>
          <Box flexGrow={1} />
          {past ? (
            <Box marginRight={2}>
              <Text bold inverse>{" REPLAY "}</Text>
            </Box>
          ) : null}
          {banner ? (
            <Box marginRight={2}>
              <Text bold inverse>{` ${banner} `}</Text>
            </Box>
          ) : null}
          {worst ? (
            <Box marginRight={2}>
              <Word tone={worst === "page" ? "bad" : worst === "warn" ? "warn" : "plain"}>{`${view.alerts.filter((a) => !a.ack).length} TO SEE`}</Word>
            </Box>
          ) : null}
          <Word tone={TONE[h.word] ?? "plain"}>{h.word}</Word>
        </Box>
        <Box>
          {SCREENS.map((s) => (
            <Box key={s.id} marginRight={fullTabs ? 2 : 0}>
              {s.id === screen ? (
                <Text bold inverse color={theme.accent}>{` ${s.key} ${tabTitle(s)} `}</Text>
              ) : (
                <Text>{` ${s.key} ${tabTitle(s)} `}</Text>
              )}
            </Box>
          ))}
        </Box>
        <Text color={theme.muted} wrap="truncate-end">{replayLine ? fitReason(replayLine, columns) : h.word === "OK" ? "─".repeat(columns) : fitReason(h.reason, columns)}</Text>
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
      </StaleAfterContext.Provider>
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
      <Box>
        <Box width={18} flexShrink={0}>
          <Text bold>{`${SCREENS[0].key} to ${SCREENS[SCREENS.length - 1]!.key}`}</Text>
        </Box>
        <Text>Go to a screen; the row at the top names them</Text>
      </Box>
      {BINDINGS.filter((b) => b.keys.length > 0 && !b.action.startsWith("screen:")).map((b) => (
        <Box key={b.action}>
          <Box width={18} flexShrink={0}>
            <Text bold>{b.keys.join(" or ")}</Text>
          </Box>
          <Text>{b.label}</Text>
        </Box>
      ))}
      <Box flexDirection="column">
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
