import React from "react";
import { Box, Text } from "ink";
import type { Theme } from "./theme.js";
import { fit } from "./format.js";
import type { Reading } from "./data.js";
import { ageText } from "./format.js";

export const ThemeContext = React.createContext<Theme>({ color: false, accent: undefined, ok: undefined, warn: undefined, bad: undefined, muted: undefined });
export const useTheme = () => React.useContext(ThemeContext);

export function Muted({ children }: { children: React.ReactNode }) {
  const t = useTheme();
  return <Text color={t.muted}>{children}</Text>;
}

export function Heading({ children }: { children: React.ReactNode }) {
  const t = useTheme();
  return (
    <Text bold color={t.accent}>
      {children}
    </Text>
  );
}

export type Tone = "ok" | "warn" | "bad" | "plain";

/** A status is always its word; colour is the second channel. */
export function Word({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  const t = useTheme();
  const color = tone === "ok" ? t.ok : tone === "warn" ? t.warn : tone === "bad" ? t.bad : undefined;
  return (
    <Text bold color={color}>
      {children}
    </Text>
  );
}

export function Field({ label, children, width = 14 }: { label: string; children: React.ReactNode; width?: number }) {
  return (
    <Box>
      <Box width={width} flexShrink={0}>
        <Muted>{label}</Muted>
      </Box>
      <Box flexShrink={1}>
        <Text wrap="truncate-end">{children}</Text>
      </Box>
    </Box>
  );
}

/** Shows the value when the reading is fine, the reason when it is not, and says so when it is old. */
export function Show<T>({ r, children, now }: { r: Reading<T>; children: (v: T) => React.ReactNode; now: number }) {
  if (r.state === "pending") return <Muted>loading...</Muted>;
  if (r.state === "ok") return <>{children(r.value)}</>;
  if (r.last) {
    return (
      <Text>
        {children(r.last.value)} <Word tone="warn">STALE</Word> <Muted>{ageText(now - r.last.at)}</Muted>
      </Text>
    );
  }
  return <Word tone="bad">no data</Word>;
}

export interface Column<R> {
  title: string;
  width: number;
  /** Right-align numbers. */
  right?: boolean;
  get: (row: R) => string;
}

/**
 * A list with a header, one highlighted row and a scrolling window. The
 * highlighted row is marked with ">" and reverse video, so it reads without colour.
 */
export function Table<R>({ columns: wanted, rows, selected, height, empty, width }: { columns: Column<R>[]; rows: R[]; selected: number; height: number; empty: string; width: number }) {
  const t = useTheme();
  const columns = shrinkColumns(wanted, width);
  const body = Math.max(1, height - 2);
  const start = Math.min(Math.max(0, selected - Math.floor(body / 2)), Math.max(0, rows.length - body));
  const visible = rows.slice(start, start + body);
  const cell = (c: Column<R>, s: string) => (c.right ? fit(s, c.width).trim().padStart(c.width) : fit(s, c.width));
  return (
    <Box flexDirection="column">
      <Text bold color={t.accent}>
        {"  " + columns.map((c) => cell(c, c.title)).join(" ")}
      </Text>
      {rows.length === 0 ? (
        <Muted>{"  " + empty}</Muted>
      ) : (
        visible.map((r, i) => {
          const idx = start + i;
          const on = idx === selected;
          return (
            <Text key={idx} inverse={on} wrap="truncate-end">
              {(on ? "> " : "  ") + columns.map((c) => cell(c, c.get(r))).join(" ")}
            </Text>
          );
        })
      )}
      {rows.length > body ? <Muted>{`  ${start + 1}-${start + visible.length} of ${rows.length}`}</Muted> : null}
    </Box>
  );
}

/** Narrow the widest columns until the row fits the terminal: the gutter is 2 cells, the gap between columns 1. */
export function shrinkColumns<R>(cols: Column<R>[], width: number): Column<R>[] {
  const out = cols.map((c) => ({ ...c }));
  const total = () => out.reduce((n, c) => n + c.width, 0) + (out.length - 1) + 2;
  while (total() > width) {
    let wi = -1;
    for (let i = 0; i < out.length; i++) if (out[i]!.width > 8 && (wi < 0 || out[i]!.width > out[wi]!.width)) wi = i;
    if (wi < 0) break;
    out[wi]!.width -= 1;
  }
  return out;
}
