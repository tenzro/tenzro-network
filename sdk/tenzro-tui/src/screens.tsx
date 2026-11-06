import React from "react";
import { Box, Text } from "ink";
import type { Reading, Snapshot } from "./data.js";
import { Field, Heading, Muted, Show, Table, Word, type Column } from "./ui.js";
import { formatDuration, formatTnzo, shortId } from "./format.js";

export interface ScreenProps {
  snap: Snapshot;
  now: number;
  width: number;
  height: number;
  selected: number;
  account: string | null;
  accountSource: "chosen" | "payee" | "none";
}

export function rowCount(screen: string, snap: Snapshot): number {
  switch (screen) {
    case "models":
      return snap.models.state === "ok" ? snap.models.value.length : snap.models.state === "error" && snap.models.last ? snap.models.last.value.length : 0;
    case "validators":
      return snap.validators.state === "ok" ? snap.validators.value.length : snap.validators.state === "error" && snap.validators.last ? snap.validators.last.value.length : 0;
    case "governance":
      return snap.proposals.state === "ok" ? snap.proposals.value.items.length : snap.proposals.state === "error" && snap.proposals.last ? snap.proposals.last.value.items.length : 0;
    default:
      return 0;
  }
}

function hasRows<T>(r: Reading<T>): boolean {
  return r.state === "ok" || (r.state === "error" && r.last !== undefined);
}

function roles(r: unknown): string {
  if (Array.isArray(r)) return r.map(String).join(", ") || "none";
  return r == null ? "none" : String(r);
}

export function Overview({ snap, now, width }: ScreenProps) {
  const wide = width >= 100;
  const idw = wide ? 40 : 26;
  const node = (
    <Box flexDirection="column" width={wide ? 46 : undefined}>
      <Heading>Node</Heading>
      <Field label="State">
        <Show r={snap.status} now={now}>{(s) => `${s.state}, ${s.health_status}`}</Show>
      </Field>
      <Field label="Version">
        <Show r={snap.health} now={now}>{(h) => h.version ?? "not reported"}</Show>
      </Field>
      <Field label="Uptime">
        <Show r={snap.status} now={now}>{(s) => formatDuration(s.uptime_secs)}</Show>
      </Field>
      <Field label="Roles">
        <Show r={snap.status} now={now}>{(s) => roles(s.roles)}</Show>
      </Field>
      <Field label="Disk">
        <Show r={snap.status} now={now}>
          {(s) => {
            const d = s.disk as { pressure?: string; used_pct?: number };
            return `${d.used_pct ?? "?"}% used, pressure ${d.pressure ?? "unknown"}`;
          }}
        </Show>
      </Field>
    </Box>
  );
  const chain = (
    <Box flexDirection="column">
      <Heading>Chain</Heading>
      <Field label="Chain id">
        <Show r={snap.chainId} now={now}>{(c) => String(c)}</Show>
      </Field>
      <Field label="Height">
        <Show r={snap.status} now={now}>{(s) => s.block_height.toLocaleString("en-US")}</Show>
      </Field>
      <Field label="Finalized">
        <Show r={snap.finalized} now={now}>{(f) => f.toLocaleString("en-US")}</Show>
      </Field>
      <Field label="Syncing">
        <Show r={snap.syncing} now={now}>{(v) => (v ? "yes, catching up" : "no, at the tip")}</Show>
      </Field>
      <Field label="Peers">
        <Show r={snap.status} now={now}>{(s) => String(s.peer_count)}</Show>
      </Field>
    </Box>
  );
  const identity = (
    <Box flexDirection="column">
      <Heading>Identity</Heading>
      <Field label="Machine">
        <Show r={snap.status} now={now}>{(s) => (s.machine_did ? shortId(s.machine_did, idw, 8) : "none")}</Show>
      </Field>
      <Field label="Operator">
        <Show r={snap.status} now={now}>{(s) => (s.operator_did ? shortId(s.operator_did, idw, 8) : "none set")}</Show>
      </Field>
      <Field label="Pays out to">
        <Show r={snap.status} now={now}>{(s) => (s.payee ? shortId(s.payee, 12, 8) : "none set")}</Show>
      </Field>
      <Field label="Iroh">
        <Show r={snap.status} now={now}>{(s) => (s.iroh_enabled ? `on, ${shortId(s.iroh_endpoint_id ?? "", 10, 6)}` : "off")}</Show>
      </Field>
    </Box>
  );
  return wide ? (
    <Box>
      <Box flexDirection="column" marginRight={4}>
        {node}
        <Box marginTop={1}>{identity}</Box>
      </Box>
      {chain}
    </Box>
  ) : (
    <Box flexDirection="column">
      {node}
      {chain}
      {identity}
    </Box>
  );
}

export function Wallet({ snap, now, account, accountSource }: ScreenProps) {
  if (!account) {
    return (
      <Box flexDirection="column">
        <Heading>Wallet</Heading>
        <Text>No account chosen.</Text>
        <Muted>Press e to type an account address, or start with --address 0x...</Muted>
      </Box>
    );
  }
  return (
    <Box flexDirection="column">
      <Heading>Wallet</Heading>
      <Field label="Account">
        <Text>{account}</Text>
      </Field>
      <Field label="Chosen by">
        <Text>{accountSource === "chosen" ? "you" : "this node's payee address"}</Text>
      </Field>
      <Field label="Balance">
        <Show r={snap.balance} now={now}>{(b) => <Text bold>{formatTnzo(b.wei)} TNZO</Text>}</Show>
      </Field>
      <Field label="Nonce">
        <Show r={snap.balance} now={now}>{(b) => (b.nonce === null ? "not reported" : String(b.nonce))}</Show>
      </Field>
      <Box marginTop={1} flexDirection="column">
        <Muted>This console only reads. Sending and signing stay in the CLI,</Muted>
        <Muted>where the key is held by this machine's hardware: tenzro wallet send</Muted>
      </Box>
    </Box>
  );
}

export function Models({ snap, now, selected, height, width }: ScreenProps) {
  const cols: Column<import("tenzro-sdk").LoadedModel>[] = [
    { title: "MODEL", width: 34, get: (m) => m.model_id },
    { title: "TYPE", width: 10, get: (m) => m.type },
    { title: "ENGINE", width: 12, get: (m) => m.engine ?? "-" },
    { title: "VISIBLE", width: 8, get: (m) => m.visibility },
    { title: "LOADED", width: 6, get: (m) => (m.loaded ? "yes" : "no") },
    { title: "SERVING", width: 7, get: (m) => (m.serving ? "yes" : "no") },
  ];
  const r = snap.models;
  const rows = r.state === "ok" ? r.value : r.state === "error" && r.last ? r.last.value : [];
  return (
    <Box flexDirection="column">
      <Heading>Models on this node</Heading>
      {r.state === "pending" ? <Muted>loading...</Muted> : null}
      {r.state === "error" ? (r.last ? <Show r={r} now={now}>{() => null}</Show> : <Word tone="bad">no data: {r.error}</Word>) : null}
      {hasRows(r) ? <Table columns={cols} rows={rows} width={width} selected={selected} height={height - 1} empty="No models here yet. Add one with: tenzro model pull <id>" /> : null}
    </Box>
  );
}

export function Validators({ snap, now, selected, height, width }: ScreenProps) {
  const cols: Column<import("tenzro-sdk").ValidatorRegistryEntry>[] = [
    { title: "ADDRESS", width: 24, get: (v) => shortId(v.address, 12, 8) },
    { title: "STATUS", width: 10, get: (v) => String(v.status) },
    { title: "SELF STAKE (TNZO)", width: 20, right: true, get: (v) => formatTnzo(v.self_stake, 2) },
    { title: "ACTIVE SINCE", width: 12, right: true, get: (v) => (v.activated_at_epoch === null ? "-" : `epoch ${v.activated_at_epoch}`) },
  ];
  const r = snap.validators;
  const rows = r.state === "ok" ? r.value : r.state === "error" && r.last ? r.last.value : [];
  return (
    <Box flexDirection="column">
      <Heading>Validators</Heading>
      {r.state === "pending" ? <Muted>loading...</Muted> : null}
      {r.state === "error" ? (r.last ? <Show r={r} now={now}>{() => null}</Show> : <Word tone="bad">no data: {r.error}</Word>) : null}
      {hasRows(r) ? <Table columns={cols} rows={rows} width={width} selected={selected} height={height - 3} empty="No validators are registered on this chain." /> : null}
      {rows[selected] ? <Muted>{"  full address: " + rows[selected]!.address}</Muted> : null}
    </Box>
  );
}

export function Governance({ snap, now, selected, height, width }: ScreenProps) {
  const cols: Column<import("tenzro-sdk").ProposalView>[] = [
    { title: "PROPOSAL", width: 14, get: (p) => shortId(p.proposal.id, 6, 6) },
    { title: "KIND", width: 20, get: (p) => p.kind },
    { title: "STATUS", width: 12, get: (p) => String(p.proposal.status) },
    { title: "TRACK", width: 10, get: (p) => String(p.proposal.track) },
    { title: "YES", width: 12, right: true, get: (p) => formatTnzo(p.tally.yes, 0) },
    { title: "NO", width: 12, right: true, get: (p) => formatTnzo(p.tally.no, 0) },
  ];
  const r = snap.proposals;
  const rows = r.state === "ok" ? r.value.items : r.state === "error" && r.last ? r.last.value.items : [];
  return (
    <Box flexDirection="column">
      <Heading>Governance proposals, newest first</Heading>
      {r.state === "pending" ? <Muted>loading...</Muted> : null}
      {r.state === "error" ? (r.last ? <Show r={r} now={now}>{() => null}</Show> : <Word tone="bad">no data: {r.error}</Word>) : null}
      {hasRows(r) ? <Table columns={cols} rows={rows} width={width} selected={selected} height={height - 1} empty="No proposals yet." /> : null}
    </Box>
  );
}
