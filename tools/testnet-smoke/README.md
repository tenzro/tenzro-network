# Testnet smoke + integration battery

Tooling for validating the live Tenzro testnet against the deployed image.
Three concurrent surfaces:

- **`consensus_monitor.sh`** — continuous health monitor. Polls every
  validator's local RPC every 10 s, parses the most recent TC / NEC
  formations from logs, writes TSV. Emits a stall-detected line if the
  public RPC tip stays static for ≥ 60 s.
- **`smoke.sh`** — one-shot pass / fail / skip battery across the public
  RPC, web verification API, MCP, A2A, faucet, identity, token registry,
  bridge router, Canton read surface, multi-modal AI catalogs, and
  settlement primitives. Returns non-zero on any FAIL.
- **`soak.sh`** — sustained-load runner. N workers each fire a mix of
  RPC + catalog + web + MCP calls at a configurable rate for a
  configurable window. Records latency + status to TSV.

## Quick start

```bash
# Continuous monitor (background)
nohup ./consensus_monitor.sh /tmp/tenzro-consensus.tsv > /tmp/tenzro-monitor.log 2>&1 &

# One-shot smoke (foreground)
./smoke.sh

# Soak — 2 h, 3 workers @ 1 op/sec each
DURATION_SECS=7200 CONCURRENCY=3 OPS_PER_SEC_PER_WORKER=1 ./soak.sh
```

All three accept env-var overrides for endpoints (`RPC`, `API`, `MCP`,
`A2A`, `CANTON_MCP`). Defaults target the public production endpoints.

## Auth model

`smoke.sh` and `soak.sh` exercise only public read surfaces. Canton-scoped
methods are SKIPped unless `X-Tenzro-Api-Key` is configured. Admin
operations require the operator admin token and are out of scope for
these tools.

## Output

- `smoke.sh` prints PASS / FAIL / SKIP per test, plus a summary line.
- `consensus_monitor.sh` writes a TSV with columns:
  `ts, validator, block_hex, block_dec, peers_hex, last_tc_view,
  tc_max_high_qc, tc_gap, nec_view, nec_signers`.
- `soak.sh` writes a TSV with columns:
  `ts, worker_id, op, latency_ms, status, bytes` and an errors log
  (`/tmp/tenzro-soak-errors.log`).

## Stop

`Ctrl+C` for foreground runs; `kill <pid>` for background. All three
trap SIGINT / SIGTERM and exit cleanly.
