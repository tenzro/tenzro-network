#!/usr/bin/env python3
"""
Performance hard-threshold gate for criterion benchmarks.

Walks target/criterion/<group>/<bench>/new/estimates.json after a
cargo bench run, looks up each bench id in thresholds.toml, and exits
non-zero if any bench breaches its hard floor / ceiling.

Usage:
  cargo bench --workspace --exclude tenzro-desktop
  python3 tools/bench-gate/gate.py
"""

from __future__ import annotations
import json
import os
import sys
import tomllib  # 3.11+
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRITERION_ROOT = ROOT / "target" / "criterion"
THRESHOLDS = ROOT / "tools" / "bench-gate" / "thresholds.toml"


def load_thresholds() -> list[dict]:
    with THRESHOLDS.open("rb") as f:
        data = tomllib.load(f)
    return data.get("bench", [])


def read_estimate(group_bench: str) -> dict | None:
    """Returns the parsed estimates.json for a `<group>/<bench>` id, or None."""
    parts = group_bench.split("/")
    if len(parts) != 2:
        return None
    path = CRITERION_ROOT / parts[0] / parts[1] / "new" / "estimates.json"
    if not path.exists():
        return None
    with path.open() as f:
        return json.load(f)


def main() -> int:
    if not CRITERION_ROOT.exists():
        print(
            f"::warning::No criterion output at {CRITERION_ROOT} — "
            "did `cargo bench` run before this gate?"
        )
        return 0

    thresholds = load_thresholds()
    failures: list[str] = []
    misses: list[str] = []

    for t in thresholds:
        est = read_estimate(t["id"])
        if est is None:
            misses.append(t["id"])
            continue
        if t["metric"] == "mean_ns":
            measured = est["mean"]["point_estimate"]
            cap = t["max_ns"]
            if measured > cap:
                failures.append(
                    f"{t['id']}: {measured:.0f} ns > cap {cap} ns "
                    f"(ref: {t['reference']})"
                )
            else:
                print(
                    f"PASS {t['id']}: {measured:.0f} ns ≤ {cap} ns"
                )
        elif t["metric"] == "ops_per_sec":
            # criterion's mean is ns per iter; ops/sec = 1e9 / mean
            measured = 1_000_000_000.0 / est["mean"]["point_estimate"]
            floor = t["min_ops_per_sec"]
            if measured < floor:
                failures.append(
                    f"{t['id']}: {measured:.0f} ops/s < floor {floor} "
                    f"(ref: {t['reference']})"
                )
            else:
                print(
                    f"PASS {t['id']}: {measured:.0f} ops/s ≥ {floor}"
                )

    if misses:
        print(
            f"::warning::{len(misses)} threshold(s) had no matching "
            f"criterion output (bench may not exist yet):"
        )
        for m in misses:
            print(f"  miss: {m}")

    if failures:
        print(f"\n::error::{len(failures)} bench(es) breached performance thresholds:")
        for f in failures:
            print(f"  FAIL {f}")
        return 1

    print(
        f"\nAll {len(thresholds) - len(misses)} measured bench(es) "
        f"within performance thresholds."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
