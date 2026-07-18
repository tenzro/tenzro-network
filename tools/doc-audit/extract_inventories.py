#!/usr/bin/env python3
"""Extract canonical inventories from codebase vs. claimed-by-docs.

Run from repo root:
    python3 tools/doc-audit/extract_inventories.py

Emits:
    tools/doc-audit/codebase-inventory.json
    tools/doc-audit/docs-claims.json
    tools/doc-audit/DRIFT_REPORT.md
"""
import re
import json
import pathlib
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "tools" / "doc-audit"
OUT.mkdir(parents=True, exist_ok=True)

# ─── 1. Codebase inventory ──────────────────────────────────────────────────

inv = {}

# JSON-RPC methods: dispatcher arms in rpc.rs, including multi-alias arms
# like `"a" | "b" => handler(...)`.
rpc_src = (ROOT / "crates/tenzro-node/src/rpc.rs").read_text()
rpc_methods = set()
quoted = re.compile(r'"((?:tenzro|eth|net|web3)_[a-zA-Z0-9_]+)"')
for line in rpc_src.splitlines():
    if "=>" not in line:
        continue
    head = line.split("=>", 1)[0]
    for m in quoted.findall(head):
        rpc_methods.add(m)
inv["rpc_methods"] = sorted(rpc_methods)

# MCP tools: rmcp #[tool(description = "...")] then pub async fn NAME(
mcp_tools = set()
for f in (ROOT / "crates/tenzro-node/src/mcp").rglob("*.rs"):
    text = f.read_text()
    pat = re.compile(
        r'#\[tool\(description[^)]*\)\]\s*(?:pub\s+)?async\s+fn\s+([a-z][a-z0-9_]+)\s*\(',
        re.S,
    )
    mcp_tools.update(pat.findall(text))
inv["mcp_tools"] = sorted(mcp_tools)

# CLI: command modules under commands/
cli_mod = (ROOT / "crates/tenzro-cli/src/commands/mod.rs").read_text()
inv["cli_command_modules"] = sorted(
    re.findall(r'^pub mod\s+([a-z][a-z0-9_]*)\s*;', cli_mod, re.M)
)

# Gossipsub topics: "tenzro/X" string literals (filter trailing-segment-too-long)
gossip = set()
for f in (ROOT / "crates").rglob("*.rs"):
    text = f.read_text(errors="ignore")
    for m in re.finditer(r'"(tenzro/[a-z][a-z0-9/_-]+)"', text):
        t = m.group(1)
        if t.count("/") <= 3:
            gossip.add(t)
inv["gossip_topics"] = sorted(gossip)

(OUT / "codebase-inventory.json").write_text(json.dumps(inv, indent=2))
print(f"codebase inventory: {len(inv['rpc_methods'])} rpc, "
      f"{len(inv['mcp_tools'])} mcp, "
      f"{len(inv['cli_command_modules'])} cli, "
      f"{len(inv['gossip_topics'])} topics")

# ─── 2. Docs claims ─────────────────────────────────────────────────────────

claims = {
    "rpc_methods": defaultdict(list),
    "gossip_topics": defaultdict(list),
    "cli_commands": defaultdict(list),
    "urls": defaultdict(list),
}

rpc_p = re.compile(r'\b((?:tenzro|eth|net|web3)_[a-zA-Z][a-zA-Z0-9_]+)\b')
gossip_p = re.compile(r'\btenzro/[a-z][a-z0-9/_-]+\b')
cli_p = re.compile(r'\btenzro(?:-cli)?\s+([a-z][a-z0-9-]{1,30})\b')
url_p = re.compile(r'\bhttps?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._?%&=/+-]*)?')

dirs = [
    ROOT / "website/src/app/docs",
    ROOT / "website/src/app/tutorials",
    pathlib.Path("/Users/hilarl/Documents/tenzro-github/tenzro-cookbook"),
]
EXTS = {".md", ".mdx", ".tsx", ".ts", ".js", ".jsx"}

def relkey(path: pathlib.Path) -> str:
    s = str(path)
    for prefix, tag in [
        ("/website/src/app/docs/", "docs:"),
        ("/website/src/app/tutorials/", "tutorials:"),
        ("/tenzro-cookbook/", "cookbook:"),
    ]:
        if prefix in s:
            return tag + s.split(prefix, 1)[1]
    return s

for root in dirs:
    if not root.exists():
        print(f"missing: {root}")
        continue
    for f in root.rglob("*"):
        if not f.is_file() or f.suffix not in EXTS:
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        key = relkey(f)
        for m in rpc_p.findall(text):
            claims["rpc_methods"][m].append(key)
        for m in gossip_p.findall(text):
            claims["gossip_topics"][m].append(key)
        for m in cli_p.findall(text):
            claims["cli_commands"][m].append(key)
        for m in url_p.findall(text):
            if "tenzro" in m:
                claims["urls"][m].append(key)

out_claims = {cat: {k: sorted(set(v)) for k, v in d.items()} for cat, d in claims.items()}
(OUT / "docs-claims.json").write_text(json.dumps(out_claims, indent=2))
print(f"docs claims: {sum(len(v) for v in claims.values())} total mentions")

# ─── 3. Drift report ────────────────────────────────────────────────────────
# (Report-generation logic lives separately; this script is the data prep.)
print(f"\nNow regenerate the drift report manually from the two JSON files,")
print(f"or extend this script with a __main__ that calls the report writer.")
