#!/usr/bin/env python3
"""Every binary that links rustls installs aws-lc-rs as its process TLS provider.

rustls picks the process-wide provider on first use when none is installed, and a dependency can
compile in the ring provider beside aws-lc-rs (iroh-relay's `server` feature, ureq's `_ring`).
A binary that installs nothing then leaves the choice to whichever crate builds the first TLS
config, and only aws-lc-rs offers the X25519MLKEM768 hybrid key exchange. So every binary target
of a workspace member whose normal dependencies reach rustls must install
`rustls::crypto::aws_lc_rs::default_provider()` in its own source. Every tracked Cargo.toml with
a [workspace] table is a workspace checked on its own, so a standalone one is covered too, and a
workspace without a committed Cargo.lock fails: its dependency set is not locked.

    scripts/supply-chain/check_tls_provider.py

Exit 0 when every such binary installs it, 1 otherwise (each binary that does not is named).
"""
import json
import os
import re
import subprocess
import sys

INSTALL = "aws_lc_rs::default_provider()"


def reaches_rustls(metadata, package_id):
    """Whether `package_id` reaches rustls through normal (not dev or build) dependencies."""
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    names = {p["id"]: p["name"] for p in metadata["packages"]}
    seen, todo = set(), [package_id]
    while todo:
        pid = todo.pop()
        if pid in seen:
            continue
        seen.add(pid)
        if names.get(pid) == "rustls":
            return True
        for dep in nodes.get(pid, {}).get("deps", []):
            if any(k.get("kind") is None for k in dep.get("dep_kinds", [])):
                todo.append(dep["pkg"])
    return False


def missing(metadata, read=lambda path: open(path, encoding="utf-8").read()):
    """The binaries (package, target, source) that link rustls and do not install aws-lc-rs."""
    members = set(metadata["workspace_members"])
    out = []
    for p in metadata["packages"]:
        if p["id"] not in members:
            continue
        bins = [t for t in p["targets"] if "bin" in t["kind"]]
        if bins and reaches_rustls(metadata, p["id"]):
            for t in bins:
                source = read(t["src_path"])
                if INSTALL not in source or ".install_default()" not in source:
                    out.append((p["name"], t["name"], t["src_path"]))
    return out


def workspaces(manifests, read=lambda path: open(path, encoding="utf-8").read()):
    """The manifests among `manifests` that hold a [workspace] table, vendored crates aside."""
    return [
        m
        for m in manifests
        if not m.startswith("vendor/") and re.search(r"^\[workspace\]", read(m), re.M)
    ]


def main():
    tracked = subprocess.run(
        ["git", "ls-files", "Cargo.toml", "*/Cargo.toml"], capture_output=True, text=True
    ).stdout.split()
    fail = 0
    for manifest in workspaces(tracked):
        if not os.path.exists(os.path.join(os.path.dirname(manifest), "Cargo.lock")):
            print(f"{manifest}: no committed Cargo.lock, so its dependencies are not locked")
            fail = 1
            continue
        run = subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", manifest],
            capture_output=True,
            text=True,
        )
        if run.returncode != 0:
            print(f"cargo metadata failed for {manifest}: {run.stderr.strip()}")
            fail = 1
            continue
        for package, target, path in missing(json.loads(run.stdout)):
            print(
                f"binary {target} ({package}, {path}) links rustls "
                "and does not install aws-lc-rs"
            )
            fail = 1
    return fail


if __name__ == "__main__":
    sys.exit(main())
