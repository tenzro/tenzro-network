#!/usr/bin/env python3
"""One release, one version: the node, the CLI and every package built for this release state the release version.

usage: check-versions.py [ROOT]   (default: the repository this script is in)

The release version is the node's (crates/tenzro-node). The CLI, the Python packages and the npm packages
outside the SDK line must state it too. The other workspace crates keep the version of their own line: they are
libraries of the node, and tenzro-types and tenzro-finality in particular are compiled into the zkVM finality
guests, where cargo hashes a crate's version into the guest's symbols and the guest image id is pinned
(scripts/testnet/final/guest-digest.py --check says MATCH only while their manifests are untouched).
Exit 0 when they agree, 1 with one line per package that does not. Exempt, by name:
- the SDK line (Rust tenzro-sdk, npm tenzro-sdk and its @tenzro packages): published as 0.7.x before this
  release line began, and a registry version never goes backwards, so they keep a line of their own. They must
  still agree with each other.
The publish lists in run/publish.sh (NPM_ORDER, PYPI_ORDER) must name each in-tree package at its tree version.
"""
import glob
import json
import os
import re
import sys
import tomllib

SDK_LINE = {"tenzro-sdk", "@tenzro/core", "@tenzro/payments", "@tenzro/settlement", "@tenzro/bridge",
            "@tenzro/inference", "@tenzro/chain", "@tenzro/agents"}
RELEASE_CRATES = {"tenzro-node", "tenzro-cli"}  # the other crates keep their own line (see above)
# Operated services built from the SDK, with a workspace and a version line of their own; they are not published
# (publish.sh names them nowhere), so they need not state the release version.
OWN_LINE = {"tenzro-mailbox-service"}


def toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def packages(root):
    """(kind, name, version, path) for every released package in the tree."""
    out = []
    ws = toml(os.path.join(root, "Cargo.toml"))["workspace"]["package"]["version"]
    manifests = sorted(glob.glob(os.path.join(root, "crates/*/Cargo.toml")) + glob.glob(os.path.join(root, "sdk/*/Cargo.toml"))
                       + glob.glob(os.path.join(root, "sdk/*/native/Cargo.toml")))
    for m in manifests:
        p = toml(m).get("package", {})
        v = p.get("version")
        if isinstance(v, dict) and v.get("workspace"):
            v = ws
        out.append(("crate", p.get("name"), v, os.path.relpath(m, root)))
    for m in sorted(glob.glob(os.path.join(root, "sdk/**/pyproject.toml"), recursive=True)):
        p = toml(m).get("project", {})
        out.append(("python", p.get("name"), p.get("version"), os.path.relpath(m, root)))
    for m in sorted(glob.glob(os.path.join(root, "sdk/**/__init__.py"), recursive=True)):
        if "node_modules" in m:
            continue
        with open(m) as f:
            hit = re.search(r'^__version__ = "([^"]+)"', f.read(), re.M)
        if hit:
            out.append(("python", os.path.basename(os.path.dirname(m)) + ".__version__", hit.group(1), os.path.relpath(m, root)))
    for m in sorted(glob.glob(os.path.join(root, "sdk/**/package.json"), recursive=True)):
        if "node_modules" in m:
            continue
        with open(m) as f:
            p = json.load(f)
        out.append(("npm", p.get("name"), p.get("version"), os.path.relpath(m, root)))
    return ws, out


def order_entries(root):
    """(list, file stem, version) for each NPM_ORDER and PYPI_ORDER entry in run/publish.sh."""
    with open(os.path.join(root, "scripts/release/run/publish.sh")) as f:
        s = f.read()
    out = []
    for var, ext in (("NPM_ORDER", r"\.tgz"), ("PYPI_ORDER", "")):
        body = re.search(rf'^{var}="([^"]*)"', s, re.M).group(1)
        for e in body.split():
            m = re.fullmatch(rf"(.+)-(\d+\.\d+\.\d+){ext}", e)
            out.append((var, m.group(1), m.group(2)))
    return out


def check(root):
    ws, pkgs = packages(root)
    release = next(v for kind, name, v, _ in pkgs if kind == "crate" and name == "tenzro-node")
    bad = []
    sdk = {}
    for kind, name, v, path in pkgs:
        if name in SDK_LINE:
            sdk.setdefault(v, []).append(name)
        elif name in OWN_LINE:
            continue
        elif kind == "crate" and name not in RELEASE_CRATES and not path.startswith("sdk/"):
            continue
        elif v != release:
            bad.append(f"{path}: {kind} {name} is {v}, the release is {release}")
    if len(sdk) > 1:
        bad.append("the SDK line disagrees: " + "; ".join(f"{v}: {', '.join(sorted(n))}" for v, n in sorted(sdk.items())))
    # npm tarballs are named after the package without "@" and with "/" as "-"; wheels with "-" as "_".
    tree = {}
    for kind, name, v, _ in pkgs:
        if kind == "npm":
            tree[("NPM_ORDER", name.lstrip("@").replace("/", "-"))] = v
        elif kind == "python" and not name.endswith(".__version__"):
            tree[("PYPI_ORDER", name.replace("-", "_"))] = v
    for var, stem, v in order_entries(root):
        if (var, stem) in tree and tree[(var, stem)] != v:
            bad.append(f"scripts/release/run/publish.sh: {var} names {stem}-{v}, the tree has {tree[(var, stem)]}")
    return release, bad


def main(argv):
    root = argv[1] if len(argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    ws, bad = check(root)
    for line in bad:
        print(line)
    print(f"release {ws}: " + ("every package agrees" if not bad else f"{len(bad)} disagree"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
