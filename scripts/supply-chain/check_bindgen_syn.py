#!/usr/bin/env python3
"""bindgen and prettyplease must agree on syn.

bindgen hands prettyplease a `syn::File` (bindgen's lib.rs, `prettyplease::unparse`), so both must
link the same major version of syn. bindgen 0.73 accepts syn ">=2, <4" and prettyplease ">=0.2.7,
<0.4", and prettyplease 0.2 is built on syn 2 while 0.3 is on syn 3; a lockfile re-resolve can give
bindgen syn 3 beside prettyplease 0.2 (or the reverse), and the native build then fails deep in a
build script. This checks every committed Cargo.lock for that mismatch before anything is built.

    scripts/supply-chain/check_bindgen_syn.py

Exit 0 when every bindgen agrees with its prettyplease on syn, 1 otherwise (the mismatch is named).
"""
import os
import subprocess
import sys
import tomllib

ROOT = subprocess.run(
    ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True
).stdout.strip() or os.getcwd()


def syn_major(packages, entry):
    """The syn major version the package `entry` ("name version") depends on, or None."""
    name, _, version = entry.partition(" ")
    for p in packages:
        if p["name"] == name and (not version or p["version"] == version):
            for d in p.get("dependencies", []):
                dn, _, dv = d.partition(" ")
                if dn == "syn":
                    if dv:
                        return dv.split(".")[0]
                    synd = [q["version"] for q in packages if q["name"] == "syn"]
                    return synd[0].split(".")[0] if len(synd) == 1 else None
    return None


def resolved(packages, dep):
    """`dep` as a lock dependency names it ("name" or "name version") made "name version"."""
    name, _, version = dep.partition(" ")
    if version:
        return dep
    found = [p["version"] for p in packages if p["name"] == name]
    return f"{name} {found[0]}" if len(found) == 1 else dep


def mismatches(lock_text):
    """Each (bindgen version, its syn major, its prettyplease, that prettyplease's syn major) that
    disagree."""
    packages = tomllib.loads(lock_text).get("package", [])
    out = []
    for p in packages:
        if p["name"] != "bindgen":
            continue
        pretty = [resolved(packages, d) for d in p.get("dependencies", []) if d.split(" ")[0] == "prettyplease"]
        if not pretty:
            continue
        own = syn_major(packages, f"bindgen {p['version']}")
        theirs = syn_major(packages, pretty[0])
        if own is None or theirs is None or own != theirs:
            out.append((p["version"], own, pretty[0], theirs))
    return out


def main():
    paths = subprocess.run(
        ["git", "-C", ROOT, "ls-files", "*Cargo.lock"], capture_output=True, text=True
    ).stdout.split()
    bad = 0
    for path in paths:
        with open(os.path.join(ROOT, path)) as f:
            for version, own, pretty, theirs in mismatches(f.read()):
                bad += 1
                print(
                    f"{path}: bindgen {version} is built on syn {own} but its {pretty} on syn "
                    f"{theirs}; resolve both to one syn (bindgen's syn 2 with prettyplease 0.2, or "
                    f"syn 3 with prettyplease 0.3)"
                )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
