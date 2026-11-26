#!/usr/bin/env python3
"""Minimum age of a new dependency version.

A compromised release of a dependency is usually found and withdrawn within days of its
publication. A lock file therefore takes a version only once it has been public for
`[new_versions] min_age_days` (supply-chain/policy.toml). This compares every committed lock
file (Cargo.lock, package-lock.json, pnpm-lock.yaml, go.sum) with the same file at a base
commit, asks the registry when each version that is new was published, and fails when one is
younger and is not listed under `[[new_versions.exception]]` with a reason (a security fix that
cannot wait).

    scripts/supply-chain/dependency_age.py --base <commit>

The minimum age is read from the policy at the base commit, so a change cannot lower it for
itself; exceptions and the git sources a Cargo package may come from are read from the change,
where they are reviewed with it (cargo-deny checks those sources against deny.toml too). The workflow runs
this script as the base commit has it.

Exit 0: every new version is old enough or excepted. 1: one is too young. 2: the check could not
run: a registry did not answer, the policy does not parse, a lock file is of a kind or format this
check does not read, a package comes from a source it cannot date, or a name or version is not
well formed. Nothing whose age is unknown is admitted.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

# The clone being checked: the one the check is run in, wherever the script itself was read from.
ROOT = subprocess.run(
    ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True
).stdout.strip() or os.getcwd()
POLICY = "supply-chain/policy.toml"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
NPM = "https://registry.npmjs.org/"

# Lock file kinds a committed tree may hold. Any other kind stops the check.
LOCK_KINDS = ("Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "go.sum")
OTHER_LOCKS = (
    "npm-shrinkwrap.json", "yarn.lock", "bun.lock", "bun.lockb", "poetry.lock", "uv.lock",
    "Pipfile.lock", "Gemfile.lock", "composer.lock", "Package.resolved", "gradle.lockfile",
)

SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
NAME = {
    "cargo": re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"),
    "npm": re.compile(r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]{0,213}$"),
    "go": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]*(/[A-Za-z0-9._~-]+)+$"),
}
VERSION = {
    "cargo": SEMVER,
    "npm": SEMVER,
    "go": re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+incompatible)?$"),
}


class CannotCheck(Exception):
    """The check cannot judge what it was given; nothing is admitted."""


def checked(ecosystem, name, version):
    """`(ecosystem, name, version)`, refused unless the name and version are well formed, so
    neither can reach another address at the registry."""
    if not NAME[ecosystem].match(name) or ".." in name or not VERSION[ecosystem].match(version):
        raise CannotCheck(f"{ecosystem} {name!r} {version!r} is not a well-formed name and version")
    return (ecosystem, name, version)


def cargo_versions(text, allowed_git):
    """The crates.io versions a Cargo.lock holds. A package from a git source the policy names is
    pinned by its commit and dated by no registry; a path package is code in this tree, reviewed
    as code. Any other source (another registry, an unlisted git host) stops the check."""
    found = set()
    for p in tomllib.loads(text).get("package", []):
        source = p.get("source")
        if source is None:
            continue
        if source == CRATES_IO:
            found.add(checked("cargo", p["name"], p["version"]))
        elif source.startswith("git+") and source[4:].split("?")[0].split("#")[0] in allowed_git:
            continue
        else:
            raise CannotCheck(f"cargo {p['name']} {p['version']} comes from {source}, a source the policy does not list")
    return found


def npm_versions(text):
    """The registry versions a package-lock.json (lockfileVersion 2 or 3) holds. Workspace
    packages of this tree are links or have no resolved address; every other package must be
    resolved from the npm registry."""
    lock = json.loads(text)
    if lock.get("lockfileVersion") not in (2, 3) or not isinstance(lock.get("packages"), dict):
        raise CannotCheck("a package-lock.json that is not lockfileVersion 2 or 3 with `packages`")
    found = set()
    for path, entry in lock["packages"].items():
        if path == "" or entry.get("link") or "node_modules/" not in path:
            continue
        resolved = entry.get("resolved", "")
        name = entry.get("name") or path.rsplit("node_modules/", 1)[1]
        if not resolved.startswith(NPM):
            raise CannotCheck(f"npm {name} {entry.get('version')} is resolved from {resolved or 'nowhere'}, not the npm registry")
        found.add(checked("npm", name, entry["version"]))
    return found


def pnpm_versions(text):
    """The registry versions a pnpm-lock.yaml (lockfileVersion 9) holds: each `packages` entry,
    `name@version`, whose resolution is an integrity hash only (a tarball, git or directory
    resolution is not from the registry and stops the check)."""
    if not re.search(r"^lockfileVersion: '9\.\d+'$", text, re.M):
        raise CannotCheck("a pnpm-lock.yaml that is not lockfileVersion 9")
    found, section, key = set(), None, None
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section, key = line.rstrip(":"), None
            continue
        if section != "packages":
            continue
        m = re.match(r"^  '?([^' ]+?)'?:$", line)
        if m:
            key = m.group(1)
            continue
        m = re.match(r"^    resolution: \{(.*)\}$", line)
        if m and key:
            name, _, version = key.rpartition("@")
            if not re.fullmatch(r"integrity: [A-Za-z0-9+/=-]+", m.group(1).strip()):
                raise CannotCheck(f"npm {key} is resolved by {m.group(1)}, not from the registry")
            found.add(checked("npm", name, version))
    return found


def go_versions(text):
    """The module versions a go.sum holds."""
    found = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3:
            raise CannotCheck(f"a go.sum line that is not `module version hash`: {line!r}")
        found.add(checked("go", parts[0], parts[1].removesuffix("/go.mod")))
    return found


def parse(path, text, allowed_git):
    kind = os.path.basename(path)
    if kind == "Cargo.lock":
        return cargo_versions(text, allowed_git)
    if kind == "package-lock.json":
        return npm_versions(text)
    if kind == "pnpm-lock.yaml":
        return pnpm_versions(text)
    return go_versions(text)


def new_versions(lockfiles, allowed_git):
    """(ecosystem, name, version) for every version a lock file holds now and did not at the
    base. `lockfiles` yields (path, text now, text at the base or None when the file is new)."""
    new = set()
    for path, now, base in lockfiles:
        before = parse(path, base, allowed_git) if base is not None else set()
        new |= parse(path, now, allowed_git) - before
    return sorted(new)


def load_policy(base_text, change_text):
    """The minimum age, from the policy at the base commit; the allowed git sources and the
    excepted versions, from the change. Only the change that introduces the rule, whose base
    has no `[new_versions]`, is held to its own minimum age."""
    change = tomllib.loads(change_text)
    days = tomllib.loads(base_text).get("new_versions", change["new_versions"])["min_age_days"]
    if not isinstance(days, int) or days < 0:
        raise CannotCheck("[new_versions] min_age_days is not a whole number of days")
    excepted = set()
    for e in change["new_versions"].get("exception", []):
        if e.get("ecosystem") not in NAME or not str(e.get("reason", "")).strip():
            raise CannotCheck(f"[[new_versions.exception]] {e} needs an ecosystem ({', '.join(NAME)}) and a reason")
        excepted.add(checked(e["ecosystem"], e["name"], e["version"]))
    return days, set(change["sources"]["git"]), excepted


def too_young(new, published, now, min_age_days, excepted):
    """The (ecosystem, name, version, age in days) of each new version below the minimum age.
    `published(ecosystem, name, version)` returns when the registry published it."""
    young = []
    for item in new:
        if item in excepted:
            continue
        age = (now - published(*item)).days
        if age < min_age_days:
            young.append((*item, age))
    return young


def fetch(url, attempts=5, pause=2.0, sleep=time.sleep, opener=urllib.request.urlopen):
    """JSON from `url`, asked again after a growing pause when the registry limits requests or
    fails; after `attempts` the error stands."""
    request = urllib.request.Request(url, headers={"User-Agent": "tenzro-dependency-age-check"})
    for attempt in range(1, attempts + 1):
        try:
            with opener(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == attempts:
                raise
            wait = float(e.headers.get("Retry-After") or pause * 2 ** (attempt - 1))
        except (urllib.error.URLError, TimeoutError):
            if attempt == attempts:
                raise
            wait = pause * 2 ** (attempt - 1)
        sleep(min(wait, 60.0))


def go_escape(path):
    """A module path as the module proxy addresses it: each capital letter as `!` and its
    lower case."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def registry_published(ecosystem, name, version):
    """When crates.io, the npm registry or the Go module proxy published `name` `version`."""
    checked(ecosystem, name, version)
    if ecosystem == "cargo":
        stamp = fetch(f"https://crates.io/api/v1/crates/{name}/{version}")["version"]["created_at"]
        # crates.io asks for at most one request a second.
        time.sleep(1.0)
    elif ecosystem == "npm":
        stamp = fetch(NPM + urllib.parse.quote(name, safe="@"))["time"][version]
    else:
        stamp = fetch(f"https://proxy.golang.org/{go_escape(name)}/@v/{go_escape(version)}.info")["Time"]
    return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def git(*args):
    return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True)


def committed_lockfiles(base):
    files = git("ls-files").stdout.split("\n")
    unread = [f for f in files if os.path.basename(f) in OTHER_LOCKS]
    if unread:
        raise CannotCheck(f"lock files of a kind this check does not read are committed: {', '.join(unread)}")
    for path in (f for f in files if os.path.basename(f) in LOCK_KINDS):
        with open(os.path.join(ROOT, path)) as f:
            now = f.read()
        at_base = git("show", f"{base}:{path}")
        yield path, now, at_base.stdout if at_base.returncode == 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True, help="the commit the lock files are compared with")
    args = parser.parse_args()
    if git("rev-parse", "--verify", "--quiet", f"{args.base}^{{commit}}").returncode != 0:
        print(f"COULD NOT RUN: {args.base} is not a commit in this clone")
        return 2
    try:
        base_policy = git("show", f"{args.base}:{POLICY}")
        if base_policy.returncode != 0:
            raise CannotCheck(f"{POLICY} is not in {args.base}")
        with open(os.path.join(ROOT, POLICY)) as f:
            min_age_days, allowed_git, excepted = load_policy(base_policy.stdout, f.read())
        new = new_versions(committed_lockfiles(args.base), allowed_git)
        now = datetime.datetime.now(datetime.timezone.utc)
        young = too_young(new, registry_published, now, min_age_days, excepted)
    except Exception as e:  # anything not judged is not admitted
        print(f"COULD NOT RUN: {type(e).__name__}: {e}")
        return 2
    print(f"{len(new)} new dependency version(s) since {args.base}; minimum age {min_age_days} day(s)")
    for ecosystem, name, version, age in young:
        print(f"TOO YOUNG: {ecosystem} {name} {version} was published {age} day(s) ago")
    if young:
        print("Wait, or list a security fix under [[new_versions.exception]] in supply-chain/policy.toml with its reason.")
        return 1
    print("RESULT: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
