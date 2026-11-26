#!/usr/bin/env python3
"""Accepted advisories stay answered for: every id in the `ignore` list of a cargo-audit
configuration carries, in the comment above it, an owner and a recheck day that has not passed.

    acceptance-recheck.py [--today YYYY-MM-DD] <audit.toml>

    # OWNER: <role>. RECHECK BY: YYYY-MM-DD.

Exit 0 when every acceptance is current, 1 otherwise (one line per entry at fault).
"""
import datetime
import re
import sys
import tomllib

ENTRY = re.compile(r'^\s*"([^"]+)"\s*,?\s*$')
OWNER = re.compile(r"OWNER:[ \t]*(.*?)[ \t.]*(?:RECHECK BY:|$)", re.M)
RECHECK = re.compile(r"RECHECK BY:\s*(\S+?)\.?(?:\s|$)")


def acceptances(text):
    """(id, comment above it) for each entry of the ignore list written alone on its line."""
    inside, comment = False, []
    for line in text.splitlines():
        if not inside:
            inside = re.match(r"^\s*ignore\s*=\s*\[\s*$", line) is not None
            continue
        if line.strip() == "]":
            return
        m = ENTRY.match(line)
        if m:
            yield m.group(1), "\n".join(comment)
            comment = []
        elif line.strip().startswith("#"):
            comment.append(line)


def faults(text, today):
    out = []
    # The list cargo-audit reads is the measure: an id written in a form the
    # comment reader does not follow would otherwise pass with nothing above it.
    listed = tomllib.loads(text).get("advisories", {}).get("ignore", [])
    read = [adv for adv, _ in acceptances(text)]
    for adv in listed:
        if listed.count(adv) != read.count(adv):
            out.append(f"{adv}: not written alone on its line under its own comment")
    for adv, comment in acceptances(text):
        owner, recheck = OWNER.search(comment), RECHECK.search(comment)
        if not owner or not owner.group(1):
            out.append(f"{adv}: no OWNER")
        if not recheck:
            out.append(f"{adv}: no RECHECK BY day")
            continue
        try:
            day = datetime.date.fromisoformat(recheck.group(1))
        except ValueError:
            out.append(f"{adv}: RECHECK BY {recheck.group(1)} is not a day (YYYY-MM-DD)")
            continue
        if day < today:
            out.append(f"{adv}: recheck was due {day}; assess it again and set a new day")
    return out


def main(argv):
    today = datetime.datetime.now(datetime.timezone.utc).date()
    if argv[:1] == ["--today"]:
        today, argv = datetime.date.fromisoformat(argv[1]), argv[2:]
    if len(argv) != 1:
        print(__doc__)
        return 2
    with open(argv[0], encoding="utf-8") as f:
        found = faults(f.read(), today)
    for line in found:
        print(f"BLOCKED: accepted advisory {line}")
    if found:
        print(f"acceptance recheck FAILED for {argv[0]}: {len(found)} fault(s)")
        return 1
    print(f"acceptance recheck passed for {argv[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
