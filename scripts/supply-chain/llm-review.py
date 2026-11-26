#!/usr/bin/env python3
"""Send files of this repository to a language model for review, under three rules the script
enforces itself, whatever the provider:

  exposure  Only what the repository's HEAD commit holds for a tracked path on the public
            allow-list (tools/sync/public-root.txt) may leave: the committed bytes are read from
            git, so an untracked file or an uncommitted edit never goes out. The text must be
            UTF-8 and pass the public scanner (tools/sync/scan-public.py) and this script's own
            stricter rules (private addresses, internal host names, password assignments). The
            instruction is scanned the same way. Any finding refuses the whole request before
            the provider is run. A request above the size cap is refused.
            What this guard is: the files are on the public allow-list and committed, so they
            are meant to be published; the shared scanner and the rules here are a second line
            behind that. After a credential's name (password, secret, token, api key, auth,
            credential and their spellings) and `=`, `:` or `=>`, a quoted string of six or
            more characters is refused wherever it stands, and so is any unquoted word of six
            or more characters that no other file of the committed tree uses (a real type or
            function name occurs elsewhere; a credential does not, however often its own file
            repeats it), and a number of eight or more digits. A name whose line ends at the
            separator is read with the value on the line or block below. A web token, a known
            credential prefix, `Authorization: Basic`, a password flag, a `password <value>`
            pair, a Dockerfile ENV or ARG with a credential's name, a value attached to -p
            after mysql or sshpass and the password of curl's user option are refused without
            a name and separator.
            What it is not: an unquoted value shorter than six characters passes, and so does
            a credential spelled exactly like a word another file of the tree uses. An unquoted
            value made only of short or known words, with spaces or hyphens between them,
            passes: `password: correct horse battery staple` is four words any tree has. It
            does not find a credential that nothing names.
            Refusal is the safe side, so harmless files are refused too (a quoted field name
            after `token =`, an address in a doc comment). The refusal names each file and
            line. To review such a file anyway, read the named lines yourself; if they hold
            nothing private, change the text and commit it, or leave the file out of the
            request. There is no flag that sends a refused file.
  spend     Every call is written to an append-only ledger BEFORE it is made, at its worst-case
            cost, under a lock. The cap counts every call at that worst case for good: what the
            provider reports afterwards is recorded beside it (reported_usd and the token counts)
            and never lowers it, since an adapter's counts are only its word. A call whose worst
            case would take the ledger past the configured cap is refused. There is no default
            cap; a ledger or a cap that cannot be read refuses every call.
  env       The provider command gets PATH and only the environment variables its config names
            in "env"; nothing else of the caller's environment reaches it.
  provider  The provider named on the command line is the one used. An unknown provider, or one
            that fails, ends the run: nothing falls back to another.

usage: llm-review.py --config FILE --provider NAME [--instruction TEXT] PATH [PATH ...]

The config file lives outside the repository:

    {"cap_usd": 10.0,
     "ledger": "/path/to/ledger.jsonl",
     "providers": {"NAME": {"command": ["/path/to/adapter", "..."],
                            "usd_per_mtok_in": 4.0, "usd_per_mtok_out": 20.0,
                            "max_output_tokens": 8000, "timeout_secs": 600,
                            "env": ["NAME_OF_A_VARIABLE_THE_ADAPTER_NEEDS"]}}}

A provider is a command the operator supplies. It reads one JSON request on stdin
({"instruction", "max_output_tokens", "files": [{"path", "text"}]}) and prints one JSON answer
({"text", "input_tokens", "output_tokens"}): input_tokens at most the request's size in bytes,
output_tokens at most max_output_tokens. The script knows no provider's API and holds no key.

Exit 0 with the review on stdout; 1 refused (exposure, cap, provider); 2 usage or config error.
"""
import argparse
import datetime
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import re
import subprocess
import sys
import unicodedata

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
DEFAULT_INSTRUCTION = "Review these files for defects. Name each finding with its file and line."
MAX_REQUEST_BYTES = 1 << 20
DEFAULT_TIMEOUT_SECS = 600

_SCANNERS = {}


def scanner(root):
    """The public scanner as the HEAD commit of `root` holds it: the rules that judge the text
    come from the same commit as the text, not from a working file someone may have edited."""
    if root not in _SCANNERS:
        source = git(root, "show", "HEAD:tools/sync/scan-public.py")
        if source.returncode != 0:
            raise Refused("the public scanner (tools/sync/scan-public.py) is not in the HEAD commit")
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader("scan_public", loader=None))
        exec(compile(source.stdout.decode("utf-8"), "HEAD:tools/sync/scan-public.py", "exec"), module.__dict__)
        _SCANNERS[root] = module
    return _SCANNERS[root]


# Stricter than the public scanner, which lets the tree's own documentation name private ranges:
# nothing that reads as a place or a credential of a private network leaves in a review request.
OWN_RULES = [
    ("private address", re.compile(
        r"(?<![\w.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))"
        r"\.\d{1,3}\.\d{1,3}(?![\w.])")),
    ("internal host name", re.compile(
        r"(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:internal|intranet|corp|lan|local|localdomain|home\.arpa)\b")),
]


class Refused(Exception):
    """The request must not be made."""


def git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True)


def public_paths(root):
    listed = git(root, "show", "HEAD:tools/sync/public-root.txt")
    if listed.returncode != 0:
        raise Refused("the public allow-list (tools/sync/public-root.txt) is not in the HEAD commit")
    lines = listed.stdout.decode("utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def is_public(rel, allowed):
    return any(rel == a or (a.endswith("/") and rel.startswith(a)) for a in allowed)


# A name that ends in a credential's word (`password`, `db_password`, `API_KEY`, `secrets`), then
# `=`, `:` or `=>`. Not `==` or the `::` of a path, and not a longer name such as `token_count`.
# The short words (`pass`, `pwd`, `auth`) count only as a whole part of a name: not `compass`.
CREDENTIAL_KEY = re.compile(
    r"(?i)(?:pass[_-]?word|passwd|passphrase|secrets?(?:[_-]?key)?|token|api[_-]?key|access[_-]?key|bearer"
    r"|private[_-]?key|credentials?|(?<![A-Za-z0-9])(?:pass|pwd|auth))[\"'`]?\s*(=>|=(?!=)|:(?!:))\s*")
PLACEHOLDERS = {"string", "str", "text", "value", "redacted", "secret", "token", "password", "number", "boolean",
                "bytes", "buffer", "uint8array", "none", "null", "true", "false", "undefined", "self"}
# Words every language here has, known without looking: the tree is asked about every other word.
BUILTIN = PLACEHOLDERS | {
    "option", "result", "return", "struct", "static", "unsafe", "extern", "export", "import", "lambda", "typeof",
    "bigint", "public", "private", "default", "function", "module", "println", "format", "assert", "unwrap",
    "expect", "to_string", "to_owned", "as_str", "as_ref", "is_some", "is_none", "is_empty", "map_err",
    "ok_or_else", "unwrap_or", "collect", "optional", "placeholder",
}
QUOTED = re.compile(r"[A-Za-z]{0,2}([\"'`])(.*?)\1")
TRIPLE = re.compile(r"(\"\"\"|''')(.*?)\1", re.S)
LIFETIME = re.compile(r"'[a-z_]\w*\b(?!')")
YAML_TAG = re.compile(r"!{1,2}[A-Za-z]+\s+")
WORD = re.compile(r"[A-Za-z0-9_]+")
URL = re.compile(r"https?://[^\s@]+$")
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))

# Credentials with no name and separator beside them.
VALUE_RULES = [
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{3,}")),
    ("credential prefix", re.compile(
        r"\b(?:gh[opsu]_|github_pat_|glpat-|xox[abprs]-|sk_test_|sk_live_|rk_live_)[A-Za-z0-9_-]{8,}")),
    ("basic authorization", re.compile(r"(?i)\bauthorization\b[\"']?\s*[:=]\s*[\"']?basic\s+[A-Za-z0-9+/=_-]{8,}")),
]
# A value that follows a credential's word with only a space between: a flag, a .netrc line.
SPACED = re.compile(
    r"(?i)(?:(?<![\w-])(?:-p|--pass(?:word)?|--token|--secret)(?:\s+|=)|\b(?:password|passwd)[ \t]+"
    r"|^\s*(?:ENV|ARG)\s+\S*(?:pass|pwd|secret|token|key|credential|auth)\S*[ \t]+)(\S+)")
# A value that is a password by where it stands: attached to -p after a command that takes one
# so, or after the colon of curl's user option.
PLACED = [
    re.compile(r"\b(?:mysql|mysqldump|mysqladmin|sshpass)\b.*?\s-p([^\s-]\S*)"),
    re.compile(r"\bcurl\b.*?(?:\s-u|--user)[ =]+[\"']?[^\s:\"']+:([^\s\"']+)"),
]


def normalise(text):
    """`text` as the rules read it: one form for look-alike characters, no zero-width characters,
    one kind of line ending, and a string in triple quotes brought onto one line."""
    text = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    def one_line(m):
        inside = m.group(2)
        return '"' + inside.replace("\n", " ").replace('"', " ") + '"' + "\n" * inside.count("\n")

    return TRIPLE.sub(one_line, text)


def placeholder(value):
    v = value.strip().strip(",;")
    return (v.lower() in PLACEHOLDERS or (v.startswith("<") and v.endswith(">"))
            or (v.startswith("${") and v.endswith("}") and ":" not in v) or (v.startswith("{{") and v.endswith("}}"))
            or (v.startswith("$") and v[1:].replace("_", "").isalnum()) or v.startswith("$(")
            or (v.startswith("{") and v.endswith("}") and len(v) <= 8) or set(v) <= set("x*.") or not v)


class Known:
    """Whether a word is one the committed tree uses outside the file under review: a real
    type, function or variable name occurs in other files; a credential does not, however
    often its own file repeats it."""

    def __init__(self, root, path=None):
        self.root, self.path, self.files = root, path, {}

    def has(self, word):
        if word.lower() in BUILTIN:
            return True
        if word not in self.files:
            where = ["--", "."] + ([f":(exclude,top,literal){self.path}"] if self.path else [])
            out = git(self.root, "grep", "-I", "-w", "-F", "-l", "-e", word, "HEAD", *where).stdout
            self.files[word] = bool(out.strip())
        return self.files[word]

    def unknown(self, text):
        """The words of 6 or more characters in `text`, numbers aside, that no other file of
        the tree uses."""
        return [w for w in WORD.findall(text) if len(w) >= 6 and not w.isdigit() and not self.has(w)]


_KNOWN = {}


def known(root, path=None):
    """The words known for a review of `path` (None for text that is no file of the tree)."""
    if (root, path) not in _KNOWN:
        _KNOWN[root, path] = Known(root, path)
    return _KNOWN[root, path]


def value_written_out(tree, value):
    """Whether `value`, the text after a credential's name and its separator, holds something
    written out: a quoted string of 6 or more characters that is no placeholder, wherever it
    stands (an argument, a default, a list), or any unquoted word of 6 or more characters the
    tree does not use elsewhere. A shape proves nothing: `hunter2(x)` is as much a call as
    `parse(x)`."""
    value = LIFETIME.sub(" ", YAML_TAG.sub("", value, count=1))
    for m in QUOTED.finditer(value):
        inside = m.group(2)
        if len(inside) >= 6 and not placeholder(inside) and not URL.match(inside):
            return True
    bare = QUOTED.sub(" ", value)
    # A long number is a value too: a count is short, a numeric passcode or key is not.
    if any(w.isdigit() and len(w) >= 8 for w in WORD.findall(bare)):
        return True
    return bool(tree.unknown(bare))


def logical_lines(text):
    """(line number, line) with lines that end in a backslash joined to the next."""
    logical, start = "", 1
    for n, line in enumerate(text.split("\n"), 1):
        if not logical:
            start = n
        if line.endswith("\\"):
            logical += line[:-1]
            continue
        yield start, logical + line
        logical = ""
    if logical:
        yield start, logical


def with_values_from_below(lines):
    """`lines` with a credential's name that ends its line joined to its value below: the line
    after a JSON key, or the indented block under a YAML `|` or `>`."""
    lines, out, i = list(lines), [], 0
    while i < len(lines):
        n, line = lines[i]
        i += 1
        keys = list(CREDENTIAL_KEY.finditer(line))
        tail = line[keys[-1].end():].strip() if keys else None
        if tail in ("", "|", ">", "|-", ">-", "|+", ">+"):
            indent = len(line) - len(line.lstrip())
            line = line[:keys[-1].end()] if tail else line
            while i < len(lines):
                below = lines[i][1]
                if not below.strip():
                    i += 1
                    continue
                # A block runs while its lines are indented under the name; without a block
                # marker the value is the one line that follows.
                if tail and len(below) - len(below.lstrip()) <= indent:
                    break
                line += " " + below.strip()
                i += 1
                if not tail:
                    break
        out.append((n, line))
    return out


def credential_lines(root, text, path=None):
    """The line numbers where a credential's name, a password flag or a `password <value>` pair
    is followed by a value written out. `path` is the file the text is, when it is one."""
    tree, found = known(root, path), []
    for n, line in with_values_from_below(logical_lines(normalise(text))):
        named = any(value_written_out(tree, line[m.end():]) for m in CREDENTIAL_KEY.finditer(line))
        # A flag's value is often a path in quotes (`mkdir -p "$out/logs"`): it is judged by its
        # words alone.
        spaced = any(not placeholder(m.group(1).strip("\"'`")) and tree.unknown(m.group(1))
                     for m in SPACED.finditer(line))
        # Where the place alone says the value is a password, any value that is no placeholder.
        placed = any(not placeholder(m.group(1).strip("\"'`")) for rule in PLACED for m in rule.finditer(line))
        if named or spaced or placed:
            found.append(n)
    return found


def findings(root, label, text, path=None):
    """What stops `text` from leaving, as lines naming `label`. `path` is the file of the tree
    the text is, when it is one."""
    found = []
    scanner(root).scan_text(label, text, False, found)
    for name, rule in OWN_RULES:
        for m in rule.finditer(text):
            found.append(f"own    {label}:{text.count(chr(10), 0, m.start()) + 1}: {name}")
    clean = normalise(text)
    for name, rule in VALUE_RULES:
        for m in rule.finditer(clean):
            found.append(f"own    {label}:{clean.count(chr(10), 0, m.start()) + 1}: {name}")
    for n in credential_lines(root, text, path):
        found.append(f"own    {label}:{n}: password assignment")
    return found


def gather(paths, root):
    """[(repository path, committed text)] of files that may leave, or Refused naming every reason."""
    allowed = public_paths(root)
    files, reasons = [], []
    for path in paths:
        rel = os.path.relpath(os.path.abspath(path), root).replace(os.sep, "/")
        if rel.startswith("../") or rel == "..":
            reasons.append(f"{path}: not inside this repository")
            continue
        if not is_public(rel, allowed):
            reasons.append(f"{rel}: not on the public allow-list (tools/sync/public-root.txt)")
            continue
        # What the commit holds, not what the working tree holds: mode 100644 or 100755, a blob.
        entry = git(root, "ls-tree", "HEAD", "--", rel).stdout.decode("utf-8", "replace").split()
        if len(entry) < 3 or entry[0] not in ("100644", "100755") or entry[1] != "blob":
            reasons.append(f"{rel}: not a regular file in the HEAD commit (untracked, a link or a directory)")
            continue
        data = git(root, "cat-file", "blob", entry[2]).stdout
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            reasons.append(f"{rel}: not UTF-8 text")
            continue
        if "\0" in text:
            reasons.append(f"{rel}: a binary file")
            continue
        reasons.extend(findings(root, rel, text, rel))
        files.append((rel, text))
    if reasons:
        raise Refused("\n".join(reasons))
    return files


def number(value, what, least=0.0):
    """`value` as a finite number of at least `least`, or Refused."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < least:
        raise Refused(f"{what} must be a finite number of at least {least:g}, not {value!r}")
    return float(value)


def count(value, what, most, least=0):
    """`value` as a whole number from `least` to `most`, or ValueError."""
    if isinstance(value, bool) or not isinstance(value, int) or not least <= value <= most:
        raise ValueError(f"{what} {value!r} is not a whole number from {least} to {most}")
    return value


def spent(lines):
    """USD the ledger holds: each call counts once, at its latest entry. Refused on a line that
    cannot be read: a ledger that is not understood caps nothing."""
    calls = {}
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            usd = entry["usd"]
            if isinstance(usd, bool) or not isinstance(usd, (int, float)) or not math.isfinite(usd) or usd < 0:
                raise ValueError(usd)
            calls[str(entry["id"])] = float(usd)
        except (ValueError, KeyError, TypeError):
            raise Refused(f"ledger line {n} cannot be read; no call is made until the ledger is put right") from None
    return math.fsum(calls.values())


def append(handle, entry):
    handle.write(json.dumps(entry, sort_keys=True) + "\n")
    handle.flush()
    os.fsync(handle.fileno())


def cost(provider, input_tokens, output_tokens):
    return (input_tokens * provider["usd_per_mtok_in"] + output_tokens * provider["usd_per_mtok_out"]) / 1e6


def review(config, name, instruction, paths, root=ROOT):
    """The provider's review text. Raises Refused; every call made is in the ledger before it is made."""
    for key in ("cap_usd", "ledger", "providers"):
        if key not in config:
            raise Refused(f"the config names no {key}")
    cap = number(config["cap_usd"], "cap_usd")
    provider = config["providers"].get(name) if isinstance(config["providers"], dict) else None
    if provider is None:
        raise Refused(f"no provider named {name!r} in the config; nothing else is tried")
    for key in ("usd_per_mtok_in", "usd_per_mtok_out"):
        number(provider.get(key), f"{name}.{key}")
    try:
        allowance = count(provider.get("max_output_tokens"), "max_output_tokens", 10**7, least=1)
    except ValueError as e:
        raise Refused(f"{name}: {e}") from None
    timeout = number(provider.get("timeout_secs", DEFAULT_TIMEOUT_SECS), f"{name}.timeout_secs", 1.0)
    names = provider.get("env", [])
    if not isinstance(names, list) or not all(isinstance(n, str) and n for n in names):
        raise Refused(f"{name}.env must be a list of variable names")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.update({n: os.environ[n] for n in names if n in os.environ})
    reasons = findings(root, "the instruction", instruction)
    if reasons:
        raise Refused("\n".join(reasons))
    files = gather(paths, root)
    request = json.dumps({
        "instruction": instruction,
        "max_output_tokens": allowance,
        "files": [{"path": p, "text": t} for p, t in files],
    }).encode()
    if len(request) > MAX_REQUEST_BYTES:
        raise Refused(f"the request is {len(request)} bytes; at most {MAX_REQUEST_BYTES} leave in one call")
    # A token is at least one byte, so the request's size bounds its input tokens.
    worst = cost(provider, len(request), allowance)
    entry = {
        "id": hashlib.sha256(os.urandom(32)).hexdigest()[:24],
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "provider": name,
        "files": [p for p, _ in files],
        "request_sha256": hashlib.sha256(request).hexdigest(),
    }
    # The cap is checked and the call entered at its worst case under one lock, so two runs
    # cannot both pass, and a run that is killed during the call has already been charged.
    try:
        with open(config["ledger"], "a+", encoding="utf-8") as ledger:
            fcntl.flock(ledger, fcntl.LOCK_EX)
            ledger.seek(0)
            before = spent(ledger.readlines())
            if not math.isfinite(before + worst) or before + worst > cap:
                raise Refused(f"this call could cost {worst:.4f} USD; {before:.4f} of the {cap:.2f} USD cap is spent")
            append(ledger, {**entry, "status": "pending", "usd": worst})
    except OSError as e:
        raise Refused(f"the ledger cannot be written ({e}); no call is made") from None

    def settle(status, usd, **more):
        try:
            with open(config["ledger"], "a", encoding="utf-8") as ledger:
                fcntl.flock(ledger, fcntl.LOCK_EX)
                append(ledger, {**entry, "status": status, "usd": usd, **more})
        except OSError as e:
            # The call is already in the ledger at its worst case; that entry stands.
            print(f"the ledger could not be written after the call ({e}); the call stays charged at "
                  f"its worst case, {worst:.4f} USD", file=sys.stderr)

    try:
        done = subprocess.run(provider["command"], input=request, capture_output=True, check=True, timeout=timeout,
                              env=env)
        answer = json.loads(done.stdout)
        if not isinstance(answer, dict) or not isinstance(answer.get("text"), str):
            raise ValueError("the answer holds no text")
        # A request is at least one token, and an answer with text at least one more: a count of
        # zero would settle a real call at nothing, so it is treated as not known.
        tokens_in = count(answer.get("input_tokens"), "input_tokens", len(request), least=1)
        tokens_out = count(answer.get("output_tokens"), "output_tokens", allowance, least=1 if answer["text"] else 0)
    except (OSError, subprocess.SubprocessError, ValueError, TypeError) as e:
        # What the call cost is unknown: the worst case stays charged.
        settle("failed", worst)
        raise Refused(f"provider {name!r} failed ({type(e).__name__}: {e}); nothing else is tried") from None
    settle("ok", worst, reported_usd=cost(provider, tokens_in, tokens_out), input_tokens=tokens_in, output_tokens=tokens_out)
    return answer["text"]


def main(argv):
    ap = argparse.ArgumentParser(usage=__doc__.split("usage: ", 1)[1].splitlines()[0])
    ap.add_argument("--config", required=True)
    ap.add_argument("--provider", required=True)
    ap.add_argument("--instruction", default=DEFAULT_INSTRUCTION)
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args(argv[1:])
    try:
        with open(a.config, encoding="utf-8") as f:
            config = json.load(f)
        if not isinstance(config, dict):
            raise ValueError("not a JSON object")
    except (OSError, ValueError) as e:
        print(f"config: {e}", file=sys.stderr)
        return 2
    try:
        print(review(config, a.provider, a.instruction, a.paths))
    except Refused as e:
        print(f"REFUSING:\n{e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
