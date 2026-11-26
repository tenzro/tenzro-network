#!/usr/bin/env python3
"""Reference implementation of docs/standards/run-manifest.md, written from
the document alone, and the source of its vectors.

  run_manifest_reference.py --check   recompute every published vector
  run_manifest_reference.py --write   rewrite docs/standards/vectors/run-manifest.json

`--check` exits 1 when a published digest or refusal reason differs from what
this reference computes, or when the vectors file is not exactly what
`--write` produces. The SDK and receipt-verify implement the same digest
independently and check the same file.
"""
import copy
import hashlib
import json
import pathlib
import re
import struct
import sys

DOMAIN = b"tenzro/run-manifest/v1"
MAX_BYTES, MAX_IN, MAX_OUT, MAX_CLAIMS, MAX_INT, MAX_TEXT = 65536, 64, 64, 32, 256, 256


class Refused(Exception):
    def __init__(self, reason):
        self.reason = reason


def obj(v):
    if not isinstance(v, dict):
        raise Refused("malformed")
    return v


def f(b):
    return struct.pack("<I", len(b)) + b


def txt(v, empty_ok=False):
    if not isinstance(v, str):
        raise Refused("malformed")
    try:
        b = v.encode()
    except UnicodeEncodeError:  # a lone surrogate is not text
        raise Refused("malformed") from None
    if not b and not empty_ok:
        raise Refused("malformed")
    if len(b) > MAX_TEXT:
        raise Refused("too_large")
    return b


def dig(v):
    if not isinstance(v, str) or not re.fullmatch("[0-9a-f]{64}", v) or v == "0" * 64:
        raise Refused("malformed")
    return bytes.fromhex(v)


def whole(v, mx):
    if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > mx:
        raise Refused("malformed")
    return v


def lst(m, k, mx):
    v = m.get(k)
    if not isinstance(v, list):
        raise Refused("malformed")
    if len(v) > mx:
        raise Refused("too_large")
    return v


def preimage(text):
    if len(text.encode()) > MAX_BYTES:
        raise Refused("too_large")
    try:
        m = obj(json.loads(text))
    except json.JSONDecodeError:
        raise Refused("malformed") from None
    s = whole(m.get("started_at_ms"), 2**63 - 1)
    e = whole(m.get("ended_at_ms"), 2**63 - 1)
    if e < s:
        raise Refused("malformed")
    ins, outs = lst(m, "inputs", MAX_IN), lst(m, "outputs", MAX_OUT)
    claims, ints = lst(m, "claims", MAX_CLAIMS), lst(m, "interactions", MAX_INT)
    if not outs:
        raise Refused("no_output")
    out = DOMAIN + f(txt(m.get("run_id"))) + f(txt(m.get("operator_did"))) + f(dig(m.get("harness_module")))
    out += struct.pack("<QQ", s, e)
    for entries, with_bytes in ((ins, False), (outs, True)):
        out += struct.pack("<I", len(entries))
        seen = set()
        for x in entries:
            x = obj(x)
            name = txt(x.get("name"))
            if name in seen:
                raise Refused("malformed")
            seen.add(name)
            out += f(name) + f(dig(x.get("digest")))
            if with_bytes:
                out += struct.pack("<Q", whole(x.get("bytes"), 2**64 - 1))
    out += struct.pack("<I", len(claims))
    for c in claims:
        c = obj(c)
        value = txt(c.get("value"))
        if not re.fullmatch(r"(0|[1-9][0-9]*)(\.[0-9]+)?", value.decode()):
            raise Refused("malformed")
        out += f(txt(c.get("metric"))) + f(value) + f(txt(c.get("unit"), empty_ok=True))
    out += struct.pack("<I", len(ints))
    for d in ints:
        out += f(dig(d))
    return out


def h(c):
    return hashlib.sha256(c.encode()).hexdigest()


worked = {
    "run_id": "run-2026-11-17-001",
    "operator_did": "did:tenzro:machine:node",
    "harness_module": h("module"),
    "started_at_ms": 1763370000000,
    "ended_at_ms": 1763370600000,
    "inputs": [{"name": "dataset", "digest": h("dataset")}],
    "outputs": [{"name": "summary.json", "digest": h("summary"), "bytes": 4096}],
    "claims": [{"metric": "documents_summarised", "value": "1200", "unit": "documents"}],
    "interactions": [h("interaction")],
}
minimal = {**worked, "inputs": [], "claims": [], "interactions": [], "run_id": "r", "started_at_ms": 0, "ended_at_ms": 0}
big = copy.deepcopy(worked)
big["outputs"][0]["bytes"] = 2**64 - 1
big["claims"] = [{"metric": "loss", "value": "0.0123", "unit": ""}]
accepted = [
    ("worked example: one input, one output, one claim, one paid interaction", worked),
    ("the least a manifest can state: one output and nothing else", minimal),
    ("an output of 2^64 - 1 bytes and a claim with no unit", big),
]


def change(**kv):
    m = copy.deepcopy(worked)
    m.update(kv)
    return m


refused = [
    ("no output", change(outputs=[]), "no_output"),
    ("ends before it starts", change(ended_at_ms=worked["started_at_ms"] - 1), "malformed"),
    ("a zero harness module", change(harness_module="0" * 64), "malformed"),
    ("an upper-case digest", change(interactions=[h("interaction").upper()]), "malformed"),
    ("one output named twice", change(outputs=worked["outputs"] * 2), "malformed"),
    ("a claim value that is not a decimal number", change(claims=[{"metric": "m", "value": "1e3", "unit": ""}]), "malformed"),
    ("an empty run id", change(run_id=""), "malformed"),
    ("too many outputs", change(outputs=[{"name": f"o{i}", "digest": h(f"o{i}"), "bytes": 1} for i in range(MAX_OUT + 1)]), "too_large"),
    ("too many claims", change(claims=[{"metric": f"m{i}", "value": "1", "unit": ""} for i in range(MAX_CLAIMS + 1)]), "too_large"),
    ("a run id longer than 256 bytes", change(run_id="r" * (MAX_TEXT + 1)), "too_large"),
    ("a manifest longer than 64 KiB, every list within its bound", change(
        inputs=[{"name": f"{i:03}" + "i" * 253, "digest": h(f"i{i}")} for i in range(MAX_IN)],
        outputs=[{"name": f"{i:03}" + "o" * 253, "digest": h(f"o{i}"), "bytes": 1} for i in range(MAX_OUT)],
        claims=[{"metric": f"{i:03}" + "m" * 253, "value": "1", "unit": "u" * 256} for i in range(MAX_CLAIMS)],
        interactions=[h(str(i)) for i in range(MAX_INT)],
    ), "too_large"),
]

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "docs/standards/vectors/run-manifest.json"


def digest(text):
    return hashlib.sha256(preimage(text)).hexdigest()


def reason(text):
    try:
        preimage(text)
    except Refused as r:
        return r.reason
    return None


def vectors_text():
    """The vectors file as this reference writes it."""
    out = {"vectors": [], "refused": []}
    for label, m in accepted:
        out["vectors"].append({"label": label, "manifest": m, "digest": digest(json.dumps(m))})
    for label, m, why in refused:
        got = reason(json.dumps(m))
        if got != why:
            raise SystemExit(f"{label}: refused as {got}, expected {why}")
        out["refused"].append({"label": label, "manifest": m, "reason": why})
    return json.dumps(out, indent=2) + "\n"


def check(text):
    """The differences between a vectors file's text and this reference."""
    published = json.loads(text)
    problems = []
    for v in published["vectors"]:
        got = reason(json.dumps(v["manifest"])) or digest(json.dumps(v["manifest"]))
        if got != v["digest"]:
            problems.append(f"{v['label']}: published {v['digest']}, computed {got}")
    for v in published["refused"]:
        got = reason(json.dumps(v["manifest"]))
        if got != v["reason"]:
            problems.append(f"{v['label']}: published {v['reason']}, computed {got}")
    if not problems and text != vectors_text():
        problems.append("the file is not what --write produces")
    return problems


def main(argv):
    if argv == ["--write"]:
        VECTORS.write_text(vectors_text(), encoding="utf-8")
        return 0
    if argv == ["--check"]:
        problems = check(VECTORS.read_text(encoding="utf-8"))
        for p in problems:
            print(p, file=sys.stderr)
        if not problems:
            print("the run manifest vectors follow from the reference")
        return 1 if problems else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
