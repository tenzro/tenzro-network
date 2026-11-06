#!/usr/bin/env python3
"""Check built model files against the catalog and write the seeding manifest.

    scripts/release/model-blobs.py <dir>

Every catalog component whose source is a network file (it has no hub copy)
must be present at <dir>/<model-id>/<path>, built by the recipe the entry
names. Each file is hashed and must match the catalog's size, SHA-256 and
BLAKE3 exactly. The result is <dir>/MANIFEST.json: one row per file with its
content address, digests, size, source checkpoint and recipe. Storage-role
nodes seed the files from that manifest at genesis. Any missing or mismatched file fails the run and writes nothing.

Needs the `blake3` Python package (pinned in tools/gguf-export/requirements-lock.txt).
"""
import hashlib
import json
import sys
from pathlib import Path

import blake3

ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "crates" / "tenzro-catalog" / "seed"


def network_components():
    for seed in sorted(SEED.glob("*.json")):
        for entry in json.loads(seed.read_text()):
            model_id = entry["model"]["spec"]["id"]
            for c in entry.get("components", []):
                if "blake3" in c:
                    yield model_id, c


def digest(path):
    sha, b3, size = hashlib.sha256(), blake3.blake3(), 0
    with open(path, "rb") as f:
        while chunk := f.read(1 << 24):
            sha.update(chunk)
            b3.update(chunk)
            size += len(chunk)
    return size, sha.hexdigest(), b3.hexdigest()


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = Path(sys.argv[1]).resolve()
    rows, failures = [], []
    for model_id, c in network_components():
        path = out / model_id / c["path"]
        if not path.is_file():
            failures.append(f"{model_id}/{c['path']}: missing")
            continue
        size, sha, b3 = digest(path)
        for field, got in (("size", size), ("sha256", sha), ("blake3", b3)):
            if got != c[field]:
                failures.append(f"{model_id}/{c['path']}: {field} {got} != catalog {c[field]}")
        rows.append({
            "model_id": model_id,
            "file": f"{model_id}/{c['path']}",
            "repo": c["repo"],
            "size": size,
            "sha256": sha,
            "blake3": b3,
            "uri": f"tenzro://blob/{b3}",
            "built_from": c["built_from"],
            "recipe": c["recipe"],
        })
    if failures:
        sys.exit("\n".join(failures))
    (out / "MANIFEST.json").write_text(json.dumps({"files": rows}, indent=2) + "\n")
    print(f"{len(rows)} files verified against the catalog; wrote {out / 'MANIFEST.json'}")


if __name__ == "__main__":
    main()
