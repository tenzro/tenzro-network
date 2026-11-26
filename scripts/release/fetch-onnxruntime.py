#!/usr/bin/env python3
"""Fetch the pinned ONNX Runtime for a target and print the ORT_LIB_LOCATION that links it.

usage: fetch-onnxruntime.py [--target TRIPLE] [--feature NAME] [--prefix DIR] [--archive FILE] [--link-at DIR | --no-link]

The archive for TRIPLE (default: this machine's, from `rustc -vV`) is the one packaging/onnxruntime.tsv pins;
--feature picks another of its rows (migraphx for a ROCm build), else the target's first row is taken.
It is downloaded (or read from --archive), refused unless its SHA-256 is the pinned one, and unpacked into
PREFIX/<version>/<triple>[+<feature>] (default PREFIX: $TENZRO_ORT_PREFIX, else ~/.cache/tenzro/onnxruntime). A directory that
already holds that archive's contents is reused. For this machine's own target the checkout's .onnxruntime/host
is made to point there (a symbolic link; a directory junction on Windows), which is where .cargo/config.toml
sends ORT_LIB_LOCATION, so a plain `cargo build` afterwards links it; --link-at puts that link elsewhere (a build
that does not read .cargo/config.toml, such as a container, then sets ORT_LIB_LOCATION to it), --no-link makes
none. The last
line of output is

    ORT_LIB_LOCATION=<dir>

for a build to export: with praecise-onnx's download-binaries off, ort-sys links the runtime found there and
fetches nothing. Exit 0 with that line, 1 refused (unknown target, wrong hash, bad archive), 2 usage.
"""
import argparse
import hashlib
import io
import lzma
import os
import subprocess
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PINS = os.path.join(HERE, "..", "..", "packaging", "onnxruntime.tsv")
MARKER = ".tenzro-onnxruntime-sha256"
CHECKOUT_LINK = os.path.join(HERE, "..", "..", ".onnxruntime", "host")


class Refused(Exception):
    pass


def pins(path=PINS):
    """(version, {triple: [(feature, url, sha256), ...]}) from the pinned table, rows in file order."""
    version, rows = None, {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            cols = line.rstrip("\n").split("\t")
            if cols[0] == "version":
                version = cols[1]
            elif len(cols) == 4:
                rows.setdefault(cols[0], []).append((cols[1], cols[2], cols[3]))
    if not version or not rows:
        raise Refused(f"{path} pins no version or no archive")
    return version, rows


def host_triple():
    out = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout
    return next(l.split(": ", 1)[1] for l in out.splitlines() if l.startswith("host: "))


def unpack(data, dest):
    """Unpack a raw LZMA2 tar into dest; only plain files, only names without a path."""
    try:
        raw = lzma.decompress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 28}])
        tar = tarfile.open(fileobj=io.BytesIO(raw))
        members = tar.getmembers()
    except (lzma.LZMAError, tarfile.TarError) as e:
        raise Refused(f"the archive does not unpack: {e}") from None
    names = []
    for m in members:
        if not m.isfile() or os.path.basename(m.name) != m.name or m.name in ("", ".", ".."):
            raise Refused(f"the archive holds {m.name!r}, not a plain file at its top")
        names.append(m.name)
    if not any(n.startswith(("libonnxruntime", "onnxruntime")) for n in names):
        raise Refused(f"the archive holds no ONNX Runtime library: {names}")
    os.makedirs(dest, exist_ok=True)
    for m in members:
        with tar.extractfile(m) as src, open(os.path.join(dest, m.name), "wb") as out:
            out.write(src.read())
    return names


def fetch(target, prefix, archive=None, pin_file=PINS, feature=None):
    version, rows = pins(pin_file)
    if target not in rows:
        raise Refused(f"no pinned ONNX Runtime for {target} (pinned: {', '.join(sorted(rows))})")
    choices = rows[target]
    picked = choices[0] if feature is None else next((c for c in choices if c[0] == feature), None)
    if picked is None:
        raise Refused(f"no pinned {feature} build for {target} (pinned: {', '.join(c[0] for c in choices)})")
    name, url, want = picked
    dest = os.path.join(prefix, version, target if picked is choices[0] else f"{target}+{name}")
    try:
        with open(os.path.join(dest, MARKER), encoding="utf-8") as f:
            if f.read().strip() == want:
                return dest
    except OSError:
        pass
    if archive:
        with open(archive, "rb") as f:
            data = f.read()
    else:
        with urllib.request.urlopen(url, timeout=300) as r:
            data = r.read()
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        raise Refused(f"the archive for {target} hashes to {got}, not the pinned {want}")
    unpack(data, dest)
    with open(os.path.join(dest, MARKER), "w", encoding="utf-8") as f:
        f.write(want + "\n")
    return dest


def link(dest, at=CHECKOUT_LINK):
    """Point `at` at `dest`, replacing an older link there; a real directory there is left alone."""
    at = os.path.normpath(at)
    os.makedirs(os.path.dirname(at), exist_ok=True)
    if os.path.islink(at):
        os.unlink(at)
    elif getattr(os.path, "isjunction", lambda _: False)(at):
        os.rmdir(at)
    elif os.path.exists(at):
        raise Refused(f"{at} exists and is not a link; remove it and fetch again")
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", at, dest], check=True, capture_output=True)
    else:
        os.symlink(dest, at)
    return at


def main(argv):
    ap = argparse.ArgumentParser(usage=__doc__.split("usage: ", 1)[1].splitlines()[0])
    ap.add_argument("--target")
    ap.add_argument("--prefix", default=os.environ.get("TENZRO_ORT_PREFIX")
                    or os.path.join(os.path.expanduser("~"), ".cache", "tenzro", "onnxruntime"))
    ap.add_argument("--archive")
    ap.add_argument("--feature")
    ap.add_argument("--link-at")
    ap.add_argument("--no-link", action="store_true")
    a = ap.parse_args(argv[1:])
    try:
        host = host_triple()
        dest = fetch(a.target or host, a.prefix, a.archive, feature=a.feature)
        if a.link_at:
            print(f"linked {link(dest, a.link_at)} -> {dest}")
            dest = os.path.abspath(a.link_at)
        elif not a.no_link and (a.target or host) == host:
            print(f"linked {link(dest)} -> {dest}")
    except Refused as e:
        print(f"REFUSING: {e}", file=sys.stderr)
        return 1
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"REFUSING: {e}", file=sys.stderr)
        return 1
    print(f"ORT_LIB_LOCATION={dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
