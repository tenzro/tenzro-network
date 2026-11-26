#!/usr/bin/env python3
"""The `tenzro update` channel of a release, written from its built archives.

The channel is what `tenzro update` reads (docs/UPDATE-MANIFEST.md): the two
binaries of every archive, under <release>/<platform>/, a targets document
listing them, a libraries document listing the files the archives keep beside
the binaries (lib/, the other files in bin/ that Windows loads, and the web
console in share/console/ with its scripts in share/console/src/), and a
timestamp document vouching for the targets document. The libraries document
is signed by the targets key and holds for exactly the release and manifest
number of the targets document; it is written only when an archive has such
files.
Each document travels in an envelope signed over its domain and payload; the
key never reaches this script. A step writes the exact bytes to sign
(<doc>.tosign), the key holder signs them with the release signing step
(`cosign sign-blob`, ECDSA P-256 over SHA-256 of the file), and `seal` checks
that signature against the public key and assembles the envelope.

  update-channel.py targets --dist DIR --channel DIR --release X.Y.Z --version N --class C0 --description TEXT
  update-channel.py seal --channel DIR --doc targets|libraries|timestamp --public-key PEM --signature FILE
  update-channel.py timestamp --channel DIR --version N [--lifetime-hours H]

Platforms: "<arch>-<os>" for a CPU archive and for macOS, which has one build
per architecture; "<arch>-<os>-<kind>" for every other kind, the kind being the
rest of the archive name (x86_64-linux-cuda, aarch64-linux-cpu-bookworm).
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

SPEC = "tenzro-update/1"
DOMAINS = {
    "targets": b"tenzro-update/1\ntargets\n",
    "libraries": b"tenzro-update/1\nlibraries\n",
    "timestamp": b"tenzro-update/1\ntimestamp\n",
}
NAMES = ("tenzro", "tenzro-node")
ARCHIVE = re.compile(r"^tenzro-node-(linux|macos|windows)-(x86_64|aarch64)-([a-z0-9][a-z0-9-]*)\.(tar\.gz|zip)$")
MAX_FILES = 64
MAX_LIBRARY_ENTRIES = 256
LIBRARY_FILE = re.compile(r"^[A-Za-z0-9_+-][A-Za-z0-9._+-]{0,127}$")
# The folders whose files the libraries document carries, and those that hold them.
LIBRARY_FOLDERS = ("lib", "bin", "share/console", "share/console/src")
CARRIED = ("lib", "bin", "share/console")
MAX_FILE_BYTES = 4 * 1024 ** 3
MAX_LIFETIME_HOURS = 7 * 24


def refuse(why):
    sys.exit("REFUSING: " + why)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def platform_of(os_name, arch, kind):
    if kind == "cpu" or os_name == "macos":
        return f"{arch}-{os_name}"
    return f"{arch}-{os_name}-{kind}"


def signed_list(dist):
    """The archives SHA256SUMS lists, each checked against its digest."""
    listed = {}
    with open(os.path.join(dist, "SHA256SUMS")) as f:
        for line in f:
            if not line.strip():
                continue
            digest, name = line.split(None, 1)
            listed[name.strip().lstrip("*")] = digest.lower()
    archives = []
    for name, digest in sorted(listed.items()):
        m = ARCHIVE.match(name)
        if not m or m.group(3).endswith("debug"):
            continue
        if sha256_file(os.path.join(dist, name)) != digest:
            refuse(f"{name} does not match SHA256SUMS")
        archives.append((name, m.group(1), m.group(2), m.group(3)))
    return archives


def read_archive(dist, archive):
    """The regular files and links under the archive's top folder: {relative path: bytes, ("link", target) or ("hardlink", target)}."""
    top = archive[: -len(".tar.gz")] if archive.endswith(".tar.gz") else archive[: -len(".zip")]
    entries = {}
    path = os.path.join(dist, archive)
    if archive.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.is_dir() and info.filename.startswith(top + "/"):
                    entries[info.filename[len(top) + 1:]] = z.read(info)
    else:
        with tarfile.open(path, "r:gz") as t:
            for info in t.getmembers():
                if not info.name.startswith(top + "/"):
                    continue
                rel = info.name[len(top) + 1:]
                if info.isfile():
                    entries[rel] = t.extractfile(info).read()
                elif info.issym():
                    entries[rel] = ("link", info.linkname)
                elif info.islnk():
                    entries[rel] = ("hardlink", info.linkname)
    return entries


def write_file(out, data, what):
    if not data or len(data) > MAX_FILE_BYTES:
        refuse(f"{what} is empty or too large")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(data)


def entry(channel, platform, name, path):
    local = os.path.join(channel, path)
    return {"platform": platform, "name": name, "path": path,
            "length": os.path.getsize(local), "sha256": sha256_file(local)}


def publish_archive(a, archive, os_name, platform):
    """Writes the archive's binaries and libraries into the channel; returns (binaries, library files, links)."""
    entries = read_archive(a.dist, archive)
    suffix = ".exe" if os_name == "windows" else ""
    binaries, files, links = [], [], []
    for name in NAMES:
        data = entries.get(f"bin/{name}{suffix}")
        if not isinstance(data, bytes):
            refuse(f"{archive} holds no bin/{name}{suffix}")
        path = f"{a.release}/{platform}/{name}{suffix}"
        write_file(os.path.join(a.channel, path), data, f"{archive}: bin/{name}{suffix}")
        binaries.append(entry(a.channel, platform, name, path))
    own = {f"bin/{n}{suffix}" for n in NAMES}
    for rel, data in sorted(entries.items()):
        if not any(rel == c or rel.startswith(c + "/") for c in CARRIED):
            continue
        folder, _, file = rel.rpartition("/")
        # Nothing in lib/ or bin/ is left out without a word: what the update
        # cannot carry makes the archive unpublishable.
        if isinstance(data, tuple) and data[0] == "hardlink":
            refuse(f"{archive}: {rel} is a hard link; pack the file itself")
        if rel in own:
            continue
        if folder not in LIBRARY_FOLDERS:
            refuse(f"{archive}: {rel} is in a folder an update does not carry; it carries files directly in {', '.join(f + '/' for f in LIBRARY_FOLDERS)} only")
        if not LIBRARY_FILE.match(file):
            refuse(f"{archive}: {rel} is not a plain file name")
        if isinstance(data, bytes):
            path = f"{a.release}/{platform}/{rel}"
            write_file(os.path.join(a.channel, path), data, f"{archive}: {rel}")
            files.append(entry(a.channel, platform, rel, path))
        elif folder == "lib":
            # A link is published as a link to the file it ends at in lib/.
            target, hops = rel, 0
            while isinstance(entries.get(target), tuple):
                link = entries[target][1]
                if "/" in link or hops > 8:
                    refuse(f"{archive}: {target} does not point at a file beside it in lib/")
                target, hops = f"lib/{link}", hops + 1
            if not isinstance(entries.get(target), bytes):
                refuse(f"{archive}: {rel} points at nothing in lib/")
            links.append({"platform": platform, "name": rel, "target": target})
        else:
            refuse(f"{archive}: {rel} is a link outside lib/")
    return binaries, files, links


def write_tosign(channel, doc, payload):
    """Writes <doc>.payload and <doc>.tosign; returns the payload bytes."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    with open(os.path.join(channel, f"{doc}.payload"), "wb") as f:
        f.write(body)
    with open(os.path.join(channel, f"{doc}.tosign"), "wb") as f:
        f.write(DOMAINS[doc] + body)
    print(f"to sign: {os.path.join(channel, doc + '.tosign')}")
    return body


def cmd_targets(a):
    if not re.fullmatch(r"\d+\.\d+\.\d+", a.release):
        refuse("--release is not major.minor.patch")
    if a.version < 1:
        refuse("--version must be 1 or more")
    if not a.description or len(a.description) > 200 or "\n" in a.description or "\r" in a.description:
        refuse("--description must be one line of 1 to 200 characters")
    release_dir = os.path.join(a.channel, a.release)
    if os.path.exists(release_dir):
        refuse(f"{release_dir} exists: a release is written once")
    archives = signed_list(a.dist)
    if not archives:
        refuse(f"SHA256SUMS in {a.dist} lists no tenzro-node archive")
    files, library_files, links = [], [], []
    seen = set()
    for archive, os_name, arch, kind in archives:
        platform = platform_of(os_name, arch, kind)
        if platform in seen:
            refuse(f"two archives give platform {platform}")
        seen.add(platform)
        binaries, libs, lks = publish_archive(a, archive, os_name, platform)
        files += binaries
        library_files += libs
        links += lks
    if len(files) > MAX_FILES:
        refuse(f"{len(files)} files; a targets document holds at most {MAX_FILES}")
    if len(library_files) + len(links) > MAX_LIBRARY_ENTRIES:
        refuse(f"{len(library_files) + len(links)} libraries; a libraries document holds at most {MAX_LIBRARY_ENTRIES}")
    targets_body = write_tosign(a.channel, "targets", {
        "_type": "targets",
        "spec": SPEC,
        "version": a.version,
        "release": a.release,
        "class": a.cls,
        "description": a.description,
        "files": files,
    })
    if library_files:
        write_tosign(a.channel, "libraries", {
            "_type": "libraries",
            "spec": SPEC,
            "version": a.version,
            "release": a.release,
            "targets_sha256": hashlib.sha256(targets_body).hexdigest(),
            "files": library_files,
            "links": links,
        })
    for f in files + library_files:
        print(f"{f['platform']:32} {f['name']:12} {f['sha256']}")
    for l in links:
        print(f"{l['platform']:32} {l['name']} -> {l['target']}")


def public_key_sec1(pem_path):
    """The uncompressed SEC1 point of a P-256 public key in PEM (its SPKI ends with it)."""
    with open(pem_path) as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("-----")]
    der = base64.b64decode("".join(lines))
    point = der[-65:]
    # SubjectPublicKeyInfo of id-ecPublicKey on prime256v1: 26 bytes of header, then the point.
    if len(der) != 91 or point[0] != 0x04 or b"\x2a\x86\x48\xce\x3d\x03\x01\x07" not in der[:26]:
        refuse(f"{pem_path} is not a P-256 public key")
    return point


def cmd_seal(a):
    tosign = os.path.join(a.channel, f"{a.doc}.tosign")
    payload_path = os.path.join(a.channel, f"{a.doc}.payload")
    with open(payload_path, "rb") as f:
        payload = f.read()
    with open(tosign, "rb") as f:
        if f.read() != DOMAINS[a.doc] + payload:
            refuse(f"{tosign} is not the domain and the payload")
    with open(a.signature, "rb") as f:
        raw = f.read().strip()
    try:
        sig = bytes.fromhex(raw.decode())
    except ValueError:
        sig = base64.b64decode(raw, validate=True)
    # The signature is checked before anything is published.
    with tempfile.TemporaryDirectory() as tmp:
        sig_path = os.path.join(tmp, "sig.der")
        with open(sig_path, "wb") as f:
            f.write(sig)
        check = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", a.public_key, "-signature", sig_path, tosign],
            capture_output=True)
    if check.returncode != 0:
        refuse(f"the signature in {a.signature} does not verify {tosign} with {a.public_key}")
    envelope = {
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": hashlib.sha256(public_key_sec1(a.public_key)).hexdigest(), "sig": sig.hex()}],
    }
    out = os.path.join(a.channel, f"{a.doc}.json")
    with open(out, "w") as f:
        json.dump(envelope, f, separators=(",", ":"))
    os.remove(tosign)
    os.remove(payload_path)
    print(f"sealed: {out}")


def cmd_timestamp(a):
    targets = os.path.join(a.channel, "targets.json")
    with open(targets, "rb") as f:
        served = f.read()
    envelope = json.loads(served)
    body = json.loads(base64.b64decode(envelope["payload"]))
    if not 0 < a.lifetime_hours <= MAX_LIFETIME_HOURS:
        refuse(f"--lifetime-hours must be 1 to {MAX_LIFETIME_HOURS}")
    if a.version < 1:
        refuse("--version must be 1 or more")
    issued = int(time.time() * 1000)
    write_tosign(a.channel, "timestamp", {
        "_type": "timestamp",
        "spec": SPEC,
        "version": a.version,
        "issued_ms": issued,
        "expires_ms": issued + a.lifetime_hours * 3600 * 1000,
        "targets_version": body["version"],
        "targets_length": len(served),
        "targets_sha256": hashlib.sha256(served).hexdigest(),
    })


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("targets")
    t.add_argument("--dist", required=True)
    t.add_argument("--channel", required=True)
    t.add_argument("--release", required=True)
    t.add_argument("--version", type=int, required=True)
    t.add_argument("--class", dest="cls", choices=["C0", "C1", "C2"], required=True)
    t.add_argument("--description", required=True)
    s = sub.add_parser("seal")
    s.add_argument("--channel", required=True)
    s.add_argument("--doc", choices=sorted(DOMAINS), required=True)
    s.add_argument("--public-key", required=True)
    s.add_argument("--signature", required=True)
    m = sub.add_parser("timestamp")
    m.add_argument("--channel", required=True)
    m.add_argument("--version", type=int, required=True)
    m.add_argument("--lifetime-hours", type=int, default=MAX_LIFETIME_HOURS)
    a = p.parse_args()
    {"targets": cmd_targets, "seal": cmd_seal, "timestamp": cmd_timestamp}[a.cmd](a)


if __name__ == "__main__":
    main()
