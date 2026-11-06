#!/usr/bin/env python3
"""Expected measurements of the confidential VM image, and a check of a
running guest against them.

    cvm-measure.py image --disk X.raw --uki X.efi
        The measurements of a built image (JSON on stdout): the unified kernel
        image's Authenticode digests (what UEFI firmware records when it starts
        the image, into TDX RTMR1 and TPM PCR4), its sections and command line
        (with the dm-verity root hash), the kernel it starts, the GPT event the
        firmware records for the boot disk, and the expected TDX RTMR1 and RTMR2
        under each platform profile in PLATFORMS.

    cvm-measure.py verify --measurements X.measurements.json --report R --eventlog CCEL
        Check a TDX guest: replay its firmware event log, require the replay to
        equal RTMR0-3 of the quote in the node's report (so the log is the one the
        hardware measured), require the image and the kernel it carries to be
        the only programs the firmware started, and compare RTMR1 and RTMR2 with the
        expected values. R is the JSON report tenzro_getTeeAttestation returns
        hex-encoded (report_hex), as hex or as the decoded JSON.

    cvm-measure.py snp-report --report R
        Print the launch measurement of an SEV-SNP report.

The SEV-SNP launch measurement covers what the hypervisor loads before the
guest starts. When the firmware boots the disk (as on a cloud platform that
supplies its own firmware), that is the firmware alone: compare it with the
platform's published firmware measurement, and bind the image through the
TPM event log. On a host that boots the unified kernel image directly
(QEMU -kernel with an SEV-SNP OVMF build and kernel hashes on), the launch
measurement covers the image too; compute it with sev-snp-measure from that
host's OVMF and vCPU configuration (see the operator documentation).

Python 3 standard library only.
"""

import argparse
import gzip
import hashlib
import json
import struct
import sys

# The order systemd-stub measures sections in (PCR 11; RTMR2 under TDX).
UKI_SECTIONS = [".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat", ".pcrpkey"]

# Event types (TCG PC Client Platform Firmware Profile).
EV_SEPARATOR = 0x4
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
EV_EFI_GPT_EVENT = 0x80000006
EV_EFI_ACTION = 0x80000007
EV_IPL = 0xD

TPM_ALG = {0x0004: ("sha1", 20), 0x000B: ("sha256", 32), 0x000C: ("sha384", 48), 0x000D: ("sha512", 64)}

# The UEFI boot path of a TDX guest booting the disk, as the firmware records
# it in RTMR1 (observed on a GCP C3 Confidential VM): the boot-option action,
# the separator, the boot disk's GPT, the unified kernel image, the kernel its
# stub starts, and the two ExitBootServices actions. RTMR2 holds the
# sections the image's stub measures. "gpt", "uki" and "linux" are filled from
# the image.
PLATFORMS = {
    "gcp-tdx": {
        "rtmr1": [
            ("action", b"Calling EFI Application from Boot Option"),
            ("separator", b"\0\0\0\0"),
            ("gpt", None),
            ("uki", None),
            ("linux", None),
            ("action", b"Exit Boot Services Invocation"),
            ("action", b"Exit Boot Services Returned with Success"),
        ],
    },
}


# ---------------------------------------------------------------- PE / UKI --

def pe_layout(data):
    if data[:2] != b"MZ":
        raise SystemExit("not a PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise SystemExit("no PE signature")
    coff = pe + 4
    nsections, = struct.unpack_from("<H", data, coff + 2)
    opt_size, = struct.unpack_from("<H", data, coff + 16)
    opt = coff + 20
    magic, = struct.unpack_from("<H", data, opt)
    if magic != 0x20B:
        raise SystemExit("not a PE32+ image")
    size_of_headers, = struct.unpack_from("<I", data, opt + 60)
    checksum_off = opt + 64
    certdir_off = opt + 112 + 4 * 8  # data directory 4: the certificate table
    cert_off, cert_size = struct.unpack_from("<II", data, certdir_off)
    sections = []
    sec = opt + opt_size
    for i in range(nsections):
        raw = data[sec + 40 * i: sec + 40 * (i + 1)]
        name = raw[:8].rstrip(b"\0").decode("ascii", "replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", raw, 8)
        sections.append({"name": name, "vsize": vsize, "rsize": rsize, "rptr": rptr})
    return {
        "size_of_headers": size_of_headers,
        "checksum_off": checksum_off,
        "certdir_off": certdir_off,
        "cert_off": cert_off,
        "cert_size": cert_size,
        "sections": sections,
    }


def authenticode(data, alg):
    """The PE Authenticode digest UEFI firmware measures for an image."""
    lay = pe_layout(data)
    h = hashlib.new(alg)
    h.update(data[:lay["checksum_off"]])
    h.update(data[lay["checksum_off"] + 4:lay["certdir_off"]])
    h.update(data[lay["certdir_off"] + 8:lay["size_of_headers"]])
    hashed = lay["size_of_headers"]
    for s in sorted((s for s in lay["sections"] if s["rsize"]), key=lambda s: s["rptr"]):
        h.update(data[s["rptr"]:s["rptr"] + s["rsize"]])
        hashed += s["rsize"]
    end = len(data) - lay["cert_size"]
    if end > hashed:
        h.update(data[hashed:end])
    return h.hexdigest()


def uki_sections(data):
    lay = pe_layout(data)
    out = {}
    for s in lay["sections"]:
        if s["name"] in UKI_SECTIONS:
            out[s["name"]] = data[s["rptr"]:s["rptr"] + min(s["vsize"], s["rsize"])]
    return out


def stub_events(data, alg):
    """The digests systemd-stub extends for the image, in order: each
    section's name (NUL-terminated), then its content."""
    secs = uki_sections(data)
    events = []
    for name in UKI_SECTIONS:
        if name in secs and name != ".pcrsig":
            events.append(hashlib.new(alg, name.encode() + b"\0").hexdigest())
            events.append(hashlib.new(alg, secs[name]).hexdigest())
    return events


# ----------------------------------------------------------------- GPT -----

def gpt_event(disk_path):
    """UEFI_GPT_DATA as firmware records it for the boot disk: the GPT header,
    the number of used partition entries, then those entries."""
    with open(disk_path, "rb") as f:
        f.seek(512)
        header = f.read(512)
        if header[:8] != b"EFI PART":
            raise SystemExit("no GPT on the disk")
        hsize, = struct.unpack_from("<I", header, 12)
        entries_lba, = struct.unpack_from("<Q", header, 72)
        nentries, esize = struct.unpack_from("<II", header, 80)
        f.seek(entries_lba * 512)
        table = f.read(nentries * esize)
    used = [table[i * esize:(i + 1) * esize] for i in range(nentries) if table[i * esize:i * esize + 16] != b"\0" * 16]
    return header[:hsize] + struct.pack("<Q", len(used)) + b"".join(used)


# ----------------------------------------------------------------- RTMR ----

def extend(reg, digest_hex, alg="sha384"):
    return hashlib.new(alg, reg + bytes.fromhex(digest_hex)).digest()


def predict(platform, image):
    """Expected RTMR1 and RTMR2 of `platform` for an image's digests."""
    r1 = bytes(48)
    for kind, val in PLATFORMS[platform]["rtmr1"]:
        digest = image[kind] if val is None else hashlib.sha384(val).hexdigest()
        r1 = extend(r1, digest)
    r2 = bytes(48)
    for d in image["stub"]:
        r2 = extend(r2, d)
    return {"RTMR1": r1.hex(), "RTMR2": r2.hex()}


def cmd_image(args):
    uki = open(args.uki, "rb").read()
    secs = uki_sections(uki)
    cmdline = secs.get(".cmdline", b"").rstrip(b"\0").decode().strip()
    roothash = next((w.split("=", 1)[1] for w in cmdline.split() if w.startswith("roothash=")), None)
    gpt = gpt_event(args.disk)
    image = {
        "gpt": hashlib.sha384(gpt).hexdigest(),
        "uki": authenticode(uki, "sha384"),
        "linux": authenticode(secs[".linux"], "sha384"),
        "stub": stub_events(uki, "sha384"),
    }
    out = {
        "uki": {
            "sha256": hashlib.sha256(uki).hexdigest(),
            "sha384": hashlib.sha384(uki).hexdigest(),
            "authenticode_sha256": authenticode(uki, "sha256"),
            "authenticode_sha384": image["uki"],
            "linux_authenticode_sha384": image["linux"],
            "cmdline": cmdline,
            "roothash": roothash,
            "sections": {n: {"sha256": hashlib.sha256(v).hexdigest(), "size": len(v)} for n, v in secs.items()},
            "stub_events_sha384": image["stub"],
        },
        "gpt_event_sha384": image["gpt"],
        "gpt_event_sha256": hashlib.sha256(gpt).hexdigest(),
        "expected_tdx": {name: predict(name, image) for name in PLATFORMS},
    }
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    print()


# --------------------------------------------------------------- reports ---

def load_report(path):
    raw = open(path, "rb").read().strip()
    try:
        text = raw.decode()
        if text.startswith("0x"):
            text = text[2:]
        if all(c in "0123456789abcdefABCDEF" for c in text[:64]):
            raw = bytes.fromhex(text)
    except (UnicodeDecodeError, ValueError):
        pass
    return json.loads(raw)


def report_evidence(report):
    data = report.get("attestation_data") or report.get("quote")
    return bytes(data) if isinstance(data, list) else bytes.fromhex(data)


def tdx_registers(quote):
    version, = struct.unpack_from("<H", quote, 0)
    body = 48 if version == 4 else 54
    regs = {"MRTD": quote[body + 136:body + 184].hex()}
    for i in range(4):
        off = body + 328 + 48 * i
        regs[f"RTMR{i}"] = quote[off:off + 48].hex()
    regs["REPORTDATA"] = quote[body + 520:body + 584].hex()
    return regs


def parse_ccel(log):
    """Events of a crypto-agile CC event log: (mr_index, type, sha384, data)."""
    off = 0
    # The first event is in the SHA-1 log format and carries the spec header.
    _, _, = struct.unpack_from("<II", log, off)
    size, = struct.unpack_from("<I", log, off + 28)
    off += 32 + size
    events = []
    while off + 12 <= len(log):
        mr, etype, count = struct.unpack_from("<III", log, off)
        if etype == 0xFFFFFFFF or (mr == 0 and etype == 0 and count == 0):
            break
        p = off + 12
        digests = {}
        for _ in range(count):
            alg, = struct.unpack_from("<H", log, p)
            name, n = TPM_ALG[alg]
            digests[name] = log[p + 2:p + 2 + n].hex()
            p += 2 + n
        dsize, = struct.unpack_from("<I", log, p)
        data = log[p + 4:p + 4 + dsize]
        events.append((mr, etype, digests.get("sha384"), data))
        off = p + 4 + dsize
    return events


def cmd_verify(args):
    m = json.load(open(args.measurements))
    report = load_report(args.report)
    if report.get("vendor") != "IntelTdx":
        raise SystemExit(f"not a TDX report: {report.get('vendor')}")
    regs = tdx_registers(report_evidence(report))
    raw = open(args.eventlog, "rb").read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    events = parse_ccel(raw)
    replay = [bytes(48) for _ in range(4)]
    for mr, _, d, _ in events:
        if 1 <= mr <= 4 and d:
            replay[mr - 1] = extend(replay[mr - 1], d)
    checks = []
    for i in range(4):
        checks.append((f"event log replays RTMR{i}", replay[i].hex() == regs[f"RTMR{i}"]))
    apps = [d for mr, t, d, _ in events if mr == 2 and t == EV_EFI_BOOT_SERVICES_APPLICATION]
    checks.append((
        "the firmware started the image and the kernel in it, nothing else",
        apps == [m["uki"]["authenticode_sha384"], m["uki"]["linux_authenticode_sha384"]],
    ))
    gpts = [d for mr, t, d, _ in events if mr == 2 and t == EV_EFI_GPT_EVENT]
    checks.append(("the boot disk's GPT is the image's", gpts in ([], [m["gpt_event_sha384"]])))
    if args.platform:
        exp = m["expected_tdx"][args.platform]
        checks.append((f"RTMR1 equals the expected value for {args.platform}", regs["RTMR1"] == exp["RTMR1"]))
        checks.append((f"RTMR2 equals the expected value for {args.platform}", regs["RTMR2"] == exp["RTMR2"]))
    out = {
        "registers": regs,
        "events": [
            {"mr": mr, "type": hex(t), "sha384": d, "data": data[:64].hex() if t != EV_EFI_ACTION else data.decode("ascii", "replace")}
            for mr, t, d, data in events
        ] if args.events else None,
        "checks": {name: ok for name, ok in checks},
        "ok": all(ok for _, ok in checks),
    }
    json.dump(out, sys.stdout, indent=2)
    print()
    sys.exit(0 if out["ok"] else 1)


def cmd_snp_report(args):
    report = load_report(args.report)
    ev = report_evidence(report)
    print(json.dumps({"vendor": report.get("vendor"), "MEASUREMENT": ev[0x90:0xC0].hex(), "REPORT_DATA": ev[0x50:0x90].hex()}))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("image")
    a.add_argument("--disk", required=True)
    a.add_argument("--uki", required=True)
    a.set_defaults(fn=cmd_image)
    v = sub.add_parser("verify")
    v.add_argument("--measurements", required=True)
    v.add_argument("--report", required=True)
    v.add_argument("--eventlog", required=True)
    v.add_argument("--platform", choices=sorted(PLATFORMS))
    v.add_argument("--events", action="store_true", help="also print the parsed events")
    v.set_defaults(fn=cmd_verify)
    s = sub.add_parser("snp-report")
    s.add_argument("--report", required=True)
    s.set_defaults(fn=cmd_snp_report)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
