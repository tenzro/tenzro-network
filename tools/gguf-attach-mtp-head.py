#!/usr/bin/env python3
"""Attach an MTP draft head to a split qwen4exp GGUF as one extra shard.

    gguf-attach-mtp-head.py <target shard 00001> <head gguf> <out dir>

WHY. Qwen3.8-Flash-Next ships a multi-token-prediction head inside its own
weights, and Unsloth's UD-Q2_K_XL build strips it. Serving the model with
speculative decoding therefore needs the head put back. Keeping it as a second
file works -- the runtime has a separate-drafter path -- but it means a second
artifact to download, hash, version and lose track of, for something that is
part of the model. Attaching it makes one artifact again: one id in the catalog,
one hash in the transparency log, and the runtime's INLINE self-speculative path
(mtp_kind set, drafter_id None) rather than the separate-drafter path.

WHAT IT WRITES. Shard 1 is rewritten with four keys changed, and the head lands
in a new final shard. Every other shard of the target is hard-linked under its
new -of-0000M name, so a 79 GB model costs ~4 GB of writes and no copy. The
originals are never modified: if this produces something that will not load,
delete the output directory and the input set is untouched.

The head's block index MUST equal the target's block_count -- it is the block
that comes after the trunk, not a replacement for any of it. That is asserted
rather than assumed, because a head numbered anywhere else will load as a
corrupt trunk and fail deep inside tensor creation with a message that points at
the wrong thing (`blk.0.hc_attn_norm.weight not found`, which cost two builds to
diagnose on 2026-09-01).
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.environ.get(
    "GGUF_PY",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "vendor", "llama-cpp-rs", "llama-cpp-sys-2",
                 "llama.cpp", "gguf-py"),
))

from gguf import GGUFReader, GGUFWriter, GGUFValueType  # noqa: E402


def scalar(field):
    return field.parts[field.data[0]][0]


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 64
    src1, head_path, out_dir = sys.argv[1:4]

    m = re.match(r"(.*)-(\d{5})-of-(\d{5})\.gguf$", os.path.basename(src1))
    if not m:
        print(f"expected a split shard name, got {os.path.basename(src1)}")
        return 64
    prefix, n_old = m.group(1), int(m.group(3))
    n_new = n_old + 1
    src_dir = os.path.dirname(os.path.abspath(src1))
    os.makedirs(out_dir, exist_ok=True)

    r1 = GGUFReader(src1)
    head = GGUFReader(head_path)

    arch = bytes(r1.fields["general.architecture"].parts[-1]).decode()
    n_layer = int(scalar(r1.fields[f"{arch}.block_count"]))

    head_tensors = [t for t in head.tensors if t.name.startswith("blk.")]
    if not head_tensors:
        print("head has no blk.* tensors — not an MTP head")
        return 1
    idxs = {int(t.name.split(".")[1]) for t in head_tensors}
    if idxs != {n_layer}:
        print(f"head block index {sorted(idxs)} != target block_count {n_layer}; "
              "the head must be the block that FOLLOWS the trunk")
        return 1
    if not any("nextn" in t.name for t in head.tensors):
        print("head has no nextn.* tensors — not an MTP head")
        return 1

    shared = [t for t in head.tensors if not t.name.startswith("blk.")]
    add = head_tensors + shared
    print(f"arch={arch} block_count={n_layer} -> {n_layer + 1}")
    print(f"attaching {len(add)} tensors as shard {n_new}/{n_new}")

    # -- rewrite shard 1: bump the counts the loader reads before it walks blocks
    out1 = os.path.join(out_dir, f"{prefix}-00001-of-{n_new:05d}.gguf")
    w = GGUFWriter(out1, arch, use_temp_file=False)
    old_total = int(scalar(r1.fields["split.tensors.count"]))
    overrides = {
        f"{arch}.block_count": n_layer + 1,
        f"{arch}.nextn_predict_layers": 1,
        "split.count": n_new,
        "split.tensors.count": old_total + len(add),
    }
    for key, field in r1.fields.items():
        if key in ("GGUF.version", "GGUF.tensor_count", "GGUF.kv_count"):
            continue
        if key in overrides:
            continue
        w.add_key_value(key, field.contents(), field.types[0],
                        sub_type=field.types[-1] if len(field.types) > 1 else None)
    for key, val in overrides.items():
        w.add_key_value(key, val, GGUFValueType.UINT32 if key.endswith("count")
                        or key.endswith("layers") else GGUFValueType.UINT16)
    for t in r1.tensors:
        w.add_tensor_info(t.name, list(reversed(t.shape.tolist())),
                          t.data.dtype, t.data.nbytes, t.tensor_type)
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.write_tensors_to_file(progress=False)
    w.close()
    print(f"  wrote {out1}")

    # -- hard-link the untouched middle shards under their new names
    for i in range(2, n_old + 1):
        src = os.path.join(src_dir, f"{prefix}-{i:05d}-of-{n_old:05d}.gguf")
        dst = os.path.join(out_dir, f"{prefix}-{i:05d}-of-{n_new:05d}.gguf")
        if os.path.exists(dst):
            os.unlink(dst)
        try:
            os.link(src, dst)
            how = "linked"
        except OSError:
            import shutil
            shutil.copy2(src, dst)
            how = "copied"
        print(f"  {how} {os.path.basename(dst)}")

    # -- new final shard carrying the head
    outN = os.path.join(out_dir, f"{prefix}-{n_new:05d}-of-{n_new:05d}.gguf")
    wN = GGUFWriter(outN, arch, use_temp_file=False)
    wN.add_key_value("split.no", n_new - 1, GGUFValueType.UINT16)
    wN.add_key_value("split.count", n_new, GGUFValueType.UINT16)
    wN.add_key_value("split.tensors.count", old_total + len(add), GGUFValueType.INT32)
    for t in add:
        wN.add_tensor(t.name, t.data, raw_dtype=t.tensor_type)
    wN.write_header_to_file()
    wN.write_kv_data_to_file()
    wN.write_tensors_to_file(progress=False)
    wN.close()
    print(f"  wrote {outN} ({len(add)} tensors)")
    print("done — load shard 00001 to use the merged model")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
