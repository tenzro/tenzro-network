#!/bin/sh
# Rebuild a reranker, pooled-embedder or decision-model GGUF byte for byte from
# its upstream checkpoint.
#
#   tools/gguf-export/convert.sh <4b|8b|vl-2b|vl-embedding-2b|laya-multilingual|laya-typed> <work-dir>
#
# Everything that decides the output bytes is pinned here: the upstream
# checkpoint commit, the converter commit (the engine commit the files were
# built and checked with), and the Python toolchain (requirements-lock.txt).
# For a reranker the converter writes the RANK pooling head (the "yes"/"no"
# rows of the LM head) and the rerank prompt template into the file; Q8_0 and
# F16 are deterministic casts, so two runs write identical files. The
# vision-language models ship in F16 (the reranker's scores under Q8_0 move by
# up to 0.05 from the checkpoint's), and the same converter writes each one's
# vision tower as a separate projector file (F16, equally deterministic),
# which takes pictures and video frames. A decision model (Laya) is a
# ModernBERT-family encoder with a decision head; the converter detects it by
# its `encoder/` directory and `rl_agent_config.json` and writes the head, the
# calibration temperatures and the question template into the file. The script prints size, SHA-256 and
# BLAKE3 of every file, the three values the catalog pins for a network file.
set -eu

CONVERTER_REPO=https://github.com/Praecise/llama.cpp
RERANKER_CONVERTER=b8343f7c57cb9b9813a48683842e5bd5c5b88d8a
EMBEDDER_CONVERTER=836a4c5ec34a33387c801ec1b25e48f493dc29aa
DECISION_CONVERTER=6f13159558a6ffff90e452218a5e66faf837dc62
# The decision checkpoints are saved by transformers 5, which the toolchain of the
# other recipes (transformers 4.57) cannot read: they get a lock of their own.
LOCK=requirements-lock.txt

case "${1:-}" in
  4b) REPO=Qwen/Qwen3-Reranker-4B; REV=22e683669bc0f0bd69640a1354a6d0aebcfeede5; ID=qwen3-reranker-4b; TYPE=q8_0; CONVERTER_COMMIT=$RERANKER_CONVERTER ;;
  8b) REPO=Qwen/Qwen3-Reranker-8B; REV=77d193c791ed757ca307ee72715aa132723da912; ID=qwen3-reranker-8b; TYPE=q8_0; CONVERTER_COMMIT=$RERANKER_CONVERTER ;;
  vl-2b) REPO=Qwen/Qwen3-VL-Reranker-2B; REV=4bd860ac4f15ad1897a214615cccc700f8f71818; ID=qwen3-vl-reranker-2b; TYPE=f16; CONVERTER_COMMIT=$RERANKER_CONVERTER ;;
  vl-embedding-2b) REPO=Qwen/Qwen3-VL-Embedding-2B; REV=9f2f7e710d6d81056aa5c0a4f04764fec6bb7bda; ID=qwen3-vl-embedding-2b; TYPE=f16; CONVERTER_COMMIT=$EMBEDDER_CONVERTER ;;
  laya-multilingual) REPO=convaiinnovations/laya-multilingual; REV=1720e3e3357cfe1e281542e223f8273b0890ca34; ID=laya-multilingual; TYPE=bf16; CONVERTER_COMMIT=$DECISION_CONVERTER; LOCK=requirements-lock-decision.txt ;;
  laya-typed) REPO=convaiinnovations/laya-typed-decisions; REV=e929ae5cf69bc34259cd2f95c9e91145b818b1f0; ID=laya-typed-decisions; TYPE=q8_0; CONVERTER_COMMIT=$DECISION_CONVERTER; LOCK=requirements-lock-decision.txt ;;
  *) echo "usage: $0 <4b|8b|vl-2b|vl-embedding-2b|laya-multilingual|laya-typed> <work-dir>" >&2; exit 2 ;;
esac
WORK=${2:?work dir}
HERE=$(cd "$(dirname "$0")" && pwd)
NAME=${REPO#*/}
OUT="$WORK/$ID-$TYPE.gguf"
mkdir -p "$WORK"

if [ ! -x "$WORK/venv/bin/python" ]; then
  python3 -m venv "$WORK/venv"
  "$WORK/venv/bin/pip" install --quiet --no-deps --extra-index-url https://download.pytorch.org/whl/cpu \
    -r "$HERE/$LOCK"
fi
PY="$WORK/venv/bin/python"

CONV="$WORK/llama.cpp-$CONVERTER_COMMIT"
if [ ! -f "$CONV/convert_hf_to_gguf.py" ]; then
  mkdir -p "$CONV"
  curl -fsSL "$CONVERTER_REPO/archive/$CONVERTER_COMMIT.tar.gz" | tar -xz --strip-components=1 -C "$CONV"
fi

# The converter recognises a reranker by its directory name.
SRC="$WORK/$NAME"
"$WORK/venv/bin/hf" download "$REPO" --revision "$REV" --local-dir "$SRC" --quiet >/dev/null

PYTHONPATH="$CONV/gguf-py" "$PY" "$CONV/convert_hf_to_gguf.py" "$SRC" --outtype "$TYPE" --outfile "$OUT" >"$WORK/convert-$1.log" 2>&1
OUTS="$OUT"
case "$1" in
  vl-*)
    MMPROJ="$WORK/$ID-mmproj-f16.gguf"
    PYTHONPATH="$CONV/gguf-py" "$PY" "$CONV/convert_hf_to_gguf.py" "$SRC" --mmproj --outtype f16 --outfile "$MMPROJ" >"$WORK/convert-$1-mmproj.log" 2>&1
    OUTS="$OUTS $MMPROJ"
    ;;
esac

# shellcheck disable=SC2086
"$PY" - "$REPO" "$REV" $OUTS <<'PY'
import hashlib, sys, blake3
repo, rev, *paths = sys.argv[1:]
for path in paths:
    sha, b3, size = hashlib.sha256(), blake3.blake3(), 0
    with open(path, "rb") as f:
        while chunk := f.read(1 << 24):
            sha.update(chunk); b3.update(chunk); size += len(chunk)
    print(f"{path}\n  built_from {repo}@{rev}\n  size {size}\n  sha256 {sha.hexdigest()}\n  blake3 {b3.hexdigest()}")
PY
