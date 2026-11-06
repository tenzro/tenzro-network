"""Reference vectors for the vision-language embedder's parity test.

Usage:
    python embed_reference.py <expected.json>

Runs Qwen3-VL-Embedding-2B through its own pipeline (the checkpoint's
embedder script at the pinned revision, float32 on the CPU, one input per
call) over text, pictures (PNG, JPEG, alpha, one larger than the pipeline's
limit), a picture with text, and videos given as frames (one longer than the
pipeline's frame count, so it is sampled down to it), and writes the vectors,
the token ids and the pipeline's picture sizing to <expected.json>, with the
pictures in <expected>-media/ next to it. The node's
`a_vision_language_embedder_matches_its_source_checkpoint` test reads them.
Needs torch, transformers, qwen-vl-utils, torchvision, numpy and pillow.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import torch

REPO = "Qwen/Qwen3-VL-Embedding-2B"
REVISION = "9f2f7e710d6d81056aa5c0a4f04764fec6bb7bda"
QUERY_TASK = "Retrieve relevant documents for the query."
DOCUMENT_TASK = "Represent the user's input."

PARITY_QUERIES = [
    "how much protein should a female eat",
    "Write a Python function that counts the frequency of each element in a list of lists.",
]
PARITY_DOCUMENTS = [
    "Definition of summit: the highest point of a mountain.",
    "People with pollen allergy can reduce exposure by staying indoors on dry, windy days.",
    "short",
]



def synthetic_image(width: int, height: int, seed: int, mode: str = "RGB"):
    """A deterministic test picture: gradients, a filled box and a disc."""
    import numpy as np
    from PIL import Image

    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:height, 0:width]
    rgb = np.stack(
        [x * 255 // max(width - 1, 1), y * 255 // max(height - 1, 1), ((x + y) * 7 + seed * 31) % 256], axis=-1
    ).astype(np.uint8)
    rgb[height // 4 : height // 2, width // 3 : 2 * width // 3] = rng.integers(0, 256, 3)
    disc = (x - width * 0.7) ** 2 + (y - height * 0.6) ** 2 < (min(width, height) * 0.15) ** 2
    rgb[disc] = rng.integers(0, 256, 3)
    if mode == "RGBA":
        alpha = ((x * 255) // max(width - 1, 1)).astype(np.uint8)[..., None]
        return Image.fromarray(np.concatenate([rgb, alpha], axis=-1), "RGBA")
    return Image.fromarray(rgb, "RGB")


def vl_parity_cases(media: Path) -> list[dict]:
    """Inputs for the vision-language parity test; pictures are written to `media`."""
    media.mkdir(parents=True, exist_ok=True)

    def save(name, image, **kw):
        image.save(media / name, **kw)
        return name

    cases = [{"role": "query", "text": q} for q in PARITY_QUERIES]
    cases += [{"role": "document", "text": d} for d in PARITY_DOCUMENTS]
    cases += [
        {"role": "document", "image": save("a-640x480.png", synthetic_image(640, 480, 1))},
        {"role": "document", "image": save("b-50x50.png", synthetic_image(50, 50, 2)), "text": "a small square"},
        {"role": "query", "image": save("c-1000x300.png", synthetic_image(1000, 300, 3))},
        {"role": "document", "image": save("d-2400x1600.png", synthetic_image(2400, 1600, 4))},
        {"role": "document", "image": save("e-300x200-rgba.png", synthetic_image(300, 200, 5, "RGBA"))},
        {"role": "document", "image": save("f-800x600.jpg", synthetic_image(800, 600, 6), quality=90)},
        {
            "role": "document",
            "video": [save(f"g-{i:02}.png", synthetic_image(320, 240, 10 + i)) for i in range(6)],
        },
        {
            "role": "query",
            "video": [save(f"h-{i:02}.png", synthetic_image(160, 120, 40 + i)) for i in range(70)],
            "text": "a moving disc",
        },
    ]
    return cases


def write_expected(path: Path) -> None:
    """Reference embeddings from the checkpoint's own pipeline (its embedder
    script at the pinned revision), one input per call, float32."""
    from huggingface_hub import snapshot_download
    from PIL import Image

    src = Path(snapshot_download(REPO, revision=REVISION))
    sys.path.insert(0, (src / "scripts").as_posix())
    import qwen3_vl_embedding as pipeline

    embedder = pipeline.Qwen3VLEmbedder(src.as_posix(), dtype=torch.float32, attn_implementation="eager")
    media = path.parent / f"{path.stem}-media"
    cases = vl_parity_cases(media)

    def picture(name):
        # decoded up front: the pipeline converts frames on several threads,
        # and a lazily decoded file shared by repeated frames is not safe there
        with Image.open(media / name) as image:
            image.load()
            return image.copy()

    for case in cases:
        item = {"instruction": QUERY_TASK if case["role"] == "query" else DOCUMENT_TASK}
        if "text" in case:
            item["text"] = case["text"]
        if "image" in case:
            item["image"] = picture(case["image"])
        if "video" in case:
            item["video"] = [picture(f) for f in case["video"]]
        conversation = embedder.format_model_input(**item)
        case["input_ids"] = embedder._preprocess_inputs([conversation])["input_ids"][0].tolist()
        # the pipeline falls back to a "NULL" input when it cannot read the media
        for key, token in (("image", "<|image_pad|>"), ("video", "<|video_pad|>")):
            if key in case and embedder.processor.tokenizer.convert_tokens_to_ids(token) not in case["input_ids"]:
                raise RuntimeError(f"the pipeline dropped the {key} of {case[key]}")
        case["embedding"] = embedder.process([item])[0].tolist()
        print(f"  {case.get('image') or (case.get('video') or [''])[0] or case['text'][:24]}: {len(case['input_ids'])} tokens", flush=True)
    import qwen_vl_utils.vision_process as vp

    pre = json.loads((src / "preprocessor_config.json").read_text())
    factor = pre["patch_size"] * pre["merge_size"]
    # A list of frames goes through the pipeline's per-image fetch with the
    # merged patch size as its patch size, so each frame is first rounded to
    # twice that factor, then resized for the video.
    spec = {
        "patch_size": pre["patch_size"],
        "merge_size": pre["merge_size"],
        "temporal_patch_size": pre["temporal_patch_size"],
        "image_mean": pre["image_mean"],
        "image_std": pre["image_std"],
        "image_min_pixels": pipeline.MIN_PIXELS,
        "image_max_pixels": pipeline.MAX_PIXELS,
        "video_frames": pipeline.MAX_FRAMES,
        "video_sample_fps": 2.0,
        "video_frame_round_factor": factor * vp.SPATIAL_MERGE_SIZE,
        "video_frame_round_min_pixels": vp.IMAGE_MIN_TOKEN_NUM * (factor * vp.SPATIAL_MERGE_SIZE) ** 2,
        "video_frame_min_pixels": vp.VIDEO_MIN_TOKEN_NUM * factor**2,
        "video_frame_max_pixels": vp.VIDEO_MAX_TOKEN_NUM * factor**2,
        "video_total_pixels": pipeline.MAX_TOTAL_PIXELS,
    }
    path.write_text(json.dumps({"spec": spec, "cases": cases}))


if __name__ == "__main__":
    torch.manual_seed(0)
    write_expected(Path(sys.argv[1]))
