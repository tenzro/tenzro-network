"""Vision trainer adapter — ViT-B/16 family.

This is the real inner-loop driver for ViT-class image training under
Decoupled DiLoCo. The default backbone is **timm ViT-B/16**
(``vit_base_patch16_224``), which is the architecture family our
inference-side vision encoders share — DINOv3 ViT-B/16, SigLIP2-base, and
CLIP ViT-B/16 in ``crates/tenzro-model/src/catalog.rs`` all use the
same ViT-B/16 backbone. A trained outer-gradient root can be slotted
directly into the serving fleet's image-encoder slot.

Other catalog-member ViT sizes (ViT-S/16, ViT-L/16) drop in by changing
``architecture.metadata.timm_model``.

Wraps cleanly under :class:`torch.distributed.fsdp.FullyShardedDataParallel`
(FSDP2) when the caller has initialized a process group — see
``docs/AI.md §7.7.1``. Plain DDP and single-GPU paths work out of the box.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:
    import torch
    from torch import nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


from tenzro_trainer.muon import build_inner_optimizer

log = logging.getLogger(__name__)


# Default backbone for the vision adapter — ``vit_base_patch16_224`` is the
# architecture family of the inference-side ViT-B/16 encoders in the
# Tenzro vision catalog (DINOv3 ViT-B/16, SigLIP2-base, CLIP ViT-B/16).
DEFAULT_TIMM_MODEL = "vit_base_patch16_224"

# ImageNet-1k mean/std — the right normalization for any ImageNet-pretrained
# ViT (``vit_base_patch16_224`` ships with these). DINOv3/SigLIP2/CLIP have
# their own normalization stats; override via ``architecture.metadata.mean``
# and ``architecture.metadata.std`` (3 floats each) when fine-tuning from
# those checkpoints.
IMAGENET_MEAN = (0.485, 0.456, 0.406)
IMAGENET_STD = (0.229, 0.224, 0.225)


@dataclass
class VisionAdapter:
    """Real timm-backed ViT adapter.

    Loads the backbone once at construction; ``shard_batches`` walks an
    ImageFolder-style shard (``<root>/<class_name>/*.{jpg,jpeg,png,webp}``),
    decodes images with Pillow, resizes/center-crops to ``img_size``, applies
    ImageNet normalization, and yields ``(images, labels)`` batches. Standard
    cross-entropy classification loss.
    """

    _model: "nn.Module"
    _optimizer: "torch.optim.Optimizer"
    img_size: int = 224
    batch_size: int = 8
    device: str = "cpu"
    mean: tuple[float, float, float] = IMAGENET_MEAN
    std: tuple[float, float, float] = IMAGENET_STD
    _class_to_idx: dict[str, int] = field(default_factory=dict)

    def model(self) -> "nn.Module":
        return self._model

    def optimizer(self) -> "torch.optim.Optimizer":
        return self._optimizer

    def shard_batches(self, shard_uri: str) -> Iterable[object]:
        if torch is None:
            raise RuntimeError("PyTorch is required")
        # Resolve the shard URI. Confidential-tier shards arrive
        # pre-decrypted as `file://` pointers into an enclave-private
        # tmpfs; see `tenzro_trainer.confidential.unwrap_shard`.
        if shard_uri.startswith("file://"):
            root = Path(shard_uri[len("file://") :])
        elif shard_uri.startswith(("ipfs://", "ar://", "https://", "http://")):
            raise NotImplementedError(
                f"remote shard scheme not supported in reference trainer "
                f"(fetch upstream, expose as file:// or via the confidential "
                f"unwrap helper): {shard_uri}"
            )
        else:
            root = Path(shard_uri)

        if not root.is_dir():
            raise ValueError(
                f"vision shard {root!r} must be an ImageFolder-style directory "
                f"(<root>/<class_name>/*.{{jpg,jpeg,png,webp}})"
            )

        samples = _scan_image_folder(root, self._class_to_idx)
        if not samples:
            raise ValueError(f"vision shard {root!r} contains no images")
        log.info(
            "vision shard %r: %d images across %d classes",
            str(root),
            len(samples),
            len(self._class_to_idx),
        )

        # Reseed deterministically so a single shard always yields the same
        # batch sequence across resumes — the outer-loop syncer assumes
        # inner steps are reproducible given (shard_uri, step_count).
        rng = torch.Generator()
        rng.manual_seed(0)
        n = len(samples)
        while True:
            offsets = torch.randint(0, n, (self.batch_size,), generator=rng).tolist()
            imgs = []
            labels = []
            for o in offsets:
                path, label = samples[o]
                imgs.append(_load_and_preprocess(path, self.img_size, self.mean, self.std))
                labels.append(label)
            x = torch.stack(imgs)
            y = torch.tensor(labels, dtype=torch.long)
            yield x.to(self.device), y.to(self.device)

    def compute_loss(self, batch: object) -> "torch.Tensor":
        if torch is None:
            raise RuntimeError("PyTorch is required")
        x, y = batch  # type: ignore[misc]
        logits = self._model(x)
        return torch.nn.functional.cross_entropy(logits, y)


def _scan_image_folder(
    root: Path, class_to_idx: dict[str, int]
) -> list[tuple[Path, int]]:
    """Walk an ImageFolder-style directory; populate ``class_to_idx`` in place.

    Subdirectory names (sorted lexicographically) are class labels. The
    ``class_to_idx`` mapping is built on first scan and reused on
    subsequent shards so label IDs are stable across shards of the same
    dataset.
    """
    exts = {".jpg", ".jpeg", ".png", ".webp"}
    classes = sorted(p.name for p in root.iterdir() if p.is_dir())
    if not classes:
        return []
    for c in classes:
        class_to_idx.setdefault(c, len(class_to_idx))
    samples: list[tuple[Path, int]] = []
    for c in classes:
        idx = class_to_idx[c]
        for p in sorted((root / c).iterdir()):
            if p.suffix.lower() in exts and p.is_file():
                samples.append((p, idx))
    return samples


def _load_and_preprocess(
    path: Path,
    img_size: int,
    mean: tuple[float, float, float],
    std: tuple[float, float, float],
) -> "torch.Tensor":
    """Decode → resize-shortest → center-crop → normalize → CHW float tensor."""
    try:
        from PIL import Image
    except ImportError as e:
        raise ImportError(
            "The vision adapter requires the `Pillow` package. "
            "Install with: `pip install tenzro-trainer[vision]`"
        ) from e

    img = Image.open(path).convert("RGB")
    # Resize so the shortest side == img_size, then center-crop to square.
    w, h = img.size
    if w < h:
        new_w, new_h = img_size, int(round(h * img_size / w))
    else:
        new_w, new_h = int(round(w * img_size / h)), img_size
    img = img.resize((new_w, new_h), Image.BICUBIC)
    left = (new_w - img_size) // 2
    top = (new_h - img_size) // 2
    img = img.crop((left, top, left + img_size, top + img_size))

    # PIL → CHW float tensor in [0, 1], then ImageNet-normalize.
    t = torch.from_numpy(_pil_to_array(img)).permute(2, 0, 1).contiguous().float() / 255.0
    mean_t = torch.tensor(mean, dtype=t.dtype).view(3, 1, 1)
    std_t = torch.tensor(std, dtype=t.dtype).view(3, 1, 1)
    return (t - mean_t) / std_t


def _pil_to_array(img: Any) -> Any:
    """PIL Image → numpy uint8 array, lazy-import numpy."""
    import numpy as np

    return np.asarray(img, dtype="uint8")


def build_adapter(
    architecture: dict[str, Any],
    hyperparams: dict[str, Any] | None = None,
) -> VisionAdapter:
    """Construct a timm ViT-B/16 (or other catalog-family ViT) adapter.

    Reads ``architecture.metadata.timm_model`` (default ``vit_base_patch16_224``),
    ``architecture.metadata.num_classes`` (default 1000 — ImageNet-1k),
    ``architecture.metadata.img_size`` (default 224),
    ``architecture.metadata.pretrained`` (default ``True`` — fine-tune from
    ImageNet weights), and optional ``architecture.metadata.mean`` / ``std``
    (3-float tuples; override for DINOv3/SigLIP2/CLIP normalization).

    Hyperparams accepted:

    * ``inner_optimizer`` (``muon`` | ``adamw`` | ``sgd``, default ``adamw``)
    * ``learning_rate`` (default 3e-5 — fine-tune scale for pretrained ViT)
    * ``weight_decay`` (default 0.05 — standard ViT recipe)
    * ``batch_size`` (default 8)
    * ``device`` (default ``"cuda"`` if available else ``"cpu"``)
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    try:
        import timm
    except ImportError as e:
        raise ImportError(
            "The vision adapter requires the `timm` package. "
            "Install with: `pip install tenzro-trainer[vision]`"
        ) from e

    md = (architecture or {}).get("metadata") or {}
    hp = hyperparams or {}
    timm_model = str(md.get("timm_model") or DEFAULT_TIMM_MODEL)
    num_classes = int(md.get("num_classes", 1000))
    img_size = int(md.get("img_size", 224))
    pretrained = bool(md.get("pretrained", True))
    mean = tuple(md.get("mean", IMAGENET_MEAN))  # type: ignore[assignment]
    std = tuple(md.get("std", IMAGENET_STD))  # type: ignore[assignment]
    if len(mean) != 3 or len(std) != 3:
        raise ValueError(
            f"vision adapter: mean/std must be 3-tuples, got mean={mean}, std={std}"
        )
    device = str(hp.get("device") or ("cuda" if torch.cuda.is_available() else "cpu"))

    log.info(
        "loading timm vision backbone %r (num_classes=%d, img_size=%d, pretrained=%s, device=%s) ...",
        timm_model,
        num_classes,
        img_size,
        pretrained,
        device,
    )
    model = timm.create_model(
        timm_model,
        pretrained=pretrained,
        num_classes=num_classes,
        img_size=img_size,
    ).to(device)

    opt = build_inner_optimizer(
        model, md, hp, default_lr=3e-5, default_weight_decay=0.05
    )
    log.info(
        "built vision adapter %r: %d params",
        timm_model,
        sum(p.numel() for p in model.parameters()),
    )
    return VisionAdapter(
        _model=model,
        _optimizer=opt,
        img_size=img_size,
        batch_size=int(hp.get("batch_size", 8)),
        device=device,
        mean=mean,  # type: ignore[arg-type]
        std=std,  # type: ignore[arg-type]
    )


__all__ = ["VisionAdapter", "build_adapter", "DEFAULT_TIMM_MODEL"]
