"""Hardware acceleration selection for the language adapter.

Two knobs, both automatic with metadata overrides:

- attention kernel: FlashAttention-2 when the ``flash_attn`` package is
  importable and a CUDA device is present, otherwise PyTorch SDPA. Override
  via ``architecture.metadata.attn_implementation``.
- FP8 training: torchao ``convert_to_float8_training`` on Ada/Hopper-class
  GPUs (compute capability >= 8.9) when ``architecture.metadata.fp8`` is
  truthy. Embedding and head modules are skipped, as are linear layers whose
  dimensions are not multiples of 16 (a hard FP8 kernel requirement).
"""

from __future__ import annotations

import importlib.util
import logging
from typing import Any, Dict

try:
    import torch
    import torch.nn as nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_FP8_SKIP_NAME_TAGS = ("embed", "lm_head", "wte", "wpe", "head")


def resolve_attn_implementation(metadata: Dict[str, Any]) -> str:
    """Pick the attention kernel to request from ``from_pretrained``."""
    override = metadata.get("attn_implementation")
    if isinstance(override, str) and override:
        return override
    if (
        torch is not None
        and torch.cuda.is_available()
        and importlib.util.find_spec("flash_attn")
    ):
        return "flash_attention_2"
    return "sdpa"


def _fp8_capable() -> bool:
    if torch is None or not torch.cuda.is_available():
        return False
    major, minor = torch.cuda.get_device_capability()
    return (major, minor) >= (8, 9)


def _fp8_module_filter(module: "nn.Module", fqn: str) -> bool:
    if not isinstance(module, nn.Linear):
        return False
    lowered = fqn.lower()
    if any(tag in lowered for tag in _FP8_SKIP_NAME_TAGS):
        return False
    return module.in_features % 16 == 0 and module.out_features % 16 == 0


def maybe_convert_fp8(model: "nn.Module", metadata: Dict[str, Any]) -> "nn.Module":
    """Convert eligible linear layers to FP8 training when requested.

    No-op (with a log line explaining why) when FP8 is not requested, the
    GPU is not Ada/Hopper-class, or torchao is not installed.
    """
    requested = metadata.get("fp8")
    if not requested or str(requested).lower() in ("0", "false", "no"):
        return model
    if not _fp8_capable():
        logger.info(
            "fp8 requested but no CUDA device with compute capability >= 8.9; "
            "continuing without fp8"
        )
        return model
    try:
        from torchao.float8 import convert_to_float8_training
    except ImportError:
        logger.info(
            "fp8 requested but torchao is not installed "
            "(pip install 'tenzro-trainer[fp8]'); continuing without fp8"
        )
        return model

    convert_to_float8_training(model, module_filter_fn=_fp8_module_filter)
    logger.info("fp8 training enabled via torchao convert_to_float8_training")
    return model
