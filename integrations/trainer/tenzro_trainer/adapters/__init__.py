"""Modality-specific trainer adapters.

Phase 1 covers:

* :mod:`tenzro_trainer.adapters.timeseries` — lead modality (TimesFM-class).
* :mod:`tenzro_trainer.adapters.language` — Qwen 3 0.6B (default) and any
  catalog-member HF causal-LM family via ``architecture.metadata.hf_repo``.
* :mod:`tenzro_trainer.adapters.vision` — timm ViT-B/16 (default) and any
  catalog-member ViT family via ``architecture.metadata.timm_model``.

Each module exposes a ``build_adapter(architecture, hyperparams) -> TrainerAdapter``
factory that the CLI dispatches to based on ``architecture.modality``.
"""

from tenzro_trainer.adapters import language, timeseries, vision

__all__ = ["language", "timeseries", "vision"]
