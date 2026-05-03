"""Modality-specific trainer adapters.

Phase 1 ships:

* :mod:`tenzro_trainer.adapters.timeseries` — lead modality (TimesFM-class).
* :mod:`tenzro_trainer.adapters.language` — stub harness for decoder-only LMs.
* :mod:`tenzro_trainer.adapters.vision` — stub harness for ViT/ConvNeXt.

Each module exposes a ``build_adapter(architecture, hyperparams) -> TrainerAdapter``
factory that the CLI dispatches to based on ``architecture.modality``.
"""

from tenzro_trainer.adapters import language, timeseries, vision

__all__ = ["language", "timeseries", "vision"]
