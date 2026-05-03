"""Tenzro Train reference trainer (Python).

Inner training loops for Decoupled DiLoCo over PyTorch FSDP2 +
Hivemind + safetensors. Coordinates with the Rust syncer in
``crates/tenzro-training`` over JSON-RPC.

See :mod:`tenzro_trainer.types` for the wire formats and
:mod:`tenzro_trainer.rpc_bridge` for the JSON-RPC client.
"""

from tenzro_trainer.types import (
    AggregationRule,
    ArchitectureSpec,
    OuterGradient,
    TrainingAttestation,
    TrainingModality,
    TrainingTier,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AggregationRule",
    "ArchitectureSpec",
    "OuterGradient",
    "TrainingAttestation",
    "TrainingModality",
    "TrainingTier",
]
