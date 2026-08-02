"""Tenzro TTS — speech synthesis for the network.

Protocol shape follows the rest of the repo: the Rust node owns admission,
billing, and the API surface; this package owns the model. The split is the
same one Tenzro Train and Media Gen use, and for the same reason — the model
stack is Python and pretending otherwise costs more than it saves.

What makes this modality buildable at all is that the Qwen3-TTS family takes
**raw text**. The obvious alternative needs grapheme-to-phoneme conversion,
and the standard engine for that (espeak-ng) is GPL, which cannot be linked
from an Apache-2.0 codebase. Choosing a model with no phonemizer removed the
hardest part of the problem rather than working around it.
"""

from .catalog import TtsModelEntry, get_tts_catalog, get_tts_model_by_id
from .types import (
    MAX_INPUT_CHARS,
    MAX_SPEED,
    MIN_SPEED,
    AudioFormat,
    StreamFormat,
    SynthesisRequest,
    SynthesisResult,
    VoiceInfo,
)

__all__ = [
    "MAX_INPUT_CHARS",
    "MAX_SPEED",
    "MIN_SPEED",
    "AudioFormat",
    "StreamFormat",
    "SynthesisRequest",
    "SynthesisResult",
    "TtsModelEntry",
    "VoiceInfo",
    "get_tts_catalog",
    "get_tts_model_by_id",
]
