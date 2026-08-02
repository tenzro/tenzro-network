"""The voice models this worker can serve.

Every entry was checked against the HuggingFace API before being listed:
ungated, licence recorded from the repo rather than assumed, and present under
the id given. A previous catalog effort in this repo listed three models that
no code could load and one release that did not exist, so entries here carry
what was verified rather than what was reported.

# Why these are not ONNX

The other six model runtimes in the node are ORT-backed. This one is not: the
Qwen3-TTS family ships ``safetensors`` with a ``config.json``, loaded through
``transformers``. Naming the entry type for what it is avoids the drift where
a field called ``onnx_filename`` holds something that is not ONNX.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TtsModelEntry:
    """A speech model, with what it costs and what it is allowed to do."""

    #: Catalog id used by the node and by callers.
    id: str
    #: Human-readable name.
    name: str
    #: Family, for grouping in listings.
    family: str
    #: HuggingFace repo.
    hf_repo: str
    #: Approximate on-disk size in bytes.
    size_bytes: int
    #: Minimum RAM in GB to load.
    min_ram_gb: int
    #: Output sample rate in Hz.
    sample_rate: int
    #: Languages, as the model card names them.
    languages: list[str]
    #: Licence exactly as the repo declares it.
    license: str
    #: Whether this checkpoint can clone a voice from reference audio.
    #:
    #: Recorded so an operator can see which models carry the capability
    #: before enabling it, rather than discovering it from a request.
    supports_voice_cloning: bool
    #: Preset voice ids, where the checkpoint ships them.
    preset_voices: list[str] = field(default_factory=list)
    description: str = ""


#: Languages the Qwen3-TTS family covers, per its model card.
_QWEN3_TTS_LANGS = [
    "Chinese",
    "English",
    "Japanese",
    "Korean",
    "German",
    "French",
    "Russian",
    "Portuguese",
    "Spanish",
    "Italian",
]


def get_tts_catalog() -> list[TtsModelEntry]:
    """The curated speech catalog.

    Qwen3-TTS only, for now, and deliberately so: it is Apache-2.0, ungated,
    and — the property that made this modality buildable at all — it takes raw
    text with no grapheme-to-phoneme step. The obvious alternative, Kokoro,
    needs a phonemizer, and the standard one (espeak-ng) is GPL, which rules
    it out of an Apache-2.0 codebase. The permissive G2P alternatives are
    Python-only and would have made the phonemizer the hardest part of the
    modality rather than an implementation detail.
    """
    return [
        # ── Qwen3-TTS 1.7B CustomVoice (Apache-2.0, Alibaba Qwen) ──
        # The default. Preset voices, no reference audio, so it carries none
        # of the consent questions the cloning checkpoints do.
        TtsModelEntry(
            id="qwen3-tts-1.7b",
            name="Qwen3-TTS 12Hz 1.7B CustomVoice",
            family="qwen3-tts",
            hf_repo="Qwen/Qwen3-TTS-12Hz-1.7B-CustomVoice",
            size_bytes=4_520_218_951,
            min_ram_gb=7,
            sample_rate=24_000,
            languages=list(_QWEN3_TTS_LANGS),
            license="Apache-2.0",
            supports_voice_cloning=False,
            preset_voices=["Vivian"],
            description="Ten-language speech synthesis from raw text; no phonemizer required",
        ),
        # ── Qwen3-TTS 0.6B CustomVoice (Apache-2.0) ──
        # Same shape, a third the size. The one to reach for when speech is
        # sharing a machine with a language model rather than owning it.
        TtsModelEntry(
            id="qwen3-tts-0.6b",
            name="Qwen3-TTS 12Hz 0.6B CustomVoice",
            family="qwen3-tts",
            hf_repo="Qwen/Qwen3-TTS-12Hz-0.6B-CustomVoice",
            size_bytes=2_498_388_392,
            min_ram_gb=4,
            sample_rate=24_000,
            languages=list(_QWEN3_TTS_LANGS),
            license="Apache-2.0",
            supports_voice_cloning=False,
            preset_voices=["Vivian"],
            description="Smaller Qwen3-TTS for nodes where speech shares the machine",
        ),
        # ── Qwen3-TTS 1.7B Base (Apache-2.0) ──
        # The cloning checkpoint: three seconds of reference audio plus its
        # transcript. Listed so an operator who wants it can have it, and
        # flagged so nobody enables it without meaning to — see
        # SynthesisRequest.validate, which refuses reference audio unless the
        # operator has opted in.
        TtsModelEntry(
            id="qwen3-tts-1.7b-clone",
            name="Qwen3-TTS 12Hz 1.7B Base",
            family="qwen3-tts",
            hf_repo="Qwen/Qwen3-TTS-12Hz-1.7B-Base",
            size_bytes=4_544_229_700,
            min_ram_gb=7,
            sample_rate=24_000,
            languages=list(_QWEN3_TTS_LANGS),
            license="Apache-2.0",
            supports_voice_cloning=True,
            preset_voices=[],
            description="Voice cloning from ~3s of reference audio and its transcript; "
            "requires an explicit operator opt-in",
        ),
    ]


def get_tts_model_by_id(model_id: str) -> TtsModelEntry | None:
    """Look up an entry, or ``None`` if this node does not know it."""
    return next((e for e in get_tts_catalog() if e.id == model_id), None)
