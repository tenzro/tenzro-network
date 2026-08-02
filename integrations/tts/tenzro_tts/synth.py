"""Loading a voice model and turning text into audio.

Split from :mod:`tenzro_tts.worker` so the encode and validation paths can be
tested without torch installed — the base package deliberately does not depend
on it, and a machine driving a worker should not need a model stack to do so.
"""

from __future__ import annotations

import io
import logging
import math
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from .catalog import TtsModelEntry, get_tts_model_by_id
from .types import AudioFormat, SynthesisRequest, SynthesisResult

log = logging.getLogger("tenzro.tts.synth")


@dataclass
class LoadedVoice:
    """A model held in memory, with the entry it was built from."""

    model: Any
    entry: TtsModelEntry


def load_voice(entry: TtsModelEntry, *, device: str = "cuda", cache_dir: str | None = None):
    """Load a voice model through ``transformers``.

    Imported lazily so the module is importable — and testable — on a machine
    with no torch. A worker that cannot synthesise should fail when asked to
    synthesise, not when the package is imported.
    """
    try:
        from transformers import AutoModel
    except ImportError as exc:  # pragma: no cover - depends on the extra
        raise RuntimeError(
            "speech synthesis needs the `synth` extra: pip install 'tenzro-tts[synth]'"
        ) from exc

    log.info("loading %s from %s", entry.id, entry.hf_repo)
    model = AutoModel.from_pretrained(
        entry.hf_repo,
        trust_remote_code=True,
        cache_dir=cache_dir,
    )
    if hasattr(model, "to"):
        model = model.to(device)
    if hasattr(model, "eval"):
        model.eval()
    return LoadedVoice(model=model, entry=entry)


def encode_audio(
    samples: Any,
    sample_rate: int,
    fmt: AudioFormat,
) -> bytes:
    """Encode float samples into ``fmt``.

    ``soundfile`` writes the lossless containers natively. The compressed ones
    need an encoder; rather than pull in a second audio library, they go
    through ffmpeg, which the node's image already carries for the video path.
    """
    try:
        import numpy as np
        import soundfile as sf
    except ImportError as exc:  # pragma: no cover - depends on the extra
        raise RuntimeError(
            "encoding needs the `synth` extra: pip install 'tenzro-tts[synth]'"
        ) from exc

    samples = np.asarray(samples, dtype="float32")

    if fmt is AudioFormat.PCM:
        # Raw little-endian 16-bit, no container. What a caller streaming into
        # an audio device wants, and what OpenAI's `pcm` means.
        return (np.clip(samples, -1.0, 1.0) * 32767.0).astype("<i2").tobytes()

    subtype = {AudioFormat.WAV: "PCM_16", AudioFormat.FLAC: "PCM_16"}.get(fmt)
    if subtype is not None:
        buf = io.BytesIO()
        sf.write(buf, samples, sample_rate, format=fmt.value.upper(), subtype=subtype)
        return buf.getvalue()

    # Compressed: write lossless first, then transcode.
    wav = io.BytesIO()
    sf.write(wav, samples, sample_rate, format="WAV", subtype="PCM_16")
    return _transcode(wav.getvalue(), fmt)


def _transcode(wav_bytes: bytes, fmt: AudioFormat) -> bytes:
    """Transcode WAV to a compressed container via ffmpeg."""
    import subprocess

    codec = {
        AudioFormat.MP3: ["-codec:a", "libmp3lame", "-f", "mp3"],
        AudioFormat.OPUS: ["-codec:a", "libopus", "-f", "opus"],
        AudioFormat.AAC: ["-codec:a", "aac", "-f", "adts"],
    }[fmt]
    try:
        proc = subprocess.run(
            ["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", "pipe:0", *codec, "pipe:1"],
            input=wav_bytes,
            capture_output=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"encoding to {fmt.value} needs ffmpeg on PATH; the lossless formats "
            f"(wav, flac, pcm) need no encoder"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"ffmpeg failed encoding {fmt.value}: {exc.stderr.decode()}") from exc
    return proc.stdout


def duration_ms(sample_count: int, sample_rate: int) -> int:
    """Clip length in milliseconds."""
    if sample_rate <= 0:
        return 0
    return math.ceil(sample_count * 1000 / sample_rate)


class VoiceCache:
    """Bounded LRU over loaded voice models.

    The same reasoning as the media-gen pipeline cache: loading is the
    expensive thing, so a worker serving one voice repeatedly should pay for
    it once — but an unbounded cache turns a worker that has served several
    models into one holding all of them, and the second job of a session is
    where that shows up as an OOM rather than as a cache problem.
    """

    def __init__(self, budget_gb: float) -> None:
        self.budget_gb = budget_gb
        self._loaded: OrderedDict[str, LoadedVoice] = OrderedDict()

    def resident_gb(self) -> float:
        return sum(v.entry.min_ram_gb for v in self._loaded.values())

    def get(self, model_id: str) -> LoadedVoice | None:
        loaded = self._loaded.get(model_id)
        if loaded is not None:
            self._loaded.move_to_end(model_id)
        return loaded

    def put(self, model_id: str, loaded: LoadedVoice) -> None:
        self._evict_until_fits(loaded.entry)
        self._loaded[model_id] = loaded

    def _evict_until_fits(self, entry: TtsModelEntry) -> None:
        while self._loaded and (self.resident_gb() + entry.min_ram_gb) > self.budget_gb:
            victim_id, victim = next(iter(self._loaded.items()))
            del self._loaded[victim_id]
            self._release(victim)
            log.info("evicted voice %s to make room for %s", victim_id, entry.id)

    @staticmethod
    def _release(loaded: LoadedVoice) -> None:
        """Actually hand the memory back.

        Dropping the reference is not enough — the allocator keeps its cache,
        so an eviction that skips this frees nothing while still losing the
        model, which is strictly worse than not evicting.
        """
        import gc

        try:
            model = loaded.model
            if hasattr(model, "to"):
                try:
                    model.to("cpu")
                except Exception:  # noqa: BLE001 - best effort
                    pass
            del model
            gc.collect()
            try:
                import torch

                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except ImportError:
                pass
        except Exception as exc:  # noqa: BLE001 - eviction must not kill the worker
            log.warning("voice release did not complete cleanly: %s", exc)


def synthesize(
    loaded: LoadedVoice,
    request: SynthesisRequest,
    *,
    allow_voice_cloning: bool = False,
) -> SynthesisResult:
    """Turn ``request.input`` into audio.

    Validation runs first and includes the cloning gate, so a request the
    operator has not permitted is refused before any compute is spent on it.
    """
    request.validate(allow_voice_cloning=allow_voice_cloning)

    entry = loaded.entry
    if request.ref_audio is not None and not entry.supports_voice_cloning:
        raise ValueError(
            f"{entry.id} has no cloning path; use a checkpoint whose supports_voice_cloning is set"
        )

    model = loaded.model
    if request.ref_audio is not None:
        samples, sample_rate = model.generate_voice_clone(
            text=request.input,
            language=request.language,
            ref_audio=request.ref_audio,
            ref_text=request.ref_text,
        )
    else:
        samples, sample_rate = model.generate_custom_voice(
            text=request.input,
            language=request.language,
            speaker=request.voice,
        )

    audio = encode_audio(samples, sample_rate, request.response_format)
    return SynthesisResult(
        audio=audio,
        format=request.response_format,
        sample_rate=sample_rate,
        duration_ms=duration_ms(len(samples), sample_rate),
        model=entry.id,
    )


def resolve_entry(model_id: str) -> TtsModelEntry:
    """Look up a catalog entry or explain what is available."""
    entry = get_tts_model_by_id(model_id)
    if entry is None:
        from .catalog import get_tts_catalog

        known = ", ".join(e.id for e in get_tts_catalog())
        raise ValueError(f"unknown voice model '{model_id}'; this node serves: {known}")
    return entry
