"""Wire types for speech synthesis.

Shaped to the OpenAI ``/v1/audio/speech`` contract, because that is what every
SDK and app already speaks. The node's REST surface projects these directly;
the JSON-RPC surface carries the same fields.

The one thing worth stating up front: the endpoint returns **raw audio bytes**,
not JSON. That is the part SDK authors most often get wrong, and it is why
:class:`SynthesisResult` carries ``audio`` as bytes with the container recorded
separately rather than base64 inside a JSON envelope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AudioFormat(str, Enum):
    """Container the synthesised audio is returned in.

    Mirrors OpenAI's ``response_format``. ``mp3`` is the default there and
    here, because it is the one every browser plays without negotiation.
    """

    MP3 = "mp3"
    OPUS = "opus"
    AAC = "aac"
    FLAC = "flac"
    WAV = "wav"
    PCM = "pcm"

    @property
    def is_lossless(self) -> bool:
        return self in (AudioFormat.FLAC, AudioFormat.WAV, AudioFormat.PCM)

    @property
    def needs_ffmpeg(self) -> bool:
        """Whether writing this container shells out to ffmpeg.

        ``soundfile`` covers the lossless set natively. The compressed ones
        need an encoder, and the node's image already carries ffmpeg for the
        video path — so this is a dependency note, not a new requirement.
        """
        return self in (AudioFormat.MP3, AudioFormat.OPUS, AudioFormat.AAC)


class StreamFormat(str, Enum):
    """How the audio reaches the caller."""

    #: One response body containing the whole clip.
    AUDIO = "audio"
    #: Server-sent events, so a caller can start playing before synthesis ends.
    SSE = "sse"


#: Ceiling on a single request's input, in characters.
#:
#: Matches OpenAI's documented limit. A cap belongs here rather than only at
#: the model, because synthesis time scales with input length and an unbounded
#: request is an unbounded hold on a concurrency slot.
MAX_INPUT_CHARS = 4096

#: Speed multiplier bounds, matching OpenAI's ``speed`` parameter.
MIN_SPEED = 0.25
MAX_SPEED = 4.0


@dataclass
class SynthesisRequest:
    """One request to turn text into speech."""

    #: Catalog id of the voice model.
    model: str
    #: The text to speak. Raw text — the Qwen3-TTS family needs no phonemes.
    input: str
    #: Named preset voice.
    voice: str
    #: Language hint. The model card takes an English language name
    #: ("English", "Chinese") rather than a BCP-47 tag.
    language: str = "English"
    #: Free-form direction on delivery. Not supported by every model.
    instructions: str | None = None
    response_format: AudioFormat = AudioFormat.MP3
    speed: float = 1.0
    stream_format: StreamFormat = StreamFormat.AUDIO

    #: Reference audio for voice cloning, as raw bytes.
    #:
    #: Cloning a voice from a sample has consent and impersonation
    #: consequences that a preset voice does not, so it is a separate field an
    #: operator can refuse to accept rather than a variation on ``voice``.
    #: See :meth:`validate`.
    ref_audio: bytes | None = None
    #: Transcript of ``ref_audio``. The clone path needs both.
    ref_text: str | None = None

    def validate(self, *, allow_voice_cloning: bool = False) -> None:
        """Reject a request that cannot be served, or must not be.

        ``allow_voice_cloning`` is the operator's switch. It defaults to
        **off**: picking a model family that happens to support cloning should
        not be the same act as offering cloning to callers.
        """
        if not self.input.strip():
            raise ValueError("input must not be empty")
        if len(self.input) > MAX_INPUT_CHARS:
            raise ValueError(
                f"input is {len(self.input)} characters; the limit is {MAX_INPUT_CHARS}"
            )
        if not MIN_SPEED <= self.speed <= MAX_SPEED:
            raise ValueError(f"speed must be between {MIN_SPEED} and {MAX_SPEED}")

        cloning = self.ref_audio is not None or self.ref_text is not None
        if cloning:
            if not allow_voice_cloning:
                raise PermissionError(
                    "voice cloning is not enabled on this node; the operator must opt in "
                    "before reference audio is accepted"
                )
            if self.ref_audio is None or self.ref_text is None:
                raise ValueError(
                    "voice cloning needs both ref_audio and its transcript ref_text; "
                    "the model conditions on the pair"
                )


@dataclass
class SynthesisResult:
    """Synthesised speech."""

    #: The encoded audio. Raw bytes, not base64 — see the module docstring.
    audio: bytes
    #: Container the bytes are in.
    format: AudioFormat
    #: Sample rate in Hz.
    sample_rate: int
    #: Duration in milliseconds, for billing and for a caller sizing a buffer.
    duration_ms: int
    #: Which model produced it.
    model: str

    def __post_init__(self) -> None:
        if not self.audio:
            raise ValueError("a synthesis result must carry audio")


@dataclass
class VoiceInfo:
    """A preset voice a model offers."""

    id: str
    name: str
    languages: list[str] = field(default_factory=list)
    description: str = ""
