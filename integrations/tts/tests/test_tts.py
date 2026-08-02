"""Tests for the speech worker.

Everything here runs without torch. The base package deliberately does not
depend on it, and the validation, catalog, and cache-policy decisions are
where the judgement lives — the model call itself is one line handed to
transformers.
"""

from __future__ import annotations

import pytest

from tenzro_tts.catalog import get_tts_catalog, get_tts_model_by_id
from tenzro_tts.synth import VoiceCache, duration_ms, resolve_entry
from tenzro_tts.types import (
    MAX_INPUT_CHARS,
    AudioFormat,
    StreamFormat,
    SynthesisRequest,
    SynthesisResult,
)


def request(**overrides) -> SynthesisRequest:
    base = {
        "model": "qwen3-tts-1.7b",
        "input": "Hello there.",
        "voice": "Vivian",
    }
    base.update(overrides)
    return SynthesisRequest(**base)


# ── validation ────────────────────────────────────────────────────────────


def test_a_plain_request_validates() -> None:
    request().validate()


def test_empty_input_is_rejected() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        request(input="   ").validate()


def test_input_past_the_documented_limit_is_rejected() -> None:
    # The cap belongs here, not only at the model: synthesis time scales with
    # input length, so an unbounded request is an unbounded hold on a
    # concurrency slot.
    with pytest.raises(ValueError, match="the limit is"):
        request(input="a" * (MAX_INPUT_CHARS + 1)).validate()
    request(input="a" * MAX_INPUT_CHARS).validate()


@pytest.mark.parametrize("speed", [0.24, 4.01, 0.0, -1.0])
def test_speed_outside_the_openai_range_is_rejected(speed: float) -> None:
    with pytest.raises(ValueError, match="speed must be"):
        request(speed=speed).validate()


@pytest.mark.parametrize("speed", [0.25, 1.0, 4.0])
def test_speed_inside_the_range_is_accepted(speed: float) -> None:
    request(speed=speed).validate()


# ── voice cloning gate ────────────────────────────────────────────────────


def test_voice_cloning_is_refused_unless_the_operator_opted_in() -> None:
    # Picking a model family that happens to support cloning must not be the
    # same act as offering cloning to callers. Consent and impersonation are
    # the operator's problem, so it is the operator's switch.
    with pytest.raises(PermissionError, match="operator must opt in"):
        request(ref_audio=b"\x00" * 16, ref_text="hi").validate()


def test_voice_cloning_works_once_enabled() -> None:
    request(ref_audio=b"\x00" * 16, ref_text="hi").validate(allow_voice_cloning=True)


def test_cloning_needs_both_the_audio_and_its_transcript() -> None:
    # The model conditions on the pair; half of it is a request that cannot
    # be served, and failing here is clearer than failing inside the model.
    with pytest.raises(ValueError, match="ref_text"):
        request(ref_audio=b"\x00" * 16).validate(allow_voice_cloning=True)
    with pytest.raises(ValueError, match="ref_audio"):
        request(ref_text="hi").validate(allow_voice_cloning=True)


def test_the_cloning_gate_fires_before_the_shape_check() -> None:
    # A node with cloning disabled should say "not enabled" rather than
    # leaking that the request was also malformed — the first is the reason
    # it will never work here.
    with pytest.raises(PermissionError):
        request(ref_audio=b"\x00").validate(allow_voice_cloning=False)


# ── formats ───────────────────────────────────────────────────────────────


def test_lossless_formats_need_no_external_encoder() -> None:
    for fmt in (AudioFormat.WAV, AudioFormat.FLAC, AudioFormat.PCM):
        assert fmt.is_lossless
        assert not fmt.needs_ffmpeg


def test_compressed_formats_declare_their_ffmpeg_dependency() -> None:
    # Worth surfacing: a node without ffmpeg can still serve wav/flac/pcm,
    # and should say so rather than failing at encode time.
    for fmt in (AudioFormat.MP3, AudioFormat.OPUS, AudioFormat.AAC):
        assert not fmt.is_lossless
        assert fmt.needs_ffmpeg


def test_the_default_format_is_the_one_every_browser_plays() -> None:
    assert request().response_format is AudioFormat.MP3
    assert request().stream_format is StreamFormat.AUDIO


# ── catalog ───────────────────────────────────────────────────────────────


def test_every_catalog_entry_is_apache_licensed_and_complete() -> None:
    catalog = get_tts_catalog()
    assert catalog, "the catalog must not be empty"
    for e in catalog:
        assert e.license == "Apache-2.0", f"{e.id} is {e.license}"
        assert e.hf_repo.startswith("Qwen/"), e.hf_repo
        assert e.size_bytes > 0 and e.min_ram_gb > 0
        assert e.sample_rate > 0
        assert "English" in e.languages


def test_cloning_capability_is_recorded_per_checkpoint() -> None:
    # An operator should be able to see which models carry the capability
    # before enabling it, rather than discovering it from a request.
    by_id = {e.id: e for e in get_tts_catalog()}
    assert by_id["qwen3-tts-1.7b"].supports_voice_cloning is False
    assert by_id["qwen3-tts-1.7b-clone"].supports_voice_cloning is True


def test_preset_voice_models_ship_at_least_one_voice() -> None:
    for e in get_tts_catalog():
        if not e.supports_voice_cloning:
            assert e.preset_voices, f"{e.id} has no voice to speak with"


def test_an_unknown_model_says_what_is_available() -> None:
    with pytest.raises(ValueError, match="this node serves"):
        resolve_entry("not-a-model")
    assert resolve_entry("qwen3-tts-1.7b").id == "qwen3-tts-1.7b"
    assert get_tts_model_by_id("nope") is None


# ── cache policy ──────────────────────────────────────────────────────────


def _fake(entry_id: str, ram_gb: int):
    from tenzro_tts.catalog import TtsModelEntry
    from tenzro_tts.synth import LoadedVoice

    class Dummy:
        def to(self, _device):
            return self

    return LoadedVoice(
        model=Dummy(),
        entry=TtsModelEntry(
            id=entry_id,
            name=entry_id,
            family="test",
            hf_repo="Qwen/test",
            size_bytes=1,
            min_ram_gb=ram_gb,
            sample_rate=24_000,
            languages=["English"],
            license="Apache-2.0",
            supports_voice_cloning=False,
        ),
    )


def test_the_voice_cache_is_bounded() -> None:
    # Same failure the media-gen cache had: a worker that has served several
    # models ends up holding all of them, and it surfaces as an OOM on a
    # later job rather than as a cache problem.
    cache = VoiceCache(budget_gb=8)
    cache.put("a", _fake("a", 6))
    cache.put("b", _fake("b", 6))
    assert cache.get("a") is None, "the first should have been evicted"
    assert cache.get("b") is not None


def test_models_that_fit_together_are_both_kept() -> None:
    cache = VoiceCache(budget_gb=8)
    cache.put("a", _fake("a", 3))
    cache.put("b", _fake("b", 3))
    assert cache.get("a") is not None
    assert cache.get("b") is not None


def test_eviction_is_least_recently_used() -> None:
    cache = VoiceCache(budget_gb=9)
    cache.put("a", _fake("a", 4))
    cache.put("b", _fake("b", 4))
    cache.get("a")  # touch a, making b oldest
    cache.put("c", _fake("c", 4))
    assert cache.get("a") is not None
    assert cache.get("b") is None


def test_release_never_raises_on_a_hostile_model() -> None:
    # Eviction runs on the request path; a model whose `.to()` throws must not
    # take the worker down, since it is being discarded anyway.
    class Hostile:
        def to(self, _device):
            raise RuntimeError("gone")

    from tenzro_tts.catalog import TtsModelEntry
    from tenzro_tts.synth import LoadedVoice

    victim = LoadedVoice(
        model=Hostile(),
        entry=TtsModelEntry(
            id="h",
            name="h",
            family="t",
            hf_repo="Qwen/t",
            size_bytes=1,
            min_ram_gb=8,
            sample_rate=24_000,
            languages=["English"],
            license="Apache-2.0",
            supports_voice_cloning=False,
        ),
    )
    cache = VoiceCache(budget_gb=8)
    cache.put("h", victim)
    cache.put("next", _fake("next", 8))
    assert cache.get("h") is None


# ── misc ──────────────────────────────────────────────────────────────────


def test_duration_is_reported_for_billing() -> None:
    assert duration_ms(24_000, 24_000) == 1000
    assert duration_ms(12_000, 24_000) == 500
    assert duration_ms(0, 24_000) == 0
    # A zero sample rate must not divide by zero.
    assert duration_ms(1000, 0) == 0


def test_a_result_must_actually_carry_audio() -> None:
    # An empty body reaching a caller as a 200 is worse than an error.
    with pytest.raises(ValueError, match="must carry audio"):
        SynthesisResult(
            audio=b"",
            format=AudioFormat.MP3,
            sample_rate=24_000,
            duration_ms=0,
            model="qwen3-tts-1.7b",
        )
