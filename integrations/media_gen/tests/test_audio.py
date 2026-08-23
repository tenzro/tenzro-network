"""Tests for the audio encode path.

Written against the WAV bytes rather than against the encoder's internals,
because every failure mode here is silent: wrong sample rate changes pitch and
duration, wrong channel orientation swaps left and right or produces noise,
and unclipped float wraps a peak to full-scale negative and arrives as a click.
None of those raise.
"""
from __future__ import annotations

import io
import wave

import numpy as np
import pytest

from tenzro_media_gen.pipelines import (
    DEFAULT_AUDIO_SAMPLE_RATE,
    _audio_from_output,
    _encode_audio_bytes,
)


def _read(b: bytes):
    with wave.open(io.BytesIO(b), "rb") as w:
        return {
            "channels": w.getnchannels(),
            "width": w.getsampwidth(),
            "rate": w.getframerate(),
            "frames": w.getnframes(),
            "pcm": np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16),
        }


def test_mono_float_round_trips_at_the_requested_rate():
    samples = np.zeros(1000, dtype=np.float32)
    got = _read(_encode_audio_bytes(samples, 32_000))
    assert got["channels"] == 1
    assert got["width"] == 2, "must be 16-bit PCM"
    assert got["rate"] == 32_000
    assert got["frames"] == 1000


def test_duration_is_preserved():
    """A second of audio must stay a second. Sample count and rate together
    are the duration, so getting either wrong silently changes the artifact."""
    rate = 32_000
    got = _read(_encode_audio_bytes(np.zeros(rate * 3, dtype=np.float32), rate))
    assert got["frames"] / got["rate"] == pytest.approx(3.0)


def test_stereo_is_interleaved_not_planar():
    """WAV is interleaved. Writing planar produces a file that plays as the
    left channel followed by the right, which sounds like a glitch rather
    than an error."""
    left = np.full(4, 0.5, dtype=np.float32)
    right = np.full(4, -0.5, dtype=np.float32)
    got = _read(_encode_audio_bytes(np.stack([left, right]), 32_000))
    assert got["channels"] == 2
    assert got["frames"] == 4
    # Interleaved means alternating, starting with left.
    assert got["pcm"][0] > 0 and got["pcm"][1] < 0
    assert got["pcm"][2] > 0 and got["pcm"][3] < 0


def test_samples_by_channels_orientation_is_detected():
    """Some pipelines hand back (samples, channels). Channels are the small
    axis either way, so the encoder orients by that rather than trusting
    the order."""
    arr = np.zeros((1000, 2), dtype=np.float32)  # samples-major
    got = _read(_encode_audio_bytes(arr, 32_000))
    assert got["channels"] == 2
    assert got["frames"] == 1000


def test_a_peak_above_unity_clips_rather_than_wrapping():
    """1.5 scaled without clipping overflows int16 and wraps to a large
    negative — a loud click exactly where the audio was loudest."""
    got = _read(_encode_audio_bytes(np.array([1.5, -1.5], dtype=np.float32), 32_000))
    assert got["pcm"][0] == 32767
    assert got["pcm"][1] == -32767


def test_a_batch_dimension_is_dropped():
    got = _read(_encode_audio_bytes(np.zeros((1, 2, 500), dtype=np.float32), 32_000))
    assert got["channels"] == 2
    assert got["frames"] == 500


def test_an_unusable_shape_is_refused():
    with pytest.raises(ValueError):
        _encode_audio_bytes(np.zeros((2, 2, 2, 2), dtype=np.float32), 32_000)


class _Out:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def test_the_pipelines_disagreeing_attribute_names_are_all_accepted():
    for attr in ("audios", "audio", "waveforms", "waveform"):
        audio, rate = _audio_from_output(_Out(**{attr: [1, 2, 3]}))
        assert audio == [1, 2, 3]
        assert rate == DEFAULT_AUDIO_SAMPLE_RATE


def test_a_reported_sample_rate_is_believed_over_the_default():
    """The fallback exists for pipelines that report nothing. One that does
    report must win, or its output is written at the wrong pitch."""
    for attr in ("sampling_rate", "sample_rate"):
        _, rate = _audio_from_output(_Out(audios=[0], **{attr: 44_100}))
        assert rate == 44_100


def test_output_with_no_audio_is_a_clear_error():
    with pytest.raises(ValueError, match="no recognisable audio"):
        _audio_from_output(_Out(images=[0]))
