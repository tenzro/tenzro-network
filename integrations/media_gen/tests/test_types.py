"""Wire shapes and admission rules.

``validate_for`` runs locally so a malformed job fails before the round trip;
the node re-checks the same bounds at admission. Both sides have to agree, so
each case below matches a branch of ``MediaGenParams::validate_for`` in
``crates/tenzro-types/src/media_gen.rs``.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from tenzro_media_gen.types import (
    MAX_MEDIA_GEN_DIMENSION,
    MAX_MEDIA_GEN_FRAMES,
    MAX_MEDIA_GEN_PROMPT_BYTES,
    MAX_MEDIA_GEN_STEPS,
    MediaGenAssignment,
    MediaGenExpertHolding,
    MediaGenExpertRole,
    MediaGenJob,
    MediaGenKind,
    MediaGenParams,
    MediaGenReceipt,
    MediaGenStatus,
    MediaGenTaskSpec,
    MediaGenWorkerCapability,
    Signature,
)

ZERO_ADDRESS = bytes(32)


def video_params(**overrides) -> MediaGenParams:
    base = dict(
        prompt="a fox walking",
        width=1280,
        height=720,
        steps=40,
        guidance_scale=4.0,
        num_frames=81,
        fps=16,
    )
    base.update(overrides)
    return MediaGenParams(**base)


# ---------------------------------------------------------------------------
# Enum properties
# ---------------------------------------------------------------------------


def test_kind_labels_match_the_rust_serde_labels():
    assert [k.value for k in MediaGenKind] == [
        "text2image",
        "image2image",
        "text2video",
        "image2video",
    ]


def test_kinds_declare_their_own_requirements():
    assert MediaGenKind.IMAGE2IMAGE.requires_input_image
    assert MediaGenKind.IMAGE2VIDEO.requires_input_image
    assert not MediaGenKind.TEXT2IMAGE.requires_input_image
    assert MediaGenKind.TEXT2VIDEO.is_video
    assert MediaGenKind.IMAGE2VIDEO.is_video
    assert not MediaGenKind.IMAGE2IMAGE.is_video


def test_only_the_three_end_states_are_terminal():
    terminal = {s for s in MediaGenStatus if s.is_terminal}
    assert terminal == {
        MediaGenStatus.COMPLETED,
        MediaGenStatus.FAILED,
        MediaGenStatus.CANCELLED,
    }


def test_expert_roles_are_each_other_s_partner():
    assert MediaGenExpertRole.HIGH_NOISE.partner is MediaGenExpertRole.LOW_NOISE
    assert MediaGenExpertRole.LOW_NOISE.partner is MediaGenExpertRole.HIGH_NOISE


# ---------------------------------------------------------------------------
# Admission
# ---------------------------------------------------------------------------


def test_a_well_formed_image_job_validates(params):
    params.validate_for(MediaGenKind.TEXT2IMAGE)


def test_a_well_formed_video_job_validates():
    video_params().validate_for(MediaGenKind.TEXT2VIDEO)


@pytest.mark.parametrize("prompt", ["", "   ", "\n\t"])
def test_an_empty_prompt_is_rejected(params, prompt):
    with pytest.raises(ValueError, match="prompt must not be empty"):
        replace(params, prompt=prompt).validate_for(MediaGenKind.TEXT2IMAGE)


def test_an_oversize_prompt_is_rejected(params):
    long = "x" * (MAX_MEDIA_GEN_PROMPT_BYTES + 1)
    with pytest.raises(ValueError, match="maximum length"):
        replace(params, prompt=long).validate_for(MediaGenKind.TEXT2IMAGE)


def test_the_prompt_bound_counts_utf8_bytes_not_characters(params):
    # Two bytes per character, so half the byte budget plus one overflows it.
    long = "é" * (MAX_MEDIA_GEN_PROMPT_BYTES // 2 + 1)
    with pytest.raises(ValueError, match="maximum length"):
        replace(params, prompt=long).validate_for(MediaGenKind.TEXT2IMAGE)


@pytest.mark.parametrize(
    ("width", "height"),
    [(0, 512), (512, 0), (-1, 512), (512, -1)],
)
def test_non_positive_dimensions_are_rejected(params, width, height):
    with pytest.raises(ValueError, match="greater than zero"):
        replace(params, width=width, height=height).validate_for(MediaGenKind.TEXT2IMAGE)


def test_oversize_dimensions_are_rejected(params):
    over = MAX_MEDIA_GEN_DIMENSION + 1
    with pytest.raises(ValueError, match="maximum dimension"):
        replace(params, width=over).validate_for(MediaGenKind.TEXT2IMAGE)


def test_zero_steps_is_rejected(params):
    with pytest.raises(ValueError, match="steps must be greater than zero"):
        replace(params, steps=0).validate_for(MediaGenKind.TEXT2IMAGE)


def test_oversize_steps_is_rejected(params):
    with pytest.raises(ValueError, match="steps exceeds"):
        replace(params, steps=MAX_MEDIA_GEN_STEPS + 1).validate_for(MediaGenKind.TEXT2IMAGE)


@pytest.mark.parametrize("scale", [float("nan"), float("inf"), float("-inf"), -0.5])
def test_a_non_finite_or_negative_guidance_scale_is_rejected(params, scale):
    """The scale is folded in as raw IEEE-754 bytes, so NaN would break determinism."""
    with pytest.raises(ValueError, match="guidance_scale"):
        replace(params, guidance_scale=scale).validate_for(MediaGenKind.TEXT2IMAGE)


def test_a_zero_guidance_scale_is_allowed(params):
    """Distilled models such as Z-Image Turbo sample without guidance."""
    replace(params, guidance_scale=0.0).validate_for(MediaGenKind.TEXT2IMAGE)


@pytest.mark.parametrize("kind", [MediaGenKind.IMAGE2IMAGE, MediaGenKind.IMAGE2VIDEO])
def test_an_image_conditioned_kind_needs_the_input_hash(kind, params):
    bare = video_params() if kind.is_video else params
    with pytest.raises(ValueError, match="input_image_hash"):
        bare.validate_for(kind)
    replace(bare, input_image_hash=bytes([7] * 32)).validate_for(kind)


@pytest.mark.parametrize(
    ("num_frames", "fps"), [(None, 16), (81, None), (None, None)]
)
def test_a_video_kind_needs_frames_and_fps(num_frames, fps):
    with pytest.raises(ValueError, match="num_frames and fps are required"):
        video_params(num_frames=num_frames, fps=fps).validate_for(MediaGenKind.TEXT2VIDEO)


@pytest.mark.parametrize(("num_frames", "fps"), [(0, 16), (81, 0)])
def test_zero_frames_or_fps_is_rejected(num_frames, fps):
    with pytest.raises(ValueError, match="greater than zero"):
        video_params(num_frames=num_frames, fps=fps).validate_for(MediaGenKind.TEXT2VIDEO)


def test_oversize_frame_count_is_rejected():
    with pytest.raises(ValueError, match="num_frames exceeds"):
        video_params(num_frames=MAX_MEDIA_GEN_FRAMES + 1).validate_for(
            MediaGenKind.TEXT2VIDEO
        )


def test_frames_and_fps_are_ignored_for_image_kinds(params):
    """An image job carrying stray video fields still validates."""
    replace(params, num_frames=81, fps=16).validate_for(MediaGenKind.TEXT2IMAGE)


# ---------------------------------------------------------------------------
# Wire round trips
# ---------------------------------------------------------------------------


def test_params_round_trip_through_json(params):
    conditioned = replace(
        params,
        input_image_hash=bytes([4] * 32),
        metadata={"scheduler": "unipc"},
    )
    assert MediaGenParams.from_json(json.loads(json.dumps(conditioned.to_json()))) == (
        conditioned
    )


def test_hashes_and_addresses_serialize_as_integer_arrays(spec):
    encoded = spec.to_json()
    assert encoded["requester_address"] == [0] * 32
    assert encoded["kind"] == "text2image"
    # ``max_price`` is a u128 with no string codec, so it stays a JSON number.
    assert isinstance(encoded["max_price"], int)
    assert isinstance(encoded["created_at"], int)


def test_task_spec_round_trips_through_json(spec):
    assert MediaGenTaskSpec.from_json(json.loads(json.dumps(spec.to_json()))) == spec


def test_receipt_round_trips_through_json(receipt):
    signed = replace(
        receipt, worker_signature=Signature(bytes_=bytes(64), public_key=bytes(32))
    )
    decoded = MediaGenReceipt.from_json(json.loads(json.dumps(signed.to_json())))
    assert decoded == signed


def test_signature_serializes_under_the_rust_field_names():
    encoded = Signature(bytes_=b"\x01\x02", public_key=b"\x03").to_json()
    assert encoded == {"bytes": [1, 2], "public_key": [3]}
    assert Signature.from_json(encoded) == Signature(bytes_=b"\x01\x02", public_key=b"\x03")


def test_an_absent_signature_decodes_as_empty():
    assert Signature.from_json({}) == Signature.empty()


# ---------------------------------------------------------------------------
# Worker capability
# ---------------------------------------------------------------------------


def capability(**overrides) -> MediaGenWorkerCapability:
    base = dict(
        worker_did="did:tenzro:machine:worker",
        worker_address=ZERO_ADDRESS,
        supported_models=["qwen-image"],
        expert_holdings=[
            MediaGenExpertHolding(
                model_id="wan2.2-t2v-a14b", role=MediaGenExpertRole.HIGH_NOISE
            )
        ],
        max_resolution=1328,
        max_frames=81,
        gpu_vram_gb=48.0,
        registered_at=1_700_000_000_000,
    )
    base.update(overrides)
    return MediaGenWorkerCapability(**base)


def test_a_whole_model_holder_qualifies_for_both_halves():
    assert capability().roles_for("qwen-image") == [
        MediaGenExpertRole.HIGH_NOISE,
        MediaGenExpertRole.LOW_NOISE,
    ]


def test_an_expert_holder_qualifies_for_its_half_only():
    assert capability().roles_for("wan2.2-t2v-a14b") == [MediaGenExpertRole.HIGH_NOISE]


def test_an_unheld_model_qualifies_for_nothing():
    assert capability().roles_for("flux2-klein-4b") == []


def test_capability_round_trips_through_json():
    cap = capability()
    assert MediaGenWorkerCapability.from_json(json.loads(json.dumps(cap.to_json()))) == cap


def test_output_bounds_are_checked_against_the_spec(spec):
    assert capability().fits_output(spec)
    assert not capability(max_resolution=512).fits_output(spec)


def test_a_video_job_needs_a_declared_frame_ceiling(spec):
    video = replace(
        spec, kind=MediaGenKind.TEXT2VIDEO, params=video_params(num_frames=81)
    )
    assert capability().fits_output(video)
    assert not capability(max_frames=None).fits_output(video)
    assert not capability(max_frames=49).fits_output(video)


# ---------------------------------------------------------------------------
# Job assignment view
# ---------------------------------------------------------------------------


def job(spec: MediaGenTaskSpec, *, roles, assignments) -> MediaGenJob:
    return MediaGenJob(
        job_id=spec.job_id,
        task_spec=spec,
        status=MediaGenStatus.PENDING,
        required_roles=roles,
        assignments=assignments,
        handoff=None,
        receipt=None,
        error=None,
        created_at=spec.created_at,
        last_update=spec.created_at,
    )


def assignment(did: str, role) -> MediaGenAssignment:
    return MediaGenAssignment(
        worker_did=did,
        worker_address=ZERO_ADDRESS,
        role=role,
        claimed_at=1_700_000_010_000,
        share_bps=0,
    )


def test_a_job_without_roles_is_not_split(spec):
    single = job(spec, roles=[], assignments=[])
    assert not single.is_split
    assert not single.is_fully_assigned()
    assert single.unclaimed_roles() == []


def test_one_claim_fully_assigns_a_single_expert_job(spec):
    single = job(spec, roles=[], assignments=[assignment("did:a", None)])
    assert single.is_fully_assigned()
    assert single.assignment_for("did:a") is not None
    assert single.assignment_for("did:b") is None


def test_a_split_job_tracks_each_half_separately(spec):
    split = job(
        spec,
        roles=[MediaGenExpertRole.HIGH_NOISE, MediaGenExpertRole.LOW_NOISE],
        assignments=[assignment("did:high", MediaGenExpertRole.HIGH_NOISE)],
    )
    assert split.is_split
    assert split.unclaimed_roles() == [MediaGenExpertRole.LOW_NOISE]
    assert not split.is_fully_assigned()
    assert split.assignment_of_role(MediaGenExpertRole.HIGH_NOISE).worker_did == "did:high"
    assert split.assignment_of_role(MediaGenExpertRole.LOW_NOISE) is None


def test_a_split_job_is_assigned_once_both_halves_are_claimed(spec):
    split = job(
        spec,
        roles=[MediaGenExpertRole.HIGH_NOISE, MediaGenExpertRole.LOW_NOISE],
        assignments=[
            assignment("did:high", MediaGenExpertRole.HIGH_NOISE),
            assignment("did:low", MediaGenExpertRole.LOW_NOISE),
        ],
    )
    assert split.unclaimed_roles() == []
    assert split.is_fully_assigned()
