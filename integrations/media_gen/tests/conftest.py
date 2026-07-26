"""Fixtures shared by the media-gen tests.

The values here are the same ones the Rust commitment tests use
(``crates/tenzro-media-gen/src/commitments.rs``). Keeping both suites on
identical inputs is what makes the digests comparable across the two
languages — a preimage change on either side shows up as a digest change on
one side only.
"""

from __future__ import annotations

import pytest

from tenzro_media_gen.commitments import compute_job_id
from tenzro_media_gen.types import (
    MediaGenHandoff,
    MediaGenKind,
    MediaGenParams,
    MediaGenReceipt,
    MediaGenTaskSpec,
    Signature,
)

ZERO_ADDRESS = bytes(32)


@pytest.fixture
def params() -> MediaGenParams:
    return MediaGenParams(
        prompt="a fox in a plaster diorama",
        negative_prompt="blurry",
        width=1024,
        height=1024,
        num_frames=None,
        fps=None,
        steps=30,
        guidance_scale=4.5,
        seed=42,
        input_image_hash=None,
    )


@pytest.fixture
def spec(params: MediaGenParams) -> MediaGenTaskSpec:
    requester_did = "did:tenzro:human:req"
    model_id = "qwen-image"
    kind = MediaGenKind.TEXT2IMAGE
    max_price = 1_000_000_000_000_000_000
    created_at = 1_700_000_000_000
    job_id = compute_job_id(
        requester_did,
        ZERO_ADDRESS,
        model_id,
        kind,
        params,
        max_price,
        created_at,
    )
    return MediaGenTaskSpec(
        job_id=job_id,
        requester_did=requester_did,
        requester_address=ZERO_ADDRESS,
        model_id=model_id,
        kind=kind,
        params=params,
        max_price=max_price,
        created_at=created_at,
    )


@pytest.fixture
def receipt(spec: MediaGenTaskSpec) -> MediaGenReceipt:
    return MediaGenReceipt(
        job_id=spec.job_id,
        task_spec=spec,
        worker_did="did:tenzro:machine:worker",
        worker_address=ZERO_ADDRESS,
        output_hash=bytes([9] * 32),
        output_mime="image/png",
        output_bytes=2048,
        seed_used=42,
        generation_time_ms=8_500,
        price_paid=500_000_000_000_000_000,
        completed_at=1_700_000_030_000,
        worker_signature=Signature.empty(),
    )


@pytest.fixture
def handoff(spec: MediaGenTaskSpec) -> MediaGenHandoff:
    return MediaGenHandoff(
        job_id=spec.job_id,
        from_worker_did="did:tenzro:machine:high",
        from_worker_address=bytes([3] * 32),
        latent_hash=bytes([5] * 32),
        latent_bytes=8_388_608,
        steps_completed=26,
        handed_off_at=1_700_000_020_000,
        worker_signature=Signature.empty(),
    )
