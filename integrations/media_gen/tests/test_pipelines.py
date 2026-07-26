"""Catalog parsing and the timestep boundary that separates the two experts.

Nothing here imports torch or diffusers: catalog rows are plain data, and the
boundary rule is arithmetic over the scheduler's timesteps, so a stub standing
in for the pipeline is enough to pin it.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from tenzro_media_gen.pipelines import (
    CatalogEntry,
    ExpertPair,
    boundary_index,
    find_entry,
    guidance_kwarg_for,
)
from tenzro_media_gen.types import MediaGenKind


def qwen_row(**overrides) -> dict:
    row = {
        "id": "qwen-image",
        "name": "Qwen-Image",
        "family": "qwen-image",
        "hf_repo": "Qwen/Qwen-Image",
        "pipeline_class": "QwenImagePipeline",
        "kinds": ["text2image"],
        "default_width": 1328,
        "default_height": 1328,
        "max_resolution": 1664,
        "default_steps": 50,
        "default_guidance_scale": 4.0,
        "default_num_frames": None,
        "default_fps": None,
        "parameters": "20.4B",
        "size_bytes": 41_000_000_000,
        "min_vram_gb": 48,
        "license": "Apache-2.0",
        "license_tier": "Permissive",
        "expert_pair": None,
        "description": "20B MMDiT text-to-image.",
    }
    row.update(overrides)
    return row


def wan_row(**overrides) -> dict:
    return qwen_row(
        id="wan2.2-t2v-a14b",
        name="Wan 2.2 T2V A14B",
        family="wan",
        hf_repo="Wan-AI/Wan2.2-T2V-A14B-Diffusers",
        pipeline_class="WanPipeline",
        kinds=["text2video"],
        default_width=1280,
        default_height=720,
        max_resolution=1280,
        default_steps=40,
        default_guidance_scale=4.0,
        default_num_frames=81,
        default_fps=16,
        min_vram_gb=80,
        expert_pair={
            "high_noise_component": "transformer",
            "low_noise_component": "transformer_2",
            "boundary_ratio": 0.875,
            "min_vram_gb_per_expert": 48,
        },
        **overrides,
    )


# ---------------------------------------------------------------------------
# Catalog rows
# ---------------------------------------------------------------------------


def test_a_dense_row_parses_and_declares_no_split():
    entry = CatalogEntry.from_json(qwen_row())
    assert entry.id == "qwen-image"
    assert entry.kinds == [MediaGenKind.TEXT2IMAGE]
    assert entry.expert_pair is None
    assert not entry.is_split


def test_a_split_row_parses_its_expert_pair():
    entry = CatalogEntry.from_json(wan_row())
    assert entry.is_split
    pair = entry.expert_pair
    assert pair == ExpertPair(
        high_noise_component="transformer",
        low_noise_component="transformer_2",
        boundary_ratio=0.875,
        min_vram_gb_per_expert=48,
    )
    # One expert fits on a card the whole model would not.
    assert pair.min_vram_gb_per_expert < entry.min_vram_gb


def test_a_renamed_field_fails_at_parse_time():
    row = qwen_row()
    del row["default_steps"]
    with pytest.raises(KeyError):
        CatalogEntry.from_json(row)


def test_an_unknown_kind_label_fails_at_parse_time():
    with pytest.raises(ValueError):
        CatalogEntry.from_json(qwen_row(kinds=["text2audio"]))


def test_declared_kinds_are_the_only_ones_served():
    entry = CatalogEntry.from_json(qwen_row())
    assert entry.supports(MediaGenKind.TEXT2IMAGE)
    assert not entry.supports(MediaGenKind.IMAGE2IMAGE)


def test_video_rows_carry_frame_defaults():
    entry = CatalogEntry.from_json(wan_row())
    assert entry.default_num_frames == 81
    assert entry.default_fps == 16


# ---------------------------------------------------------------------------
# Pipeline class resolution
# ---------------------------------------------------------------------------


def test_a_text_conditioned_kind_uses_the_declared_class():
    entry = CatalogEntry.from_json(wan_row())
    assert entry.pipeline_class_for(MediaGenKind.TEXT2VIDEO) == "WanPipeline"


def test_an_image_conditioned_kind_resolves_to_the_sibling_class():
    """Wan takes the same weights through a different class for image input."""
    entry = CatalogEntry.from_json(
        wan_row(id="wan2.2-ti2v-5b", kinds=["text2video", "image2video"])
    )
    assert entry.pipeline_class_for(MediaGenKind.IMAGE2VIDEO) == "WanImageToVideoPipeline"


def test_a_class_that_already_covers_image_input_keeps_it():
    entry = CatalogEntry.from_json(
        qwen_row(
            id="qwen-image-edit",
            pipeline_class="QwenImageEditPlusPipeline",
            kinds=["image2image"],
        )
    )
    assert entry.pipeline_class_for(MediaGenKind.IMAGE2IMAGE) == (
        "QwenImageEditPlusPipeline"
    )


# ---------------------------------------------------------------------------
# Guidance keyword
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pipeline_class",
    ["QwenImagePipeline", "QwenImageEditPlusPipeline"],
)
def test_the_qwen_classes_take_guidance_as_true_cfg_scale(pipeline_class):
    """Their ``guidance_scale`` is an embedded-guidance vector these checkpoints
    do not have, so it would be dropped with a warning."""
    assert guidance_kwarg_for(pipeline_class) == "true_cfg_scale"


@pytest.mark.parametrize(
    "pipeline_class",
    [
        "WanPipeline",
        "WanImageToVideoPipeline",
        "ZImagePipeline",
        "Flux2KleinPipeline",
    ],
)
def test_every_other_class_takes_guidance_as_guidance_scale(pipeline_class):
    assert guidance_kwarg_for(pipeline_class) == "guidance_scale"


def test_an_unmapped_class_falls_back_to_guidance_scale():
    """A catalog row added later gets the common spelling until proven otherwise."""
    assert guidance_kwarg_for("SomePipelineAddedLater") == "guidance_scale"


# ---------------------------------------------------------------------------
# Catalog lookup
# ---------------------------------------------------------------------------


def test_a_catalog_lookup_returns_the_matching_row():
    assert find_entry([qwen_row(), wan_row()], "wan2.2-t2v-a14b").family == "wan"


def test_an_unknown_model_id_is_reported_by_name():
    with pytest.raises(ValueError, match="not in the node's catalog"):
        find_entry([qwen_row()], "sdxl")


# ---------------------------------------------------------------------------
# Timestep boundary
# ---------------------------------------------------------------------------


@dataclass
class StubScheduler:
    """Enough of a diffusers scheduler for the boundary arithmetic."""

    schedule: list[int]
    num_train_timesteps: int = 1000

    def __post_init__(self):
        self.timesteps: list[int] = []
        self.requested_steps: int | None = None
        self.config = self

    def set_timesteps(self, steps: int, device=None) -> None:
        self.requested_steps = steps
        self.timesteps = self.schedule


class StubPipe:
    def __init__(self, schedule: list[int], num_train_timesteps: int = 1000):
        self.scheduler = StubScheduler(schedule, num_train_timesteps)
        self._execution_device = "cpu"


def test_the_boundary_is_the_first_step_below_the_noise_level():
    """0.875 × 1000 = 875, so 800 is the first low-noise step."""
    pipe = StubPipe([1000, 900, 800, 700])
    assert boundary_index(pipe, 4, 0.875) == 2


def test_the_scheduler_is_left_configured_for_the_requested_steps():
    pipe = StubPipe([1000, 900, 800, 700])
    boundary_index(pipe, 4, 0.875)
    assert pipe.scheduler.requested_steps == 4


def test_the_boundary_tracks_the_noise_level_not_the_step_count():
    """A longer schedule splits at the same noise level, at a later index."""
    short = StubPipe([1000, 900, 800, 700])
    long = StubPipe([1000, 950, 900, 850, 800, 750, 700, 650])
    assert boundary_index(short, 4, 0.875) == 2
    assert boundary_index(long, 8, 0.875) == 3


def test_a_schedule_that_never_crosses_the_boundary_leaves_no_low_noise_work():
    pipe = StubPipe([1000, 950])
    assert boundary_index(pipe, 2, 0.5) == 2


def test_a_schedule_below_the_boundary_throughout_leaves_no_high_noise_work():
    pipe = StubPipe([400, 300, 200])
    assert boundary_index(pipe, 3, 0.875) == 0


def test_the_boundary_scales_with_the_training_timestep_count():
    """``boundary_ratio`` is a fraction of the scheduler's own range."""
    pipe = StubPipe([1500, 1400, 1300, 1200], num_train_timesteps=1500)
    assert boundary_index(pipe, 4, 0.875) == 2
