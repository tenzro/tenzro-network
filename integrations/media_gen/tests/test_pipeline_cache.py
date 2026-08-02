"""The pipeline cache must be bounded, or the second job of a session OOMs.

A worker renders an image job with a 33 GB pipeline, then a video job with a
34 GB one. An unbounded cache holds both — 67 GB — on a machine budgeted for
one at a time. The kill lands on the video job, so it reads as a video bug
when it is a cache bug.

These tests pin the bound, the recency order, and the two ways eviction can
go wrong quietly: freeing the dict entry without freeing the memory, and
evicting the pipeline that is about to be used again.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from tenzro_media_gen.pipelines import CatalogEntry, LoadedPipeline
from tenzro_media_gen.types import MediaGenKind
from tenzro_media_gen.worker import MediaGenWorker, WorkerConfig


@dataclass
class FakePipe:
    """Stands in for a diffusers pipeline and records that it was released."""

    released_to: str | None = None

    def to(self, device: str) -> FakePipe:
        self.released_to = device
        return self


def entry(model_id: str, vram_gb: int) -> CatalogEntry:
    return CatalogEntry(
        id=model_id,
        name=model_id,
        family="test",
        hf_repo=f"test/{model_id}",
        pipeline_class="TestPipeline",
        kinds=[MediaGenKind.TEXT2IMAGE],
        default_width=1024,
        default_height=1024,
        max_resolution=2048,
        default_steps=20,
        default_guidance_scale=4.0,
        default_num_frames=None,
        default_fps=None,
        min_vram_gb=vram_gb,
        license="Apache-2.0",
        expert_pair=None,
    )


def worker(vram_gb: float) -> MediaGenWorker:
    config = WorkerConfig(
        worker_did="did:tenzro:machine:test",
        worker_address=b"\x00" * 20,
        gpu_vram_gb=vram_gb,
    )
    return MediaGenWorker(config, client=None, key=None)  # type: ignore[arg-type]


def install(w: MediaGenWorker, e: CatalogEntry) -> FakePipe:
    """Put a pipeline in the cache without loading anything real."""
    pipe = FakePipe()
    key = (e.id, MediaGenKind.TEXT2IMAGE.value, None)
    w._pipelines[key] = LoadedPipeline(pipe=pipe, entry=e, kind=MediaGenKind.TEXT2IMAGE, role=None)
    return pipe


def test_the_second_large_pipeline_evicts_the_first() -> None:
    # The exact scenario the bound exists for: image then video on a budget
    # sized for one.
    w = worker(vram_gb=48)
    image = entry("z-image-turbo", 16)
    install(w, image)

    video = entry("wan2.2-ti2v-5b", 40)
    w._evict_until_fits(video)

    assert w._pipelines == {}, "the 16 GB pipeline must go to fit a 40 GB one"


def test_pipelines_that_fit_together_are_both_kept() -> None:
    # Eviction must not be eager: two small pipelines on a large budget should
    # both survive, or a worker rendering alternating jobs reloads constantly.
    w = worker(vram_gb=48)
    install(w, entry("flux2-klein-4b", 12))
    w._evict_until_fits(entry("z-image-turbo", 16))
    assert len(w._pipelines) == 1, "12 + 16 fits in 48; nothing should be evicted"


def test_eviction_is_least_recently_used_not_first_inserted() -> None:
    w = worker(vram_gb=40)
    a, b = entry("a", 16), entry("b", 16)
    install(w, a)
    install(w, b)

    # Touch `a`, making `b` the least recently used.
    w._pipelines.move_to_end(("a", MediaGenKind.TEXT2IMAGE.value, None))

    w._evict_until_fits(entry("c", 16))
    remaining = {k[0] for k in w._pipelines}
    assert remaining == {"a"}, f"expected b evicted as LRU, kept {remaining}"


def test_eviction_actually_releases_the_pipeline() -> None:
    # Dropping the dict entry only drops a Python reference. An eviction that
    # frees no memory is worse than none: it loses the pipeline AND keeps the
    # VRAM.
    w = worker(vram_gb=20)
    pipe = install(w, entry("big", 16))
    w._evict_until_fits(entry("bigger", 18))
    assert pipe.released_to == "cpu", "the pipeline must be moved off the GPU"


def test_a_pipeline_larger_than_the_whole_budget_still_attempts_to_load() -> None:
    # The catalog's VRAM figures are estimates. Refusing on an estimate makes
    # a worker decline jobs it could have rendered; the authoritative ceiling
    # is the node's memory budget on the Rust side.
    w = worker(vram_gb=8)
    install(w, entry("small", 4))
    w._evict_until_fits(entry("enormous", 400))
    assert w._pipelines == {}, "everything evictable was evicted"
    # No exception: the caller proceeds to load.


def test_an_empty_cache_needs_no_eviction() -> None:
    w = worker(vram_gb=8)
    w._evict_until_fits(entry("anything", 400))
    assert w._pipelines == {}


def test_release_never_raises_even_on_a_hostile_pipeline() -> None:
    # Eviction runs on the render path. A pipeline whose `.to()` throws must
    # not take the worker down — it is being discarded anyway.
    class Hostile:
        def to(self, device: str) -> Any:
            raise RuntimeError("device moved away")

    w = worker(vram_gb=10)
    e = entry("hostile", 8)
    w._pipelines[(e.id, MediaGenKind.TEXT2IMAGE.value, None)] = LoadedPipeline(
        pipe=Hostile(), entry=e, kind=MediaGenKind.TEXT2IMAGE, role=None
    )
    w._evict_until_fits(entry("next", 8))
    assert w._pipelines == {}


@pytest.mark.parametrize("declared,expected", [(16, 16.0), (0, 0.0)])
def test_vram_cost_reads_the_catalogs_own_figure(declared: int, expected: float) -> None:
    w = worker(vram_gb=48)
    assert w._entry_vram_gb(entry("m", declared)) == expected


def test_precision_is_part_of_the_cache_key() -> None:
    """The same model at nf4 and at bf16 are different objects.

    Keying the pipeline cache on the model alone would hand a caller who asked
    for bf16 whichever precision happened to be loaded first — with a different
    VRAM cost and different outputs, silently.
    """
    import inspect

    from tenzro_media_gen.worker import MediaGenWorker

    src = inspect.getsource(MediaGenWorker._pipeline)
    key_region = src.split("cache_key = (", 1)[1].split(")", 1)[0]
    assert "precision" in key_region, (
        "the pipeline cache key does not include precision:\n" + key_region
    )
