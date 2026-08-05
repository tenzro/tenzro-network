"""Backend pluggability: a non-diffusers entry runs without displacing diffusers.

These assert the property the design exists for — that adding TRELLIS.2 changed
nothing about how the seventeen pixel pipelines load or render, and that a
worker which cannot load a backend never advertises it.
"""

from __future__ import annotations

import pytest

from tenzro_media_gen.pipelines import (
    BackendAdapter,
    CatalogEntry,
    backend_adapter,
    backend_is_available,
    register_backend_adapter,
)


def _entry(**over) -> dict:
    base = {
        "id": "x",
        "name": "X",
        "family": "x",
        "hf_repo": "org/x",
        "pipeline_class": "XPipeline",
        "kinds": ["text2image"],
        "default_width": 1024,
        "default_height": 1024,
        "max_resolution": 1024,
        "default_steps": 30,
        "default_guidance_scale": 4.0,
        "default_num_frames": None,
        "default_fps": None,
        "min_vram_gb": 8,
        "license": "Apache-2.0",
        "expert_pair": None,
    }
    base.update(over)
    return base


def test_an_entry_without_a_backend_is_diffusers() -> None:
    """Every pre-3D catalog row omits the field. It must keep meaning diffusers."""
    entry = CatalogEntry.from_json(_entry())
    assert entry.backend == "diffusers"
    assert entry.default_voxel_resolution is None


def test_the_diffusers_path_has_no_adapter() -> None:
    """`None`, not a no-op adapter — the diffusers path is not an adapter and
    pretending otherwise invites someone to 'finish' a symmetry that is absent."""
    assert backend_adapter("diffusers") is None
    assert backend_adapter("") is None


def test_a_declared_backend_resolves_to_its_adapter() -> None:
    entry = CatalogEntry.from_json(_entry(backend="trellis2", default_voxel_resolution=1024))
    assert entry.backend == "trellis2"
    assert entry.default_voxel_resolution == 1024
    adapter = backend_adapter("trellis2")
    assert adapter is not None
    assert adapter.required_package == "trellis2"


def test_an_unknown_backend_is_not_available() -> None:
    """Unknown means unservable, not 'fall back to diffusers'. Falling back
    would load the wrong library against weights it cannot read."""
    assert backend_is_available("no-such-backend") is False
    assert backend_adapter("no-such-backend") is None


def test_availability_reflects_a_missing_package() -> None:
    class Absent(BackendAdapter):
        backend = "absent-for-test"
        required_package = "a_package_that_is_not_installed_anywhere"

    register_backend_adapter(Absent())
    assert backend_is_available("absent-for-test") is False


def test_availability_reflects_a_present_package() -> None:
    class Present(BackendAdapter):
        backend = "present-for-test"
        required_package = "json"

    register_backend_adapter(Present())
    assert backend_is_available("present-for-test") is True


def test_a_backend_without_hooks_refuses_rather_than_silently_doing_nothing() -> None:
    class Bare(BackendAdapter):
        backend = "bare-for-test"
        required_package = "json"

    bare = Bare()
    with pytest.raises(NotImplementedError):
        bare.load(CatalogEntry.from_json(_entry(backend="bare-for-test")), "text2image", None)
    with pytest.raises(NotImplementedError):
        bare.render(None, None, None)
