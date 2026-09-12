"""A worker sharing its card with a resident LLM.

FLUX.2 klein 4B on a 16 GB card that already holds a 9 GB language model:
neither the 7.75 GB transformer nor the 8.05 GB Qwen3 text encoder fits in
what is left, so the worker needs three things it did not have — a quantized
text encoder, model-CPU-offload, and an honest figure to record against the
node's memory ledger instead of the catalog's full-precision floor. These pin
the plumbing for all three without touching a GPU.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tenzro_media_gen import pipelines
from tenzro_media_gen.cli import _worker_config, build_parser
from tenzro_media_gen.pipelines import _text_encoder_quantization_for
from tenzro_media_gen.worker import MediaGenWorker, WorkerConfig

ADDRESS_HEX = "ab" * 32


# ── text-encoder quantization ─────────────────────────────────────────


def test_no_text_encoder_precision_means_no_config() -> None:
    assert _text_encoder_quantization_for(None, object()) is None


def test_a_floating_point_tier_is_refused_for_the_text_encoder() -> None:
    # The float tiers are expressed as dtype, never as a quantization config;
    # naming one here is a misconfiguration, not a no-op.
    with pytest.raises(ValueError, match="text-encoder precision"):
        _text_encoder_quantization_for("bfloat16", object())


def test_nf4_builds_a_transformers_config_not_a_diffusers_one() -> None:
    transformers = pytest.importorskip("transformers")
    torch = pytest.importorskip("torch")
    cfg = _text_encoder_quantization_for("nf4", torch.bfloat16)
    # Pipeline-level quantization hands each component the config type of the
    # library that loads it; a text encoder is a transformers model.
    assert isinstance(cfg, transformers.BitsAndBytesConfig)
    assert cfg.load_in_4bit is True
    assert cfg.bnb_4bit_quant_type == "nf4"
    assert cfg.bnb_4bit_use_double_quant is True
    assert cfg.bnb_4bit_compute_dtype == torch.bfloat16


def test_int8_builds_an_8bit_config() -> None:
    transformers = pytest.importorskip("transformers")
    # transformers' config resolves its default compute dtype through torch.
    pytest.importorskip("torch")
    cfg = _text_encoder_quantization_for("int8", None)
    assert isinstance(cfg, transformers.BitsAndBytesConfig)
    assert cfg.load_in_8bit is True


# ── ledger figure ─────────────────────────────────────────────────────


def _worker_with(**overrides: object) -> SimpleNamespace:
    config = WorkerConfig(worker_did="did:tenzro:machine:test", worker_address=bytes(32), **overrides)
    return SimpleNamespace(config=config)


def test_the_catalog_floor_is_recorded_by_default() -> None:
    entry = SimpleNamespace(min_vram_gb=12, size_bytes=23_740_007_447)
    assert MediaGenWorker._entry_vram_gb(_worker_with(), entry) == 12.0


def test_an_operator_override_replaces_the_catalog_floor() -> None:
    # NF4 on both halves plus offload peaks near 4.5 GB where the catalog
    # says 12; the override is what lets the load be admitted at all on a
    # card shared with an LLM, while still being recorded.
    entry = SimpleNamespace(min_vram_gb=12, size_bytes=23_740_007_447)
    assert MediaGenWorker._entry_vram_gb(_worker_with(admit_vram_gb=4.5), entry) == 4.5


def test_the_override_also_beats_the_size_fallback() -> None:
    entry = SimpleNamespace(min_vram_gb=None, size_bytes=8_000_000_000)
    assert MediaGenWorker._entry_vram_gb(_worker_with(admit_vram_gb=3.0), entry) == 3.0


# ── prefetch skips what the pipeline never opens ──────────────────────


def test_prefetch_fetches_components_and_skips_top_level_bundles(monkeypatch: pytest.MonkeyPatch) -> None:
    hub = pytest.importorskip("huggingface_hub")
    listed = [
        "model_index.json",
        "flux-2-klein-4b.safetensors",  # 7.75 GB single-file bundle for other UIs
        "realism.jpg",
        "README.md",
        "transformer/config.json",
        "transformer/diffusion_pytorch_model.safetensors",
        "text_encoder/model-00001-of-00002.safetensors",
        "vae/config.json",
    ]
    fetched: list[str] = []

    class FakeApi:
        def list_repo_files(self, repo_id: str, token: str | None = None) -> list[str]:
            return listed

    def fake_download(*, repo_id: str, filename: str, cache_dir: str, token: str | None) -> str:
        fetched.append(filename)
        return filename

    monkeypatch.setattr(hub, "HfApi", FakeApi)
    monkeypatch.setattr(hub, "hf_hub_download", fake_download)

    pipelines._prefetch_repo_files("black-forest-labs/FLUX.2-klein-4B", "/cache", None)

    assert fetched == [
        "model_index.json",
        "transformer/config.json",
        "transformer/diffusion_pytorch_model.safetensors",
        "text_encoder/model-00001-of-00002.safetensors",
        "vae/config.json",
    ]


# ── the flags reach the config ────────────────────────────────────────


def test_serve_flags_land_in_the_worker_config() -> None:
    args = build_parser().parse_args(
        [
            "serve",
            "--worker-did", "did:tenzro:machine:test",
            "--worker-address", ADDRESS_HEX,
            "--model", "flux2-klein-4b",
            "--precision", "nf4",
            "--text-encoder-precision", "nf4",
            "--cpu-offload",
            "--admit-vram-gb", "4.5",
            "--gpu-vram-gb", "6",
        ]
    )
    config = _worker_config(args)
    assert config.precision == "nf4"
    assert config.text_encoder_precision == "nf4"
    assert config.cpu_offload is True
    assert config.admit_vram_gb == 4.5
    assert config.served_models == ["flux2-klein-4b"]


def test_the_new_flags_default_off() -> None:
    args = build_parser().parse_args(
        ["serve", "--worker-did", "did:tenzro:machine:test", "--worker-address", ADDRESS_HEX, "--model", "qwen-image"]
    )
    config = _worker_config(args)
    assert config.text_encoder_precision is None
    assert config.cpu_offload is False
    assert config.admit_vram_gb is None
