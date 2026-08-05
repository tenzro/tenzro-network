"""Diffusers pipeline loading and the split-expert denoising loop.

The node never executes a denoising step; it holds the queue, the catalog, the
prices, and the commitments. This module is the half that actually renders.

Two execution shapes, chosen by whether the worker holds a role:

``role is None``
    The model has one transformer. Call the stock pipeline and take its output.

``role is not None``
    The model splits its schedule at a timestep boundary. The high-noise expert
    runs the early (noisy) part and hands over a latent; the low-noise expert
    resumes from that latent and decodes. Both halves run the same loop body,
    parameterised by which timesteps they own and which transformer they hold.

The boundary rule comes from the pipeline's own config: a step belongs to the
high-noise expert while ``t >= boundary_ratio * num_train_timesteps``. Because
timesteps descend, that is a prefix of the schedule, so one integer index
separates the two halves and exactly one latent crosses the wire per job.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import tempfile
from dataclasses import dataclass
from typing import Any

from .types import MediaGenExpertRole, MediaGenKind, MediaGenParams

# A catalog entry names one pipeline class, but a few classes have a sibling
# that handles the image-conditioned kind of the same model. Entries whose
# single class already covers every kind they declare are absent here.
_IMAGE_CONDITIONED_SIBLING = {
    "WanPipeline": "WanImageToVideoPipeline",
}

# Which keyword carries classifier-free guidance for a given pipeline class.
#
# Most classes take the scale as ``guidance_scale``. The Qwen-Image classes do
# not: there, ``guidance_scale`` feeds an embedded-guidance vector that only
# exists on a guidance-distilled transformer, and every Qwen-Image checkpoint in
# the catalog reports ``guidance_embeds: false`` — passing it is warned about and
# dropped. Real classifier-free guidance in that family is ``true_cfg_scale``,
# and it engages only when the job also carries a negative prompt. A job without
# one renders unguided whatever scale it asked for; the worker does not
# substitute a placeholder negative prompt, because the receipt binds the
# parameters the requester signed and a verifier re-rendering from those
# parameters has to reach the same output.
_GUIDANCE_KWARG = {
    "QwenImagePipeline": "true_cfg_scale",
    "QwenImageEditPlusPipeline": "true_cfg_scale",
}


def guidance_kwarg_for(pipeline_class: str) -> str:
    """Keyword under which ``guidance_scale`` from the job reaches the pipeline."""
    return _GUIDANCE_KWARG.get(pipeline_class, "guidance_scale")


@dataclass
class ExpertPair:
    """The two halves of a split denoising schedule.

    ``boundary_ratio`` is a fraction of the scheduler's training timestep count,
    not of the step count a job asks for — a 40-step job and a 100-step job
    split at the same *noise level*, not the same step index.
    """

    high_noise_component: str
    low_noise_component: str
    boundary_ratio: float
    min_vram_gb_per_expert: int

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ExpertPair:
        return cls(
            high_noise_component=str(data["high_noise_component"]),
            low_noise_component=str(data["low_noise_component"]),
            boundary_ratio=float(data["boundary_ratio"]),
            min_vram_gb_per_expert=int(data["min_vram_gb_per_expert"]),
        )


@dataclass
class CatalogEntry:
    """One row of ``tenzro_mediaGen_listCatalog``.

    Mirrors ``MediaGenModelEntry`` in ``crates/tenzro-model/src/catalog.rs``.
    Held as a dataclass rather than a dict so a catalog refresh that renames a
    field fails at parse time instead of at render time.
    """

    id: str
    name: str
    family: str
    hf_repo: str
    pipeline_class: str
    kinds: list[MediaGenKind]
    default_width: int
    default_height: int
    max_resolution: int
    default_steps: int
    default_guidance_scale: float
    default_num_frames: int | None
    default_fps: int | None
    min_vram_gb: int
    license: str
    expert_pair: ExpertPair | None
    # A GGUF release publishes only the quantized transformer; every other
    # component (text encoder, VAE, tokenizer, scheduler) still comes from
    # `hf_repo`. Both fields are set together or neither is.
    gguf_repo: str | None = None
    gguf_file: str | None = None
    transformer_class: str | None = None
    # Where the transformer's diffusers config comes from, when that is not
    # `hf_repo`. Needed when a release ships weights whose geometry no repo in
    # the entry describes; `None` reads the config from `hf_repo` as before.
    #
    # A `~`-prefixed local directory holding a `model_index.json` is read as a
    # whole converted snapshot rather than a config-only override, and the
    # pipeline is built from it instead of `hf_repo`. That is what LTX-2.3
    # needs: its components are published across two repos in a key layout the
    # installed diffusers converters predate, so they are renamed once offline
    # and `hf_repo` stays the upstream id for provenance.
    config_repo: str | None = None
    # Step-distilled release: sample on the trajectory the distillation was
    # trained against rather than letting the scheduler derive its own. The
    # values are resolved per family by its `FamilyAdapter`, never shared
    # across families.
    distilled: bool = False
    # Subfolder of the converted snapshot holding the latent upsampler stage 2
    # refines through. `None` renders in one stage.
    latent_upsampler: str | None = None

    def local_snapshot(self) -> pathlib.Path | None:
        """The converted snapshot to build from, if `config_repo` names one."""
        if self.config_repo is None:
            return None
        path = pathlib.Path(self.config_repo).expanduser()
        return path if (path / "model_index.json").is_file() else None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> CatalogEntry:
        pair = data.get("expert_pair")
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            family=str(data["family"]),
            hf_repo=str(data["hf_repo"]),
            pipeline_class=str(data["pipeline_class"]),
            kinds=[MediaGenKind(k) for k in data["kinds"]],
            default_width=int(data["default_width"]),
            default_height=int(data["default_height"]),
            max_resolution=int(data["max_resolution"]),
            default_steps=int(data["default_steps"]),
            default_guidance_scale=float(data["default_guidance_scale"]),
            default_num_frames=(
                int(data["default_num_frames"])
                if data.get("default_num_frames") is not None
                else None
            ),
            default_fps=(int(data["default_fps"]) if data.get("default_fps") is not None else None),
            min_vram_gb=int(data["min_vram_gb"]),
            license=str(data["license"]),
            expert_pair=ExpertPair.from_json(pair) if pair else None,
            gguf_repo=(str(data["gguf_repo"]) if data.get("gguf_repo") is not None else None),
            gguf_file=(str(data["gguf_file"]) if data.get("gguf_file") is not None else None),
            transformer_class=(
                str(data["transformer_class"])
                if data.get("transformer_class") is not None
                else None
            ),
            config_repo=(str(data["config_repo"]) if data.get("config_repo") is not None else None),
            distilled=bool(data.get("distilled", False)),
            latent_upsampler=(
                str(data["latent_upsampler"]) if data.get("latent_upsampler") is not None else None
            ),
        )

    @property
    def is_split(self) -> bool:
        return self.expert_pair is not None

    @property
    def is_gguf(self) -> bool:
        return self.gguf_repo is not None and self.gguf_file is not None

    def supports(self, kind: MediaGenKind) -> bool:
        return kind in self.kinds

    def pipeline_class_for(self, kind: MediaGenKind) -> str:
        """Class name to instantiate for one kind.

        A model whose declared class already handles its image-conditioned kind
        keeps that class; the rest resolve to the sibling.
        """
        if not kind.requires_input_image:
            return self.pipeline_class
        return _IMAGE_CONDITIONED_SIBLING.get(self.pipeline_class, self.pipeline_class)


def find_entry(catalog: list[dict[str, Any]], model_id: str) -> CatalogEntry:
    for raw in catalog:
        if raw.get("id") == model_id:
            return CatalogEntry.from_json(raw)
    raise ValueError(f"model {model_id!r} is not in the node's catalog")


@dataclass
class LoadedPipeline:
    """A diffusers pipeline plus the catalog row it was built from.

    ``role`` records which expert slot is populated. On a split model the other
    slot is ``None``, so the pipeline cannot be called directly — the loop in
    :func:`denoise` drives it instead.
    """

    pipe: Any
    entry: CatalogEntry
    kind: MediaGenKind
    role: MediaGenExpertRole | None
    #: Weight format the transformer was loaded at. Recorded because a
    #: quantized pipeline behaves differently in ways a caller has to know
    #: about — it cannot be moved between devices after load, and its outputs
    #: are not bit-identical to the same model at bf16.
    precision: str = "bfloat16"

    @property
    def is_quantized(self) -> bool:
        """Whether the transformer holds sub-8-bit or int8 weights.

        Callers use this to decide whether moving the pipeline between devices
        is allowed — a bitsandbytes module is placed at load time and raises if
        moved afterwards.
        """
        return self.precision in _QUANTIZED_PRECISIONS

    @property
    def transformer(self) -> Any:
        """The transformer this worker actually holds."""
        if self.role is MediaGenExpertRole.LOW_NOISE:
            return self.pipe.transformer_2
        return self.pipe.transformer


#: Precisions a diffusion transformer can be loaded at, coarsest first.
#:
#: The two sub-8-bit tiers go through bitsandbytes, which was verified working
#: on this project's target hardware (GB10, compute capability 12.1) with
#: bitsandbytes 0.50.0 — both ``Linear4bit`` and ``Linear8bitLt`` execute there.
#: On a GPU where the kernels are unavailable the load raises rather than
#: silently falling back, because a caller who asked for 4-bit to make a model
#: fit needs to know it did not.
DIFFUSION_PRECISIONS: tuple[str, ...] = (
    "nf4",
    "int4",
    "int8",
    "float16",
    "bfloat16",
    "float32",
)

#: Precisions that need bitsandbytes and are applied to the transformer only.
_QUANTIZED_PRECISIONS = {"nf4", "int4", "int8"}


def _quantization_for(precision: str, compute_dtype: Any) -> Any | None:
    """Build the diffusers quantization config for ``precision``.

    Returns ``None`` for the plain floating-point tiers, which are expressed as
    ``torch_dtype`` instead.

    Quantization is scoped to the **transformer**, not the whole pipeline. The
    text encoder and VAE are a small share of the weights and are where output
    quality degrades most visibly under aggressive quantization — quantizing
    the VAE in particular shows up as colour banding in every frame. The
    transformer is both the bulk of the memory and the part that tolerates it,
    so that is what gets quantized.
    """
    if precision not in _QUANTIZED_PRECISIONS:
        return None
    from diffusers import BitsAndBytesConfig

    if precision == "int8":
        return BitsAndBytesConfig(load_in_8bit=True)
    # nf4 is the normal-float 4-bit type; int4 is plain fp4. nf4 is the better
    # default for weights that are roughly normally distributed, which
    # transformer weights are, and it is what the diffusers guides use.
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4" if precision == "nf4" else "fp4",
        bnb_4bit_compute_dtype=compute_dtype,
        # Quantizes the quantization constants too — a further ~0.4 bits per
        # weight for no measurable quality cost, which matters when the reason
        # to be at 4-bit is that the model did not otherwise fit.
        bnb_4bit_use_double_quant=True,
    )


def tenzro_home() -> pathlib.Path:
    """The one Tenzro root: ``$TENZRO_HOME``, else ``~/.tenzro``.

    Mirrors ``tenzro_types::paths::tenzro_home`` on the Rust side.
    """
    root = os.environ.get("TENZRO_HOME", "").strip()
    if root:
        return pathlib.Path(root).expanduser()
    return pathlib.Path.home() / ".tenzro"


def default_cache_dir() -> pathlib.Path:
    """Where model weights land when the caller names no ``cache_dir``.

    Without this, ``diffusers``/``huggingface_hub`` fall through to their own
    ``~/.cache/huggingface`` default — a directory nothing else in Tenzro reads
    or accounts for, so a machine ends up with two copies of every checkpoint
    and no way to say which one is in use. ``$HF_HOME`` is honoured first
    because the node exports it when it spawns a worker.
    """
    hf_home = os.environ.get("HF_HOME", "").strip()
    if hf_home:
        return pathlib.Path(hf_home).expanduser()
    return tenzro_home() / "hf"


def _token_from_cli_login() -> str | None:
    """The HuggingFace token from disk, if the operator has one.

    The Tenzro-owned copy first, then the standard location
    `huggingface-cli login` writes, so someone who has already logged in the
    ordinary way does not also have to export an environment variable.
    """
    candidates = [
        default_cache_dir() / "token",
        pathlib.Path.home() / ".cache" / "huggingface" / "token",
    ]
    for path in candidates:
        try:
            token = path.read_text().strip()
        except OSError:
            continue
        if token:
            return token
    return None


class FamilyAdapter:
    """Per-family hooks the generic render path calls through.

    Everything in here is something the render path cannot infer from the
    catalog: a checkpoint converter that needs patching, the sigma trajectory a
    distilled release was trained on, how a family's refiner is constructed.
    Those are properties of a model family, not of generative media, so they
    live behind this seam rather than as branches in the render path.

    The distinction matters for extensibility. A render path written as
    ``if family == "ltx2"`` is not generic code — it is LTX-specific code with
    a hole for everything else, and every new family widens the hole. Here,
    adding a family means registering an adapter: the render path does not
    change, and a family that needs none of these hooks registers nothing.

    Every method is optional. The default implementations say "this family does
    not do that", and the render path is responsible for turning a catalog
    claim it cannot honour into a clear error rather than silence.
    """

    #: Catalog ``family`` string this adapter serves.
    family: str = ""

    def patch_converter(self, entry: CatalogEntry) -> None:
        """Fix up diffusers' single-file converter before a checkpoint loads."""
        return

    def sigma_schedules(self, entry: CatalogEntry) -> tuple[list[float], list[float]]:
        """The (stage-1, stage-2) sigma trajectories for a distilled release.

        Step distillation is a general technique but the trajectory belongs to
        the specific training run, so this is never shared across families —
        handing one family's curve to another produces a plausible render that
        is not the one the checkpoint was trained to produce.
        """
        raise NotImplementedError(
            f"{entry.id} is marked distilled but family {entry.family!r} publishes "
            "no sigma schedule; add one to its adapter rather than borrowing "
            "another family's"
        )

    def refine(
        self,
        loaded: LoadedPipeline,
        params: MediaGenParams,
        stage1_kwargs: dict[str, Any],
        generator: Any,
    ) -> Any:
        """Run a multi-stage render and return pixel frames."""
        raise NotImplementedError(
            f"{loaded.entry.id} declares latent_upsampler but family "
            f"{loaded.entry.family!r} has no refiner wired in its adapter"
        )


_FAMILY_ADAPTERS: dict[str, FamilyAdapter] = {}


def register_family_adapter(adapter: FamilyAdapter) -> None:
    """Register `adapter` as the handler for its family."""
    _FAMILY_ADAPTERS[adapter.family] = adapter


def family_adapter(family: str) -> FamilyAdapter:
    """The adapter for `family`, or a no-op adapter if it needs no hooks.

    Returning a base instance rather than `None` keeps the render path free of
    null checks: a family with nothing special registered simply declines every
    hook, and the render path's own guards decide whether declining is an error.
    """
    return _FAMILY_ADAPTERS.get(family, _DEFAULT_ADAPTER)


_DEFAULT_ADAPTER = FamilyAdapter()


class Ltx2Adapter(FamilyAdapter):
    """LTX-2 (Lightricks). Two-stage, step-distilled, single-file transformer.

    Everything LTX-specific in this worker lives here. The render path calls
    the base-class hooks and never names this family.
    """

    family = "ltx2"

    def patch_converter(self, entry: CatalogEntry) -> None:
        """Teach diffusers' LTX-2.0-era transformer converter the 2.3 key layout.

        2.3 renamed the prompt modulation block. The shipped converter's
        special handler matches on the ``adaln_single`` substring but only
        rewrites the ``adaln_single.`` / ``audio_adaln_single.`` prefixes, so 12
        ``prompt_adaln_single.*`` keys fall through unrenamed and the load fails
        on missing tensors.

        The entry in ``SINGLE_FILE_LOADABLE_CLASSES`` is replaced rather than
        the ``single_file_utils`` module attribute: that mapping captures the
        function by reference at import, so rebinding the attribute has no
        effect.
        """
        from diffusers.loaders import single_file_utils as sfu
        from diffusers.loaders.single_file_model import SINGLE_FILE_LOADABLE_CLASSES

        slot = SINGLE_FILE_LOADABLE_CLASSES["LTX2VideoTransformer3DModel"]
        if getattr(slot["checkpoint_mapping_fn"], "_ltx23", False):
            return
        base = sfu.convert_ltx2_transformer_to_diffusers

        def convert_ltx2_3(checkpoint, **kw):
            converted = base(checkpoint, **kw)
            return {
                k.replace("prompt_adaln_single.", "prompt_adaln."): v for k, v in converted.items()
            }

        convert_ltx2_3._ltx23 = True
        slot["checkpoint_mapping_fn"] = convert_ltx2_3

    def sigma_schedules(self, entry: CatalogEntry) -> tuple[list[float], list[float]]:
        """The trajectories the LTX-2 distillation was trained against.

        Published by diffusers rather than restated here, so they cannot drift
        from the installed pipeline.
        """
        from diffusers.pipelines.ltx2.utils import (
            DISTILLED_SIGMA_VALUES,
            STAGE_2_DISTILLED_SIGMA_VALUES,
        )

        return list(DISTILLED_SIGMA_VALUES), list(STAGE_2_DISTILLED_SIGMA_VALUES)

    def refine(
        self,
        loaded: LoadedPipeline,
        params: MediaGenParams,
        stage1_kwargs: dict[str, Any],
        generator: Any,
    ) -> Any:
        """Stage 1 → 2x latent upsample → short stage-2 pass. Returns frames.

        Stage 1 lays down composition and motion at the base resolution and
        stops at latents. Those are upsampled and handed back to the *same*
        transformer for a second pass that synthesizes detail at the higher
        resolution. Decoding stage 1 directly is a different product — the
        draft — and extra stage-1 steps do not substitute, because the detail is
        not under-sampled, it is absent at that resolution.
        """
        from diffusers.pipelines.ltx2 import LTX2LatentUpsamplePipeline
        from diffusers.pipelines.ltx2.latent_upsampler import LTX2LatentUpsamplerModel

        entry = loaded.entry
        snapshot = entry.local_snapshot()
        if snapshot is None:
            raise ValueError(
                f"{entry.id} declares latent_upsampler but has no converted "
                "snapshot to load it from"
            )
        _, stage2_sigmas = self.sigma_schedules(entry)

        # Stage 1 stops at latents. `return_dict=False` because the video and
        # audio latents come back as a plain tuple in this mode.
        stage1 = dict(stage1_kwargs)
        stage1["output_type"] = "latent"
        stage1["return_dict"] = False
        video_latent, audio_latent = loaded.pipe(**stage1)

        upsampler = LTX2LatentUpsamplerModel.from_pretrained(
            str(snapshot / entry.latent_upsampler),
            torch_dtype=loaded.pipe.dtype,
        ).to(loaded.pipe._execution_device)
        upsample_pipe = LTX2LatentUpsamplePipeline(vae=loaded.pipe.vae, latent_upsampler=upsampler)
        upscaled = upsample_pipe(latents=video_latent, output_type="latent", return_dict=False)[0]

        # Stage 2 re-enters the same pipeline with the upsampled latents. The
        # renoise level is the first stage-2 sigma: the pass has to add noise
        # back before it can denoise detail in, and starting anywhere else
        # either scrubs stage 1's structure or leaves nothing to resolve.
        stage2: dict[str, Any] = {
            "latents": upscaled,
            "audio_latents": audio_latent,
            "prompt": params.prompt,
            "num_inference_steps": len(stage2_sigmas),
            "noise_scale": stage2_sigmas[0],
            "sigmas": stage2_sigmas,
            "generator": generator,
            "output_type": "np",
            "return_dict": False,
        }
        stage2[guidance_kwarg_for(entry.pipeline_class_for(loaded.kind))] = params.guidance_scale
        if params.negative_prompt is not None:
            stage2["negative_prompt"] = params.negative_prompt

        video, _audio = loaded.pipe(**stage2)
        del upsample_pipe, upsampler
        return video[0]


register_family_adapter(Ltx2Adapter())


def load_pipeline(
    entry: CatalogEntry,
    kind: MediaGenKind,
    role: MediaGenExpertRole | None = None,
    *,
    device: str = "cuda",
    dtype: str = "bfloat16",
    precision: str | None = None,
    cache_dir: str | None = None,
) -> LoadedPipeline:
    """Build the pipeline for one job.

    On a split model only the requested expert is loaded — the other slot stays
    empty, which is why the worker holding one half needs roughly half the VRAM
    the whole model would want. The pipeline reads whichever slot is populated
    for its dtype and channel count, so leaving one empty is supported.

    ``precision`` selects the transformer's weight format from
    :data:`DIFFUSION_PRECISIONS`. The floating-point tiers are the same thing as
    ``dtype``; the ``nf4`` / ``int4`` / ``int8`` tiers additionally quantize the
    transformer through bitsandbytes, with ``dtype`` remaining the compute type.
    Defaults to ``dtype``, so an existing caller gets exactly what it did
    before.
    """
    import diffusers
    import torch

    if not entry.supports(kind):
        raise ValueError(f"model {entry.id!r} does not serve {kind.value}")
    if entry.is_split and role is None:
        raise ValueError(f"model {entry.id!r} splits its schedule; a role is required")
    if role is not None and not entry.is_split:
        raise ValueError(f"model {entry.id!r} has one transformer; a role is meaningless")

    precision = precision or dtype
    if precision not in DIFFUSION_PRECISIONS:
        raise ValueError(
            f"unknown precision {precision!r}; expected one of {list(DIFFUSION_PRECISIONS)}"
        )
    # The compute dtype stays floating point even when the weights are
    # quantized: 4-bit weights are dequantized into this type per matmul.
    compute_dtype_name = dtype if precision in _QUANTIZED_PRECISIONS else precision
    torch_dtype = getattr(torch, compute_dtype_name)
    quant_config = _quantization_for(precision, torch_dtype)

    class_name = entry.pipeline_class_for(kind)
    pipeline_cls = getattr(diffusers, class_name, None)
    if pipeline_cls is None:
        raise ValueError(
            f"diffusers {diffusers.__version__} has no {class_name!r}; "
            "the catalog is ahead of the installed diffusers"
        )

    # An unset `cache_dir` used to mean "whatever huggingface_hub defaults to",
    # which is a directory outside the Tenzro root that nothing else reads.
    # Resolve it here instead so every load lands in one place.
    resolved_cache = (
        str(pathlib.Path(cache_dir).expanduser()) if cache_dir else str(default_cache_dir())
    )

    kwargs: dict[str, Any] = {"torch_dtype": torch_dtype, "cache_dir": resolved_cache}

    # Gated checkpoints — FLUX.2 dev, the klein-9B line — need the operator's
    # own HuggingFace token. `diffusers` reads `HF_TOKEN` itself, but only for
    # some code paths and only in some versions, so it is passed explicitly.
    # Absent, this is a no-op and ungated models load exactly as before.
    hf_token = (
        os.environ.get("HF_TOKEN")
        or os.environ.get("HUGGING_FACE_HUB_TOKEN")
        or _token_from_cli_login()
    )
    if hf_token:
        kwargs["token"] = hf_token

    if entry.is_split:
        assert entry.expert_pair is not None
        subfolder = (
            entry.expert_pair.high_noise_component
            if role is MediaGenExpertRole.HIGH_NOISE
            else entry.expert_pair.low_noise_component
        )
        transformer_cls = diffusers.WanTransformer3DModel
        expert = transformer_cls.from_pretrained(
            entry.hf_repo,
            subfolder=subfolder,
            torch_dtype=torch_dtype,
            **({"quantization_config": quant_config} if quant_config else {}),
            cache_dir=resolved_cache,
        )
        slot = "transformer" if role is MediaGenExpertRole.HIGH_NOISE else "transformer_2"
        other = "transformer_2" if role is MediaGenExpertRole.HIGH_NOISE else "transformer"
        kwargs[slot] = expert
        kwargs[other] = None

    if entry.is_gguf:
        if entry.is_split:
            raise ValueError(
                f"model {entry.id!r} declares both a GGUF transformer and a split schedule; "
                "the two loading paths are mutually exclusive"
            )
        # A GGUF release ships the transformer alone, dequantized per matmul
        # into `torch_dtype`. Everything else — text encoder, VAE, tokenizer,
        # scheduler — is read from `hf_repo` as usual, so the pipeline is the
        # upstream one with a smaller transformer swapped in. `config` points
        # `from_single_file` at the architecture it should build, because the
        # GGUF carries weights and no diffusers config.
        from diffusers import GGUFQuantizationConfig

        transformer_class_name = entry.transformer_class or f"{entry.pipeline_class}"
        transformer_cls = getattr(diffusers, transformer_class_name, None)
        if transformer_cls is None:
            raise ValueError(
                f"diffusers {diffusers.__version__} has no {transformer_class_name!r}; "
                "the catalog names a transformer class this install cannot build"
            )
        family_adapter(entry.family).patch_converter(entry)
        snapshot = entry.local_snapshot()
        local_gguf = (snapshot.parent / entry.gguf_file) if snapshot is not None else None
        # A converted snapshot sits beside the GGUF it was built against, so
        # prefer that file over re-fetching 17 GB the operator already holds.
        source = (
            str(local_gguf)
            if local_gguf is not None and local_gguf.is_file()
            else f"https://huggingface.co/{entry.gguf_repo}/blob/main/{entry.gguf_file}"
        )
        kwargs["transformer"] = transformer_cls.from_single_file(
            source,
            quantization_config=GGUFQuantizationConfig(compute_dtype=torch_dtype),
            config=str(snapshot) if snapshot is not None else (entry.config_repo or entry.hf_repo),
            subfolder="transformer",
            torch_dtype=torch_dtype,
            cache_dir=resolved_cache,
            **({"token": hf_token} if hf_token else {}),
        )
        # The bitsandbytes tiers quantize the transformer that was just built
        # from GGUF, which would be a second quantization of the same weights.
        quant_config = None

    if quant_config is not None and not entry.is_split:
        # A whole-model load quantizes the transformer through the pipeline's
        # own quantization mapping. The split path above already built its
        # expert with the config applied directly, so it is not repeated here.
        from diffusers.quantizers import PipelineQuantizationConfig

        kwargs["quantization_config"] = PipelineQuantizationConfig(
            quant_mapping={"transformer": quant_config}
        )

    # A converted snapshot already holds every component in diffusers layout,
    # so it is the source; `hf_repo` stays the upstream id for provenance.
    snapshot = entry.local_snapshot()
    pipe = pipeline_cls.from_pretrained(
        str(snapshot) if snapshot is not None else entry.hf_repo, **kwargs
    )
    # A bitsandbytes-quantized module is already placed on its device by the
    # loader and cannot be moved afterwards; calling `.to()` on it raises.
    if quant_config is None:
        pipe.to(device)
    return LoadedPipeline(pipe=pipe, entry=entry, kind=kind, role=role, precision=precision)


def boundary_index(pipe: Any, steps: int, boundary_ratio: float) -> int:
    """First step index that belongs to the low-noise expert.

    Timesteps descend, so the high-noise expert owns ``[0, index)`` and the
    low-noise expert owns ``[index, steps)``. The scheduler is left configured
    for ``steps`` steps, which is what the caller needs next either way.
    """
    pipe.scheduler.set_timesteps(steps, device=pipe._execution_device)
    boundary_t = boundary_ratio * pipe.scheduler.config.num_train_timesteps
    for i, t in enumerate(pipe.scheduler.timesteps):
        if float(t) < boundary_t:
            return i
    return steps


@dataclass
class DenoiseResult:
    """What one expert produced.

    Exactly one of ``latents`` / ``media`` is set. The high-noise expert stops
    at the boundary and returns latents for the handoff; the low-noise expert
    and the whole-model path decode and return encoded bytes.
    """

    latents: Any | None
    media: bytes | None
    mime: str
    seed_used: int
    steps_completed: int
    total_steps: int
    boundary_index: int | None


def _resolve_seed(seed: int | None) -> int:
    if seed is not None:
        return seed
    return int.from_bytes(os.urandom(8), "big")


def _encode_prompts(
    pipe: Any,
    params: MediaGenParams,
    device: Any,
) -> tuple[Any, Any | None]:
    """Text-encode the prompt pair.

    Both halves of a split job re-encode rather than transporting embeds: the
    text encoder is small next to a transformer expert, the prompt is already
    bound into the job id, and shipping embeds would put a second
    schema-versioned tensor on the wire for no gain.
    """
    do_cfg = params.guidance_scale > 1.0
    prompt_embeds, negative_prompt_embeds = pipe.encode_prompt(
        prompt=params.prompt,
        negative_prompt=params.negative_prompt if do_cfg else None,
        do_classifier_free_guidance=do_cfg,
        device=device,
    )
    return prompt_embeds, negative_prompt_embeds


def _decode_video(pipe: Any, latents: Any) -> Any:
    """Denormalize latents by the VAE's per-channel statistics, then decode."""
    import torch

    latents = latents.to(pipe.vae.dtype)
    z_dim = pipe.vae.config.z_dim
    mean = (
        torch.tensor(pipe.vae.config.latents_mean)
        .view(1, z_dim, 1, 1, 1)
        .to(latents.device, latents.dtype)
    )
    inv_std = 1.0 / torch.tensor(pipe.vae.config.latents_std).view(1, z_dim, 1, 1, 1).to(
        latents.device, latents.dtype
    )
    latents = latents / inv_std + mean
    frames = pipe.vae.decode(latents, return_dict=False)[0]
    return pipe.video_processor.postprocess_video(frames, output_type="pil")[0]


def _encode_image_bytes(image: Any) -> bytes:
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


def _encode_video_bytes(frames: Any, fps: int) -> bytes:
    from diffusers.utils import export_to_video

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "out.mp4")
        export_to_video(frames, path, fps=fps)
        with open(path, "rb") as fh:
            return fh.read()


def denoise_whole(
    loaded: LoadedPipeline,
    params: MediaGenParams,
    input_image: bytes | None = None,
) -> DenoiseResult:
    """Render a non-split job with the stock pipeline call."""
    import torch

    if loaded.entry.is_split:
        raise ValueError("split model reached the whole-job path")

    seed = _resolve_seed(params.seed)
    generator = torch.Generator(device=loaded.pipe._execution_device).manual_seed(seed)

    guidance_kwarg = guidance_kwarg_for(loaded.entry.pipeline_class_for(loaded.kind))
    kwargs: dict[str, Any] = {
        "prompt": params.prompt,
        "width": params.width,
        "height": params.height,
        "num_inference_steps": params.steps,
        guidance_kwarg: params.guidance_scale,
        "generator": generator,
    }
    if loaded.entry.distilled:
        stage1, _ = family_adapter(loaded.entry.family).sigma_schedules(loaded.entry)
        kwargs["sigmas"] = stage1
        kwargs["num_inference_steps"] = len(stage1)
    if params.negative_prompt is not None:
        kwargs["negative_prompt"] = params.negative_prompt
    if loaded.kind.is_video:
        kwargs["num_frames"] = params.num_frames or loaded.entry.default_num_frames
    if loaded.kind.requires_input_image:
        if input_image is None:
            raise ValueError(f"{loaded.kind.value} needs a conditioning image")
        kwargs["image"] = _load_image(input_image)

    if loaded.entry.latent_upsampler is not None and loaded.kind.is_video:
        frames = family_adapter(loaded.entry.family).refine(loaded, params, kwargs, generator)
        fps = params.fps or loaded.entry.default_fps or 16
        media = _encode_video_bytes(frames, fps)
        mime = "video/mp4"
        return DenoiseResult(
            latents=None,
            media=media,
            mime=mime,
            seed_used=seed,
            steps_completed=params.steps,
            total_steps=params.steps,
            boundary_index=None,
        )

    out = loaded.pipe(**kwargs)

    if loaded.kind.is_video:
        fps = params.fps or loaded.entry.default_fps or 16
        media = _encode_video_bytes(out.frames[0], fps)
        mime = "video/mp4"
    else:
        media = _encode_image_bytes(out.images[0])
        mime = "image/png"

    return DenoiseResult(
        latents=None,
        media=media,
        mime=mime,
        seed_used=seed,
        steps_completed=params.steps,
        total_steps=params.steps,
        boundary_index=None,
    )


def _load_image(data: bytes) -> Any:
    from PIL import Image

    return Image.open(io.BytesIO(data)).convert("RGB")


def denoise_split(
    loaded: LoadedPipeline,
    params: MediaGenParams,
    *,
    input_image: bytes | None = None,
    inbound_latents: Any = None,
) -> DenoiseResult:
    """Run one expert's half of a split schedule.

    The high-noise expert starts from fresh noise and stops at the boundary. The
    low-noise expert starts from the handed-off latent, tells the scheduler where
    in the schedule it is resuming, runs to the end, and decodes.
    """
    import torch

    pair = loaded.entry.expert_pair
    if pair is None:
        raise ValueError("whole model reached the split path")
    if loaded.role is None:
        raise ValueError("split path needs a role")

    pipe = loaded.pipe
    device = pipe._execution_device
    transformer = loaded.transformer
    transformer_dtype = transformer.dtype

    if getattr(pipe.config, "expand_timesteps", False):
        raise ValueError(
            f"{loaded.entry.id} sets expand_timesteps; the split loop does not "
            "carry a first-frame mask"
        )

    seed = _resolve_seed(params.seed)
    generator = torch.Generator(device=device).manual_seed(seed)

    split_at = boundary_index(pipe, params.steps, pair.boundary_ratio)
    timesteps = pipe.scheduler.timesteps

    prompt_embeds, negative_prompt_embeds = _encode_prompts(pipe, params, device)
    do_cfg = negative_prompt_embeds is not None

    num_frames = params.num_frames or loaded.entry.default_num_frames
    num_channels = transformer.config.in_channels

    condition = None
    if loaded.kind.requires_input_image:
        if input_image is None:
            raise ValueError(f"{loaded.kind.value} needs a conditioning image")
        # Both halves recompute the conditioning latent: it is derived from the
        # image the job names, so it is identical on both machines and does not
        # need to cross the wire. The latents this returns are discarded on the
        # low-noise half in favour of the handed-off ones.
        prepared, condition = pipe.prepare_latents(
            _load_image(input_image),
            1,
            num_channels,
            params.height,
            params.width,
            num_frames,
            torch.float32,
            device,
            generator,
            None,
        )
    else:
        prepared = pipe.prepare_latents(
            1,
            num_channels,
            params.height,
            params.width,
            num_frames,
            torch.float32,
            device,
            generator,
            None,
        )

    if loaded.role is MediaGenExpertRole.HIGH_NOISE:
        latents = prepared
        owned = timesteps[:split_at]
        pipe.scheduler.set_begin_index(0)
    else:
        if inbound_latents is None:
            raise ValueError("low-noise expert needs the handed-off latent")
        latents = inbound_latents.to(device=device, dtype=torch.float32)
        owned = timesteps[split_at:]
        pipe.scheduler.set_begin_index(split_at)

    for t in owned:
        latent_model_input = (
            torch.cat([latents, condition], dim=1).to(transformer_dtype)
            if condition is not None
            else latents.to(transformer_dtype)
        )
        timestep = t.expand(latents.shape[0])

        with transformer.cache_context("cond"):
            noise_pred = transformer(
                hidden_states=latent_model_input,
                timestep=timestep,
                encoder_hidden_states=prompt_embeds,
                return_dict=False,
            )[0]

        if do_cfg:
            with transformer.cache_context("uncond"):
                noise_uncond = transformer(
                    hidden_states=latent_model_input,
                    timestep=timestep,
                    encoder_hidden_states=negative_prompt_embeds,
                    return_dict=False,
                )[0]
            noise_pred = noise_uncond + params.guidance_scale * (noise_pred - noise_uncond)

        latents = pipe.scheduler.step(noise_pred, t, latents, return_dict=False)[0]

    if loaded.role is MediaGenExpertRole.HIGH_NOISE:
        return DenoiseResult(
            latents=latents,
            media=None,
            mime="application/octet-stream",
            seed_used=seed,
            steps_completed=split_at,
            total_steps=params.steps,
            boundary_index=split_at,
        )

    frames = _decode_video(pipe, latents)
    fps = params.fps or loaded.entry.default_fps or 16
    return DenoiseResult(
        latents=None,
        media=_encode_video_bytes(frames, fps),
        mime="video/mp4",
        seed_used=seed,
        steps_completed=params.steps - split_at,
        total_steps=params.steps,
        boundary_index=split_at,
    )


def encode_latents(result: DenoiseResult, params: MediaGenParams) -> bytes:
    """Serialize the intermediate latent for the handoff.

    safetensors so the low-noise worker can load the tensor without executing
    anything the high-noise worker wrote. The sidecar metadata is str→str
    because that is all the format carries; it records the schedule position the
    receiving expert must resume from, and the receipt's ``steps_completed`` is
    signed over separately so this copy is a convenience, not the authority.
    """
    from safetensors.torch import save

    if result.latents is None:
        raise ValueError("no latents to encode")
    tensor = result.latents.contiguous().cpu()
    metadata = {
        "steps_completed": str(result.steps_completed),
        "total_steps": str(result.total_steps),
        "boundary_index": str(result.boundary_index),
        "seed": str(result.seed_used),
        "shape": json.dumps(list(tensor.shape)),
        "dtype": str(tensor.dtype).removeprefix("torch."),
        "width": str(params.width),
        "height": str(params.height),
    }
    return save({"latents": tensor}, metadata=metadata)


def decode_latents(data: bytes) -> tuple[Any, dict[str, str]]:
    """Load a handed-off latent back into a tensor plus its sidecar metadata."""
    from safetensors import safe_open

    with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as fh:
        fh.write(data)
        path = fh.name
    try:
        with safe_open(path, framework="pt") as f:
            metadata = dict(f.metadata() or {})
            tensor = f.get_tensor("latents")
    finally:
        os.unlink(path)
    return tensor, metadata
