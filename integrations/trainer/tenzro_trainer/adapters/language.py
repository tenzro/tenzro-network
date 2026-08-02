"""Language trainer adapter — Qwen 3 family.

This is the real inner-loop driver for decoder-only LM training under
decoupled outer aggregation. The default backbone is **Qwen 3 0.6B**, which matches
the entries in the Tenzro model catalog at
``crates/tenzro-model/src/catalog.rs`` — the same family that the network
serves via llama.cpp at inference time, so trained outer-gradient roots
can be slotted directly into the serving fleet.

Loaded via :class:`transformers.AutoModelForCausalLM` so any other
catalog-member LM family (Qwen 2 / 3.5 / 3.6 / Gemma 3 / 4 / Mistral /
Phi 3 / DeepSeek V3 / Granite / Granite-H) drops in by changing
``architecture.metadata.hf_repo`` — no code change. Llama is intentionally
**not** the default: it is not in the Tenzro registry.

MoE backbones (Qwen3-MoE-class) work out of the box: expert weights are
ordinary named parameters so the name-sorted fragment partition covers
them, the router/gating layers train alongside, and the auxiliary
load-balancing loss is added to the cross-entropy objective when the
model reports one (``output_router_logits`` is enabled at load time for
MoE configs).

Under torchrun (``RANK``/``WORLD_SIZE`` set), the model is sharded with
FSDP2 (``torch.distributed.fsdp.fully_shard``) — per-parameter DTensor
sharding, bf16 compute with fp32 gradient reduction — before the optimizer
is constructed; see ``docs/AI.md §7.7.1``. Single-process runs skip
sharding entirely. Attention dispatches to FlashAttention-2 when the
``flash_attn`` package and an accelerator are present (CUDA, or the AMD
ROCm build of the package; SDPA otherwise), and
``architecture.metadata.fp8`` opts eligible linear layers into torchao FP8
training on Ada/Hopper-class GPUs. AMD ROCm GPUs run bf16/fp16 + SDPA (or
ROCm FlashAttention); QLoRA on ROCm needs the patched bitsandbytes wheel.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

try:
    import torch
    from torch import nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


from tenzro_trainer.accel import maybe_convert_fp8, resolve_attn_implementation
from tenzro_trainer.distributed import DistContext, shard_model_fsdp2
from tenzro_trainer.muon import build_inner_optimizer
from tenzro_trainer.shards import resolve_shard

log = logging.getLogger(__name__)


# bitsandbytes builds at or below this version carry a 4-bit dequant NaN bug
# on ROCm; the fixed line ships as a pre-release wheel. See the ROCm install
# note in ``docs/AI.md``.
_BNB_ROCM_MIN_SAFE = (0, 49, 3)


def _warn_if_rocm_bnb_4bit_nan_risk() -> None:
    """Warn once when QLoRA is requested on ROCm with a NaN-prone bitsandbytes.

    On a ROCm/HIP torch build, 4-bit NF4 dequant in ``bitsandbytes`` produces
    NaN gradients on builds <= 0.49.2. The check is advisory — training still
    proceeds — because the operator may have installed a patched wheel whose
    version string does not parse cleanly.
    """
    if torch is None or getattr(torch.version, "hip", None) is None:
        return
    try:
        import bitsandbytes as bnb

        raw = str(getattr(bnb, "__version__", "")).split("+")[0]
        parts = tuple(int(p) for p in raw.split(".")[:3])
    except Exception:
        return
    if parts and parts < _BNB_ROCM_MIN_SAFE:
        log.warning(
            "QLoRA (nf4) on ROCm with bitsandbytes %s: builds <= 0.49.2 have a "
            "4-bit dequant NaN bug on AMD GPUs. Install the ROCm pre-release "
            "wheel (bitsandbytes-1.33.7.preview) or >= 0.49.1; see the ROCm "
            "install note in docs/AI.md.",
            ".".join(str(p) for p in parts),
        )


# Default HF repo for the language adapter — Qwen 3 0.6B is the smallest
# entry in the Tenzro catalog's language section, ideal for whole-pipeline
# rehearsals. Production runs override this via
# ``architecture.metadata.hf_repo``.
DEFAULT_HF_REPO = "Qwen/Qwen3-0.6B"


def is_moe_config(config: Any) -> bool:
    """True when a HF model config describes a mixture-of-experts backbone.

    Covers the attribute names used across the catalog MoE families:
    Qwen3-MoE (``num_experts``), Mixtral-style (``num_local_experts``),
    DeepSeek V3 (``n_routed_experts``), and Qwen2-MoE
    (``moe_intermediate_size``).
    """
    for attr in (
        "num_experts",
        "num_local_experts",
        "n_routed_experts",
        "moe_intermediate_size",
    ):
        value = getattr(config, attr, None)
        if isinstance(value, int) and value > 0:
            return True
    return False


def moe_parameter_names(model: nn.Module) -> tuple[list[str], list[str]]:
    """Split a MoE model's parameter names into ``(expert, router)`` lists.

    Expert weights live under ``.experts.`` submodules; router/gating
    weights carry ``.gate.`` or ``router`` in their name (Qwen3-MoE uses
    ``mlp.gate``, Mixtral uses ``block_sparse_moe.gate``, DeepSeek V3 uses
    ``mlp.gate`` — all covered). Both sets are ordinary named parameters,
    so the name-sorted fragment partition covers them without special
    handling; this split exists for diagnostics and tests.
    """
    expert_names: list[str] = []
    router_names: list[str] = []
    for name, _ in model.named_parameters():
        lowered = name.lower()
        if ".experts." in lowered:
            expert_names.append(name)
        elif ".gate." in lowered or "router" in lowered:
            router_names.append(name)
    return expert_names, router_names


def lora_factor_names(model: nn.Module) -> tuple[list[str], list[str]]:
    """Split a PEFT-wrapped model's trainable params into ``(a_names, b_names)``.

    PEFT names LoRA matrices ``...lora_A.<adapter>.weight`` and
    ``...lora_B.<adapter>.weight``. Under alternating low-rank aggregation we
    freeze one factor per round; this split tells :meth:`set_round` which
    parameters to toggle.
    """
    a_names: list[str] = []
    b_names: list[str] = []
    for name, _ in model.named_parameters():
        if "lora_A" in name:
            a_names.append(name)
        elif "lora_B" in name:
            b_names.append(name)
    return a_names, b_names


@dataclass
class LanguageAdapter:
    """Real HF-backed causal-LM adapter.

    Loads the model + tokenizer once at construction; ``shard_batches``
    streams over a text shard (one document per line, or a single flat
    UTF-8 blob), tokenizes on the fly, and yields packed ``(input_ids,
    labels)`` tensors of fixed ``seq_len``. Standard causal-LM loss:
    next-token cross-entropy with ``ignore_index=-100`` on the padding
    positions of the final block.

    When ``lora_alternating`` is set (the model was wrapped with PEFT and the
    task selected ``AggregationRule::LoraAlternating``), :meth:`set_round`
    freezes one low-rank factor per round so each round's transmitted delta is
    a single factor — the shape the Rust syncer's per-coordinate mean is
    correct for.
    """

    _model: nn.Module
    _optimizer: torch.optim.Optimizer
    _tokenizer: Any
    seq_len: int = 1024
    batch_size: int = 1
    device: str = "cpu"
    data_seed: int = 0
    lora_alternating: bool = False
    _lora_a_names: list[str] = field(default_factory=list)
    _lora_b_names: list[str] = field(default_factory=list)

    def model(self) -> nn.Module:
        return self._model

    def optimizer(self) -> torch.optim.Optimizer:
        return self._optimizer

    def set_round(self, round_index: int) -> None:
        """Alternating low-rank freeze: sync B on even rounds, A on odd rounds.

        No-op unless ``lora_alternating`` is on. On an even round we freeze the
        A factors (``requires_grad=False``) and leave B trainable, so only B is
        snapshotted and transmitted; on an odd round the roles swap. Holding
        the other factor fixed across all contributors is what makes a plain
        per-coordinate mean of the active factor correct.
        """
        if not self.lora_alternating:
            return
        train_b = round_index % 2 == 0
        params = dict(self._model.named_parameters())
        for name in self._lora_a_names:
            if name in params:
                params[name].requires_grad_(not train_b)
        for name in self._lora_b_names:
            if name in params:
                params[name].requires_grad_(train_b)

    def shard_batches(self, shard_uri: str) -> Iterable[object]:
        if torch is None:
            raise RuntimeError("PyTorch is required")
        # Resolve the shard URI. tenzro:// fetches from the local node's
        # iroh blob store; ipfs:// / ar:// / http(s):// go through gateways.
        # Confidential-tier shards arrive pre-decrypted as `file://`
        # pointers into an enclave-private tmpfs; see
        # `tenzro_trainer.confidential.unwrap_shard`.
        path = resolve_shard(shard_uri)

        with open(path, "rb") as f:
            text = f.read().decode("utf-8", errors="replace")
        if not text:
            raise ValueError(f"language shard {path!r} is empty after UTF-8 decode")

        # One-shot tokenize. For larger shards a streaming
        # token-pack pipeline would be the next iteration —
        # adequate for Phase 1 / smoke runs.
        ids = self._tokenizer(
            text,
            return_tensors="pt",
            add_special_tokens=False,
            truncation=False,
        ).input_ids[0]
        if ids.shape[0] < self.seq_len + 1:
            raise ValueError(
                f"language shard {path!r} too small: "
                f"{ids.shape[0]} tokens, need at least seq_len+1={self.seq_len + 1}"
            )

        # Per-rank seed: under torchrun every rank must sample different
        # offsets from the shard, otherwise the world trains on identical
        # batches and the data-parallel width is wasted.
        rng = torch.Generator()
        rng.manual_seed(self.data_seed)
        n = ids.shape[0] - self.seq_len - 1
        while True:
            offsets = torch.randint(0, n, (self.batch_size,), generator=rng)
            x = torch.stack([ids[o : o + self.seq_len] for o in offsets])
            y = torch.stack([ids[o + 1 : o + 1 + self.seq_len] for o in offsets])
            yield x.to(self.device), y.to(self.device)

    def compute_loss(self, batch: object) -> torch.Tensor:
        if torch is None:
            raise RuntimeError("PyTorch is required")
        x, y = batch  # type: ignore[misc]
        out = self._model(input_ids=x)
        # `transformers` causal-LM heads return a `CausalLMOutput`-style
        # object with `.logits` — `[B, T, V]`. Flatten for cross-entropy.
        logits = out.logits if hasattr(out, "logits") else out[0]
        loss = torch.nn.functional.cross_entropy(
            logits.reshape(-1, logits.shape[-1]),
            y.reshape(-1),
            ignore_index=-100,
        )
        # MoE backbones surface a router load-balancing auxiliary loss
        # (already scaled by `router_aux_loss_coef` inside the model) when
        # `output_router_logits` is on — add it so the gating layers train.
        aux = getattr(out, "aux_loss", None)
        if aux is not None:
            loss = loss + aux
        return loss


@dataclass
class LanguageRolloutAdapter:
    """HF-backed :class:`tenzro_trainer.rl.RolloutAdapter` for GRPO post-training.

    Wraps the same model/optimizer/tokenizer that :func:`build_adapter`
    produces. Prompts come one-per-line from the shard; sampling is a manual
    temperature-scaled loop so the per-token logprobs of the *actually drawn*
    tokens are captured at sampling time (the anchor for the surrogate ratio
    and the k3 KL penalty in :func:`tenzro_trainer.rl.grpo_loss`).
    """

    _model: nn.Module
    _optimizer: torch.optim.Optimizer
    _tokenizer: Any
    max_prompt_len: int = 512
    device: str = "cpu"

    def model(self) -> nn.Module:
        return self._model

    def optimizer(self) -> torch.optim.Optimizer:
        return self._optimizer

    def shard_prompts(self, shard_uri: str) -> Iterable[str]:
        path = resolve_shard(shard_uri)
        with open(path, "rb") as f:
            text = f.read().decode("utf-8", errors="replace")
        prompts = [line.strip() for line in text.splitlines() if line.strip()]
        if not prompts:
            raise ValueError(f"prompt shard {path!r} has no non-empty lines")
        return prompts

    def _encode_prompt(self, prompt: str) -> torch.Tensor:
        ids = self._tokenizer(
            prompt,
            return_tensors="pt",
            add_special_tokens=True,
            truncation=True,
            max_length=self.max_prompt_len,
        ).input_ids
        return ids.to(self.device)

    def sample_rollouts(
        self,
        prompt: str,
        group_size: int,
        max_new_tokens: int,
        temperature: float,
    ) -> list:
        if torch is None:
            raise RuntimeError("PyTorch is required")
        from tenzro_trainer.rl import Rollout

        prompt_ids = self._encode_prompt(prompt)
        eos_id = self._tokenizer.eos_token_id
        rollouts: list[Rollout] = []
        self._model.eval()
        with torch.no_grad():
            for _ in range(group_size):
                ids = prompt_ids.clone()
                token_ids: list[int] = []
                logprobs: list[torch.Tensor] = []
                for _step in range(max_new_tokens):
                    logits = self._forward_logits(ids)[0, -1, :]
                    lp = torch.log_softmax(
                        logits.float() / temperature, dim=-1
                    )
                    next_id = int(torch.multinomial(lp.exp(), 1).item())
                    token_ids.append(next_id)
                    logprobs.append(lp[next_id].detach())
                    ids = torch.cat(
                        [ids, torch.tensor([[next_id]], device=ids.device)],
                        dim=1,
                    )
                    # Always keep at least one generated token so the
                    # rollout has a defined loss even when the policy
                    # opens with EOS.
                    if eos_id is not None and next_id == eos_id:
                        break
                completion = self._tokenizer.decode(
                    token_ids, skip_special_tokens=True
                )
                rollouts.append(
                    Rollout(
                        completion=completion,
                        token_ids=token_ids,
                        old_logprobs=torch.stack(logprobs),
                    )
                )
        self._model.train()
        return rollouts

    def rollout_logprobs(
        self, prompt: str, rollout: Any, temperature: float
    ) -> torch.Tensor:
        if torch is None:
            raise RuntimeError("PyTorch is required")
        prompt_ids = self._encode_prompt(prompt)
        completion_ids = torch.tensor(
            [rollout.token_ids], device=prompt_ids.device, dtype=prompt_ids.dtype
        )
        full = torch.cat([prompt_ids, completion_ids], dim=1)
        logits = self._forward_logits(full)
        p = prompt_ids.shape[1]
        t = completion_ids.shape[1]
        # Position i predicts token i+1: completion tokens P..P+T-1 are
        # predicted by positions P-1..P+T-2.
        pred = logits[0, p - 1 : p - 1 + t, :]
        lp = torch.log_softmax(pred.float() / temperature, dim=-1)
        return lp.gather(1, completion_ids[0].unsqueeze(1)).squeeze(1)

    def _forward_logits(self, input_ids: torch.Tensor) -> torch.Tensor:
        out = self._model(input_ids=input_ids)
        return out.logits if hasattr(out, "logits") else out[0]


def build_rollout_adapter(
    architecture: dict[str, Any],
    hyperparams: dict[str, Any] | None = None,
) -> LanguageRolloutAdapter:
    """Construct the GRPO rollout adapter on top of :func:`build_adapter`.

    Reuses the full loading pipeline (HF repo resolution, dtype, MoE, LoRA,
    FSDP2, inner optimizer) and rewraps the pieces behind the
    :class:`tenzro_trainer.rl.RolloutAdapter` protocol. Extra hyperparam:
    ``max_prompt_len`` (default 512).
    """
    hp = hyperparams or {}
    base = build_adapter(architecture, hyperparams)
    return LanguageRolloutAdapter(
        _model=base._model,
        _optimizer=base._optimizer,
        _tokenizer=base._tokenizer,
        max_prompt_len=int(hp.get("max_prompt_len", 512)),
        device=base.device,
    )


def build_adapter(
    architecture: dict[str, Any],
    hyperparams: dict[str, Any] | None = None,
) -> LanguageAdapter:
    """Construct a Qwen 3 (or other catalog-family) HF causal-LM adapter.

    Reads ``architecture.metadata.hf_repo`` (defaults to ``Qwen3-0.6B``)
    and ``architecture.metadata.dtype`` (``"bf16"`` | ``"fp16"`` | ``"fp32"``,
    default ``"bf16"``). MoE repos (Qwen3-MoE-class) are auto-detected from
    the config and get ``output_router_logits=True`` so the auxiliary
    load-balancing loss reaches ``compute_loss``. Hyperparams accepted:

    * ``inner_optimizer`` (``muon`` | ``adamw`` | ``sgd``, default ``adamw``)
    * ``learning_rate`` (default 1e-5 — small for LMs)
    * ``weight_decay`` (default 0.0)
    * ``seq_len`` (default 1024)
    * ``batch_size`` (default 1)
    * ``device`` (default ``"cuda"`` if available else ``"cpu"``)

    LoRA/QLoRA is opt-in via ``architecture.metadata.lora``. When present, the
    base is frozen and PEFT injects low-rank adapter matrices; only those
    matrices carry gradient, so the outer-gradient snapshot transmits adapter
    deltas alone. Recognized ``lora`` sub-keys:

    * ``r`` (rank, default 16)
    * ``alpha`` (default ``2*r``)
    * ``dropout`` (default 0.0)
    * ``target_modules`` (default ``["q_proj","k_proj","v_proj","o_proj",
      "gate_proj","up_proj","down_proj"]`` — the attention + MLP projections
      shared across the catalog decoder families)
    * ``quantize`` (``"nf4"`` for QLoRA 4-bit base, else full-precision base)
    * ``alternating`` (default ``True`` — alternating low-rank per-round factor freeze,
      matching :class:`AggregationRule::LoraAlternating` on the syncer side)
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as e:
        raise ImportError(
            "The language adapter requires the `transformers` package. "
            "Install with: `pip install tenzro-trainer[language]`"
        ) from e

    md = (architecture or {}).get("metadata") or {}
    hp = hyperparams or {}
    repo = str(md.get("hf_repo") or DEFAULT_HF_REPO)
    dtype_str = str(md.get("dtype", "bf16")).lower()
    dtype = {
        "bf16": torch.bfloat16,
        "fp16": torch.float16,
        "fp32": torch.float32,
    }.get(dtype_str, torch.bfloat16)
    ctx = DistContext.detect()
    if ctx.enabled and torch.cuda.is_available():
        device = f"cuda:{ctx.local_rank}"
    else:
        device = str(
            hp.get("device") or ("cuda" if torch.cuda.is_available() else "cpu")
        )
    lora_cfg = md.get("lora")

    attn_impl = resolve_attn_implementation(md)
    load_kwargs: dict[str, Any] = {
        "torch_dtype": dtype,
        "trust_remote_code": True,
        "attn_implementation": attn_impl,
    }
    quantize = str((lora_cfg or {}).get("quantize", "")).lower()
    if lora_cfg is not None and quantize == "nf4":
        # QLoRA: 4-bit NF4 base, adapters trained in bf16 on top.
        try:
            from transformers import BitsAndBytesConfig
        except ImportError as e:
            raise ImportError(
                "QLoRA (lora.quantize='nf4') requires `bitsandbytes`. "
                "Install with: `pip install tenzro-trainer[language]`"
            ) from e
        _warn_if_rocm_bnb_4bit_nan_risk()
        load_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=dtype,
        )

    log.info(
        "loading causal LM %r (dtype=%s, device=%s, attn=%s) ...",
        repo,
        dtype_str,
        device,
        attn_impl,
    )
    tokenizer = AutoTokenizer.from_pretrained(repo, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(repo, **load_kwargs)
    # A 4-bit base is placed by the quantizer; only move a full-precision base.
    if "quantization_config" not in load_kwargs:
        model = model.to(device)

    if is_moe_config(model.config):
        # Surface the router load-balancing aux loss on every forward so
        # the gating layers receive gradient (compute_loss adds it to CE).
        model.config.output_router_logits = True
        expert_names, router_names = moe_parameter_names(model)
        log.info(
            "MoE backbone detected: %d expert params, %d router params "
            "(aux load-balancing loss enabled)",
            len(expert_names),
            len(router_names),
        )

    lora_alternating = False
    lora_a_names: list[str] = []
    lora_b_names: list[str] = []
    if lora_cfg is not None:
        try:
            from peft import LoraConfig, get_peft_model
        except ImportError as e:
            raise ImportError(
                "LoRA (architecture.metadata.lora) requires the `peft` package. "
                "Install with: `pip install tenzro-trainer[language]`"
            ) from e
        if quantize == "nf4":
            from peft import prepare_model_for_kbit_training

            model = prepare_model_for_kbit_training(model)
        rank = int(lora_cfg.get("r", 16))
        peft_config = LoraConfig(
            r=rank,
            lora_alpha=int(lora_cfg.get("alpha", 2 * rank)),
            lora_dropout=float(lora_cfg.get("dropout", 0.0)),
            target_modules=list(
                lora_cfg.get(
                    "target_modules",
                    [
                        "q_proj",
                        "k_proj",
                        "v_proj",
                        "o_proj",
                        "gate_proj",
                        "up_proj",
                        "down_proj",
                    ],
                )
            ),
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, peft_config)
        lora_a_names, lora_b_names = lora_factor_names(model)
        lora_alternating = bool(lora_cfg.get("alternating", True))
        trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
        log.info(
            "LoRA enabled (r=%d, %d A-factors, %d B-factors, "
            "alternating=%s, quantize=%s): %d trainable params",
            rank,
            len(lora_a_names),
            len(lora_b_names),
            lora_alternating,
            quantize or "none",
            trainable,
        )

    model = maybe_convert_fp8(model, md)

    if ctx.enabled:
        if quantize == "nf4":
            raise ValueError(
                "QLoRA (lora.quantize='nf4') cannot be combined with FSDP2 "
                "sharding: bitsandbytes 4-bit parameters are not DTensor-"
                "compatible. Run QLoRA single-process, or drop `quantize` "
                "for multi-process LoRA."
            )
        model = shard_model_fsdp2(model, ctx)
        log.info(
            "FSDP2 sharding applied (rank %d/%d)", ctx.rank, ctx.world_size
        )

    opt = build_inner_optimizer(model, md, hp, default_lr=1e-5)
    log.info(
        "built language adapter %r: %d params",
        repo,
        sum(p.numel() for p in model.parameters()),
    )
    return LanguageAdapter(
        _model=model,
        _optimizer=opt,
        _tokenizer=tokenizer,
        seq_len=int(hp.get("seq_len", 1024)),
        batch_size=int(hp.get("batch_size", 1)),
        device=device,
        data_seed=ctx.rank,
        lora_alternating=lora_alternating,
        _lora_a_names=lora_a_names,
        _lora_b_names=lora_b_names,
    )


__all__ = [
    "DEFAULT_HF_REPO",
    "LanguageAdapter",
    "LanguageRolloutAdapter",
    "build_adapter",
    "build_rollout_adapter",
    "is_moe_config",
    "moe_parameter_names",
]
