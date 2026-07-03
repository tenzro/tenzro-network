"""Language trainer adapter — Qwen 3 family.

This is the real inner-loop driver for decoder-only LM training under
Decoupled DiLoCo. The default backbone is **Qwen 3 0.6B**, which matches
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

Wraps cleanly under :class:`torch.distributed.fsdp.FullyShardedDataParallel`
(FSDP2) when the caller has initialized a process group — see
``docs/AI.md §7.7.1``. Plain DDP and single-GPU paths work out of the box.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable

try:
    import torch
    from torch import nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


from tenzro_trainer.muon import build_inner_optimizer

log = logging.getLogger(__name__)


# Default HF repo for the language adapter — Qwen 3 0.6B is the smallest
# entry in the Tenzro catalog's language section, ideal for end-to-end
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


def moe_parameter_names(model: "nn.Module") -> tuple[list[str], list[str]]:
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


@dataclass
class LanguageAdapter:
    """Real HF-backed causal-LM adapter.

    Loads the model + tokenizer once at construction; ``shard_batches``
    streams over a text shard (one document per line, or a single flat
    UTF-8 blob), tokenizes on the fly, and yields packed ``(input_ids,
    labels)`` tensors of fixed ``seq_len``. Standard causal-LM loss:
    next-token cross-entropy with ``ignore_index=-100`` on the padding
    positions of the final block.
    """

    _model: "nn.Module"
    _optimizer: "torch.optim.Optimizer"
    _tokenizer: Any
    seq_len: int = 1024
    batch_size: int = 1
    device: str = "cpu"

    def model(self) -> "nn.Module":
        return self._model

    def optimizer(self) -> "torch.optim.Optimizer":
        return self._optimizer

    def shard_batches(self, shard_uri: str) -> Iterable[object]:
        if torch is None:
            raise RuntimeError("PyTorch is required")
        # Resolve the shard URI. Confidential-tier shards arrive
        # pre-decrypted as `file://` pointers into an enclave-private
        # tmpfs; see `tenzro_trainer.confidential.unwrap_shard`.
        if shard_uri.startswith("file://"):
            path = shard_uri[len("file://") :]
        elif shard_uri.startswith(("ipfs://", "ar://", "https://", "http://")):
            raise NotImplementedError(
                f"remote shard scheme not supported in reference trainer "
                f"(fetch upstream, expose as file:// or via the confidential "
                f"unwrap helper): {shard_uri}"
            )
        else:
            path = shard_uri

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

        rng = torch.Generator()
        rng.manual_seed(0)
        n = ids.shape[0] - self.seq_len - 1
        while True:
            offsets = torch.randint(0, n, (self.batch_size,), generator=rng)
            x = torch.stack([ids[o : o + self.seq_len] for o in offsets])
            y = torch.stack([ids[o + 1 : o + 1 + self.seq_len] for o in offsets])
            yield x.to(self.device), y.to(self.device)

    def compute_loss(self, batch: object) -> "torch.Tensor":
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
    device = str(hp.get("device") or ("cuda" if torch.cuda.is_available() else "cpu"))

    log.info("loading causal LM %r (dtype=%s, device=%s) ...", repo, dtype_str, device)
    tokenizer = AutoTokenizer.from_pretrained(repo, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        repo,
        torch_dtype=dtype,
        trust_remote_code=True,
    ).to(device)

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
    )


__all__ = [
    "LanguageAdapter",
    "build_adapter",
    "is_moe_config",
    "moe_parameter_names",
    "DEFAULT_HF_REPO",
]
