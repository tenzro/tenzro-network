"""Tenzro timeseries ONNX export harness.

Usage:
    python export.py <target_id> [--out <dir>] [--opset 17]

Each target's architecture is dispatched to a dedicated export function.
The output is always a single-file ONNX with shape `[1, context_len]
-> [1, horizon]` or `[1, horizon, n_quantiles]` so the Tenzro
`TimeseriesRuntime::GenericForecast` adapter can load it without
per-model tweaks.

Supported architectures:
- timesfm:      Google TimesFM 2.5, patch decoder (Apache 2.0, Google).
- chronos2:     Amazon Chronos-2 (Apache 2.0), exported with the five-input,
                quantile-major contract `Chronos2Forecast` loads: `context`,
                `group_ids`, `attention_mask` (f32), `future_covariates`,
                `future_covariates_mask` -> `quantile_preds` [B, 13, 672].

Every export is reproducible: the base weights are fetched at the revision
`targets.toml` pins, the trace runs on CPU in float32 with fixed seeds, and
the same toolchain (`requirements-lock.txt`) writes byte-identical files.
`--expect-sha256` refuses an export whose bytes differ from the published one.

`timesfm` uses a hand-rolled torch.onnx.export wrapper because its
published `forward()` signature doesn't match the `[B, T] -> [B, H, Q]`
shape the runtime expects. The wrapper module adapts the real model's
I/O to the runtime's contract before tracing.
"""

from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

import torch


# ──────────────────────────────────────────────────────────────────────
# Target registry
# ──────────────────────────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class Target:
    id: str
    hf_repo: str
    arch: str
    license: str
    params: str
    context_length: int
    max_horizon: int
    n_quantiles: int
    notes: str
    revision: str = "main"


def load_targets(path: Path | None = None) -> dict[str, Target]:
    here = Path(__file__).resolve().parent
    targets_path = path or (here / "targets.toml")
    with targets_path.open("rb") as f:
        raw = tomllib.load(f)
    out: dict[str, Target] = {}
    for entry in raw.get("target", []):
        t = Target(**entry)
        out[t.id] = t
    return out


# ──────────────────────────────────────────────────────────────────────
# Architecture-specific export functions
# ──────────────────────────────────────────────────────────────────────


def export_timesfm(target: Target, out_path: Path, opset: int) -> Path:
    """Export TimesFM 2.5 200M.

    TimesFM uses a 32-token patch tokenizer and a decoder-only
    transformer. Tracing the full inference loop (autoregressive patch
    generation) is fragile; instead, we trace the single-shot forecast
    head which Google ships for fixed-horizon evaluation.
    """
    try:
        from timesfm import TimesFmHparams, TimesFmTorch
    except ImportError as e:
        raise RuntimeError(
            "timesfm export requires `pip install timesfm[torch]`. "
            "This dep is intentionally not in pyproject.toml because it "
            "drags in a large optional ecosystem."
        ) from e

    hparams = TimesFmHparams(
        backend="cpu",
        per_core_batch_size=1,
        horizon_len=target.max_horizon,
        context_len=target.context_length,
        num_layers=50,
    )
    print(f"  → loading {target.hf_repo}")
    model = TimesFmTorch(hparams=hparams, repo=target.hf_repo)
    model.load_from_checkpoint()

    class TimesFmWrapper(torch.nn.Module):
        def __init__(self, inner, horizon: int):
            super().__init__()
            self.inner = inner
            self.horizon = horizon

        def forward(self, history: torch.Tensor) -> torch.Tensor:
            # TimesFm returns (mean, quantiles) — quantiles is [B, H, 10].
            _mean, quantiles = self.inner.forecast_on_tensor(
                history, freq=[0]  # 0 = unknown frequency
            )
            return quantiles

    wrapper = TimesFmWrapper(model, target.max_horizon).eval()
    dummy = torch.randn(1, target.context_length, dtype=torch.float32)

    print(f"  → tracing to ONNX (opset={opset})")
    torch.onnx.export(
        wrapper,
        (dummy,),
        out_path.as_posix(),
        input_names=["history"],
        output_names=["quantiles"],
        dynamic_axes={
            "history": {0: "batch"},
            "quantiles": {0: "batch"},
        },
        opset_version=opset,
        do_constant_folding=True,
    )
    return out_path


def _lower_nanmean() -> None:
    """Replace `nanmean`, which has no ONNX lowering, with operators that lower.

    The same mean over the values that are not NaN: a sum over the kept values
    divided by their count (NaN where there are none, as `nanmean` gives).
    """

    def nanmean(x, dim=None, keepdim=False, *, dtype=None):
        keep = torch.isnan(x).logical_not()
        total = torch.where(keep, x, torch.zeros_like(x)).sum(dim=dim, keepdim=keepdim)
        return total / keep.sum(dim=dim, keepdim=keepdim).to(x.dtype)

    torch.nanmean = nanmean
    torch.Tensor.nanmean = nanmean


def export_chronos2(target: Target, out_path: Path, opset: int) -> Path:
    """Export Chronos-2 with the contract the runtime's `Chronos2Forecast` reads.

    The model's own forward takes the context with an optional mask and a
    patch count; the wrapper fixes the horizon at `max_horizon` (42 output
    patches of 16), names the inputs as the runtime feeds them, and returns
    the quantiles `[B, Q, T]`.
    """
    try:
        from chronos.chronos2 import Chronos2Model
    except ImportError as e:
        raise RuntimeError("chronos2 export requires `pip install chronos-forecasting`") from e

    print(f"  → loading {target.hf_repo}@{target.revision}")
    model = Chronos2Model.from_pretrained(target.hf_repo, revision=target.revision, torch_dtype=torch.float32)
    model = model.eval()
    patch = model.chronos_config.output_patch_size
    if target.max_horizon % patch:
        raise RuntimeError(f"max_horizon {target.max_horizon} is not a multiple of the output patch {patch}")
    num_output_patches = target.max_horizon // patch

    class Chronos2Contract(torch.nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def forward(self, context, group_ids, attention_mask, future_covariates, future_covariates_mask):
            out = self.inner(
                context=context,
                context_mask=attention_mask,
                group_ids=group_ids,
                future_covariates=future_covariates,
                future_covariates_mask=future_covariates_mask,
                num_output_patches=num_output_patches,
            )
            return out.quantile_preds

    wrapper = Chronos2Contract(model).eval()

    _lower_nanmean()
    # `arcsinh` and `sinh` are the norm's optional squashing.
    # Patching with a stride equal to the patch size is a reshape; `unfold`
    # has no ONNX lowering for a length known only at run time. The runtime
    # pads every context to a whole number of patches before it is fed.
    from chronos.chronos_bolt import Patch

    if model.patch.patch_size != model.patch.patch_stride:
        raise RuntimeError("only non-overlapping patches export as a reshape")

    def patch_forward(self, x):
        return x.reshape(x.shape[0], -1, self.patch_size)

    Patch.forward = patch_forward

    # The [REG] token's id is built with `torch.full`, which the tracer
    # records as a float constant; an embedding lookup needs integer ids.
    shared = model.shared
    model.shared.forward = lambda ids: torch.nn.functional.embedding(ids.long(), shared.weight)
    _register_hyperbolic(opset)
    batch, ctx = 1, 512
    example = (
        torch.zeros(batch, ctx, dtype=torch.float32),
        torch.zeros(batch, dtype=torch.int64),
        torch.ones(batch, ctx, dtype=torch.float32),
        torch.zeros(batch, target.max_horizon, dtype=torch.float32),
        torch.zeros(batch, target.max_horizon, dtype=torch.float32),
    )
    print(f"  → tracing to ONNX (opset={opset})")
    with torch.no_grad():
        torch.onnx.export(
            wrapper,
            example,
            out_path.as_posix(),
            input_names=["context", "group_ids", "attention_mask", "future_covariates", "future_covariates_mask"],
            output_names=["quantile_preds"],
            dynamic_axes={
                "context": {0: "batch", 1: "context_length"},
                "group_ids": {0: "batch"},
                "attention_mask": {0: "batch", 1: "context_length"},
                "future_covariates": {0: "batch"},
                "future_covariates_mask": {0: "batch"},
                "quantile_preds": {0: "batch"},
            },
            opset_version=opset,
            do_constant_folding=True,
            dynamo=False,
        )
    return out_path


def _register_hyperbolic(opset: int) -> None:
    # `arcsinh` and `sinh` map one to one onto the ONNX operators of the same
    # name, which the exporter does not wire.
    torch.onnx.register_custom_op_symbolic("aten::asinh", lambda g, x: g.op("Asinh", x), opset)
    torch.onnx.register_custom_op_symbolic("aten::sinh", lambda g, x: g.op("Sinh", x), opset)


def _export_single_input(wrapper: torch.nn.Module, target: Target, out_path: Path, opset: int) -> Path:
    """Trace a `context [1, ctx] -> quantiles [1, H, Q]` wrapper at fixed shapes."""
    t = torch.arange(target.context_length, dtype=torch.float32)
    example = (torch.sin(t / 24.0).unsqueeze(0),)
    print(f"  → tracing to ONNX (opset={opset})")
    with torch.no_grad():
        torch.onnx.export(
            wrapper,
            example,
            out_path.as_posix(),
            input_names=["context"],
            output_names=["quantiles"],
            opset_version=opset,
            do_constant_folding=True,
            dynamo=False,
        )
    return out_path


def tirex2_trend_flag(x: torch.Tensor, threshold: float, min_r2: float) -> torch.Tensor:
    """The checkpoint's trend test as tensor operations, so the graph keeps it.

    Upstream decides in NumPy whether a series is differenced before the
    forward pass: an ordinary least-squares line through the z-scored series,
    trending when `|slope| * length` reaches `threshold` and the fit's R^2
    reaches `min_r2`. The same closed-form fit in float64 on the whole (fully
    observed) context. Returns a `[1]` bool.
    """
    v = x[0].to(torch.float64)
    n = v.shape[-1]
    idx = torch.arange(n, dtype=torch.float64)
    mean = v.mean()
    std = torch.sqrt(((v - mean) ** 2).sum() / (n - 1))
    z = (v - mean) / torch.clamp(std, min=1e-300)
    i_c = idx - idx.mean()
    slope = (i_c * (z - z.mean())).sum() / (i_c * i_c).sum()
    intercept = z.mean() - slope * idx.mean()
    resid = z - (slope * idx + intercept)
    ss_res = (resid * resid).sum()
    ss_tot = ((z - z.mean()) ** 2).sum()
    r2 = torch.where(ss_tot > 1e-12, 1.0 - ss_res / torch.clamp(ss_tot, min=1e-300), torch.zeros_like(ss_tot))
    score = slope.abs() * n
    flag = (std >= 1e-12) & (score >= threshold) & (r2 >= min_r2)
    return flag.reshape(1)


def export_tirex2(target: Target, out_path: Path, opset: int) -> Path:
    """Export TiRex-2 as one input `context [1, ctx]` -> `quantiles [1, H, 9]`.

    The checkpoint differences a trending series before the forward pass and
    integrates the forecast back. Upstream makes that choice in Python, which a
    trace cannot keep, so the graph runs both paths (the raw series and the
    differenced one) and selects with the in-graph trend test. The recurrent
    layers run the package's native CPU kernels.
    """
    try:
        from tirex2 import TimeseriesType, load_model
    except ImportError as e:
        raise RuntimeError("tirex2 export requires `pip install tirex-2`") from e

    print(f"  → loading {target.hf_repo}@{target.revision}")
    model = load_model(target.hf_repo, device="cpu", hf_kwargs={"revision": target.revision})
    backbone = model.model if hasattr(model, "model") else model
    backbone = backbone.eval()
    if backbone.tta_sign_flip:
        raise RuntimeError("sign-flip augmentation is not part of this export contract")
    if backbone.context_len != target.context_length or backbone.future_len != target.max_horizon:
        raise RuntimeError(
            f"checkpoint is ctx {backbone.context_len} / future {backbone.future_len}, "
            f"targets.toml says {target.context_length} / {target.max_horizon}"
        )
    # Blocks the package compiles at import cannot be traced; their plain
    # call path computes the same thing.
    for cls in {type(m) for m in backbone.modules()}:
        for name in ("__call__", "_call_impl"):
            orig = getattr(cls.__dict__.get(name), "_torchdynamo_orig_callable", None)
            if orig is not None:
                setattr(cls, name, orig)
    _lower_nanmean()
    _register_hyperbolic(opset)
    # Patching with a stride equal to the patch size is a reshape; the traced
    # `unfold` loses the length its lowering needs.
    from tirex2.model.component.patch_tokenizer import Patch as TiRexPatch

    def patch_forward(self, x):
        if self.patch_size != self.patch_stride or x.shape[-1] % self.patch_size:
            raise RuntimeError("only whole, non-overlapping patches export as a reshape")
        return x.reshape(x.shape[0], -1, self.patch_size)

    TiRexPatch.forward = patch_forward
    post = backbone.postprocessor
    cfg = post.cfg

    def run(context: torch.Tensor, differenced: bool) -> torch.Tensor:
        post._detect_trends = lambda x: [differenced] * (1 if x.ndim == 1 else x.shape[0])
        ts = TimeseriesType(target=context, past_covariates=None, future_covariates=None)
        return backbone.predict([ts], target.max_horizon, tta_diff=True)[0]  # [1, Q, H]

    class TiRex2Contract(torch.nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def forward(self, context):
            raw = run(context, False)
            diff = run(context, True)
            flag = tirex2_trend_flag(context, cfg.trend_threshold, cfg.trend_min_r2)
            out = torch.where(flag.reshape(1, 1, 1), diff, raw)
            return out.transpose(1, 2)

    return _export_single_input(TiRex2Contract(backbone).eval(), target, out_path, opset)


def export_toto2(target: Target, out_path: Path, opset: int) -> Path:
    """Export Toto 2.0 as one input `context [1, ctx]` -> `quantiles [1, H, 9]`.

    The whole horizon decodes in one block (`decode_block_size = max_horizon`),
    the upstream single-pass path with no cache; the decoder is causal, so a
    shorter horizon is the leading slice of the same output.
    """
    try:
        from toto2 import Toto2Model
    except ImportError as e:
        raise RuntimeError("toto2 export requires `pip install toto-models`") from e

    print(f"  → loading {target.hf_repo}@{target.revision}")
    model = Toto2Model.from_pretrained(target.hf_repo, revision=target.revision).float().eval()
    patch = model.config.patch_size
    if target.max_horizon % patch or target.context_length % patch:
        raise RuntimeError(f"context and horizon must be whole patches of {patch}")

    class Toto2Contract(torch.nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def forward(self, context):
            series = context.unsqueeze(1)
            q = self.inner.forecast(
                {
                    "target": series,
                    "target_mask": torch.ones_like(series, dtype=torch.bool),
                    "series_ids": torch.zeros(1, 1, dtype=torch.long),
                },
                horizon=target.max_horizon,
                decode_block_size=target.max_horizon,
                has_missing_values=False,
            )  # [Q, 1, 1, H]
            return q[:, 0, 0, :].transpose(0, 1).unsqueeze(0)

    # The causal scaler takes a running sum of the boolean mask; ONNX CumSum
    # has no boolean form. The same sums over the mask as floats.
    from toto2.model import PatchedCausalStdScaler

    loc_scale = PatchedCausalStdScaler._compute_loc_scale
    PatchedCausalStdScaler._compute_loc_scale = lambda self, data, mask: loc_scale(self, data, mask.to(data.dtype))
    _register_hyperbolic(opset)
    return _export_single_input(Toto2Contract(model).eval(), target, out_path, opset)


EXPORTERS = {
    "timesfm": export_timesfm,
    "chronos2": export_chronos2,
    "tirex2": export_tirex2,
    "toto2": export_toto2,
}


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target_id", help="ID from targets.toml (e.g. 'timesfm-2.5-200m')")
    p.add_argument(
        "--out",
        type=Path,
        default=Path("./out"),
        help="output directory (default: ./out)",
    )
    p.add_argument(
        "--opset",
        type=int,
        default=17,
        help="ONNX opset version (default: 17 — matches ort 2.x baseline)",
    )
    p.add_argument(
        "--targets-file",
        type=Path,
        default=None,
        help="path to targets.toml (default: alongside this script)",
    )
    p.add_argument(
        "--expect-sha256",
        default=None,
        help="refuse the export unless its SHA-256 is this (reproducibility check)",
    )
    args = p.parse_args(argv)

    targets = load_targets(args.targets_file)
    if args.target_id not in targets:
        known = ", ".join(sorted(targets.keys()))
        print(f"Unknown target '{args.target_id}'. Known: {known}", file=sys.stderr)
        return 2

    target = targets[args.target_id]
    if target.arch not in EXPORTERS:
        print(
            f"No exporter wired for arch='{target.arch}'. "
            f"Add one to EXPORTERS in export.py.",
            file=sys.stderr,
        )
        return 2

    torch.manual_seed(0)
    torch.use_deterministic_algorithms(True)
    args.out.mkdir(parents=True, exist_ok=True)
    out_path = args.out / f"{target.id}.onnx"

    print(f"Exporting {target.id} ({target.hf_repo}) → {out_path}")
    print(f"  arch={target.arch}, params={target.params}, license={target.license}")
    print(f"  context_length={target.context_length}, max_horizon={target.max_horizon}")

    exporter = EXPORTERS[target.arch]
    exporter(target, out_path, args.opset)

    import hashlib

    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    size = out_path.stat().st_size
    print(f"OK — {out_path} ({size} bytes, sha256 {digest})")
    if args.expect_sha256 is not None and digest != args.expect_sha256:
        print(f"the export is not reproducible: expected sha256 {args.expect_sha256}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
