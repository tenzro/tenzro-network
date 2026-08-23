# Provider capability records

How a consumer decides which provider to route to, when providers are
heterogeneous, self-interested, and untrusted.

A signature proves *who* published a number. It never proves the number is
true. Every field below is classified by how a consumer can come to believe
it, and that classification — not the field list — is the design.

## Why declared capability does not work

The strongest evidence is not from a decentralised network. It is Azure
retiring the Azure Compute Unit, its published cross-SKU performance scalar,
after roughly a decade:

> Azure is no longer publishing ACUs since the metric has limited ability to
> inform users of the expected performance of a virtual machine across various
> attributes. For the most accurate results on a specific virtual machine,
> Azure recommends users run their workload(s) on that virtual machine to
> verify performance.
>
> — learn.microsoft.com/azure/virtual-machines/acu, archived 2024-08-22

A hyperscaler with full control of its own fleet concluded that a declared
number cannot represent delivered performance, and told customers to measure.
A permissionless network has strictly less control and strictly more incentive
to misreport.

The same pattern shows up wherever the declared number is checked:

- One EC2 instance family spans two CPU generations (`c5.large`–`c5.9xlarge`
  on Xeon 8124M, `c5.12xlarge`+ on 8275CL). Azure's B-series spans **five**,
  and the vendor's advice is to "query the virtual hardware from within the
  virtual machine" to discover which you got.
- `c5.large` advertises "Up to 10 Gigabit" against a baseline of **0.75
  Gbps** — a 13× gap, burstable "typically from 5 to 60 minutes".
- A `t3.medium` sold as 2 vCPU has a sustained entitlement of 20% of a vCPU
  each: ~0.4 vCPU steady state.
- AWS, GCP and Azure SLAs all define their only measurable quantity as
  **connectivity minutes**. None commits to GHz, IOPS, Gbps or latency. A
  machine that answers while delivering a fraction of its advertised
  throughput is 100% available and generates no credits.

So the incumbents neither guarantee nor even publish performance. A network
that ranks providers on self-declared capability is doing something the people
with the most control gave up on.

## What the field must be classified by

### (a) Externally measurable — a consumer can verify without cooperation

Derivable from ordinary streaming responses. These are the only fields a
consumer should weight heavily.

| Field | Meaning |
|---|---|
| `itl_intercept_ms` | per-step cost of streaming model weights |
| `itl_slope_us_per_ctx_token` | per-step cost of streaming one token of KV |
| `ttft_slope_ms_per_prompt_token` | prefill cost per prompt token |
| `observed_at`, `sample_count` | when, and over how many requests |

Decode is memory-bandwidth-bound and prefill is FLOPs-bound, so they are
different machines and must be ranked separately. Ranking one provider on a
blend of the two sends a long-prompt request to a node that is fast at decode
and slow at prefill.

**These are the most reliable fields, not reliable fields.** What a client-side
timer actually measures is the joint output of the provider's batching policy,
speculation config, cache state, chunked-prefill budget, stream buffer size,
tier assignment, quantization, and network path — plus how fast the measuring
client drains its own socket. Model and hardware speed is one term in that sum
and not obviously the largest. Three of those knobs deserve naming because a
provider can move its ranking without touching hardware:

- **Stream buffering is a server flag.** vLLM's `--stream-interval` batches
  tokens before sending; SGLang's `batch_notify_size` defaults to **16**, so
  chunks arrive in clumps under concurrency even at `stream_interval=1`. vLLM
  additionally merges outputs when the producer outruns the consumer — so
  measured ITL depends partly on the measuring client.
- **`max_num_batched_tokens` is a direct TTFT↔ITL dial.** Smaller values give
  better ITL, larger give better TTFT. One integer trades one ranking against
  the other, with no model, hardware, or API change.
- **Prefix caching lands entirely on TTFT.** vLLM is explicit that automatic
  prefix caching "does not reduce the time of generating new tokens" — so the
  cache confound hits the first number any harness reports, and the cache is
  instance-global rather than tenant-scoped.

That is not an argument against measuring. It is an argument for measuring
**distributions rather than means**, recording provenance, and treating the
result as a service-level observation rather than a hardware fact.

**This model is not ours.** DistServe (OSDI 2024, App. A.3) publishes it term
for term — `T_Decoding = C₄(4h² + 2hm) + C₅·3ht`, both constants fitted by
profiling. LLMVisor fits the same two parameters by OLS. Databricks' MBU is the
same equation rearranged. The closest match is arXiv 2605.15051, which
decomposes per-request demand into "load-independent and load-dependent
components" and infers effective batch size via Little's Law — intercept and
slope, named as such. Cite them; do not claim the model.

What has no clear prior art is the **inversion** — fitting the slope on a
black-box endpoint to recover its KV bytes per token or effective bandwidth.
The nearest neighbour, NightVision (arXiv 2607.01313), does exactly this move
on the *prefill*, compute-bound side and explicitly treats bandwidth as a
nuisance parameter it does not solve for. Inventive step is thin: it is
DistServe's published equation solved for a different unknown. Treat it as a
measurement technique, not a discovery, and note no patent search was done.

Measured first-party on a GB10 serving Qwen3.8-27B-FP8: intercept 124.17 ms,
slope 0.3355 µs/token, TTFT slope 0.650 ms/token, decode:prefill ≈ 191:1 —
which independently reproduces Sarathi-Serve's 128:1 on an A100, on entirely
different silicon.

**Three traps in measuring this.**

*Reasoning models.* A probe reading only `content` deltas measured **zero
tokens** on a reasoning model, because it emits `reasoning` deltas first. Both
are decode steps and both cost a full pass over the weights. A probe that
yields no tokens must be recorded as `unknown`, never as a slow provider — a
measurement that returns zero looks identical to a measurement of zero.

*The word "ITL" means three incompatible things.* They coincide only when
every stream chunk carries exactly one token and there are no stalls — that is,
not under speculative decoding or chunked prefill:

| Quantity | Who | Note |
|---|---|---|
| request-mean over n−1 | vLLM TPOT, MLPerf TPOT, DistServe | averages away stalls |
| raw inter-**chunk** gap | vLLM ITL, SGLang default, Sarathi TBT | inflated when chunks bundle tokens |
| chunk gap ÷ tokens in chunk | NVIDIA GenAI-Perf, SGLang retokenized | corrects bundling |

"P99 TPOT" is a percentile over *requests*; "P99 ITL" is a percentile over
*token gaps*. Different populations, routinely compared as if identical. Record
which one a number is.

*Metric names drift.* vLLM renamed `vllm:time_per_output_token_seconds` to
`vllm:inter_token_latency_seconds` — the same quantity, correctly renamed —
so any figure citing "vLLM TPOT" from ≤ v0.10.0 Prometheus is reporting ITL.
Scrape a live endpoint and pin parser tests to its actual exposition text
rather than to documentation.

**Probe hygiene, if we measure providers ourselves.** Each of these is a way to
measure your own harness instead of the provider:

1. **Never count SSE chunks as tokens.** Re-tokenize the text, or divide each
   gap by the tokens in that chunk. A harness that equates chunks with tokens
   overstates ITL by roughly the acceptance length on a speculative-decoding
   provider — *penalising the faster system*.
2. **Randomise a high-entropy prefix per request**, or you measure your own
   cache hits. Note this cuts both ways: Azure starts *missing* the cache above
   ~15 requests/minute on identical prefixes, so probe rate changes hit rate in
   both directions.
3. **Report token1→token2 separately** from steady-state ITL. Disaggregated
   prefill puts a one-off KV transfer there — Splitwise measures ~5–8 ms and
   16.5% added latency to the second token specifically.
4. **Discard warm-ups explicitly.** Fetching a 130 GB checkpoint takes ~26 s;
   a single unwarmed request does not perturb a mean, it destroys it.
5. **Never fold 429-retry time into latency silently.** Worse, a harness that
   *drops* 429s selectively deletes its slowest samples — biasing p99 downward
   exactly when the provider is under load.
6. **Prefer percentiles and variance to means.** A mean survives chunk
   coalescing; the distribution does not, and the distribution is where
   speculation, stream buffering and proxy buffering all appear as the *same*
   signature from *different* causes.

One more reason to distrust the mean: measured human reading speed is ~4.8
tokens/s. Bursts above that are perceptually wasted while the pauses between
them are perceptually costly, so **mean tokens/s credits the wasted part and
hides the costly part — systematically rewarding bursty serving.**

### (b) Self-declared but verifiable — believe after checking

Cheap to claim, cheap to falsify. Accept, then verify, then downgrade.

| Field | How it is checked |
|---|---|
| `prefix_cache` summary | gated on `prefix_cache_queries_total > 0` at the provider |
| `mtp_enabled` | provider-side, over the models actually announced |
| `active_requests`, `max_concurrent_requests` | scraped from the serving engine |
| `architecture`, `engine_version`, `quant_format` | a probe of the served model contradicts a false claim |

Advertise capability by `(architecture, engine version, format)`, never by GPU
model. The same NVFP4 checkpoint is a full win on sm100 and a silent
W4A16-Marlin fallback on Hopper; an L40S running QServe can beat an A100
running TRT-LLM. GPU model tells a consumer nothing actionable.

Version skew is a correctness hazard, not just a performance one: a vLLM FP8-KV
accumulation bug produced **13% vs 89%** on 128k needle-in-a-haystack — same
checkpoint, same flags, different version.

**Claims expire, at different rates.** Nosana — the closest working prior art —
expires GPU metrics after **3 hours** and LLM throughput metrics after **5
days**, and re-benchmarks continuously rather than only at onboarding. A
capability record without a TTL is a claim about the past presented as a claim
about the present.

### (c) Self-declared and unverifiable — record, never rank on

| Field | Why it cannot be checked |
|---|---|
| `geography` / `jurisdiction` | an operator can claim any region |
| `moe_holdings`, `moe_roles` | no consumer-side probe |
| `requests_per_second` ceiling | a declared ceiling, not an observation |

Fail closed on these: an absent jurisdiction claim must mean the node never
satisfies a jurisdiction pin, never that it satisfies all of them.

## Two rules that fall out of the classification

**An absent value is unknown, never the most attractive value.** `0` in
`active_requests` reads as "idle", which is the single most attractive thing a
provider can publish and the most dangerous to fabricate. It is also the serde
default, so a truncated announcement lands in the winning bucket for free. A
failed scrape must return `None` and leave prior values intact.

The same reasoning applies to any concurrency ceiling: `max_concurrent_requests
== 0` must mean *unknown*, not *infinite*, or declaring nothing beats answering
honestly.

**Validate adversarial fields where they are decoded.** Advertised warm-prefix
trees arrive in gossip; a signature proves who sent one, not that it is honest.
Roughly 61,000 radix nodes fit in a single gossip frame, and the match walk
rescans the vector per prompt run, so an oversized tree makes every routing
decision expensive. A `run_len` other than the constant the honest producer
emits is a forgery that wins every affinity tie-break while holding no cache.
Both are enforced at the deserialization boundary.

## What the network can and cannot promise

MLPerf shows what "verified" actually costs: an unaltered harness owning the
clock, math constrained to be equivalent to a reference implementation,
mandatory compliance tests, **peer review of results and code** with objections
citing offending lines, and third-party audit with two days of hardware access
and the burden of proof on the submitter. Too heavy for a permissionless
network.

But one piece transfers exactly — **name control**. A result not submitted for
review may not be called verified:

> If you used an MLPerf benchmark to obtain a result … but did not submit …
> for MLCommons review, then your result is unverified, and you must disclose
> this fact.

That is the model for trust tiers. Not "trusted vs untrusted", but a claim
carrying its own provenance:

| Tier | Meaning |
|---|---|
| `measured` | consumer-side observation, with `observed_at` |
| `attested` | provider-side, cross-checked against a live probe |
| `declared` | published, unchecked — recorded, not ranked on |

Prior art brackets the honest range. Nosana **measures** GPU model with its own
software and gates market admission on a real benchmark, with an anti-spoof
subsystem. SALAD **self-reports** hardware from its agent, keeps its "Trust
Rating" formula private, and pushes verification to the buyer:

> The most efficient way to manage performance variances across nodes is to
> perform initial checks while instances are running and verify requirements …
> before serving traffic.

Render's OctaneBench is client-run on the operator's machine — auto-triggered,
but not attested; its published node tiers turn out to be *artist-selected job
tiers*, not node grades.

None of these attests hardware cryptographically outside dedicated TEE markets.
That is the realistic bar.

And measurement itself is gameable, which the most rigorous public measurer
concedes by contract. Artificial Analysis binds providers not to "detect,
fingerprint, or otherwise identify Artificial Analysis traffic … and serve it
differently", not to route it "to dedicated, reserved, or non-public
resources", and not to serve it "at a batch size, concurrency, or load
configuration that is not representative". Those clauses exist because each is
achievable. A measurement regime therefore needs unpredictable timing and
unattributable origin, not merely a good harness — the same reasoning that
makes consumer-side observation preferable to a provider-run benchmark.

## Attestation cannot answer the capability question

The obvious objection to all of this is: why measure, when hardware attestation
could prove what the GPU is? Because attestation answers a different question,
and the gap is structural rather than a gap in maturity.

**Attested inference means attested code identity, never attested execution
quality.** Across TDX, SEV-SNP and Nitro, the quote bodies carry firmware and
kernel measurements, register hashes, and a chip identity — and nothing else.
NVIDIA's remote attestation is the same shape: `hwmodel`, `driver_version`,
`vbios_version`. Surveying the full NRAS claim list turns up **no claim for
FLOPS, memory bandwidth, clock speed, SM count, MIG partition size, power
limit, or thermal throttling**.

So attestation answers *"is this really an H100 die"*. It does not answer
*"does this host deliver H100-class throughput to my job"*. Those come apart in
practice, and the observed failure modes are all **genuine, fully attestable
GPUs that underdeliver by 1.5–2.8×**: a 100 W-capped A100, an RTX 3090 running
at 444 GB/s, a card behind a mining riser with ~2.8 GB/s of PCIe bandwidth.
Every one would pass attestation. None would serve at its nameplate.

Three further limits, worth knowing before betting on it:

- **Coverage.** NVIDIA CC is Hopper and Blackwell only, which excludes the
  entire consumer long tail a permissionless network is largely made of.
- **Binding.** TEE.fail (IEEE S&P 2026) reports that NVIDIA attestation
  reports are *not bound to the identity of a specific confidential VM*, so a
  malicious host can relay a genuine attestation while the job runs elsewhere.
- **Weights.** Of the confidential-inference providers surveyed, only one binds
  the model weight bytes into the launch measurement. The rest attest a
  container that fetches weights at runtime from a mutable tag — so the
  attestation covers the code that downloads the model, not the model.

And attestation is not free: measured TEE overhead is under ~7% for typical
LLM queries but **+19–25% on TTFT**, and on Blackwell's serialised bridge,
24.7–27.6% for MoE routing and **+131% on TTFT** for KV-cache restoration. It
is a confidentiality mechanism with a performance cost, not a capability oracle.

### What survives an untrusted host

Everything readable from the host is unsigned and rewritable by the operator —
`nvidia-smi`, NVML, DCGM, NVAPI, `lscpu`, PCI config space, and the GPU UUID.
This is not hypothetical: published tooling spoofs one GPU model as another,
rewrites the GPU UUID (defeating UUID-keyed ban lists), and makes a cluster
with zero GPUs advertise `nvidia.com/gpu` complete with synthetic metrics.

Four signal classes survive, in rough order of cost:

1. **Kernel-authored inventories the userspace shim does not write** —
   `/proc/driver/nvidia/gpus/*/information`, `/sys/devices/system/cpu/present`.
   Cheap, and catches the common spoof.
2. **Integrity of the driver stack** — hashing `libnvidia-ml` against
   known-good digests per driver version, which catches a preloaded fake NVML.
3. **Device attestation** — identity and firmware only, per the ceiling above.
4. **Observed behaviour under a verifier-chosen challenge** — a challenge the
   provider cannot precompute. Verifiable-matmul schemes (Freivalds plus a
   Merkle commitment, with the challenge vector secret until the commitment is
   made) and deterministic re-execution both work here; the latter has a useful
   side effect, since bit-exactness holds only within an architecture, making
   it an implicit hardware detector needing no attestation at all.

Two families that do **not** work, so nobody rebuilds them: proof-of-learning
is broken in the literature, and zkML is hardware-blind by construction — it
proves the function was computed, not which silicon computed it.

**This is the strongest argument for the classification at the top of this
document.** Attestation gives identity; only behaviour gives capability. So
capability belongs in tier (a) — measured, with provenance and an expiry — and
attestation, where available, belongs in tier (b) as a check on *identity*
claims rather than as evidence of speed.

## Identity is the precondition

A capability record is only worth as much as the identity it is attached to.
Two properties have to hold before any of the above means anything:

- **The identity must be durable and non-transferable**, or reputation resets
  on a whim and Sybils are free. Node identity derives from a TPM primary in
  the *endorsement* hierarchy — it survives a wiped data directory and a
  `TPM2_Clear`, and cannot be moved to another chip.
- **The announcement must prove it owns the identity it claims.** Otherwise a
  peer publishes another node's `peer_id` and inherits its advertised
  capability wholesale — warm caches, speculative flag, idle count. The
  announce key is signed by the libp2p key, and a verifier recomputes `peer_id`
  from the carried key before believing anything else in the message.

Where authority is delegated to a human rather than a machine, the root is a
passkey — as a **delegation** over a machine-generated key, not a derived
secret. `prf`/`hmac-secret` cannot serve: synced passkeys replicate the secret
across devices by design, and `hmac-secret` refuses to evaluate without user
presence, so an unattended node can never re-derive. Those two identity classes
are different trust tiers and should be recorded and priced as such.

## References

Every quantitative claim above traces to a primary source. Key ones:

- Azure ACU retirement — learn.microsoft.com/azure/virtual-machines/acu (archived 2024-08-22)
- EC2 network bandwidth / burst — docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-network-bandwidth.html
- EC2 burstable credits — docs.aws.amazon.com/AWSEC2/latest/UserGuide/burstable-credits-baseline-concepts.html
- Azure B-series processor list — learn.microsoft.com/azure/virtual-machines/sizes/general-purpose/bv1-series
- AWS / GCP / Azure SLAs — aws.amazon.com/compute/sla, cloud.google.com/compute/sla, microsoft.com/licensing/docs/view/Service-Level-Agreements-SLA-for-Online-Services
- DistServe decode model — arxiv.org/abs/2401.09670, Appendix A.3
- Sarathi-Serve chunked prefill / TBT — arxiv.org/abs/2403.02310
- Databricks MBU — databricks.com/blog/llm-inference-performance-engineering-best-practices
- MLPerf inference rules — github.com/mlcommons/inference_policies/blob/master/inference_rules.adoc
- MLPerf submission + review — github.com/mlcommons/policies/blob/master/submission_rules.adoc
- MLPerf results messaging — github.com/mlcommons/policies/blob/master/MLPerf_Results_Messaging_Guidelines.adoc
- vLLM benchmark metrics — github.com/vllm-project/vllm/blob/main/vllm/benchmarks/serve.py
- Nosana benchmark suite (live) — host-manager.k8s.prd.nos.ci/benchmarks/operations
- SALAD verification guidance — docs.salad.com/container-engine/tutorials/performance/high-performance-apps.md
- WebAuthn `prf` — w3.org/TR/webauthn-3/, §10.1.4; CTAP 2.1/2.3 `hmac-secret`
- Speculative-decoding latency model — arxiv.org/abs/2605.15051
- Black-box architecture inference from TTFT — arxiv.org/abs/2607.01313
- Prompt-cache side channel, global sharing across users — arxiv.org/abs/2502.07776 (ICML 2025)
- Speculative decoding, capped-geometric acceptance — arxiv.org/abs/2211.17192
- Perceived vs delivered token speed — arxiv.org/abs/2404.16283
- Splitwise, second-token transfer cost — arxiv.org/abs/2311.18677
- Artificial Analysis performance methodology — artificialanalysis.ai/methodology/performance-benchmarking
- vLLM prefix caching — docs.vllm.ai/en/latest/features/automatic_prefix_caching.html
- vLLM stream interval — docs.vllm.ai/en/latest/cli/serve.html
- NVIDIA attestation claims — docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html
- TEE.fail, attestation not bound to a CVM — tee.fail
- Confidential-computing overhead on Hopper — arxiv.org/abs/2409.03992
- Proof-of-learning is broken — arxiv.org/abs/2108.09454, arxiv.org/abs/2208.03567
- Verifiable matmul challenge — github.com/PrimeIntellect-ai/gpu-challenge
- Deterministic re-execution — arxiv.org/abs/2502.19405
