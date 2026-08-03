# Running a node on a unified-memory host

Applies to NVIDIA Grace-Blackwell (GB10 / DGX Spark), Apple Silicon, and AMD
APUs — any part where the GPU pool **is** system memory rather than a separate
device.

On a discrete card, over-committing GPU memory is a bounded failure: CUDA
raises, one job dies, the process lives. On a coherent-memory part there is no
separate pool to exhaust, so the same over-commit is served by the kernel until
the machine runs out and the **global OOM killer** starts choosing victims
across every cgroup — including the node, and including whatever else the
operator was running. The blast radius is the machine, not the request.

Everything below comes out of a real incident on a 121 GB GB10 on 2026-08-03.

---

## 1. The models are not what fills the machine

A full five-modality serving set is comfortable on 121 GB:

| Slot               | Model                                  |   Resident |
| ------------------ | -------------------------------------- | ---------: |
| Text               | Qwen3.6-35B-A3B MTP, 32 concurrent     |     ~28 GB |
| Embeddings         | Qwen3-Embedding-4B (ONNX, fp32)        |     ~16 GB |
| Image **or** video | one diffusion pipeline at a time       |     ~21 GB |
| Timeseries         | TimesFM 2.5 200M                       |      ~1 GB |
| —                  | node process (RocksDB, runtimes, mesh) |     ~17 GB |
|                    | **Total**                              | **~83 GB** |

What took the machine down was not the models. It was `cargo nextest run
--workspace` on the same box: every test binary statically embeds llama.cpp, and
**13 concurrent GNU `ld` processes ran at 12–13 GB RSS each — roughly 85 GB of
linker**. The node was OOM-killed twice as collateral.

**Do not build the workspace on a node that is serving.** If you must, see §4.

---

## 2. `--gpu-vram-gb` is the only thing bounding the pipeline cache

The media-gen worker caches diffusion pipelines and evicts LRU while
`resident + needed > budget` (`integrations/media_gen/.../worker.py`,
`_evict_until_fits`). A budget larger than the machine does not merely permit
more caching — it disables the bound outright, because the condition never
becomes true.

The incident configuration was `--gpu-vram-gb 100` on a 121 GB box. A 14 GB
image pipeline plus a 21 GB video pipeline is 35 GB, which never exceeds 100, so
both stayed resident forever and the LRU never fired once.

Size the budget to **one pipeline at a time**, not to the machine:

```
--gpu-vram-gb 34      # holds the largest single pipeline, forces image/video to alternate
```

Since 2026-08-03 the worker clamps this itself: `resolve_vram_budget_gb()`
detects a shared pool using the same `vram * 8 >= ram * 7` rule as
`tenzro_types::hardware::shared_memory_pool`, and caps the budget at 70% of it
(matching the `total_ram_gb * 0.7` rule in `tenzro-cli/src/commands/join.rs`).
An oversized figure is clamped with a warning rather than honoured. The clamp is
a backstop, not a substitute for choosing the number.

The same clamp guards `WorkerConfig.capability()`, which advertises
`gpu_vram_gb` to the node — an unclamped worker would otherwise solicit jobs
sized for memory it does not have.

---

## 3. Give the node a floor and the OOM killer a preference

Both node and worker run as systemd **user** units. The memory controller is
delegated to the user manager on a stock Ubuntu 24.04+ install (check with
`cat /sys/fs/cgroup/user.slice/user-1000.slice/cgroup.subtree_control`), so
`MemoryMin` / `MemoryHigh` / `MemoryMax` and a negative `OOMScoreAdjust` all
work without root.

`~/.config/systemd/user/tenzro-node.service.d/memory.conf`:

```ini
[Service]
# Never reclaimed under pressure — a runaway build cannot page the served
# models back out.
MemoryMin=32G

# The node was killed twice at oom_score_adj:200 — the kernel valued it no more
# than a linker. Bias selection away from the thing serving the network.
OOMScoreAdjust=-500
```

`~/.config/systemd/user/tenzro-media-gen.service.d/memory.conf`:

```ini
[Service]
MemoryHigh=40G
MemoryMax=52G
```

Verify a limit actually took, rather than trusting the unit file:

```bash
systemctl --user show tenzro-node.service -p MemoryMin -p OOMScoreAdjust
```

---

## 4. Contain builds instead of trusting them

Interactive shells are where `cargo` gets launched, and on GNOME they live under
`app-org.gnome.Terminal.slice`. Cap that slice to the headroom the models leave:

`~/.config/systemd/user/app-org.gnome.Terminal.slice.d/memory.conf`:

```ini
[Slice]
MemoryHigh=24G     # reclaim pressure first
MemoryMax=30G      # then kill the build, and only the build
```

Confirm the ceiling is live:

```bash
cat /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/\
app-org.gnome.Terminal.slice/memory.max
```

Then cut the peak itself, with `mold` and a job cap:

```toml
# ~/.cargo/config.toml
[build]
jobs = 12          # one linker per job; 20 cores will start 20 of them
```

```bash
# ~/.bashrc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=mold"
```

**The linker flag must be an environment variable, not `~/.cargo/config.toml`.**
The repository's own `.cargo/config.toml` pins
`[target.aarch64-unknown-linux-gnu] rustflags = []`, and repo config outranks
user config for the same key — a `rustflags` entry in the user file is silently
ignored. Environment variables outrank both. `-fuse-ld=mold` is deliberately
kept out of the committed config so builders without mold (including CI) are
unaffected.

---

## 5. Reading the aftermath

The kernel names the victim, but the victim is rarely the cause. Get the whole
task list from the last OOM event, sorted by RSS, rather than the single
`Killed process` line:

```bash
journalctl -b -1 -k | rg "Out of memory: Killed"          # every victim
journalctl -b -1 -k | rg -A400 "invoked oom-killer" | tail -120   # task dump
```

Two readings that matter:

- **RSS in the task dump is in pages, not kB.** Multiply by 4096. A row reading
  `3182742` is 12.7 GB, not 3 GB.
- **Repeated kills of the same service are a symptom, not the fault.** In the
  incident, `stellar-core` was killed six times and the node twice, while the
  actual consumer — thirteen linkers — was never killed at all until the end,
  because each individual `ld` looked no worse than its neighbours.

---

## 6. Checklist before serving

- [ ] `--gpu-vram-gb` sized to one pipeline, not to the machine
- [ ] `MemoryMin` + negative `OOMScoreAdjust` on the node unit
- [ ] `MemoryHigh`/`MemoryMax` on the shell slice, sized to leftover headroom
- [ ] `mold` exported as a target-scoped env var; `jobs` capped
- [ ] No other memory-hungry service sharing the box (a second chain daemon,
      an IDE indexer, a container build)
- [ ] `free -g` after all models load shows real headroom, not just `available`
      inflated by page cache — mmap'd GGUF weights count as cache
