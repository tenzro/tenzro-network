# Serving one model across your own machines

A model too large for one machine can be served by several machines of one
operator on the same local network. Each machine loads a contiguous range of the
model's blocks. The first machine holds the token embedding, takes requests and
drives generation; every later machine receives the hidden states of the
machine before it, runs its blocks and passes the result on; the last machine
holds the output head and returns logits up the chain. The weights never move
between machines, only the hidden states of the tokens being processed.

The split runs inside the Praecise engine in each node process. No separate
serving program is started.

## Who may take part

Every machine in a pipeline must be an accepted member of the operator's
cluster (see `docs/AI.md`, section 3.5): a membership list the operator approved
with their passkey and that every listed machine accepted with its own hardware
key. A machine outside that list is refused even if the table below names it.

Each link between two machines is authenticated by both ends. Each signs the
handshake transcript with the hardware key (TPM or Secure Enclave) its machine
DID derives from, and checks that the other's DID derives from the key that
signed and is a member of the cluster. The keys that encrypt the link are made
fresh for each connection from an ephemeral exchange the two signatures bind; no
key is configured, distributed or stored, and no key leaves the hardware.

## Configuration

Every machine of the pipeline carries the same table in its node configuration
and finds its own place by its machine DID (`tenzro node layer-pipeline-status`
prints it, configured or not):

```toml
[layer_pipeline]
model_id = "qwen3-235b-a22b"
micro_batch = 64            # tokens per micro-batch (default 64)
context_length = 8192       # default 8192
answer_timeout_secs = 120   # default 120

[[layer_pipeline.stages]]
machine_did = "did:tenzro:machine:..."   # drives generation; no address

[[layer_pipeline.stages]]
machine_did = "did:tenzro:machine:..."
address = "192.168.1.21:7300"            # where this stage listens
weight = 2                               # optional share of the blocks

[[layer_pipeline.stages]]
machine_did = "did:tenzro:machine:..."
address = "192.168.1.22:7300"
```

Blocks are split in proportion to `weight` (default 1 each, for example the
machine's memory in GB). To place them by hand, give every stage
`layers = [begin, end]`; the ranges must cover the model's blocks in order.

Every machine must have downloaded the same weights for `model_id` before it
starts. The machines compare a digest of their weights, the block split and
every machine's DID when they connect, and refuse to connect when any of them
differs.

Supported architectures: Llama, Qwen2, Qwen3 and Qwen3-MoE. A model of any
other architecture is refused when its first stage loads.

## Operation

Start the later machines in any order, then the first. The first machine
retries every 15 seconds until every stage answers, then serves the model
through the usual chat, completion and streaming surfaces. Pictures, audio,
tool grammars and speculative decoding are not available on a pipeline; a
request that needs them is refused.

When a machine fails or stops answering, the request in flight fails with an
error naming that stage and the cause. The next request reconnects to the same
machines. The model is never served from a different set of machines or from
the first machine alone.

`tenzro_layerPipelineStatus` (operator only; `tenzro node layer-pipeline-status`,
MCP `layer_pipeline_status`, SDK `layerPipelineStatus` / `layer_pipeline_status`)
reports this machine's DID, role, stage, block range, the digest of the plan all
machines agreed on, its state and the last error.
