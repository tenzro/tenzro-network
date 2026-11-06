# tenzro-catalog

Every model a node can serve: what it is, which engine runs it, where its
weights come from and the hash every file must have, what licence governs them,
what it costs to hold, and the recipe its publisher shipped it with.

## The catalog is data

Nothing is compiled in. A model is a `CatalogEntry`:

- `model`: the engine family (`gguf`, `rerank`, `decision`, `embed`, `onnx-vision`,
  `onnx-forecast`, `onnx-text-embedding`, `onnx-segmentation`, `onnx-text-segmentation`,
  `onnx-detection`, `onnx-audio`, `tts`, `onnx-video`, `media-gen`) and that
  engine's description of the model (`HfModelEntry`, `OnnxVisionEntry`, ...);
- `licence`: name, the id of a custom licence, and the `LicenseTier`;
- `gated`: the origin requires the operator's own account and token, and the
  weights are never redistributed between nodes;
- `components`: every file the model downloads, with its size and SHA-256,
  from one of two sources. A hub file names the commit it is read at
  (`revision`). A network file has no hub copy: it names its BLAKE3 content
  address (`blake3`), the checkpoint it is built from (`built_from`) and the
  in-tree script that rebuilds it byte for byte (`recipe`); storage providers
  hold it, a node fetches it by that address and keeps it only if it is the
  pinned size and SHA-256. A gated entry has no network files;
- `capabilities`, `capability_priors` (basis points) and, for a
  Mixture-of-Experts model, `moe_source`.

A publisher signs entries and publishes them as `TenzroCatalogEntry` trust
records (`tenzro-trust`). A node serves the entries of the publishers its
operator's catalog trust list recognises, builds them into a `Catalog`
(`Catalog::build` refuses malformed entries, a downloaded file without a hash,
and two entries that hash one file differently) and installs it in the
process-wide `store`. The accessors (`get_model_catalog`, `get_model_by_id`,
`get_vision_catalog`, ..., `entry`, `file`) read the installed catalog, so a
newly published model is served without a rebuild or a restart.

The first published content is `seed/`, one JSON array of entries per engine
family, read with `read_entries` and published with `tenzro catalog publish`.

## Why it is its own crate

Reading the catalog and running a model are different jobs. This crate has no
inference dependency, so anything that wants to name a model (the CLI, the
node's routing and admission, the SDKs' tooling) does not build llama.cpp to do
it.
