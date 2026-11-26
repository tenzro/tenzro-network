# Run manifest

A harness run (`@tenzrolabs/harness`) ends with a run manifest: what the run
consumed, what useful output it produced, what it claims about that output and
which paid interactions it rests on. The manifest has a digest that anyone can
recompute from the manifest alone, and the operator anchors that digest on the
Tenzro Ledger. This document specifies the manifest, its digest and its
anchor, so that a verifier can be written without reading any implementation.
`docs/standards/vectors/run-manifest.json` holds test vectors: manifests with
their digest, and manifests a verifier must refuse with the reason.

## The manifest

A JSON object with these members. Text is UTF-8: a string whose JSON escapes
leave a lone surrogate (`"\ud800"`) is not text and is refused. A digest is 64
lower-case hex characters and never all zeros.

| Member | Type | Meaning |
|---|---|---|
| `run_id` | text, non-empty | The run's name, chosen by the operator |
| `operator_did` | text, non-empty | The identity that ran it |
| `harness_module` | digest | Bundle digest of the harness module's `standard` registry entry |
| `started_at_ms` | integer, 0..=2^63 - 1 | When the run started, Unix milliseconds |
| `ended_at_ms` | integer, `started_at_ms`..=2^63 - 1 | When it ended |
| `inputs` | list of `{name, digest}` | What it consumed; names unique |
| `outputs` | non-empty list of `{name, digest, bytes}` | What it produced; names unique, `bytes` 0..=2^64 - 1 |
| `claims` | list of `{metric, value, unit}` | What it states about its output; `metric` non-empty, `value` a decimal number (`0`, `12`, `0.5`; no sign, exponent or leading zero), `unit` may be empty |
| `interactions` | list of digests | Interaction receipt digests (`interaction-receipt.md`) of what the run paid for |

A manifest with no output states no useful output and has no digest.

### Bounds

| Bound | Value |
|---|---|
| Manifest, as JSON text | 65,536 bytes |
| `inputs` | 64 entries |
| `outputs` | 64 entries |
| `claims` | 32 entries |
| `interactions` | 256 entries |
| Any text member | 256 bytes |

## The digest

SHA-256 over the preimage, written as 64 lower-case hex characters. The
preimage is the 22 bytes of the domain tag `tenzro/run-manifest/v1`, written
as they are with no length before them, followed by, in order:

1. `run_id`, `operator_did` and the 32 bytes of `harness_module`, each as a
   field;
2. `started_at_ms` and `ended_at_ms`, each as 8 bytes little-endian;
3. the number of inputs as 4 bytes little-endian, then per input its `name`
   and the 32 bytes of its `digest`, each as a field;
4. the number of outputs, then per output its `name` and digest as fields and
   `bytes` as 8 bytes little-endian;
5. the number of claims, then per claim `metric`, `value` and `unit` as
   fields;
6. the number of interactions, then each interaction digest's 32 bytes as a
   field.

A field is its length as 4 bytes little-endian followed by its bytes. Lists
keep the order they are written in.

An integer in JSON may exceed what a double holds exactly (`bytes` up to
2^64 - 1); a verifier reads integers exactly.

## Manifests that have no digest

A verifier refuses a manifest, and states why:

- `no_output`: `outputs` is empty;
- `too_large`: a bound above is passed;
- `malformed`: anything else above is broken: a member missing or of the
  wrong type, a string with a lone surrogate, a digest that is not lower-case
  hex or is all zeros, a name used twice in one list, an end before the
  start, a claim value that is not a decimal number.

## The anchor

The operator anchors the digest in the generic registry of consensus state
with a registry `put`:

- `id`: `<account hex>/runs`, the operator's account as 64 hex characters,
  an id the registry reserves to that account;
- `kind`: `run-manifest`;
- `anchor`: the manifest's digest;
- `data`: empty. The manifest stays with the operator, who hands it to
  whoever is to check the run.

Each run is a new version of the same entry. The registry keeps every version
(`tenzro_getRegistryEntry` with `version`), so the first put locks the
governed registry bond once and every later run anchors without another. A
manifest is anchored when some version of its operator's runs entry carries
its digest.

## Worked example

The first vector, "worked example", is a run with one input, one output of
4,096 bytes, one claim (`documents_summarised`, `1200`, `documents`) and one
paid interaction. Its digest is
`68a35668c992efaf6b533e29f7712e1af87ae95d9796ba82290c05d1eeeba965`.

## Verifiers

Three implementations written from this document check every vector:

- `scripts/standards/run_manifest_reference.py`, the Python reference the
  vectors are written by: `--check` recomputes every digest and refusal
  reason and fails on any difference (gate row 2f).

- `tools/receipt-verify`, a standalone Rust program with no Tenzro
  dependency: `tenzro-receipt-verify --run-manifest [--expect HEX] [FILE]`
  prints the digest, or the reason the manifest has none.
- The TypeScript SDK, which also builds the anchoring transaction:
  `runManifestDigest`, `runManifestPreimage` and `runManifestPutTx` in
  `@tenzro/inference`.
