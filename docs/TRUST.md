# Trust: certifications, operator policies, the model catalog and model provenance

Tenzro is a network of independent operators serving AI models. This document describes how anyone can certify or rate a model or an
operator, how operators declare and are held to their own policies, how the
model catalog is published and chosen, and how every model's bytes are verified across independent origins.

The protocol privileges no issuer and keeps no allowlist. Nobody's private key reaches a node: every record is signed by its author on their
own TPM 2.0, Apple Secure Enclave or passkey, and every node re-verifies every record it receives. Records are held in the trust ledger
(`crates/tenzro-trust`) and propagate on the `tenzro/trust` gossip topic.

## Subjects

| subject | name |
|---|---|
| a model | `tenzro:model:<root>`, where `<root>` is the hex BLAKE3 Merkle root of the model's manifest (every file, every byte) |
| an operator | its DID, derived from its hardware key (`did:tenzro:machine:...`, or `did:tenzro:human:...` for a passkey) |

## Signed documents

Every trust document carries a W3C Data Integrity proof with cryptosuite `ecdsa-jcs-2019` over P-256:

- the document without `proof`, and the proof options, are each canonicalised (RFC 8785 JSON Canonicalization) and hashed with SHA-256;
  the signer signs `SHA-256(SHA-256(options) || SHA-256(document))`;
- the proof options carry the signer's public key as `publicKeyJwk`, and `verificationMethod` is `<signer DID>#hardware-key`; the signer
  DID must be the one that key derives, so no directory lookup is needed;
- a TPM or Secure Enclave signs that digest directly (`proofValue` = multibase base58btc raw `r||s`);
- a passkey signs a WebAuthn assertion whose challenge is that digest: the proof adds `authenticatorData`, `clientDataJSON` and `rpId`.
  User verification is required and synced (backup-eligible) passkeys are refused.

## Credentials

A credential is a VC 2.0 document (`type: ["VerifiableCredential", "TenzroTrustCredential"]`) with:

- `issuer`: any DID;
- `validFrom` and `validUntil`: both required, at most five years apart;
- `credentialSubject`: `{ "id": <subject>, "claim": { "kind", "scheme", "grade"?, "score"?, "scope"?, "evidence"? } }`, where `kind` is
  `certification`, `rating`, `evaluation`, `safety-scan` or `policy-conformance`, `scheme` names the standard, benchmark or programme,
  `score` is 0-10000, and `evidence` lists `{ uri, sha256 }` references to the report;
- `credentialStatus`: a `BitstringStatusListEntry` for revocation in the issuer's own list, `tenzro:status:<issuer DID>`.

A credential is valid when its proof verifies, it is inside its validity window, its status bit is not set, and its issuer has not revoked
its key (or had its identity revoked).

### Revocation

- `TenzroRevocation { issuer, statusListIndex: [...], revokedAt }`, signed by the issuer's key, sets bits in the issuer's list. Only the
  issuer can revoke its own credentials, and a set bit never clears.
- `TenzroIssuerRevocation { issuer, revokedAt, reason }`, signed by the issuer's key, invalidates everything that key ever signed.
- `tenzro_getStatusList(issuer)` returns the list as a `BitstringStatusListCredential` (`encodedList` = multibase base64url of the
  GZIP-compressed bitstring, at least 131,072 entries) together with the signed revocations it was computed from.

A network provider is linked to its operator DID by the operator's own policy (below), which lists the P-256 point of the provider machine's hardware identity key
(the key registered for the machine DID its announcements are signed as) as a
receipt key.

## Operator policies

An operator publishes what it serves and refuses, signed by its hardware key:

```json
{
  "type": ["TenzroOperatorPolicy"], "operator": "<DID>", "sequence": 1,
  "validFrom": "...", "validUntil": "...",
  "receiptKeys": [{ "algorithm": "p256", "publicKey": "<hex x || y>", "pqPublicKey": "<hex ML-DSA-65, when present>", "binding": "<hex composite signature>" }],
  "serves": { "models": ["model-id", "..."], "trust": { "issuers": [...], "require": [...] } },
  "jurisdictions": ["EU", "CH"],
  "refuses": { "categories": ["..."], "unsafeFormats": true },
  "data": { "retentionDays": 0, "trainsOnInputs": false },
  "proof": { "...": "..." }
}
```

- A receipt key is a serving node's hardware identity key (P-256, with its ML-DSA-65 leg when the hardware holds one). It signs the
  operator DID under the `tenzro/trust/receipt-key-binding` signature context (`binding`, both legs when it has two), so only the holder
  of a key can bind it to an operator.
- A policy takes effect no earlier than it was signed, and a node accepts a newly submitted policy only when its signature is fresh (within
  15 minutes of the node's clock). A policy is in force from its `validFrom` until the next sequence's `validFrom`, and never after its
  `validUntil`.
- The operator's node refuses, on its own serving path, a model its policy in force does not serve, and a model lacking the credentials the
  policy promises.
- `serves.models` and `jurisdictions` are checkable from a signed inference receipt alone. `refuses.categories` and `data` are declarations
  relying parties can filter on; they are never slashed automatically.

### Violations and slashing

`TenzroPolicyViolation { policy, receipt: { kind: "jurisdiction", body }, clause }` is verified by anyone the same way: the policy verifies
and was published; the receipt is signed by a session key that a hardware identity key the policy binds certified (a composite signature under the
`tenzro/session/certificate` context) for a period covering the receipt; it was signed while that policy was in force (a later policy does not
excuse it); and it contradicts the clause (`serves.models`: a model the policy does not list; `jurisdictions`: served outside the declared
ones). A proven violation is recorded once and fails the operator in every trust verdict that reads it. The same receipt proves one
violation, however the evidence is packaged. Bonds are slashed only by consensus transactions; a node never slashes on its own reading of
a trust record.

## Model provenance

- `TenzroModelManifest { name, files: [{ path, size, sha256, blake3 }] }` lists every file of a model. The root is a BLAKE3 Merkle tree:
  leaf `BLAKE3(0x00 || len(path) || path || size || sha256 || blake3)`, node `BLAKE3(0x01 || left || right)`, an odd node promoted. The
  root is always recomputed, never trusted. Each file's BLAKE3 is its blob address `tenzro://blob/<blake3>`, so peers and storage providers
  serve it with chunk-by-chunk verification.
- `TenzroOriginAttestation { observer, origin: { kind, locator }, name, files, observedAt }`, signed by the observer, states what one origin
  serves: `creator` (the creator's own DID), `huggingface` (`hf:<owner>/<repo>@<40-hex commit>`, with the LFS SHA-256 per file), `mirror`
  (`https://...`) or `storage` (`tenzro:<DID>`). `tenzro trust observe-hub` drafts one from a saved Hub revision listing.
- A manifest is corroborated file by file. Verified (the network default) means every file is confirmed by at least two distinct observers
  across at least two distinct origins, and no signed observation contradicts any file. A contradicting observation is kept as a signed,
  attributable conflict.
- A manifest named after a Hub repository in the node's catalog must agree with the SHA-256 and size the catalog entry gives every file it
  lists; one that contradicts it is refused, whether it arrives over RPC or gossip.

### Holding and loading models

Every model a node downloads or serves is hashed into a manifest and recorded in its ledger. A catalogued model is named by its Hub
repository and its files by their paths there, so the manifest meets the Hub's own origin attestations; any other model is named by its
id. A node with a hardware key also signs a `storage` origin attestation for the files it holds; a node without one records the manifest
and signs nothing.

Before weights load (served GGUF models and the ONNX forecast, text-embedding and segmentation bundles), each file is hashed once and
checked against the hash in the model's catalog entry, when it lists the file, and against the model's verified manifest, when one lists the
file. A file that
differs from either refuses the load with error `-32006` naming the file. A load whose files all match a verified manifest reports
`provenance: { status: "verified", manifests: [...] }`, and on hardware with a TEE the attestation it produces commits to those manifest
roots; any other load reports `provenance: { status: "unverified" }`. Downloads take peer hints (BLAKE3 blob address plus SHA-256) for every
file a verified manifest lists, except the files of a gated model (below).

## Model catalog

The model catalog is data. Each model is a `TenzroCatalogEntry` a publisher signs:

```
{ type: ["TenzroCatalogEntry"], publisher: <DID>, model: <id>, sequence: <n>, entry: { ... } | null, proof: { ... } }
```

The `entry` names the engine family and that engine's description of the model (`model: { engine, spec }`, with `engine` one of `gguf`,
`onnx-vision`, `onnx-forecast`, `onnx-text-embedding`, `onnx-segmentation`, `onnx-text-segmentation`, `onnx-detection`, `onnx-audio`, `tts`,
`onnx-video`, `media-gen`), the licence (`licence: { name, id, tier }`, tier `permissive`, `attribution`, `commercial_custom` or
`non_commercial`), whether the weights are `gated` at their origin, every file the model downloads (`components: [{ repo, path, revision,
size, sha256 }]`, each fixed to a 40-hex commit), capability tags, published-benchmark priors (basis points) and, for a Mixture-of-Experts
model, the checkpoint its experts are extracted from. Unlike other trust documents an entry may carry fractional numbers (sampler
settings); they are canonicalised like every other value.

- Only a higher `sequence` from the same publisher replaces its entry for a model; `entry: null` withdraws the model.
- The ledger checks the signature and the envelope and keeps the entry; the node interprets the body. An entry for an engine or
  architecture the running build does not know is kept and reported as not understood, and is served once the operator runs a build that
  knows it, without being published again.
- An entry is refused when it is malformed, when a file it downloads has no hash, when a custom-licence tier has no licence id, or when
  another served entry hashes one of its files differently.

A node serves the catalog entries whose signing key's ledger account holds a catalog publisher bond (the `catalog` role stake): anyone who
bonds may publish, with no list to be added to. A publisher may be an autonomous machine, whose DID is derived from a key its own TPM
holds and which no person controls; it signs its entries with that key on that machine (`tenzro trust whoami --key-label
tenzro/catalog/publisher` prints the DID), and the bond is a `Stake` transaction from that same key's account. An entry whose pinned SHA-256 or size does not match the bytes at
its source is a catalog fault: anyone files it (the `InferenceFault` transaction's `file_catalog` operation, carrying the signed entry
and the component), validators fetch the component and attest, and an upheld fault takes `catalog.fault_slash_bps` of the publisher's
`catalog` stake into the insurance pool, and the entry is never served again. An operator may narrow what its own node serves with `--catalog-publisher <did>` (config
`catalog_publishers`; repeat or comma-separate for several): the node keeps only those from among the bonded publishers, and naming one never adds a
publisher that holds no bond. With no bonded publisher the node serves no catalog
model, and `tenzro_listCatalog` says why. The catalog is re-assembled whenever a catalog entry or an issuer revocation arrives (and
every 30 seconds, so a publisher whose DID is revoked drops out), and installed in place: a newly published model is served without a
rebuild or a restart. A publisher whose key is revoked stops counting. Two trusted publishers that publish different entries for one model
are a conflict: neither is served until they agree or one withdraws.

The catalog drives every model path of the node: downloads fetch each file at its commit and refuse bytes that do not match its SHA-256
(from the Hugging Face Hub or from a peer), loads are checked against the same hashes, the licence decides which models the operator's
licence acceptance admits (`--accept-non-commercial`, `--accept-license <id>`) and whether a territorial grant applies, and capability tags
feed the router's tiering.

- **Gated weights are never redistributed.** A gated model needs the operator's own Hugging Face token; without one a download is refused
  before anything is fetched, with an error naming the terms page. Its files are not fetched from peers, not published to the node's blob
  store, not offered by `tenzro_hostModel`, and no `storage` attestation is signed for them.
- **A non-commercial model is never charged for.** A node may serve a `non_commercial` model (with `--accept-non-commercial`) but not sell
  it: its offer and announcement are priced at zero, a served call is metered at zero, and no payment is ever required for it.

The first published content of the catalog is the seed in `crates/tenzro-catalog/seed/`, one JSON array per engine family; a publisher
publishes it with `tenzro catalog publish crates/tenzro-catalog/seed --key-label tenzro/catalog/publisher` on the machine the genesis
names.

## Engine releases

A node build is published as a `TenzroEngineRelease` its publisher signs:

```
{ type: ["TenzroEngineRelease"], publisher: <DID>, version: "MAJOR.MINOR.PATCH",
  artifacts: [{ platform, size, sha256, blake3 }], proof: { ... } }
```

`platform` is `<arch>-<os>` as a node reports its own (for example `x86_64-linux`), optionally followed by an accelerator. A publisher
publishes a version once. Releases travel on `tenzro/trust` like every other record, so the network learns that a release exists; no node
installs one. A node reports the releases of the publishers its operator names (`--release-publisher <did>`, config
`release_publishers`), newest first, marking those newer than the build it runs (`tenzro_getEngineReleases`). The operator downloads a
binary from wherever it chooses, and `tenzro node upgrade apply` re-verifies the signed release, refuses a file whose size, SHA-256 or BLAKE3
differs from the release's artifact for the platform, and installs it atomically; the operator restarts the node when it chooses. An upgrade
changes the software a node runs, never the chain.

```
tenzro node upgrade publish --version 1.4.0 --artifact x86_64-linux=./tenzro-node --key-label publisher
tenzro node upgrade check
tenzro node upgrade apply --version 1.4.0 --file ./tenzro-node-1.4.0 --install-to /usr/local/bin/tenzro-node
```

### Ingest scanning

`tenzro_scanModelFiles` classifies each file by content: safetensors and GGUF headers are checked for internal consistency; pickle (including
PyTorch ZIP archives holding one and NumPy object arrays) is refused whatever the file is called; unknown binaries above 16 MiB are refused.
A GGUF file's embedded chat template is reported by its SHA-256. The result includes a `safety-scan` claim a scanning party can sign.

## RPC methods

| method | access | purpose |
|---|---|---|
| `tenzro_submitTrustRecord` | open | submit any signed record, a manifest, or violation evidence |
| `tenzro_verifyTrustCredential` | open | verify a credential now |
| `tenzro_getTrustCredentials` | open | credentials about a subject, with their state |
| `tenzro_getStatusList` | open | an issuer's status list |
| `tenzro_getOperatorPolicy` | open | policy in force, history, proven violations |
| `tenzro_getModelProvenance` | open | manifests, observations, verification status |
| `tenzro_listCatalog` | open | the catalog entries the node serves, its named publishers and publishers, and published models it left out with the reason |
| `tenzro_getEngineReleases` | open | releases from the operator's named release publishers, and which are newer than the running build |
| `tenzro_getCatalogEntry` | open | one model's entry, its publishers and whether a token is needed, or why it is not served |
| `tenzro_buildModelManifest` | admin | hash a local model directory into a manifest |
| `tenzro_verifyModelFiles` | admin | check local files against a manifest |
| `tenzro_scanModelFiles` | admin | ingest scan of local files |
| `tenzro_hostModel` | admin | publish verified local files to the node's blob store |

## CLI

```
tenzro trust whoami --key-label issuer                   # the DID your TPM or Secure Enclave key derives (created on first use)
tenzro trust draft-credential --issuer <did> --subject tenzro:model:<root> --kind certification --scheme iso-iec-42001 --index 1 --out c.json
tenzro trust sign --doc c.json --key-label issuer --out c.signed.json
tenzro trust submit --file c.signed.json
tenzro trust draft-revocation --issuer <did> --index 1 --out r.json
tenzro trust manifest --name org/model --path ./model --out m.json
tenzro trust observe-hub --repo org/model --listing listing.json --observer <did> --out o.json
tenzro trust provenance org/model
tenzro catalog publish ./entries --key-label publisher         # sign each entry with the publisher key and submit it
tenzro catalog withdraw <model id> --key-label publisher
tenzro catalog list [--engine gguf]
tenzro catalog show <model id>
```

An operator chooses its catalog publishers by starting the node with `--catalog-publisher <publisher did>`.
