# tenzro-keygen

A Tenzro node's Ed25519, ML-DSA-65 and X25519 keys, derived on
demand from the machine's TPM or Secure Enclave through
`tenzro_device_key::DerivationRoot`.

None of these key types can be held by the hardware, so none of them is
generated, stored or sealed. `NodeKeys::open` returns a handle holding only the
derivation root; each signature derives its key, uses it once and wipes it.
The same machine always derives the same keys, so the public halves
(`NodeKeys::validator_pubkeys`, rendered for genesis by
`ValidatorPubkeys::to_genesis_toml`) are stable.

- `NodeKeys::ed25519_signer` and `NodeKeys::hybrid_signer` implement
  `tenzro_crypto`'s `Signer` and `HybridSigner`.
- `NodeKeys::model_recipient` and `NodeKeys::machine_sealing` return the
  node's hybrid X25519 + ML-KEM-768 recipient (`DerivedHybridRecipient`, which
  implements `tenzro_crypto::hybrid_seal::HybridRecipient`); the private halves
  are derived on demand from hardware and never held.

A machine without a TPM or Secure Enclave has no local keys and `open` refuses. Such a machine can keep its node keys in another machine's TPM through the node's key holder (`tenzro-node tpm key-holder`, see `docs/NODE.md`), which this crate does not reach.

It is its own crate so the CLI can reach the keys without depending on
`tenzro-node`.
