# References

Tenzro Network is an original, compositional implementation. It builds on open
standards, published research, and open-source software. This file records the
prior art the protocol composes, so the lineage of each design is legible.

The presence of a reference here means the corresponding public work informed a
design decision. It does not imply any code was copied; components that ship code
are credited in [NOTICE](NOTICE) under their own licenses.

## Consensus

- HotStuff / HotStuff-2 — pipelined BFT consensus with linear communication.
- Block-STM — optimistic parallel transaction execution with MVCC and
  deterministic re-execution.
- Reputation-weighted proposer election.

## Cryptography and proofs

- Plonky3 — STARK proving over small fields (KoalaBear), with Poseidon2 hashing
  and FRI commitments.
- FROST — flexible round-optimized threshold Schnorr/Ed25519 signatures.
- DKLS23 — threshold ECDSA.
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) — post-quantum
  key encapsulation and signatures.
- RFC 9381 — ECVRF (Edwards25519, SHA-512, TAI).
- RFC 9180 — HPKE, used for sealed-shard key wrapping.

## Distributed training

- Data-parallel low-communication training with periodic outer synchronization
  (DiLoCo-family methods), and the open reference implementations thereof.
- Gradient quantization and sparsification for communication-efficient outer
  synchronization.
- TOPLOC-class activation commitments for verifiable inference and training.
- Byzantine-robust aggregation (trimmed mean, coordinate-wise median, Krum).
- Witness-committee coordination with idempotent on-chain finalization and
  no-endorsement certificates, as used by production decentralized-training
  protocols.

## Payments and identity

- W3C Decentralized Identifiers (DID) and Verifiable Credentials.
- ERC-8004 — trustless agent registries.
- ERC-4337 / ERC-7579 — account abstraction and modular smart-account validators.
- EIP-7702 — set-code authorizations.
- EIP-1559 — fee market.
- ERC-7683 — cross-chain intents.
- Permit2 — signature-based token transfers.
- x402 and the Machine Payments Protocol (MPP) — HTTP 402 payment flows.
- x402-rs — reference pattern for the self-hosted EIP-3009 / Permit2 facilitator.
- EIP-3009 — `transferWithAuthorization` meta-transactions (gasless USDC transfers).
- AP2 — agent payment mandates.

## Transport and data availability

- iroh / iroh-blobs — QUIC-native content-addressed transfer, BLAKE3-verified.
- Erasure-coded data availability.
- Pkarr — DNS-over-DHT discovery.

## Trusted execution

- Intel TDX, AMD SEV-SNP, AWS Nitro, and NVIDIA GPU confidential computing
  attestation formats and certificate chains.
