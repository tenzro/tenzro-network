# tenzro-secure-enclave

Apple Secure Enclave as a **machine-identity** root — the SEP counterpart to
TPM 2.0.

Tenzro keeps three concerns separate, and this crate is only the second:

| Concern | Root |
|---|---|
| **Human** identity | passkeys |
| **Machine** identity | TPM 2.0, or the Secure Enclave on Apple hardware |
| **Network** security | TEE attestation (`tenzro-tee`) |

A TEE, a TPM and the Secure Enclave are not the same thing. A TEE attests that a
*workload* runs unmodified; a TPM and the SEP attest that a *machine* holds a key
nobody can copy.

**Permissionless on Apple hardware:** no Developer Program membership, no
provisioning profile, no entitlements.

⚠ The SEP has **no PCRs and issues no quote**. `MachineRootKind::can_quote()`
returns `false` for it, and that distinction must be recorded rather than
inferred — an enclave-rooted node is not TPM-attested.
