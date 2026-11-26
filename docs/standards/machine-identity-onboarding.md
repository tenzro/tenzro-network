# Machine identity onboarding

What a device must do to be admitted to Tenzro as an autonomous machine: a
machine that answers for itself, with no human or institution as its
controller. It is written for device makers. A maker checks a device with
`tenzro-node tpm check` before shipping it, and may state that a model
conforms with a registry `conformance` entry.

`docs/standards/vectors/machine-identity-onboarding.json` holds test
vectors for every derivation below. A test in `crates/tenzro-tee` runs them
against the code the network admits machines with.

## Why hardware

A machine with no controller has no party that answers for it, so an
attestable root in its hardware stands in that place. Admission rests on a
proof, not a claim: the machine shows that a key it uses lives in a hardware
root of trust, and that this root answered a challenge chosen by the
verifier. A chip vendor's certificate is not required, because a vendor root
in the admission rule would make vendors the gatekeepers of who may hold an
identity; it is recorded as reputation.

## The TPM 2.0 path

1. **Endorsement key.** The machine reads its endorsement key (EK) from the
   persistent handle provisioning keeps it at: `0x81010020` (ECC P-256),
   `0x81010016` (ECC P-384), `0x81010001` (RSA-2048) or `0x8101001C`
   (RSA-3072), the first one the TPM holds a manufacturer certificate for.
   It is never recreated.
2. **Attestation key.** A restricted ECC P-256 signing key (AK) is created
   in the same TPM. A restricted key signs only structures the TPM
   generates, so its quotes are statements by the TPM.
3. **Credential activation.** The verifier encrypts a fresh secret to the EK,
   bound to the AK's name (`TPM2_MakeCredential`). The TPM releases it
   (`TPM2_ActivateCredential`) only if an object with exactly that name is
   loaded beside the EK. Returning the secret proves the AK lives in the
   endorsed TPM.
4. **Quote.** The AK quotes the admission challenge as `extraData`:

   ```
   challenge = SHA-256( "tenzro/machine-admission/v1" || 0x00
                        || u32_be(len(did)) || did
                        || u32_be(len(wallet_key)) || wallet_key
                        || nonce )
   ```

   `did` is the machine's DID (step 5), `wallet_key` the public key its
   ledger account signs with (empty for the self-check), and `nonce` 32
   bytes chosen by the verifier, used once.
5. **DID.** The machine's DID is a function of the AK, so nobody can claim
   it without the key:

   ```
   did = "did:tenzro:machine:" || hex( SHA-256( "tenzro/machine-did/device-key"
                                                || u32_be(65) || ak_sec1 ) )
   ```

   `ak_sec1` is the AK's uncompressed SEC1 point (65 bytes, leading `0x04`).

A verifier that ran activation records it; a later relying party re-checks
the quote and the DID from the evidence the identity carries.

## Identifier sources

Besides its attestation, a machine reports the identifiers it can read, each
by a label and a grade. Only SHA-256 digests of values are carried, never
the values. Grades, strongest first:

| Grade | Meaning | Can anchor a machine nobody delegated |
|-------|---------|-----|
| `attestable` | A secret in hardware that can prove itself | Yes |
| `fused` | Per unit, but readable by software | No |
| `model` | Names a design, not a unit | No |

| Label | Grade |
|-------|-------|
| `tpm:ek` | attestable |
| `tcm:ek` | attestable |
| `amd:snp-chip-id` | attestable |
| `intel:ppid` | attestable |
| `apple:sep` | attestable |
| `qualcomm:qfprom` | attestable |
| `hisilicon:platform` | attestable |
| `hygon:psp` | attestable |
| `domestic:tpcm` | attestable |
| `rpi:dus` | attestable |
| `atecc:serial` | attestable |
| `se050:id` | attestable |
| `esp32:efuse` | attestable |
| `intel:ppin` | fused |
| `amd:ppin` | fused |
| `apple:ecid` | fused |
| `mediatek:efuse` | fused |
| `rockchip:otp` | fused |
| `allwinner:sid` | fused |
| `rpi:serial` | fused |
| `mcu:uid` | fused |
| `smbios:platform` | fused |
| `arm:midr` | model |

An accelerator's serial or UUID is not an identifier source: it is the part
most often swapped between machines.

## Requirements

| Id | Required | Met when |
|----|----------|----------|
| `credential-activation` | Yes | The AK's credential activation against the EK succeeded |
| `did-from-attestation-key` | Yes | The DID is the one the AK derives (step 5) |
| `attestable-identifier` | Yes | At least one identifier source of grade `attestable` |
| `manufacturer-endorsement` | No | The EK certificate carries the EK and chains to a manufacturer root; recorded as the identity's `tpm_endorsement` grade |

The quote over the admission challenge is verified as part of the
attestation; a machine whose quote does not verify produces no attestation.

## Checking a device

On the device, as a user that can open the TPM, after
`tenzro-node tpm provision`:

```
tenzro-node tpm check --roots <manufacturer-roots.pem> --out evidence.json
```

It runs the attestation above on the device itself, prints one line per
requirement, writes the evidence and the report to `evidence.json`, and exits
non-zero when a required requirement is not met. The roots are optional; without
them `manufacturer-endorsement` is not met, which does not block admission.

## Claiming conformance

The bundle digest of this standard (this document and its vector file) is
registered as a registry entry of kind `standard`. A maker states that a
device model passes it with an entry of kind `conformance` whose anchor is
the digest of the device's firmware or image and whose data lists the
standard's bundle digest. The chain checks the entry's form; whether the
statement is true is for relying parties to check against published
`evidence.json` files and their own runs.
