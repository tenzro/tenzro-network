# TEE-Attested Clock

Long-running multi-party workflows on Tenzro need timestamps that no
single participant can lie about. Wall-clock `now()` is fine when every
replica trusts every other replica — but for institutional workflows
(DvP settlement deadlines, L/C presentation windows, parametric-
insurance trigger evaluation, margin-call grace periods, AP2 mandate
expiry) Tenzro carries a hardware-attested timestamp envelope.

## When to use

- **Workflow step deadlines** — `step_deadline_ms` carried as
  `AttestedTimestamp`.
- **AP2 mandate expiry** — cart mandate `valid_until` attested.
- **Parametric-insurance trigger windows** — the trigger evaluation
  fixes the wall-time the parametric condition was observed.
- **Margin-call grace periods** — the issued-at timestamp on a margin
  call is the authoritative clock; the borrower cannot dispute the
  grace deadline.
- **DvP settlement windows** — T+0 / T+1 enforcement.

## When NOT to use

- In-memory ephemeral state (use `SystemTime::now()`).
- Pure consensus path — block timestamps are already attested by the
  block's quorum certificate; no separate enclave attestation needed.

## Wire shape

The envelope carries:

- `wall_ms` — Unix epoch milliseconds from the enclave's trusted-platform
  timer
- `monotonic_ns` — enclave-local monotonic counter; MUST increase
  strictly between two timestamps from the same enclave — detects
  clock-rollback attacks regardless of any claimed `wall_ms` drift
- `nonce` — caller-supplied 32-byte nonce binding the timestamp to a
  specific workflow event (prevents replay across unrelated events)
- `tee_vendor` — `intel-tdx` / `amd-sev-snp` / `aws-nitro` /
  `nvidia-gpu` / `intel-tiber`
- `enclave_id_hex` — 32-byte firmware-measurement digest; relying
  parties whitelist a set of acceptable enclave ids at enrolment
- `attestation_hash` — SHA-256 of the full vendor-specific attestation
  envelope; lets relying parties cache previously-verified envelopes
- `signature` — signature over the canonical preimage by the enclave's
  attested signing key

## Verification

Relying parties check three things:

1. **Drift tolerance** — `wall_ms` must fall within the configured
   skew window of the relying party's local clock (default 30s per
   Canton 3.5 timestamp-drift guidance).
2. **Monotonic counter** — `monotonic_ns` must strictly exceed the last
   accepted value from the same `enclave_id_hex`.
3. **Signature** — the canonical preimage hashes to a value the
   enclave's attested signing key verifies against.

## RPC surface

| Method | Description |
|---|---|
| `tenzro_attestedClockNow` | Return the current local wall-clock as an `AttestedTimestamp` envelope. When the node is running inside a TEE the timestamp carries vendor attestation; when running outside a TEE (e.g. local dev) the envelope is unsigned and `tee_vendor` is `null` — relying parties MUST reject unsigned envelopes for production use. |

## Status

Library types + drift / monotonic / vendor-tag validation + node-level
RPC live. Per-vendor live signing (Intel TDX `/dev/tdx-guest`, AMD SEV-
SNP `/dev/sev-guest`, AWS Nitro `/dev/nsm`, NVIDIA NRAS, Intel Tiber)
reuses the existing TEE attestation surface — no separate enclave
boot required.
