# Run OpenShell agents on Tenzro

[OpenShell](https://github.com/NVIDIA/OpenShell) runs an agent in a sandbox
behind a gateway: the gateway creates the sandbox, a supervisor outside the
sandbox enforces its policy, and every outbound request passes through the
supervisor's network proxy. The Tenzro extensions for OpenShell
(`crates/tenzro-openshell`) plug into those extension points so that an agent in
a sandbox acts under Terms its controller approved with a passkey, calls models
through Tenzro, pays outside services, and leaves a signed record of every
action that anyone can check without trusting the gateway.

This page covers setup, how a sandbox policy maps to Terms, payments,
attestation, and how to verify a session. The SDK helpers named here exist in
the TypeScript (`tenzro-sdk`), Python (`tenzro.agents.openshell`) and Rust
(`tenzro_sdk::openshell`) SDKs under the same names in each language's style.

## What runs where

| Piece | Runs in | Does |
| --- | --- | --- |
| Credential driver | the gateway | resolves the sandbox's `tenzro` provider credential to the delegated agent; the agent's access tokens stay with its serving nodes, never in the sandbox |
| Gateway interceptor | the gateway | refuses to create or update a sandbox whose policy has no `tenzro` middleware that fails closed, and checks the agent's Terms are live |
| Supervisor middleware | the supervisor, outside the sandbox | checks each request against the Terms it reads from Tenzro, records it as a signed agent audit entry, and settles inference charges and payments |
| Inference provider (`providers/tenzro.yaml`) | the gateway's provider profiles | routes the sandbox's model calls to Tenzro serving nodes |
| Attestation | the serving node's host | the node's hardware identity (TPM or Secure Enclave) certifies the session keys that sign the records |
| Payments | the supervisor middleware | pays x402, MPP and AP2 services the agent calls, inside its Terms |

Nothing in the sandbox holds a key. The supervisor's session key and the
agent's signing keys live in the TPM or Secure Enclave of the machines that
hold them; the controller's approval is a passkey assertion.

## Setup

These are the steps the live end-to-end test
(`crates/tenzro-openshell/tests/openshell_e2e.rs`) runs against a Tenzro node,
with OpenShell 0.1.5 (`openshell` and `openshell-gateway`, the release
`crates/tenzro-openshell` pins).

1. Admit the serving node. On the machine that runs the node and the
   extensions, register its machine identity once; the registration records
   its TPM attestation, which admits that TPM under the machine's one identity,
   so the session keys it certifies for the agents it serves are accepted:

   ```shell
   tenzro validator register-machine --key-namespace <node hardware_key_namespace> --rpc <node rpc url>
   ```

   The TPM's endorsement certificate has to chain to a manufacturer root the
   network recognizes (`[economy] tpm_endorsement_roots_pem` in its genesis).

2. Delegate the agent. Its controller (the root) bonds it and approves its
   Terms, served by that node. A machine root does it with its own hardware
   keys:

   ```shell
   tenzro agent delegation create-as-machine --terms terms.json --key-namespace <root namespace> \
     --bond 1000000000000000000 --rpc <node rpc url>
   ```

   ```json
   {
     "agent_name": "my-agent",
     "delegation_scope": {
       "allowed_operations": ["sandbox", "sandbox.policy", "fetch", "inference", "pay"],
       "max_transaction_value": "500",
       "max_daily_spend": "100000",
       "allowed_payment_protocols": ["x402"],
       "allowed_models": ["tenzro/e2e"]
     },
     "capabilities": [],
     "min_distinct_operators": 1,
     "expires_at_ms": 1798000000000
   }
   ```

   It prints the agent's DID (`identity.did`) and its controller's
   (`identity.controller_did`). A controller with a passkey builds the same
   Terms from the sandbox policy and a grant with `mintOpenShellCredential`
   (next section) and approves them with the passkey.

3. Run the extensions on the serving node's host, in one process built on
   `tenzro-openshell`, reading delegations from the node
   (`NodeDelegations::new(<node rpc url>)`):

   - the credential driver on a Unix socket (mode 0600) that only the
     `openshell-gateway` binary, as the same user, may call;
   - the gateway interceptor on a Unix socket, for calls that carry the
     gateway's extension JWT and come from that binary;
   - the supervisor middleware over TLS under its own CA
     (`openshell-gateway generate-certs --output-dir ext-pki`), for calls that
     carry a gateway or supervisor extension JWT. The process installs the
     rustls provider first (`rustls::crypto::aws_lc_rs::default_provider().install_default()`).

   Every decision is signed by a session key the host's TPM identity certified
   and appended to the record directory (`RecordLog::with_export_dir`).

4. Configure the gateway with the extensions and start it:

   ```toml
   [openshell]
   version = 2

   [openshell.gateway]
   guest_tls_ca = "pki/ca.crt"
   credential_drivers = ["tenzro"]

   [openshell.gateway.gateway_jwt]
   signing_key_path = "jwt/signing.pem"
   public_key_path = "jwt/public.pem"
   kid_path = "jwt/kid"
   gateway_id = "my-gateway"

   [openshell.gateway.mtls_auth]
   enabled = true

   [[openshell.gateway.interceptors]]
   name = "tenzro"
   grpc_endpoint = "unix:///run/tenzro/tenzro-interceptor.sock"
   audience = "urn:tenzro:openshell:interceptor"
   failure_policy = "fail_closed"
   timeout = "2s"

   [[openshell.supervisor.middleware]]
   name = "tenzro"
   grpc_endpoint = "https://127.0.0.1:<middleware port>"
   tls_ca_cert_path = "ext-pki/ca.crt"
   audience = "urn:openshell:extension:middleware:tenzro"
   max_payload_bytes = 262144
   timeout = "5s"

   [openshell.credential_drivers.tenzro]
   transport = "uds"
   socket_path = "/run/tenzro/tenzro-credentials.sock"
   ```

   ```shell
   openshell-gateway --config gateway.toml --compute-driver docker \
     --tls-cert pki/server/tls.crt --tls-key pki/server/tls.key --tls-client-ca pki/ca.crt
   ```

   The gateway refuses to start when it cannot reach the extensions.

5. Import the Tenzro inference provider profile (copy
   `crates/tenzro-openshell/providers/tenzro.yaml` and set `binaries` and the
   endpoint for your image), then create the provider with the agent's DID as
   its one credential:

   ```shell
   openshell profile import --file tenzro.yaml
   openshell provider create --name tenzro --type tenzro --credential TENZRO_AGENT_TOKEN=<agent did>
   ```

   A provider holding anything but an agent's DID is refused. The credential
   driver mints a short-lived token from the DID on every resolve; neither the
   DID nor the token reaches the sandbox's environment.

6. Create the sandbox for the agent:

   ```shell
   openshell sandbox create --provider tenzro --annotation tenzro.agent=<agent did> \
     --policy policy.yaml --no-auto-providers -- <agent command>
   ```

   The interceptor refuses a sandbox that names no agent, an agent another
   account delegated, or a policy without the `tenzro` middleware, and
   annotates the sandbox with the host's TPM binding (`tenzro.host`).

7. Verify the session from the record directory (see "Verify a session").

## From policy to Terms

Terms stay on Tenzro. The sandbox policy only routes the sandbox's traffic
through the Tenzro extensions, with a network middleware whose `middleware` is
`tenzro` and which carries no config; the extensions read the agent's Terms
from Tenzro on every decision and refuse when the node cannot be read.

```yaml
version: 1
network_policies:
  data:
    name: data
    endpoints:
      - { host: data.example.com, port: 443 }
network_middlewares:
  tenzro:
    middleware: tenzro
    endpoints:
      include: ["data.example.com"]
```

`endpoints.include` names the hosts whose requests pass through the
middleware; the live test routes the paid service and the inference endpoint
this way.

What the agent may do is the grant the controller approves:

```ts
const grant = {
  models: ["qwen3-0.6b"],
  tools: true,
  max_transaction_value: "1000000",
  max_daily_spend: "5000000",
  chains: ["tenzro", "eip155:8453"],
  payments: {
    protocols: ["x402"],
    payees: ["0xabcdef0123456789abcdef0123456789abcdef01"],
    services: ["data.example.com"],
  },
  expires_in_secs: 3600,
};
```

`openShellTerms(policy, grant, options)` checks the grant against the policy
and returns the Terms the controller approves:

| Grant | Terms |
| --- | --- |
| every sandbox | the `sandbox` and `fetch` operations |
| `policy_changes: true` | the `sandbox.policy` operation |
| `tools: true` | the `tool` operation |
| `models` | `allowed_models`; adds the `inference` operation |
| `payments.protocols` | `allowed_payment_protocols`; adds the `pay` operation |
| `payments.payees` | `allowed_counterparties` (lower case) |
| `payments.any_payee: true` | `allowed_counterparties: []`, any payee |
| `max_transaction_value`, `max_daily_spend` | the same limits, wei, canonical decimals |
| `chains` | `allowed_chains`; `[tenzro]` when omitted |
| `expires_in_secs` | `expires_at_ms` from now |

In Terms an empty list allows anything, so the check refuses a grant or policy
that would leave one open by accident:

- no `tenzro` middleware, the middleware named twice, a `config` on it, or
  `on_error` other than `fail_closed`;
- a model given as a wildcard;
- a payment protocol other than `x402`, `mpp` or `ap2`;
- payment protocols with no payees, unless `any_payee: true` says so;
- a payee that is not a 20-byte hex address;
- payment services with no payment protocol, or a service that is not an
  endpoint of `network_policies`;
- a missing or non-canonical limit, or a per-payment limit above the daily one;
- no positive `expires_in_secs`.

The two layers stay separate. OpenShell's network policy decides which hosts
the sandbox may reach at all; the Terms decide what the agent may pay, to whom,
and how much. A payment needs both. The shared vectors in
`sdk/fixtures/openshell/policy_terms.json` state every mapping and every
refusal; each SDK is tested against them.

## Payments

Inference goes through the `tenzro` provider: the supervisor middleware checks
the model against `allowed_models` and the charge against the limits, and the
call is settled on Tenzro. Its audit entry is a `model_call` that names the
settlement of its charge, and the response carries that signed entry in the
`x-tenzro-receipt` header.

When the agent calls an outside service that answers with an x402, MPP or AP2
payment request, the middleware checks the rail, the payee and the amount
against the Terms and pays from the agent's wallet. Each attempt is a `spend`
entry whose action is `<rail> <url>`: allowed with the transaction it
produced, or refused with the reason (for example `max_transaction_value`).

`openShellPayments(session)` lists both kinds from a verified session, in
order: `{ seq, at_ms, rail, target, outcome, linked_tx }`, with `rail`
`inference` for model charges. A refused payment has `linked_tx: null`. To read
the settled payment itself, look `linked_tx` up with the settlement client.

## Attestation

Every record is signed by a session key that the serving node's hardware
identity (its TPM or Secure Enclave key, and its ML-DSA-65 key when it has
one) certified for a bounded time. The signature carries that certificate, so
a verifier needs only the hardware identity's public key, never a key a record
names for itself. Once hybrid records are in force on the chain, a record must
be signed by a hybrid (Ed25519 with ML-DSA-65) session key. The agent audit
commit the node writes once per epoch carries an attestation over the epoch
root (`AgentClient.verifyAuditAttestation`).

## Verify a session

The extensions append every entry, as it is signed, to `<session id hex>.jsonl`
in their record directory (one signed entry per line), and write
`identity.json` there: the hardware identity the session keys sign for
(`p256`, and `pq` when it holds an ML-DSA-65 key) and `hybrid_records_from_ms`.
Nothing in that directory is secret.

```ts
import { parseOpenShellEntries, verifyOpenShellSession, openShellPayments, openShellSessionId } from "tenzro-sdk";

const entries = parseOpenShellEntries(jsonl);
const session = await verifyOpenShellSession(entries, {
  identity: { p256: id.p256, pq: id.pq },                 // from identity.json
  hybridRecordsFromMs: id.hybrid_records_from_ms,
  sessionId: await openShellSessionId("my-gateway", "my-sandbox"),
});
console.log(session.count, session.root);
console.log(openShellPayments(session));
```

`verifyOpenShellSession` needs nothing but the entries and the hardware
identity. It checks that:

- every entry is signed by a session key the identity certified, within the
  certificate's validity, and by a hybrid session key once hybrid records are
  in force;
- entries are numbered from 0 with no gap, all of one session and one agent;
- each entry names the leaf hash of the one before it, so none can be dropped,
  reordered or replaced.

It names the first fault it finds and otherwise returns the entries and the
session's MMR root. `verifyOpenShellReceipt` checks the signed entry a model
call returns in `x-tenzro-receipt` the same way, as one entry of the agent's
session.

The session id is SHA-256 of `tenzro/openshell/session/v1`, a zero byte, the
gateway name, a zero byte and the session's name: the sandbox, or the agent's
DID for its model calls. Entries are the signed agent audit entries of
`tenzro-types::agent_audit`, `{"body": <hex of the entry JSON>, "signature":
<hex of the session signature JSON>}`; the signature is the
`tenzro-crypto::session` session signature, which carries the session key's
certificate by the hardware identity. `sdk/fixtures/openshell/vectors.json` holds
sessions the extensions' record log signed and the tamperings every SDK must
refuse; `crates/tenzro-openshell/tests/sdk_vectors.rs` wrote it once and checks
it with the extensions' own verifier.

To check a session against the chain as well, take an audit proof for any of
its entries from the serving node and pass it to `AgentClient.verifyAuditEntry`:
it walks the entry to its session root, the session root to the epoch root,
and compares that with the root committed on chain.

## Revoke an agent

Revoke the agent with its controller's passkey (`revokeIdentity` in the SDKs).
A machine root revokes itself with `tenzro identity revoke <root did> --approval <approval.json>`
(the approval is its signature over `tenzro agent delegation challenge ... revoke`), and with it
every agent it delegated.
Once the revocation is in a block, every node revokes the agent's tokens; the
credential driver can no longer resolve the sandbox's credential, and the next
action the agent tries is refused and recorded as such (`grant_use`, refused,
`agent revoked`). The session's records up to and including that refusal still
verify.
