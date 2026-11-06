# Agent trust

How a party that has never seen a Tenzro agent can decide whether to deal with it, and what record exists afterwards.

## Standing

The protocol keeps no reputation score. What it records about an agent or a provider is public state that any party can read and weigh for itself:

| Read | What it records |
|---|---|
| `tenzro_slaVerdict` | the availability verdict validators froze for a bonded subject in each closed hour |
| `tenzro_getRoleStakes` | the bond a role holder has at stake, and what has been slashed from it |
| `tenzro_getComputeBond` | a provider's compute bond, its status, and what remains after upheld inference faults slashed it |
| `tenzro_getAgentQuarantine`, revocations, audit commitments | the oversight record of each agent (see below) |

Inference routing ranks providers by their standing: 0 without a live serving bond (a model-provider role stake or an active compute bond), otherwise a governed bonded standing plus a governed availability standing scaled by the share of judged hours in the governed window (`routing.standing_*`, genesis 3000 + 7000 over 24 hours) in which the validators' verdicts found the provider available. An upheld inference fault lowers standing through the bond it slashes; a bond slashed to nothing leaves none. Every node computes the same standing from the same state. A call that names a model and no provider ranks the live announcements the same way: room to take another request first, then standing, then the price the signed card quotes for a 1000-in 1000-out reference call, then the latency the provider reports, then its announced load, with payee address and endpoint id as the last tie-break so the choice is deterministic.

Richer scoring (settled history, disputes, quarantines, weighting of faults) is an application concern. The harness ships a scorer built only on these public reads; any party can run its own.

## Signed agent requests

Every HTTP request an agent sends through its serving node carries an RFC 9421 HTTP Message Signature, so a server that is not on Tenzro can tell which agent is calling, who stands behind it and under which mandate, per request.

The node signs with the agent's key on that machine: a P-256 key held in the machine's TPM, which the agent's controller approved, by passkey, in the agent's on-chain terms (`serving_nodes[].dpop_public_key`). The key never leaves the TPM and no software copy exists. A machine that serves the agent but cannot sign refuses the request rather than send it unsigned.

| Header | Content |
|---|---|
| `Tenzro-Agent` | the agent's DID |
| `Tenzro-Mandate` | the approval digest of the terms the agent acts under, hex |
| `Content-Digest` | `sha-256=:<base64>:` of the body (RFC 9530), when there is one |
| `Signature-Input` | `tenzro=("@method" "@authority" "@path" ["@query"] "tenzro-agent" "tenzro-mandate" ["content-digest"]);created=..;expires=..;nonce="..";keyid="<jkt>";alg="ecdsa-p256-sha256";tag="tenzro-agent"` |
| `Signature` | `tenzro=:<base64 r‖s>:` |

`keyid` is the RFC 7638 thumbprint of the key. A signature is valid for at most 300 seconds.

To verify a request:

1. Read `keyid` and `Tenzro-Agent` (`agentKeyOf` in the TypeScript SDK, `agent_key_of` in `tenzro_payments::rfc9421::agent`).
2. Resolve them with `tenzro_resolveAgentKey { agent_did, keyid }` (`AgentClient.resolveAgentKey`). The answer comes from chain state: the key, the machine holding it with its TPM certification, the agent's root identity, the approval digest and version of the terms in force, their expiry, and whether the agent is revoked or quarantined.
3. Check the request against the resolution (`verifyAgentRequest` in TypeScript, `verify_agent_request` in Rust). It refuses a request whose covered components or body changed, a signature outside its validity, a key that is not the agent's, a revoked or quarantined agent, expired terms, and a mandate other than the terms in force.

Replay protection beyond the signature's lifetime is the verifier's: remember each `nonce` until its `expires`.

## Epoch commitments

The agent's runtime appends each signed entry to its session's log (an MMR)
and reports the session's latest line, its MMR root over its entry count, to
its serving node with `tenzro_recordAgentAuditSession { session_id, mmr_root,
count }` (operator only; `AgentClient.recordAgentAuditSession` in TypeScript,
`record_agent_audit_session` in Rust, MCP `record_agent_audit_session`, CLI
`tenzro agent rpc record-audit-session`). A session's log only grows: a line
covering fewer entries than one already reported, or another root over as
many, is refused. Once an epoch ends the node commits that epoch's lines on
its own schedule, in one `AgentAuditCommit` from its own account: the root over
the lines ordered by session id, the session count, and its TPM quote over
`(epoch, root)` where it has a TPM. It retries each poll until the commitment
is on chain, within the `AGENT_AUDIT_COMMIT_WINDOW` epochs consensus accepts.
`tenzro_getAgentAuditCommit { committer, epoch }` reads it back.

## Audit retention

Audit entries are recorded and kept by whoever runs the agent, outside the node; the node keeps the roots committed on chain. `storage.audit_retention_seconds` is the governed retention a recorder keeps entries for: its floor and genesis value are 183 days. See [NETWORK.md](NETWORK.md#audit-retention).

## Evidence pack

`tenzro_exportEvidencePack { agent_did }` or `{ root_did }` (one agent, or a root identity and the agents it names in `agents`) returns one JSON document. The caller passes the audit entry proofs (`audit`, at most 2,000) and session receipts (`receipts`) its recorder holds; the node checks each entry against the root committed on chain and refuses one that does not reach it. `tenzro agent audit evidence export --agent <did> --audit entries.json --out pack.json` writes it. On a private node only the root identity may export.

| Section | Content |
|---|---|
| `checkpoint` | a proof from genesis that the checkpoint committing `state_root` at `state_height` is certified |
| `audit` | the agent's audit entries, each with its proof to the epoch root its recorder committed |
| `commitments` | those on-chain commitments, each with a state proof under `state_root` |
| `oversight` | the quarantine or revocation record of each agent, with state proofs, and the grant-use and approval entries of the audit log |
| `mandate` | the terms each agent acts under (scope, limits, serving nodes, the controller's approval digest), with state proofs |
| `receipts` | the signed closing receipts of the sessions covered |
| `models` | the models the agents called, with the file hashes the catalog pins for each |
| `jurisdiction` | the country and blocs the exporting node declares |
| `manifest` | per section, the SHA-256 of its JSON and the control references below |

`tenzro agent audit evidence verify --file pack.json --chain-id <id> --genesis-hash <hex> --genesis-committee-root <hex>` checks the pack offline with nothing but the chain's genesis anchor: the checkpoint certificate chain from the genesis committee, that the checkpoint commits the pack's state root, every chain record's state proof, every audit entry's path to the root committed on chain, and the manifest digests.

### Control references

| Reference | Requirement | Sections |
|---|---|---|
| `eu-ai-act:12(1)` | Art. 12(1): automatic recording of events over the system's lifetime | `audit`, `commitments` |
| `eu-ai-act:12(2)` | Art. 12(2): logs that identify risk situations, support post-market monitoring and monitor operation | `audit`, `receipts`, `models` |
| `eu-ai-act:14(3)` | Art. 14(3): oversight measures built in or identified before deployment | `mandate` |
| `eu-ai-act:14(4)(d)` | Art. 14(4)(d): the ability to decide not to use, disregard, override or reverse the output | `oversight` |
| `eu-ai-act:14(4)(e)` | Art. 14(4)(e): the ability to intervene or interrupt through a stop procedure | `oversight` |
| `iso-42001:A.6.2.6` | AI system operation and monitoring | `oversight` |
| `iso-42001:A.6.2.7` | AI system technical documentation | `models` |
| `iso-42001:A.6.2.8` | AI system recording of event logs | `audit`, `commitments`, `receipts` |
| `iso-42001:A.9.2` | Processes for responsible use of AI systems | `oversight` |
| `iso-42001:A.9.4` | Intended use of the AI system | `mandate`, `jurisdiction` |
| `iso-42001:A.10.3` | Suppliers | `models` |

Art. 19 and Art. 26(6) require providers and deployers to keep these logs for at least six months; the audit retention floor is the period a recorder keeps them.

The same pack answers a payment dispute: it shows the agent's identity and root, the mandate it acted under, each action it took with the supervisor's decision, and the controller's oversight, all checkable by the merchant without trusting the node that produced it.

## Tool-call records

Every tool call an agent makes through a node's `/mcp`, `/mcp/compact` or A2A endpoint with a valid access token leaves one entry in the agent's audit log, recorded and signed by that node. The entry is an ordinary audit entry (`kind: tool_call`, the tool as `action`, the SHA-256 of the arguments as `detail`) with a `call` object:

| Field | Content |
|---|---|
| `node` | the machine DID of the serving node, whose registered hardware identity certified the signing key |
| `surface` | `mcp`, `mcp_compact` or `a2a` |
| `principal` | for a delegated agent: the human (passkey) or machine DID at its root, the root kind, the Terms version and the digest of the approval those Terms carry |
| `result` | the SHA-256 of the result returned, success or error; absent when the call was refused before it ran |
| `approval` | the approval reference the caller presented, in the MCP request's `_meta` or an A2A data part under `tenzro/approval`, exactly as presented |

The entry's `outcome` is `allowed`, or `refused` with the reason the node gave (the agent's Terms, its pinned tools, the access policy). The arguments and results are never stored, only their digests.

The node signs each entry with its record signer: a session key its hardware identity certified, hybrid Ed25519 / ML-DSA-65 once governance puts hybrid records in force. The entries of one agent form a session per node process, chained by hash, and the node's epoch commitment fixes each session's root on chain. Entries are written to `audit/tool-calls/` in the data directory before the response is returned. `tenzro_getToolCallRecords { agent_did }` returns them; `tenzro_exportEvidencePack` with `tool_calls: true` adds this node's committed entries to the pack, with the registration of every node that signed one (a `node_identity` record in `mandate`).

A node that cannot sign records (no hardware identity) refuses every tool call by an authenticated agent before it runs, with JSON-RPC error `-32041` naming the reason; it never serves one unrecorded. A call whose record cannot be written is answered with the same error instead of its result. `tenzro_getToolCallRecords` reports `recording: false` and the count of calls refused. Calls without a valid access token are not attributed to anyone and are not recorded. On `/mcp` both a DPoP-bound access token and the server's OAuth bearer token name the caller.

Cost per call, measured on the record path (signature, append to disk, tree update; 512-byte arguments; unoptimised test build on an ARM build host): about 0.26 ms and 2.9 KB stored per call with an Ed25519 session key, about 5.7 ms and 40 KB with a hybrid one, most of it the ML-DSA-65 signature and the session certificate each entry carries. `the_cost_of_a_record_is_measured` in `tool_call_record` prints both.

What a tool-call record proves, once the pack verifies:

- the named node, holding the hardware identity registered for its DID, stated at the time given that this agent called this tool with arguments and a result of these digests, and that it allowed or refused the call for the reason given;
- the entry is in the session the node committed on chain for that epoch, in order, with nothing removed between it and the entries around it.

What it does not prove:

- what the arguments or the result were: only someone holding them can show they match the digests;
- that the node recorded every call: a node that serves a call without recording it is not caught by its own records, only by the agent or a counterparty holding a response the log does not contain;
- that a presented approval reference was valid or that anyone reviewed the call;
- anything about calls served by nodes the pack does not cover.

## EU AI Act profile

`tenzro agent audit evidence profile --file pack.json --out profile.json` maps a pack to the record-keeping and human oversight provisions of Regulation (EU) 2024/1689. Each clause names the pack items it rests on, what they establish and what they do not:

| Clause | Measure | Pack items |
|---|---|---|
| `eu-ai-act:12(1)` | recording | every audit entry and the commitments they reach |
| `eu-ai-act:12(2)` | monitoring | refused calls and violations, payments, token issuer actions, session receipts, models called |
| `eu-ai-act:14(3)` | mandate | the Terms records, serving node identities and the approvals the Terms carry |
| `eu-ai-act:14(4)(d)` | approval | approval and grant entries, actions held for approval, calls with a presented approval |
| `eu-ai-act:14(4)(d)` | revocation | revocation records, or a proven absence of any |
| `eu-ai-act:14(4)(e)` | halt | quarantines in force or proven absent, and governance decisions touching the subject |

`tenzro agent audit evidence verify --file pack.json --profile profile.json --chain-id <id> --genesis-hash <hex> --genesis-committee-root <hex>` is the check an auditor runs, with nothing but the chain's genesis anchor: everything the pack check covers, every node-signed tool-call entry against the key its node registered on chain (proven under the same certified state root), and the profile rebuilt from the pack, so a profile that claims anything the pack does not hold is refused. The operator that produced the pack is not trusted for any of it.

A profile lists evidence. It is not a legal assessment: it does not decide whether a system is high-risk, whether its logging or oversight is adequate for its use, or whether its provider or deployer complies with the Regulation.
