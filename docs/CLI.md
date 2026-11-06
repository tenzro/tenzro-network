# Tenzro CLI reference

Every command `tenzro` accepts, generated from the binary.

Generated from `tenzro 0.2.0` by `scripts/gen-cli-docs.sh`. Do not edit by
hand — `cargo test -p tenzro-cli` fails when this file and the binary
disagree, and a hand edit is how they start to.

For how to *use* the network rather than what each flag is called, start
with [GUIDE.md](GUIDE.md).

```
Tenzro Network CLI — AI-Native, Agentic, Tokenized Settlement Layer

Usage: tenzro [OPTIONS] <COMMAND>

Commands:
  join            Join the Tenzro Network (one-click participate)
  setup           Guided setup — join the network, provide, validate, or bootstrap a private network
  node            Node management commands
  wallet          Wallet management commands
  model           Model management commands
  stake           Staking commands
  governance      Governance commands
  tx              Transaction inspection
  funding         Network funding: grant and tranche requests, reward claims, vesting release
  sponsor         Sponsorship: check eligibility, prepare an application, see status
  provider        Provider management commands
  schedule        Provider schedule management
  inference       Inference commands
  identity        Identity management commands (TDIP)
  payment         Payment commands
  agent           AI agent management commands
  escrow          Escrow and payment channel commands
  duty            Network duties: work the chain pays the first prover for
  dev             Start a local single-validator chain for development, keys in this machine's hardware
  token           Token management commands (create, query, cross-VM transfers)
  contract        Contract deployment commands
  bridge          Cross-chain bridge commands (quote, execute, status, routes)
  relay           Relayer commands: deliver what other chains report to Tenzro
  events          Event streaming commands (subscribe, history, webhooks)
  crypto          Cryptographic operations (sign, verify, encrypt, decrypt, hash, keygen)
  tee             TEE operations (detect, attest, challenge, verify, providers)
  zk              Zero-knowledge proof operations (prove, verify, circuits, fraud proofs)
  vrf             VRF proof verification — RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  finality        Finality: verify the latest compact certificate from genesis as a light client
  passkey         Passkey-first wallet onboarding + custody (enrollment, recovery, session keys, hardware signers)
  machine-access  Owner-signed machine access for agents, tools and models (add, list, revoke)
  media-gen       Generative media: the media catalog and renders
  forecast        Timeseries forecasting (TimesFM 2.5, Chronos-2, TiRex-2, Toto 2.0)
  embed-text      Text embeddings (Qwen3-Embedding, EmbeddingGemma, BGE-M3)
  embed-image     Image embeddings (CLIP, SigLIP2, DINOv3)
  segment         Image segmentation (SAM 2, EdgeSAM, MobileSAM)
  text-segment    Open-vocabulary text-promptable segmentation (SAM 3, SAM 3.1)
  detect          Object detection (RF-DETR, D-FINE)
  decide          Decision models: answer typed questions about a text
  rerank          Rerankers: score documents against a query
  speech          Speech synthesis (text to speech)
  training        LoRA training on this node's CUDA device (operator only)
  transcribe      Audio transcription / ASR (Moonshine, Distil-Whisper, Parakeet, Canary)
  embed-video     Video embeddings (catalog scaffolding for V-JEPA / VideoMAE)
  auth            OAuth 2.1 + DPoP auth: refresh access tokens, link wallet for auth
  reserve         Proof-of-Reserve attestations for tokenized assets
  provenance      C2PA-style content provenance manifests (EU AI Act §50(2))
  trust           Certifications, operator policies and model provenance
  catalog         The model catalog: what a node serves, and publishing entries to it
  bond            AgentBond surety primitive: post, increase, withdraw, get, list
  insurance       The network insurance pool: claim, list, get, pool
  registry        The generic registry: list, get (read-only)
  validator       Validator set (Dynamic Validator Set): register, exit, update-metadata, get, list
  da              Committee data availability: challenge, challenges, availability, committee, blobs, object, retention
  beacon          The chain's randomness beacon
  fee-market      The base fee of every resource market: compute, state growth, bandwidth, proof
  iroh            Iroh content-addressed transport: info, endpoint-id, alpns, publish, fetch
  adaptive-burn   Adaptive-burn governance dial: config, metrics, recommendation, proposals
  settle          Settlement plans: legs on several networks, one Commit-or-Abort decision, the split fixed by the quote
  pq-hybrid       PQ-hybrid signing helper commands
  access          Node access: sign in for an access token; administer who may use a node
  permit2         Permit2 SignatureTransfer: domain-separator / digest / verify-and-consume / nonce-used
  urwa            ERC-7943 (uRWA) tokenized RWA compliance: kill-switch / freeze / forced-transfer
  bridge-fee      Bridge fee in TNZO: quote destination-native bridge fees in TNZO + list sponsorship pools
  moe             Decentralized Mixture-of-Experts serving
  discover        Discovery: node hardware profile
  cluster         Local-network cluster planning
  device          Devices bound to an identity, and machine ownership
  rails           Settlement rails and micropayment routing
  interaction     Interaction receipts: mirror a settlement to other chains
  status          Live resource and traffic status for this node
  rpc             Discover and call any JSON-RPC method this node serves
  visibility      Show or set this node's visibility (public, gated or private)
  chat            Interactive chat with AI models
  hardware        Show hardware profile
  info            Show network information
  version         Show version information
  help            Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
  -V, --version          Print version
```

## `tenzro access`

```
Node access: sign in for an access token; administer who may use a node

Usage: tenzro access [OPTIONS] <COMMAND>

Commands:
  sign-in       Sign in with this machine's hardware key and store the access token
  show          The access policy in force, as `access.toml`
  set           Replace the access policy with a TOML file
  preview       What the policy decides for a caller, without serving anything
  tokens        The live access tokens the node issued
  revoke        Withdraw one access token, or every live token of a DID
  audit         The node's administrative audit log: who called which administrative method, from where, with which credential, and what came of it
  audit-verify  Check the administrative audit log's chain and signed checkpoints
  help          Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro access audit`

```
The node's administrative audit log: who called which administrative method, from where, with which credential, and what came of it

Usage: tenzro access audit [OPTIONS]

Options:
      --method <METHOD>        Only calls to this method
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --principal <PRINCIPAL>  Only calls by this DID
      --since <SINCE>          Only records at or after this time (RFC 3339)
      --until <UNTIL>          Only records before this time (RFC 3339)
      --limit <LIMIT>          At most this many records, the most recent [default: 100]
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro access audit-verify`

```
Check the administrative audit log's chain and signed checkpoints

Usage: tenzro access audit-verify [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro access preview`

```
What the policy decides for a caller, without serving anything

Usage: tenzro access preview [OPTIONS] --surface <SURFACE>

Options:
      --surface <SURFACE>  rpc, mcp, a2a, openai, files, web or iroh
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --method <METHOD>    A JSON-RPC method name
      --class <CLASS>      A method class
      --did <DID>          The caller's DID; omit for an anonymous caller
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro access revoke`

```
Withdraw one access token, or every live token of a DID

Usage: tenzro access revoke [OPTIONS]

Options:
      --jti <JTI>        The token id
  -v, --verbose          Enable verbose logging
      --did <DID>        Withdraw every live token of this DID
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro access set`

```
Replace the access policy with a TOML file

Usage: tenzro access set [OPTIONS] <FILE>

Arguments:
  <FILE>  The new `access.toml`

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro access show`

```
The access policy in force, as `access.toml`

Usage: tenzro access show [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro access sign-in`

```
Sign in with this machine's hardware key and store the access token

Usage: tenzro access sign-in [OPTIONS]

Options:
      --key-label <KEY_LABEL>          Hardware key to sign in with, by label. The default is this machine's identity key, which signs in as its machine DID [default: tenzro/consensus/validator]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace the key lives under: a node's `hardware_key_namespace`, to sign in as that node's identity rather than the machine's default one. The DPoP key stays this client's own
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro access tokens`

```
The live access tokens the node issued

Usage: tenzro access tokens [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro adaptive-burn`

```
Adaptive-burn governance dial: config, metrics, recommendation, proposals

Usage: tenzro adaptive-burn [OPTIONS] <COMMAND>

Commands:
  config          Show the active BurnRateConfig (base and local fee burn bps)
  metrics         Show the latest SupplyMetricsSnapshot (circulating supply, burns, supply added: always 0, TNZO supply is fixed)
  recommendation  Compute the recommended BurnRateRecommendation from current metrics
  proposals       List burn-dial governance proposals, newest first
  fee-rate        Show the TNZO/USD rate fees are priced at, its mode, and the base fee
  economy         Show an epoch's settled value, payers, seed vs organic volume, burn vs rewards released from the pool and holder concentration
  help            Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro adaptive-burn config`

```
Show the active BurnRateConfig (base and local fee burn bps)

Usage: tenzro adaptive-burn config [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro adaptive-burn economy`

```
Show an epoch's settled value, payers, seed vs organic volume, burn vs rewards released from the pool and holder concentration

Usage: tenzro adaptive-burn economy [OPTIONS]

Options:
      --epoch <EPOCH>    Reward epoch; the current one when omitted
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro adaptive-burn fee-rate`

```
Show the TNZO/USD rate fees are priced at, its mode, and the base fee

Usage: tenzro adaptive-burn fee-rate [OPTIONS]

Options:
      --symbol <SYMBOL>  Another asset's committed USD rate instead (`ETH`, `SOL`, ...)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro adaptive-burn metrics`

```
Show the latest SupplyMetricsSnapshot (circulating supply, burns, supply added: always 0, TNZO supply is fixed)

Usage: tenzro adaptive-burn metrics [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro adaptive-burn proposals`

```
List burn-dial governance proposals, newest first

Usage: tenzro adaptive-burn proposals [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro adaptive-burn recommendation`

```
Compute the recommended BurnRateRecommendation from current metrics

Usage: tenzro adaptive-burn recommendation [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro agent`

```
AI agent management commands

Usage: tenzro agent [OPTIONS] <COMMAND>

Commands:
  terms                      Call tenzro_getAgentTerms: the agent's full consensus Terms, root kind, status and spend so far
  flag-audit                 Call tenzro_flagAgentAudit (flag agent audit) and print the node's answer
  record-audit-session       Call tenzro_recordAgentAuditSession: report an audit session's latest line for this node to commit
  bridge-circuit             Call tenzro_getBridgeCircuit (get bridge circuit) and print the node's answer
  resolve-key                Call tenzro_resolveAgentKey (resolve agent key) and print the node's answer
  kill-switch-receipt        Call tenzro_getKillSwitchReceipt (get kill switch receipt) and print the node's answer
  kill-switch-by-agent       Call tenzro_listKillSwitchByAgent (list kill switch by agent) and print the node's answer
  kill-switch-by-controller  Call tenzro_listKillSwitchByController (list kill switch by controller) and print the node's answer
  tool-call-records          Call tenzro_getToolCallRecords (the tool-call records this node signed for an agent (`agent_did`, `limit`), and whether it records) and print the node's answer
  node-pq-key                Call tenzro_agentNodePqKey (this node's ML-DSA-65 key for an agent (`agent_did`) and its proof of possession) and print the node's answer
  fund                       Fund an agent's wallet
  pause                      Pause an agent via kill-switch (reversible). Freezes payments, allows reward distribution + stake withdrawals
  quarantine                 Quarantine an agent via kill-switch (reversible). Freezes payments, reward distribution, and stake withdrawals; stake remains intact
  lift-quarantine            Lift an agent's quarantine. Only the owner or controller the quarantine names may, signing with the wallet its identity is registered with
  terminate                  Terminate an agent via kill-switch (irreversible). Slashes stake by `slash_bps`, optionally cascades to descendants
  audit                      The audit trail a node keeps of an agent's actions: fetch an entry and check it against the root committed on chain
  delegation                 Agents a human delegates with their passkey: approve terms, change them, revoke
  accounts                   The agent's account on every other chain the network configures
  grant                      Issue a grant on another chain, as the agent
  grant-proof                The agent's grant on a chain and its state proof
  act                        The serving node's signature over an action on another chain
  sync                       What a relayer installs with the account's sync on its chain
  wallet-consent             The consent that makes the agent's EVM account its ERC-8004 agentWallet
  help                       Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro agent accounts`

```
The agent's account on every other chain the network configures

Usage: tenzro agent accounts [OPTIONS] <DID>

Arguments:
  <DID>  The agent

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro agent act`

```
The serving node's signature over an action on another chain

Usage: tenzro agent act [OPTIONS] --chain <CHAIN> --nonce <NONCE> --action <ACTION>

Options:
      --chain <CHAIN>    The chain, CAIP-2
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --nonce <NONCE>    The account's next action nonce, read from that chain
      --action <ACTION>  A JSON file with the action: target, selector, amount, relay_refund, data (hex and decimal strings)
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro agent audit`

```
The audit trail a node keeps of an agent's actions: fetch an entry and check it against the root committed on chain

Usage: tenzro agent audit [OPTIONS] <COMMAND>

Commands:
  verify       Verify one entry's proof from the agent's recorder: the recorder's signature, the path to the session root and the epoch root, and that root against the one recorded on chain
  attestation  Check the hardware attestation a committer recorded with its audit root: the TPM quote binding the root to its measured boot state and machine identity
  quarantine   Whether an agent is quarantined, as chain state records it
  evidence     Compliance and dispute evidence packs
  help         Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro agent audit attestation`

```
Check the hardware attestation a committer recorded with its audit root: the TPM quote binding the root to its measured boot state and machine identity

Usage: tenzro agent audit attestation [OPTIONS] --committer <COMMITTER> --epoch <EPOCH>

Options:
      --committer <COMMITTER>  Ledger account that committed (0x hex)
  -v, --verbose                Enable verbose logging
      --epoch <EPOCH>          Epoch of the commitment
      --format <FORMAT>        Output format (text, json) [default: text]
      --rpc <RPC>              RPC endpoint to read chain state from [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

#### `tenzro agent audit evidence`

```
Compliance and dispute evidence packs

Usage: tenzro agent audit evidence [OPTIONS] <COMMAND>

Commands:
  export   Export the pack for one agent, or for every agent of a root identity
  verify   Verify a pack offline against the chain's genesis anchor
  profile  Write the EU AI Act profile of a pack: which records support Art. 12 and Art. 14, what each proves and what it does not
  check    Check evidence items against chain state (`tenzro_verifyEvidence`)
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

##### `tenzro agent audit evidence check`

```
Check evidence items against chain state (`tenzro_verifyEvidence`)

Usage: tenzro agent audit evidence check [OPTIONS] --items <ITEMS>

Options:
      --items <ITEMS>    A JSON file holding the list of evidence items
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint of a node that follows the chain [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

##### `tenzro agent audit evidence export`

```
Export the pack for one agent, or for every agent of a root identity

Usage: tenzro agent audit evidence export [OPTIONS] --out <OUT>

Options:
      --agent <AGENT>         The agent
  -v, --verbose               Enable verbose logging
      --format <FORMAT>       Output format (text, json) [default: text]
      --root <ROOT>           A root identity: its agents named with --covers or in the audit file
      --covers <AGENTS>       An agent of --root to cover; repeat for each
      --audit <AUDIT>         File holding the audit entry proofs from the agents' recorder (JSON array)
      --receipts <RECEIPTS>   File holding the agents' signed session receipts (JSON array)
      --payment <PAYMENTS>    A payment the covered agents made (pay_ref hex), proven into the pack's commerce section; repeat for each
      --proposal <PROPOSALS>  A governance proposal touching the subject (64 hex), proven into the governance section with its decision; repeat for each
      --token <TOKENS>        A token the covered agents held (64 hex): its issuer actions are proven into the token_actions section; repeat for each
      --out <OUT>             Where to write the pack
      --rpc <RPC>             RPC endpoint of a node that follows the chain [default: http://127.0.0.1:8545]
  -h, --help                  Print help
```

##### `tenzro agent audit evidence profile`

```
Write the EU AI Act profile of a pack: which records support Art. 12 and Art. 14, what each proves and what it does not

Usage: tenzro agent audit evidence profile [OPTIONS] --file <FILE>

Options:
      --file <FILE>      The pack
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --out <OUT>        Where to write the profile; printed when absent
  -h, --help             Print help
```

##### `tenzro agent audit evidence verify`

```
Verify a pack offline against the chain's genesis anchor

Usage: tenzro agent audit evidence verify [OPTIONS] --file <FILE> --chain-id <CHAIN_ID> --genesis-hash <GENESIS_HASH> --genesis-committee-root <GENESIS_COMMITTEE_ROOT>

Options:
      --file <FILE>
          The pack
  -v, --verbose
          Enable verbose logging
      --chain-id <CHAIN_ID>
          Chain id, from the genesis file
      --format <FORMAT>
          Output format (text, json) [default: text]
      --genesis-hash <GENESIS_HASH>
          Genesis block hash, hex
      --genesis-committee-root <GENESIS_COMMITTEE_ROOT>
          Root of the genesis committee, hex
      --handover-program <HANDOVER_PROGRAM>
          Image id of the handover program, hex, from the chain's governance: needed when the pack's checkpoint is certified from a handover chain proof
      --profile <PROFILE>
          An EU AI Act profile of the pack (`evidence profile`) to check too: every node-signed tool-call record against its node's registered identity, and the profile against the pack it names
  -h, --help
          Print help
```

#### `tenzro agent audit quarantine`

```
Whether an agent is quarantined, as chain state records it

Usage: tenzro agent audit quarantine [OPTIONS] --agent-did <AGENT_DID>

Options:
      --agent-did <AGENT_DID>  Agent DID
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

#### `tenzro agent audit verify`

```
Verify one entry's proof from the agent's recorder: the recorder's signature, the path to the session root and the epoch root, and that root against the one recorded on chain

Usage: tenzro agent audit verify [OPTIONS] --proof <PROOF> --signer <SIGNER>

Options:
      --proof <PROOF>          File holding the entry's proof (JSON), as the recorder exported it
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --signer <SIGNER>        The recorder's hardware identity key: its P-256 point (hex, x || y)
      --signer-pq <SIGNER_PQ>  The recorder's ML-DSA-65 identity key (hex), when its identity has one
      --rpc <RPC>              RPC endpoint to read chain state from. Any node answers it, so pass one you trust [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro agent bridge-circuit`

```
Call tenzro_getBridgeCircuit (get bridge circuit) and print the node's answer

Usage: tenzro agent bridge-circuit [OPTIONS] --source-chain <SOURCE_CHAIN> --adapter <ADAPTER>

Options:
      --source-chain <SOURCE_CHAIN>  source chain
  -v, --verbose                      Enable verbose logging
      --adapter <ADAPTER>            adapter
      --format <FORMAT>              Output format (text, json) [default: text]
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro agent delegation`

```
Agents a human delegates with their passkey: approve terms, change them, revoke

Usage: tenzro agent delegation [OPTIONS] <COMMAND>

Commands:
  challenge          Ask the node for the challenge the controller's passkey signs
  onboard            Create the agent from the completed terms and the signed approval
  update             Replace the agent's terms with newly approved ones
  revoke             Revoke the agent; every node refuses it from then on
  sign               Sign a challenge (custody or step-up) as a machine root, with this machine's hardware key
  create-as-machine  Create an agent rooted in this machine's hardware key: register the machine's identity on chain if it is not yet, then challenge, sign and onboard in one go
  act                Take one action as the agent, with its access token; the serving node refuses anything outside the terms
  help               Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro agent delegation act`

```
Take one action as the agent, with its access token; the serving node refuses anything outside the terms

Usage: tenzro agent delegation act [OPTIONS] --operation <OPERATION>

Options:
      --operation <OPERATION>
          The operation, as the agent's terms name it
  -v, --verbose
          Enable verbose logging
      --counterparty <COUNTERPARTY>
          Recipient address, hex, when the action moves value
      --format <FORMAT>
          Output format (text, json) [default: text]
      --amount <AMOUNT>
          Value moved, wei
      --chain <CHAIN>
          Chain [default: tenzro]
      --payment-protocol <PAYMENT_PROTOCOL>
          Payment protocol
      --model <MODEL>
          Model
      --asset <ASSET>
          Asset moved other than TNZO: a token id (0x hex)
      --usd-e6 <USD_E6>
          USD price of the value moved, micro-units (required with --asset) [default: 0]
      --payment-id <PAYMENT_ID>
          For `pay`: the payment id the record is keyed by
      --request <REQUEST>
          For `pay`: the resource paid for
      --quote-digest <QUOTE_DIGEST>
          For `pay`: the payee's quote digest (hex)
      --step-up <STEP_UP>
          The controller's step-up of this action, JSON: `account`, `nonce` and `root_public_key` (hex, from the refused attempt's `step_up` data and the root's P-256 key `x || y`) and `signature`, the root's composite signature (a passkey's WebAuthn assertion, or a machine root's TPM or Secure Enclave signature) over that data's challenge. Sent with the same action, unchanged, when its terms hold it
      --rpc <RPC>
          RPC endpoint of one of the agent's serving nodes [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

#### `tenzro agent delegation challenge`

```
Ask the node for the challenge the controller's passkey signs

Usage: tenzro agent delegation challenge [OPTIONS] --account <ACCOUNT> <OP>

Arguments:
  <OP>
          The change to authorize

          Possible values:
          - delegate: Create an agent
          - update:   Replace an agent's terms
          - revoke:   Revoke an agent

Options:
      --account <ACCOUNT>
          The account the root approves from, hex: a human's smart account, or the account a machine root's hardware key names

  -v, --verbose
          Enable verbose logging

      --format <FORMAT>
          Output format (text, json)
          
          [default: text]

      --terms <TERMS>
          JSON file with the agent's terms (delegate, update)

      --agent-did <AGENT_DID>
          The agent (update, revoke)

      --rotate-tokens
          Also withdraw the agent's live access tokens (update)

      --reason <REASON>
          Reason the revocation records (revoke); the approval covers it, so pass the same reason to `revoke`

      --rpc <RPC>
          RPC endpoint
          
          [default: http://127.0.0.1:8545]

  -h, --help
          Print help (see a summary with '-h')
```

#### `tenzro agent delegation create-as-machine`

```
Create an agent rooted in this machine's hardware key: register the machine's identity on chain if it is not yet, then challenge, sign and onboard in one go

Usage: tenzro agent delegation create-as-machine [OPTIONS] --terms <TERMS>

Options:
      --terms <TERMS>                  JSON file with the agent's terms; `controller_did` is set to this machine's DID, and absent `serving_nodes` become the node at `--rpc`
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The hardware key namespace of the machine root's account [default: client]
      --bond <BOND>                    Post this bond (wei) against the agent from the machine root's account before its terms, which need a bond sized by their spend ceiling (`tenzro bond get` shows an existing one)
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

#### `tenzro agent delegation onboard`

```
Create the agent from the completed terms and the signed approval

Usage: tenzro agent delegation onboard [OPTIONS] --terms <TERMS> --authorization <AUTHORIZATION>

Options:
      --terms <TERMS>                  JSON file with the completed terms the challenge returned, unchanged
  -v, --verbose                        Enable verbose logging
      --authorization <AUTHORIZATION>  JSON file with the controller's signed authorization
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

#### `tenzro agent delegation revoke`

```
Revoke the agent; every node refuses it from then on

Usage: tenzro agent delegation revoke [OPTIONS] --agent-did <AGENT_DID> --controller-did <CONTROLLER_DID> --approval <APPROVAL>

Options:
      --agent-did <AGENT_DID>
          The agent
  -v, --verbose
          Enable verbose logging
      --controller-did <CONTROLLER_DID>
          The controller that approves, as the agent's terms name it
      --format <FORMAT>
          Output format (text, json) [default: text]
      --approval <APPROVAL>
          JSON file with the controller's approval of the revoke_identity challenge: {account, nonce, root_public_key, signature}
      --reason <REASON>
          Reason the challenge was issued for
      --key-namespace <KEY_NAMESPACE>
          Hardware key namespace of the account that sends the transaction [default: client]
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

#### `tenzro agent delegation sign`

```
Sign a challenge (custody or step-up) as a machine root, with this machine's hardware key

Usage: tenzro agent delegation sign [OPTIONS] --challenge <CHALLENGE>

Options:
      --challenge <CHALLENGE>          JSON file with the challenge: a `challenge` result, or the `step_up` error data `act` returned for a held action
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The hardware key namespace of the machine root's account [default: client]
  -h, --help                           Print help
```

#### `tenzro agent delegation update`

```
Replace the agent's terms with newly approved ones

Usage: tenzro agent delegation update [OPTIONS] --agent-did <AGENT_DID> --terms <TERMS> --authorization <AUTHORIZATION>

Options:
      --agent-did <AGENT_DID>          The agent
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --terms <TERMS>                  JSON file with the completed terms the challenge returned, unchanged
      --authorization <AUTHORIZATION>  JSON file with the controller's signed authorization
      --rotate-tokens                  Also withdraw the agent's live access tokens; must match the challenge
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro agent flag-audit`

```
Call tenzro_flagAgentAudit (flag agent audit) and print the node's answer

Usage: tenzro agent flag-audit [OPTIONS] --agent-did <AGENT_DID> --epoch <EPOCH> --findings <FINDINGS>

Options:
      --agent-did <AGENT_DID>  agent did
  -v, --verbose                Enable verbose logging
      --epoch <EPOCH>          epoch
      --format <FORMAT>        Output format (text, json) [default: text]
      --findings <FINDINGS>    findings (JSON)
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro agent fund`

```
Fund an agent's wallet

Usage: tenzro agent fund [OPTIONS] --agent-did <AGENT_DID> --amount-wei <AMOUNT_WEI>

Options:
      --agent-did <AGENT_DID>          The agent's DID; its wallet is the one its consensus Terms name
  -v, --verbose                        Enable verbose logging
      --amount-wei <AMOUNT_WEI>        Amount to fund, in wei (1 TNZO = 10^18 wei)
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The paying client identity's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro agent grant`

```
Issue a grant on another chain, as the agent

Usage: tenzro agent grant [OPTIONS] --chain <CHAIN> --asset <ASSET> --budget <BUDGET>

Options:
      --chain <CHAIN>                  The chain, CAIP-2
  -v, --verbose                        Enable verbose logging
      --asset <ASSET>                  The asset, CAIP-19
      --format <FORMAT>                Output format (text, json) [default: text]
      --budget <BUDGET>                Most the account may move under the grant, in the asset's smallest unit
      --per-action <PER_ACTION>        Most one action may move; defaults to the budget
      --ttl-ms <TTL_MS>                How long the grant lives, ms [default: 600000]
      --target <TARGETS>               An allowed target, `target_hex:selector_hex` (repeatable)
      --exact <EXACT>                  A JSON file with the one action an exact grant allows (target, selector, amount, relay_refund, data)
      --relay-fee-max <RELAY_FEE_MAX>  Most a relayer may be refunded per action [default: 0]
      --step-up <STEP_UP>              The controller's step-up approval, JSON (`account`, `nonce`, `root_public_key` hex, and the composite `signature` over the challenge a refused attempt returns), when the terms require it
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro agent grant-proof`

```
The agent's grant on a chain and its state proof

Usage: tenzro agent grant-proof [OPTIONS] --chain <CHAIN> <DID>

Arguments:
  <DID>  The agent

Options:
      --chain <CHAIN>            The chain, CAIP-2
  -v, --verbose                  Enable verbose logging
      --checkpoint <CHECKPOINT>  The checkpoint; defaults to the latest certified one
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro agent kill-switch-by-agent`

```
Call tenzro_listKillSwitchByAgent (list kill switch by agent) and print the node's answer

Usage: tenzro agent kill-switch-by-agent [OPTIONS] --agent-did <AGENT_DID>

Options:
      --agent-did <AGENT_DID>  agent did
  -v, --verbose                Enable verbose logging
      --cursor <CURSOR>        cursor
      --format <FORMAT>        Output format (text, json) [default: text]
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro agent kill-switch-by-controller`

```
Call tenzro_listKillSwitchByController (list kill switch by controller) and print the node's answer

Usage: tenzro agent kill-switch-by-controller [OPTIONS] --controller-did <CONTROLLER_DID>

Options:
      --controller-did <CONTROLLER_DID>  controller did
  -v, --verbose                          Enable verbose logging
      --cursor <CURSOR>                  cursor
      --format <FORMAT>                  Output format (text, json) [default: text]
      --rpc <RPC>                        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                             Print help
```

### `tenzro agent kill-switch-receipt`

```
Call tenzro_getKillSwitchReceipt (get kill switch receipt) and print the node's answer

Usage: tenzro agent kill-switch-receipt [OPTIONS] --receipt-id <RECEIPT_ID>

Options:
      --receipt-id <RECEIPT_ID>  receipt id
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro agent lift-quarantine`

```
Lift an agent's quarantine. Only the owner or controller the quarantine names may, signing with the wallet its identity is registered with

Usage: tenzro agent lift-quarantine [OPTIONS] --controller <CONTROLLER> --agent-did <AGENT_DID>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --controller <CONTROLLER>        Controller address (hex, must match the signing key)
      --format <FORMAT>                Output format (text, json) [default: text]
      --agent-did <AGENT_DID>          Agent DID whose quarantine to lift
      --reason-text <REASON_TEXT>      Optional human reason text
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro agent node-pq-key`

```
Call tenzro_agentNodePqKey (this node's ML-DSA-65 key for an agent (`agent_did`) and its proof of possession) and print the node's answer

Usage: tenzro agent node-pq-key [OPTIONS]

Options:
      --params <PARAMS>  Parameters as a JSON object [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro agent pause`

```
Pause an agent via kill-switch (reversible). Freezes payments, allows reward distribution + stake withdrawals

Usage: tenzro agent pause [OPTIONS] --controller <CONTROLLER> --controller-did <CONTROLLER_DID> --agent-did <AGENT_DID>

Options:
      --key-namespace <KEY_NAMESPACE>
          Hardware key namespace of the signing account [default: client]
  -v, --verbose
          Enable verbose logging
      --controller <CONTROLLER>
          Controller address (hex, must match the signing key)
      --format <FORMAT>
          Output format (text, json) [default: text]
      --controller-did <CONTROLLER_DID>
          Controller DID (e.g. `did:tenzro:human:...`)
      --agent-did <AGENT_DID>
          Agent DID to pause (`did:tenzro:machine:...`)
      --reason-code <REASON_CODE>
          Reason code (canonical kill-switch spec §"Reason codes") [default: 0]
      --reason-text <REASON_TEXT>
          Optional human reason text (capped at 256 bytes)
      --until <UNTIL>
          Optional pause expiry as Unix timestamp in milliseconds
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro agent quarantine`

```
Quarantine an agent via kill-switch (reversible). Freezes payments, reward distribution, and stake withdrawals; stake remains intact

Usage: tenzro agent quarantine [OPTIONS] --controller <CONTROLLER> --controller-did <CONTROLLER_DID> --agent-did <AGENT_DID>

Options:
      --key-namespace <KEY_NAMESPACE>
          Hardware key namespace of the signing account [default: client]
  -v, --verbose
          Enable verbose logging
      --controller <CONTROLLER>
          Controller address (hex, must match the signing key)
      --format <FORMAT>
          Output format (text, json) [default: text]
      --controller-did <CONTROLLER_DID>
          Controller DID
      --agent-did <AGENT_DID>
          Agent DID to quarantine
      --reason-code <REASON_CODE>
          Reason code [default: 0]
      --reason-text <REASON_TEXT>
          Optional human reason text
      --evidence-hash <EVIDENCE_HASH>
          Optional 32-byte SHA-256 evidence hash (hex)
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro agent record-audit-session`

```
Call tenzro_recordAgentAuditSession: report an audit session's latest line for this node to commit

Usage: tenzro agent record-audit-session [OPTIONS] --session-id <SESSION_ID> --mmr-root <MMR_ROOT> --count <COUNT>

Options:
      --session-id <SESSION_ID>  The session id (32-byte hex)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --mmr-root <MMR_ROOT>      The session's MMR root (32-byte hex)
      --count <COUNT>            Entries the root covers
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro agent resolve-key`

```
Call tenzro_resolveAgentKey (resolve agent key) and print the node's answer

Usage: tenzro agent resolve-key [OPTIONS] --agent-did <AGENT_DID> --keyid <KEYID>

Options:
      --agent-did <AGENT_DID>  agent did
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --keyid <KEYID>          keyid
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro agent sync`

```
What a relayer installs with the account's sync on its chain

Usage: tenzro agent sync [OPTIONS] --chain <CHAIN> <DID>

Arguments:
  <DID>  The agent

Options:
      --chain <CHAIN>            The chain, CAIP-2
  -v, --verbose                  Enable verbose logging
      --checkpoint <CHECKPOINT>  The checkpoint; defaults to the latest certified one
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro agent terminate`

```
Terminate an agent via kill-switch (irreversible). Slashes stake by `slash_bps`, optionally cascades to descendants

Usage: tenzro agent terminate [OPTIONS] --controller <CONTROLLER> --controller-did <CONTROLLER_DID> --agent-did <AGENT_DID>

Options:
      --key-namespace <KEY_NAMESPACE>
          Hardware key namespace of the signing account [default: client]
  -v, --verbose
          Enable verbose logging
      --controller <CONTROLLER>
          Controller address (hex, must match the signing key)
      --format <FORMAT>
          Output format (text, json) [default: text]
      --controller-did <CONTROLLER_DID>
          Controller DID
      --agent-did <AGENT_DID>
          Agent DID to terminate
      --reason-code <REASON_CODE>
          Reason code [default: 0]
      --slash-bps <SLASH_BPS>
          Basis points of stake to slash (0..=10000) [default: 0]
      --cascade
          Recursively terminate descendants under children:<parent_id>
      --reason-text <REASON_TEXT>
          Optional human reason text
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro agent terms`

```
Call tenzro_getAgentTerms: the agent's full consensus Terms, root kind, status and spend so far

Usage: tenzro agent terms [OPTIONS] --agent-did <AGENT_DID>

Options:
      --agent-did <AGENT_DID>  agent did
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro agent tool-call-records`

```
Call tenzro_getToolCallRecords (the tool-call records this node signed for an agent (`agent_did`, `limit`), and whether it records) and print the node's answer

Usage: tenzro agent tool-call-records [OPTIONS]

Options:
      --params <PARAMS>  Parameters as a JSON object [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro agent wallet-consent`

```
The consent that makes the agent's EVM account its ERC-8004 agentWallet

Usage: tenzro agent wallet-consent [OPTIONS] --did <DID> --chain <CHAIN> --agent-id <AGENT_ID> --owner <OWNER> --deadline <DEADLINE>

Options:
      --did <DID>            The agent DID
  -v, --verbose              Enable verbose logging
      --chain <CHAIN>        The chain, CAIP-2 (eip155:<id>)
      --format <FORMAT>      Output format (text, json) [default: text]
      --agent-id <AGENT_ID>  The ERC-8004 agentId
      --owner <OWNER>        The address that owns the entry
      --deadline <DEADLINE>  Unix seconds the consent expires (at most 300 s after it is used)
      --registry <REGISTRY>  The identity registry, if not the canonical one
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

## `tenzro auth`

```
OAuth 2.1 + DPoP auth: refresh access tokens, link wallet for auth

Usage: tenzro auth [OPTIONS] <COMMAND>

Commands:
  exchange-token  Call tenzro_exchangeToken (exchange token) and print the node's answer
  introspect      Call tenzro_introspectToken (introspect token) and print the node's answer
  discovery       Call tenzro_oauthDiscovery (oauth discovery) and print the node's answer
  onboard-agent   Call tenzro_onboardAutonomousAgent (onboard autonomous agent) and print the node's answer
  onboard-human   Call tenzro_onboardHuman (onboard human) and print the node's answer
  refresh         Exchange a refresh token for a fresh access token
  dpop-key        Show this machine's DPoP key, creating one on first use
  dpop-proof      Sign a one-off DPoP proof for a request
  help            Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro auth discovery`

```
Call tenzro_oauthDiscovery (oauth discovery) and print the node's answer

Usage: tenzro auth discovery [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro auth dpop-key`

```
Show this machine's DPoP key, creating one on first use.

Prints the RFC 7638 thumbprint (`jkt`) that `--dpop-jkt` wants: bind a token to it once, and every later CLI call signs its own proof.

Usage: tenzro auth dpop-key [OPTIONS]

Options:
  -v, --verbose
          Enable verbose logging

      --format <FORMAT>
          Output format (text, json)
          
          [default: text]

  -h, --help
          Print help (see a summary with '-h')
```

### `tenzro auth dpop-proof`

```
Sign a one-off DPoP proof for a request.

Ordinary CLI calls mint their own, so this is for driving the node from curl or a script — anywhere the proof has to be produced by hand.

Usage: tenzro auth dpop-proof [OPTIONS]

Options:
      --method <METHOD>
          HTTP method the proof authorises. Bound into the proof, so it must match the request
          
          [default: POST]

  -v, --verbose
          Enable verbose logging

      --format <FORMAT>
          Output format (text, json)
          
          [default: text]

      --url <URL>
          Target URL. Query and fragment are stripped, matching what the node compares against
          
          [default: http://127.0.0.1:8545]

      --token <TOKEN>
          Access token this proof is presented with. Hashed into `ath`, which the node requires on access-token requests. Falls back to `TENZRO_BEARER_JWT`

  -h, --help
          Print help (see a summary with '-h')
```

### `tenzro auth exchange-token`

```
Call tenzro_exchangeToken (exchange token) and print the node's answer

Usage: tenzro auth exchange-token [OPTIONS] --subject-token <SUBJECT_TOKEN> --child-bearer-did <CHILD_BEARER_DID> --child-dpop-jkt <CHILD_DPOP_JKT> --requested-rar <REQUESTED_RAR>

Options:
      --subject-token <SUBJECT_TOKEN>
          The parent access token
  -v, --verbose
          Enable verbose logging
      --child-bearer-did <CHILD_BEARER_DID>
          DID the child token is issued to
      --format <FORMAT>
          Output format (text, json) [default: text]
      --child-dpop-jkt <CHILD_DPOP_JKT>
          JWK thumbprint of the child holder's key; the child token is DPoP-bound to it
      --requested-rar <REQUESTED_RAR>
          File holding the child's `authorization_details` array, a subset of the parent's
      --capability <REQUESTED_AAP_CAPABILITIES>
          A capability the child carries, a subset of the parent's (repeatable)
      --requested-ttl-secs <REQUESTED_TTL_SECS>
          Child lifetime in seconds, clamped to the parent's remaining lifetime
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro auth introspect`

```
Call tenzro_introspectToken (introspect token) and print the node's answer

Usage: tenzro auth introspect [OPTIONS] --token <TOKEN>

Options:
      --token <TOKEN>    token
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro auth onboard-agent`

```
Call tenzro_onboardAutonomousAgent (onboard autonomous agent) and print the node's answer

Usage: tenzro auth onboard-agent [OPTIONS] --device-public-key <DEVICE_PUBLIC_KEY> --machine-id <MACHINE_ID>

Options:
      --device-public-key <DEVICE_PUBLIC_KEY>
          The agent's device public key (hex), held by its secure element; its DID derives from it, and its bond is posted on chain for that DID
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --machine-id <MACHINE_ID>
          Identifier of the secure element that holds the device key
      --dpop-jkt <DPOP_JKT>
          JWK thumbprint to DPoP-bind the issued token to
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro auth onboard-human`

```
Call tenzro_onboardHuman (onboard human) and print the node's answer

Usage: tenzro auth onboard-human [OPTIONS] --display-name <DISPLAY_NAME> --credential-id-hex <CREDENTIAL_ID_HEX> --public-key-hex <PUBLIC_KEY_HEX> --ml-dsa-public-key-hex <ML_DSA_PUBLIC_KEY_HEX> --challenge-id <CHALLENGE_ID> --authenticator-data-hex <AUTHENTICATOR_DATA_HEX> --client-data-json <CLIENT_DATA_JSON> --signature-hex <SIGNATURE_HEX> --ml-dsa-signature-hex <ML_DSA_SIGNATURE_HEX>

Options:
      --display-name <DISPLAY_NAME>
          Display name
  -v, --verbose
          Enable verbose logging
      --credential-id-hex <CREDENTIAL_ID_HEX>
          Passkey credential id, hex
      --format <FORMAT>
          Output format (text, json) [default: text]
      --public-key-hex <PUBLIC_KEY_HEX>
          Passkey P-256 public key (raw x||y), hex
      --ml-dsa-public-key-hex <ML_DSA_PUBLIC_KEY_HEX>
          ML-DSA-65 verifying key, hex
      --challenge-id <CHALLENGE_ID>
          Custody challenge id (tenzro_createCustodyChallenge, operation `enroll_passkey`)
      --authenticator-data-hex <AUTHENTICATOR_DATA_HEX>
          `authenticatorData` bytes, hex
      --client-data-json <CLIENT_DATA_JSON>
          File holding the exact `clientDataJSON` bytes; they are signed as returned and must not be re-serialized
      --signature-hex <SIGNATURE_HEX>
          Assertion signature (DER or raw r||s), hex
      --ml-dsa-signature-hex <ML_DSA_SIGNATURE_HEX>
          ML-DSA-65 signature over the challenge, hex
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro auth refresh`

```
Exchange a refresh token for a fresh access token

Usage: tenzro auth refresh [OPTIONS]

Options:
      --rpc <RPC>                      RPC endpoint [default: https://rpc.tenzro.com]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --refresh-token <REFRESH_TOKEN>  Refresh token. If omitted, reads from `~/.tenzro/config.json`
  -h, --help                           Print help
```

## `tenzro beacon`

```
The chain's randomness beacon

Usage: tenzro beacon [OPTIONS]

Options:
      --round <ROUND>    The value taken at this round
  -v, --verbose          Enable verbose logging
      --at-ms <AT_MS>    The first value taken at or after this block time, ms
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro bond`

```
AgentBond surety primitive: post, increase, withdraw, get, list

Usage: tenzro bond [OPTIONS] <COMMAND>

Commands:
  post      Post a new AgentBond (signed PostAgentBond transaction)
  increase  Increase an existing AgentBond (signed IncreaseAgentBond transaction)
  withdraw  Initiate cooldown / withdrawal of an AgentBond (signed WithdrawAgentBond transaction)
  get       Inspect a single AgentBond by agent DID (read-only)
  list      List AgentBonds by controller DID (read-only)
  help      Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro bond get`

```
Inspect a single AgentBond by agent DID (read-only)

Usage: tenzro bond get [OPTIONS] <AGENT_DID>

Arguments:
  <AGENT_DID>  Agent DID

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro bond increase`

```
Increase an existing AgentBond (signed IncreaseAgentBond transaction)

Usage: tenzro bond increase [OPTIONS] --agent-did <AGENT_DID> --amount <AMOUNT>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --agent-did <AGENT_DID>          Agent DID whose bond is being increased
      --format <FORMAT>                Output format (text, json) [default: text]
      --amount <AMOUNT>                Additional bond amount in wei
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro bond list`

```
List AgentBonds by controller DID (read-only)

Usage: tenzro bond list [OPTIONS] <CONTROLLER_DID>

Arguments:
  <CONTROLLER_DID>  Controller DID

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro bond post`

```
Post a new AgentBond (signed PostAgentBond transaction)

Usage: tenzro bond post [OPTIONS] --agent-did <AGENT_DID> --controller-did <CONTROLLER_DID> --amount <AMOUNT>

Options:
      --key-namespace <KEY_NAMESPACE>
          Hardware key namespace of the signing account [default: client]
  -v, --verbose
          Enable verbose logging
      --agent-did <AGENT_DID>
          Agent DID (e.g. `did:tenzro:machine:...`) the bond is posted against
      --format <FORMAT>
          Output format (text, json) [default: text]
      --controller-did <CONTROLLER_DID>
          Controller DID (e.g. `did:tenzro:human:...`)
      --amount <AMOUNT>
          Bond amount in wei (1 TNZO = 10^18 wei)
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro bond withdraw`

```
Initiate cooldown / withdrawal of an AgentBond (signed WithdrawAgentBond transaction)

Usage: tenzro bond withdraw [OPTIONS] --agent-did <AGENT_DID>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --agent-did <AGENT_DID>          Agent DID whose bond is being withdrawn
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

## `tenzro bridge`

```
Cross-chain bridge commands (quote, execute, status, routes)

Usage: tenzro bridge [OPTIONS] <COMMAND>

Commands:
  routes                 List every governed route with its caps, epoch usage and supply
  route                  Show one route by transport and external chain
  send                   Send TNZO to an external chain, or withdraw a deposit asset over its deposit route (signed in hardware by the holder)
  deliver                Deliver a committee-attested inbound transfer
  light-client           Relay a light-client update (bootstrap or committee handover) for a route
  ibc                    Relay an IBC message (a classic handshake step, or a packet's acknowledgement or timeout) from the Cosmos chain of an IBC route
  attest                 Build a delivery for a route's verifiers to sign from the source chain, or add a verifier's signature to one
  descriptor             Print the Bitcoin deposit descriptor for a set of signers
  withdrawal             Sign a Bitcoin route's withdrawal
  draw-committee         Draw a route's committees from the bonded attestors with a bridge signer, once a draw is due
  report-equivocation    Report a committee member that signed two deliveries with one nonce
  report-wrong-handover  Report a committee member that signed a handover to a committee the chain did not draw
  outflow                Show the network-wide exit limits: each unit's cap per epoch and what has left this epoch, the exit delay rule and the cap-raise bound
  exit                   Show a queued exit
  release-exit           Release a queued exit whose delay has passed
  cancel-exit            Cancel a queued exit and return its value to the sender
  help                   Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro bridge attest`

```
Build a delivery for a route's verifiers to sign from the source chain, or add a verifier's signature to one

Usage: tenzro bridge attest [OPTIONS]

Options:
      --adapter <ADAPTER>
          Route transport: ccip, ibc, deposit or contract
  -v, --verbose
          Enable verbose logging
      --chain <CHAIN>
          External chain the message comes from
      --format <FORMAT>
          Output format (text, json) [default: text]
      --tx <TX>
          The source transaction: a Solana signature (base58) or an EVM transaction hash
      --source-rpc <SOURCE_RPC>
          This verifier's own RPC endpoint on the external chain
      --beacon <BEACON>
          A beacon node's Beacon API, for routes that follow Ethereum's beacon chain
      --sequence <SEQUENCE>
          The message's sequence, when the transaction sent more than one
      --nonce <NONCE>
          The delivery's nonce, as the relayer assigned it
      --expiry-ms <EXPIRY_MS>
          Unix ms after which the delivery is refused, as the relayer set it
      --outbound-sequence <OUTBOUND_SEQUENCE>
          Attest Tenzro's outbound record with this sequence instead, for the bridge contract on the external chain to execute
      --handover <HANDOVER>
          Hand the route's bridge contract over to this drawn committee instead, signed by the committee the contract trusts (`--from-set`)
      --from-set <FROM_SET>
          The committee the bridge contract trusts now, whose members sign the handover
      --request-out <REQUEST_OUT>
          Where to write the unsigned delivery
      --request-in <REQUEST_IN>
          A delivery written by the first step, to add a signature to
      --signature <SIGNATURE>
          A verifier's 65-byte signature over the digest (hex)
      --pq-signature <PQ_SIGNATURE>
          A verifier's 3309-byte ML-DSA-65 signature over the digest (hex), for a delivery
      --rpc <RPC>
          Tenzro RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro bridge cancel-exit`

```
Cancel a queued exit and return its value to the sender

Usage: tenzro bridge cancel-exit [OPTIONS] --id <ID>

Options:
      --id <ID>                        The exit's id
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro bridge deliver`

```
Deliver a committee-attested inbound transfer

Usage: tenzro bridge deliver [OPTIONS] --adapter <ADAPTER> --from-chain <FROM_CHAIN> --delivery <DELIVERY>

Options:
      --adapter <ADAPTER>              Route transport: ccip, ibc, deposit or contract
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --from-chain <FROM_CHAIN>        External chain the delivery comes from
      --delivery <DELIVERY>            The attested delivery (hex)
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro bridge descriptor`

```
Print the Bitcoin deposit descriptor for a set of signers

Usage: tenzro bridge descriptor [OPTIONS] --signers <SIGNERS> --threshold <THRESHOLD>

Options:
      --signers <SIGNERS>      The signers' BIP-340 keys (hex, x-only), in order
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --threshold <THRESHOLD>  How many must sign a withdrawal
  -h, --help                   Print help
```

### `tenzro bridge draw-committee`

```
Draw a route's committees from the bonded attestors with a bridge signer, once a draw is due

Usage: tenzro bridge draw-committee [OPTIONS] --adapter <ADAPTER> --chain <CHAIN>

Options:
      --adapter <ADAPTER>              Route transport: ccip, ibc, deposit or contract
  -v, --verbose                        Enable verbose logging
      --chain <CHAIN>                  External chain of the route
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro bridge exit`

```
Show a queued exit

Usage: tenzro bridge exit [OPTIONS] --id <ID>

Options:
      --id <ID>          The exit's id
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro bridge ibc`

```
Relay an IBC message (a classic handshake step, or a packet's acknowledgement or timeout) from the Cosmos chain of an IBC route

Usage: tenzro bridge ibc [OPTIONS] --chain <CHAIN> --message <MESSAGE> --cosmos-rpc <COSMOS_RPC>

Options:
      --chain <CHAIN>
          External chain of the IBC route

  -v, --verbose
          Enable verbose logging

      --format <FORMAT>
          Output format (text, json)
          
          [default: text]

      --message <MESSAGE>
          The message

          Possible values:
          - connection-open-try:     The Cosmos connection end is INIT: open Tenzro's (classic)
          - connection-open-confirm: The Cosmos connection end is OPEN: open Tenzro's (classic)
          - channel-open-try:        The Cosmos channel end is INIT: open Tenzro's (classic)
          - channel-open-confirm:    The Cosmos channel end is OPEN: open Tenzro's (classic)
          - acknowledge:             The Cosmos chain acknowledged an outbound packet
          - timeout:                 An outbound packet timed out unreceived

      --cosmos-rpc <COSMOS_RPC>
          The Cosmos chain's CometBFT RPC endpoint

      --height <HEIGHT>
          The header height whose app hash the proof reaches (default: the height the route's light client stands at)

      --sequence <SEQUENCE>
          Acknowledge and timeout: the outbound packet's sequence

      --acknowledgement <ACKNOWLEDGEMENT>
          Acknowledge: the acknowledgement the Cosmos chain wrote (hex)

      --key-namespace <KEY_NAMESPACE>
          The signing account's hardware key namespace
          
          [default: client]

      --rpc <RPC>
          RPC endpoint
          
          [default: http://127.0.0.1:8545]

  -h, --help
          Print help (see a summary with '-h')
```

### `tenzro bridge light-client`

```
Relay a light-client update (bootstrap or committee handover) for a route

Usage: tenzro bridge light-client [OPTIONS] --adapter <ADAPTER> --chain <CHAIN>

Options:
      --adapter <ADAPTER>              Route transport: ccip, ibc, deposit or contract
  -v, --verbose                        Enable verbose logging
      --chain <CHAIN>                  External chain the light client follows
      --format <FORMAT>                Output format (text, json) [default: text]
      --update <UPDATE>                The update (hex): the bootstrap from the route's anchor, or a committee handover
      --beacon <BEACON>                A beacon node's Beacon API base URL: read the route's light-client state, fetch the update it needs next (the bootstrap from its anchor, or the handover of its current period) and relay it
      --cosmos-rpc <COSMOS_RPC>        A CometBFT RPC endpoint of the route's Cosmos chain: relay the bootstrap from the route's anchor, or the header at `--height` (default: the latest) from the height the light client trusts
      --height <HEIGHT>                With `--cosmos-rpc`: the header height to move the light client to
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro bridge outflow`

```
Show the network-wide exit limits: each unit's cap per epoch and what has left this epoch, the exit delay rule and the cap-raise bound

Usage: tenzro bridge outflow [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro bridge release-exit`

```
Release a queued exit whose delay has passed

Usage: tenzro bridge release-exit [OPTIONS] --id <ID>

Options:
      --id <ID>                        The exit's id
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro bridge report-equivocation`

```
Report a committee member that signed two deliveries with one nonce

Usage: tenzro bridge report-equivocation [OPTIONS] --adapter <ADAPTER> --chain <CHAIN> --member <MEMBER> --first <FIRST> --second <SECOND>

Options:
      --adapter <ADAPTER>              Route transport: ccip, ibc, deposit or contract
  -v, --verbose                        Enable verbose logging
      --chain <CHAIN>                  External chain of the route
      --format <FORMAT>                Output format (text, json) [default: text]
      --member <MEMBER>                The member's 20-byte signing address (hex)
      --first <FIRST>                  One delivery the member signed (hex)
      --second <SECOND>                Another delivery with the same nonce the member signed (hex)
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro bridge report-wrong-handover`

```
Report a committee member that signed a handover to a committee the chain did not draw

Usage: tenzro bridge report-wrong-handover [OPTIONS] --adapter <ADAPTER> --chain <CHAIN> --signed-by-set <SIGNED_BY_SET> --set-index <SET_INDEX> --members <MEMBERS> --threshold <THRESHOLD> --expires-at <EXPIRES_AT> --signature <SIGNATURE>

Options:
      --adapter <ADAPTER>              Route transport: ccip, ibc, deposit or contract
  -v, --verbose                        Enable verbose logging
      --chain <CHAIN>                  External chain of the route
      --format <FORMAT>                Output format (text, json) [default: text]
      --signed-by-set <SIGNED_BY_SET>  The committee the signer sat on
      --set-index <SET_INDEX>          The set index the handover names
      --members <MEMBERS>              The handover's member addresses (20-byte hex each), in order
      --threshold <THRESHOLD>          The handover's threshold
      --expires-at <EXPIRES_AT>        The handover's expiry, Unix seconds
      --signature <SIGNATURE>          The member's 65-byte signature over the handover digest (hex)
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro bridge route`

```
Show one route by transport and external chain

Usage: tenzro bridge route [OPTIONS] --adapter <ADAPTER> --chain <CHAIN>

Options:
      --adapter <ADAPTER>  Route transport: ccip, ibc, deposit or contract
  -v, --verbose            Enable verbose logging
      --chain <CHAIN>      External chain (e.g. "ethereum", "base", "arbitrum", "solana")
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro bridge routes`

```
List every governed route with its caps, epoch usage and supply

Usage: tenzro bridge routes [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro bridge send`

```
Send TNZO to an external chain, or withdraw a deposit asset over its deposit route (signed in hardware by the holder)

Usage: tenzro bridge send [OPTIONS] --target-chain <TARGET_CHAIN> --recipient <RECIPIENT> --amount <AMOUNT>

Options:
      --target-chain <TARGET_CHAIN>    Destination chain, served by exactly one governed route
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --recipient <RECIPIENT>          Recipient on the destination chain (hex); for Bitcoin, the output script to pay
      --amount <AMOUNT>                Amount in the smallest unit (decimal): TNZO wei, or the deposit asset's unit over a deposit route, or the carried asset's unit
      --asset <ASSET>                  A carried asset's symbol (USDC, OUSD): burns its representation here and the route's vault releases the token on the destination chain
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro bridge withdrawal`

```
Sign a Bitcoin route's withdrawal

Usage: tenzro bridge withdrawal [OPTIONS]

Options:
      --chain <CHAIN>              The deposit route's external chain [default: bitcoin]
  -v, --verbose                    Enable verbose logging
      --format <FORMAT>            Output format (text, json) [default: text]
      --sequence <SEQUENCE>        The withdrawal's sequence on the route
      --request-out <REQUEST_OUT>  Where to write the withdrawal to collect signatures in
      --request-in <REQUEST_IN>    A withdrawal written by --request-out
      --signer <SIGNER>            The signer's BIP-340 key (hex)
      --signatures <SIGNATURES>    The signer's signature over each input's digest, in input order (hex)
      --rpc <RPC>                  Tenzro RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

## `tenzro bridge-fee`

```
Bridge fee in TNZO: quote destination-native bridge fees in TNZO + list sponsorship pools

Usage: tenzro bridge-fee [OPTIONS] <COMMAND>

Commands:
  quote  Quote a destination-native bridge fee in TNZO
  help   Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro bridge-fee quote`

```
Quote a destination-native bridge fee in TNZO

Usage: tenzro bridge-fee quote [OPTIONS] --adapter <ADAPTER> --dest-chain <DEST_CHAIN> --native-fee <NATIVE_FEE>

Options:
      --adapter <ADAPTER>        Route transport: ccip, ibc, deposit or contract
  -v, --verbose                  Enable verbose logging
      --dest-chain <DEST_CHAIN>  Destination chain CAIP-2 identifier (e.g. eip155:1, solana:mainnet-beta)
      --format <FORMAT>          Output format (text, json) [default: text]
      --native-fee <NATIVE_FEE>  Destination-native fee in the destination chain smallest unit (u128 decimal)
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

## `tenzro catalog`

```
The model catalog: what a node serves, and publishing entries to it

Usage: tenzro catalog [OPTIONS] <COMMAND>

Commands:
  list      List the models a node's catalog serves, and any it left out and why
  show      Show one model's entry, its publishers, and whether a token is needed
  publish   Sign catalog entries (a JSON file, or a directory of them) and submit them
  withdraw  Sign and submit the withdrawal of a model you published
  help      Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro catalog list`

```
List the models a node's catalog serves, and any it left out and why

Usage: tenzro catalog list [OPTIONS]

Options:
      --engine <ENGINE>  Only this engine family (gguf, onnx-vision, media-gen, ...)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro catalog publish`

```
Sign catalog entries (a JSON file, or a directory of them) and submit them

Usage: tenzro catalog publish [OPTIONS] --key-label <KEY_LABEL> <PATH>

Arguments:
  <PATH>  A catalog entry JSON file (one entry or an array), or a directory of them

Options:
      --key-label <KEY_LABEL>  Label of the publisher's key in this machine's TPM or Secure Enclave
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --sequence <SEQUENCE>    Sequence of this publication; a node replaces a model's entry only with a higher one. Defaults to the current Unix time
      --out <OUT>              Write the signed records here instead of submitting them
      --rpc <RPC>              [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro catalog show`

```
Show one model's entry, its publishers, and whether a token is needed

Usage: tenzro catalog show [OPTIONS] <MODEL>

Arguments:
  <MODEL>  

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro catalog withdraw`

```
Sign and submit the withdrawal of a model you published

Usage: tenzro catalog withdraw [OPTIONS] --key-label <KEY_LABEL> <MODEL>

Arguments:
  <MODEL>  

Options:
      --key-label <KEY_LABEL>  
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --sequence <SEQUENCE>    
      --rpc <RPC>              [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

## `tenzro chat`

```
Interactive chat with AI models

Usage: tenzro chat [OPTIONS] [MODEL_ID]

Arguments:
  [MODEL_ID]  Model ID to use. Omit to select one from `--use-case` + `--budget`

Options:
      --use-case <USE_CASE>
          Use case for intent selection when no model_id is given: chat, code, reasoning, summarize, extract, or embed
  -v, --verbose
          Enable verbose logging
      --budget <BUDGET>
          Per-request cost cap in smallest TNZO unit (decimal string) for intent selection. Only used when no model_id is given
      --format <FORMAT>
          Output format (text, json) [default: text]
      --optimize <OPTIMIZE>
          Cost-quality knob in [0.0, 1.0] for intent selection
      --quality-floor <QUALITY_FLOOR>
          Reject models below this tier during intent selection: cheap or strong
      --max-tokens <MAX_TOKENS>
          Maximum tokens to generate [default: 512]
      --temperature <TEMPERATURE>
          Temperature (0.0-2.0) [default: 0.7]
      --draft-n <DRAFT_N>
          Enable Multi-Token Prediction with this draft count (1..=6). Only meaningful on models whose catalog entry declares a paired drafter (e.g. Gemma 4 12B / 31B via `gemma4-*-mtp-draft`). Unsloth recommends 2 as a starting point; optimal value is hardware-dependent
      --jurisdiction <JURISDICTION>
          Comma-separated jurisdiction pin: ISO 3166-1 alpha-2 country codes and/or bloc tokens (e.g. "DE,EU"), case-insensitive. The serving node must declare a matching attestation-bound locality claim or the request is refused
      --require-jurisdiction-receipt
          Fail the request unless the response carries a verifiable signed jurisdiction receipt
      --channel-voucher <CHANNEL_VOUCHER>
          Path to a JSON escrow voucher (`escrow_id`, `cumulative_amount`, `public_key`, composite `signature`): the payer's next cumulative voucher on an open payment channel, paying for this turn
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

## `tenzro cluster`

```
Local-network cluster planning

Usage: tenzro cluster [OPTIONS] <COMMAND>

Commands:
  members  List the verified members of a cluster (this node's own by default), with the hardware of those found on the local network
  derive   Create a cluster or change its members: derive the cluster DID and the digests the operator's passkey and each member machine must sign
  accept   Accept this machine's inclusion in a cluster list, signed by its own hardware key (node administrators only)
  set      Submit an operator-approved, member-accepted membership list
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro cluster accept`

```
Accept this machine's inclusion in a cluster list, signed by its own hardware key (node administrators only)

Usage: tenzro cluster accept [OPTIONS] --cluster-did <CLUSTER_DID> --seq <SEQ>

Options:
      --cluster-did <CLUSTER_DID>  The cluster DID
  -v, --verbose                    Enable verbose logging
      --format <FORMAT>            Output format (text, json) [default: text]
      --seq <SEQ>                  Sequence number of the list being accepted
      --rpc <RPC>                  RPC endpoint of the member machine [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

### `tenzro cluster derive`

```
Create a cluster or change its members: derive the cluster DID and the digests the operator's passkey and each member machine must sign

Usage: tenzro cluster derive [OPTIONS] --operator-did <OPERATOR_DID> --name <NAME> --seq <SEQ> --member <MEMBERS>

Options:
      --operator-did <OPERATOR_DID>  The operator's human DID
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --name <NAME>                  Cluster name
      --seq <SEQ>                    Sequence number: 1 creates the cluster, each change uses a higher one
      --member <MEMBERS>             Member machine DIDs (repeat for each member)
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro cluster members`

```
List the verified members of a cluster (this node's own by default), with the hardware of those found on the local network

Usage: tenzro cluster members [OPTIONS]

Options:
      --cluster-did <CLUSTER_DID>  Cluster DID to list (defaults to this node's own cluster)
  -v, --verbose                    Enable verbose logging
      --format <FORMAT>            Output format (text, json) [default: text]
      --rpc <RPC>                  RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

### `tenzro cluster set`

```
Submit an operator-approved, member-accepted membership list

Usage: tenzro cluster set [OPTIONS] --membership <MEMBERSHIP> --challenge-id <CHALLENGE_ID>

Options:
      --membership <MEMBERSHIP>      Path to a JSON file holding the signed membership list
  -v, --verbose                      Enable verbose logging
      --challenge-id <CHALLENGE_ID>  The custody challenge id the operator's approval answers
      --format <FORMAT>              Output format (text, json) [default: text]
      --rpc <RPC>                    RPC endpoint (the node that issued the custody challenge) [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

## `tenzro contract`

```
Contract deployment commands

Usage: tenzro contract [OPTIONS] <COMMAND>

Commands:
  deploy  Deploy an EVM contract from the signing account
  call    Call contracts in the EVM and the SVM as one all-or-nothing transaction
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro contract call`

```
Call contracts in the EVM and the SVM as one all-or-nothing transaction

Usage: tenzro contract call [OPTIONS] --call <CALLS>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --call <CALLS>                   A call, `<vm>:<to hex>:<calldata hex>[:<value wei>]` with vm one of evm or svm. Repeat for each call, in order
      --format <FORMAT>                Output format (text, json) [default: text]
      --gas-limit <GAS_LIMIT>          Gas for all the calls together [default: 1000000]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro contract deploy`

```
Deploy an EVM contract from the signing account

Usage: tenzro contract deploy [OPTIONS] --bytecode <BYTECODE>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --bytecode <BYTECODE>            Contract creation code (hex-encoded, with optional 0x prefix)
      --format <FORMAT>                Output format (text, json) [default: text]
      --args <ARGS>                    Constructor arguments (hex-encoded ABI)
      --gas-limit <GAS_LIMIT>          Gas limit [default: 3000000]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

## `tenzro crypto`

```
Cryptographic operations (sign, verify, encrypt, decrypt, hash, keygen)

Usage: tenzro crypto [OPTIONS] <COMMAND>

Commands:
  verify  Verify a message signature
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro crypto verify`

```
Verify a message signature

Usage: tenzro crypto verify [OPTIONS] --key <KEY> --message <MESSAGE> --signature <SIGNATURE>

Options:
      --key <KEY>              Public key (hex)
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --message <MESSAGE>      Message (hex)
      --signature <SIGNATURE>  Signature (hex)
      --key-type <KEY_TYPE>    Key type: ed25519 or secp256k1 [default: ed25519]
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

## `tenzro da`

```
Committee data availability: challenge, challenges, availability, committee, blobs, object, retention

Usage: tenzro da [OPTIONS] <COMMAND>

Commands:
  challenge     Challenge a committee member to prove sliver possession
  challenges    List resolved possession-challenge records, newest-first
  availability  Show availability scores (one member or all, lowest first)
  committee     Show the committee roster with per-member availability
  blobs         List blob commitments held in the local committee store
  object        Show an object's record in chain state and its expiry
  retention     Show the retention of each class and the live and expired totals
  help          Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro da availability`

```
Show availability scores (one member or all, lowest first)

Usage: tenzro da availability [OPTIONS]

Options:
      --address <ADDRESS>  Optional 0x-prefixed member address; omit for all scored members
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro da blobs`

```
List blob commitments held in the local committee store

Usage: tenzro da blobs [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro da challenge`

```
Challenge a committee member to prove sliver possession

Usage: tenzro da challenge [OPTIONS] --commitment <COMMITMENT> --target-index <TARGET_INDEX>

Options:
      --commitment <COMMITMENT>      0x-prefixed 32-byte blob commitment
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --target-index <TARGET_INDEX>  Committee index of the member to challenge
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro da challenges`

```
List resolved possession-challenge records, newest-first

Usage: tenzro da challenges [OPTIONS]

Options:
      --limit <LIMIT>    Maximum records to return, newest-first [default: 100]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro da committee`

```
Show the committee roster with per-member availability

Usage: tenzro da committee [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro da object`

```
Show an object's record in chain state and its expiry

Usage: tenzro da object [OPTIONS] <COMMITMENT>

Arguments:
  <COMMITMENT>  The object's 32-byte commitment, hex

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro da retention`

```
Show the retention of each class and the live and expired totals

Usage: tenzro da retention [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro decide`

```
Decision models: answer typed questions about a text

Usage: tenzro decide [OPTIONS] <COMMAND>

Commands:
  catalog  List the decision-model catalog
  load     Fetch a catalog decision model onto this node and serve it
  unload   Unload a decision model
  run      Answer questions about a text
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro decide catalog`

```
List the decision-model catalog

Usage: tenzro decide catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro decide load`

```
Fetch a catalog decision model onto this node and serve it

Usage: tenzro decide load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro decide run`

```
Answer questions about a text

Usage: tenzro decide run [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>                
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --state <STATE>                The text to decide about
      --state-file <STATE_FILE>      A file holding the state: text, or JSON (an email, a ticket, a record)
      --yes-no <YES_NO>              A yes/no question as `id=instructions`; repeat for each
      --questions <QUESTIONS>        Questions as JSON: an array of `{ id, type, instructions, criteria }` (see the MCP `decide` tool), or `@path` to read it from a file
      --verification <VERIFICATION>  Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>                    [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro decide unload`

```
Unload a decision model

Usage: tenzro decide unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro detect`

```
Object detection (RF-DETR, D-FINE)

Usage: tenzro detect [OPTIONS] <COMMAND>

Commands:
  catalog  List the curated detection catalog (RF-DETR, D-FINE)
  load     Fetch a catalog detector onto this node and serve it
  unload   Unregister a previously-loaded detector
  run      Run object detection
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro detect catalog`

```
List the curated detection catalog (RF-DETR, D-FINE)

Usage: tenzro detect catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro detect load`

```
Fetch a catalog detector onto this node and serve it

Usage: tenzro detect load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro detect run`

```
Run object detection

Usage: tenzro detect run [OPTIONS] --model <MODEL> --image <IMAGE>

Options:
      --model <MODEL>
          
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --image <IMAGE>
          
      --score-threshold <SCORE_THRESHOLD>
          Score threshold in [0, 1]. Default 0.25 [default: 0.25]
      --verification <VERIFICATION>
          Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>
          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro detect unload`

```
Unregister a previously-loaded detector

Usage: tenzro detect unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro dev`

```
Start a local single-validator chain for development, keys in this machine's hardware

Usage: tenzro dev [OPTIONS]

Options:
      --data-dir <DATA_DIR>            Data directory of the developer chain. A fresh directory starts a new chain; an existing one resumes it
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc-addr <RPC_ADDR>            RPC listen address [default: 127.0.0.1:8545]
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the client account funded at genesis (the account the other commands sign with by default) [default: client]
      --fund <ADDRESS>                 Another account to fund at genesis, 32-byte hex: an account whose key is a passkey or another machine's hardware. Repeatable
  -h, --help                           Print help
```

## `tenzro device`

```
Devices bound to an identity, and machine ownership

Usage: tenzro device [OPTIONS] <COMMAND>

Commands:
  bind-device       Call tenzro_bindDevice (bind device) and print the node's answer
  list              List the devices bound to an identity
  wallet-readiness  Check whether a wallet may be created yet, and why not
  revoke            Unbind a device and end every session it authorised
  transfer          Move a machine to another identity
  help              Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro device bind-device`

```
Call tenzro_bindDevice (bind device) and print the node's answer

Usage: tenzro device bind-device [OPTIONS] --identity-did <IDENTITY_DID> --label <LABEL> --attestation-object-b64 <ATTESTATION_OBJECT_B64>

Options:
      --identity-did <IDENTITY_DID>
          identity did
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --label <LABEL>
          label
      --attestation-object-b64 <ATTESTATION_OBJECT_B64>
          attestation object b64
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro device list`

```
List the devices bound to an identity

Usage: tenzro device list [OPTIONS] <DID>

Arguments:
  <DID>  Identity whose devices to list

Options:
      --json             
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro device revoke`

```
Unbind a device and end every session it authorised

Usage: tenzro device revoke [OPTIONS] --challenge-id <CHALLENGE_ID> --authorization <AUTHORIZATION> <DID> <CREDENTIAL_ID>

Arguments:
  <DID>            
  <CREDENTIAL_ID>  Credential id of the device to unbind

Options:
      --challenge-id <CHALLENGE_ID>    Custody challenge id (`tenzro_createCustodyChallenge`, operation `revoke_device`)
  -v, --verbose                        Enable verbose logging
      --authorization <AUTHORIZATION>  JSON file holding a bound device's WebAuthn assertion over that challenge: `credential_id`, `authenticator_data_b64`, `client_data_json_b64`, `signature_b64`
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro device transfer`

```
Move a machine to another identity

Usage: tenzro device transfer [OPTIONS] --challenge-id <CHALLENGE_ID> <MACHINE_DID> <NEW_OWNER_DID>

Arguments:
  <MACHINE_DID>    Machine being transferred
  <NEW_OWNER_DID>  Identity taking ownership

Options:
      --authority <AUTHORITY>
          `controller` for a machine a party delegated, `machine_key` for one nobody delegated. The two are not interchangeable [default: controller]
  -v, --verbose
          Enable verbose logging
      --controller-did <CONTROLLER_DID>
          The controlling DID, for a controller-authorised transfer
      --format <FORMAT>
          Output format (text, json) [default: text]
      --challenge-id <CHALLENGE_ID>
          Custody challenge id (`tenzro_createCustodyChallenge`, operation `transfer_machine_ownership`)
      --authorization <AUTHORIZATION>
          Controller transfer: JSON file holding an assertion over the challenge from a device bound to the controller
      --machine-signature-hex <MACHINE_SIGNATURE_HEX>
          Hardware-root transfer: the machine key's signature over the challenge digest, hex
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro device wallet-readiness`

```
Check whether a wallet may be created yet, and why not

Usage: tenzro device wallet-readiness [OPTIONS] <DID>

Arguments:
  <DID>  

Options:
      --this-device <THIS_DEVICE>  Credential id of the device you are on, when it is one of the bound ones. Supplying it is what lets the check notice that every bound device is this same machine
  -v, --verbose                    Enable verbose logging
      --format <FORMAT>            Output format (text, json) [default: text]
      --rpc <RPC>                  [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

## `tenzro discover`

```
Discovery: node hardware profile

Usage: tenzro discover [OPTIONS] <COMMAND>

Commands:
  profile  Show this node's hardware serving profile
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro discover profile`

```
Show this node's hardware serving profile

Usage: tenzro discover profile [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro duty`

```
Network duties: work the chain pays the first prover for

Usage: tenzro duty [OPTIONS] <COMMAND>

Commands:
  list  List every open duty (read-only)
  get   Show one duty by id (read-only)
  help  Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro duty get`

```
Show one duty by id (read-only)

Usage: tenzro duty get [OPTIONS] <DUTY_ID>

Arguments:
  <DUTY_ID>  Duty id (32-byte hex)

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro duty list`

```
List every open duty (read-only)

Usage: tenzro duty list [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro embed-image`

```
Image embeddings (CLIP, SigLIP2, DINOv3)

Usage: tenzro embed-image [OPTIONS] <COMMAND>

Commands:
  catalog     List the curated vision-encoder catalog (CLIP, SigLIP2, DINOv3)
  load        Fetch a catalog image encoder onto this node and serve it
  unload      Unregister a previously-loaded image encoder
  run         Embed a single image
  similarity  Cosine similarity between an image embedding and a text embedding
  help        Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro embed-image catalog`

```
List the curated vision-encoder catalog (CLIP, SigLIP2, DINOv3)

Usage: tenzro embed-image catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro embed-image load`

```
Fetch a catalog image encoder onto this node and serve it

Usage: tenzro embed-image load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro embed-image run`

```
Embed a single image

Usage: tenzro embed-image run [OPTIONS] --model <MODEL> --image <IMAGE>

Options:
      --model <MODEL>                Model id of a loaded image encoder
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --image <IMAGE>                Path to the input image (PNG/JPEG/WebP)
      --normalize                    L2-normalize the output (most retrieval pipelines want this)
      --verification <VERIFICATION>  Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>                    [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro embed-image similarity`

```
Cosine similarity between an image embedding and a text embedding

Usage: tenzro embed-image similarity [OPTIONS] --image-embedding <IMAGE_EMBEDDING> --text-embedding <TEXT_EMBEDDING>

Options:
      --image-embedding <IMAGE_EMBEDDING>
          JSON file holding the image embedding as an array of numbers
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --text-embedding <TEXT_EMBEDDING>
          JSON file holding the text embedding as an array of numbers
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro embed-image unload`

```
Unregister a previously-loaded image encoder

Usage: tenzro embed-image unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro embed-text`

```
Text embeddings (Qwen3-Embedding, EmbeddingGemma, BGE-M3)

Usage: tenzro embed-text [OPTIONS] <COMMAND>

Commands:
  catalog  List the curated text-embedding catalog (Qwen3-Embedding, EmbeddingGemma, BGE-M3, ...)
  load     Fetch a catalog encoder onto this node and serve it
  unload   Unregister a previously-loaded text encoder
  run      Embed one or more strings
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro embed-text catalog`

```
List the curated text-embedding catalog (Qwen3-Embedding, EmbeddingGemma, BGE-M3, ...)

Usage: tenzro embed-text catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro embed-text load`

```
Fetch a catalog encoder onto this node and serve it

Usage: tenzro embed-text load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro embed-text run`

```
Embed one or more strings

Usage: tenzro embed-text run [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>                   Model id of a loaded text encoder
  -v, --verbose                         Enable verbose logging
      --format <FORMAT>                 Output format (text, json) [default: text]
      --input <INPUTS>                  Input strings (repeat --input for multiple)
      --image <IMAGES>                  A picture to embed (PNG, JPEG or WebP; repeat for multiple). Needs a vision-language embedder
      --video-frames <VIDEO_FRAMES>...  A video to embed, as its frames in order, comma-separated (repeat for multiple videos). Needs a vision-language embedder
      --media-text <MEDIA_TEXT>         Text embedded together with the single --image or --video-frames item, as one input
      --requested-dim <REQUESTED_DIM>   Optional Matryoshka truncation dim (e.g. 512, 256, 128 for EmbeddingGemma)
      --normalize                       L2-normalize the output (most retrieval pipelines want this)
      --role <ROLE>                     Whether these inputs are a search query or documents being indexed. Drives the model's own instruction template (Qwen3-Embedding, EmbeddingGemma, ModernBERT-embed each prefix queries/documents differently, or not at all for BGE-M3) — see `embed-text catalog` for which family this model belongs to. Defaults to document [default: document] [possible values: document, query]
      --task <TASK>                     Task description for the query role (Qwen3-Embedding, EmbeddingGemma). Falls back to the model's own default task when omitted. Ignored for the document role and for families with no instruction template
      --title <TITLE>                   Title for the document role (EmbeddingGemma only; ignored elsewhere)
      --verification <VERIFICATION>     Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>             Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>                       [default: http://127.0.0.1:8545]
  -h, --help                            Print help
```

### `tenzro embed-text unload`

```
Unregister a previously-loaded text encoder

Usage: tenzro embed-text unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro embed-video`

```
Video embeddings (catalog scaffolding for V-JEPA / VideoMAE)

Usage: tenzro embed-video [OPTIONS] <COMMAND>

Commands:
  catalog  List the curated video catalog (V-JEPA 2 ViT-L/H/g)
  load     Register a frame-pooling clip encoder over a loaded image encoder
  unload   Unregister a previously-loaded video encoder
  run      Embed a video file into a clip-level vector
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro embed-video catalog`

```
List the curated video catalog (V-JEPA 2 ViT-L/H/g)

Usage: tenzro embed-video catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro embed-video load`

```
Register a frame-pooling clip encoder over a loaded image encoder

Usage: tenzro embed-video load [OPTIONS] --model <MODEL> --vision-model <VISION_MODEL>

Options:
      --model <MODEL>                Model id to register the clip encoder under
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --vision-model <VISION_MODEL>  Model id of an already-loaded image encoder to pool frames through
      --num-frames <NUM_FRAMES>      Evenly-spaced frames sampled per clip. Defaults to 8 node-side
      --visibility <VISIBILITY>      Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                    [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro embed-video run`

```
Embed a video file into a clip-level vector

Usage: tenzro embed-video run [OPTIONS] --model <MODEL> --video <VIDEO>

Options:
      --model <MODEL>                
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --video <VIDEO>                Path to a video file (MP4, WebM or MKV)
      --normalize                    
      --frame-stride <FRAME_STRIDE>  Keep every Nth decoded frame instead of spreading the samples evenly across the clip. Still capped at the encoder's frame budget
      --verification <VERIFICATION>  Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>                    [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro embed-video unload`

```
Unregister a previously-loaded video encoder

Usage: tenzro embed-video unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro escrow`

```
Escrow and payment channel commands

Usage: tenzro escrow [OPTIONS] <COMMAND>

Commands:
  by-payee         Call tenzro_listEscrowsByPayee (list escrows by payee) and print the node's answer
  by-payer         Call tenzro_listEscrowsByPayer (list escrows by payer) and print the node's answer
  create           Create a new on-chain escrow (signed CreateEscrow transaction)
  release          Release escrowed funds to the payee (signed ReleaseEscrow transaction)
  refund           Refund escrowed funds back to the payer (signed RefundEscrow transaction)
  get              Inspect an escrow record by id
  redeem-delivery  Redeem a sealed delivery: the node claims the hash-locked escrows and publishes the key
  meter-bond       Read the bond behind a usage meter's key
  open-channel     Open a payment channel over a funded escrow
  voucher          Pay on a payment channel with the payer's next cumulative voucher
  close-channel    Close a payment channel (payer-signed)
  help             Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro escrow by-payee`

```
Call tenzro_listEscrowsByPayee (list escrows by payee) and print the node's answer

Usage: tenzro escrow by-payee [OPTIONS] --payee <PAYEE>

Options:
      --payee <PAYEE>    payee
  -v, --verbose          Enable verbose logging
      --cursor <CURSOR>  cursor
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro escrow by-payer`

```
Call tenzro_listEscrowsByPayer (list escrows by payer) and print the node's answer

Usage: tenzro escrow by-payer [OPTIONS] --payer <PAYER>

Options:
      --payer <PAYER>    payer
  -v, --verbose          Enable verbose logging
      --cursor <CURSOR>  cursor
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro escrow close-channel`

```
Close a payment channel (payer-signed)

Usage: tenzro escrow close-channel [OPTIONS] <CHANNEL_ID>

Arguments:
  <CHANNEL_ID>  Channel id (the escrow id, 32-byte hex)

Options:
      --key-namespace <KEY_NAMESPACE>  The payer's hardware key namespace (a-z, 0-9, '-', '_'): the client account that funded the escrow [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro escrow create`

```
Create a new on-chain escrow (signed CreateEscrow transaction)

Usage: tenzro escrow create [OPTIONS] --payee <PAYEE> --amount <AMOUNT> --expires-at <EXPIRES_AT>

Options:
      --key-namespace <KEY_NAMESPACE>
          The payer's hardware key namespace (a-z, 0-9, '-', '_'): the client account that funds the escrow and signs the transaction [default: client]
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --payee <PAYEE>
          Payee address (hex)
      --amount <AMOUNT>
          Amount in wei (smallest unit; 1 TNZO = 10^18 wei)
      --asset <ASSET>
          Asset id (defaults to native TNZO) [default: TNZO]
      --expires-at <EXPIRES_AT>
          Expiry as Unix timestamp in milliseconds
      --release <RELEASE>
          Release condition kind: timeout | provider | consumer | both | custom | stream (pays the payee per elapsed epoch: a compute rental or a standby) | executor (released by `--executor`, or by the payer, before expiry) [default: timeout]
      --executor <EXECUTOR>
          For `--release executor`: the account (32-byte hex) that may release the escrow besides the payer; the payer alone when omitted
      --rate-per-epoch <RATE_PER_EPOCH>
          For `--release stream`: wei paid per elapsed epoch
      --epoch-ms <EPOCH_MS>
          For `--release stream`: the epoch length, ms [default: 3600000]
      --reference <REFERENCE>
          An opaque reference the escrow carries (32-byte hex), so the application that opens it can find it again
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro escrow get`

```
Inspect an escrow record by id

Usage: tenzro escrow get [OPTIONS] <ESCROW_ID>

Arguments:
  <ESCROW_ID>  Escrow id (32-byte hex)

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro escrow meter-bond`

```
Read the bond behind a usage meter's key

Usage: tenzro escrow meter-bond [OPTIONS] <METER_ID>

Arguments:
  <METER_ID>  The meter id: the account slot of its P-256 key (32-byte hex)

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro escrow open-channel`

```
Open a payment channel over a funded escrow

Usage: tenzro escrow open-channel [OPTIONS] --channel-id <CHANNEL_ID>

Options:
      --channel-id <CHANNEL_ID>  The funded escrow's id (32-byte hex): the channel id
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro escrow redeem-delivery`

```
Redeem a sealed delivery: the node claims the hash-locked escrows and publishes the key

Usage: tenzro escrow redeem-delivery [OPTIONS] --escrow-id <ESCROW_ID>

Options:
      --escrow-id <ESCROW_ID>
          The HashLock escrow paying the node's payee (32-byte hex)
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --network-escrow-id <NETWORK_ESCROW_ID>
          The HashLock escrow paying the network's share under the same lock (32-byte hex)
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro escrow refund`

```
Refund escrowed funds back to the payer (signed RefundEscrow transaction)

Usage: tenzro escrow refund [OPTIONS] --payer <PAYER> <ESCROW_ID>

Arguments:
  <ESCROW_ID>  Escrow id (32-byte hex)

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --payer <PAYER>                  Payer address (must match the signing key)
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro escrow release`

```
Release escrowed funds to the payee (signed ReleaseEscrow transaction)

Usage: tenzro escrow release [OPTIONS] --payer <PAYER> <ESCROW_ID>

Arguments:
  <ESCROW_ID>  Escrow id (32-byte hex, with or without 0x prefix)

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --payer <PAYER>                  Payer address (must match the signing key)
      --proof <PROOF>                  Optional proof data (hex). If omitted, an empty proof is used: the release transaction signed from your own account is your authorisation, all that any kind but a custom or quorum escrow asks
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro escrow voucher`

```
Pay on a payment channel with the payer's next cumulative voucher

Usage: tenzro escrow voucher [OPTIONS] --cumulative <CUMULATIVE> <CHANNEL_ID>

Arguments:
  <CHANNEL_ID>  Channel id (the escrow id, 32-byte hex)

Options:
      --cumulative <CUMULATIVE>        The channel's cumulative total after this payment, in wei
  -v, --verbose                        Enable verbose logging
      --charge <CHARGE>                What this payment pays, in wei (the increase over the last voucher)
      --format <FORMAT>                Output format (text, json) [default: text]
      --out <OUT>                      Write the signed voucher to this file as JSON and pay nothing now
      --binding <BINDING>              The head of the receipt chain this voucher pays for (32 bytes of hex); omit for a voucher signed ahead of delivery
      --key-namespace <KEY_NAMESPACE>  The payer's hardware key namespace (a-z, 0-9, '-', '_'): the client account that funded the escrow [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

## `tenzro events`

```
Event streaming commands (subscribe, history, webhooks)

Usage: tenzro events [OPTIONS] <COMMAND>

Commands:
  subscribe  Follow the chain's events from a cursor
  history    Query a range of the chain's events, with proofs
  verify     Verify an event from genesis, as a light client
  complete   Query a range and verify from genesis that it left nothing out
  logs       Get event logs (eth_getLogs compatible)
  info       Show event streaming server info
  help       Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro events complete`

```
Query a range and verify from genesis that it left nothing out

Usage: tenzro events complete [OPTIONS] --chain-id <CHAIN_ID> --genesis-hash <GENESIS_HASH> --genesis-committee-root <GENESIS_COMMITTEE_ROOT>

Options:
      --from-height <FROM_HEIGHT>
          Start at this height
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --from-cursor <FROM_CURSOR>
          Resume after this cursor (height:tx_index:event_index)
      --to-cursor <TO_CURSOR>
          Stop at this cursor, inclusive
      --types <TYPES>
          Event types (comma-separated): log, transaction_included
      --address <ADDRESS>
          Filter logs by contract address (20-byte hex)
      --topic <TOPIC>
          Filter logs by their first topic (32-byte hex)
      --limit <LIMIT>
          Maximum events to return [default: 100]
      --chain-id <CHAIN_ID>
          Chain id
      --genesis-hash <GENESIS_HASH>
          Genesis block hash (0x-prefixed hex)
      --genesis-committee-root <GENESIS_COMMITTEE_ROOT>
          Root of the genesis committee (0x-prefixed hex), from the genesis file
      --handover-program <HANDOVER_PROGRAM>
          Image id of the handover program (0x-prefixed hex), from the chain's governance: needed once the node serves a handover chain proof
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro events history`

```
Query a range of the chain's events, with proofs

Usage: tenzro events history [OPTIONS]

Options:
      --from-height <FROM_HEIGHT>  Start at this height
  -v, --verbose                    Enable verbose logging
      --from-cursor <FROM_CURSOR>  Resume after this cursor (height:tx_index:event_index)
      --to-cursor <TO_CURSOR>      Stop at this cursor, inclusive
      --types <TYPES>              Event types (comma-separated): log, transaction_included
      --address <ADDRESS>          Filter logs by contract address (20-byte hex)
      --limit <LIMIT>              Maximum events to return [default: 100]
      --format <FORMAT>            Output format: json, compact [default: compact]
      --rpc <RPC>                  RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

### `tenzro events info`

```
Show event streaming server info

Usage: tenzro events info [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro events logs`

```
Get event logs (eth_getLogs compatible)

Usage: tenzro events logs [OPTIONS]

Options:
      --address <ADDRESS>        Contract address to filter (hex)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --topic0 <TOPIC0>          Topic[0] filter (event signature hash, hex)
      --from-block <FROM_BLOCK>  From block
      --to-block <TO_BLOCK>      To block
      --limit <LIMIT>            Maximum logs to return [default: 100]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro events subscribe`

```
Follow the chain's events from a cursor

Usage: tenzro events subscribe [OPTIONS]

Options:
      --types <TYPES>              Event types (comma-separated): log, transaction_included
  -v, --verbose                    Enable verbose logging
      --address <ADDRESS>          Filter logs by contract address (20-byte hex)
      --topic <TOPIC>              Filter logs by topic[0] (32-byte hex)
      --from-cursor <FROM_CURSOR>  Resume after this cursor (height:tx_index:event_index)
      --from-height <FROM_HEIGHT>  Start at this height (default: the current tip)
      --limit <LIMIT>              Stop after this many events (0 = follow until interrupted) [default: 0]
      --format <FORMAT>            Output format: json, compact [default: compact]
      --rpc <RPC>                  RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

### `tenzro events verify`

```
Verify an event from genesis, as a light client

Usage: tenzro events verify [OPTIONS] --chain-id <CHAIN_ID> --genesis-hash <GENESIS_HASH> --genesis-committee-root <GENESIS_COMMITTEE_ROOT> <CURSOR>

Arguments:
  <CURSOR>  The event's cursor (height:tx_index:event_index)

Options:
      --chain-id <CHAIN_ID>
          Chain id
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --genesis-hash <GENESIS_HASH>
          Genesis block hash (0x-prefixed hex)
      --genesis-committee-root <GENESIS_COMMITTEE_ROOT>
          Root of the genesis committee (0x-prefixed hex), from the genesis file
      --handover-program <HANDOVER_PROGRAM>
          Image id of the handover program (0x-prefixed hex), from the chain's governance: needed once the node serves a handover chain proof
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

## `tenzro fee-market`

```
The base fee of every resource market: compute, state growth, bandwidth, proof

Usage: tenzro fee-market [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro finality`

```
Finality: verify the latest compact certificate from genesis as a light client

Usage: tenzro finality [OPTIONS] <COMMAND>

Commands:
  verify    Verify the latest compact certificate from genesis, as a light client
  step      Write the finality step of one checkpoint: the input a finality prover turns into a STARK finality proof, the quantum-safe form every light client and settlement uses. The prover can also wrap it in a Groth16 proof over BN254 for an EVM verifier; that wrap rests on a classical assumption and is not quantum-safe
  handover  Write the handover of one epoch (bincode), as `tenzro-finality-prover handover` takes it for one link of the handover chain proof
  help      Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro finality handover`

```
Write the handover of one epoch (bincode), as `tenzro-finality-prover handover` takes it for one link of the handover chain proof

Usage: tenzro finality handover [OPTIONS] --epoch <EPOCH> --out <OUT>

Options:
      --epoch <EPOCH>    The epoch handed over
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --out <OUT>        Where to write the handover (bincode)
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro finality step`

```
Write the finality step of one checkpoint: the input a finality prover turns into a STARK finality proof, the quantum-safe form every light client and settlement uses. The prover can also wrap it in a Groth16 proof over BN254 for an EVM verifier; that wrap rests on a classical assumption and is not quantum-safe

Usage: tenzro finality step [OPTIONS] --chain-id <CHAIN_ID> --genesis-hash <GENESIS_HASH> --out <OUT>

Options:
      --index <INDEX>                Checkpoint index; the latest when omitted
  -v, --verbose                      Enable verbose logging
      --chain-id <CHAIN_ID>          Chain id
      --format <FORMAT>              Output format (text, json) [default: text]
      --genesis-hash <GENESIS_HASH>  Genesis block hash (0x-prefixed hex)
      --out <OUT>                    Where to write the step (bincode)
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro finality verify`

```
Verify the latest compact certificate from genesis, as a light client

Usage: tenzro finality verify [OPTIONS] --chain-id <CHAIN_ID> --genesis-hash <GENESIS_HASH> --genesis-committee-root <GENESIS_COMMITTEE_ROOT>

Options:
      --chain-id <CHAIN_ID>
          Chain id
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --genesis-hash <GENESIS_HASH>
          Genesis block hash (0x-prefixed hex)
      --genesis-committee-root <GENESIS_COMMITTEE_ROOT>
          Root of the genesis committee (0x-prefixed hex), from the genesis file
      --handover-program <HANDOVER_PROGRAM>
          Image id of the handover program (0x-prefixed hex), from the chain's governance: needed once the node serves a handover chain proof
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

## `tenzro forecast`

```
Timeseries forecasting (TimesFM 2.5, Chronos-2, TiRex-2, Toto 2.0)

Usage: tenzro forecast [OPTIONS] <COMMAND>

Commands:
  catalog  List the curated forecast catalog (TimesFM 2.5, Chronos-2, TiRex-2, Toto 2.0)
  load     Fetch a catalog forecaster onto this node and serve it
  unload   Unregister a previously-loaded forecaster
  run      Run a univariate forecast
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro forecast catalog`

```
List the curated forecast catalog (TimesFM 2.5, Chronos-2, TiRex-2, Toto 2.0)

Usage: tenzro forecast catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro forecast load`

```
Fetch a catalog forecaster onto this node and serve it

Usage: tenzro forecast load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro forecast run`

```
Run a univariate forecast

Usage: tenzro forecast run [OPTIONS] --model <MODEL> --horizon <HORIZON>

Options:
      --model <MODEL>
          Model id of a loaded forecaster
  -v, --verbose
          Enable verbose logging
      --context <CONTEXT>...
          Context series, most-recent-last. Comma-separated or repeated
      --format <FORMAT>
          Output format (text, json) [default: text]
      --context-file <CONTEXT_FILE>
          JSON file holding the context series as an array of numbers. Use this instead of `--context` for series too long for a command line
      --horizon <HORIZON>
          Steps ahead to predict. Must not exceed the model's max horizon
      --quantile <QUANTILES>...
          Quantile levels to return, e.g. `--quantile 0.1,0.5,0.9`
      --frequency-seconds <FREQUENCY_SECONDS>
          Sampling interval of the context series, in seconds
      --verification <VERIFICATION>
          Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>
          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro forecast unload`

```
Unregister a previously-loaded forecaster

Usage: tenzro forecast unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro funding`

```
Network funding: grant and tranche requests, reward claims, vesting release

Usage: tenzro funding [OPTIONS] <COMMAND>

Commands:
  request-grant      Request a treasury grant (optionally in tranches) for a governance vote
  request-tranche    Request the release of a grant's next tranche
  verify-milestone   Record that a scheduled grant tranche's milestone is met (a named verifier)
  release-milestone  Release a scheduled grant's next tranche against its verified milestone
  report-work        Record validator-signed settled receipts as reward work
  claim-rewards      Claim your issued reward coupons (part liquid, the rest vests)
  release-vesting    Release what your vesting schedules have accrued
  show               Show a funding proposal or grant
  help               Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro funding claim-rewards`

```
Claim your issued reward coupons (part liquid, the rest vests)

Usage: tenzro funding claim-rewards [OPTIONS]

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro funding release-milestone`

```
Release a scheduled grant's next tranche against its verified milestone

Usage: tenzro funding release-milestone [OPTIONS] --grant-id <GRANT_ID> --index <INDEX>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --grant-id <GRANT_ID>            Id of the enacted grant proposal (64 hex)
      --index <INDEX>                  Tranche index (1 is the second tranche)
      --evidence <EVIDENCE>            What was delivered, recorded with the verification (verify only) [default: ""]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro funding release-vesting`

```
Release what your vesting schedules have accrued

Usage: tenzro funding release-vesting [OPTIONS]

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro funding report-work`

```
Record validator-signed settled receipts as reward work

Usage: tenzro funding report-work [OPTIONS] --legs <LEGS>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --legs <LEGS>                    Leg ids (hex) of committed settlement plans that paid you
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro funding request-grant`

```
Request a treasury grant (optionally in tranches) for a governance vote

Usage: tenzro funding request-grant [OPTIONS] --amount <AMOUNT> --milestones <MILESTONES>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --recipient <RECIPIENT>          Who is paid (a registered identity's account); defaults to --from
      --amount <AMOUNT>                Total amount in wei
      --category <CATEGORY>            Free category label: development, research, audit, infrastructure, community, events, operators, ... [default: ""]
      --link <LINK>                    Link to the public write-up [default: ""]
      --memo <MEMO>                    Why [default: ""]
      --tranches <TRANCHES>            Tranche amounts in wei, comma separated; they must sum to --amount
      --milestones <MILESTONES>        The milestone each payment is for, one per tranche (one without tranches); separate them with a semicolon
      --vesting <VESTING>              How each payment vests: liquid, grant (6 months linear) or contributor (12-month cliff, then 36 months linear) [default: grant] [possible values: liquid, grant, contributor]
      --asset <ASSET>                  Pay in a USD stable asset instead of TNZO: its token id (0x and 64 hex). Amounts are then in the asset's smallest unit and the grant vests liquid
      --release <RELEASE>              How later tranches are released: governed (a proposal each) or scheduled (against milestones the verifiers record) [default: governed] [possible values: governed, scheduled]
      --verifiers <VERIFIERS>          Accounts that record milestones (64 hex), comma separated; with --release scheduled
      --threshold <THRESHOLD>          Distinct verifiers needed per milestone; with --release scheduled [default: 1]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro funding request-tranche`

```
Request the release of a grant's next tranche

Usage: tenzro funding request-tranche [OPTIONS] --grant-id <GRANT_ID> --index <INDEX>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --grant-id <GRANT_ID>            Id of the enacted grant proposal (64 hex)
      --index <INDEX>                  Tranche index (the next unpaid one; 1 is the second tranche)
      --memo <MEMO>                    Milestone evidence [default: ""]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro funding show`

```
Show a funding proposal or grant

Usage: tenzro funding show [OPTIONS] <KIND> <ID>

Arguments:
  <KIND>  proposal | grant [possible values: proposal, grant]
  <ID>    Proposal or grant id

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro funding verify-milestone`

```
Record that a scheduled grant tranche's milestone is met (a named verifier)

Usage: tenzro funding verify-milestone [OPTIONS] --grant-id <GRANT_ID> --index <INDEX>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --grant-id <GRANT_ID>            Id of the enacted grant proposal (64 hex)
      --index <INDEX>                  Tranche index (1 is the second tranche)
      --evidence <EVIDENCE>            What was delivered, recorded with the verification (verify only) [default: ""]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

## `tenzro governance`

```
Governance commands

Usage: tenzro governance [OPTIONS] <COMMAND>

Commands:
  decode-action                  Call tenzro_decodeAction (decode action) and print the node's answer
  list                           List proposals, newest first
  show                           Show one proposal and its tally
  propose                        Open a proposal (needs bonded stake)
  vote                           Vote on an open proposal, weighted by bonded stake
  execute                        Enact a proposal that passed, once its timelock has run
  veto                           Veto a proposal during its timelock (governance guardians, or Foundation stewards on a treasury or expedited proposal; takes effect once the guardian threshold of distinct seats of the role has signed)
  veto-signal                    Lock TNZO against a treasury, sanction or protocol upgrade proposal: past 1% of supply (governed) its timelock stretches, at 10% it is voted again on the Ratify track
  veto-withdraw                  Take back a veto lock once its proposal is decided
  concern                        Raise your human root's concern on a queued proposal; past the quorum its timelock doubles, once
  receipt                        Fetch a proposal's governance receipt (its records with state proofs under a certified checkpoint) and, with --verify, check it offline against the genesis anchor
  readiness                      Show which validators' machines have quoted a binary, against the share a protocol upgrade needs before it enacts
  upgrade-ready                  Quote the binary staged in this node's data directory (upgrade/staged) with its TPM and signal readiness from the validator account
  disclose                       Settle a security fix's vulnerability commitment: reveal the disclosure, or with no file claim the lapse past the deadline, which slashes the proposer
  pause                          Signal a pause (or with --resume a resume): a protocol guardian's holds all enactment, a Foundation steward's holds treasury and expedited enactment; takes effect at the guardian threshold
  guardians                      Show every seat, the pauses, the threshold and the steward sunset
  treasury                       Show the treasury's keyless accounts on other chains and their last grants
  voting-power                   Show the bonded stake an address votes with
  policy                         Show the last enacted change of a network policy
  economic-policy                Show the economic policy this node is applying
  params                         Show the governed network parameters: value, bounds, genesis value and any enacted change waiting for its epoch
  levers                         List every governed lever: its kind (status, switch or value), the value or status in force, its bounds and any change waiting for its epoch, plus the mode every bridge route is left in
  propose-param                  Propose changing one governed network parameter. A change that only pauses a status lever (value 1) is decided on the expedited track
  sponsored-bond                 Show the governance-sponsored part of a validator's stake and the caps
  propose-sponsor-bond           Propose bonding existing treasury TNZO on a validator's behalf
  propose-recall-sponsored-bond  Propose recalling a validator's sponsored bond to the treasury
  release-sponsored-bond         Return a validator's matured unbonding sponsored stake to the treasury
  payouts                        List every sponsorship and grant disbursement by recipient and class, the governed caps, and the approval status of one address
  propose-approve-operator       Propose approving an operator (validator or provider) for sponsorship
  propose-reinstate-validator    Propose returning a jailed validator to candidacy at the next epoch, ahead of the end of its jail term (slashing is not undone)
  propose-revoke-operator        Propose revoking an operator's approval
  propose-approve-grantee        Propose approving a grantee (developer, contributor or community)
  propose-revoke-grantee         Propose revoking a grantee's approval
  propose-operator-running-cost  Propose paying an approved operator's running cost for verified hours
  propose-operator-stable        Propose paying an approved operator's running cost in a USD stable asset
  help                           Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro governance concern`

```
Raise your human root's concern on a queued proposal; past the quorum its timelock doubles, once

Usage: tenzro governance concern [OPTIONS] <PROPOSAL_ID>

Arguments:
  <PROPOSAL_ID>  Proposal id (64 hex)

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance decode-action`

```
Call tenzro_decodeAction (decode action) and print the node's answer

Usage: tenzro governance decode-action [OPTIONS] --transaction <TRANSACTION>

Options:
      --transaction <TRANSACTION>  transaction
  -v, --verbose                    Enable verbose logging
      --format <FORMAT>            Output format (text, json) [default: text]
      --rpc <RPC>                  RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

### `tenzro governance disclose`

```
Settle a security fix's vulnerability commitment: reveal the disclosure, or with no file claim the lapse past the deadline, which slashes the proposer

Usage: tenzro governance disclose [OPTIONS] <PROPOSAL_ID>

Arguments:
  <PROPOSAL_ID>  Proposal id (64 hex)

Options:
      --file <FILE>                    File holding the disclosure; omit to claim the lapse
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance economic-policy`

```
Show the economic policy this node is applying

Usage: tenzro governance economic-policy [OPTIONS]

Options:
      --json             Emit the raw JSON the node returned
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro governance execute`

```
Enact a proposal that passed, once its timelock has run

Usage: tenzro governance execute [OPTIONS] <PROPOSAL_ID>

Arguments:
  <PROPOSAL_ID>  Proposal id (64 hex)

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance guardians`

```
Show every seat, the pauses, the threshold and the steward sunset

Usage: tenzro governance guardians [OPTIONS]

Options:
      --address <ADDRESS>  Account whose guardian seat to show (hex)
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro governance levers`

```
List every governed lever: its kind (status, switch or value), the value or status in force, its bounds and any change waiting for its epoch, plus the mode every bridge route is left in

Usage: tenzro governance levers [OPTIONS]

Options:
      --area <AREA>      Only the levers of one area, the first part of their key (`bridge`, `roles`, `zk`, `fees`, ...)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --json             Emit the raw JSON the node returned
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro governance list`

```
List proposals, newest first

Usage: tenzro governance list [OPTIONS]

Options:
      --kind <KIND>      Keep only one action kind (policy_update, parameter_change, treasury_grant, ...)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --limit <LIMIT>    How many to show (1-100) [default: 20]
      --before <BEFORE>  Continue from a previous page's `next`
      --json             Emit the raw JSON
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro governance params`

```
Show the governed network parameters: value, bounds, genesis value and any enacted change waiting for its epoch

Usage: tenzro governance params [OPTIONS]

Options:
      --key <KEY>        Show one parameter only
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --json             Emit the raw JSON the node returned
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro governance pause`

```
Signal a pause (or with --resume a resume): a protocol guardian's holds all enactment, a Foundation steward's holds treasury and expedited enactment; takes effect at the guardian threshold

Usage: tenzro governance pause [OPTIONS]

Options:
      --resume                         Signal a resume instead of a pause
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the protocol guardian or Foundation steward account signing [default: client]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance payouts`

```
List every sponsorship and grant disbursement by recipient and class, the governed caps, and the approval status of one address

Usage: tenzro governance payouts [OPTIONS]

Options:
      --address <ADDRESS>  Address (hex) to show the approval status of
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --offset <OFFSET>    Disbursements to skip [default: 0]
      --limit <LIMIT>      Most disbursements to show [default: 100]
      --rpc <RPC>          [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro governance policy`

```
Show the last enacted change of a network policy

Usage: tenzro governance policy [OPTIONS] <KIND>

Arguments:
  <KIND>  economic_policy | adaptive_burn_config | supply_targets | protocol_upgrade [possible values: economic_policy, adaptive_burn_config, supply_targets, protocol_upgrade]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro governance propose`

```
Open a proposal (needs bonded stake)

Usage: tenzro governance propose [OPTIONS]

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account; with --node-account, the node's `hardware_key_namespace` (omit for the machine's default node)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --node-account                   Propose from this machine's node account, the validator account its genesis entry or registration bonded, instead of a client account
      --action <ACTION>                The proposal action as JSON, tagged by "action", e.g. '{"action":"parameter_change","key":"...","value":1,"memo":"..."}' or '{"action":"policy_update","update":{...},"memo":"...","track":{"kind":"standard"}}'; a security fix is '"track":{"kind":"security_fix","basis":{"kind":"vulnerability","commitment":"<hex sha256>"}}'
      --file <FILE>                    Read the proposal action from a JSON file
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance propose-approve-grantee`

```
Propose approving a grantee (developer, contributor or community)

Usage: tenzro governance propose-approve-grantee [OPTIONS] --grantee <GRANTEE> --class <CLASS> --summary <SUMMARY> --memo <MEMO>

Options:
      --grantee <GRANTEE>              Grantee account (64 hex)
  -v, --verbose                        Enable verbose logging
      --class <CLASS>                  developer, contributor or community [possible values: developer, contributor, community]
      --format <FORMAT>                Output format (text, json) [default: text]
      --summary <SUMMARY>              What the grantee builds or does
      --link <LINK>                    Link to the public statement of the criteria [default: ""]
      --memo <MEMO>                    Why, shown to voters
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account
      --node-account                   Propose from this machine's node account
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance propose-approve-operator`

```
Propose approving an operator (validator or provider) for sponsorship

Usage: tenzro governance propose-approve-operator [OPTIONS] --operator <OPERATOR> --class <CLASS> --provider-did <PROVIDER_DID> --region <REGION> --history-from-epoch <HISTORY_FROM_EPOCH> --history-to-epoch <HISTORY_TO_EPOCH> --independence <INDEPENDENCE> --memo <MEMO>

Options:
      --operator <OPERATOR>
          Operator account (64 hex)
  -v, --verbose
          Enable verbose logging
      --class <CLASS>
          validator or provider [possible values: validator, provider]
      --format <FORMAT>
          Output format (text, json) [default: text]
      --provider-did <PROVIDER_DID>
          The operator's machine identity (did:tenzro:machine:...)
      --region <REGION>
          Where the operator runs
      --history-from-epoch <HISTORY_FROM_EPOCH>
          First hourly epoch of the availability history counted
      --history-to-epoch <HISTORY_TO_EPOCH>
          Last hourly epoch of the availability history counted
      --independence <INDEPENDENCE>
          The operator's independence declaration, or a link to it
      --link <LINK>
          Link to the public statement of the criteria [default: ""]
      --memo <MEMO>
          Why, shown to voters
      --key-namespace <KEY_NAMESPACE>
          Hardware key namespace of the signing account
      --node-account
          Propose from this machine's node account
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro governance propose-operator-running-cost`

```
Propose paying an approved operator's running cost for verified hours

Usage: tenzro governance propose-operator-running-cost [OPTIONS] --operator <OPERATOR> --from-epoch <FROM_EPOCH> --to-epoch <TO_EPOCH> --amount <AMOUNT> --memo <MEMO>

Options:
      --operator <OPERATOR>            Approved operator account (64 hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --from-epoch <FROM_EPOCH>        First hourly epoch claimed
      --to-epoch <TO_EPOCH>            Last hourly epoch claimed
      --amount <AMOUNT>                Amount, smallest unit
      --memo <MEMO>                    Why, shown to voters
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account
      --node-account                   Propose from this machine's node account
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance propose-operator-stable`

```
Propose paying an approved operator's running cost in a USD stable asset

Usage: tenzro governance propose-operator-stable [OPTIONS] --operator <OPERATOR> --from-epoch <FROM_EPOCH> --to-epoch <TO_EPOCH> --token-id <TOKEN_ID> --amount <AMOUNT> --memo <MEMO>

Options:
      --operator <OPERATOR>            Approved operator account (64 hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --from-epoch <FROM_EPOCH>        First hourly epoch claimed
      --to-epoch <TO_EPOCH>            Last hourly epoch claimed
      --token-id <TOKEN_ID>            The settlement asset: its token id (0x and 64 hex)
      --amount <AMOUNT>                Amount, the asset's smallest unit
      --period-exception               Use the governed per-payment headroom above the period limit
      --memo <MEMO>                    Why, shown to voters
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account
      --node-account                   Propose from this machine's node account
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance propose-param`

```
Propose changing one governed network parameter. A change that only pauses a status lever (value 1) is decided on the expedited track

Usage: tenzro governance propose-param [OPTIONS] --key <KEY> --value <VALUE> --memo <MEMO>

Options:
      --key <KEY>                      Parameter key, as `tenzro governance params` lists it
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --value <VALUE>                  The proposed value
      --memo <MEMO>                    Why, shown to voters
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account
      --node-account                   Propose from this machine's node account
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance propose-recall-sponsored-bond`

```
Propose recalling a validator's sponsored bond to the treasury

Usage: tenzro governance propose-recall-sponsored-bond [OPTIONS] --validator <VALIDATOR> --amount <AMOUNT> --memo <MEMO>

Options:
  -v, --verbose                        Enable verbose logging
      --validator <VALIDATOR>          Validator address (64 hex)
      --amount <AMOUNT>                Amount, smallest unit
      --format <FORMAT>                Output format (text, json) [default: text]
      --memo <MEMO>                    Why, shown to voters
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account
      --node-account                   Propose from this machine's node account
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance propose-reinstate-validator`

```
Propose returning a jailed validator to candidacy at the next epoch, ahead of the end of its jail term (slashing is not undone)

Usage: tenzro governance propose-reinstate-validator [OPTIONS] --account <ACCOUNT> --memo <MEMO>

Options:
      --account <ACCOUNT>              Account (64 hex): the operator, grantee or jailed validator
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --memo <MEMO>                    Why, shown to voters
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account
      --node-account                   Propose from this machine's node account
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance propose-revoke-grantee`

```
Propose revoking a grantee's approval

Usage: tenzro governance propose-revoke-grantee [OPTIONS] --account <ACCOUNT> --memo <MEMO>

Options:
      --account <ACCOUNT>              Account (64 hex): the operator, grantee or jailed validator
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --memo <MEMO>                    Why, shown to voters
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account
      --node-account                   Propose from this machine's node account
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance propose-revoke-operator`

```
Propose revoking an operator's approval

Usage: tenzro governance propose-revoke-operator [OPTIONS] --account <ACCOUNT> --memo <MEMO>

Options:
      --account <ACCOUNT>              Account (64 hex): the operator, grantee or jailed validator
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --memo <MEMO>                    Why, shown to voters
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account
      --node-account                   Propose from this machine's node account
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance propose-sponsor-bond`

```
Propose bonding existing treasury TNZO on a validator's behalf

Usage: tenzro governance propose-sponsor-bond [OPTIONS] --validator <VALIDATOR> --amount <AMOUNT> --memo <MEMO>

Options:
  -v, --verbose                        Enable verbose logging
      --validator <VALIDATOR>          Validator address (64 hex)
      --amount <AMOUNT>                Amount, smallest unit
      --format <FORMAT>                Output format (text, json) [default: text]
      --memo <MEMO>                    Why, shown to voters
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account
      --node-account                   Propose from this machine's node account
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance readiness`

```
Show which validators' machines have quoted a binary, against the share a protocol upgrade needs before it enacts

Usage: tenzro governance readiness [OPTIONS] <CODE_HASH>

Arguments:
  <CODE_HASH>  Hex SHA-256 of the binary

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro governance receipt`

```
Fetch a proposal's governance receipt (its records with state proofs under a certified checkpoint) and, with --verify, check it offline against the genesis anchor

Usage: tenzro governance receipt [OPTIONS] <PROPOSAL_ID>

Arguments:
  <PROPOSAL_ID>  Proposal id (64 hex)

Options:
      --file <FILE>
          Read the receipt from this file instead of the node
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --out <OUT>
          Write the receipt fetched from the node to this file
      --verify
          Verify it offline against the genesis anchor
      --chain-id <CHAIN_ID>
          Chain id, from the genesis file
      --genesis-hash <GENESIS_HASH>
          Genesis block hash, hex
      --genesis-committee-root <GENESIS_COMMITTEE_ROOT>
          Root of the genesis committee, hex
      --handover-program <HANDOVER_PROGRAM>
          Image id of the handover program, hex, from the chain's governance: needed when the receipt's checkpoint is certified from a handover chain proof
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro governance release-sponsored-bond`

```
Return a validator's matured unbonding sponsored stake to the treasury

Usage: tenzro governance release-sponsored-bond [OPTIONS] <VALIDATOR>

Arguments:
  <VALIDATOR>  Validator address (64 hex)

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance show`

```
Show one proposal and its tally

Usage: tenzro governance show [OPTIONS] <PROPOSAL_ID>

Arguments:
  <PROPOSAL_ID>  Proposal id (64 hex)

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro governance sponsored-bond`

```
Show the governance-sponsored part of a validator's stake and the caps

Usage: tenzro governance sponsored-bond [OPTIONS] <ADDRESS>

Arguments:
  <ADDRESS>  Validator address (hex)

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro governance treasury`

```
Show the treasury's keyless accounts on other chains and their last grants

Usage: tenzro governance treasury [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro governance upgrade-ready`

```
Quote the binary staged in this node's data directory (upgrade/staged) with its TPM and signal readiness from the validator account

Usage: tenzro governance upgrade-ready [OPTIONS] <CODE_HASH>

Arguments:
  <CODE_HASH>  Hex SHA-256 of the binary the protocol upgrade names

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro governance veto`

```
Veto a proposal during its timelock (governance guardians, or Foundation stewards on a treasury or expedited proposal; takes effect once the guardian threshold of distinct seats of the role has signed)

Usage: tenzro governance veto [OPTIONS] <PROPOSAL_ID>

Arguments:
  <PROPOSAL_ID>  Proposal id (64 hex)

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance veto-signal`

```
Lock TNZO against a treasury, sanction or protocol upgrade proposal: past 1% of supply (governed) its timelock stretches, at 10% it is voted again on the Ratify track

Usage: tenzro governance veto-signal [OPTIONS] <PROPOSAL_ID> <AMOUNT>

Arguments:
  <PROPOSAL_ID>  Proposal id (64 hex)
  <AMOUNT>       TNZO to lock, in base units; it returns in full once the proposal is decided

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance veto-withdraw`

```
Take back a veto lock once its proposal is decided

Usage: tenzro governance veto-withdraw [OPTIONS] <PROPOSAL_ID>

Arguments:
  <PROPOSAL_ID>  Proposal id (64 hex)

Options:
      --holder <HOLDER>                The account that locked it (64 hex); defaults to the signing account
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance vote`

```
Vote on an open proposal, weighted by bonded stake

Usage: tenzro governance vote [OPTIONS] --validator <VALIDATOR> <PROPOSAL_ID>

Arguments:
  <PROPOSAL_ID>  Proposal id (64 hex)

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace: the signing client account's (default `client`), or with --machine-root the node's `hardware_key_namespace` (default: the machine's default node)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --validator <VALIDATOR>          Validator account whose bond the ballot carries (64 hex). The ballot is cast by the validator's root: its operator's passkey identity signs it, or, with --machine-root, the autonomous machine that is the validator approves it
      --machine-root                   Cast the ballot as the validator's machine root: this machine's identity key (the key its machine DID derives from) approves it and the node account submits it. For a validator whose identity is this autonomous machine
      --yes                            Vote yes
      --no                             Vote no
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro governance voting-power`

```
Show the bonded stake an address votes with

Usage: tenzro governance voting-power [OPTIONS] <ADDRESS>

Arguments:
  <ADDRESS>  Account address (hex)

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro hardware`

```
Show hardware profile

Usage: tenzro hardware [OPTIONS]

Options:
      --format <FORMAT>  Output format (text, json) [default: text]
  -v, --verbose          Enable verbose logging
  -h, --help             Print help
```

## `tenzro identity`

```
Identity management commands (TDIP)

Usage: tenzro identity [OPTIONS] <COMMAND>

Commands:
  verify-envelope        Call tenzro_verifyDidEnvelope (verify did envelope) and print the node's answer
  verify-kya-credential  Call tenzro_verifyKyaCredential (verify kya credential) and print the node's answer
  verify-did-document    Call tenzro_verifyNodeDidDocument (verify node did document) and print the node's answer
  delegation7702         Call tenzro_get7702Delegation (get7702 delegation) and print the node's answer
  issue-kya-credential   Call tenzro_issueKyaCredential (issue kya credential) and print the node's answer
  update                 Add a resource to a DID (tenzro_updateIdentity, operator only)
  service                Publish or remove a service entry of a machine DID's document, approved by the machine's identity key (an IdentityServices transaction)
  services               Show the service entries of a DID's document from consensus state (tenzro_getDidServices)
  rotate-to-pq           Hand the identity to a hardware ML-DSA-65 key (tenzro_rotateIdentityToPq)
  register               Register a new TDIP identity
  resolve                Resolve a DID to its identity or W3C DID Document
  list                   List locally known identities
  document               Show W3C DID Document for a DID
  resolve-did            Resolve a DID to identity info (alias for resolve)
  resolve-document       Resolve a DID to its W3C DID Document
  register-machine       Register a new machine identity
  revoke                 Revoke an identity on its root's authority (a RevokeIdentity transaction)
  revoke-jwt             Revoke a single JWT by its `jti` (cascades through the act-chain)
  forget                 Hard-delete a revoked identity (TDIP/GDPR Article 17 right-to-erasure)
  help                   Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro identity delegation7702`

```
Call tenzro_get7702Delegation (get7702 delegation) and print the node's answer

Usage: tenzro identity delegation7702 [OPTIONS] --authority <AUTHORITY>

Options:
      --authority <AUTHORITY>  authority
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro identity document`

```
Show W3C DID Document for a DID

Usage: tenzro identity document [OPTIONS] <DID>

Arguments:
  <DID>  The DID to get the document for

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro identity forget`

```
Hard-delete a revoked identity (TDIP/GDPR Article 17 right-to-erasure)

Usage: tenzro identity forget [OPTIONS] <DID>

Arguments:
  <DID>  The DID to erase. Must already be in `Revoked` status

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro identity issue-kya-credential`

```
Call tenzro_issueKyaCredential (issue kya credential) and print the node's answer

Usage: tenzro identity issue-kya-credential [OPTIONS] --did <DID>

Options:
      --did <DID>                      did
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --validity-secs <VALIDITY_SECS>  validity secs
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro identity list`

```
List locally known identities

Usage: tenzro identity list [OPTIONS]

Options:
      --identity-type <IDENTITY_TYPE>  Filter by type: human, machine, or all [default: all]
  -v, --verbose                        Enable verbose logging
      --detailed                       Show detailed information
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: https://rpc.tenzro.com]
  -h, --help                           Print help
```

### `tenzro identity register`

```
Register a new TDIP identity

Usage: tenzro identity register [OPTIONS] --name <NAME>

Options:
      --name <NAME>                    Display name for the identity
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --identity-type <IDENTITY_TYPE>  Identity type: human or machine [default: human]
      --controller <CONTROLLER>        Controller DID (required for machine identities; it signs the registration)
      --public-key <PUBLIC_KEY>        Machine P-256 public key, hex x || y from its TPM or Secure Enclave
      --capabilities <CAPABILITIES>    Machine capabilities, comma-separated
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the controller account that signs a machine registration [default: client]
      --rpc <RPC>                      RPC endpoint [default: https://rpc.tenzro.com]
  -h, --help                           Print help
```

### `tenzro identity register-machine`

```
Register a new machine identity

Usage: tenzro identity register-machine [OPTIONS]

Options:
      --controller <CONTROLLER>      Controller DID: who the machine acts for and who signs the request
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --public-key <PUBLIC_KEY>      The machine's public key (hex), from its TPM or Secure Enclave
      --capabilities <CAPABILITIES>  Capabilities (comma-separated)
      --request-out <REQUEST_OUT>    Write the prepared request here and print the `params_hash` to sign
      --request-in <REQUEST_IN>      Send a request prepared with `--request-out`
      --did-envelope <DID_ENVELOPE>  Hex DID envelope by the controller over the prepared request
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro identity resolve`

```
Resolve a DID to its identity or W3C DID Document

Usage: tenzro identity resolve [OPTIONS] <DID>

Arguments:
  <DID>  The DID to resolve (e.g. did:tenzro:human:abc123)

Options:
      --rpc <RPC>        RPC endpoint [default: https://rpc.tenzro.com]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro identity resolve-did`

```
Resolve a DID to identity info (alias for resolve)

Usage: tenzro identity resolve-did [OPTIONS] <DID>

Arguments:
  <DID>  DID to resolve

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro identity resolve-document`

```
Resolve a DID to its W3C DID Document

Usage: tenzro identity resolve-document [OPTIONS] <DID>

Arguments:
  <DID>  DID to resolve

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro identity revoke`

```
Revoke an identity on its root's authority (a RevokeIdentity transaction)

Usage: tenzro identity revoke [OPTIONS] --approval <APPROVAL> <DID>

Arguments:
  <DID>  The DID to revoke

Options:
      --reason <REASON>                Reason recorded with the revocation; the approval covers it, so it must be the reason the challenge was issued for
  -v, --verbose                        Enable verbose logging
      --approver <APPROVER>            The approving root's DID; the DID itself when absent
      --format <FORMAT>                Output format (text, json) [default: text]
      --approval <APPROVAL>            JSON file with the approving root's approval of the challenge
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the account that sends the transaction [default: client]
      --gas-limit <GAS_LIMIT>          Gas for the transaction; a root with many agents needs more [default: 1000000]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro identity revoke-jwt`

```
Revoke a single JWT by its `jti` (cascades through the act-chain)

Usage: tenzro identity revoke-jwt [OPTIONS] --did-envelope <DID_ENVELOPE> <JTI>

Arguments:
  <JTI>  The JWT id (`jti`) to revoke

Options:
      --reason <REASON>              Optional reason for revocation (recorded in the audit log)
  -v, --verbose                      Enable verbose logging
      --did-envelope <DID_ENVELOPE>  Hex DID envelope proving control of the token's bearer DID or of the controller DID that authorized it. Must be bound to method `tenzro_revokeJwt` with the jti as the params hash
      --format <FORMAT>              Output format (text, json) [default: text]
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro identity rotate-to-pq`

```
Hand the identity to a hardware ML-DSA-65 key (tenzro_rotateIdentityToPq)

Usage: tenzro identity rotate-to-pq [OPTIONS] --did <DID>

Options:
      --did <DID>                      The DID to rotate
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --sequence <SEQUENCE>            The rotation's sequence number: one more than the last rotation (1 for the first) [default: 1]
      --key-namespace <KEY_NAMESPACE>  The hardware key namespace of the signing account [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro identity service`

```
Publish or remove a service entry of a machine DID's document, approved by the machine's identity key (an IdentityServices transaction)

Usage: tenzro identity service [OPTIONS] --did <DID> --id <ID>

Options:
      --did <DID>
          The machine DID whose document changes
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --id <ID>
          The service id fragment (`<did>#<id>`)
      --service-type <SERVICE_TYPE>
          The service type, for example LinkedDomains; required unless --remove
      --endpoint <ENDPOINT>
          The service endpoint URL; required unless --remove
      --remove
          Remove the entry instead of publishing it
      --machine-namespace <MACHINE_NAMESPACE>
          The machine's node key namespace (its identity key); the default node when omitted
      --key-namespace <KEY_NAMESPACE>
          The hardware key namespace of the account that sends and pays [default: client]
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro identity services`

```
Show the service entries of a DID's document from consensus state (tenzro_getDidServices)

Usage: tenzro identity services [OPTIONS] <DID>

Arguments:
  <DID>  The DID

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro identity update`

```
Add a resource to a DID (tenzro_updateIdentity, operator only)

Usage: tenzro identity update [OPTIONS] --did <DID> --update <UPDATE>

Options:
      --did <DID>        The DID to update
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --update <UPDATE>  The update (JSON) with its `kind`: `{"kind":"resource","resource_type":..,"resource_id":..}`
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro identity verify-did-document`

```
Call tenzro_verifyNodeDidDocument (verify node did document) and print the node's answer

Usage: tenzro identity verify-did-document [OPTIONS] --document <DOCUMENT>

Options:
      --document <DOCUMENT>  document (JSON)
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --id <ID>              id
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro identity verify-envelope`

```
Call tenzro_verifyDidEnvelope (verify did envelope) and print the node's answer

Usage: tenzro identity verify-envelope [OPTIONS] --envelope <ENVELOPE>

Options:
      --envelope <ENVELOPE>  envelope (JSON)
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro identity verify-kya-credential`

```
Call tenzro_verifyKyaCredential (verify kya credential) and print the node's answer

Usage: tenzro identity verify-kya-credential [OPTIONS] --credential <CREDENTIAL>

Options:
      --credential <CREDENTIAL>  credential (JSON)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

## `tenzro inference`

```
Inference commands

Usage: tenzro inference [OPTIONS] <COMMAND>

Commands:
  generation           Call tenzro_getGeneration (get generation) and print the node's answer
  usage                Call tenzro_listInferenceUsage (list inference usage) and print the node's answer
  audit-challenge      Call tenzro_auditInferenceChallenge (audit inference challenge) and print the node's answer
  verify-receipt       Call tenzro_verifyInferenceReceipt (verify inference receipt) and print the node's answer
  prefix-probe         Call tenzro_prefixProbe (prefix probe) and print the node's answer
  moe-route            Call tenzro_moeRoute (moe route) and print the node's answer
  moe-execute          Call tenzro_moeExecute (moe execute) and print the node's answer
  moe-dispute-receipt  Re-execute a stored expert receipt and dispute it if it does not match (tenzro_moeDisputeReceipt)
  standby-quote        Live operators holding a model on standby in a jurisdiction, cheapest first, with the account a reservation escrow must pay and the hourly fee each one advertises (tenzro_standbyQuote)
  request              Submit an inference request
  sponsored            Run a short inference a sponsoring agent pays for, on a node that offers it
  router-metrics       Read the inference router's live metrics (requests routed, hedges dispatched, hedges won, deadline-exceeded requests)
  get-commitment       Fetch a stored TOPLOC inference commitment by hash
  verify-commitment    Re-execute a prompt against a stored commitment and report the per-step verification outcome
  file-challenge       File a challenge against a stored inference commitment
  get-challenge        Fetch an inference challenge by id
  list-challenges      List inference challenges, optionally filtered by status or provider
  commit-vote          Commit a committee vote (hidden) on an inference challenge
  reveal-vote          Reveal a previously committed committee vote
  finalize-challenge   Finalize an inference challenge by tallying revealed committee votes. Upheld verdicts decrement the provider's reputation and record a compute-bond failure
  route                Select a model for an intent (use case + budget + quality floor + cost-quality knob) without naming one. Discovery only — dispatches nothing. With `--message`, discovers and runs in one call
  record-outcome       Report how a routed call turned out, so the router's per-cluster error rates reflect what happened rather than only what the catalog declares
  difficulty-stats     Read the node's difficulty index: cluster sizes, and per-cluster outcome counters for a model when one is named
  help                 Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro inference audit-challenge`

```
Call tenzro_auditInferenceChallenge (audit inference challenge) and print the node's answer

Usage: tenzro inference audit-challenge [OPTIONS] --challenge-id <CHALLENGE_ID>

Options:
      --challenge-id <CHALLENGE_ID>  challenge id
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro inference commit-vote`

```
Commit a committee vote (hidden) on an inference challenge

Usage: tenzro inference commit-vote [OPTIONS] --commit-hash <COMMIT_HASH> <CHALLENGE_ID>

Arguments:
  <CHALLENGE_ID>  Challenge id (UUID)

Options:
      --commit-hash <COMMIT_HASH>  Vote commitment hash (hex)
  -v, --verbose                    Enable verbose logging
      --voter-rpc <VOTER_RPC>      The voting validator's own node, which signs the commit [default: http://127.0.0.1:8545]
      --format <FORMAT>            Output format (text, json) [default: text]
      --rpc <RPC>                  RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

### `tenzro inference difficulty-stats`

```
Read the node's difficulty index: cluster sizes, and per-cluster outcome counters for a model when one is named

Usage: tenzro inference difficulty-stats [OPTIONS]

Options:
      --model-id <MODEL_ID>  Report per-cluster outcome counters and error rate for this model
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro inference file-challenge`

```
File a challenge against a stored inference commitment

Usage: tenzro inference file-challenge [OPTIONS] <COMMITMENT_HASH> <CHALLENGER>

Arguments:
  <COMMITMENT_HASH>  Commitment hash being disputed (hex, with or without 0x prefix)
  <CHALLENGER>       Challenger identity (DID or address)

Options:
      --reason <REASON>  Optional free-text reason for the dispute
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro inference finalize-challenge`

```
Finalize an inference challenge by tallying revealed committee votes. Upheld verdicts decrement the provider's reputation and record a compute-bond failure

Usage: tenzro inference finalize-challenge [OPTIONS] <CHALLENGE_ID>

Arguments:
  <CHALLENGE_ID>  Challenge id (UUID)

Options:
      --format <FORMAT>  Output format (text, json) [default: text]
  -v, --verbose          Enable verbose logging
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro inference generation`

```
Call tenzro_getGeneration (get generation) and print the node's answer

Usage: tenzro inference generation [OPTIONS] --id <ID>

Options:
      --id <ID>          id
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro inference get-challenge`

```
Fetch an inference challenge by id

Usage: tenzro inference get-challenge [OPTIONS] <CHALLENGE_ID>

Arguments:
  <CHALLENGE_ID>  Challenge id (UUID)

Options:
      --format <FORMAT>  Output format (text, json) [default: text]
  -v, --verbose          Enable verbose logging
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro inference get-commitment`

```
Fetch a stored TOPLOC inference commitment by hash

Usage: tenzro inference get-commitment [OPTIONS] <COMMITMENT_HASH>

Arguments:
  <COMMITMENT_HASH>  Commitment hash (hex, with or without 0x prefix)

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro inference list-challenges`

```
List inference challenges, optionally filtered by status or provider

Usage: tenzro inference list-challenges [OPTIONS]

Options:
      --status <STATUS>      Filter by status (voting_commit, voting_reveal, upheld, dismissed)
  -v, --verbose              Enable verbose logging
      --provider <PROVIDER>  Filter by provider (announce-signer pubkey hex)
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro inference moe-dispute-receipt`

```
Re-execute a stored expert receipt and dispute it if it does not match (tenzro_moeDisputeReceipt)

Usage: tenzro inference moe-dispute-receipt [OPTIONS] --key <KEY>

Options:
      --key <KEY>        Storage key of the receipt
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro inference moe-execute`

```
Call tenzro_moeExecute (moe execute) and print the node's answer

Usage: tenzro inference moe-execute [OPTIONS] --request <REQUEST>

Options:
      --request <REQUEST>  request (JSON)
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro inference moe-route`

```
Call tenzro_moeRoute (moe route) and print the node's answer

Usage: tenzro inference moe-route [OPTIONS] --model-id <MODEL_ID> --hidden-states <HIDDEN_STATES>

Options:
      --model-id <MODEL_ID>            model id
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --hidden-states <HIDDEN_STATES>  hidden states (JSON)
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro inference prefix-probe`

```
Call tenzro_prefixProbe (prefix probe) and print the node's answer

Usage: tenzro inference prefix-probe [OPTIONS]

Options:
      --digests <DIGESTS>  digests
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro inference record-outcome`

```
Report how a routed call turned out, so the router's per-cluster error rates reflect what happened rather than only what the catalog declares

Usage: tenzro inference record-outcome [OPTIONS] --model-id <MODEL_ID> --cluster <CLUSTER> --outcome <OUTCOME>

Options:
      --model-id <MODEL_ID>  The model that served the call — the routing decision's model_id
  -v, --verbose              Enable verbose logging
      --cluster <CLUSTER>    The difficulty cluster the request landed in — the routing decision's `cluster`
      --outcome <OUTCOME>    How the call turned out: resolved, escalated, or failed
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro inference request`

```
Submit an inference request

Usage: tenzro inference request [OPTIONS] <MODEL_ID> <INPUT>

Arguments:
  <MODEL_ID>  Model ID to use
  <INPUT>     Input text, file path, or URL

Options:
      --max-price <MAX_PRICE>        Maximum price willing to pay (TNZO) [default: 1.0]
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --verification <VERIFICATION>  Verification the answer must carry: none, receipt, optimistic or tee [default: none] [possible values: none, receipt, optimistic, tee]
      --temperature <TEMPERATURE>    Temperature (0.0-2.0, for text models)
      --max-tokens <MAX_TOKENS>      Maximum output tokens (for text models)
      --output-file <OUTPUT_FILE>    Save output to file
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro inference reveal-vote`

```
Reveal a previously committed committee vote

Usage: tenzro inference reveal-vote [OPTIONS] --salt <SALT> <CHALLENGE_ID>

Arguments:
  <CHALLENGE_ID>  Challenge id (UUID)

Options:
  -v, --verbose                Enable verbose logging
      --voter-rpc <VOTER_RPC>  The voting validator's own node, which signs the reveal [default: http://127.0.0.1:8545]
      --verdict                Revealed verdict (true = did-not-verify / upholds)
      --salt <SALT>            Reveal salt (hex) — must reproduce the earlier commit hash
      --format <FORMAT>        Output format (text, json) [default: text]
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro inference route`

```
Select a model for an intent (use case + budget + quality floor + cost-quality knob) without naming one. Discovery only — dispatches nothing. With `--message`, discovers and runs in one call

Usage: tenzro inference route [OPTIONS] --use-case <USE_CASE>

Options:
      --use-case <USE_CASE>
          Use case: chat, code, reasoning, summarize, extract, or embed
  -v, --verbose
          Enable verbose logging
      --budget <BUDGET>
          Per-request cost cap in smallest TNZO unit (decimal string)
      --optimize <OPTIMIZE>
          Cost-quality knob in [0.0, 1.0]: 0.0 cheapest acceptable, 1.0 strongest
      --quality-floor <QUALITY_FLOOR>
          Reject any model below this tier: cheap or strong
      --est-input-tokens <EST_INPUT_TOKENS>
          Estimated input tokens for cost estimation
      --est-output-tokens <EST_OUTPUT_TOKENS>
          Estimated output tokens for cost estimation
      --payer-did <PAYER_DID>
          Payer DID — enables the per-DID rolling-window budget gate
      --payer-address <PAYER_ADDRESS>
          Payer wallet address (hex) — the payer's on-chain TNZO balance becomes a hard ceiling, so unaffordable models are dropped
      --prompt <PROMPT>
          Text the model would answer. Used only to place the request in a difficulty cluster, so selection accounts for how hard the prompt is; it is not sent to any provider. Redundant with --message, which the node reads for the same purpose
      --message <MESSAGE>
          When set, discover a model and run this prompt in one call
      --max-tokens <MAX_TOKENS>
          Maximum output tokens (only used with --message) [default: 256]
      --jurisdiction <JURISDICTION>
          Comma-separated jurisdiction pin: ISO 3166-1 alpha-2 country codes and/or bloc tokens (e.g. "DE,EU"), case-insensitive. The serving node must declare a matching attestation-bound locality claim or the request is refused. Only used with --message
      --require-jurisdiction-receipt
          Fail the request unless the response carries a verifiable signed jurisdiction receipt. Only used with --message
      --format <FORMAT>
          Output format (text, json) [default: text]
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro inference router-metrics`

```
Read the inference router's live metrics (requests routed, hedges dispatched, hedges won, deadline-exceeded requests)

Usage: tenzro inference router-metrics [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro inference sponsored`

```
Run a short inference a sponsoring agent pays for, on a node that offers it

Usage: tenzro inference sponsored [OPTIONS] --model <MODEL> --sponsor <SPONSOR> <INPUT>

Arguments:
  <INPUT>  Prompt (at most 4096 bytes)

Options:
      --model <MODEL>            Model id
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --sponsor <SPONSOR>        The sponsoring agent's DID
      --max-tokens <MAX_TOKENS>  Most output tokens (up to the node's cap)
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro inference standby-quote`

```
Live operators holding a model on standby in a jurisdiction, cheapest first, with the account a reservation escrow must pay and the hourly fee each one advertises (tenzro_standbyQuote)

Usage: tenzro inference standby-quote [OPTIONS] --model-id <MODEL_ID> --jurisdiction <JURISDICTION>

Options:
      --model-id <MODEL_ID>          The model the standby holder must have staged
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --jurisdiction <JURISDICTION>  The jurisdiction the session is pinned to (an operator outside it can never succeed the session)
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro inference usage`

```
Call tenzro_listInferenceUsage (list inference usage) and print the node's answer

Usage: tenzro inference usage [OPTIONS]

Options:
      --model-id <MODEL_ID>  model id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --provider <PROVIDER>  provider
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro inference verify-commitment`

```
Re-execute a prompt against a stored commitment and report the per-step verification outcome

Usage: tenzro inference verify-commitment [OPTIONS] <COMMITMENT_HASH> <PROMPT>

Arguments:
  <COMMITMENT_HASH>  Commitment hash (hex, with or without 0x prefix)
  <PROMPT>           The exact prompt the committed response was generated from

Options:
      --format <FORMAT>  Output format (text, json) [default: text]
  -v, --verbose          Enable verbose logging
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro inference verify-receipt`

```
Call tenzro_verifyInferenceReceipt (verify inference receipt) and print the node's answer

Usage: tenzro inference verify-receipt [OPTIONS] --level <LEVEL> --receipt <RECEIPT>

Options:
      --level <LEVEL>      level
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --receipt <RECEIPT>  receipt (JSON)
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

## `tenzro info`

```
Show network information

Usage: tenzro info [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint to query [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro insurance`

```
The network insurance pool: claim, list, get, pool

Usage: tenzro insurance [OPTIONS] <COMMAND>

Commands:
  claim  Claim from the pool on a reconciliation mismatch that names you
  list   List every paid claim (read-only)
  get    Inspect a paid claim by id (read-only)
  pool   Show the pool's balance, history and claim cap (read-only)
  help   Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro insurance claim`

```
Claim from the pool on a reconciliation mismatch that names you

Usage: tenzro insurance claim [OPTIONS]

Options:
      --recon-adapter <RECON_ADAPTER>
          Bridge protocol of a route whose settlement lock mismatch cost you a leg (ccip, ibc, deposit or contract)
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --recon-chain <RECON_CHAIN>
          The route's external chain
      --recon-position <RECON_POSITION>
          The mismatch's position in the lock's record
      --key-namespace <KEY_NAMESPACE>
          The harmed account's hardware key namespace [default: client]
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro insurance get`

```
Inspect a paid claim by id (read-only)

Usage: tenzro insurance get [OPTIONS] <CLAIM_ID>

Arguments:
  <CLAIM_ID>  Claim ID (hex)

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro insurance list`

```
List every paid claim (read-only)

Usage: tenzro insurance list [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro insurance pool`

```
Show the pool's balance, history and claim cap (read-only)

Usage: tenzro insurance pool [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro interaction`

```
Interaction receipts: mirror a settlement to other chains

Usage: tenzro interaction [OPTIONS] <COMMAND>

Commands:
  mirror  Record a settlement, given as its interaction record, on other chains, in parallel
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro interaction mirror`

```
Record a settlement, given as its interaction record, on other chains, in parallel

Usage: tenzro interaction mirror [OPTIONS] --chain <CHAINS> <INTERACTION_JSON>

Arguments:
  <INTERACTION_JSON>
          Path to the interaction record JSON of the settlement to mirror

Options:
      --chain <CHAINS>
          Chains to mirror onto — CAIP-2 ids or adapter chain names. Repeat the flag for several

  -v, --verbose
          Enable verbose logging

      --format <FORMAT>
          Output format (text, json)
          
          [default: text]

      --key-namespace <KEY_NAMESPACE>
          Hardware key namespace of the account that signs and pays for the mirror transactions
          
          [default: client]

      --digest-only
          Write only the digest rather than the full settlement bytes.
          
          Cheaper, and it proves a payload you already hold is the one that settled — but it cannot say *what* settled, so it does not survive the Tenzro Ledger losing state.

      --primary-committed
          Whether the primary settlement committed

      --rpc <RPC>
          [default: http://127.0.0.1:8545]

  -h, --help
          Print help (see a summary with '-h')
```

## `tenzro iroh`

```
Iroh content-addressed transport: info, endpoint-id, alpns, publish, fetch

Usage: tenzro iroh [OPTIONS] <COMMAND>

Commands:
  info          Show endpoint id, Pkarr relay, and bound ALPNs
  endpoint-id   Print just the iroh EndpointId (z-base-32 + hex)
  alpns         List ALPNs registered on the shared iroh router
  publish       Publish a local file as a tenzro:// blob
  fetch         Fetch a tenzro:// URI to a local file (or stdout)
  connectivity  Show how the node is reached: directly, after hole punching, or through relays
  help          Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro iroh alpns`

```
List ALPNs registered on the shared iroh router

Usage: tenzro iroh alpns [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro iroh connectivity`

```
Show how the node is reached: directly, after hole punching, or through relays

Usage: tenzro iroh connectivity [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro iroh endpoint-id`

```
Print just the iroh EndpointId (z-base-32 + hex)

Usage: tenzro iroh endpoint-id [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro iroh fetch`

```
Fetch a tenzro:// URI to a local file (or stdout)

Usage: tenzro iroh fetch [OPTIONS] --uri <URI>

Options:
      --uri <URI>        tenzro:// URI to fetch (blob / model / receipt)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --out <OUT>        Output path; if omitted, writes raw bytes to stdout
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro iroh info`

```
Show endpoint id, Pkarr relay, and bound ALPNs

Usage: tenzro iroh info [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro iroh publish`

```
Publish a local file as a tenzro:// blob

Usage: tenzro iroh publish [OPTIONS] --file <FILE>

Options:
      --file <FILE>      Path to the local file whose bytes should be published
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro join`

```
Join the Tenzro Network (one-click participate)

Usage: tenzro join [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint. Defaults to https://rpc.tenzro.com, or to the local node (http://127.0.0.1:8545) when --provider is set
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --name <NAME>      Display name [default: "Tenzro User"]
      --origin <ORIGIN>  Origin hint (e.g. "cli", "sdk", "app", "mcp", "a2a") [default: cli]
      --type <TYPE>      Participant type: human, agent, or bot [default: human]
      --provider         Also become an inference provider: detect hardware, post the compute bond, register, set default pricing, and pull + serve the largest catalog model that fits this machine. Requires a running local tenzro-node (or --rpc pointing at your node)
  -h, --help             Print help
```

## `tenzro machine-access`

```
Owner-signed machine access for agents, tools and models (add, list, revoke)

Usage: tenzro machine-access [OPTIONS] <COMMAND>

Commands:
  add     Grant access to a network range, a local service or a folder
  list    List the grants on the node, with their use counts
  revoke  Revoke a grant. It stops applying at once
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro machine-access add`

```
Grant access to a network range, a local service or a folder

Usage: tenzro machine-access add [OPTIONS] --grantee <GRANTEE> --operations <OPERATIONS>

Options:
      --grantee <GRANTEE>
          Who the grant is for: the node's machine DID for any sandboxed job on it, or an agent or tool DID
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --network <NETWORKS>
          A network range, as CIDR with an optional port: `198.51.100.0/24`, `127.0.0.1/32:5432`, `fd12::/64:443`. Repeatable
      --folder <FOLDERS>
          An absolute folder path the sandbox mounts. Repeatable
      --operations <OPERATIONS>
          Operations: `connect` for networks, `read` and/or `write` for folders
      --expires-at-ms <EXPIRES_AT_MS>
          When the grant ends, in milliseconds since the Unix epoch. Pass the value the first run printed when approving
      --expires-in-secs <EXPIRES_IN_SECS>
          When the grant ends, in seconds from now. Resolved on the first run
      --max-uses-per-minute <MAX_USES_PER_MINUTE>
          
      --max-bytes <MAX_BYTES>
          Most bytes moved through the grant
      --challenge-id <CHALLENGE_ID>
          The challenge the first run printed
      --authorization <AUTHORIZATION>
          JSON file from the owner's wallet: `credential_id_hex`, `assertion` and `ml_dsa_signature_hex` over that challenge
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro machine-access list`

```
List the grants on the node, with their use counts

Usage: tenzro machine-access list [OPTIONS]

Options:
      --json                           
  -v, --verbose                        Enable verbose logging
      --challenge-id <CHALLENGE_ID>    The challenge the first run printed
      --format <FORMAT>                Output format (text, json) [default: text]
      --authorization <AUTHORIZATION>  JSON file from the owner's wallet: `credential_id_hex`, `assertion` and `ml_dsa_signature_hex` over that challenge
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro machine-access revoke`

```
Revoke a grant. It stops applying at once

Usage: tenzro machine-access revoke [OPTIONS] <GRANT_ID>

Arguments:
  <GRANT_ID>  

Options:
      --challenge-id <CHALLENGE_ID>    The challenge the first run printed
  -v, --verbose                        Enable verbose logging
      --authorization <AUTHORIZATION>  JSON file from the owner's wallet: `credential_id_hex`, `assertion` and `ml_dsa_signature_hex` over that challenge
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

## `tenzro media-gen`

```
Generative media: the media catalog and renders

Usage: tenzro media-gen [OPTIONS] <COMMAND>

Commands:
  catalog  List the curated generative-media model catalog
  render   Render one output now, on this node or a provider serving the model
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro media-gen catalog`

```
List the curated generative-media model catalog

Usage: tenzro media-gen catalog [OPTIONS]

Options:
      --kind <KIND>      Only entries serving this kind (text2image, image2image, text2video, image2video, text2audio, image23d, text23d, action_policy, world_model)
  -v, --verbose          Enable verbose logging
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro media-gen render`

```
Render one output now, on this node or a provider serving the model

Usage: tenzro media-gen render [OPTIONS] --model <MODEL> --kind <KIND> --params <PARAMS>

Options:
      --model <MODEL>
          Catalog model id
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --kind <KIND>
          Media kind (text2image, image2image, text2video, image2video, text2audio, image23d, action_policy, world_model)
      --params <PARAMS>
          Path to a JSON file containing `MediaGenParams`, with a `seed`
      --input <INPUTS>
          A file holding one of the inputs `params.inputs` names by SHA-256, in their order; repeatable
      --verification <VERIFICATION>
          Verification the answer must carry: none, receipt, optimistic or tee
      --out <OUT>
          Write the rendered output to this path
      --channel-voucher <CHANNEL_VOUCHER>
          A signed channel voucher (`tenzro escrow voucher --out`) the render's metered cost is charged against
      --json
          Print the whole answer as JSON (receipt, units, settlement)
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

## `tenzro model`

```
Model management commands

Usage: tenzro model [OPTIONS] <COMMAND>

Commands:
  delete-served          Call tenzro_deleteModel (delete model) and print the node's answer
  preview-serve          Call tenzro_previewServe (preview serve) and print the node's answer
  build-manifest         Call tenzro_buildModelManifest (build model manifest) and print the node's answer
  pin                    Call tenzro_pinModel (pin model) and print the node's answer
  unpin                  Call tenzro_unpinModel (unpin model) and print the node's answer
  metadata               Call tenzro_modelMetadata (model metadata) and print the node's answer
  attestation-log        Call tenzro_getAttestationLog (get attestation log) and print the node's answer
  moe-receipts           Call tenzro_moeListReceipts (moe list receipts) and print the node's answer
  load-media-model       Call tenzro_loadMediaModel (load media model) and print the node's answer
  unload-media-model     Call tenzro_unloadMediaModel (unload media model) and print the node's answer
  key-release-register   Call tenzro_registerKeyRelease (register a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy) and print the node's answer
  key-release-revoke     Call tenzro_revokeKeyRelease (revoke a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy) and print the node's answer
  key-release-request    Call tenzro_requestKeyRelease (submit an attested environment's release request (`request`), which the provider node verifies and records) and print the node's answer
  key-release-get        Call tenzro_getKeyRelease (a model's release policy and releases (`model_id`), or for a recorded `request` the content key sealed to the environment) and print the node's answer
  training-commit-round  Call tenzro_commitTrainingRound (commit a training round's signed receipt against its milestone escrow) and print the node's answer
  training-settle-round  Call tenzro_settleTrainingRound (settle a committed training round (`receipt_id`) once its challenge window has closed) and print the node's answer
  trained-provenance     Call tenzro_trainedModelProvenance (the provenance of a trained model (`model_id`) from its committed training rounds (`rounds`)) and print the node's answer
  list                   List available models from catalog
  territory              Show this node's territorial licensing policy
  info                   Show detailed model information
  download               Download a model from HuggingFace
  serve                  Load and serve a model locally
  stop                   Stop serving a model
  delete                 Delete a downloaded model (removes all local files and caches)
  endpoints              List all model service endpoints
  endpoint               Get details of a specific model endpoint
  discover               Discover models on the network
  register-endpoint      Register a new model endpoint
  unregister-endpoint    Unregister a model endpoint
  prune                  Reconcile the node's model registry (auto-reload served models, prune stale endpoints)
  seal                   Seal a local model artifact into encrypted shards for named recipients
  install-sealed         Install a sealed model (fetch, verify, decrypt into local model storage)
  sealed-list            List sealed-model manifests stored on the node
  sealed-get             Fetch a full sealed-model manifest (for out-of-band delivery to recipients)
  recipient-key          Show the node's hybrid X25519 + ML-KEM-768 recipient public key for sealed models
  help                   Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro model attestation-log`

```
Call tenzro_getAttestationLog (get attestation log) and print the node's answer

Usage: tenzro model attestation-log [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    model
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model build-manifest`

```
Call tenzro_buildModelManifest (build model manifest) and print the node's answer

Usage: tenzro model build-manifest [OPTIONS] --name <NAME> --path <PATH>

Options:
      --name <NAME>      name
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --path <PATH>      Absolute directory on the node holding the model's files
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model delete`

```
Delete a downloaded model (removes all local files and caches)

Usage: tenzro model delete [OPTIONS] <MODEL_ID>

Arguments:
  <MODEL_ID>  Model ID to delete

Options:
  -v, --verbose          Enable verbose logging
  -y, --yes              Skip confirmation prompt
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro model delete-served`

```
Call tenzro_deleteModel (delete model) and print the node's answer

Usage: tenzro model delete-served [OPTIONS] --model-id <MODEL_ID>

Options:
      --model-id <MODEL_ID>  model id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro model discover`

```
Discover models on the network

Usage: tenzro model discover [OPTIONS]

Options:
      --category <CATEGORY>  Filter by category (e.g. "text-generation", "image", "embedding")
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --name <NAME>          Filter by name substring
      --limit <LIMIT>        Maximum results [default: 20]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro model download`

```
Download a model from HuggingFace

Usage: tenzro model download [OPTIONS] <MODEL_ID>

Arguments:
  <MODEL_ID>  Model ID to download

Options:
      --source <SOURCE>            Fetch source: 'network' (verified network providers only), 'huggingface' (HuggingFace only), or omit for network-first with a HuggingFace fallback
  -v, --verbose                    Enable verbose logging
      --catalog-rpc <CATALOG_RPC>  Node whose model catalog is read (the catalog is published data that nodes serve, not compiled into this binary) [default: http://127.0.0.1:8545]
      --format <FORMAT>            Output format (text, json) [default: text]
  -h, --help                       Print help
```

### `tenzro model endpoint`

```
Get details of a specific model endpoint

Usage: tenzro model endpoint [OPTIONS] <ID>

Arguments:
  <ID>  Instance ID of the endpoint

Options:
      --format <FORMAT>  Output format (text, json) [default: text]
  -v, --verbose          Enable verbose logging
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model endpoints`

```
List all model service endpoints

Usage: tenzro model endpoints [OPTIONS]

Options:
      --format <FORMAT>  Output format (table, json) [default: table]
  -v, --verbose          Enable verbose logging
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model info`

```
Show detailed model information

Usage: tenzro model info [OPTIONS] <MODEL_ID>

Arguments:
  <MODEL_ID>  Model ID

Options:
      --catalog-rpc <CATALOG_RPC>  Node whose model catalog is read (the catalog is published data that nodes serve, not compiled into this binary) [default: http://127.0.0.1:8545]
  -v, --verbose                    Enable verbose logging
      --format <FORMAT>            Output format (text, json) [default: text]
  -h, --help                       Print help
```

### `tenzro model install-sealed`

```
Install a sealed model (fetch, verify, decrypt into local model storage)

Usage: tenzro model install-sealed [OPTIONS] --recipient-did <RECIPIENT_DID>

Options:
      --recipient-did <RECIPIENT_DID>  Recipient DID (must match a manifest recipient addressed to this node)
  -v, --verbose                        Enable verbose logging
      --model-id <MODEL_ID>            Model ID whose manifest is already stored on the node
      --manifest-file <MANIFEST_FILE>  Path to a manifest JSON file received out-of-band from the publisher
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
      --format <FORMAT>                Output format (text, json) [default: text]
  -h, --help                           Print help
```

### `tenzro model key-release-get`

```
Call tenzro_getKeyRelease (a model's release policy and releases (`model_id`), or for a recorded `request` the content key sealed to the environment) and print the node's answer

Usage: tenzro model key-release-get [OPTIONS]

Options:
      --params <PARAMS>  Parameters as a JSON object [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model key-release-register`

```
Call tenzro_registerKeyRelease (register a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy) and print the node's answer

Usage: tenzro model key-release-register [OPTIONS]

Options:
      --params <PARAMS>  Parameters as a JSON object [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model key-release-request`

```
Call tenzro_requestKeyRelease (submit an attested environment's release request (`request`), which the provider node verifies and records) and print the node's answer

Usage: tenzro model key-release-request [OPTIONS]

Options:
      --params <PARAMS>  Parameters as a JSON object [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model key-release-revoke`

```
Call tenzro_revokeKeyRelease (revoke a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy) and print the node's answer

Usage: tenzro model key-release-revoke [OPTIONS]

Options:
      --params <PARAMS>  Parameters as a JSON object [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model list`

```
List available models from catalog

Usage: tenzro model list [OPTIONS]

Options:
      --downloaded                 Show only downloaded models
  -v, --verbose                    Enable verbose logging
      --serving                    Show only models currently being served
      --family <FAMILY>            Filter by family (e.g. qwen3, gemma3, mistral)
      --loaded                     List every model the node holds, of every type (chat, vision, embedding, forecast, segmentation, detection, audio, video, media, speech), with its engine, visibility, access and state
      --format <FORMAT>            Output format (table, json) [default: table]
      --catalog-rpc <CATALOG_RPC>  Node whose model catalog is read (the catalog is published data that nodes serve, not compiled into this binary) [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

### `tenzro model load-media-model`

```
Call tenzro_loadMediaModel (load media model) and print the node's answer

Usage: tenzro model load-media-model [OPTIONS] --model-id <MODEL_ID>

Options:
      --model-id <MODEL_ID>  model id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro model metadata`

```
Call tenzro_modelMetadata (model metadata) and print the node's answer

Usage: tenzro model metadata [OPTIONS] --model-id <MODEL_ID>

Options:
      --model-id <MODEL_ID>  model id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro model moe-receipts`

```
Call tenzro_moeListReceipts (moe list receipts) and print the node's answer

Usage: tenzro model moe-receipts [OPTIONS]

Options:
      --model-id <MODEL_ID>  model id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --limit <LIMIT>        limit
      --cursor <CURSOR>      The next_cursor of the page before
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro model pin`

```
Call tenzro_pinModel (pin model) and print the node's answer

Usage: tenzro model pin [OPTIONS] --model-id <MODEL_ID>

Options:
      --model-id <MODEL_ID>  model id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro model preview-serve`

```
Call tenzro_previewServe (preview serve) and print the node's answer

Usage: tenzro model preview-serve [OPTIONS] --model-id <MODEL_ID>

Options:
      --model-id <MODEL_ID>              model id
  -v, --verbose                          Enable verbose logging
      --format <FORMAT>                  Output format (text, json) [default: text]
      --quant <QUANT>                    quant
      --context-length <CONTEXT_LENGTH>  context length
      --max-concurrent <MAX_CONCURRENT>  max concurrent
      --rpc <RPC>                        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                             Print help
```

### `tenzro model prune`

```
Reconcile the node's model registry (auto-reload served models, prune stale endpoints)

Usage: tenzro model prune [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint (default: http://127.0.0.1:8545) [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro model recipient-key`

```
Show the node's hybrid X25519 + ML-KEM-768 recipient public key for sealed models

Usage: tenzro model recipient-key [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro model register-endpoint`

```
Register a new model endpoint

Usage: tenzro model register-endpoint [OPTIONS] --model-id <MODEL_ID>

Options:
      --model-id <MODEL_ID>  Model ID
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --provider <PROVIDER>  Provider name
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro model seal`

```
Seal a local model artifact into encrypted shards for named recipients

Usage: tenzro model seal [OPTIONS] --path <PATH> --owner-did <OWNER_DID> --recipient <RECIPIENTS> <MODEL_ID>

Arguments:
  <MODEL_ID>  Model ID to seal under

Options:
      --path <PATH>                    Local artifact file to seal (e.g. a GGUF)
  -v, --verbose                        Enable verbose logging
      --owner-did <OWNER_DID>          Publisher DID recorded on the manifest
      --recipient <RECIPIENTS>         Recipient in `did:...=<2432-hex hybrid recipient key>[=<enclave measurement hex>]` form (repeatable). A third component pins the recipient to an enclave measurement — that node must produce a matching attestation to install
      --artifact-name <ARTIFACT_NAME>  Artifact name (defaults to the file name)
      --shard-bytes <SHARD_BYTES>      Shard size in bytes (defaults to 256 MiB)
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
      --format <FORMAT>                Output format (text, json) [default: text]
  -h, --help                           Print help
```

### `tenzro model sealed-get`

```
Fetch a full sealed-model manifest (for out-of-band delivery to recipients)

Usage: tenzro model sealed-get [OPTIONS] <MODEL_ID>

Arguments:
  <MODEL_ID>  Model ID

Options:
      --out <OUT>        Write the manifest JSON to this file instead of stdout
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model sealed-list`

```
List sealed-model manifests stored on the node

Usage: tenzro model sealed-list [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (table, json) [default: table]
  -h, --help             Print help
```

### `tenzro model serve`

```
Load and serve a model locally

Usage: tenzro model serve [OPTIONS] <MODEL_ID>

Arguments:
  <MODEL_ID>
          Model ID to serve

Options:
      --rpc <RPC>
          RPC endpoint to serve on a remote node (omit to serve locally)

  -v, --verbose
          Enable verbose logging

      --cluster
          Force a LAN cluster even when the model fits one machine. By default the node forms a cluster only when the model is too large for the biggest single member; this requests one regardless

      --format <FORMAT>
          Output format (text, json)
          
          [default: text]

      --force-single
          Never form a cluster — load the whole model on this node even if it is too large for one machine (the load will fail if it does not fit)

      --public
          Announce the model; any caller may invoke it by paying your per-use price (free at 0), with no key, even on a node whose service-key gate is on. Overrides the node's visibility for this model

      --gated
          Announce the model as access-required: only callers your access policy names may invoke it. There is no pay-per-use path. Overrides the node's visibility for this model

      --private
          Do not announce the model; only this node's own callers may invoke it. Overrides the node's visibility for this model.
          
          With none of --public, --gated or --private the model follows the node's visibility (`tenzro visibility show`).

      --no-speculative
          Serve without speculative decoding, even where the catalog pairs a drafter with this model.
          
          # What this costs and what it saves
          
          A drafter is a second model. Where the catalog declares one, serving fetches it if it is not already on disk and holds it resident beside the target for as long as the target is served — several more gigabytes of download and of VRAM, bought for roughly a 2x decode speed-up.
          
          That is usually the right trade and it is why it is the default. It is the wrong trade on a machine that is short of VRAM, on one paying for the bandwidth, or when the target is being served to sit idle most of the time — and until now there was no way to say so from here. The node has always accepted `load_drafter: false`; nothing exposed it.
          
          Models with an inline MTP head are unaffected: their speculation is trained into the target's own weights, so there is nothing separate to decline.
          
          Applies to a node serve — `--rpc`, or a node running locally. Drafters are loaded by the node, so a bare `model serve` that only warms weights in this process never loads one either way.

      --catalog-rpc <CATALOG_RPC>
          Node whose model catalog is read (the catalog is published data that nodes serve, not compiled into this binary)
          
          [default: http://127.0.0.1:8545]

  -h, --help
          Print help (see a summary with '-h')
```

### `tenzro model stop`

```
Stop serving a model

Usage: tenzro model stop [OPTIONS] <MODEL_ID>

Arguments:
  <MODEL_ID>
          Model ID to stop serving

Options:
      --rpc <RPC>
          RPC endpoint of the node serving the model. Defaults to the local one, which is what an operator running their own node and chain wants.
          
          If nothing answers there, the decision is still recorded locally: an operator who starts their node on demand is not a failed stop. What is a failed stop is a node that answers and refuses — that used to print success too.
          
          [default: http://127.0.0.1:8545]

  -v, --verbose
          Enable verbose logging

      --format <FORMAT>
          Output format (text, json)
          
          [default: text]

  -h, --help
          Print help (see a summary with '-h')
```

### `tenzro model territory`

```
Show this node's territorial licensing policy

Usage: tenzro model territory [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro model trained-provenance`

```
Call tenzro_trainedModelProvenance (the provenance of a trained model (`model_id`) from its committed training rounds (`rounds`)) and print the node's answer

Usage: tenzro model trained-provenance [OPTIONS]

Options:
      --params <PARAMS>  Parameters as a JSON object [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model training-commit-round`

```
Call tenzro_commitTrainingRound (commit a training round's signed receipt against its milestone escrow) and print the node's answer

Usage: tenzro model training-commit-round [OPTIONS]

Options:
      --params <PARAMS>  Parameters as a JSON object [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model training-settle-round`

```
Call tenzro_settleTrainingRound (settle a committed training round (`receipt_id`) once its challenge window has closed) and print the node's answer

Usage: tenzro model training-settle-round [OPTIONS]

Options:
      --params <PARAMS>  Parameters as a JSON object [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro model unload-media-model`

```
Call tenzro_unloadMediaModel (unload media model) and print the node's answer

Usage: tenzro model unload-media-model [OPTIONS] --model-id <MODEL_ID>

Options:
      --model-id <MODEL_ID>  model id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro model unpin`

```
Call tenzro_unpinModel (unpin model) and print the node's answer

Usage: tenzro model unpin [OPTIONS] --model-id <MODEL_ID>

Options:
      --model-id <MODEL_ID>  model id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro model unregister-endpoint`

```
Unregister a model endpoint

Usage: tenzro model unregister-endpoint [OPTIONS] <INSTANCE_ID>

Arguments:
  <INSTANCE_ID>  Instance ID of the endpoint to unregister

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro moe`

```
Decentralized Mixture-of-Experts serving

Usage: tenzro moe [OPTIONS] <COMMAND>

Commands:
  shard-map           Show the live expert-shard map for a model (holders, replication, hot experts, under-replicated experts)
  plan-dispatch       Build a dispatch plan from a JSON file of top-k routing decisions. Useful for inspecting how a request would fan out across holders before submitting it
  replication-policy  Show the current governance-tuned replication policy
  catalog-shape       Show the catalog-side MoE topology for a model
  load-expert         Load a per-expert safetensors weight blob into the node's expert runtime, from a local file or a tenzro://blob URI
  load-gate           Load a gating-network safetensors blob (router.weight) for a layer
  unload-expert       Unload one resident expert
  unload-gate         Unload one resident gating network
  status              Show the node's resident experts and gates
  prepare-experts     Extract per-expert (and optionally gate) weight blobs for a layer from the catalog checkpoint, optionally quantizing them, and publish each as a content-addressed tenzro://blob URI. Returns a job id
  prepare-status      Snapshot one prepare-experts job by id (state, per-blob URIs, quant)
  forward             Run a distributed MoE forward for one layer: route locally, fan expert sub-batches out to holders, gather the combined outputs
  help                Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro moe catalog-shape`

```
Show the catalog-side MoE topology for a model

Usage: tenzro moe catalog-shape [OPTIONS] --model-id <MODEL_ID>

Options:
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --model-id <MODEL_ID>  
  -h, --help                 Print help
```

### `tenzro moe forward`

```
Run a distributed MoE forward for one layer: route locally, fan expert sub-batches out to holders, gather the combined outputs

Usage: tenzro moe forward [OPTIONS] --model-id <MODEL_ID> --layer <LAYER> --d-model <D_MODEL> --hidden-file <HIDDEN_FILE>

Options:
      --rpc <RPC>                  [default: http://127.0.0.1:8545]
  -v, --verbose                    Enable verbose logging
      --format <FORMAT>            Output format (text, json) [default: text]
      --model-id <MODEL_ID>        
      --layer <LAYER>              
      --d-model <D_MODEL>          Hidden dimension per token
      --hidden-file <HIDDEN_FILE>  Local file of raw little-endian f32 hidden states (n_tokens x d_model)
      --top-k <TOP_K>              Experts per token; defaults to the catalog experts_per_token
      --allow-cold                 Allow dispatch to experts that are not warm-resident
      --out-file <OUT_FILE>        Write the combined f32 outputs to this file instead of printing base64
  -h, --help                       Print help
```

### `tenzro moe load-expert`

```
Load a per-expert safetensors weight blob into the node's expert runtime, from a local file or a tenzro://blob URI

Usage: tenzro moe load-expert [OPTIONS] --model-id <MODEL_ID> --layer <LAYER> --expert <EXPERT>

Options:
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --model-id <MODEL_ID>  
      --layer <LAYER>        
      --expert <EXPERT>      
      --file <FILE>          Local safetensors file with gate_proj/up_proj/down_proj weights
      --uri <URI>            Content-addressed tenzro://blob/<hash> URI (fetched over iroh-blobs)
  -h, --help                 Print help
```

### `tenzro moe load-gate`

```
Load a gating-network safetensors blob (router.weight) for a layer

Usage: tenzro moe load-gate [OPTIONS] --model-id <MODEL_ID> --layer <LAYER>

Options:
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --model-id <MODEL_ID>  
      --layer <LAYER>        
      --file <FILE>          Local safetensors file with the router.weight tensor
      --uri <URI>            Content-addressed tenzro://blob/<hash> URI (fetched over iroh-blobs)
  -h, --help                 Print help
```

### `tenzro moe plan-dispatch`

```
Build a dispatch plan from a JSON file of top-k routing decisions. Useful for inspecting how a request would fan out across holders before submitting it

Usage: tenzro moe plan-dispatch [OPTIONS] --model-id <MODEL_ID> --routings-json <ROUTINGS_JSON>

Options:
      --rpc <RPC>                      [default: http://127.0.0.1:8545]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --model-id <MODEL_ID>            Tenzro model id
      --routings-json <ROUTINGS_JSON>  Path to a JSON file containing an array of routing decisions — `[{token_index: u32, experts: [{layer: u32, expert: u32}, ...]}]`
      --allow-cold                     Allow cold-residency holders when no warm holder is available
  -h, --help                           Print help
```

### `tenzro moe prepare-experts`

```
Extract per-expert (and optionally gate) weight blobs for a layer from the catalog checkpoint, optionally quantizing them, and publish each as a content-addressed tenzro://blob URI. Returns a job id

Usage: tenzro moe prepare-experts [OPTIONS] --model-id <MODEL_ID> --layer <LAYER>

Options:
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --model-id <MODEL_ID>      
      --layer <LAYER>            
      --experts <EXPERTS>        Comma-separated expert ids to prepare; omit to prepare every expert in the layer
      --no-gate                  Skip publishing the layer's gating-network blob
      --quant <QUANT>            Quantization preset (`q4_k_m`, `q8_0`, `q4_k`, `q6_k`) applied to all projections. Omit to publish dense f32 blobs
      --quant-json <QUANT_JSON>  Per-projection quant as JSON, e.g. `{"gate":"q4_k","up":"q4_k","down":"q6_k"}`. Omitted projections stay dense
  -h, --help                     Print help
```

### `tenzro moe prepare-status`

```
Snapshot one prepare-experts job by id (state, per-blob URIs, quant)

Usage: tenzro moe prepare-status [OPTIONS] --job-id <JOB_ID>

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --job-id <JOB_ID>  Job id returned by `moe prepare-experts`
  -h, --help             Print help
```

### `tenzro moe replication-policy`

```
Show the current governance-tuned replication policy

Usage: tenzro moe replication-policy [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro moe shard-map`

```
Show the live expert-shard map for a model (holders, replication, hot experts, under-replicated experts)

Usage: tenzro moe shard-map [OPTIONS] --model-id <MODEL_ID>

Options:
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --model-id <MODEL_ID>  Tenzro model id (e.g. `qwen3.5-397b-a17b`)
  -h, --help                 Print help
```

### `tenzro moe status`

```
Show the node's resident experts and gates

Usage: tenzro moe status [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro moe unload-expert`

```
Unload one resident expert

Usage: tenzro moe unload-expert [OPTIONS] --model-id <MODEL_ID> --layer <LAYER> --expert <EXPERT>

Options:
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --model-id <MODEL_ID>  
      --layer <LAYER>        
      --expert <EXPERT>      
  -h, --help                 Print help
```

### `tenzro moe unload-gate`

```
Unload one resident gating network

Usage: tenzro moe unload-gate [OPTIONS] --model-id <MODEL_ID> --layer <LAYER>

Options:
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --model-id <MODEL_ID>  
      --layer <LAYER>        
  -h, --help                 Print help
```

## `tenzro node`

```
Node management commands

Usage: tenzro node [OPTIONS] <COMMAND>

Commands:
  block-number                 Call tenzro_blockNumber (block number) and print the node's answer
  block                        Call tenzro_getBlock (get block) and print the node's answer
  export-config                Call tenzro_exportConfig (export config) and print the node's answer
  hardware-profile             Call tenzro_getHardwareProfile (get hardware profile) and print the node's answer
  role                         Call tenzro_getRole (get role) and print the node's answer
  set-role                     Call tenzro_setRole (set role) and print the node's answer
  snapshot-manifest            Call tenzro_getSnapshotManifest (get snapshot manifest) and print the node's answer
  snapshots                    Call tenzro_listSnapshots (list snapshots) and print the node's answer
  current-header               Call tenzro_currentHeader (current header) and print the node's answer
  fabric-profile               Call tenzro_fabricProfile (fabric profile) and print the node's answer
  gossip-stats                 Call tenzro_gossipStats (gossip stats) and print the node's answer
  graceful-exit                Call tenzro_gracefulExit (graceful exit) and print the node's answer
  resolve-tenzro-uri           Call tenzro_iroh_resolveTenzroUri (iroh resolve tenzro uri) and print the node's answer
  liveness-stats               Call tenzro_livenessStats (liveness stats) and print the node's answer
  set-draining                 Call tenzro_setDraining (set draining) and print the node's answer
  cleanup-idle-model-services  Call tenzro_cleanupIdleLocalModelServices (cleanup idle local model services) and print the node's answer
  layer-pipeline-status        Call tenzro_layerPipelineStatus and print this machine's part in a model served across the operator's machines
  produce-snapshot             Call tenzro_produceSnapshot (produce snapshot) and print the node's answer
  state-root                   Call tenzro_getStateRoot (get state root) and print the node's answer
  state-proof                  Call tenzro_getStateProof (get state proof) and print the node's answer
  account-contention           Call tenzro_getAccountContention (get account contention) and print the node's answer
  consensus-metrics            Call tenzro_getConsensusMetrics (get consensus metrics) and print the node's answer
  finality                     Call tenzro_getFinality (get finality) and print the node's answer
  reward-epoch                 Call tenzro_getRewardEpoch (get reward epoch) and print the node's answer
  reward-schedule              Call tenzro_getRewardSchedule (get reward schedule) and print the node's answer
  reward-coupons               Call tenzro_listRewardCoupons (list reward coupons) and print the node's answer
  hardware-level               Call tenzro_getHardwareLevel (get hardware level) and print the node's answer
  vesting                      Call tenzro_getVesting (get vesting) and print the node's answer
  validator-self-stake         Call tenzro_validatorSelfStake (validator self stake) and print the node's answer
  da-backends                  Call tenzro_getDaBackends (get da backends) and print the node's answer
  verify-da-pointer            Call tenzro_verifyDaPointer (verify da pointer) and print the node's answer
  verify-event-proof           Call tenzro_verifyEventProof (verify event proof) and print the node's answer
  start                        Start a Tenzro Network node
  status                       Check node status
  stop                         Stop the running node
  peers                        Show the connected peer count and the peers this node hears from
  activity                     Show settlement activity on the chain by reward epoch
  syncing                      Show sync status
  sync-range                   Fetch a contiguous range of blocks for sync inspection
  fee-market                   Inspect the EIP-1559 fee market (current gas price, suggested tip, fee history)
  mempool-stats                Show admission-controller mempool stats (per-lane admit/reject counters + lane config)
  mempool-lane                 Resolve which admission lane an address would land in, plus its current token-bucket state
  stats                        Show network-layer counters and gauges (gossip, connections, peer-address migrations)
  did-document                 Show this node's DID Document — every way of reaching it, in one place
  storage                      Storage-provider operations (store objects, pricing)
  upgrade                      Engine releases: check for, verify and install a signed release, or publish one
  help                         Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node account-contention`

```
Call tenzro_getAccountContention (get account contention) and print the node's answer

Usage: tenzro node account-contention [OPTIONS] --address <ADDRESS>

Options:
      --address <ADDRESS>  address
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro node activity`

```
Show settlement activity on the chain by reward epoch

Usage: tenzro node activity [OPTIONS]

Options:
      --epochs <EPOCHS>  How many of the latest epochs (at most 168)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro node block`

```
Call tenzro_getBlock (get block) and print the node's answer

Usage: tenzro node block [OPTIONS]

Options:
      --block-number <BLOCK_NUMBER>  block number
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro node block-number`

```
Call tenzro_blockNumber (block number) and print the node's answer

Usage: tenzro node block-number [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node cleanup-idle-model-services`

```
Call tenzro_cleanupIdleLocalModelServices (cleanup idle local model services) and print the node's answer

Usage: tenzro node cleanup-idle-model-services [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node consensus-metrics`

```
Call tenzro_getConsensusMetrics (get consensus metrics) and print the node's answer

Usage: tenzro node consensus-metrics [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node current-header`

```
Call tenzro_currentHeader (current header) and print the node's answer

Usage: tenzro node current-header [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node da-backends`

```
Call tenzro_getDaBackends (get da backends) and print the node's answer

Usage: tenzro node da-backends [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node did-document`

```
Show this node's DID Document — every way of reaching it, in one place

Usage: tenzro node did-document [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node export-config`

```
Call tenzro_exportConfig (export config) and print the node's answer

Usage: tenzro node export-config [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node fabric-profile`

```
Call tenzro_fabricProfile (fabric profile) and print the node's answer

Usage: tenzro node fabric-profile [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node fee-market`

```
Inspect the EIP-1559 fee market (current gas price, suggested tip, fee history)

Usage: tenzro node fee-market [OPTIONS]

Options:
      --rpc <RPC>                  RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose                    Enable verbose logging
      --blocks <BLOCKS>            Number of recent blocks to include in fee-history summary (1..=1024) [default: 10]
      --percentiles <PERCENTILES>  Tip percentiles to request (e.g. "25,50,75") [default: 25,50,75]
      --format <FORMAT>            Output format (text, json) [default: text]
  -h, --help                       Print help
```

### `tenzro node finality`

```
Call tenzro_getFinality (get finality) and print the node's answer

Usage: tenzro node finality [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node gossip-stats`

```
Call tenzro_gossipStats (gossip stats) and print the node's answer

Usage: tenzro node gossip-stats [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node graceful-exit`

```
Call tenzro_gracefulExit (graceful exit) and print the node's answer

Usage: tenzro node graceful-exit [OPTIONS]

Options:
      --max-wait-secs <MAX_WAIT_SECS>  max wait secs
  -v, --verbose                        Enable verbose logging
      --force <FORCE>                  force [possible values: true, false]
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro node hardware-level`

```
Call tenzro_getHardwareLevel (get hardware level) and print the node's answer

Usage: tenzro node hardware-level [OPTIONS] --address <ADDRESS>

Options:
      --address <ADDRESS>  address
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro node hardware-profile`

```
Call tenzro_getHardwareProfile (get hardware profile) and print the node's answer

Usage: tenzro node hardware-profile [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node layer-pipeline-status`

```
Call tenzro_layerPipelineStatus and print this machine's part in a model served across the operator's machines

Usage: tenzro node layer-pipeline-status [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node liveness-stats`

```
Call tenzro_livenessStats (liveness stats) and print the node's answer

Usage: tenzro node liveness-stats [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node mempool-lane`

```
Resolve which admission lane an address would land in, plus its current token-bucket state

Usage: tenzro node mempool-lane [OPTIONS] <ADDRESS>

Arguments:
  <ADDRESS>  Address to probe (hex, 0x-prefixed or bare)

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node mempool-stats`

```
Show admission-controller mempool stats (per-lane admit/reject counters + lane config)

Usage: tenzro node mempool-stats [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node peers`

```
Show the connected peer count and the peers this node hears from

Usage: tenzro node peers [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node produce-snapshot`

```
Call tenzro_produceSnapshot (produce snapshot) and print the node's answer

Usage: tenzro node produce-snapshot [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node resolve-tenzro-uri`

```
Call tenzro_iroh_resolveTenzroUri (iroh resolve tenzro uri) and print the node's answer

Usage: tenzro node resolve-tenzro-uri [OPTIONS] --tenzro-uri <TENZRO_URI>

Options:
      --tenzro-uri <TENZRO_URI>  tenzro uri
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro node reward-coupons`

```
Call tenzro_listRewardCoupons (list reward coupons) and print the node's answer

Usage: tenzro node reward-coupons [OPTIONS] --address <ADDRESS>

Options:
      --address <ADDRESS>  address
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro node reward-epoch`

```
Call tenzro_getRewardEpoch (get reward epoch) and print the node's answer

Usage: tenzro node reward-epoch [OPTIONS] --epoch <EPOCH>

Options:
      --epoch <EPOCH>    epoch
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro node reward-schedule`

```
Call tenzro_getRewardSchedule (get reward schedule) and print the node's answer

Usage: tenzro node reward-schedule [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node role`

```
Call tenzro_getRole (get role) and print the node's answer

Usage: tenzro node role [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node set-draining`

```
Call tenzro_setDraining (set draining) and print the node's answer

Usage: tenzro node set-draining [OPTIONS]

Options:
      --draining <DRAINING>  draining [possible values: true, false]
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro node set-role`

```
Call tenzro_setRole (set role) and print the node's answer

Usage: tenzro node set-role [OPTIONS] --role <ROLES>

Options:
      --role <ROLES>     A role this node takes (repeatable): the full set replaces the current one
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro node snapshot-manifest`

```
Call tenzro_getSnapshotManifest (get snapshot manifest) and print the node's answer

Usage: tenzro node snapshot-manifest [OPTIONS] --height <HEIGHT>

Options:
      --height <HEIGHT>  height
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro node snapshots`

```
Call tenzro_listSnapshots (list snapshots) and print the node's answer

Usage: tenzro node snapshots [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node start`

```
Start a Tenzro Network node

Usage: tenzro node start [OPTIONS]

Options:
      --roles <ROLES>        Comma-separated node roles. One stake backs every role. Tokens: validator, ai, storage, tee, user. Examples: "validator", "validator,storage,ai", "storage" [default: user]
  -v, --verbose              Enable verbose logging
      --config <CONFIG>      Path to configuration file
      --format <FORMAT>      Output format (text, json) [default: text]
      --data-dir <DATA_DIR>  Data directory for blockchain storage. Defaults to the canonical per-instance directory under the Tenzro root ($TENZRO_HOME, or ~/.tenzro) — the same one `tenzro-node` picks with no flags, so starting through the CLI and starting the binary directly land on the same state rather than two half-populated trees. Also settable via `$TENZRO_DATA_DIR`, the same variable `tenzro-node` itself reads [env: TENZRO_DATA_DIR=]
      --metrics              Enable metrics server
      --rpc-addr <RPC_ADDR>  RPC listen address [default: 127.0.0.1:9944]
  -h, --help                 Print help
```

### `tenzro node state-proof`

```
Call tenzro_getStateProof (get state proof) and print the node's answer

Usage: tenzro node state-proof [OPTIONS] --namespace <NAMESPACE> --key <KEY>

Options:
      --namespace <NAMESPACE>  namespace
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --key <KEY>              key
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro node state-root`

```
Call tenzro_getStateRoot (get state root) and print the node's answer

Usage: tenzro node state-root [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node stats`

```
Show network-layer counters and gauges (gossip, connections, peer-address migrations)

Usage: tenzro node stats [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node status`

```
Check node status

Usage: tenzro node status [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint to query [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node stop`

```
Stop the running node

Usage: tenzro node stop [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint of the node to stop [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --force            Force stop without graceful shutdown
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node storage`

```
Storage-provider operations (store objects, pricing)

Usage: tenzro node storage [OPTIONS] <COMMAND>

Commands:
  store        Erasure-code an object and publish its shards over the transport
  retrieve     Rebuild a stored object from its shards and write its bytes to a file
  set-pricing  Switch the provider to network-dynamic byte-epoch pricing
  status       Show this node's storage-provider state (rate, object count)
  help         Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro node storage retrieve`

```
Rebuild a stored object from its shards and write its bytes to a file

Usage: tenzro node storage retrieve [OPTIONS] --object-id <OBJECT_ID> --out <OUT>

Options:
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --object-id <OBJECT_ID>  Logical object id it was stored under
      --out <OUT>              Where the bytes are written
  -h, --help                   Print help
```

#### `tenzro node storage set-pricing`

```
Switch the provider to network-dynamic byte-epoch pricing

Usage: tenzro node storage set-pricing [OPTIONS] --rate <RATE>

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rate <RATE>      Fixed byte-epoch rate (wei)
  -h, --help             Print help
```

#### `tenzro node storage status`

```
Show this node's storage-provider state (rate, object count)

Usage: tenzro node storage status [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro node storage store`

```
Erasure-code an object and publish its shards over the transport

Usage: tenzro node storage store [OPTIONS] --object-id <OBJECT_ID> --owner <OWNER> --file <FILE>

Options:
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --object-id <OBJECT_ID>          Logical object id (content key the renter will reference)
      --owner <OWNER>                  Owner address (hex, 0x-prefixed or bare)
      --file <FILE>                    Path to the file whose bytes are stored
      --data-shards <DATA_SHARDS>      Data shards (default 4) [default: 4]
      --parity-shards <PARITY_SHARDS>  Parity shards (default 2) [default: 2]
  -h, --help                           Print help
```

### `tenzro node syncing`

```
Show sync status

Usage: tenzro node syncing [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node sync-range`

```
Fetch a contiguous range of blocks for sync inspection

Usage: tenzro node sync-range [OPTIONS] --start <START> --end <END>

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --start <START>    Inclusive starting height
      --end <END>        Inclusive ending height
      --max <MAX>        Maximum number of blocks to return in this batch (1..=256, default 64)
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro node upgrade`

```
Engine releases: check for, verify and install a signed release, or publish one

Usage: tenzro node upgrade [OPTIONS] <COMMAND>

Commands:
  check    Show the releases the node reports and whether one is newer than it runs
  apply    Verify a downloaded binary against a signed release and install it
  publish  Hash node binaries, sign a release with your hardware key and submit it
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro node upgrade apply`

```
Verify a downloaded binary against a signed release and install it

Usage: tenzro node upgrade apply [OPTIONS] --version <VERSION> --file <FILE> --install-to <INSTALL_TO>

Options:
  -v, --verbose                  Enable verbose logging
      --version <VERSION>        The release version to install
      --file <FILE>              The downloaded binary
      --format <FORMAT>          Output format (text, json) [default: text]
      --install-to <INSTALL_TO>  Where the node binary is installed; replaced atomically
      --platform <PLATFORM>      The artifact platform; defaults to the platform the node reports
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

#### `tenzro node upgrade check`

```
Show the releases the node reports and whether one is newer than it runs

Usage: tenzro node upgrade check [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro node upgrade publish`

```
Hash node binaries, sign a release with your hardware key and submit it

Usage: tenzro node upgrade publish [OPTIONS] --version <VERSION> --artifact <ARTIFACTS> --key-label <KEY_LABEL>

Options:
  -v, --verbose                Enable verbose logging
      --version <VERSION>      
      --artifact <ARTIFACTS>   `<platform>=<path to binary>`, once per platform
      --format <FORMAT>        Output format (text, json) [default: text]
      --key-label <KEY_LABEL>  Label of the publisher's key in this machine's TPM or Secure Enclave
      --rpc <RPC>              [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro node validator-self-stake`

```
Call tenzro_validatorSelfStake (validator self stake) and print the node's answer

Usage: tenzro node validator-self-stake [OPTIONS]

Options:
      --additional <ADDITIONAL>  additional
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro node verify-da-pointer`

```
Call tenzro_verifyDaPointer (verify da pointer) and print the node's answer

Usage: tenzro node verify-da-pointer [OPTIONS] --pointer <POINTER>

Options:
      --pointer <POINTER>  pointer (JSON)
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro node verify-event-proof`

```
Call tenzro_verifyEventProof (verify event proof) and print the node's answer

Usage: tenzro node verify-event-proof [OPTIONS]

Options:
      --proof <PROOF>                      proof (JSON)
  -v, --verbose                            Enable verbose logging
      --certified-proof <CERTIFIED_PROOF>  certified proof (JSON)
      --format <FORMAT>                    Output format (text, json) [default: text]
      --rpc <RPC>                          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                               Print help
```

### `tenzro node vesting`

```
Call tenzro_getVesting (get vesting) and print the node's answer

Usage: tenzro node vesting [OPTIONS] --address <ADDRESS>

Options:
      --address <ADDRESS>  address
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

## `tenzro passkey`

```
Passkey-first wallet onboarding + custody (enrollment, recovery, session keys, hardware signers)

Usage: tenzro passkey [OPTIONS] <COMMAND>

Commands:
  login     Create a passkey account via the browser (gcloud-style login)
  enroll    Enroll a passkey-bound smart account from pre-acquired ceremony output
  keystore  Show an account's keystore from consensus state
  resolve   Find the accounts whose keystore links a passkey credential id
  update    Send a keystore change (link or unlink a passkey, policy, recovery signers, recovery) approved by the account's passkeys, paying its fee from this machine's client account
  help      Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro passkey enroll`

```
Enroll a passkey-bound smart account from pre-acquired ceremony output

Usage: tenzro passkey enroll [OPTIONS] --passkey-pubkey-hex <PASSKEY_PUBKEY_HEX> --credential-id-hex <CREDENTIAL_ID_HEX> --ml-dsa-public-key-hex <ML_DSA_PUBLIC_KEY_HEX>

Options:
      --passkey-pubkey-hex <PASSKEY_PUBKEY_HEX>
          Raw or SEC1 P-256 public key hex
  -v, --verbose
          Enable verbose logging
      --credential-id-hex <CREDENTIAL_ID_HEX>
          Opaque credential ID returned by the platform authenticator
      --format <FORMAT>
          Output format (text, json) [default: text]
      --ml-dsa-public-key-hex <ML_DSA_PUBLIC_KEY_HEX>
          The ML-DSA-65 verifying key of the hardware that holds the passkey, hex; the authorization carries its signature over the same challenge
      --registration-authenticator-data-hex <REGISTRATION_AUTHENTICATOR_DATA_HEX>
          The registration's `authenticatorData`, hex, as `navigator.credentials.create()` returned it; required for a first wallet (salt 0)
      --rp-id <RP_ID>
          The relying party the passkey is registered on (the wallet provider's domain); the node's own when omitted
      --authorization <AUTHORIZATION>
          Proof of possession (JSON), `{challenge_id, credential_id_hex, assertion, ml_dsa_signature_hex}` for an `enroll_passkey` custody challenge: the assertion signing its `webauthn_challenge` and the ML-DSA-65 key signing the same challenge
      --display-name <DISPLAY_NAME>
          Optional display name
      --salt <SALT>
          CREATE2 salt [default: 0]
  -h, --help
          Print help
```

### `tenzro passkey keystore`

```
Show an account's keystore from consensus state

Usage: tenzro passkey keystore [OPTIONS] <ACCOUNT>

Arguments:
  <ACCOUNT>  The account, 20-byte hex

Options:
      --anchor <ANCHOR>  For an account with no keystore on chain: its anchor (the JSON `tenzro_enrollPasskey` returned, or a file holding it)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro passkey login`

```
Create a passkey account via the browser (gcloud-style login)

Usage: tenzro passkey login [OPTIONS]

Options:
      --display-name <DISPLAY_NAME>  Optional display name for the new identity
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --salt <SALT>                  CREATE2 salt [default: 0]
      --web-url <WEB_URL>            Web API base serving /auth/passkey (derived from the RPC URL when omitted)
  -h, --help                         Print help
```

### `tenzro passkey resolve`

```
Find the accounts whose keystore links a passkey credential id

Usage: tenzro passkey resolve [OPTIONS] --rp-id <RP_ID> <CREDENTIAL_ID>

Arguments:
  <CREDENTIAL_ID>  The WebAuthn credential id, hex

Options:
      --rp-id <RP_ID>    The relying party the passkey is registered on (the wallet provider's domain)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro passkey update`

```
Send a keystore change (link or unlink a passkey, policy, recovery signers, recovery) approved by the account's passkeys, paying its fee from this machine's client account

Usage: tenzro passkey update [OPTIONS] <UPDATE>

Arguments:
  <UPDATE>  The update as JSON (chain_id, account, anchor, previous_commitment, op, approvals, possession), or a file holding it

Options:
      --key-namespace <KEY_NAMESPACE>  Key namespace of the client account that pays the fee [default: default]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
  -h, --help                           Print help
```

## `tenzro payment`

```
Payment commands

Usage: tenzro payment [OPTIONS] <COMMAND>

Commands:
  challenge       Create a payment challenge for a resource
  verify          Verify a payment credential
  settle          Settle a payment on-chain
  record          Show a payment's consensus record
  history         List consensus payment records from the event index
  settlements     List the paid calls a node served or routed, with how each settled
  statement       An account's statement of the payment legs paid to it (as operator, reseller or platform), verifiable against the chain
  legs            List the provider legs a node owes for calls it forwarded
  retry-leg       Drive a failed provider leg again under its payment id (operator)
  agent-voucher   Sign a delegated agent's next voucher on its channel (serving node)
  refund          Return part or all of a payment you received to its payer
  set-split       Set the standing split rule every payment you receive is divided by
  split           Show a payee's standing split rule from consensus
  prove           Record a payment a delegated agent's account made on another chain, from the account's report proven through that chain's route
  quote           Price a USD amount in each accepted asset, with its fee in kind
  remote-voucher  Have the agent's serving node sign a voucher on a channel its account holds on another chain
  help            Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro payment agent-voucher`

```
Sign a delegated agent's next voucher on its channel (serving node)

Usage: tenzro payment agent-voucher [OPTIONS] --channel-id <CHANNEL_ID> --cumulative-amount <CUMULATIVE_AMOUNT>

Options:
      --channel-id <CHANNEL_ID>
          The channel's escrow id (hex)
  -v, --verbose
          Enable verbose logging
      --cumulative-amount <CUMULATIVE_AMOUNT>
          The cumulative amount the payee may have claimed in total
      --format <FORMAT>
          Output format (text, json) [default: text]
      --rpc <RPC>
          RPC endpoint of one of the agent's serving nodes [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro payment challenge`

```
Create a payment challenge for a resource

Usage: tenzro payment challenge [OPTIONS] --amount <AMOUNT> <RESOURCE>

Arguments:
  <RESOURCE>  Resource URI (e.g. /api/inference/gemma4-9b)

Options:
      --amount <AMOUNT>        Amount in smallest unit
  -v, --verbose                Enable verbose logging
      --asset <ASSET>          Asset (e.g. USDC, TNZO) [default: USDC]
      --format <FORMAT>        Output format (text, json) [default: text]
      --protocol <PROTOCOL>    Protocol: mpp or x402 [default: mpp]
      --recipient <RECIPIENT>  Recipient DID or address
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro payment history`

```
List consensus payment records from the event index

Usage: tenzro payment history [OPTIONS]

Options:
      --payee <PAYEE>              Only payments to this payee (32-byte hex address)
  -v, --verbose                    Enable verbose logging
      --format <FORMAT>            Output format (text, json) [default: text]
      --payer <PAYER>              Only payments from this payer
      --agent-did <AGENT_DID>      Only payments made by this delegated agent
      --class <CLASS>              Only this record class: native, proven or attested
      --asset <ASSET>              Only this asset
      --from-cursor <FROM_CURSOR>  Continue after this event cursor
      --from-height <FROM_HEIGHT>  Start at this block height
      --limit <LIMIT>              Most records
      --proofs                     Include each record's event proof
      --rpc <RPC>                  RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

### `tenzro payment legs`

```
List the provider legs a node owes for calls it forwarded

Usage: tenzro payment legs [OPTIONS]

Options:
      --status <STATUS>      Only legs in this state (`queued`, `pending`, `settled`, `failed`)
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --provider <PROVIDER>  Only legs owed to this provider account
      --limit <LIMIT>        Most entries
      --cursor <CURSOR>      Continue from this cursor (the previous page's `cursor`)
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro payment prove`

```
Record a payment a delegated agent's account made on another chain, from the account's report proven through that chain's route

Usage: tenzro payment prove [OPTIONS] --agent-did <AGENT_DID> --chain <CHAIN> --delivery <DELIVERY>

Options:
      --agent-did <AGENT_DID>          The paying agent's DID
  -v, --verbose                        Enable verbose logging
      --chain <CHAIN>                  The chain its account paid on (CAIP-2)
      --format <FORMAT>                Output format (text, json) [default: text]
      --delivery <DELIVERY>            The route delivery carrying the account's payment report (hex)
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro payment quote`

```
Price a USD amount in each accepted asset, with its fee in kind

Usage: tenzro payment quote [OPTIONS] --usd-e6 <USD_E6>

Options:
      --usd-e6 <USD_E6>  The price in USD micro-units (1 USD = 1000000)
  -v, --verbose          Enable verbose logging
      --accept <ACCEPT>  Assets to price it in (`TNZO` or a `0x` token id); TNZO when none
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro payment record`

```
Show a payment's consensus record

Usage: tenzro payment record [OPTIONS]

Options:
      --pay-ref <PAY_REF>        The record's reference (hex)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --payment-id <PAYMENT_ID>  The payment id a native payment settled under
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro payment refund`

```
Return part or all of a payment you received to its payer

Usage: tenzro payment refund [OPTIONS] --pay-ref <PAY_REF> --amount <AMOUNT>

Options:
      --pay-ref <PAY_REF>              The payment record's reference (hex)
  -v, --verbose                        Enable verbose logging
      --amount <AMOUNT>                Amount to return, in the asset's smallest unit (decimal)
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro payment remote-voucher`

```
Have the agent's serving node sign a voucher on a channel its account holds on another chain

Usage: tenzro payment remote-voucher [OPTIONS] --chain <CHAIN> --channel-id <CHANNEL_ID> --cumulative-amount <CUMULATIVE_AMOUNT>

Options:
      --chain <CHAIN>
          The chain the account holds the channel on (CAIP-2)
  -v, --verbose
          Enable verbose logging
      --channel-id <CHANNEL_ID>
          The channel's id on the account
      --format <FORMAT>
          Output format (text, json) [default: text]
      --cumulative-amount <CUMULATIVE_AMOUNT>
          The cumulative amount the payee may have claimed in total
      --rpc <RPC>
          RPC endpoint of one of the agent's serving nodes [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro payment retry-leg`

```
Drive a failed provider leg again under its payment id (operator)

Usage: tenzro payment retry-leg [OPTIONS] --payment-id <PAYMENT_ID>

Options:
      --payment-id <PAYMENT_ID>  The leg's payment id
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro payment set-split`

```
Set the standing split rule every payment you receive is divided by

Usage: tenzro payment set-split [OPTIONS]

Options:
      --rule <RULE>                    The rule as JSON, or `@<path>` to read it from a file
  -v, --verbose                        Enable verbose logging
      --clear                          Clear the standing rule
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro payment settle`

```
Settle a payment on-chain

Usage: tenzro payment settle [OPTIONS] --payee <PAYEE> --amount <AMOUNT> --payment-id <PAYMENT_ID> --request <REQUEST>

Options:
      --payee <PAYEE>                  Payee address (hex)
  -v, --verbose                        Enable verbose logging
      --amount <AMOUNT>                Amount in wei (decimal)
      --format <FORMAT>                Output format (text, json) [default: text]
      --payment-id <PAYMENT_ID>        Payment id, the idempotency key the authorization signs
      --request <REQUEST>              The resource paid for; its digest is the request the payment binds
      --quote-digest <QUOTE_DIGEST>    The payee's quote digest (hex), when the payment pays a quote
      --usd-e6 <USD_E6>                The quoted USD price in micro-units, when the payment is USD-priced [default: 0]
      --app-wallet <APP_WALLET>        Wallet an application's developer margin is paid to (hex); signed with the payment, together with --margin-bps
      --margin-bps <MARGIN_BPS>        The developer margin in basis points, carved out of --amount and paid to --app-wallet
      --key-namespace <KEY_NAMESPACE>  The paying account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro payment settlements`

```
List the paid calls a node served or routed, with how each settled

Usage: tenzro payment settlements [OPTIONS]

Options:
  -v, --verbose                  Enable verbose logging
      --work-class <WORK_CLASS>  Only this work class (inference_served, ...)
      --format <FORMAT>          Output format (text, json) [default: text]
      --provider <PROVIDER>      Only calls paid to this provider account
      --payer <PAYER>            Only calls paid by this account
      --from-ms <FROM_MS>        Only calls served at or after this time, unix ms
      --to-ms <TO_MS>            Only calls served before this time, unix ms
      --cursor <CURSOR>          Continue from this cursor (the previous page's `cursor`)
      --limit <LIMIT>            Most entries (at most 200)
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro payment split`

```
Show a payee's standing split rule from consensus

Usage: tenzro payment split [OPTIONS] --payee <PAYEE>

Options:
      --payee <PAYEE>    The payee's address (hex)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro payment statement`

```
An account's statement of the payment legs paid to it (as operator, reseller or platform), verifiable against the chain

Usage: tenzro payment statement [OPTIONS] --account <ACCOUNT>

Options:
      --account <ACCOUNT>        The account (32 bytes of hex)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --max <MAX>                Most payments read (pages of 200) [default: 2000]
      --verify                   Re-read every payment from this endpoint and report each difference (`--verify` alone uses `--rpc`)
      --verify-rpc <VERIFY_RPC>  The endpoint the statement is checked against
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro payment verify`

```
Verify a payment credential

Usage: tenzro payment verify [OPTIONS] --credential <CREDENTIAL>

Options:
      --credential <CREDENTIAL>  Payment credential (JSON); it names the challenge it answers
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

## `tenzro permit2`

```
Permit2 SignatureTransfer: domain-separator / digest / verify-and-consume / nonce-used

Usage: tenzro permit2 [OPTIONS] <COMMAND>

Commands:
  verify-and-consume  Atomically verify a signed Permit2 message and consume the nonce
  nonce-used          Check whether a (owner, nonce) slot has been consumed
  help                Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro permit2 nonce-used`

```
Check whether a (owner, nonce) slot has been consumed

Usage: tenzro permit2 nonce-used [OPTIONS] --owner <OWNER> --nonce <NONCE>

Options:
      --owner <OWNER>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --nonce <NONCE>    
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro permit2 verify-and-consume`

```
Atomically verify a signed Permit2 message and consume the nonce

Usage: tenzro permit2 verify-and-consume [OPTIONS] --chain-id <CHAIN_ID> --owner <OWNER> --token <TOKEN> --amount <AMOUNT> --spender <SPENDER> --nonce <NONCE> --deadline <DEADLINE> --signature <SIGNATURE>

Options:
      --chain-id <CHAIN_ID>                        
  -v, --verbose                                    Enable verbose logging
      --format <FORMAT>                            Output format (text, json) [default: text]
      --owner <OWNER>                              
      --token <TOKEN>                              
      --amount <AMOUNT>                            
      --spender <SPENDER>                          
      --nonce <NONCE>                              
      --deadline <DEADLINE>                        
      --signature <SIGNATURE>                      
      --witness <WITNESS>                          
      --witness-type-string <WITNESS_TYPE_STRING>  
      --rpc <RPC>                                  [default: http://127.0.0.1:8545]
  -h, --help                                       Print help
```

## `tenzro pq-hybrid`

```
PQ-hybrid signing helper commands

Usage: tenzro pq-hybrid [OPTIONS] <COMMAND>

Commands:
  inspect  Inspect a finalized transaction's signature legs
  enroll   Enroll the hardware ML-DSA-65 key as the client account's post-quantum key
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro pq-hybrid enroll`

```
Enroll the hardware ML-DSA-65 key as the client account's post-quantum key

Usage: tenzro pq-hybrid enroll [OPTIONS]

Options:
      --key-namespace <KEY_NAMESPACE>  The client account's hardware key namespace [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro pq-hybrid inspect`

```
Inspect a finalized transaction's signature legs

Usage: tenzro pq-hybrid inspect [OPTIONS] --tx-hash <TX_HASH>

Options:
      --tx-hash <TX_HASH>  Transaction hash
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

## `tenzro provenance`

```
C2PA-style content provenance manifests (EU AI Act §50(2))

Usage: tenzro provenance [OPTIONS] <COMMAND>

Commands:
  get    Fetch the provenance manifest for a given content hash
  model  Verify offline where a trained model came from: its trainer's signed receipt, every round on chain, each milestone released, from the chain's genesis anchor alone
  help   Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro provenance get`

```
Fetch the provenance manifest for a given content hash

Usage: tenzro provenance get [OPTIONS] <CONTENT_HASH>

Arguments:
  <CONTENT_HASH>  Content hash (32 bytes hex, 0x-prefix optional)

Options:
      --format <FORMAT>  Output format (text, json) [default: text]
  -v, --verbose          Enable verbose logging
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro provenance model`

```
Verify offline where a trained model came from: its trainer's signed receipt, every round on chain, each milestone released, from the chain's genesis anchor alone

Usage: tenzro provenance model [OPTIONS] --file <FILE> --chain-id <CHAIN_ID> --genesis-hash <GENESIS_HASH> --genesis-committee-root <GENESIS_COMMITTEE_ROOT>

Options:
      --file <FILE>
          The provenance pack
  -v, --verbose
          Enable verbose logging
      --chain-id <CHAIN_ID>
          Chain id, from the genesis file
      --format <FORMAT>
          Output format (text, json) [default: text]
      --genesis-hash <GENESIS_HASH>
          Genesis block hash, hex
      --genesis-committee-root <GENESIS_COMMITTEE_ROOT>
          Root of the genesis committee, hex
      --handover-program <HANDOVER_PROGRAM>
          Image id of the handover program, hex, when the pack's checkpoint is certified from a handover chain proof
      --weights <WEIGHTS>
          The weights file, to check it is the one the receipt names
  -h, --help
          Print help
```

## `tenzro provider`

```
Provider management commands

Usage: tenzro provider [OPTIONS] <COMMAND>

Commands:
  sla-params          Call tenzro_slaGetParams (sla get params) and print the node's answer
  sla-probe           Call tenzro_slaIssueProbe (sla issue probe) and print the node's answer
  sla-probes          Call tenzro_slaListOutstandingProbes (sla list outstanding probes) and print the node's answer
  compute-claim       Call tenzro_computeGetClaim (compute get claim) and print the node's answer
  compute-claims      Call tenzro_computeListClaims (compute list claims) and print the node's answer
  compute-price-feed  Call tenzro_computePriceFeed (compute price feed) and print the node's answer
  sla-verdict         Call tenzro_slaVerdict (sla verdict) and print the node's answer
  status              Show provider status
  models              List models being served
  list                List all providers discovered on the network
  quote               Price one request at every provider serving a model, cheapest first
  scorecard           Show a provider's standing, price cards, and settled volume and latency
  statement           A provider's settlement statement for a window, by UTC day or month
  pricing             Provider pricing management
  bond                Compute bond (admission collateral) management
  help                Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro provider bond`

```
Compute bond (admission collateral) management

Usage: tenzro provider bond [OPTIONS] <COMMAND>

Commands:
  post      Post a new compute bond
  increase  Top up an existing bond
  get       Get a single provider's bond state
  list      List every compute bond on chain
  withdraw  Initiate withdrawal, starting the cooldown
  finalize  Release the vault back to the provider once the cooldown has elapsed
  params    Show the admission dials: minimum bond and cooldown length
  help      Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro provider bond finalize`

```
Release the vault back to the provider once the cooldown has elapsed

Usage: tenzro provider bond finalize [OPTIONS] --did <DID> --address <ADDRESS>

Options:
      --did <DID>          Provider DID
  -v, --verbose            Enable verbose logging
      --address <ADDRESS>  Provider wallet address (32-byte hex; must match the bond's payout address)
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

#### `tenzro provider bond get`

```
Get a single provider's bond state

Usage: tenzro provider bond get [OPTIONS] --did <DID>

Options:
      --did <DID>        Provider DID
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

#### `tenzro provider bond increase`

```
Top up an existing bond

Usage: tenzro provider bond increase [OPTIONS] --did <DID> --address <ADDRESS> --amount <AMOUNT>

Options:
      --did <DID>          Provider DID
  -v, --verbose            Enable verbose logging
      --address <ADDRESS>  Provider wallet address (32-byte hex; must match the bond's payout address)
      --format <FORMAT>    Output format (text, json) [default: text]
      --amount <AMOUNT>    Additional amount in TNZO
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

#### `tenzro provider bond list`

```
List every compute bond on chain

Usage: tenzro provider bond list [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro provider bond params`

```
Show the admission dials: minimum bond and cooldown length

Usage: tenzro provider bond params [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro provider bond post`

```
Post a new compute bond

Usage: tenzro provider bond post [OPTIONS] --did <DID> --address <ADDRESS> --amount <AMOUNT>

Options:
      --did <DID>          Provider DID (e.g. did:tenzro:machine:...)
  -v, --verbose            Enable verbose logging
      --address <ADDRESS>  Provider wallet address (32-byte hex; with or without 0x)
      --format <FORMAT>    Output format (text, json) [default: text]
      --amount <AMOUNT>    Bond amount in TNZO (decimal, e.g. "100" for 100 TNZO)
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

#### `tenzro provider bond withdraw`

```
Initiate withdrawal, starting the cooldown

Usage: tenzro provider bond withdraw [OPTIONS] --did <DID> --address <ADDRESS>

Options:
      --did <DID>          Provider DID
  -v, --verbose            Enable verbose logging
      --address <ADDRESS>  Provider wallet address (32-byte hex; must match the bond's payout address)
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro provider compute-claim`

```
Call tenzro_computeGetClaim (compute get claim) and print the node's answer

Usage: tenzro provider compute-claim [OPTIONS] --claim-id <CLAIM_ID>

Options:
      --claim-id <CLAIM_ID>  claim id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro provider compute-claims`

```
Call tenzro_computeListClaims (compute list claims) and print the node's answer

Usage: tenzro provider compute-claims [OPTIONS]

Options:
      --party <PARTY>    party
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --limit <LIMIT>    limit
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro provider compute-price-feed`

```
Call tenzro_computePriceFeed (compute price feed) and print the node's answer

Usage: tenzro provider compute-price-feed [OPTIONS]

Options:
      --model-id <MODEL_ID>            model id
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --region <REGION>                region
      --attested-only <ATTESTED_ONLY>  attested only [possible values: true, false]
      --limit <LIMIT>                  limit
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro provider list`

```
List all providers discovered on the network

Usage: tenzro provider list [OPTIONS]

Options:
      --provider-type <type>  Filter by provider type (ai, tee, storage, compute, general)
  -v, --verbose               Enable verbose logging
      --format <FORMAT>       Output format (text, json) [default: text]
      --rpc <RPC>             RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                  Print help
```

### `tenzro provider models`

```
List models being served

Usage: tenzro provider models [OPTIONS]

Options:
      --address <ADDRESS>  Provider address (optional, uses default wallet if not specified)
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro provider pricing`

```
Provider pricing management

Usage: tenzro provider pricing [OPTIONS] <COMMAND>

Commands:
  set   Set one of this node's price cards
  show  Show this node's price cards
  post  Publish this node's card for a model as a registry entry, signed by the operator account
  card  Show the card a provider publishes for a model (read-only)
  help  Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro provider pricing card`

```
Show the card a provider publishes for a model (read-only)

Usage: tenzro provider pricing card [OPTIONS] --provider <PROVIDER> --model <MODEL>

Options:
      --provider <PROVIDER>  The provider's account (hex)
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --model <MODEL>        Catalog id of the model or service
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

#### `tenzro provider pricing post`

```
Publish this node's card for a model as a registry entry, signed by the operator account

Usage: tenzro provider pricing post [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>                  Catalog id of the model
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The operator account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

#### `tenzro provider pricing set`

```
Set one of this node's price cards

Usage: tenzro provider pricing set [OPTIONS] --line <LINES>

Options:
      --model <MODEL>                  Catalog id of the model the card is for
  -v, --verbose                        Enable verbose logging
      --denom <DENOM>                  What the prices are in: nano_usd or wei [default: nano_usd]
      --format <FORMAT>                Output format (text, json) [default: text]
      --line <LINES>                   A priced line, `unit[@tier]=price[/per_exp]`; repeat for each
      --min-charge <MIN_CHARGE>        Least one call is charged, in the card's denomination [default: 0]
      --post                           Post the card on chain after setting it, signed by the operator account under `--key-namespace`, so receipts and disputes can name it
      --key-namespace <KEY_NAMESPACE>  The operator account's hardware key namespace, for `--post` [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

#### `tenzro provider pricing show`

```
Show this node's price cards

Usage: tenzro provider pricing show [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro provider quote`

```
Price one request at every provider serving a model, cheapest first

Usage: tenzro provider quote [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>                  Model id
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --input-tokens <INPUT_TOKENS>    Prompt tokens [default: 0]
      --output-tokens <OUTPUT_TOKENS>  Completion tokens [default: 0]
      --verification <VERIFICATION>    Verification level: none, receipt, optimistic or tee [default: none]
      --provider <PROVIDER>            Only this provider (address)
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro provider scorecard`

```
Show a provider's standing, price cards, and settled volume and latency

Usage: tenzro provider scorecard [OPTIONS] <PROVIDER>

Arguments:
  <PROVIDER>  The provider's account address

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro provider sla-params`

```
Call tenzro_slaGetParams (sla get params) and print the node's answer

Usage: tenzro provider sla-params [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro provider sla-probe`

```
Call tenzro_slaIssueProbe (sla issue probe) and print the node's answer

Usage: tenzro provider sla-probe [OPTIONS] --provider-did <PROVIDER_DID> --epoch <EPOCH> --round <ROUND> --deadline-ms <DEADLINE_MS>

Options:
      --provider-did <PROVIDER_DID>  provider did
  -v, --verbose                      Enable verbose logging
      --epoch <EPOCH>                epoch
      --format <FORMAT>              Output format (text, json) [default: text]
      --round <ROUND>                round
      --deadline-ms <DEADLINE_MS>    deadline ms
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro provider sla-probes`

```
Call tenzro_slaListOutstandingProbes (sla list outstanding probes) and print the node's answer

Usage: tenzro provider sla-probes [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro provider sla-verdict`

```
Call tenzro_slaVerdict (sla verdict) and print the node's answer

Usage: tenzro provider sla-verdict [OPTIONS] --provider-did <PROVIDER_DID> --epoch <EPOCH>

Options:
      --provider-did <PROVIDER_DID>  provider did
  -v, --verbose                      Enable verbose logging
      --epoch <EPOCH>                epoch
      --format <FORMAT>              Output format (text, json) [default: text]
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro provider statement`

```
A provider's settlement statement for a window, by UTC day or month

Usage: tenzro provider statement [OPTIONS] --provider <PROVIDER> --from <FROM> --to <TO>

Options:
      --provider <PROVIDER>      The provider's account address
  -v, --verbose                  Enable verbose logging
      --from <FROM>              Start of the window, inclusive: a UTC date (YYYY-MM-DD) or unix milliseconds
      --to <TO>                  End of the window, exclusive: a UTC date (YYYY-MM-DD) or unix milliseconds
      --period <PERIOD>          Period the statement is cut into: day or month [default: day]
      --format <FORMAT>          Output format: json or csv [default: json]
      --lines                    With csv, one row per call instead of the summary rows
      --verify                   Recompute the statement from chain data and exit non-zero on any difference
      --verify-rpc <VERIFY_RPC>  Node to read the chain from when verifying [default: --rpc]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
      --also-rpc <ALSO_RPC>      Another node the provider served through, such as a platform it moved from; its lines join the statement. Repeat for each
  -h, --help                     Print help
```

### `tenzro provider status`

```
Show provider status

Usage: tenzro provider status [OPTIONS]

Options:
      --address <ADDRESS>  Provider address (optional, uses default wallet if not specified)
  -v, --verbose            Enable verbose logging
      --detailed           Show detailed statistics
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

## `tenzro rails`

```
Settlement rails and micropayment routing

Usage: tenzro rails [OPTIONS] <COMMAND>

Commands:
  list   List every network a payment can settle on
  route  Ask where a specific charge would settle
  help   Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro rails list`

```
List every network a payment can settle on

Usage: tenzro rails list [OPTIONS]

Options:
  -v, --verbose          Enable verbose logging
      --x402-only        Show only rails that can settle an x402 payment
      --asset <ASSET>    Show only rails carrying this asset (e.g. USDC, RLUSD, pUSD)
      --format <FORMAT>  Output format (text, json) [default: text]
      --json             
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro rails route`

```
Ask where a specific charge would settle

Usage: tenzro rails route [OPTIONS] <AMOUNT_WEI>

Arguments:
  <AMOUNT_WEI>  Charge to route, in TNZO wei

Options:
      --asset <ASSET>
          Asset the payee wants to hold. Omit for TNZO on the home chain
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --tnzo-micro-usd <TNZO_MICRO_USD>
          TNZO price in micro-USD, needed to compare against a rail's fee. Without it the node settles on the home chain rather than guessing
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

## `tenzro registry`

```
The generic registry: list, get (read-only)

Usage: tenzro registry [OPTIONS] <COMMAND>

Commands:
  list  List the standing entries of one kind, in id order (read-only)
  get   Show one entry, the latest version or the one named (read-only)
  help  Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro registry get`

```
Show one entry, the latest version or the one named (read-only)

Usage: tenzro registry get [OPTIONS] --id <ID>

Options:
      --id <ID>            Entry id
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --version <VERSION>  A past version of the entry (default: the latest)
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro registry list`

```
List the standing entries of one kind, in id order (read-only)

Usage: tenzro registry list [OPTIONS] --kind <KIND>

Options:
      --kind <KIND>      Entry kind, e.g. unit, card, service, app, dataset
  -v, --verbose          Enable verbose logging
      --after <AFTER>    List ids after this one (the previous page's next)
      --format <FORMAT>  Output format (text, json) [default: text]
      --limit <LIMIT>    Most entries to return (default 100, at most 500)
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro relay`

```
Relayer commands: deliver what other chains report to Tenzro

Usage: tenzro relay [OPTIONS] <COMMAND>

Commands:
  agent-account  Settle a report of an agent's account on another chain
  help           Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro relay agent-account`

```
Settle a report of an agent's account on another chain

Usage: tenzro relay agent-account [OPTIONS] --chain <CHAIN> --agent <AGENT> --delivery <DELIVERY>

Options:
      --chain <CHAIN>                  The chain, CAIP-2
  -v, --verbose                        Enable verbose logging
      --agent <AGENT>                  The agent
      --format <FORMAT>                Output format (text, json) [default: text]
      --delivery <DELIVERY>            The route delivery carrying the report, hex
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

## `tenzro rerank`

```
Rerankers: score documents against a query

Usage: tenzro rerank [OPTIONS] <COMMAND>

Commands:
  catalog  List the reranker catalog
  load     Fetch a catalog reranker onto this node and serve it
  unload   Unload a reranker
  run      Score documents against a query, best first
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro rerank catalog`

```
List the reranker catalog

Usage: tenzro rerank catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro rerank load`

```
Fetch a catalog reranker onto this node and serve it

Usage: tenzro rerank load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro rerank run`

```
Score documents against a query, best first

Usage: tenzro rerank run [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>
          
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --query <QUERY>
          The query
      --query-image <QUERY_IMAGE>
          A picture in the query (PNG, JPEG or WebP), read with the query text. Needs a vision-language reranker
      --query-video-frames <QUERY_VIDEO_FRAMES>...
          A video in the query, as its frames in order, comma-separated. Needs a vision-language reranker
      --document <DOCUMENTS>
          A text document; repeat for each
      --document-image <DOCUMENT_IMAGES>
          A picture document (PNG, JPEG or WebP); repeat for each
      --document-video-frames <DOCUMENT_VIDEOS>
          A video document, as its frames in order, comma-separated; repeat for each video
      --top-n <TOP_N>
          Return only the best N
      --return-documents
          Include each document as given in the answer
      --verification <VERIFICATION>
          Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>
          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro rerank unload`

```
Unload a reranker

Usage: tenzro rerank unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro reserve`

```
Proof-of-Reserve attestations for tokenized assets

Usage: tenzro reserve [OPTIONS] <COMMAND>

Commands:
  submit  Submit a Proof-of-Reserve attestation backing a tokenized asset
  get     Read the current reserve attestation
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro reserve get`

```
Read the current reserve attestation

Usage: tenzro reserve get [OPTIONS] <ASSET_ID>

Arguments:
  <ASSET_ID>  Tokenized-asset id

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro reserve submit`

```
Submit a Proof-of-Reserve attestation backing a tokenized asset

Usage: tenzro reserve submit [OPTIONS] <ATTESTATION>

Arguments:
  <ATTESTATION>  ReserveAttestation JSON (inline or `@file.json`)

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro rpc`

```
Discover and call any JSON-RPC method this node serves

Usage: tenzro rpc [OPTIONS] <COMMAND>

Commands:
  methods  List the methods this node serves, with how each is gated
  call     Call any method by name
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro rpc call`

```
Call any method by name

Usage: tenzro rpc call [OPTIONS] <METHOD>

Arguments:
  <METHOD>  Method name, e.g. `tenzro_previewServe`

Options:
      --params <PARAMS>  Parameters as a JSON object. Defaults to `{}` [default: {}]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro rpc methods`

```
List the methods this node serves, with how each is gated

Usage: tenzro rpc methods [OPTIONS]

Options:
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --namespace <NAMESPACE>  Restrict to one namespace (`eth`, `iroh`, …)
      --contains <CONTAINS>    Case-insensitive substring of the method name
      --namespaces             List the namespaces rather than the methods
  -h, --help                   Print help
```

## `tenzro schedule`

```
Provider schedule management

Usage: tenzro schedule [OPTIONS] <COMMAND>

Commands:
  stacks  Show model stacks: what is serving now, what runs next, and when
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro schedule stacks`

```
Show model stacks: what is serving now, what runs next, and when

Usage: tenzro schedule stacks [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro segment`

```
Image segmentation (SAM 2, EdgeSAM, MobileSAM)

Usage: tenzro segment [OPTIONS] <COMMAND>

Commands:
  catalog  List the curated segmentation catalog (SAM 2, EdgeSAM, MobileSAM)
  load     Fetch a catalog segmenter onto this node and serve it
  unload   Unregister a previously-loaded segmenter
  run      Run a segmentation request given prompts
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro segment catalog`

```
List the curated segmentation catalog (SAM 2, EdgeSAM, MobileSAM)

Usage: tenzro segment catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro segment load`

```
Fetch a catalog segmenter onto this node and serve it

Usage: tenzro segment load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro segment run`

```
Run a segmentation request given prompts

Usage: tenzro segment run [OPTIONS] --model <MODEL> --image <IMAGE> --prompts <PROMPTS>

Options:
      --model <MODEL>                
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --image <IMAGE>                Path to the input image (PNG/JPEG/WebP)
      --prompts <PROMPTS>            JSON file containing a list of SegmentPrompt values. Coordinates are in original-image pixels: `{"type":"point","x":412,"y":310,"is_foreground":true}`, `{"type":"points","points":[{"x":412,"y":310,"is_foreground":true}]}`, `{"type":"box","x0":120,"y0":80,"x1":540,"y1":420}`
      --verification <VERIFICATION>  Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>                    [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro segment unload`

```
Unregister a previously-loaded segmenter

Usage: tenzro segment unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro settle`

```
Settlement plans: legs on several networks, one Commit-or-Abort decision, the split fixed by the quote

Usage: tenzro settle [OPTIONS] <COMMAND>

Commands:
  preview              Preview how a gross amount divides under a split rule
  open                 Open a plan as its payer
  prove                Record that a leg reached its evidence class; commits the plan when it is the last
  dispute              Dispute a rail leg its attestor confirmed, as the leg's payee
  get                  Show a plan
  decision             Show a plan's decision
  receipt              Show one leg's receipt
  list                 List plans
  post-collateral      Post collateral for netted plans
  withdraw-collateral  Withdraw collateral down to what the open batch's net debit needs
  netting              Show an asset's netting batch, and a participant's gross-to-net statement
  reconcile            Reconcile a route's settlement lock against Tenzro's books
  reconciliation       Show how far a route's settlement lock is reconciled
  mismatches           List the reconciliation mismatches stored for a route's settlement lock
  help                 Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro settle decision`

```
Show a plan's decision

Usage: tenzro settle decision [OPTIONS] --plan-id <PLAN_ID>

Options:
      --plan-id <PLAN_ID>  Plan id (32-byte hex)
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro settle dispute`

```
Dispute a rail leg its attestor confirmed, as the leg's payee

Usage: tenzro settle dispute [OPTIONS] --plan-id <PLAN_ID> --index <INDEX> --evidence <EVIDENCE>

Options:
      --plan-id <PLAN_ID>              Plan id (32-byte hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --index <INDEX>                  The rail leg's index
      --evidence <EVIDENCE>            The payee's evidence that the payment did not arrive, hex
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro settle get`

```
Show a plan

Usage: tenzro settle get [OPTIONS] --plan-id <PLAN_ID>

Options:
      --plan-id <PLAN_ID>  Plan id (32-byte hex)
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro settle list`

```
List plans

Usage: tenzro settle list [OPTIONS]

Options:
      --payer <PAYER>    Only plans this payer opened (32-byte hex)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --status <STATUS>  Only plans in this status: open, committed, aborted
      --limit <LIMIT>    Most plans to return [default: 50]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro settle mismatches`

```
List the reconciliation mismatches stored for a route's settlement lock

Usage: tenzro settle mismatches [OPTIONS] --adapter <ADAPTER> --chain <CHAIN>

Options:
      --adapter <ADAPTER>  The route's bridge protocol: ccip, ibc, deposit or contract
  -v, --verbose            Enable verbose logging
      --chain <CHAIN>      The route's external chain
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro settle netting`

```
Show an asset's netting batch, and a participant's gross-to-net statement

Usage: tenzro settle netting [OPTIONS] --asset <ASSET>

Options:
      --asset <ASSET>              Token id of the asset (32-byte hex)
  -v, --verbose                    Enable verbose logging
      --format <FORMAT>            Output format (text, json) [default: text]
      --seq <SEQ>                  Batch number; the latest when omitted
      --participant <PARTICIPANT>  A participant's address (32-byte hex) for its collateral and statement
      --rpc <RPC>                  RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                       Print help
```

### `tenzro settle open`

```
Open a plan as its payer

Usage: tenzro settle open [OPTIONS] --plan <PLAN>

Options:
      --plan <PLAN>                    JSON file holding the `open` operation's fields; a `split_hash` left out is the hash of its `split`
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro settle post-collateral`

```
Post collateral for netted plans

Usage: tenzro settle post-collateral [OPTIONS] --asset <ASSET> --amount <AMOUNT>

Options:
      --asset <ASSET>                  Token id of the asset (32-byte hex; TNZO's id for TNZO)
  -v, --verbose                        Enable verbose logging
      --amount <AMOUNT>                Amount in the asset's smallest unit
      --format <FORMAT>                Output format (text, json) [default: text]
      --agent-auth <AGENT_AUTH>        JSON file holding a delegated agent's signed action (`{ action, signature }`): the collateral is the agent's, moving to or from its wallet under its terms. A post states the amount; a withdrawal states none
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro settle preview`

```
Preview how a gross amount divides under a split rule

Usage: tenzro settle preview [OPTIONS] --gross <GROSS> --split <SPLIT>

Options:
      --gross <GROSS>                Gross amount, wei
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --split <SPLIT>                JSON file holding the split rule
      --network-fees <NETWORK_FEES>  Network fees the payee side bears, wei [default: 0]
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro settle prove`

```
Record that a leg reached its evidence class; commits the plan when it is the last

Usage: tenzro settle prove [OPTIONS] --plan-id <PLAN_ID> --index <INDEX>

Options:
      --plan-id <PLAN_ID>              Plan id (32-byte hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --index <INDEX>                  The leg's index
      --evidence <EVIDENCE>            The leg's evidence, hex: a lock leg's `Locked` event proof, a hash-locked leg's funding proof or, once funded, its preimage; a rail leg's settlement confirmation, sent by its attestor or payee once the plan commits [default: ""]
      --network-fee <NETWORK_FEE>      The fee paid on the leg's network to carry this proof, wei of TNZO; a commit repays it up to the leg's `max_network_fee` [default: 0]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro settle receipt`

```
Show one leg's receipt

Usage: tenzro settle receipt [OPTIONS] --plan-id <PLAN_ID> --index <INDEX>

Options:
      --plan-id <PLAN_ID>  Plan id (32-byte hex)
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --index <INDEX>      The leg's index
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro settle reconcile`

```
Reconcile a route's settlement lock against Tenzro's books

Usage: tenzro settle reconcile [OPTIONS] --adapter <ADAPTER> --chain <CHAIN> --entries <ENTRIES> --checkpoint <CHECKPOINT>

Options:
      --adapter <ADAPTER>              The route's bridge protocol
  -v, --verbose                        Enable verbose logging
      --chain <CHAIN>                  The route's external chain
      --format <FORMAT>                Output format (text, json) [default: text]
      --entries <ENTRIES>              JSON file holding the entries the lock recorded since the last reconciliation, in order: `[{plan_id, leg_id, kind, amount}]`, kind one of locked, released, refunded
      --checkpoint <CHECKPOINT>        The route's proof of the lock's checkpoint, hex
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro settle reconciliation`

```
Show how far a route's settlement lock is reconciled

Usage: tenzro settle reconciliation [OPTIONS] --adapter <ADAPTER> --chain <CHAIN>

Options:
      --adapter <ADAPTER>  The route's bridge protocol: ccip, ibc, deposit or contract
  -v, --verbose            Enable verbose logging
      --chain <CHAIN>      The route's external chain
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro settle withdraw-collateral`

```
Withdraw collateral down to what the open batch's net debit needs

Usage: tenzro settle withdraw-collateral [OPTIONS] --asset <ASSET> --amount <AMOUNT>

Options:
      --asset <ASSET>                  Token id of the asset (32-byte hex; TNZO's id for TNZO)
  -v, --verbose                        Enable verbose logging
      --amount <AMOUNT>                Amount in the asset's smallest unit
      --format <FORMAT>                Output format (text, json) [default: text]
      --agent-auth <AGENT_AUTH>        JSON file holding a delegated agent's signed action (`{ action, signature }`): the collateral is the agent's, moving to or from its wallet under its terms. A post states the amount; a withdrawal states none
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

## `tenzro setup`

```
Guided setup — join the network, provide, validate, or bootstrap a private network

Usage: tenzro setup [OPTIONS]

Options:
      --path <PATH>
          Setup path: "network" (join the public Tenzro network), "local" (create a local or sovereign network), or "private" (join an existing private network) [possible values: network, local, private]
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --rpc <RPC>
          RPC endpoint override for identity provisioning
      --name <NAME>
          Display name for identity provisioning
      --mode <MODE>
          Participation mode on the public network. A shorthand for `--roles`: `consume` selects no serving role, `provide` selects the AI provider role, `validate` selects the validator role. `--roles` wins when both are given, since it says strictly more [possible values: consume, provide, validate]
      --machine-name <MACHINE_NAME>
          Machine name — a label of 3-63 characters, `[a-z0-9-]`, not starting or ending with a hyphen
      --visibility <VISIBILITY>
          Whether this node is reachable from the public internet, or stays reachable only on the local network [possible values: public, private]
      --operator <OPERATOR>
          Who operates this machine: `self` (a human holds the passkey) or `autonomous` (the machine answers for itself via an attestable hardware root). `autonomous` requires a usable TPM 2.0 or, on Apple hardware, a Secure Enclave [possible values: self, autonomous]
      --roles <ROLES>
          Comma-separated roles this node serves, e.g. `validator,ai,storage`
      --access <ACCESS>
          Comma-separated access models offered for provided resources: `on-demand`, `subscription`, `rental`
      --network-name <NETWORK_NAME>
          Name for a new local or sovereign network
      --chain-id <CHAIN_ID>
          Chain id for a new local or sovereign network. Defaults to a random five-digit id, so it collides with neither the local developer chain (1337) nor the preview network (13380)
      --data-dir <DATA_DIR>
          Node data directory. Defaults depend on the chosen path. Also settable via `$TENZRO_DATA_DIR`, the same variable `tenzro-node` itself reads, so a setup and the node it bootstraps agree on where state lives without repeating the flag [env: TENZRO_DATA_DIR=]
      --stake <STAKE>
          Genesis stake for the founding validator (whole TNZO units) [default: 1000]
      --validator-stake <VALIDATOR_STAKE>
          Self-stake a public-network validator registers with: TNZO (`10000`, `10000 TNZO`) or wei with its suffix. The network's minimum is the governed `stake.validator_tnzo` (10,000 TNZO at genesis) [default: 10000]
      --bootstrap <BOOTSTRAP>
          Boot identity of an existing private network, as its operator prints it: `did:tenzro:machine:<id>@<relay url>`
      --genesis <GENESIS>
          Path to the genesis.toml of an existing private network
      --provision-tpm
          Create this machine's TPM keys with `tenzro-node tpm provision` without asking, when the preflight finds they are missing. Without this flag the wizard asks, and a non-interactive run stops and prints the command. Implied by --apply
      --apply
          After setup, install the node as a service, start it, and follow it until it has synced. On Linux this runs `sudo` for the systemd unit; on macOS it loads a launch agent. Interactive runs are asked instead
      --yes
          Non-interactive: accept defaults, take everything else from flags
  -h, --help
          Print help
```

## `tenzro speech`

```
Speech synthesis (text to speech)

Usage: tenzro speech [OPTIONS] <COMMAND>

Commands:
  catalog  List the speech model catalog
  load     Fetch a catalog speech model onto this node and serve it
  unload   Unload a speech model
  speak    Speak text into a WAV file
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro speech catalog`

```
List the speech model catalog

Usage: tenzro speech catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro speech load`

```
Fetch a catalog speech model onto this node and serve it

Usage: tenzro speech load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro speech speak`

```
Speak text into a WAV file

Usage: tenzro speech speak [OPTIONS] --model <MODEL> --text <TEXT> --out <OUT>

Options:
      --model <MODEL>
          
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --text <TEXT>
          The text to speak
      --language <LANGUAGE>
          Language code (en, zh, ...)
      --voice-reference <VOICE_REFERENCE>
          Reference audio of the voice (wav, mp3, flac); the node must allow cloning
      --seed <SEED>
          Seed; the same seed, text and voice give the same audio
      --out <OUT>
          Where to write the WAV
      --channel-voucher <CHANNEL_VOUCHER>
          A signed channel voucher (`tenzro escrow voucher --out`) the call's metered cost is charged against
      --verification <VERIFICATION>
          Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>
          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro speech unload`

```
Unload a speech model

Usage: tenzro speech unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro sponsor`

```
Sponsorship: check eligibility, prepare an application, see status

Usage: tenzro sponsor [OPTIONS] <COMMAND>

Commands:
  check   Report whether this operator qualifies for sponsorship (read-only)
  apply   Prepare a sponsorship application: the proposal a proposer files and the grant request you can file yourself
  status  Show the approval record, what sponsorship has paid, and any proposal in flight (read-only)
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro sponsor apply`

```
Prepare a sponsorship application: the proposal a proposer files and the grant request you can file yourself

Usage: tenzro sponsor apply [OPTIONS]

Options:
      --rpc <RPC>                    The node's RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose                      Enable verbose logging
      --account <ACCOUNT>            Operator account (64 hex). Defaults to the node's own account
      --format <FORMAT>              Output format (text, json) [default: text]
      --did <DID>                    Machine identity (did:tenzro:machine:...). Defaults to the node's
      --hours <HOURS>                How many past hours of availability to count [default: 168]
      --json                         Print the gathered facts as JSON instead of the readout
      --region <REGION>              Where the operator runs (shown to voters) [default: <region>]
      --independence <INDEPENDENCE>  The operator's independence declaration, or a link to it [default: <independence-statement-or-link>]
      --grant-amount <GRANT_AMOUNT>  Stake the grant request asks for: TNZO (`10000`) or wei with its suffix [default: 10000]
      --out <OUT>                    Write the application summary here instead of ~/.tenzro/sponsor-application.json
  -h, --help                         Print help
```

### `tenzro sponsor check`

```
Report whether this operator qualifies for sponsorship (read-only)

Usage: tenzro sponsor check [OPTIONS]

Options:
      --rpc <RPC>          The node's RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose            Enable verbose logging
      --account <ACCOUNT>  Operator account (64 hex). Defaults to the node's own account
      --format <FORMAT>    Output format (text, json) [default: text]
      --did <DID>          Machine identity (did:tenzro:machine:...). Defaults to the node's
      --hours <HOURS>      How many past hours of availability to count [default: 168]
      --json               Print the gathered facts as JSON instead of the readout
  -h, --help               Print help
```

### `tenzro sponsor status`

```
Show the approval record, what sponsorship has paid, and any proposal in flight (read-only)

Usage: tenzro sponsor status [OPTIONS]

Options:
      --rpc <RPC>          The node's RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose            Enable verbose logging
      --account <ACCOUNT>  Operator account (64 hex). Defaults to the node's own account
      --format <FORMAT>    Output format (text, json) [default: text]
      --did <DID>          Machine identity (did:tenzro:machine:...). Defaults to the node's
      --hours <HOURS>      How many past hours of availability to count [default: 168]
      --json               Print the gathered facts as JSON instead of the readout
  -h, --help               Print help
```

## `tenzro stake`

```
Staking commands

Usage: tenzro stake [OPTIONS] <COMMAND>

Commands:
  bond             Bond stake for a role
  unbond           Start unbonding stake for a role
  withdraw         Withdraw unbonded stake for a role once its period has passed
  info             Show an account's stake per role (read-only)
  wallet-provider  Show whether a staked wallet provider serves a passkey domain (read-only)
  endpoint         Publish, or clear, the public URL a bonded role is served at
  endpoints        List a role's staked operators and the URLs they published (read-only)
  relays           List the relays staked edge operators serve, with their last SLA verdict and the node's latest check (read-only)
  help             Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro stake bond`

```
Bond stake for a role

Usage: tenzro stake bond [OPTIONS] --role <ROLE> --amount <AMOUNT>

Options:
      --role <ROLE>                    Role: rpc, tee, ai, compute, storage, attestor, wallet, catalog or edge (relay)
  -v, --verbose                        Enable verbose logging
      --amount <AMOUNT>                Amount: whole or fractional TNZO (`10000`, `10000 TNZO`, `0.5tnzo`) or wei with its suffix (`250000000000000000wei`)
      --format <FORMAT>                Output format (text, json) [default: text]
      --domain <DOMAIN>                The relying-party domain your passkeys are bound to, for wallet. The domain must serve /.well-known/tenzro-provider naming the bonding account
      --bridge-signer <BRIDGE_SIGNER>  For attestor: the 20-byte secp256k1 address (hex) you sign bridge deliveries with, which makes you eligible for bridge route committees
      --rpc-provider <RPC_PROVIDER>    For attestor with a bridge signer: the RPC provider you read source chains from
      --signer-proof <SIGNER_PROOF>    For attestor with a bridge signer: that key's 65-byte recoverable signature (hex) over the bridge signer digest of the bonding account
      --pq-public-key <PQ_PUBLIC_KEY>  For attestor with a bridge signer: the ML-DSA-65 verifying key (hex, 1952 bytes) of the signer's second leg. Both legs are mandatory
      --pq-proof <PQ_PROOF>            For attestor with a bridge signer: the ML-DSA-65 key's signature (hex) over the same bridge signer digest, context `tenzro/bridge/signer/ml-dsa-65`
      --accelerators <ACCELERATORS>    Accelerator classes pledged, for compute (integrated, consumer, workstation, datacentre)
      --terabytes <TERABYTES>          Whole terabytes pledged, for storage
      --key-namespace <KEY_NAMESPACE>  The staking account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro stake endpoint`

```
Publish, or clear, the public URL a bonded role is served at

Usage: tenzro stake endpoint [OPTIONS] --role <ROLE> --url <URL>

Options:
      --role <ROLE>                    Role
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --url <URL>                      Public https URL of your own edge in front of the role, or "" to clear
      --key-namespace <KEY_NAMESPACE>  The staking account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro stake endpoints`

```
List a role's staked operators and the URLs they published (read-only)

Usage: tenzro stake endpoints [OPTIONS]

Options:
      --role <ROLE>      Role [default: rpc]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro stake info`

```
Show an account's stake per role (read-only)

Usage: tenzro stake info [OPTIONS]

Options:
      --address <ADDRESS>  Account to query (defaults to the node's operator payee)
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro stake relays`

```
List the relays staked edge operators serve, with their last SLA verdict and the node's latest check (read-only)

Usage: tenzro stake relays [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro stake unbond`

```
Start unbonding stake for a role

Usage: tenzro stake unbond [OPTIONS] --role <ROLE> --amount <AMOUNT>

Options:
      --role <ROLE>                    Role
  -v, --verbose                        Enable verbose logging
      --amount <AMOUNT>                Amount: TNZO (`100`, `100 TNZO`) or wei with its suffix (`100wei`)
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The staking account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro stake wallet-provider`

```
Show whether a staked wallet provider serves a passkey domain (read-only)

Usage: tenzro stake wallet-provider [OPTIONS] <RP_ID>

Arguments:
  <RP_ID>  The relying-party domain (RP ID) a wallet's passkeys are bound to

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro stake withdraw`

```
Withdraw unbonded stake for a role once its period has passed

Usage: tenzro stake withdraw [OPTIONS] --role <ROLE>

Options:
      --role <ROLE>                    Role
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The staking account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

## `tenzro status`

```
Live resource and traffic status for this node

Usage: tenzro status [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --watch [<MS>]     Redraw the screen in place every N milliseconds (2000 when no value is given) until interrupted
      --json             Print one JSON object instead of the formatted readout
  -h, --help             Print help
```

## `tenzro tee`

```
TEE operations (detect, attest, challenge, verify, providers)

Usage: tenzro tee [OPTIONS] <COMMAND>

Commands:
  detect     Detect available TEE hardware on this node
  attest     Get a TEE attestation quote
  challenge  Get a single-use nonce an attestation report must answer
  verify     Verify a TEE attestation report against a nonce from `challenge`
  providers  List registered TEE providers on the network
  help       Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro tee attest`

```
Get a TEE attestation quote

Usage: tenzro tee attest [OPTIONS]

Options:
      --user-data <USER_DATA>  Hex data the report commits to (64 zero bytes when omitted)
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --out <OUT>              Write the report (JSON, as `tee verify --report` takes its hex) to this file
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro tee challenge`

```
Get a single-use nonce an attestation report must answer

Usage: tenzro tee challenge [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro tee detect`

```
Detect available TEE hardware on this node

Usage: tenzro tee detect [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro tee providers`

```
List registered TEE providers on the network

Usage: tenzro tee providers [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro tee verify`

```
Verify a TEE attestation report against a nonce from `challenge`

Usage: tenzro tee verify [OPTIONS] --report <REPORT> --nonce <NONCE>

Options:
      --report <REPORT>          Hex of the JSON attestation report, including its vendor collateral
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --nonce <NONCE>            The nonce from `tenzro tee challenge` the report answers
      --bound-data <BOUND_DATA>  Hex of any extra data the report binds alongside the nonce
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

## `tenzro text-segment`

```
Open-vocabulary text-promptable segmentation (SAM 3, SAM 3.1)

Usage: tenzro text-segment [OPTIONS] <COMMAND>

Commands:
  catalog  List the curated text-segmentation catalog (SAM 3, SAM 3.1)
  load     Fetch a catalog SAM-3 bundle onto this node and serve it
  unload   Unregister a previously-loaded text-promptable segmenter
  run      Run an open-vocabulary text-prompt segmentation
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro text-segment catalog`

```
List the curated text-segmentation catalog (SAM 3, SAM 3.1)

Usage: tenzro text-segment catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro text-segment load`

```
Fetch a catalog SAM-3 bundle onto this node and serve it

Usage: tenzro text-segment load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro text-segment run`

```
Run an open-vocabulary text-prompt segmentation

Usage: tenzro text-segment run [OPTIONS] --model <MODEL> --image <IMAGE> --text <TEXT>

Options:
      --model <MODEL>
          Model id of a loaded SAM-3 segmenter
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --image <IMAGE>
          Path to the input image (PNG/JPEG/WebP)
      --text <TEXT>
          Free-text label to segment (e.g. `"person"`, `"sofa"`, `"dog"`)
      --box <BOX>
          Optional normalized cxcywh box prompt, four floats in `[0,1]` (e.g. `--box "0.5,0.5,0.3,0.4"`)
      --score-threshold <SCORE_THRESHOLD>
          Score threshold in `[0, 1]` [default: 0.5]
      --verification <VERIFICATION>
          Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>
          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>
          [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro text-segment unload`

```
Unregister a previously-loaded text-promptable segmenter

Usage: tenzro text-segment unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro token`

```
Token management commands (create, query, cross-VM transfers)

Usage: tenzro token [OPTIONS] <COMMAND>

Commands:
  por-reserve                         Call tenzro_readPorReserve (read por reserve) and print the node's answer
  reserve-feed                        Call tenzro_getReserveFeed: the reserve feed governance installed for an asset
  build-reserve-attestation-from-por  Call tenzro_buildReserveAttestationFromPor (build reserve attestation from por) and print the node's answer
  create                              Create a token issued by the client account (signed in hardware)
  mint                                Issue more of a token (by its mint authority)
  burn                                Retire part of the client account's balance
  transfer                            Move part of the client account's balance
  freeze                              Freeze part of a holder's balance (freeze authority; zero unfreezes)
  halt                                Halt or resume holder transfers (halt authority)
  force-transfer                      Move a holder's balance past a halt or a freeze (force authority)
  renounce                            Narrow who holds an issuer power (never widens)
  set-policy                          Queue a new eligibility policy (applies after the policy timelock)
  set-reserve-backing                 Queue new reserve backing (applies after the policy timelock)
  execute-policy                      Apply a queued policy or reserve-backing change whose timelock has passed
  claim                               Record a claim about an account (a claim issuer the token names)
  revoke-claim                        Withdraw a claim the client account made
  approve                             Approve an issuer operation as an issuer-council member
  can-transfer                        Check whether the token's rules allow a transfer now
  info                                Get information about a token
  list                                List registered tokens
  balance                             Get token balance across all VMs
  help                                Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro token approve`

```
Approve an issuer operation as an issuer-council member

Usage: tenzro token approve [OPTIONS] --op <OP>

Options:
      --op <OP>                        The issuer operation as TokenOp JSON (for example a set_frozen op)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token balance`

```
Get token balance across all VMs

Usage: tenzro token balance [OPTIONS] <ADDRESS>

Arguments:
  <ADDRESS>  Address to query (hex)

Options:
      --token <TOKEN>    Token symbol (default: TNZO) [default: TNZO]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro token build-reserve-attestation-from-por`

```
Call tenzro_buildReserveAttestationFromPor (build reserve attestation from por) and print the node's answer

Usage: tenzro token build-reserve-attestation-from-por [OPTIONS] --asset-id <ASSET_ID> --attestor-did <ATTESTOR_DID>

Options:
      --asset-id <ASSET_ID>          asset id
  -v, --verbose                      Enable verbose logging
      --attestor-did <ATTESTOR_DID>  attestor did
      --format <FORMAT>              Output format (text, json) [default: text]
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro token burn`

```
Retire part of the client account's balance

Usage: tenzro token burn [OPTIONS] --token-id <TOKEN_ID> --amount <AMOUNT>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --amount <AMOUNT>                Amount (smallest units)
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token can-transfer`

```
Check whether the token's rules allow a transfer now

Usage: tenzro token can-transfer [OPTIONS] --token-id <TOKEN_ID> --from <FROM> --to <TO> --amount <AMOUNT>

Options:
      --token-id <TOKEN_ID>  Token id (hex)
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --from <FROM>          Sender (hex)
      --to <TO>              Recipient (hex)
      --amount <AMOUNT>      Amount (smallest units)
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro token claim`

```
Record a claim about an account (a claim issuer the token names)

Usage: tenzro token claim [OPTIONS] --token-id <TOKEN_ID> --subject <SUBJECT> --kind <KIND> --expires-ms <EXPIRES_MS>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --subject <SUBJECT>              Account the claim is about (hex)
      --kind <KIND>                    Claim kind (kyc, accredited, jurisdiction, ...)
      --value <VALUE>                  Claim value (a jurisdiction code, a level, ...) [default: ""]
      --expires-ms <EXPIRES_MS>        Block time (Unix ms) the claim lapses at
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token create`

```
Create a token issued by the client account (signed in hardware)

Usage: tenzro token create [OPTIONS] --name <NAME> --symbol <SYMBOL> --supply <SUPPLY> --powers <POWERS> --policy <POLICY>

Options:
      --name <NAME>
          Token name (e.g. "My Token")
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --symbol <SYMBOL>
          Token symbol (e.g. "MTK")
      --supply <SUPPLY>
          Initial supply credited to the issuer (smallest units)
      --decimals <DECIMALS>
          Token decimals [default: 18]
      --max-supply <MAX_SUPPLY>
          Ceiling on the supply (smallest units)
      --powers <POWERS>
          Power manifest JSON, e.g. '{"mint":"issuer","freeze":"disabled",...}'
      --policy <POLICY>
          Eligibility policy JSON: '{"eligibility":[...],"policy_timelock_ms":604800000}'
      --council <COUNCIL>
          Issuer council JSON '{"k":2,"members":["<hex>",...]}', when a power names one
      --reserve-attestor-stake <RESERVE_ATTESTOR_STAKE>
          For a token backed one to one by reserves: the bonded attestor stake, whole TNZO, each mint's reserve attestations must hold between them. Any bonded attestor may attest
      --key-namespace <KEY_NAMESPACE>
          The signing account's hardware key namespace [default: client]
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro token execute-policy`

```
Apply a queued policy or reserve-backing change whose timelock has passed

Usage: tenzro token execute-policy [OPTIONS] --token-id <TOKEN_ID>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token force-transfer`

```
Move a holder's balance past a halt or a freeze (force authority)

Usage: tenzro token force-transfer [OPTIONS] --token-id <TOKEN_ID> --from <FROM> --to <TO> --amount <AMOUNT> --reason-code <REASON_CODE> --evidence <EVIDENCE>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --from <FROM>                    Holder debited (hex)
      --to <TO>                        Account credited (hex)
      --amount <AMOUNT>                Amount (smallest units)
      --reason-code <REASON_CODE>      Issuer reason code (non-zero)
      --evidence <EVIDENCE>            SHA-256 of the evidence held off-chain (hex)
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token freeze`

```
Freeze part of a holder's balance (freeze authority; zero unfreezes)

Usage: tenzro token freeze [OPTIONS] --token-id <TOKEN_ID> --account <ACCOUNT> --amount <AMOUNT> --reason-code <REASON_CODE> --evidence <EVIDENCE>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --account <ACCOUNT>              Holder account (hex)
      --format <FORMAT>                Output format (text, json) [default: text]
      --amount <AMOUNT>                Amount frozen (smallest units)
      --reason-code <REASON_CODE>      Issuer reason code (non-zero)
      --evidence <EVIDENCE>            SHA-256 of the evidence held off-chain (hex)
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token halt`

```
Halt or resume holder transfers (halt authority)

Usage: tenzro token halt [OPTIONS] --token-id <TOKEN_ID> --reason-code <REASON_CODE> --evidence <EVIDENCE>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --resume                         Resume transfers instead of halting them
      --reason-code <REASON_CODE>      Issuer reason code (non-zero)
      --evidence <EVIDENCE>            SHA-256 of the evidence held off-chain (hex)
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token info`

```
Get information about a token

Usage: tenzro token info [OPTIONS]

Options:
      --symbol <SYMBOL>    Token symbol (e.g. "TNZO")
  -v, --verbose            Enable verbose logging
      --address <ADDRESS>  EVM contract address
      --format <FORMAT>    Output format (text, json) [default: text]
      --id <ID>            Token ID (hex)
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro token list`

```
List registered tokens

Usage: tenzro token list [OPTIONS]

Options:
  -v, --verbose          Enable verbose logging
      --vm <VM>          Filter by VM type: evm, svm, native
      --format <FORMAT>  Output format (text, json) [default: text]
      --limit <LIMIT>    Maximum tokens to list [default: 50]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro token mint`

```
Issue more of a token (by its mint authority)

Usage: tenzro token mint [OPTIONS] --token-id <TOKEN_ID> --to <TO> --amount <AMOUNT>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --to <TO>                        Recipient account (hex)
      --amount <AMOUNT>                Amount (smallest units)
      --reserve <RESERVE>              JSON files holding the reserve attestations a reserve-backed token needs (one per attestor)
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token por-reserve`

```
Call tenzro_readPorReserve (read por reserve) and print the node's answer

Usage: tenzro token por-reserve [OPTIONS] --asset-id <ASSET_ID>

Options:
      --asset-id <ASSET_ID>  asset id
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro token renounce`

```
Narrow who holds an issuer power (never widens)

Usage: tenzro token renounce [OPTIONS] --token-id <TOKEN_ID> --power <POWER> --to <TO>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --power <POWER>                  The power: mint, freeze, halt, force or policy_change
      --to <TO>                        Who holds it afterwards, JSON: '"disabled"' or '{"issuer_council":{"k":3}}'
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token reserve-feed`

```
Call tenzro_getReserveFeed: the reserve feed governance installed for an asset

Usage: tenzro token reserve-feed [OPTIONS] --asset-id <ASSET_ID>

Options:
      --asset-id <ASSET_ID>  asset id (`tnzo:<route key>` for a bridge route)
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro token revoke-claim`

```
Withdraw a claim the client account made

Usage: tenzro token revoke-claim [OPTIONS] --token-id <TOKEN_ID> --subject <SUBJECT> --kind <KIND>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --subject <SUBJECT>              Account the claim is about (hex)
      --kind <KIND>                    Claim kind
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token set-policy`

```
Queue a new eligibility policy (applies after the policy timelock)

Usage: tenzro token set-policy [OPTIONS] --token-id <TOKEN_ID> --policy <POLICY>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --policy <POLICY>                Policy JSON: '{"eligibility":[...],"policy_timelock_ms":604800000}'
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro token set-reserve-backing`

```
Queue new reserve backing (applies after the policy timelock)

Usage: tenzro token set-reserve-backing [OPTIONS] --token-id <TOKEN_ID>

Options:
      --token-id <TOKEN_ID>
          Token id (hex)
  -v, --verbose
          Enable verbose logging
      --attestor-stake <ATTESTOR_STAKE>
          Bonded attestor stake, whole TNZO, each mint's reserve attestations must hold between them; omit to remove the backing
      --format <FORMAT>
          Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>
          The signing account's hardware key namespace [default: client]
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro token transfer`

```
Move part of the client account's balance

Usage: tenzro token transfer [OPTIONS] --token-id <TOKEN_ID> --to <TO> --amount <AMOUNT>

Options:
      --token-id <TOKEN_ID>            Token id (hex)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --to <TO>                        Recipient account (hex)
      --amount <AMOUNT>                Amount (smallest units)
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

## `tenzro training`

```
LoRA training on this node's CUDA device (operator only)

Usage: tenzro training [OPTIONS] <COMMAND>

Commands:
  load    Load a downloaded catalog language model for training
  unload  Unload a model loaded for training
  round   Run one supervised LoRA round
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro training load`

```
Load a downloaded catalog language model for training

Usage: tenzro training load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    Catalog model id, downloaded with `tenzro model download`
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro training round`

```
Run one supervised LoRA round

Usage: tenzro training round [OPTIONS] --model <MODEL> --round <ROUND>

Options:
      --model <MODEL>    Model id loaded for training
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --round <ROUND>    JSON file holding the round: `recipe`, `records` (`[{ prompt, completion }]`), `sample_seed`, `steps`, `adapter_seed`, and optionally `start` (`{ state_uri, start_root, steps_taken }`) and `verification`
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro training unload`

```
Unload a model loaded for training

Usage: tenzro training unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    Catalog model id, downloaded with `tenzro model download`
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro transcribe`

```
Audio transcription / ASR (Moonshine, Distil-Whisper, Parakeet, Canary)

Usage: tenzro transcribe [OPTIONS] <COMMAND>

Commands:
  catalog  List the curated audio ASR catalog (Moonshine, Whisper, Parakeet, Canary)
  load     Fetch a catalog ASR model onto this node and serve it
  unload   Unregister a previously-loaded transcriber
  run      Run an ASR request on an audio file
  stream   Stream a 16-bit PCM WAV to the node in chunks and print partial and final transcripts as they arrive (`/tenzro/realtime/transcribe`)
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro transcribe catalog`

```
List the curated audio ASR catalog (Moonshine, Whisper, Parakeet, Canary)

Usage: tenzro transcribe catalog [OPTIONS]

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro transcribe load`

```
Fetch a catalog ASR model onto this node and serve it

Usage: tenzro transcribe load [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>            Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --visibility <VISIBILITY>  Visibility override: `public`, `gated` or `private`. Omit to follow the node's visibility
      --rpc <RPC>                [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro transcribe run`

```
Run an ASR request on an audio file

Usage: tenzro transcribe run [OPTIONS] --model <MODEL> --audio <AUDIO>

Options:
      --model <MODEL>                
  -v, --verbose                      Enable verbose logging
      --audio <AUDIO>                Path to the input audio (WAV/MP3/FLAC)
      --format <FORMAT>              Output format (text, json) [default: text]
      --language <LANGUAGE>          Optional language ISO code (e.g. "en", "fr"). Auto-detect if omitted
      --timestamps                   Emit per-segment timestamps when supported
      --temperature <TEMPERATURE>    Optional decoding temperature (sampling-capable models)
      --verification <VERIFICATION>  Verification level: none, receipt, optimistic or tee. A call for a model the node does not serve is forwarded to a provider offering it, and an optimistic answer may be re-executed on another provider
      --provider <PROVIDER>          Serve on this provider's offer (its payee address, hex)
      --rpc <RPC>                    [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro transcribe stream`

```
Stream a 16-bit PCM WAV to the node in chunks and print partial and final transcripts as they arrive (`/tenzro/realtime/transcribe`)

Usage: tenzro transcribe stream [OPTIONS] --model <MODEL> --audio <AUDIO>

Options:
      --model <MODEL>                ASR model served by the node
  -v, --verbose                      Enable verbose logging
      --audio <AUDIO>                16-bit PCM WAV to stream (the first channel is sent)
      --format <FORMAT>              Output format (text, json) [default: text]
      --language <LANGUAGE>          Optional language ISO code (e.g. "en", "fr")
      --chunk-ms <CHUNK_MS>          Milliseconds of audio per chunk line [default: 200]
      --verification <VERIFICATION>  Verification level for each final segment: none, receipt, optimistic or tee
      --rpc <RPC>                    [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

### `tenzro transcribe unload`

```
Unregister a previously-loaded transcriber

Usage: tenzro transcribe unload [OPTIONS] --model <MODEL>

Options:
      --model <MODEL>    
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro trust`

```
Certifications, operator policies and model provenance

Usage: tenzro trust [OPTIONS] <COMMAND>

Commands:
  host-model               Call tenzro_hostModel (host model) and print the node's answer
  scan-model-files         Call tenzro_scanModelFiles (scan model files) and print the node's answer
  verify-model-files       Call tenzro_verifyModelFiles (verify model files) and print the node's answer
  publish-tee-measurement  Log the measurement of the TEE this machine runs in (tenzro_publishTeeMeasurement)
  whoami                   Print the DID a hardware key derives
  sign                     Sign a trust document with a hardware key
  submit                   Submit a signed record (or a manifest) to a node
  verify                   Verify a credential against a node's revocation state
  draft-credential         Draft an unsigned certification, rating, evaluation or scan credential
  draft-revocation         Draft an unsigned revocation of status list entries
  draft-issuer-revocation  Draft an unsigned revocation of an issuer's own key
  draft-policy             Draft an unsigned operator policy from a terms file
  draft-violation          Assemble violation evidence from a signed policy and a signed receipt
  verify-file              Check one downloaded file against a model's manifest root
  manifest                 Hash a local model directory into a content-addressed manifest
  observe-hub              Draft an unsigned Hugging Face origin observation from a saved Hub revision listing (`/api/models/<repo>/revision/<commit>?blobs=true`)
  credentials              Credentials stated about a model or operator
  status-list              An issuer's revocation status list
  policy                   An operator's policy, history and proven violations
  provenance               A model's manifests, observations and verification status
  help                     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro trust credentials`

```
Credentials stated about a model or operator

Usage: tenzro trust credentials [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro trust draft-credential`

```
Draft an unsigned certification, rating, evaluation or scan credential

Usage: tenzro trust draft-credential [OPTIONS] --issuer <ISSUER> --subject <SUBJECT> --kind <KIND> --scheme <SCHEME> --index <INDEX>

Options:
      --issuer <ISSUER>          Issuer DID (from `tenzro trust whoami`)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --subject <SUBJECT>        `tenzro:model:<root>` or an operator DID
      --kind <KIND>              certification, rating, evaluation, safety-scan or policy-conformance
      --scheme <SCHEME>          
      --grade <GRADE>            
      --score <SCORE>            0..=10000
      --scope <SCOPE>            
      --evidence <EVIDENCE>      Report reference as `<uri>=<sha256 hex>`; repeatable
      --valid-days <VALID_DAYS>  [default: 365]
      --index <INDEX>            Status list index this credential occupies in the issuer's list
      --out <OUT>                
  -h, --help                     Print help
```

### `tenzro trust draft-issuer-revocation`

```
Draft an unsigned revocation of an issuer's own key

Usage: tenzro trust draft-issuer-revocation [OPTIONS] --issuer <ISSUER>

Options:
      --issuer <ISSUER>  
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --reason <REASON>  [default: ""]
      --out <OUT>        
  -h, --help             Print help
```

### `tenzro trust draft-policy`

```
Draft an unsigned operator policy from a terms file

Usage: tenzro trust draft-policy [OPTIONS] --operator <OPERATOR> --sequence <SEQUENCE> --terms <TERMS>

Options:
      --operator <OPERATOR>      
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --sequence <SEQUENCE>      
      --terms <TERMS>            
      --valid-days <VALID_DAYS>  [default: 90]
      --out <OUT>                
  -h, --help                     Print help
```

### `tenzro trust draft-revocation`

```
Draft an unsigned revocation of status list entries

Usage: tenzro trust draft-revocation [OPTIONS] --issuer <ISSUER> --index <INDEX>

Options:
      --issuer <ISSUER>  
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --index <INDEX>    
      --out <OUT>        
  -h, --help             Print help
```

### `tenzro trust draft-violation`

```
Assemble violation evidence from a signed policy and a signed receipt

Usage: tenzro trust draft-violation [OPTIONS] --policy <POLICY> --receipt <RECEIPT> --clause <CLAUSE>

Options:
      --policy <POLICY>    
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --receipt <RECEIPT>  A signed jurisdiction receipt, as returned with an inference response
      --clause <CLAUSE>    `serves.models` or `jurisdictions`
      --out <OUT>          
  -h, --help               Print help
```

### `tenzro trust host-model`

```
Call tenzro_hostModel (host model) and print the node's answer

Usage: tenzro trust host-model [OPTIONS] --path <PATH>

Options:
      --name <NAME>      name
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --root <ROOT>      root
      --path <PATH>      path
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro trust manifest`

```
Hash a local model directory into a content-addressed manifest

Usage: tenzro trust manifest [OPTIONS] --name <NAME> --path <PATH>

Options:
      --name <NAME>      
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --path <PATH>      
      --out <OUT>        
  -h, --help             Print help
```

### `tenzro trust observe-hub`

```
Draft an unsigned Hugging Face origin observation from a saved Hub revision listing (`/api/models/<repo>/revision/<commit>?blobs=true`)

Usage: tenzro trust observe-hub [OPTIONS] --repo <REPO> --listing <LISTING> --observer <OBSERVER>

Options:
      --repo <REPO>          
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --listing <LISTING>    
      --observer <OBSERVER>  
      --out <OUT>            
  -h, --help                 Print help
```

### `tenzro trust policy`

```
An operator's policy, history and proven violations

Usage: tenzro trust policy [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro trust provenance`

```
A model's manifests, observations and verification status

Usage: tenzro trust provenance [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro trust publish-tee-measurement`

```
Log the measurement of the TEE this machine runs in (tenzro_publishTeeMeasurement)

Usage: tenzro trust publish-tee-measurement [OPTIONS] --report <REPORT> --nonce <NONCE> --measurement <MEASUREMENT>

Options:
      --report <REPORT>                Path to the attestation report (JSON)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --nonce <NONCE>                  The challenge nonce the report answers, hex
      --measurement <MEASUREMENT>      The report's measurement, hex (the node checks it against the report)
      --key-namespace <KEY_NAMESPACE>  The hardware key namespace of the signing account [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro trust scan-model-files`

```
Call tenzro_scanModelFiles (scan model files) and print the node's answer

Usage: tenzro trust scan-model-files [OPTIONS] --path <PATH>

Options:
      --name <NAME>      name
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --root <ROOT>      root
      --path <PATH>      path
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro trust sign`

```
Sign a trust document with a hardware key

Usage: tenzro trust sign [OPTIONS] --doc <DOC> --key-label <KEY_LABEL>

Options:
      --doc <DOC>              
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --key-label <KEY_LABEL>  
      --out <OUT>              
  -h, --help                   Print help
```

### `tenzro trust status-list`

```
An issuer's revocation status list

Usage: tenzro trust status-list [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro trust submit`

```
Submit a signed record (or a manifest) to a node

Usage: tenzro trust submit [OPTIONS] --file <FILE>

Options:
      --file <FILE>      
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro trust verify`

```
Verify a credential against a node's revocation state

Usage: tenzro trust verify [OPTIONS] --file <FILE>

Options:
      --file <FILE>      
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro trust verify-file`

```
Check one downloaded file against a model's manifest root

Usage: tenzro trust verify-file [OPTIONS] --root <ROOT> --file <FILE> --path <PATH>

Options:
      --root <ROOT>      
  -v, --verbose          Enable verbose logging
      --file <FILE>      The file's path inside the model
      --format <FORMAT>  Output format (text, json) [default: text]
      --path <PATH>      The downloaded file on this machine
      --rpc <RPC>        [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro trust verify-model-files`

```
Call tenzro_verifyModelFiles (verify model files) and print the node's answer

Usage: tenzro trust verify-model-files [OPTIONS] --path <PATH>

Options:
      --name <NAME>      name
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --root <ROOT>      root
      --path <PATH>      path
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro trust whoami`

```
Print the DID a hardware key derives

Usage: tenzro trust whoami [OPTIONS] --key-label <KEY_LABEL>

Options:
      --key-label <KEY_LABEL>  
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
  -h, --help                   Print help
```

## `tenzro tx`

```
Transaction inspection

Usage: tenzro tx [OPTIONS] <COMMAND>

Commands:
  explain          Show what a privileged transaction does and the digest it is signed over, decoded locally from its typed preimage
  signing-payload  Ask a node what an unsigned transaction is signed over: the canonical `tx_type` encoding, or the typed preimage, and the digest
  help             Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro tx explain`

```
Show what a privileged transaction does and the digest it is signed over, decoded locally from its typed preimage

Usage: tenzro tx explain [OPTIONS] <INPUT>

Arguments:
  <INPUT>  An unsigned transaction as JSON, or the hex preimage a wallet was asked to sign

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro tx signing-payload`

```
Ask a node what an unsigned transaction is signed over: the canonical `tx_type` encoding, or the typed preimage, and the digest

Usage: tenzro tx signing-payload [OPTIONS] <INPUT>

Arguments:
  <INPUT>  The unsigned transaction as `tenzro_sendRawTransaction` takes it (JSON, or a file holding it), without signatures

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro urwa`

```
ERC-7943 (uRWA) tokenized RWA compliance: kill-switch / freeze / forced-transfer

Usage: tenzro urwa [OPTIONS] <COMMAND>

Commands:
  is-kill-switched   Check whether the kill-switch is active for a token
  get-frozen-tokens  Read the frozen-token amount for a (token, account) pair
  help               Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro urwa get-frozen-tokens`

```
Read the frozen-token amount for a (token, account) pair

Usage: tenzro urwa get-frozen-tokens [OPTIONS] --token-id <TOKEN_ID> --account <ACCOUNT>

Options:
      --token-id <TOKEN_ID>  
  -v, --verbose              Enable verbose logging
      --account <ACCOUNT>    20-byte hex-encoded account address
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

### `tenzro urwa is-kill-switched`

```
Check whether the kill-switch is active for a token

Usage: tenzro urwa is-kill-switched [OPTIONS] --token-id <TOKEN_ID>

Options:
      --token-id <TOKEN_ID>  32-byte hex-encoded token id (with or without 0x)
  -v, --verbose              Enable verbose logging
      --format <FORMAT>      Output format (text, json) [default: text]
      --rpc <RPC>            [default: http://127.0.0.1:8545]
  -h, --help                 Print help
```

## `tenzro validator`

```
Validator set (Dynamic Validator Set): register, exit, update-metadata, get, list

Usage: tenzro validator [OPTIONS] <COMMAND>

Commands:
  register            Register a new validator candidate (signed RegisterValidator transaction)
  exit                Voluntarily exit the validator set (signed ExitValidator transaction)
  increase-stake      Add to this validator's self-stake (signed IncreaseValidatorStake)
  update-metadata     Update validator metadata / TEE attestation commitment
  get                 Inspect a single validator entry by address (read-only)
  list                List validators (optionally filter by status) (read-only)
  list-active         List currently-Active validators (read-only)
  keys                Print this node's genesis `[[validators]]` entry
  register-machine    Register this machine's identity on chain with the node account as its wallet and its TPM attestation, so the validator votes, attests and serves agents as its machine root
  attach-attestation  Attach this machine's TPM attestation to its machine root, when the root was registered without one
  help                Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro validator attach-attestation`

```
Attach this machine's TPM attestation to its machine root, when the root was registered without one

Usage: tenzro validator attach-attestation [OPTIONS]

Options:
      --key-namespace <KEY_NAMESPACE>  The node's `hardware_key_namespace` (default: the machine's default node)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro validator exit`

```
Voluntarily exit the validator set (signed ExitValidator transaction)

Usage: tenzro validator exit [OPTIONS]

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro validator get`

```
Inspect a single validator entry by address (read-only)

Usage: tenzro validator get [OPTIONS] <ADDRESS>

Arguments:
  <ADDRESS>  Validator address (32-byte hex; with or without 0x prefix)

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro validator increase-stake`

```
Add to this validator's self-stake (signed IncreaseValidatorStake)

Usage: tenzro validator increase-stake [OPTIONS] --additional <ADDITIONAL>

Options:
      --key-namespace <KEY_NAMESPACE>  Hardware key namespace of the signing account [default: client]
  -v, --verbose                        Enable verbose logging
      --additional <ADDITIONAL>        Additional self-stake: TNZO (`500`, `500 TNZO`) or wei with its suffix. Only ever adds; reducing a stake is unbonding, which has its own path and delay
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro validator keys`

```
Print this node's genesis `[[validators]]` entry

Usage: tenzro validator keys [OPTIONS] --stake <STAKE>

Options:
      --stake <STAKE>    Stake for this entry, in whole TNZO units
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --name <NAME>      A comment written above the entry, so a reader can tell which machine it came from
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro validator list`

```
List validators (optionally filter by status) (read-only)

Usage: tenzro validator list [OPTIONS]

Options:
      --status <STATUS>  Filter by status: Active | Candidate | PendingActive | PendingExit | Exited | Jailed
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro validator list-active`

```
List currently-Active validators (read-only)

Usage: tenzro validator list-active [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro validator register`

```
Register a new validator candidate (signed RegisterValidator transaction)

Usage: tenzro validator register [OPTIONS] --ml-dsa-public-key <ML_DSA_PUBLIC_KEY> --p256-public-key <P256_PUBLIC_KEY> --node-key <NODE_KEY> --proof-of-possession <PROOF_OF_POSSESSION> --node-key-proof <NODE_KEY_PROOF> --vrf-key <VRF_KEY> --vrf-key-proof <VRF_KEY_PROOF> --withdrawal-address <WITHDRAWAL_ADDRESS> --self-stake <SELF_STAKE>

Options:
      --key-namespace <KEY_NAMESPACE>
          Hardware key namespace of the signing account [default: client]
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --ml-dsa-public-key <ML_DSA_PUBLIC_KEY>
          1952-byte ML-DSA-65 verifying key of the hardware consensus key (hex), as printed by `tenzro validator keys`
      --p256-public-key <P256_PUBLIC_KEY>
          65-byte uncompressed P-256 key, the classical half of the same composite key (hex)
      --node-key <NODE_KEY>
          32-byte Ed25519 node key of the node that runs the validator (hex), as printed by `tenzro validator keys`
      --proof-of-possession <PROOF_OF_POSSESSION>
          Composite proof of possession the hardware signed over `from`, both key halves and the node key (hex), as printed by `tenzro validator keys`. Registration is refused without a valid one
      --node-key-proof <NODE_KEY_PROOF>
          The node key's Ed25519 signature over the same registration (hex), as printed by `tenzro validator keys`
      --vrf-key <VRF_KEY>
          32-byte VRF key of the node that runs the validator (hex), a key of its own apart from the node key, as printed by `tenzro validator keys`
      --vrf-key-proof <VRF_KEY_PROOF>
          The VRF key's 80-byte proof over the same registration (hex), as printed by `tenzro validator keys`
      --withdrawal-address <WITHDRAWAL_ADDRESS>
          Withdrawal address — rewards / unbonded principal settle here (hex; 32 bytes)
      --self-stake <SELF_STAKE>
          Self-stake committed to the candidate: TNZO (`10000`, `10000 TNZO`) or wei with its suffix. Must be at least the registry's `min_self_stake` (default 10,000 TNZO)
      --metadata-uri <METADATA_URI>
          Optional ≤256-byte off-chain pointer (moniker / website / contact) [default: ""]
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

### `tenzro validator register-machine`

```
Register this machine's identity on chain with the node account as its wallet and its TPM attestation, so the validator votes, attests and serves agents as its machine root

Usage: tenzro validator register-machine [OPTIONS]

Options:
      --key-namespace <KEY_NAMESPACE>  The node's `hardware_key_namespace` (default: the machine's default node)
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro validator update-metadata`

```
Update validator metadata / TEE attestation commitment

Usage: tenzro validator update-metadata [OPTIONS]

Options:
      --key-namespace <KEY_NAMESPACE>
          Hardware key namespace of the signing account [default: client]
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --metadata-uri <METADATA_URI>
          New off-chain pointer (≤256 bytes); omit to skip
      --tee-attestation-hash <TEE_ATTESTATION_HASH>
          New 32-byte SHA-256 TEE attestation commitment (hex); omit to skip
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help
          Print help
```

## `tenzro version`

```
Show version information

Usage: tenzro version [OPTIONS]

Options:
      --detailed         Show detailed version information
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro visibility`

```
Show or set this node's visibility (public, gated or private)

Usage: tenzro visibility [OPTIONS] <COMMAND>

Commands:
  show  Show the node's visibility and the resources that override it
  set   Set the node's visibility
  help  Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro visibility set`

```
Set the node's visibility

Usage: tenzro visibility set [OPTIONS] <VISIBILITY>

Arguments:
  <VISIBILITY>
          The node's visibility

          Possible values:
          - public:  Announced; anyone may use a resource by paying the per-use price
          - gated:   Announced as access-required; callers the access policy names only
          - private: Not announced; this node's own callers only

Options:
      --rpc <RPC>
          RPC endpoint
          
          [default: http://127.0.0.1:8545]

  -v, --verbose
          Enable verbose logging

      --format <FORMAT>
          Output format (text, json)
          
          [default: text]

  -h, --help
          Print help (see a summary with '-h')
```

### `tenzro visibility show`

```
Show the node's visibility and the resources that override it

Usage: tenzro visibility show [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

## `tenzro vrf`

```
VRF proof verification — RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI

Usage: tenzro vrf [OPTIONS] <COMMAND>

Commands:
  verify  Verify a VRF proof against a public key and input message
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro vrf verify`

```
Verify a VRF proof against a public key and input message

Usage: tenzro vrf verify [OPTIONS] --pubkey <PUBKEY> --proof <PROOF> --alpha <ALPHA>

Options:
      --pubkey <PUBKEY>  Hex-encoded 32-byte VRF public key
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --proof <PROOF>    Hex-encoded 80-byte VRF proof (Gamma(32) || c(16) || s(32))
      --alpha <ALPHA>    Hex-encoded input message (alpha)
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro wallet`

```
Wallet management commands

Usage: tenzro wallet [OPTIONS] <COMMAND>

Commands:
  native-balance             Call tenzro_getBalance (get balance) and print the node's answer
  nonce                      Call tenzro_getNonce (get nonce) and print the node's answer
  settlement-preference      Call tenzro_getSettlementPreference (get settlement preference) and print the node's answer
  set-settlement-preference  Choose the asset you are paid in, signed by your hardware key (tenzro_setSettlementPreference)
  balance                    Check wallet balance
  send                       Send tokens or stablecoins
  history                    Get transaction history for an address
  token-balance              Get token balance for a specific ERC-20 token
  create-local               Show the self-custody client account this machine's hardware keys (node never signs for it)
  outflow                    Opt-in outflow limits on an account: a cap per window, a hold and a guardian
  help                       Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro wallet balance`

```
Check wallet balance

Usage: tenzro wallet balance [OPTIONS]

Options:
      --address <ADDRESS>  Wallet address (optional; defaults to the configured wallet, then this machine's client account)
  -v, --verbose            Enable verbose logging
      --detailed           Show detailed asset breakdown
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro wallet create-local`

```
Show the self-custody client account this machine's hardware keys (node never signs for it)

Usage: tenzro wallet create-local [OPTIONS]

Options:
      --key-namespace <KEY_NAMESPACE>  The client identity's hardware key namespace (a-z, 0-9, '-', '_'). Each namespace is its own account [default: client]
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --rpc <RPC>                      Enroll the account's ML-DSA-65 key on this node now. An account signs nothing until it has enrolled one, and needs funds for the gas of the enrolment; without this flag the first transaction it sends enrolls it
  -h, --help                           Print help
```

### `tenzro wallet history`

```
Get transaction history for an address

Usage: tenzro wallet history [OPTIONS] <ADDRESS>

Arguments:
  <ADDRESS>  Wallet address (hex)

Options:
      --limit <LIMIT>    Maximum transactions to return [default: 20]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro wallet native-balance`

```
Call tenzro_getBalance (get balance) and print the node's answer

Usage: tenzro wallet native-balance [OPTIONS] --address <ADDRESS>

Options:
      --address <ADDRESS>  address
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro wallet nonce`

```
Call tenzro_getNonce (get nonce) and print the node's answer

Usage: tenzro wallet nonce [OPTIONS] --address <ADDRESS>

Options:
      --address <ADDRESS>  address
  -v, --verbose            Enable verbose logging
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro wallet outflow`

```
Opt-in outflow limits on an account: a cap per window, a hold and a guardian

Usage: tenzro wallet outflow [OPTIONS] <COMMAND>

Commands:
  show             Show an account's policy and its queued payments
  set              Set or change the policy (a loosening is queued for the hold)
  remove           Remove the policy (queued for the hold)
  cancel-pending   Cancel a queued change to the policy (the account or its guardian)
  release          Queue a payment of any size; it can be paid after the hold
  cancel-release   Cancel a queued payment (the account or its guardian)
  claim            Pay a queued payment (the account after the hold, the guardian at once)
  delegate-check   Check a delegation target before signing a delegation to it
  approval-target  Print the bytes a guardian's passkey signs for one action
  help             Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro wallet outflow approval-target`

```
Print the bytes a guardian's passkey signs for one action

Usage: tenzro wallet outflow approval-target [OPTIONS] --account <ACCOUNT> <ACTION>

Arguments:
  <ACTION>  cancel_pending, cancel_release or claim_release

Options:
      --id <ID>            The queued payment's number (0 for cancel_pending) [default: 0]
  -v, --verbose            Enable verbose logging
      --account <ACCOUNT>  The guarded account, hex
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

#### `tenzro wallet outflow cancel-pending`

```
Cancel a queued change to the policy (the account or its guardian)

Usage: tenzro wallet outflow cancel-pending [OPTIONS]

Options:
      --account <ACCOUNT>              The account the policy belongs to, hex. Default: this machine's client account. A guardian names the account it guards and signs as itself
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
      --yes                            Sign without typing `yes` at the prompt (the preview is still shown)
      --approval-file <APPROVAL_FILE>  The guardian's passkey approval (JSON file), needed when the account's guardian cancels or pays early. `approval-target` prints what it signs
  -h, --help                           Print help
```

#### `tenzro wallet outflow cancel-release`

```
Cancel a queued payment (the account or its guardian)

Usage: tenzro wallet outflow cancel-release [OPTIONS] <ID>

Arguments:
  <ID>  The queued payment's number (see `outflow show`)

Options:
      --account <ACCOUNT>              The account the policy belongs to, hex. Default: this machine's client account. A guardian names the account it guards and signs as itself
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
      --yes                            Sign without typing `yes` at the prompt (the preview is still shown)
      --approval-file <APPROVAL_FILE>  The guardian's passkey approval (JSON file), needed when the account's guardian cancels or pays early. `approval-target` prints what it signs
  -h, --help                           Print help
```

#### `tenzro wallet outflow claim`

```
Pay a queued payment (the account after the hold, the guardian at once)

Usage: tenzro wallet outflow claim [OPTIONS] <ID>

Arguments:
  <ID>  The queued payment's number (see `outflow show`)

Options:
      --account <ACCOUNT>              The account the policy belongs to, hex. Default: this machine's client account. A guardian names the account it guards and signs as itself
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
      --yes                            Sign without typing `yes` at the prompt (the preview is still shown)
      --approval-file <APPROVAL_FILE>  The guardian's passkey approval (JSON file), needed when the account's guardian cancels or pays early. `approval-target` prints what it signs
  -h, --help                           Print help
```

#### `tenzro wallet outflow delegate-check`

```
Check a delegation target before signing a delegation to it

Usage: tenzro wallet outflow delegate-check [OPTIONS] <TARGET>

Arguments:
  <TARGET>  The delegate's address (hex)

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

#### `tenzro wallet outflow release`

```
Queue a payment of any size; it can be paid after the hold

Usage: tenzro wallet outflow release [OPTIONS] <TO> <AMOUNT>

Arguments:
  <TO>      Recipient address
  <AMOUNT>  Amount in TNZO

Options:
      --account <ACCOUNT>              The account the policy belongs to, hex. Default: this machine's client account. A guardian names the account it guards and signs as itself
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
      --yes                            Sign without typing `yes` at the prompt (the preview is still shown)
      --approval-file <APPROVAL_FILE>  The guardian's passkey approval (JSON file), needed when the account's guardian cancels or pays early. `approval-target` prints what it signs
  -h, --help                           Print help
```

#### `tenzro wallet outflow remove`

```
Remove the policy (queued for the hold)

Usage: tenzro wallet outflow remove [OPTIONS]

Options:
      --account <ACCOUNT>              The account the policy belongs to, hex. Default: this machine's client account. A guardian names the account it guards and signs as itself
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
      --yes                            Sign without typing `yes` at the prompt (the preview is still shown)
      --approval-file <APPROVAL_FILE>  The guardian's passkey approval (JSON file), needed when the account's guardian cancels or pays early. `approval-target` prints what it signs
  -h, --help                           Print help
```

#### `tenzro wallet outflow set`

```
Set or change the policy (a loosening is queued for the hold)

Usage: tenzro wallet outflow set [OPTIONS] --cap <CAP>

Options:
      --account <ACCOUNT>              The account the policy belongs to, hex. Default: this machine's client account. A guardian names the account it guards and signs as itself
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The signing account's hardware key namespace [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
      --yes                            Sign without typing `yes` at the prompt (the preview is still shown)
      --approval-file <APPROVAL_FILE>  The guardian's passkey approval (JSON file), needed when the account's guardian cancels or pays early. `approval-target` prints what it signs
      --cap <CAP>                      Most the account may send per window, in TNZO
      --window-hours <WINDOW_HOURS>    The window the cap counts over, in hours [default: 24]
      --hold-hours <HOLD_HOURS>        How long a queued payment waits, in hours [default: 24]
      --guardian <GUARDIAN>            The guardian: a person's identity (DID) whose passkey approves a cancel or an early payment, ideally on different hardware from this account
  -h, --help                           Print help
```

#### `tenzro wallet outflow show`

```
Show an account's policy and its queued payments

Usage: tenzro wallet outflow show [OPTIONS]

Options:
      --account <ACCOUNT>              The account, hex. Default: this machine's client account
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>  The key namespace used to find the default account [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro wallet send`

```
Send tokens or stablecoins

Usage: tenzro wallet send [OPTIONS] <TO> <AMOUNT>

Arguments:
  <TO>      Recipient address
  <AMOUNT>  Amount to send

Options:
      --asset <ASSET>
          Asset to send (TNZO, USDC, USDT) [default: TNZO]
  -v, --verbose
          Enable verbose logging
      --format <FORMAT>
          Output format (text, json) [default: text]
      --key-namespace <KEY_NAMESPACE>
          The signing account's hardware key namespace (a-z, 0-9, '-', '_'). Each namespace is its own account [default: client]
      --rpc <RPC>
          RPC endpoint [default: http://127.0.0.1:8545]
      --confirm-address <CONFIRM_ADDRESS>
          The full recipient address, repeated, to proceed when the recipient is new to this account or resembles one it trusts. Without it a terminal asks for the address to be typed; a script must pass it
      --confirm-amount <CONFIRM_AMOUNT>
          The amount again, in TNZO, to proceed with a transfer at or above the governed step-up amount (`wallet.step_up_threshold_tnzo`)
  -h, --help
          Print help
```

### `tenzro wallet set-settlement-preference`

```
Choose the asset you are paid in, signed by your hardware key (tenzro_setSettlementPreference)

Usage: tenzro wallet set-settlement-preference [OPTIONS] --asset <ASSET>

Options:
      --asset <ASSET>                  `keep_inbound` or `tnzo`
  -v, --verbose                        Enable verbose logging
      --format <FORMAT>                Output format (text, json) [default: text]
      --payee-did <PAYEE_DID>          The payee DID (defaults to the configured identity)
      --key-namespace <KEY_NAMESPACE>  The hardware key namespace of the signing account [default: client]
      --rpc <RPC>                      RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                           Print help
```

### `tenzro wallet settlement-preference`

```
Call tenzro_getSettlementPreference (get settlement preference) and print the node's answer

Usage: tenzro wallet settlement-preference [OPTIONS] --payee-did <PAYEE_DID>

Options:
      --payee-did <PAYEE_DID>  payee did
  -v, --verbose                Enable verbose logging
      --format <FORMAT>        Output format (text, json) [default: text]
      --rpc <RPC>              RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                   Print help
```

### `tenzro wallet token-balance`

```
Get token balance for a specific ERC-20 token

Usage: tenzro wallet token-balance [OPTIONS] --token <TOKEN> <ADDRESS>

Arguments:
  <ADDRESS>  Wallet address (hex)

Options:
      --token <TOKEN>    Token symbol or contract address
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

## `tenzro zk`

```
Zero-knowledge proof operations (prove, verify, circuits, fraud proofs)

Usage: tenzro zk [OPTIONS] <COMMAND>

Commands:
  create-proof               Call tenzro_createZkProof (create zk proof) and print the node's answer
  list-circuits              Call tenzro_listCircuits (list circuits) and print the node's answer
  verify-tee-proof           Call tenzro_verifyTeeZkProof (verify tee zk proof) and print the node's answer
  create-tee-zk-proof        Call tenzro_createTeeZkProof (create tee zk proof) and print the node's answer
  attest-finality-proof      Bind a Groth16-wrapped finality proof made on this machine to an attestation of the node's TEE (tenzro_attestFinalityProof). The wrap rests on a classical assumption (BN254) and is not quantum-safe
  verify-tee-finality-proof  Verify a TEE-bound finality proof and print its measurement registers (tenzro_verifyTeeFinalityProof)
  prove                      Create a Plonky3 STARK proof
  verify                     Verify a Plonky3 STARK proof
  circuits                   List available ZK circuits
  attestation                Whether a commitment is attested on chain
  help                       Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro zk attestation`

```
Whether a commitment is attested on chain

Usage: tenzro zk attestation [OPTIONS] --commitment <COMMITMENT>

Options:
      --commitment <COMMITMENT>  Hex-encoded 32-byte commitment hash (with or without 0x prefix)
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro zk attest-finality-proof`

```
Bind a Groth16-wrapped finality proof made on this machine to an attestation of the node's TEE (tenzro_attestFinalityProof). The wrap rests on a classical assumption (BN254) and is not quantum-safe

Usage: tenzro zk attest-finality-proof [OPTIONS] --proof <PROOF> --out <OUT>

Options:
      --proof <PROOF>    The proof JSON `tenzro-finality-prover wrap` wrote
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --out <OUT>        Where to write the bound proof (JSON)
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro zk circuits`

```
List available ZK circuits

Usage: tenzro zk circuits [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro zk create-proof`

```
Call tenzro_createZkProof (create zk proof) and print the node's answer

Usage: tenzro zk create-proof [OPTIONS] --witness <WITNESS> --binding <BINDING>

Options:
  -v, --verbose            Enable verbose logging
      --witness <WITNESS>  The 32-byte service result, hex
      --binding <BINDING>  The 32-byte request binding, hex
      --format <FORMAT>    Output format (text, json) [default: text]
      --rpc <RPC>          RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help               Print help
```

### `tenzro zk create-tee-zk-proof`

```
Call tenzro_createTeeZkProof (create tee zk proof) and print the node's answer

Usage: tenzro zk create-tee-zk-proof [OPTIONS] --circuit-id <CIRCUIT_ID> --vendor <VENDOR> --witness <WITNESS> --binding <BINDING>

Options:
      --circuit-id <CIRCUIT_ID>  circuit id
  -v, --verbose                  Enable verbose logging
      --format <FORMAT>          Output format (text, json) [default: text]
      --vendor <VENDOR>          vendor
      --witness <WITNESS>        witness
      --binding <BINDING>        binding
      --rpc <RPC>                RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                     Print help
```

### `tenzro zk list-circuits`

```
Call tenzro_listCircuits (list circuits) and print the node's answer

Usage: tenzro zk list-circuits [OPTIONS]

Options:
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
  -h, --help             Print help
```

### `tenzro zk prove`

```
Create a Plonky3 STARK proof

Usage: tenzro zk prove [OPTIONS] --circuit-id <CIRCUIT_ID> --binding <BINDING>

Options:
      --circuit-id <CIRCUIT_ID>  Circuit identifier — `identity` or `settlement`
  -v, --verbose                  Enable verbose logging
      --binding <BINDING>        32-byte hex binding: the verifier's challenge or the request hash
      --format <FORMAT>          Output format (text, json) [default: text]
  -h, --help                     Print help
```

### `tenzro zk verify`

```
Verify a Plonky3 STARK proof

Usage: tenzro zk verify [OPTIONS] --bundle <BUNDLE>

Options:
      --bundle <BUNDLE>  Path to the JSON bundle printed by `tenzro zk prove` (`{circuit_id, public_inputs, proofs}`)
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro zk verify-tee-finality-proof`

```
Verify a TEE-bound finality proof and print its measurement registers (tenzro_verifyTeeFinalityProof)

Usage: tenzro zk verify-tee-finality-proof [OPTIONS] --bundle <BUNDLE>

Options:
      --bundle <BUNDLE>  The bound proof `attest-finality-proof` wrote
  -v, --verbose          Enable verbose logging
      --format <FORMAT>  Output format (text, json) [default: text]
      --rpc <RPC>        RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help             Print help
```

### `tenzro zk verify-tee-proof`

```
Call tenzro_verifyTeeZkProof (verify tee zk proof) and print the node's answer

Usage: tenzro zk verify-tee-proof [OPTIONS] --tee-zk-proof <TEE_ZK_PROOF>

Options:
      --tee-zk-proof <TEE_ZK_PROOF>  tee zk proof (JSON)
  -v, --verbose                      Enable verbose logging
      --format <FORMAT>              Output format (text, json) [default: text]
      --rpc <RPC>                    RPC endpoint [default: http://127.0.0.1:8545]
  -h, --help                         Print help
```

