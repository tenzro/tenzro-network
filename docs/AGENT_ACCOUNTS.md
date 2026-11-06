# Agent accounts on other chains

A delegated agent has one identity, its DID, and one account on each chain
the network configures. The account is derived from the DID, holds no key,
and acts only within a **grant**: a bounded authority the agent's terms allow,
issued on Tenzro and proven to the other chain under Tenzro finality.

## Where an agent's accounts are

The account of `did` on a chain is a pure function of the DID and of where the
agent account code is deployed on that chain (the chain's record, set by
governance with `SetAgentAccountChain`). The salt is
`sha256("tenzro/omni-account/v1" || did)`.

| Chain family | Account | Code on the chain |
|---|---|---|
| EVM (`eip155:*`) | CREATE2 from the account factory with the salt, over a minimal proxy of the account. The factory and the account are deployed with the keyless deterministic deployer, so an agent has **the same address on every EVM chain** | `contracts/agent-account/evm` |
| Solana | the program address `[b"agent", sha256(did)]` of the agent account program (immutable, no upgrade authority) | `programs/agent-account` |
| Sui | the derived object of the registry for the salt | `contracts/sui/sources/agent_account.move` |
| Aptos | the named object of the registry for the salt | `contracts/aptos/sources/agent_account.move` |
| Stellar | the contract the factory deploys with the salt | `contracts/stellar-agent-account` |
| CosmWasm chains | instantiate2 of the account code by the registry with the salt | `contracts/cosmos-agent-account` |
| TON (`tvm:-239`) | the hash of the StateInit of the account code and `sha256(did) || tree key` | `contracts/ton/contracts/agent-account.fc` |

`tenzro agent accounts <did>` (RPC `tenzro_agentAccounts`, MCP `agent_accounts`)
lists every account as CAIP-10 and, for EVM and Solana, as an ERC-7930
interoperable address (`tenzro caip erc7930 --caip10 <id>`). The agent's DID
document lists each one as a `blockchainAccountId`.

## Grants

A grant is issued by the agent (its serving node signs a `remote_grant`
action) and checked by the chain against the agent's terms, like any other
agent action:

- the chain must be listed in the terms' `allowed_chains`, and the asset in
  `remote_limits` with its daily limit (which also counts what the agent's
  settlement plans lock on other chains, see SETTLING_ACROSS_NETWORKS.md);
- the budget counts against the agent's daily (and hourly) spend at the rate
  the terms set: a budget `b` of an asset limited to `m` per day uses
  `b * max_daily_spend / m`. Grants on all chains together never exceed the
  daily cap. No price oracle is involved;
- one grant holds at most `1/24` of the asset's daily limit and lives at most
  the terms' `remote_grant_ttl_ms` (10 minutes when the terms set none). Both
  defaults are governed parameters (`agent.remote_grant_budget_divisor`,
  `agent.remote_grant_ttl_ms`);
- an action above the terms' `step_up_above` needs the controller's passkey
  approval of the grant;
- the terms' `cosign_above` sets the amount above which an action on the other
  chain needs the signatures of two serving nodes of distinct operators.

The grant is written to chain state at `agent_grant:<did>:<caip2>` in a fixed
layout every chain decodes the same way: the chain, the account, the agent,
the sequence, the time window, the asset, the budget, the per-action limit,
the cosign threshold, the Merkle roots of the serving nodes' P-256 keys and of
the allowed targets, the payload hash of an exact grant, the relay refund cap
and the void flag.

```
tenzro agent grant --chain eip155:8453 --asset eip155:8453/erc20:0x... --budget 100000000
tenzro agent grant --chain aptos:1 --asset aptos:1/fa:0x... --budget 5000 --exact action.json
```

## Installing a grant on the other chain

Anyone can install a grant: `sync` takes the grant bytes and their state proof
under the state root of a checkpoint that chain's Tenzro finality client
accepted. `tenzro agent sync <did> --chain <caip2>` (RPC
`tenzro_getAgentGrantProof`, MCP `agent_account_sync`) returns both. The
account accepts only a later grant, or the void of the current one.

Finality clients exist on every chain listed above. They check Tenzro's
Groth16 finality proof (BN254) natively on EVM chains, Solana, Sui, Aptos and
Stellar, in software on CosmWasm chains, and, on TON, a BLS12-381 wrap of the
same proof (`crates/tenzro-finality-prover/bls12381-wrap`): a circuit over
BLS12-381 that verifies the BN254 proof, whose keys come from a two-phase key
ceremony.

## Acting

An action names its target, the function, the amount of the grant's asset it
moves, the relayer's refund and its data. The serving node signs the digest
`sha256("tenzro/agent-act/v1" || chain || account || seq || nonce || action)`
with its hardware P-256 key after checking the action against the live grant
(`tenzro agent act`, RPC `tenzro_signRemoteAction`, MCP `agent_remote_act`).
The account checks, in order: a live, unvoided grant inside its time window;
each signature low-S and valid under the chain's native P-256 verification;
each key in the grant's key root; two operators above the cosign threshold;
the target in the grant's targets; the per-action limit and the budget; the
relay refund cap. It then runs the action and moves its nonce.

An exact grant carries one action (its payload hash) and runs it once without
signatures.

What each chain supports:

| Chain | Open grants | Exact grants | P-256 check |
|---|---|---|---|
| EVM | yes, also through ERC-4337 (EntryPoint v0.9) | yes | the P-256 precompile at `0x100`; an account refuses to deploy where it is missing |
| Solana | yes | yes | the secp256r1 program, in the instruction before the action |
| Sui | yes | yes | `ecdsa_r1` |
| Aptos | no: Move has no P-256 verification | yes | none |
| Stellar | yes, as a custom account (`__check_auth`) | yes | `secp256r1_verify` |
| CosmWasm | yes | yes | `secp256r1_verify` |
| TON | yes | yes | `P256_CHKSIGNU` over the SHA-256 of the digest |
| Bitcoin | no account: an agent pays to Bitcoin through the Bitcoin route or a hash-locked settlement plan leg, proven by the route's light client | | |

The TON contracts' tests also run on the TON node's own native emulator:
`TON_EMULATOR=<path to libemulator from a TON release> npm run test:native` in
`contracts/ton` runs every transaction and get method on the native TVM,
including the P-256 checks of agent actions.

Relayers that submit transactions on chains that need a fee payer (Solana,
Stellar, TON) use their own accounts there and hold no authority over the
account. The account refunds the relayer of an action up to the grant's cap
on every chain but Stellar, where an authorization covers the one call it
names and the relayer pays its own fee.

## ERC-8004 agent wallet

On an EVM chain the agent's account can be the `agentWallet` of its ERC-8004
identity entry. The registry's `setAgentWallet(agentId, newWallet, deadline,
signature)` requires the new wallet's consent to the EIP-712 digest of
`AgentWalletSet(agentId, newWallet, owner, deadline)` under the registry's
domain (`ERC8004IdentityRegistry`, version `1`, the chain id, the registry
address); for a contract wallet it asks `isValidSignature` (ERC-1271).

1. `tenzro_agentWalletConsent` (CLI `tenzro agent wallet-consent`, MCP
   `agent_wallet_consent`, SDK `walletConsent` / `wallet_consent`) returns the
   digest, the `approveHash(digest)` action on the account itself (amount 0)
   and the `setAgentWallet` calldata with an empty signature.
2. The agent signs and submits the action like any other (`tenzro agent act`);
   a grant with a target list must include the account's own `approveHash`.
3. The entry's owner sends the calldata to the registry before `deadline` (at
   most 300 s ahead). The registry asks the account, which answers for the
   digest while the grant it was approved under is live.

The consent names the owner and the deadline, so it cannot be reused for
another entry or owner, and it ends with the grant (a new grant, a void, or
expiry).

## Revocation

Revoking, pausing, quarantining or terminating the agent, or approving new
terms that change anything but a later expiry, voids every live grant: each is rewritten with the void flag and the
next sequence. Anyone may install the void on the other chain. Where the chain
proves its accounts' reports back to Tenzro through a bridge route, the void
opens a relay task paid from a deposit taken when the grant was issued, paid
once the install is proven.

A remote account stops the agent **at most at the grant's expiry**: when the
void is installed, or when the grant's time window ends, whichever comes
first. Shorter lifetimes and smaller budgets bound what a compromised serving
node can spend before then.

## Renewal

An agent acts only within `agent.max_unrenewed_ms` (governed; 90 days at
genesis) of the last time its root approved its terms in full. The terms
record carries that time as `renewed_at_ms`. Past it, every action, call and
payment the agent proposes is refused with `renewal:` until the root approves
the terms again, so an agent does not outlive the person or machine that
answers for it. A scope change approved within the controller's pre-approved
bounds does not renew. A machine root renews its agents with its own hardware
approval. A renewal that changes nothing but a later expiry keeps the agent's
grants on other chains.

## Reports back to Tenzro

On chains with a report route, an account's reports (a grant closed with what
it spent, an action taken, a void installed) are delivered to Tenzro as a
`RemoteGrantSettle` transaction (`tenzro relay agent-account`): a closed
grant credits its unspent budget back to the agent's daily spend once, an
action joins the agent's audit trail, and an installed void pays its relay
task. Without a report route a grant's whole budget counts as spent.

## Trust

Every account trusts Tenzro finality: a checkpoint certified by the committee
of its epoch, proven by the finality proof. Nothing else holds authority: no
relayer, no committee and no key on the
other chain.
