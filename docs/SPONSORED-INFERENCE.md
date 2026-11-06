# Cover your users' fees: sponsored inference

An application can let its users call a model without holding TNZO, a key or
an account. The application pays for each call from its own funds, through a
delegated agent it controls. The user's request carries only the prompt and the
sponsor's DID. The provider serves the call and is paid on chain for the work
it served.

This page covers who pays what, how an application sets up a sponsor, how a
provider offers sponsored calls, how a user makes one, and how anyone checks the
payment afterwards. The node method is `tenzro_sponsoredInference`. The CLI
command is `tenzro inference sponsored`. The SDK bindings are `sponsoredInference`
(TypeScript), `sponsored_inference` (Rust and Python) and the MCP tool
`sponsored_inference`.

## Who pays what

| Party | Holds | Pays |
| --- | --- | --- |
| User | nothing: no key, no account, no TNZO | nothing |
| Application | its own identity and account, and the sponsor agent's wallet, which it funds | the price of each call, from the sponsor wallet |
| Provider (node operator) | the serving node and its payee wallet | the network fee of the payment transaction its node submits, as on every paid route; the governed settlement fee is taken from the operator's leg of the payment, as on any paid call |

The money that covers a user's call comes only from the application's own
account, moved into its sponsor wallet. Nothing comes from network rewards, the
treasury or any pool, and no TNZO is created. A sponsored call is paid work like
any other: the provider is paid for the call it served, at the price its rate
card sets, and the payment is recorded on chain against that call.

## How a call is paid

1. The user sends `tenzro_sponsoredInference` with `model`, `input`, `sponsor`
   and optionally `max_tokens` to a node that offers sponsored calls.
2. The node checks the call against its own limits (the sponsor and models it
   accepts, a per-source rate, a global rate, an output cap and a daily budget)
   and against the sponsor's terms on chain. The terms must name this node as a
   serving node and cover the model and the most the call can cost. A call
   outside the terms is refused before anything is served.
3. The node runs the model, prices the metered tokens from its rate card, and
   pays its operator's payee from the sponsor wallet with an `AgentAct`. It signs
   the payment with the key its TPM holds for the agent. The chain checks it
   against the agent's terms (caps, daily spend, counterparties, standing, bond)
   like any other agent action.
4. The payment binds the model, the prompt and the output the user received
   (its `request_digest`). The reply carries the output, the metered `units`, the
   `cost`, the payment's `tx_hash` and its `pay_ref`.

## Set up a sponsor (application)

The sponsor is a delegated agent whose controller is the application's identity.
Its terms are the grant: the only calls it pays for.

1. **Find the provider's node.** The terms name each serving node by its machine
   DID and its operator's DID. `tenzro_listPeers` returns the `machine_did` of
   the node and of each peer whose signed announcement it holds.

2. **Write the terms.** Allow only payments, only the models you sponsor, and cap
   what one payment and one day may spend. Caps are in micro-units of account
   (USD millionths). For example, `terms.json`:

   ```json
   {
     "controller_did": "did:tenzro:human:...",
     "agent_name": "my-app-sponsor",
     "delegation_scope": {
       "allowed_operations": ["pay"],
       "allowed_models": ["qwen3-0.6b"],
       "max_transaction_value": "1000000",
       "max_daily_spend": "5000000"
     },
     "serving_nodes": [
       { "machine_did": "did:tenzro:machine:...", "operator_did": "did:tenzro:human:..." }
     ],
     "min_distinct_operators": 1,
     "expires_at_ms": null
   }
   ```

3. **Bond and create the agent.** An agent's terms need a bond sized by their
   spend ceiling; `tenzro bond get` shows an existing one.
   - Rooted in a person's passkey: post the bond with
     `tenzro bond post --agent-did <agent> --controller-did <app> --amount <wei>`,
     ask for the challenge with
     `tenzro agent delegation challenge delegate --account <smart account> --terms terms.json`,
     have the passkey sign it, then create the agent with
     `tenzro agent delegation onboard --terms <completed terms> --authorization <signed authorization>`.
     Over RPC these are `tenzro_createCustodyChallenge` (operation
     `delegate_agent`) and `tenzro_onboardDelegatedAgent`.
   - Rooted in the application server's own hardware key:
     `tenzro agent delegation create-as-machine --terms terms.json --bond <wei>`
     registers the machine, posts the bond, signs and onboards in one go.

   Onboarding fills in each serving node's key for the agent: the node creates
   it in its TPM and the TPM certifies it. `tenzro agent terms --agent-did <agent>`
   (`tenzro_getAgentTerms`) shows the terms as the chain holds them.

4. **Fund the sponsor wallet from your own account.**
   `tenzro agent fund --agent-did <agent> --amount-wei <wei>` moves TNZO from your
   account into the wallet the agent's terms name. A `SetAgentTopUp` transaction
   from the controller's wallet lets the agent's wallet be refilled from it
   within an allowance per period.

5. **Tell the provider your agent's DID**, and give your users (or your page) the
   node's RPC address and that DID.

To stop sponsoring, revoke the agent (`tenzro agent delegation revoke`) or
replace its terms (`tenzro agent delegation update`); every node refuses its
calls from then on. Unspent funds stay in the agent's wallet under your control.

## Offer sponsored calls (provider)

Sponsored calls are off unless the operator configures them. In the node's
configuration file:

```toml
[sponsored_inference]
sponsor = "did:tenzro:machine:..."   # the application's agent
models = ["qwen3-0.6b"]              # each must be served by this node
max_tokens = 256                     # most output tokens one call may ask for
per_source_per_minute = 10           # calls one source address may make per minute
global_per_minute = 600              # calls per minute from all sources together
daily_budget = "50000000000000000000" # most the sponsor pays per UTC day, TNZO base units
```

The node must serve each listed model, have a rate card for it, have a payee (its
operator identity's wallet), and run with consensus so it can submit the payment.
Its ledger account pays the network fee of each payment it submits.

## Make a call (user or page)

No key, no account and no signature are needed. Over HTTP:

```sh
curl -s http://127.0.0.1:8545 -H 'content-type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "tenzro_sponsoredInference",
  "params": [{ "model": "qwen3-0.6b", "input": "Name one primary colour.",
               "sponsor": "did:tenzro:machine:...", "max_tokens": 16 }]
}'
```

With the CLI:

```sh
tenzro inference sponsored --model qwen3-0.6b --sponsor did:tenzro:machine:... \
  --max-tokens 16 --rpc http://127.0.0.1:8545 "Name one primary colour."
```

With the SDKs:

```ts
import { TenzroClient } from "tenzro-sdk";
const node = new TenzroClient({ endpoint: "http://127.0.0.1:8545", chainId: 1337 });
const r = await node.sponsoredInference({
  model: "qwen3-0.6b", input: "Name one primary colour.", sponsor, max_tokens: 16,
});
```

```rust
let node = tenzro_sdk::TenzroClient::new("http://127.0.0.1:8545").await?;
let r = node
    .sponsored_inference("qwen3-0.6b", "Name one primary colour.", sponsor, Some(16))
    .await?;
```

```python
from tenzro import RpcClient

with RpcClient("http://127.0.0.1:8545") as node:
    r = node.sponsored_inference([{"model": "qwen3-0.6b", "input": "Name one primary colour.",
                                   "sponsor": sponsor, "max_tokens": 16}])
```

The reply is `{ provider, model, output, units, cost, sponsor, tx_hash, pay_ref }`.
`input` is at most 4096 bytes. Calls over the rate limits get a rate-limited
error with `retry_after_ms`.

## Check the payment

Anyone can read the payment by its reference: `tenzro_getPayment` with
`{"pay_ref": "<pay_ref>"}` returns the payer (the sponsor's wallet), the payee
(the operator), the amount (the call's `cost`), the settlement fee, the paying
agent and the `request_digest`. The digest is SHA-256 over the domain
`tenzro/sponsored-inference` followed by the model, the input and the output,
each prefixed with its length as a little-endian u64. Recomputing it from the
reply shows that the payment is for the output the user received.

## When a call is refused

| Refusal | Why |
| --- | --- |
| `this node does not offer sponsored inference` | the operator has not configured it |
| `this node sponsors calls for another sponsor` | the node accepts a different agent |
| `... is not sponsored on this node` / `... is not loaded on this node` | the model is not in the node's list, or not served |
| `outside the sponsor's grant: ...` | the agent's terms do not cover the call: the model, the per-payment or daily cap, the expiry, this node, the bond, or the agent is revoked |
| `sponsored calls are rate limited; retry later` | the per-source or global rate |
| `today's sponsored budget is spent; try again tomorrow (UTC)` | the node's daily budget for the sponsor is spent |

## Tested

`crates/tenzro-node/tests/sponsored_inference_e2e.rs` runs this flow on a live
solo-validator node with a real model and the machine's TPM: the application
funds its sponsor wallet from its own account on chain, a caller with no account
completes a paid call over HTTP, the sponsor wallet pays exactly the call's cost,
the operator receives it net of the settlement fee, the payment record binds the
model, prompt and output, the caller is charged nothing, and a call for a model
outside the grant is refused with no payment. It is ignored by default (it needs
a TPM and downloads a model); run it with `--ignored`.
