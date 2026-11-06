# Wallet Custody

How a Tenzro wallet is created, how devices are linked to it, and what stops
someone else linking themselves to yours.

## The invariant

**A private key never leaves the device that generated it.** A wallet is the
user's devices plus its keystore on the ledger: the passkeys that may act for
the account, its policy, its recovery signers and any recovery in progress.
The keystore is consensus state under the state root, so every node holds the
same one; no node, site or wallet provider holds anything the account needs
that the ledger does not, and the account survives all of them. Nodes see
public keys and assertions; nothing they see or store can sign.

- **Any linked device acts alone.** Every passkey the keystore links signs for
  the account, approves keystore changes and roots agents. A synced passkey is
  allowed; what counts is independence: passkeys one sync provider holds
  count as one root of control, each device-bound credential as its own.
  Spending needs two independent roots, so one stolen sync account is never
  enough to move funds.
- **The post-quantum leg.** A passkey's P-256 key can have an ML-DSA-65 key
  enrolled in chain state (`AccountKeys`); from then on every signature by
  that key must carry the ML-DSA-65 leg.

## Two setup flows

Both are first-class, and both preserve the invariant.

**Node operator / CLI.** The user runs a node, so the ceremony page is served
from their own machine at `127.0.0.1:8080`. `tenzro passkey login` mints a
session, opens the local page, and polls. Nothing remote is involved, and only
that machine can reach the page — which is the safer default and why the CLI
derives a loopback URL rather than asking a node where its page lives.

**App user.** No node on their machine. They click a button in a web app and
everything happens in the browser, so the page is served from wherever the app
runs — an RPC node, or the app's own hosting. The hosting node relays the
ceremony; it still never sees a key.

A device that cannot do WebAuthn at all gets an inline QR of the page URL, so
the ceremony can be handed to a phone. Any number of devices may *view* a
session; the first to complete it claims it, single-use.

## The keystore

Each passkey account has an address that commits to its first passkey, its
identity and a salt, and never changes when devices change. Until its first
change the keystore is implied: the first passkey alone. Every change is a
`KeystoreUpdate` transaction:

| Change | Approved by |
|---|---|
| link a passkey | the account's passkeys per its policy, plus the new passkey's own assertion (proof of possession; its signed BE/BS flags must match what the change claims) |
| unlink a passkey | the account's passkeys per its policy; a passkey still in its waiting period is cancelled by any one other passkey; the last passkey stays |
| set the policy | `single_credential` (any one passkey, the default) or `two_credentials` (two passkeys, which then also stops one passkey acting alone) |
| set the recovery signers | the account's passkeys per its policy |
| start a recovery | the recovery signers, by threshold of independent roots, plus the joining passkey's proof of possession |
| cancel a recovery | any one passkey of the account |
| complete a recovery | anyone, once its wait has passed |
| set or turn off the recovery code | the account's passkeys per its policy |
| claim the recovery code for a passkey | nobody: any account other than the locked one sends and pays for it |
| recover with the code | the code, revealed after its claim has aged, plus the joining passkey's proof of possession |

Each approval signs `SHA-256(domain ‖ chain id ‖ account ‖ commitment ‖
change)`, where the commitment is that of the keystore being changed. The
commitment moves with every change, so an approval applies once and cannot be
replayed. The same passkey derives the same account on every chain and every
chain starts it from the same genesis record, so the change names the chain
it is for (`chain_id`, signed as 8 bytes little-endian like a transaction's):
a chain refuses a change made for another, and an approval made on a test
network never applies on the main one. The
account's first change carries its anchor (the first passkey, which must
derive the account), so nobody can claim an address their key does not derive.

**Who pays.** No change is free. The account pays when it sends a change
itself, signed by one of its passkeys, which then counts as that passkey's
approval. An account with no balance yet (a new wallet's first change) has a
sponsor pay: a wallet provider, a sponsor or a friend sends the change from
its own account and pays the fee, and the change carries the passkey's
approval explicitly. The authority is in the approvals, never in the sender,
so a sponsor can pay for a change but cannot make one. The same holds for a
DID's service entries (`IdentityServices`). The wallet kernel takes a
`sponsor` and uses it only while the account holds nothing; the SDKs'
`KeystoreClient.send` without an account to send from is the sponsor's
side.

**Waiting periods.** A passkey linked while the account holds fewer than two
independent roots signs at once but counts as a root only after
`keystore.add_device_wait_ms` (48 hours at genesis), during which any other
passkey can unlink it; one stolen passkey cannot add a "second root" and
spend. A recovery waits `keystore.recovery_wait_key_and_email_ms` (1 hour at
genesis) when a recovery key and an email verifier approved,
`keystore.recovery_wait_key_ms` (48 hours) for a recovery key alone and
`keystore.recovery_wait_other_ms` (7 days) otherwise; any passkey still on
the account can cancel it meanwhile. Every wait is a governed parameter.
Recovery adds a passkey and removes nothing.

**The recovery code.** An account may hold one optional, one-time recovery
code: a 32-byte secret its holder keeps, downloaded or written down, of which
the chain holds only a commitment, `SHA-256(domain ‖ chain id ‖ account ‖
code)`. It is off until the account's passkeys set
it. It is no key and signs nothing; it can only start a recovery that any
linked passkey cancels. Using it takes two steps so nobody who sees the code
can use it first: a claim, `SHA-256(domain ‖ chain id ‖ account ‖ code ‖
passkey)`, sent
and paid by another account (the locked account pays for no claim), then,
after `keystore.recovery_code_reveal_delay_ms` and before
`keystore.recovery_code_claim_ttl_ms`, the code and that passkey. The
recovery then waits `keystore.recovery_code_wait_ms` (7 days at genesis) and
spends the code; the holder sets a new one.

## Multiple wallet providers

No wallet provider needs another's permission. Each passkey in a keystore
records its own relying party, the domain of the wallet that registered it,
and every assertion by it must carry that relying party's `rpIdHash` and come
from that domain or a subdomain of it, over https. No list of related origins
applies anywhere in consensus, so nothing depends on `tenzro.com` or its
`/.well-known/webauthn`; `tenzro.com` is only the relying party the network's
own wallet creates first passkeys on.

A passkey registered with another provider (any third party's
domain) joins an account through an ordinary `link a passkey` change approved
by a passkey already on it. From then on it acts for the account, approves
changes and roots agents like any other, for its own relying party and no
other. The credential index is keyed by relying party and credential id, so a
wallet finds the account from any of its passkeys.

## Who reads what

Reads are open: `tenzro_getKeystore` returns an account's keystore, its
commitment and whether its passkeys may spend now; `tenzro_resolveCredential`
returns the accounts a passkey (credential id and relying party) is linked
to. Both answer from committed chain state, so every node gives the same
answer.

Enrollment of a brand-new account needs no prior authority: there is nothing
to prove control of yet. It still answers a node-issued challenge with the
passkey being enrolled, with user verification, and stores nothing; it
returns the account, its genesis keystore and the anchor its first change
carries.

## Value and authority change only in consensus

An account acts through transactions its keystore authorizes; no node holds
modules or operations that move value or authority on its own. What an agent
may spend is its Terms, a session of authority is a delegated agent, and a
second device is a passkey the keystore links. There are no node-held user
operations, session keys, spending limits or hardware-signer modules.

## Devices bound to an identity

`tenzro_bindDevice`, `tenzro_revokeBoundDevice` and
`tenzro_transferMachineOwnership` are custody changes too. Each consumes a
custody challenge naming the exact change. The first device bound to an
identity must be the key the identity's DID derives from; after that, a new
device or a revocation needs a user-verified assertion from a device already
bound. A delegated machine moves on an assertion from its controller's device,
a machine nobody delegated on a signature by its own registered key.

## Surfaces

JSON-RPC (`tenzro_getKeystore`, `tenzro_resolveCredential`, and
`KeystoreUpdate` through `tenzro_sendRawTransaction`), MCP (`get_keystore`,
`resolve_credential`), the TypeScript, Rust and Python SDKs (`KeystoreClient`,
`keystoreDigest` / `keystore_digest` over one shared vector), and the CLI
(`tenzro passkey keystore|resolve|update`).
