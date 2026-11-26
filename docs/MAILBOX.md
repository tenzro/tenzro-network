# Mailbox (preview)

A mailbox holds sealed messages for a recipient who is offline, and hands them over once the
recipient comes back. An operator runs it beside its own node as a separate program,
`tenzro-mailbox-service`, and the node does not link it. Senders pay for each message with an
escrow voucher. The mailbox stores bytes it cannot read.

The library is `crates/tenzro-mailbox`. It contains the service and the client that senders and
recipients use (`MailboxClient`). The program is in `sdk/tenzro-mailbox-service`.

## Publishing a mailbox

The service's key lives in the operator machine's TPM or Secure Enclave. On a machine without
either, the service does not start. By default it listens on `127.0.0.1:8095`. To reach the
network it sits behind the operator's own TLS front end:

```sh
tenzro-mailbox-service --data-dir /var/lib/tenzro-mailbox \
    --rate-per-byte-hour 1000 --address https://mbx.example.org
```

At start the service prints the DID service entry that recipients publish:

| Field | Value |
|---|---|
| `type` | `TenzroMailbox` |
| `serviceEndpoint` | `https://mbx.example.org#key=<SHA-256 digest of the operator key, hex>` |

The service itself speaks plain HTTP. Do not expose its port: put the operator's own TLS front end in
front of it and publish the `https://` address. A client reaches a mailbox only over `https://`, or
over `http://` on its own machine, and refuses an address that names a private or loopback network
(a DID document is written by its subject, so its addresses are not trusted).

The endpoint pins a digest of the operator key rather than the key itself, because a service
endpoint is too short to hold the ML-DSA half of the key. The client reads the key from the mailbox
and refuses the mailbox unless the key hashes to the pinned digest. Every receipt is then checked
against that key.

```rust
let doc = rpc.call("tenzro_resolveDidDocument", json!({ "did": bob })).await?;
for entry in tenzro_mailbox::mailboxes_in(&doc) {
    let terms = Terms { chain_id, max_rate_per_byte_hour, max_prekey_price };
    let mailbox = MailboxClient::connect(&entry, terms).await?;
    // ...
}
```

`Terms` is what the payer is willing to pay. Before it signs a voucher for a deposit or a key package,
the client reads the mailbox's price list and refuses it when the chain is not the payer's, the rate or
the key package price is above the terms, or the message is outside the sizes and lifetime the mailbox
takes. A client gives each request 30 seconds, follows no redirect and reads at most 2 MiB of an answer.

## Sending

1. Read `info()`: the price, the payee account, the chain, and the size classes. The default size
   classes are 1, 4, 16 and 64 KiB.
2. Seal the message to the recipient, then pad it to a size class (`size_class_for`). The padding is
   the sealer's job, and the sealed format carries the message's own length.
3. Open an escrow to the mailbox's payee, or reuse one. Then call `deposit(...)` with the next
   cumulative amount. The voucher is signed over this deposit only, so it cannot be spent on
   another one.
4. The mailbox answers with a signed `Receipt`.

A recipient can accept mail only from named depositors (`set_policy`), and can give a named sender
a capability to deposit (`capability`). A sender can prove who it is (the `sender` argument);
otherwise the mailbox learns the sender only as far as the paying account names one. The proof names
the escrow that pays, so nobody else can pay to deliver the same message again under the sender's
name.

## Collecting

`list`, `collect` and `ack` are signed by the recipient's own key, which its DID document names.
A message can be collected again until it is acknowledged. After the acknowledgement, the mailbox
deletes it.

## Recipients addressed by tag

A recipient that doesn't want the operator to link its mail to its DID can be addressed by tag. The
tag is `tag:` followed by the SHA-256 of a composite key that the recipient makes for one epoch
(`recipient_tag`). The recipient tells its contacts the current tag inside their sealed conversation.
Every request for a tag is signed by that tag's key, with both the P-256 and the ML-DSA-65 halves;
no DID document is consulted. A new key each epoch gives a new tag, and the operator cannot link
one epoch's tag to the next. Policies, capabilities and key packages work for a tag as they do for a
DID.

## Key packages

A recipient uploads one-time key packages (`upload_prekeys`) and an optional last-resort package.
A sender pays to fetch one (`fetch_prekey`), so it can start a conversation while the recipient is
offline. The mailbox serves each one-time package once. Anyone who pays can fetch a recipient's packages, up
to 60 an hour, so a paying attacker can use them up and leave only the last-resort package: a session
started from it has weaker forward secrecy than one started from a one-time package. A recipient who
sees its packages gone uploads more.

## Group sessions (preview)

With the `mls` feature, `tenzro-mailbox` keeps MLS (RFC 9420) groups: `GroupMember` creates a group,
adds and removes members, updates its own keys, and seals and opens messages. The cipher suite is
hybrid X25519 with ML-KEM-768 (`GROUP_CIPHERSUITE`), so a recording of a group's traffic stays
sealed against a quantum computer. Signatures inside the group use Ed25519.

A member publishes key packages in its mailbox with `upload_prekeys`, each one a `MemberPackage`
signed by a key of its DID. A member who adds it fetches a package with `fetch_prekey` and checks it
against the DID document (`MemberPackage::verify`) before calling `add`. This way a mailbox cannot
substitute a key package of its own. The other members rely on that check, as MLS relies on its
authentication service.

A member's DID in a group is a claim, not a proof. The MLS credential names a DID, and the member
that adds it checks the DID against its key package. The other members, and a member who joins from a
welcome, accept any credential the group's MLS state carries, so they rely on the adder's check. A
group whose members must not rely on one another's check needs a credential validator, which this
preview does not have.

Commits, welcomes and messages are ordinary sealed messages: the sender deposits each one in every
other member's mailbox. Members apply commits in the order the group made them. Group state is kept
in memory, so a member that restarts has to join again.

## Shared files (preview)

With the `files` feature, `share` seals a file for several recipients as an age v1 file. The file
has one random file key and one stanza per recipient (type `tenzro-hybrid`). Each stanza wraps the
file key with the hybrid X25519 + ML-KEM-768 seal, so reading it needs both key exchanges broken.

A recipient publishes its hybrid key as a `RecipientCard`, signed by a key of its DID. A sharer seals
only to cards that `RecipientCard::verify` accepted against the DID document. The recipient's
private half can be derived on demand from its TPM or Secure Enclave.

Every shared file comes with a `ShareManifest`, signed by the sharer's DID key. It names the
recipients and the digest of the file, so a recipient can check who else was given it. `open` checks
the manifest before it opens the file.

To take a recipient off, call `reshare`: it seals the content again under a new file key, to the
others only. A copy the removed recipient already holds cannot be recalled. A sharer who wants to
reshare later includes its own card.

The sealed bytes start with the age file's length, so a depositor can pad them to a size class. A
file larger than the largest size class does not fit in a mailbox.

## Signatures

A recipient or a sender whose identity has an ML-DSA-65 key must sign with it. An identity without
one is accepted on P-256 alone, and what it signs is then only as safe as P-256 is against a quantum
computer. A voucher is always a composite signature. Every signature is under
the `tenzro/mailbox` context, so none of them is valid in any other protocol.

## Limits

The service bounds the ledger reads that a voucher causes before any signature has vouched for it: 6000
a minute in all and 120 a minute for one escrow. It keeps at most 256 MiB of key packages and depositor
policies for all recipients together, which matters for recipients addressed by tag, since anyone can
make a tag.

## What the operator learns

The operator learns:

- each message's recipient, size class, lifetime and arrival time
- the paying account
- the sender, when the sender proves itself
- when the recipient collects and acknowledges

It never learns a message's content. Sender anonymity is not promised: a sender who wants its
deposits unlinked pays each conversation from a fresh funded account.
