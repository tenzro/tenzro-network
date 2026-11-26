# App transport (preview)

The app transport lets the devices of applications built on Tenzro (a messenger, a file-sharing app) reach each
other through a node: a device signs in to the node over WebTransport and opens a stream to a device of another
identity, and the node carries the bytes. What travels inside a stream is the application's: devices seal it end to
end, and the node only moves it and counts it.

It is a preview. It is off unless the node is built with the `app-transport` feature and the operator configures
`[app_transport]`, and the wire format may still change. A node without the section opens no socket, starts no task
and mints no certificate; a node built without the feature refuses to start with the section.

A device reaches devices signed in to the same node, and, when both nodes carry streams between nodes, devices
signed in to another node. A node that serves the relay role can also let its signed-in devices use the relay.

## Configuration

```toml
[app_transport]
listen = "0.0.0.0:4433"          # UDP address the listener binds
url = "https://node.example.org:4433/app"   # how devices reach it; host = certificate name, path = session path
# cert = "/etc/tenzro/app-transport/fullchain.pem"   # the operator's own certificate (PEM), with:
# key = "/etc/tenzro/app-transport/key.pem"
max_sessions = 1024              # devices signed in at once (also the connection limit)
pending_per_ip = 8               # connections one IP address may hold before they sign in
bytes_per_second = 1048576       # carried for one identity, both directions together
burst_bytes = 4194304            # one identity may move at once after a pause
opens_per_minute = 60            # streams one identity may open in a minute
pending_per_device = 8           # streams that may wait for one device's answer
sessions_per_identity = 8        # devices of one identity signed in at once
streams_per_identity = 64        # streams one identity may have open at once
idle_secs = 300                  # a carried stream that moves nothing either way this long ends
# peer_streams = 64              # streams one other node may carry here at once; unset: none between nodes
# paid_mebibytes = 256           # mebibytes a paid session pays for up front; unset: no paid carriage
# relay_connections_per_identity = 4   # relay connections one signed-in identity may hold; unset: none
```

With `cert` and `key` the node serves the operator's certificate, and any client that trusts its issuer connects.
Without them the node mints its own: a self-signed ECDSA P-256 certificate valid for 13 days for the host in `url`,
replaced by the next one every 5 days. A client pins it by its SHA-256 hash (in a browser,
`serverCertificateHashes`, with `allowPooling: false`). The node logs both hashes when the listener starts. The
hashes come signed by the key the node's access tokens verify under, as a publication naming the node and the
listener (`app-transport`). A publication has no expiry of its own: a client checks its signing time and each hash's
validity before pinning.

A device finds the listener and the hashes three ways: `tenzro_getAppTransportInfo` returns the URL and the signed
publication; the node's DID document lists the URL as a `TenzroAppTransport` service and each hash, current first,
as a `TenzroPinnedCertSha256` service; and the operator can hand out the hashes the node logs.

The key exchange prefers X25519MLKEM768. A client that sends the hybrid key share gets it; one that sends a
classical key share is answered on it.

## Who may sign in

A device signs in with an access token of this node and a DPoP proof made over the session's nonce. The node sends
the nonce first on the session's control stream; the proof's `htu` is `tenzro-app://<nonce>` and its `htm` is
`POST`, so a proof made for one session is refused on every other. A device with no token is refused whatever the
policy says. An address holds at most `pending_per_ip` connections that have not signed in;
one more is refused at the handshake, and a connection stops counting once it signs in.

The access policy decides with the rule `access.toml` gives the **`iroh` surface for the `read` class**: a caller
that rule refuses cannot sign in, and a rule with a tier holds sign-ins to that tier's rate. A rule that asks for
payment (`paid`) makes the device pay for carriage; see below. A delegated agent signs in only within
its consensus Terms, and a revoked or quarantined identity is refused.

The node answers a sign-in with a `welcome` it signs twice over the session's nonce and what it says: with the
P-256 key its access tokens and the certificate publication verify under, and with the ML-DSA-65 key its DID
document names `#pq-key-1`. A device that checks both knows the node it pinned is the node whose tokens it holds,
and the ML-DSA-65 signature still holds once P-256 does not.

A device that can export keying material from its TLS session (RFC 5705; a native client can, a browser
cannot) binds its sign-in to that session: it exports 32 bytes under the label
`EXPORTER-tenzro-app-transport-sign-in` with the nonce as context, sends them hex-encoded as `binding` in its
`hello`, and makes its proof for `tenzro-app://<nonce>/<binding>`. The node exports the same and refuses a binding
that differs, so a token and proof relayed through another TLS session do not sign in. The Rust SDK always binds;
a browser signs in unbound.

A session lasts as long as its token. Before the token ends the device sends a fresh `hello` on the control stream;
otherwise the node closes the session. A fresh `hello` cannot change the session's identity or device.

## Who may reach a device

A signed-in device is reachable by nobody until it says who may open streams to it: identities it names, or anyone
opening with an application label it names. A later `listen` replaces the earlier one. An open the target does not
admit is answered exactly as an open to an identity with no device on the node, so a sender learns nothing about who
is signed in. Each identity opens at most `opens_per_minute` streams a minute and has at most `streams_per_identity` open at
once, at most `sessions_per_identity` of its devices are signed in at once, and at most `pending_per_device`
streams wait for one device's answer. A carried stream that moves nothing either way for `idle_secs` ends.

## Datagrams

Once a stream between two devices signed in to the node is accepted, each end has a flow number for it (`flow` in
`opened` and in `incoming`). A datagram a device sends is its flow number as a little-endian `u32`, then the
payload; the node forwards it to the other end under that end's number, for as long as the stream is carried,
and counts the payload against the stream's opener like the stream's own bytes. A datagram the opener's rate or
paid budget has no room for at that moment is dropped rather than held. A stream through another node has no flow.
A datagram is bounded by the path's datagram size, less the 4 bytes of its flow number; datagram sizes and loss
through the node have not been measured.

## Streams between nodes

With `peer_streams` set, a device opens a stream to a device signed in to another node by naming that node's
machine DID in `via`. Its node finds the other node by the endpoint record it holds for that DID and carries the
stream under the iroh protocol `tenzro/app-stream/1`, which it serves only when `peer_streams` is set (the DID
document lists it among the node's protocols then). The other node admits the protocol only from registered
machines, as it does every protocol outside onboarding, holds each node to `peer_streams` streams at once, and
applies the target device's `listen` exactly as for a device of its own: the target sees the carrying node in
`via`. The opener's node counts the stream against the opener; the target's node counts it against the node that
carried it there. Without `peer_streams` a node refuses an open naming another node and serves no such protocol.

## Paid carriage

When the access policy's rule for the `iroh` surface's `read` class is `paid`, its price is the price of one
mebibyte carried for the device's identity, both directions together, in the asset the rule names; that asset
must be the one the node is paid in (`[payments] default_asset`). The node answers the device's `hello` with
`payment_required {challenge, price, asset}`: an x402 challenge for `/app-transport` whose amount is the price
times `paid_mebibytes`. The device signs in again with a credential for it in the `payment` field of a fresh
`hello`. The node checks the credential before carrying anything (the payer signed a ceiling within the challenge,
and its identity, delegation and spending policy admit it) and holds the identity to the mebibytes that ceiling
buys: a stream that would carry past them ends. When the session ends, however it ends, the node charges the
mebibytes started, beneath the ceiling, with a usage record its meter signs, and settles through its payment
gateway. One identity pays for one session at a time. A node with no payment gateway, or with `paid_mebibytes`
unset, refuses a device the policy asks to pay. The charge is settled under the `upto` scheme when the node's x402
server issues it; a pending charge does not survive a restart of the node.

## The relay

A node that serves the relay role and sets `relay_connections_per_identity` lets an app device signed in to it
use that relay, beyond the machines the identity gate admits (see NODE-NETWORKING.md). The device presents an
access token of this node and a DPoP proof made for the relay's client URL (`<relay URL>/relay`, method `GET`),
either in the `Authorization: DPoP <token>` and `DPoP` headers of its WebSocket request or, for a client that
sets no headers, as the `token` and `dpop` query parameters. The node judges it as it judges a sign-in to the app
transport. One identity's devices hold at most `relay_connections_per_identity` relay connections at once. The
relay's own per-client byte rate applies to them as to every client; the node counts their connections, not
their bytes.

## Metering

The node counts, for each identity, the streams it opened that reached their target and the bytes carried from and
to it, and holds it to `bytes_per_second` (both directions together) with `burst_bytes` of slack. The counters are
in memory and start again with the node. `tenzro_getAppTransportUsage` returns a signed-in caller's own counters, and
every identity's to the node's administrators.

## Wire format

Every frame is a little-endian `u32` length and that many bytes of JSON, at most 16 KiB (a welcome carries an ML-DSA-65 signature), tagged by `type`. The node
opens the control stream: `challenge {nonce}`, then the device's `hello {access_token, dpop}`, answered by
`welcome {did, device, expires_at, signature, pq_signature}`, `payment_required {challenge, price, asset}` (then
another `hello` carrying `payment`) or `refused {reason}`. Both signatures are base64url
over SHA-256 of `tenzro/app-transport/welcome/v1`, then the nonce, the DID and the device each as a big-endian `u64`
length and its bytes, then `expires_at` as a big-endian `u64`: `signature` is ECDSA P-256 `r || s`, and
`pq_signature` is ML-DSA-65 under the context `tenzro/app-transport/welcome`. On it the device also sends `listen {from, apps}`
(answered `listening`) and later `hello`s. A stream the device opens starts with `open {to, device, via, app}`,
answered `opened {device}` or `refused {reason}`; a stream offered to a device starts with
`incoming {from, device, via, app}`, answered `accept` or `decline`. A stream between nodes starts with
`carry {from, from_device, to, device, app}` from the opener's node, answered `opened {device}` or
`refused {reason}`. After the first frame each way a stream is raw bytes, and an end in one direction is passed on.

## Not tested

No real browser, phone or Safari session has been run against it, and a node that starts in a test needs its machine
identity key in hardware, so the end-to-end tests run only where one is present. Long Safari sessions are reported
to stall; treat Safari as untested. Streams between nodes are tested between two listeners in one process joined by
an in-memory pipe; two nodes carrying a stream over iroh have not been run.
