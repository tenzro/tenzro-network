# tenzro-embedded

A C library for machines too small to run a node: microcontrollers that take
part in the network through a node's public interface, with their own machine
identity.

What it holds today: the exact bytes a Tenzro signature covers (the message
representative and the P-256 digest of each signature context), the bytes
of an escrow voucher, the digest of a sensor reading, the evidence item
that carries a signed reading to the ledger, the hash of a native
transaction with the type of a transfer, and the JSON-RPC request that
submits a signed transfer. The device signs them with its
own key; the ledger verifies them as it does any other signature.

To join and read: the account its P-256 key holds (`tz_account_slot`), the
command its operator runs to register it as a machine they control
(`tz_enrolment_command`, printed on the device's console), and the requests
for its balance, its next nonce and the network's finality with readers for
the node's answers (`tz_read_request`, `tz_read_quantity`,
`tz_read_finality`). The readers check the answer's structure and its id and
decode only the members asked for. The finality reader reports the heights
the node gives; checking the certificate on the device (a quorum of ML-DSA-65
and P-256 signatures) waits for the measurements on the boards.

Signed updates with roll back (`include/tenzro/update.h`): the firmware
comes on a release channel of its own in the node's channel format
(`docs/UPDATE-MANIFEST.md`): a targets document in an envelope, signed by
the release key under the channel's domain, naming each platform's image
(`name` `firmware`) by path, length and SHA-256. `tz_update_target_of`
takes a document only when the release key signed it (raw `r || s` or DER),
its version is above the one the device installed last, and it names one
image for the device's platform. The firmware then writes the image to its
spare slot, checks the SHA-256 as it writes, and boots it on trial; with
ESP-IDF's app roll back on, the bootloader returns to the old image unless
the new one marks itself good once it has reached a node, and only then
stores the document's version as the floor for the next one. Freshness
comes from that floor: a device has no clock to check a timestamp role by.

- `include/tenzro/sign.h`: the interface.
- `include/tenzro/update.h`: the update check.
- `port/`: the two hashes and the P-256 check the library needs, through the
  PSA Crypto API on a device and through OpenSSL in the host tests.
- `CMakeLists.txt`: an ESP-IDF component.

## Tests

`make test` builds the library for the host and checks it against
`sdk/fixtures/signing/composite.txt`. That file is written by the
`signing_vectors` test of `tenzro-crypto` from the code the ledger verifies
with, so the two cannot drift apart unnoticed.
