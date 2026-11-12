# Release signing keys

The keys that sign Tenzro releases, with their fingerprints. This file is one of several independent
places the fingerprint is published; see [VERIFY-DOWNLOAD.md](VERIFY-DOWNLOAD.md) for how to use it.

## Current key

| | |
|---|---|
| Purpose | signs `SHA256SUMS` of each release; nothing else is signed (the provenance is unsigned and archives have no signature of their own) |
| Algorithm | ECDSA P-256 with SHA-256; signatures are base64 DER, as `cosign verify-blob` expects |
| Held in | a TPM 2.0 chip; created non-exportable (fixed to the TPM and its parent, sensitive data generated inside) |
| Authorisation | a passphrase typed by the release signer at each signing; never stored, scripted or logged |
| Transparency log | none; verify with `--insecure-ignore-tlog=true` |
| Fingerprint (SHA-256 of DER SubjectPublicKeyInfo) | `c88aaee70b3c0bf17a994bad44963a6a72359b2e1497df9a15a40ed099aeb72d` |
| Status | current |

Public key (`tenzro-release.pub`):

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3/NYEWx6w1OdV23xU656MhkpzxNM
PAP5jhmCYs7mWBx/W6lVL7cgwsTRlzcNq8iMIyU2lPMsmGNC7nZkxpaTZA==
-----END PUBLIC KEY-----
```

Check a copy of the key against the fingerprint:

```bash
openssl pkey -pubin -in tenzro-release.pub -outform DER | sha256sum
```

The fingerprint is also published at <https://tenzro.com/docs/verify-your-download> and
<https://downloads.tenzro.com/RELEASE-KEY.txt>. All published copies must agree.

## Revoked and retired keys

None.

A bare cosign key has no revocation mechanism. If this key is ever retired or suspected, the notice will be
added here and at the other places above, with the date and the fingerprint of the key that replaces it,
and the replacement will be announced in a statement signed by this key where it is still trusted. Users
who keep their own copy of `tenzro-release.pub` and are told of a changed key should stop and ask.

## Rotation

Archives signed with this key remain verifiable with
it after a rotation.
