# Signing log

Each time the release key (fingerprint `c88aaee70b3c0bf17a994bad44963a6a72359b2e1497df9a15a40ed099aeb72d`, see [RELEASE-KEYS.md](RELEASE-KEYS.md)) signs a
manifest, one row is added here. Rows are only ever appended. A manifest that is not listed here was not signed
with this key by the release process; a signature over `SHA256SUMS` can be checked against the "SHA-256 of
SHA256SUMS" column with `sha256sum SHA256SUMS`.

| Signed (UTC) | Build commit | Archives | SHA-256 of SHA256SUMS | Signature file |
|---|---|---|---|---|
