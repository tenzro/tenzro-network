# Network profiles

A release ships `share/network/<chain_id>.toml` beside `bin/`; a node started
without `--boot-nodes` joins the network through it (see
`crates/tenzro-node/src/network_profile.rs`). Put the file for a network here as
`config/network/<chain_id>.toml` and the release builders
(`scripts/release/build-linux.sh`, `build-macos.sh`, `build-windows.ps1`) ship it. A release with no
profile is refused unless `ALLOW_NO_NETWORK_PROFILE=1`.

The profile is packaging. It is not a genesis field and does not change the
genesis hash.

```toml
version = 1
chain_id = 13380

[relay]
url = "https://relay.example.net/"
operator_did = "did:tenzro:machine:<64 hex>"   # the relay operator's machine DID

[[validators]]
did = "did:tenzro:machine:<64 hex>"            # one per genesis validator
# relay = "https://other-relay.example.net/"   # default: [relay].url
```

An optional table sets the identity gate mode for nodes of the network; a node
config that sets `[onboarding] mode` itself wins:

```toml
[onboarding]
mode = "enforce"   # off, audit or enforce
```

The DIDs are printed on each host by `tenzro-node tpm provision`.
