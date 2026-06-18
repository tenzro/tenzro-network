# Tenzro CAIP-2 Namespace — Staging Directory

This directory stages the Tenzro namespace specification for upstream
submission to [ChainAgnostic/namespaces][].

## Layout

```
docs/caip2-namespace/
├── README.md            ← this file (not part of the upstream PR)
└── tenzro/              ← copied verbatim into ChainAgnostic/namespaces/tenzro/
    ├── README.md        ← namespace overview
    ├── caip2.md         ← chain identifier (CAIP-2)
    ├── caip10.md        ← address format (CAIP-10)
    ├── caip19.md        ← asset identifier (CAIP-19)
    └── caip25.md        ← provider authorization (CAIP-25)
```

The `tenzro/` subdirectory mirrors the upstream layout: each ChainAgnostic
namespace lives under `namespaces/<namespace>/` and contains a `README.md`
plus per-CAIP markdown files. Compare `namespaces/solana/` or
`namespaces/eip155/` upstream for the convention.

## Authoritative facts encoded in these files

These values are referenced across multiple files; if any change, update
all of them in lockstep.

| Field                    | Value                                                                 |
| :---                     | :---                                                                  |
| Namespace identifier     | `tenzro`                                                              |
| Testnet genesis hash     | `92bd27db9713293097f0e63476e3911e77b706c1b20f4a5e97d44fe7a8d51648`    |
| Testnet CAIP-2 reference | `tenzro:92bd27db9713293097f0e63476e3911e` (first 16 bytes / 32 hex)   |
| Testnet EVM chain ID     | `1337`                                                                |
| Mainnet CAIP-2 reference | TBD — populated at mainnet launch                                     |
| Address width            | 32 bytes (hex `0x` + 64 chars OR 44-char base58btc)                   |
| Native asset (slip44)    | `tenzro` (pre-registration; SLIP-44 PR pending)                       |
| Token / NFT IDs          | 32-byte SHA-256 of `creator || nonce`                                 |
| Wallet `rdns` (EIP-6963) | `network.tenzro.wallet`                                               |

## Upstreaming workflow

The upstream submission is gated on explicit maintainer authorization
(`gh pr create` crosses the boundary into shared external state). The
process when authorized:

1. **Fork** [ChainAgnostic/namespaces][] under the user's GitHub
   account or the `tenzro` org.

2. **Copy** the `tenzro/` directory verbatim into the fork at
   `namespaces/tenzro/`:

   ```bash
   git clone git@github.com:tenzro/namespaces.git /tmp/chain-agnostic-namespaces
   cd /tmp/chain-agnostic-namespaces
   git checkout -b add-tenzro-namespace
   cp -R ~/AI/tenzronetwork/docs/caip2-namespace/tenzro namespaces/tenzro
   git add namespaces/tenzro
   git commit -m "Add tenzro namespace (CAIP-2/10/19/25)"
   git push -u origin add-tenzro-namespace
   ```

3. **Open the PR** against `ChainAgnostic/namespaces:main` with title
   `Add tenzro namespace (CAIP-2/10/19/25)` and a body summarizing:
   - Tenzro Ledger is a HotStuff-2 BFT network
   - Multi-VM execution layer (EVM + SVM + Canton/DAML) over a single
     native balance (Sei-V2 pointer model)
   - One namespace + four CAIPs in this PR (2 / 10 / 19 / 25)
   - Mainnet reference will be added in a follow-up PR at mainnet launch
   - Repo: <https://github.com/tenzro/tenzro-network>

4. **Update `discussions-to`** in each markdown frontmatter once the
   PR number is assigned (currently set to `TBD`).

5. **File the SLIP-44 PR** in parallel against
   [satoshilabs/slips][] to register a coin index for `TNZO`. Until
   that PR is merged, the `slip44` reference in `caip19.md` uses the
   pre-registration string `tenzro`.

[ChainAgnostic/namespaces]: https://github.com/ChainAgnostic/namespaces
[satoshilabs/slips]: https://github.com/satoshilabs/slips
