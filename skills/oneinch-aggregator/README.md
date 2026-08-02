# 1inch Aggregator Skill

1inch DEX aggregation skill for the Tenzro Network. Covers spot swaps via the 1inch Aggregation Protocol and cross-chain swaps via Fusion+.

## Backend

| Field | Value |
|---|---|
| Provider | 1inch Developer Portal |
| Auth | Required (API key from `https://business.1inch.com/portal`) |
| Categories | DEX aggregation, Fusion+ cross-chain |

## Skill registration

This skill is registered in the Tenzro Skills Registry (`CF_SKILLS`) at node startup as:

| Field | Value |
|---|---|
| Skill ID | `oneinch-aggregator` |
| Category | `defi` |
| Tags | `1inch, dex, aggregator, swap, defi, fusion` |

Discover it from any Tenzro node via `tenzro_listSkills` / `tenzro_searchSkills`.

## Quick Start

Set your 1inch API key in the environment, then call the swap routing tools:

```bash
export ONEINCH_API_KEY=your_key_here
```

See [`SKILL.md`](SKILL.md) for the full tool reference, payload shapes, and Fusion+ flow examples.

## License

Apache-2.0
