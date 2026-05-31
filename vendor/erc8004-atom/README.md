# 8004-atom

ATOM Engine - AI Agent Trust & Reputation Metrics for Solana

## Overview

ATOM (AI Agent Trust On-chain Model) is the reputation computation engine for ERC-8004 compliant agent registries. It provides:

- **HyperLogLog** (256 registers, 4-bit) for unique client estimation (~6.5% error)
- **Dual EMA** (fast α=0.30, slow α=0.05) for score smoothing
- **MRT Protection** (Minimum Retention Time) prevents ring buffer gaming
- **Quality Circuit Breaker** with freeze mechanism and floor protection
- **Sybil Tax** with VIP lane for verified callers
- **Trust Tiers**: Platinum/Gold/Silver/Bronze with hysteresis

## Program ID

```
AToMufS4QD6hEXvcvBDg9m1AHeCLpmZQsyfYa5h9MwAF
```

## Installation

### As Cargo Dependency (for CPI)

```toml
[dependencies]
atom-engine = { git = "https://github.com/QuantuLabs/8004-atom.git", tag = "v0.2.2", features = ["cpi"] }
```

### Local Development

```bash
# Clone
git clone https://github.com/QuantuLabs/8004-atom.git
cd 8004-atom

# Install dependencies
yarn install

# Build
anchor build

# Test (uses localnet with devnet programs cloned)
anchor test
```

## Usage

### Initialize ATOM for an Agent

```typescript
import { getAtomConfigPda, getAtomStatsPda } from "./tests/utils/helpers";

const [atomConfigPda] = getAtomConfigPda(atomEngine.programId);
const [atomStatsPda] = getAtomStatsPda(assetPubkey);

// Update stats with feedback
await atomEngine.methods
  .updateStats(clientHash, score)
  .accounts({
    payer: wallet.publicKey,
    asset: assetPubkey,
    collection: collectionPubkey,
    config: atomConfigPda,
    stats: atomStatsPda,
    systemProgram: SystemProgram.programId,
  })
  .rpc();
```

### Get Reputation Summary

```typescript
const summary = await atomEngine.methods
  .getSummary()
  .accounts({
    asset: assetPubkey,
    stats: atomStatsPda,
  })
  .view();

console.log("Trust Tier:", summary.trustTier);
console.log("Quality Score:", summary.qualityScore);
console.log("Unique Clients:", summary.uniqueClients.toNumber());
```

## Related

- [8004-solana](https://github.com/QuantuLabs/8004-solana) - Agent Registry using ATOM via CPI
- [ERC-8004 Spec](https://github.com/QuantuLabs/8004-spec) - Standard specification

## License

MIT
