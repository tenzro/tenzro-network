# Cross-VM Unified Token Architecture

**Version:** 1.0.0
**Date:** 2026-04-19
**Status:** Implemented

## Executive Summary

Tenzro Ledger is a multi-VM L1 blockchain supporting EVM (revm), SVM (solana_rbpf), and DAML (Canton 3.x). This document describes the implemented architecture for cross-VM token interoperability based on the Sei V2 pointer model.

## Design Principles

### 1. Pointer Model Over Bridge Model (Sei V2)

Instead of lock-and-mint bridging, we use **Sei V2's pointer contract pattern**: thin interface contracts that expose the same underlying balance through different VM APIs. A transfer via the ERC-20 interface and a transfer via the native layer affect the **same balance**.

**Rationale:** Bridges create fragmented liquidity, introduce bridge risk, and add latency. Pointer contracts eliminate all three issues.

### 2. System Precompiles for Native Access

Following Cosmos EVM's `0x0800+` precompile pattern, we place Tenzro system precompiles in the `0x1000+` address range.

**Address Allocation:**

| Address | Name | Purpose |
|---------|------|---------|
| `0x...0100` | TEE_VERIFY | TEE attestation verification |
| `0x...0101` | ZK_VERIFY | ZK proof verification |
| `0x...0102` | MODEL_INFERENCE | AI inference (stub) |
| `0x...0103` | SETTLEMENT | Payment settlement (stub) |
| `0x...1001` | TNZO_BRIDGE | Native TNZO <-> wTNZO ERC-20 lock/unlock |
| `0x...1002` | TOKEN_FACTORY | Deterministic ERC-20 deployment (CREATE2 + ERC-1167) |
| `0x...1003` | CROSS_VM_BRIDGE | Cross-VM token transfer (EVM <-> SVM <-> DAML) |
| `0x...1004` | STAKING | Stake/unstake TNZO from EVM contracts |
| `0x...1005` | GOVERNANCE | Vote on proposals from EVM contracts |
| `0x...1006` | NFT_FACTORY | ERC-721 deployment with VRF-based mintRandom |
| `0x...1007` | VRF_VERIFY | RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI verifiable random function |
| `0x...101a` | ERC8004_IDENTITY | ERC-8004 Trustless Agents — `registerAgent` / `getAgent` (selectors byte-identical to Ethereum mirror) |
| `0x...101b` | ERC8004_REPUTATION | ERC-8004 — `submitFeedback` / `getFeedback` / `getFeedbackCount` |
| `0x...101c` | ERC8004_VALIDATION | ERC-8004 — `validationRequest` / `validationResponse` / `getValidation` |

### 3. Deterministic Addresses via CREATE2

All system-deployed contracts use CREATE2 for deterministic, cross-chain-consistent addresses. The wTNZO ERC-20 contract lives at well-known address `0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93`.

### 4. Minimal Proxy Clones for Token Factory (ERC-1167)

User-created ERC-20 tokens are deployed as ERC-1167 minimal proxy clones (~45 bytes each) pointing to a shared implementation. This reduces deployment gas from ~1.5M to ~100K.

### 5. Agent-Native via TDIP Delegation Scopes

Agents deploy tokens and contracts via TDIP delegation scope enforcement: `allowed_operations: ["contract_deploy", "token_create"]` so agents can only create tokens within their delegated authority.

### 6. SPL Compatibility via Account Model Adapter

SVM token operations map to Tenzro's SPL-compatible token program. Following Neon EVM's pattern, we implement an SPL Token Program that stores balances in Solana-style Associated Token Accounts (ATAs) while reading from the unified token registry underneath.

**9-decimal precision:** Native 18-decimal amounts are converted to 9-decimal SPL amounts with truncation to match Solana convention and avoid u64 overflow (max representable: ~18.4 TNZO with 18 decimals).

### 7. Canton CIP-56 for Enterprise

DAML token operations follow the CIP-56 standard with two-step transfer (sender creates TransferInstruction, receiver accepts), embedded compliance rules, and atomic DvP settlement.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │         Unified Token Registry           │
                    │     (tenzro-token/src/registry.rs)       │
                    │                                          │
                    │  TokenId -> TokenDefinition               │
                    │    - native_balance: u128                 │
                    │    - evm_contract: Option<[u8;20]>        │
                    │    - svm_mint: Option<[u8;32]>            │
                    │    - daml_template: Option<String>        │
                    │    - total_supply, decimals, metadata     │
                    │  RocksDB persistence: CF_TOKENS           │
                    └──────────────┬───────────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
    ┌─────────▼──────────┐ ┌──────▼───────┐ ┌─────────▼──────────┐
    │   EVM Interface     │ │ SVM Interface │ │  DAML Interface     │
    │                     │ │              │ │                     │
    │ wTNZO ERC-20        │ │ wTNZO SPL    │ │ TNZO CIP-56        │
    │ (pointer at         │ │ Token Mint   │ │ Holding Template    │
    │  0x7a4bcb13...)     │ │              │ │                     │
    │                     │ │ SPL Token    │ │ TransferFactory     │
    │ TokenFactory        │ │ Program      │ │ TransferInstruction │
    │ (ERC-1167 clones)   │ │              │ │                     │
    │                     │ │ ATA accounts │ │ DvP settlement      │
    │ System Precompiles  │ │ 9-decimal    │ │                     │
    │ 0x1001-0x1007 +     │ │ truncation   │ │                     │
    │ 0x101a-0x101c       │ │              │ │                     │
    └─────────────────────┘ └──────────────┘ └─────────────────────┘
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │     Cross-VM Bridge Engine       │
                    │  (precompile 0x1003)             │
                    │                                  │
                    │  EVM wTNZO -> burn -> native     │
                    │  native -> lock -> mint SVM wTNZO│
                    │  Atomic cross-VM swaps           │
                    └─────────────────────────────────┘
```

## Component Design

### 1. Unified Token Registry (`tenzro-token/src/registry.rs`)

The registry is the canonical source for all token metadata and cross-VM address mappings.

```rust
pub struct TokenDefinition {
    pub token_id: TokenId,              // SHA256(creator || nonce)
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u128,
    pub max_supply: Option<u128>,
    pub creator: Address,
    pub token_type: TokenType,          // Native | ERC20 | SPL | CIP56 | CrossVm
    pub vm_addresses: VmAddresses,      // Cross-VM address mapping
    pub permissions: TokenPermissions,  // Mintable, burnable, pausable, freezable
    pub created_at: u64,
    pub metadata: TokenMetadata,        // URI, description, icon
}

pub struct VmAddresses {
    pub evm: Option<[u8; 20]>,         // ERC-20 contract address
    pub svm: Option<[u8; 32]>,         // SPL mint address
    pub daml: Option<String>,          // DAML template ID
    pub native: Option<Address>,       // Native token address (TNZO only)
}

pub struct TokenRegistry {
    tokens: DashMap<TokenId, TokenDefinition>,
    by_evm_address: DashMap<[u8; 20], TokenId>,
    by_svm_mint: DashMap<[u8; 32], TokenId>,
    by_symbol: DashMap<String, TokenId>,
    storage: Option<Arc<dyn KvStore>>,  // CF_TOKENS column family
}
```

**Persistence:** Write-through to RocksDB `CF_TOKENS` under key patterns `token:{token_id}`, `evm:{address}`, `svm:{mint}`, `symbol:{symbol}`.

### 2. wTNZO ERC-20 Pointer Contract

The wTNZO ERC-20 is a **pointer contract** at well-known address `0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93`. It does NOT hold balances. Every `balanceOf()`, `transfer()`, and `approve()` call is routed through the TNZO_BRIDGE precompile (0x1001) to the native `TnzoToken` balance.

**ERC-20 Interface (all delegated to precompile 0x1001):**

| Function | Behavior |
|----------|----------|
| `name()` | Returns "Wrapped TNZO" |
| `symbol()` | Returns "wTNZO" |
| `decimals()` | Returns 18 |
| `totalSupply()` | Calls precompile: reads `TnzoToken.total_supply()` |
| `balanceOf(owner)` | Calls precompile: reads `TnzoToken.balance_of(owner)` |
| `transfer(to, amount)` | Calls precompile: executes `TnzoToken.transfer(msg.sender, to, amount)` |
| `approve(spender, amount)` | Stores approval in EVM storage (standard ERC-20 mapping) |
| `transferFrom(from, to, amount)` | Checks EVM approval, then calls precompile for transfer |
| `allowance(owner, spender)` | Reads from EVM storage |
| `deposit()` | Payable: locks msg.value native TNZO, credits EVM balance via precompile |
| `withdraw(amount)` | Burns EVM balance via precompile, sends native TNZO to msg.sender |

**EIP-2612 Permit:** Supports gasless approvals via signature.

### 3. TNZO Bridge Precompile (0x1001)

The bridge precompile is the **only code that can modify native TNZO balances from within the EVM**.

**Function selectors:**

| Selector | Function | Gas | Description |
|----------|----------|-----|-------------|
| `0x70a08231` | `balanceOf(address)` | 2,600 | Read native TNZO balance |
| `0xa9059cbb` | `transfer(address,uint256)` | 9,000 | Transfer native TNZO |
| `0x18160ddd` | `totalSupply()` | 2,600 | Read total TNZO supply |
| `0xd0e30db0` | `deposit()` | 9,000 | Lock native TNZO, credit EVM mapping |
| `0x2e1a7d4d` | `withdraw(uint256)` | 9,000 | Burn EVM mapping, unlock native TNZO |
| `0x3eaaf86b` | `_crossVmTransfer(bytes32,uint256,uint8)` | 15,000 | Cross-VM transfer (internal) |

**Security:**
- Only callable by the wTNZO contract address or by EOAs (not arbitrary contracts) for deposit/withdraw
- Transfer validates sender == `msg.sender` from the EVM execution context
- All balance mutations go through `TnzoToken.transfer()` which has overflow checks
- Reentrancy safe: precompile executes atomically, no callbacks

### 4. wTNZO SPL Token Adapter

The SVM adapter creates an SPL-compatible token program that maps to native TNZO balances.

**Architecture:**
- A system SPL Token Program manages wTNZO
- The mint authority is a system PDA (Program Derived Address) — no private key exists
- **Associated Token Accounts (ATAs)** are created per-owner following Solana conventions
- Balance reads go through the unified token registry (same balance as native and EVM)
- **9 decimals** for the SPL representation (matching Solana convention), with the adapter handling decimal conversion (native 18 -> SPL 9, truncation not rounding)

**Operations:**
- `transfer(from, to, amount)` — deducts from sender ATA, credits recipient ATA, updates native balance
- `mint_to(to, amount)` — only callable by bridge program (deposit from native)
- `burn(from, amount)` — only callable by bridge program (withdraw to native)

### 5. TNZO DAML Token Template (CIP-56)

For Canton enterprise integration, TNZO is represented as a CIP-56-compliant DAML contract.

**Template structure:**
```
template TnzoHolding
  with
    owner : Party
    amount : Decimal
    admin : Party
  where
    signatory owner, admin

    choice Transfer : ContractId TnzoHolding
      with
        newOwner : Party
        transferAmount : Decimal
      controller owner
      do
        -- Validates against native balance via oracle
        -- Creates TransferInstruction for receiver consent
        create TnzoTransferInstruction with ...

    choice Deposit : ContractId TnzoHolding
      controller admin
      do
        -- Called by bridge when native TNZO is locked
        create this with amount = amount + depositAmount

    choice Withdraw : ContractId TnzoHolding
      controller owner
      do
        -- Burns DAML holding, unlocks native TNZO
        create this with amount = amount - withdrawAmount
```

**Integration:** The `DamlExecutor` submits commands to the Canton participant, and the bridge precompile synchronizes balances bidirectionally.

### 6. Cross-VM Bridge Precompile (0x1003)

Handles atomic cross-VM token transfers.

**Flow: EVM -> SVM**
1. EVM contract calls `crossVmTransfer(svm_address, amount, VM_SVM)`
2. Precompile burns wTNZO-EVM balance (updates native TnzoToken)
3. Precompile mints wTNZO-SPL to the target SVM address (updates native TnzoToken)
4. Both operations are atomic within the same block

**Flow: SVM -> EVM**
1. SVM program calls cross-VM system instruction
2. Burns SPL token, credits native balance
3. Native balance now accessible via wTNZO ERC-20

**Flow: Any -> DAML**
1. Lock native TNZO via bridge
2. Submit `Deposit` command to Canton participant
3. Canton creates/updates `TnzoHolding` contract

### 7. Token Factory (0x1002)

Permissionless token creation using ERC-1167 minimal proxy clones.

**ERC-20 Implementation Contract:** A full-featured ERC-20 deployed at genesis with:
- `name`, `symbol`, `decimals` set via `initialize()` (not constructor, since clones share bytecode)
- `mint()` — only callable by token creator (if mintable flag set)
- `burn()` — callable by token holder
- `pause()`/`unpause()` — only callable by creator (if pausable flag set)
- EIP-2612 permit support
- EIP-20 standard events (Transfer, Approval)

**Factory Precompile Interface:**

| Selector | Function | Gas | Description |
|----------|----------|-----|-------------|
| `0x...` | `createToken(string,string,uint8,uint256,uint8)` | 150,000 | Deploy ERC-1167 clone, register in TokenRegistry |
| `0x...` | `predictAddress(bytes32)` | 2,600 | Predict CREATE2 address before deployment |
| `0x...` | `getImplementation()` | 2,600 | Return ERC-20 implementation address |

**CREATE2 salt:** `keccak256(abi.encode(creator, name, symbol, nonce))`

**Registration:** After deployment, the factory calls `TokenRegistry.register_token()` to make the token discoverable across all VMs.

### 8. NFT Factory (0x1006) with VRF-based mintRandom

The NFT factory precompile provides ERC-721 collection deployment with VRF-powered provably-fair minting.

**mintRandom selector 0x52517e21:**

1. ABI-decodes `(collection_id, to, id_space, vrfPubkey, vrfProof, alpha)`
2. Verifies the VRF proof via `tenzro_crypto::vrf::verify`
3. Derives up to four token-id candidates from rolling 8-byte windows of the VRF output; the first collision-free candidate becomes the new token id
4. Derives rarity tier from `output[32]` (0..=255):
   - Common: 70% (0-178)
   - Uncommon: 20% (179-229)
   - Rare: 7% (230-247)
   - Epic: 2.5% (248-254)
   - Legendary: 0.5% (255)
5. Commits owner, URI, balance, and total_supply
6. Returns `(uint256 token_id, uint256 rarity)`

**Gas:** 130,000. If a collision-free slot cannot be found after 4 attempts the call reverts.

### 9. VRF Precompile (0x1007)

RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI verifiable random function.

**Input:**
```
pubkey         (32 bytes)
proof          (80 bytes)
alpha_len      (32-byte big-endian uint)
alpha          (alpha_len bytes)
```

**Output** (on success, 96 bytes):
```
status (32B, right-padded 0x...01)
output (64B, VRF beta)
```

**Gas:** `50_000 + 3 × alpha_len`

## RPC Methods

| Method | Namespace | Description |
|--------|-----------|-------------|
| `tenzro_createToken` | TokenRegistry | Deploy new token via factory |
| `tenzro_getToken` | TokenRegistry | Get token definition by ID or address |
| `tenzro_listTokens` | TokenRegistry | List registered tokens with filtering |
| `tenzro_crossVmTransfer` | TokenRegistry | Transfer token between VMs |
| `tenzro_deployContract` | Blockchain | Deploy contract to specified VM |
| `tenzro_wrapTnzo` | TokenRegistry | Deposit native TNZO -> wTNZO on target VM |
| `tenzro_getTokenBalance` | TokenRegistry | Get balance across all VMs for a token |
| `tenzro_generateVrfProof` | Crypto | Generate VRF proof from secret key + alpha |
| `tenzro_verifyVrfProof` | Crypto | Verify VRF proof and return deterministic output |

## MCP Tools

| Tool | Description |
|------|-------------|
| `create_token` | Create ERC-20/SPL token via factory |
| `get_token_info` | Get token definition and cross-VM addresses |
| `list_tokens` | List all registered tokens |
| `deploy_contract` | Deploy contract bytecode to EVM/SVM/DAML |
| `cross_vm_transfer` | Transfer tokens between VMs |
| `wrap_tnzo` | Wrap native TNZO to EVM/SVM/DAML representation |
| `get_token_balance` | Get balance across all VMs for a token |
| `generate_vrf_proof` | Generate VRF proof and deterministic output |
| `verify_vrf_proof` | Verify VRF proof and return deterministic output |

## CLI Commands

```
tenzro token create    --name --symbol --decimals --supply --vm --mintable --burnable
tenzro token info      --address | --symbol | --token-id
tenzro token list      [--vm evm|svm|daml] [--creator 0x...]
tenzro token wrap      --amount --to-vm evm|svm|daml
tenzro token transfer  --token --to --amount [--from-vm --to-vm]
tenzro token balance   --token --address
tenzro contract deploy --bytecode --vm --constructor-args --gas-limit
tenzro vrf keygen
tenzro vrf prove       --secret-key 0x... --alpha 0xdeadbeef
tenzro vrf verify      --pubkey 0x... --proof 0x... --alpha 0xdeadbeef
```

## Storage Schema

### RocksDB Column Family: `CF_TOKENS`

| Key Pattern | Value | Description |
|-------------|-------|-------------|
| `token:{token_id}` | `bincode(TokenDefinition)` | Token metadata |
| `evm:{address}` | `token_id` | EVM address -> token ID index |
| `svm:{mint}` | `token_id` | SPL mint -> token ID index |
| `symbol:{symbol}` | `token_id` | Symbol -> token ID index |
| `creator:{address}:{token_id}` | `()` | Creator -> token index |
| `approval:{owner}:{spender}:{token_id}` | `u128 LE` | ERC-20 approvals (wTNZO) |

### Existing CF_ACCOUNTS (unchanged)

Native TNZO balances remain in `CF_ACCOUNTS` via `TnzoToken`. The unified registry reads from here for TNZO.

## Security Considerations

1. **Single source of truth:** Native TNZO balances in `TnzoToken` are canonical. All VM wrappers are views, not copies.
2. **No double-spend:** Cross-VM transfers are atomic within a block. The bridge precompile locks then mints in the same execution.
3. **Precompile access control:** Only the wTNZO contract can call TNZO_BRIDGE for balance-mutating operations. EOAs can deposit/withdraw directly.
4. **SPL decimal conversion:** Native 18-decimal amounts are converted to 9-decimal SPL amounts with truncation (not rounding), preventing inflation from rounding errors.
5. **DAML two-step transfer:** Canton transfers require receiver consent, preventing spam deposits.
6. **Factory replay protection:** CREATE2 with creator+nonce salt prevents duplicate deployments.
7. **Agent delegation enforcement:** All agent operations go through TDIP delegation scope checks before execution.
8. **VRF determinism:** RFC 9381 guarantees full uniqueness, trusted collision resistance, and full pseudorandomness for Edwards25519 with correctly validated public keys.

## References

- [Sei V2 Pointer Contracts](https://docs.sei.io/learn/pointers) — Shared-state cross-VM token model
- [Cosmos EVM Precompiles](https://docs.cosmos.network/evm/latest/documentation/overview) — Stateful SDK module precompiles
- [Neon ERC20ForSPL](https://docs.neonevm.org/docs/developing/deploy_facilities/interacting_with_spl_tokens) — SPL-to-ERC-20 mapping
- [CIP-56 Token Standard](https://www.canton.network/blog/what-is-cip-56-a-guide-to-cantons-token-standard) — Enterprise token with receiver consent
- [ERC-1167 Minimal Proxy](https://eips.ethereum.org/EIPS/eip-1167) — Clone factory pattern
- [RFC 9381 — Verifiable Random Functions](https://datatracker.ietf.org/doc/rfc9381/) — ECVRF specification
