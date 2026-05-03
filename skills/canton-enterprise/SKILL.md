---
name: canton-enterprise
version: 0.1.0
author: Tenzro Network
description: Canton Network enterprise skill — submit DAML commands, query contracts, manage parties, transfer Canton Coin (CIP-56), create tokenized assets, execute atomic DvP settlements, upload DAR packages.
tags:
  - canton
  - daml
  - enterprise
  - tokenization
  - dvp
  - cip56
  - rwa
  - institutional
---

# Canton Enterprise Skill

Interact with the Canton Network for enterprise DAML smart contracts, party management, CIP-56 token operations, tokenized asset creation, and atomic Delivery-vs-Payment settlement.

## MCP Endpoint

| Service | URL | Description |
|---------|-----|-------------|
| Canton MCP | `https://canton-mcp.tenzro.network/mcp` | Canton MCP Server (port 3005) |

For local development, use `http://localhost:3005/mcp`.

## Canton Network Overview

Canton is an enterprise-grade blockchain network built on DAML (Digital Asset Modeling Language). It powers $8T+ in tokenized assets monthly across major financial institutions including JPMorgan, Goldman Sachs, and Deutsche Börse.

**Key concepts:**
- **Parties** — Identities on the Canton ledger (allocated per participant)
- **Templates** — DAML contract types (e.g. `Main:Asset`, `CantonCoin:Holding`)
- **Contracts** — Instances of templates with specific data
- **Choices** — Actions that can be exercised on contracts
- **Synchronization Domains** — Privacy-preserving sub-networks

## Tools

### DAML Contracts

#### canton_submit_command
Submit a DAML command (Create or Exercise) to the Canton 3.x JSON Ledger API v2 via /v2/commands/submit-and-wait-for-transaction. Uses identifierFilter for contract queries.

**Parameters:**
- `command_type` (string, required) — "create" or "exercise"
- `template_id` (string, required) — Qualified template ID (e.g. "Main:Asset")
- `contract_id` (string, optional) — Contract ID (required for exercise)
- `choice` (string, optional) — Choice name (required for exercise)
- `arguments` (string, required) — JSON object of template/choice arguments
- `act_as` (string, required) — Party acting on the command
- `user_id` (string, optional) — User ID for the command

**Example (Create):**
```
canton_submit_command(
  command_type="create",
  template_id="Main:Asset",
  arguments='{"issuer":"Alice","owner":"Alice","name":"Bond2025","amount":"1000000"}',
  act_as="Alice"
)
```

**Example (Exercise):**
```
canton_submit_command(
  command_type="exercise",
  template_id="Main:Asset",
  contract_id="00abcdef...",
  choice="Transfer",
  arguments='{"newOwner":"Bob"}',
  act_as="Alice"
)
```

#### canton_list_contracts
Query active contracts filtered by template and party.

**Parameters:**
- `template_id` (string, required) — Template to filter by
- `party` (string, required) — Party with visibility

**Returns:** List of active contracts with IDs and payload.

#### canton_get_events
Get create/archive events for a specific contract.

**Parameters:**
- `contract_id` (string, required) — Contract ID
- `requesting_parties` (string, required) — Comma-separated parties

**Returns:** Creation and archive events with timestamps.

#### canton_get_transaction
Get full transaction tree by ID.

**Parameters:**
- `transaction_id` (string, required) — Transaction ID
- `requesting_parties` (string, required) — Comma-separated parties

**Returns:** Transaction tree with all events.

### Party Management

#### canton_allocate_party
Allocate a new party on the Canton participant.

**Parameters:**
- `party_hint` (string, required) — Desired party identifier hint
- `display_name` (string, required) — Human-readable display name

**Returns:** Allocated party identifier.

#### canton_list_parties
List all known parties on the participant.

**Returns:** List of parties with display names and participant IDs.

### Canton Coin (CIP-56)

#### canton_get_balance
Get Canton Coin balance for a party.

**Parameters:**
- `party` (string, required) — Party identifier

**Returns:** CC balance amount.

#### canton_transfer
Transfer Canton Coin between parties.

**Parameters:**
- `sender` (string, required) — Sender party
- `receiver` (string, required) — Receiver party
- `amount` (string, required) — Amount to transfer

**Returns:** Transfer transaction result.

### Tokenization & Settlement

#### canton_create_asset
Create a tokenized real-world asset (bond, equity, repo) as a DAML contract.

**Parameters:**
- `asset_type` (string, required) — "bond", "equity", or "repo"
- `issuer` (string, required) — Issuer party
- `description` (string, required) — Asset description
- `amount` (string, required) — Nominal amount
- `maturity_date` (string, optional) — Maturity date for bonds (ISO 8601)

**Returns:** Created asset contract ID.

#### canton_dvp_settle
Execute atomic Delivery-vs-Payment settlement (asset delivery simultaneous with cash payment).

**Parameters:**
- `buyer` (string, required) — Buyer party
- `seller` (string, required) — Seller party
- `asset_contract_id` (string, required) — Asset contract to deliver
- `payment_amount` (string, required) — Cash payment amount

**Returns:** Settlement transaction with both legs.

### Administration

#### canton_upload_dar
Upload a DAML Archive (DAR) package to the Canton participant.

**Parameters:**
- `dar_path` (string, required) — Path to DAR file (describes the process)

**Returns:** Upload instructions and expected result.

#### canton_get_fee_schedule
Get the fee schedule for a synchronization domain.

**Parameters:**
- `synchronizer_id` (string, required) — Synchronizer domain ID

**Returns:** Base fee, per-byte fee, and fee schedule details.

### Network Health

#### canton_list_domains
List connected synchronization domains.

**Returns:** Domain IDs, aliases, connection status.

#### canton_get_health
Check Canton participant health and connectivity.

**Returns:** Health status, connected domains, ledger API status.

## Common Workflows

### Tokenize a Bond
1. `canton_allocate_party(party_hint="issuer", display_name="Bond Issuer Corp")` — Create issuer party
2. `canton_create_asset(asset_type="bond", issuer="issuer", description="US Treasury 5Y", amount="10000000", maturity_date="2031-04-08")` — Create bond
3. `canton_list_contracts(template_id="Main:Asset", party="issuer")` — Verify creation

### Execute DvP Settlement
1. `canton_list_contracts(template_id="Main:Asset", party="seller")` — Find asset
2. `canton_get_balance(party="buyer")` — Verify buyer has funds
3. `canton_dvp_settle(buyer="buyer", seller="seller", asset_contract_id="00abc...", payment_amount="5000000")` — Atomic settlement

### Monitor Participant
1. `canton_get_health()` — Check health
2. `canton_list_domains()` — Check domain connectivity
3. `canton_list_parties()` — List active parties
4. `canton_get_fee_schedule(synchronizer_id="global-domain")` — Check fees
