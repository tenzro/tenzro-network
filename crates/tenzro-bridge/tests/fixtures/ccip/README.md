# CCIP contract bytecode (test fixtures)

Creation bytecode of the published CCIP contracts, used only by the route
framework's tests (`src/route/ccip_contracts.rs`) to run them on a local
Tenzro EVM. Taken unmodified from the `bytecode/` directory of the npm package
`@chainlink/contracts-ccip` 1.6.4:

| File | Package path |
|------|--------------|
| `router.bin` | `bytecode/v1_2_0/router.bin` |
| `rmn_remote.bin` | `bytecode/v1_6_0/rmn_remote.bin` |
| `nonce_manager.bin` | `bytecode/v1_6_0/nonce_manager.bin` |
| `fee_quoter.bin` | `bytecode/v1_6_0/fee_quoter.bin` |
| `onramp.bin` | `bytecode/v1_6_0/onramp.bin` |
| `offramp.bin` | `bytecode/v1_6_0/offramp.bin` |
| `token_admin_registry.bin` | `bytecode/v1_5_0/token_admin_registry.bin` |
| `burn_mint_token_pool.bin` | `bytecode/v1_6_1/burn_mint_token_pool.bin` |
| `factory_burn_mint_erc20.bin` | `bytecode/v1_5_1/factory_burn_mint_erc20.bin` |

The contracts are licensed under the Business Source License 1.1
(`LICENSE-BUSL.md`), which permits copying, redistribution and non-production
use. These files are test fixtures and are not part of any build artifact.

## On-ramp message events

`mainnet_onramp_logs.json` holds message events recorded from Ethereum
mainnet (`eth_getLogs`), one or more per on-ramp version a CCIP lane may run:
`OnRamp 2.0.0` (a token transfer and a data message), `OnRamp 1.6.0` and
`EVM2EVMOnRamp 1.5.0`, each with its emitting contract, block, transaction
and log index. `src/route/evm.rs` reads each in its lane's version and
recomputes its message id.
