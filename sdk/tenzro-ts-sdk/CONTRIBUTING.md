# Contributing

Issues and pull requests are welcome in this repository.

- Bug reports and questions about `npm install tenzro-sdk`: open an issue using the templates.
- Code changes: open a PR here; maintainers land it upstream in `sdk/tenzro-ts-sdk/` (tenzro-network) as part of review, so a change here and the monorepo stay in sync.
- Security issues: do not open an issue. See [SECURITY.md](SECURITY.md).

**Maintainer note**: `npm test` here currently shows 16 failing test files (agent-accounts, amounts, ap2-terms, challenge-payment, did-envelope, eip7702, event-proof, governance-receipt, hybrid-payer, keystore, nft-abi, openshell, payment-abstraction, payment-ops, settle, web-payments) — they read fixture files from `../fixtures/` relative to the monorepo's `sdk/` layout, which this standalone repo doesn't carry. 354 of 393 tests pass; `npm run build` and the examples typecheck cleanly. Fixing this means either vendoring `sdk/fixtures/` here or rewriting those tests to be self-contained — neither done yet.
