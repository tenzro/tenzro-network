# tenzro-settlement

Shared settlement pieces for Tenzro Network. Value moves only in consensus:
payments, escrows, settlement plans and their netting are VM transactions
(see `tenzro-vm` `native::payment_settlement`). This crate keeps no books of
its own; it holds the pure pieces the VM and the node share:

- `escrow`: the `EscrowAccount` record stored at `escrow:<id>` in VM state, and
  `verify_release_conditions`, the release-proof check the VM runs.
- `netting`: the netting algorithm (obligations to per-asset net instructions,
  with the conservation check), called by the VM once per epoch.
