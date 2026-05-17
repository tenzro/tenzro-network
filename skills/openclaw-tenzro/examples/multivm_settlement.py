"""
Multi-VM settlement — the pointer-model invariant against live testnet.

One TNZO balance, four VM views:

    native       (18-dec wei)        ─┐
    evm_wtnzo    (ERC-20, 18-dec)    │  all share the same underlying
    svm_wtnzo    (SPL, 9-dec)        │  native balance via the Sei V2
    daml_holding (CIP-56, 18-dec)    ─┘  pointer model — no bridge

Walks through:
    1. spawn two fresh identities (sender + receiver) via `join_as_micro_node`
    2. fund the sender from the faucet
    3. snapshot all four VM views of the sender's balance
    4. drive a `tenzro_crossVmTransfer` (native → evm)
    5. re-snapshot both addresses
    6. assert the pointer-model invariants:
         • native       == evm_wtnzo        (EVM tracks native 1:1)
         • native       == daml_holding     (Canton tracks native 1:1)
         • svm_wtnzo    == native // 1e9    (SPL is 9-decimal truncation)
         • sender_before == sender_after + receiver_after  (conservation)

Run with: `python3 examples/multivm_settlement.py`

Honest caveat: the testnet handler accepts `tenzro_submitDamlCommand`
and returns a typed Canton envelope, but no live Canton participant
is wired up. What this example demonstrates is that `daml_holding`
is a real *view* of the underlying balance — the post-transfer delta
confirms it.
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import tenzro_rpc  # noqa: E402

TRANSFER_AMOUNT_WEI = 1_000_000_000_000_000_000  # 1 TNZO
FAUCET_POLL_SECS = 180


def _int_str(value) -> int:
    """Coerce a wire value (decimal string or int) to int."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    raise ValueError(f"unexpected numeric value: {value!r}")


def _balance_wei(address: str) -> int:
    res = tenzro_rpc.get_balance(address)
    if isinstance(res, str):
        return _int_str(res)
    if isinstance(res, dict):
        for k in ("balance_wei", "balance", "wei"):
            if k in res:
                return _int_str(res[k])
    raise ValueError(f"unexpected balance response: {res!r}")


def _print_views(label: str, balance: dict) -> None:
    print(f"   {label}")
    native = _int_str(balance["native"]["balance_wei"])
    evm = _int_str(balance["evm_wtnzo"]["balance_wei"])
    spl = _int_str(balance["svm_wtnzo"]["balance_base_units"])
    daml = _int_str(balance["daml_holding"]["amount_wei"])
    print(f"     native       {native} wei")
    print(f"     evm_wtnzo    {evm} wei")
    print(f"     svm_wtnzo    {spl} base units (9 dec)")
    print(f"     daml_holding {daml} wei")


def _views(balance: dict) -> tuple[int, int, int, int]:
    return (
        _int_str(balance["native"]["balance_wei"]),
        _int_str(balance["evm_wtnzo"]["balance_wei"]),
        _int_str(balance["svm_wtnzo"]["balance_base_units"]),
        _int_str(balance["daml_holding"]["amount_wei"]),
    )


def _assert_eq(actual: int, expected: int, msg: str) -> None:
    if actual != expected:
        raise AssertionError(f"{msg}: actual {actual}, expected {expected}")


def main() -> None:
    print("=== OpenClaw — Multi-VM Settlement ===\n")

    # ------------------------------------------------------------------
    # 1. Spawn sender + receiver
    # ------------------------------------------------------------------
    print("1. Spawning sender and receiver identities...")
    sender = tenzro_rpc.join_as_micro_node(display_name="sender")
    receiver = tenzro_rpc.join_as_micro_node(display_name="receiver")
    sender_addr = sender["address"]
    receiver_addr = receiver["address"]
    print(f"   sender   {sender_addr}")
    print(f"   receiver {receiver_addr}\n")

    # ------------------------------------------------------------------
    # 2. Fund sender from faucet
    # ------------------------------------------------------------------
    print("2. Requesting faucet TNZO for sender...")
    tenzro_rpc.request_faucet(sender_addr)

    print(f"   polling balance (up to {FAUCET_POLL_SECS}s)...")
    started = time.time()
    funded = False
    while time.time() - started < FAUCET_POLL_SECS:
        try:
            bal = _balance_wei(sender_addr)
        except Exception:
            bal = 0
        if bal >= TRANSFER_AMOUNT_WEI:
            elapsed = int(time.time() - started)
            print(f"   funded after {elapsed}s\n")
            funded = True
            break
        time.sleep(3)
    if not funded:
        raise SystemExit(
            f"sender never funded within {FAUCET_POLL_SECS}s — testnet faucet busy"
        )

    # ------------------------------------------------------------------
    # 3. Snapshot pre-transfer four-view balance
    # ------------------------------------------------------------------
    print("3. Pre-transfer balance (4 VM views):")
    pre = tenzro_rpc.get_token_balance_all_vms(sender_addr)
    _print_views("sender:", pre)
    native_before, evm_before, spl_before, daml_before = _views(pre)
    _assert_eq(evm_before, native_before, "EVM view diverges from native")
    _assert_eq(daml_before, native_before, "DAML view diverges from native")
    _assert_eq(
        spl_before, native_before // 1_000_000_000, "SVM truncation incorrect"
    )
    print("   invariants pre-transfer hold\n")

    # ------------------------------------------------------------------
    # 4. Cross-VM transfer (native → evm)
    # ------------------------------------------------------------------
    print(
        "4. tenzro_crossVmTransfer 1 TNZO sender(native) → receiver(evm)..."
    )
    result = tenzro_rpc.cross_vm_transfer(
        token="TNZO",
        amount=str(TRANSFER_AMOUNT_WEI),
        from_vm="native",
        to_vm="evm",
        from_address=sender_addr,
        to_address=receiver_addr,
    )
    print(f"   status: {result.get('status')}\n")

    # ------------------------------------------------------------------
    # 5. Snapshot post-transfer views
    # ------------------------------------------------------------------
    print("5. Post-transfer balances:")
    sender_post = tenzro_rpc.get_token_balance_all_vms(sender_addr)
    receiver_post = tenzro_rpc.get_token_balance_all_vms(receiver_addr)
    _print_views("sender:", sender_post)
    print()
    _print_views("receiver:", receiver_post)

    # ------------------------------------------------------------------
    # 6. Conservation + invariants post-transfer
    # ------------------------------------------------------------------
    s_native, s_evm, s_spl, s_daml = _views(sender_post)
    r_native, r_evm, _r_spl, _r_daml = _views(receiver_post)

    _assert_eq(s_evm, s_native, "sender EVM view diverges from native")
    _assert_eq(r_evm, r_native, "receiver EVM view diverges from native")
    _assert_eq(s_daml, s_native, "sender DAML view diverges from native")
    _assert_eq(s_spl, s_native // 1_000_000_000, "sender SVM truncation incorrect")
    _assert_eq(s_native + r_native, native_before, "conservation broken")

    print("\n6. Pointer-model invariants post-transfer: ALL PASS")
    print("   • native == evm_wtnzo (sender & receiver)")
    print("   • native == daml_holding (sender)")
    print("   • svm_wtnzo == native // 1e9 (sender)")
    print("   • conservation: sender_before == sender_after + receiver_after")

    print("\n=== Multi-VM settlement complete ===")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
