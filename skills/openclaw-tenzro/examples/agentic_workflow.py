"""
Task marketplace settlement cycle — end-to-end against the live testnet.

Walks through the full money-moving path using the OpenClaw Python
wrappers:

    join_as_micro_node (poster)   → request_faucet → post_task
    join_as_micro_node (provider)                  → quote_task
                                                   → assign_task    (locks price)
                                                   → complete_task  (TNZO transfer)
    get_balance                                    → reconcile deltas

`complete_task` is the moneyed step: the RPC handler transfers
`final_price` (the quoted price, or `max_price` if unquoted) from the
poster's wallet to the provider's wallet through the unified token
registry. The settlement block in the response contains the
post-transfer balances; this example confirms them via
`tenzro_getBalance`.

Run with: `python3 examples/agentic_workflow.py`

Honest caveat: the testnet `tenzro_participate` / `tenzro_joinAsMicroNode`
endpoint silently ignores any password; we don't pass one.
"""

import os
import sys
import time

# Make the sibling `tools/` directory importable when this script runs
# from the `examples/` directory.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import tenzro_rpc  # noqa: E402

POST_PRICE_WEI = 1_000_000_000_000_000_000  # 1 TNZO
QUOTE_PRICE_WEI = 900_000_000_000_000_000   # 0.9 TNZO
FAUCET_POLL_SECS = 180


def _balance_wei(address: str) -> int:
    """Read balance via tenzro_getBalance and coerce to int wei.

    The handler returns either a hex string or an object with
    `balance_wei`; tolerate both.
    """
    res = tenzro_rpc.get_balance(address)
    if isinstance(res, str):
        return int(res, 16) if res.startswith("0x") else int(res)
    if isinstance(res, dict):
        for k in ("balance_wei", "balance", "wei"):
            v = res.get(k)
            if isinstance(v, str):
                return int(v, 16) if v.startswith("0x") else int(v)
            if isinstance(v, int):
                return v
    raise ValueError(f"unexpected balance response: {res!r}")


def main() -> None:
    print("=== OpenClaw — Task Marketplace Settlement Cycle ===\n")

    # ------------------------------------------------------------------
    # 1. Spawn poster + provider
    # ------------------------------------------------------------------
    print("1. Spawning poster and provider identities...")
    poster = tenzro_rpc.join_as_micro_node(display_name="poster")
    provider = tenzro_rpc.join_as_micro_node(display_name="provider")
    poster_addr = poster["address"]
    provider_addr = provider["address"]
    print(f"   poster   {poster_addr}")
    print(f"   provider {provider_addr}\n")

    # ------------------------------------------------------------------
    # 2. Fund poster from faucet
    # ------------------------------------------------------------------
    print("2. Requesting faucet TNZO for poster...")
    faucet = tenzro_rpc.request_faucet(poster_addr)
    print(f"   faucet response: {faucet}")

    print(f"   polling balance (up to {FAUCET_POLL_SECS}s)...")
    target = POST_PRICE_WEI
    started = time.time()
    funded = False
    while time.time() - started < FAUCET_POLL_SECS:
        try:
            bal = _balance_wei(poster_addr)
        except Exception:
            bal = 0  # transient — keep polling
        if bal >= target:
            elapsed = int(time.time() - started)
            print(f"   funded after {elapsed}s — balance {bal} wei\n")
            funded = True
            break
        time.sleep(3)
    if not funded:
        raise SystemExit(
            f"poster never funded within {FAUCET_POLL_SECS}s — testnet faucet busy"
        )

    # ------------------------------------------------------------------
    # 3. Snapshot pre-settlement balances
    # ------------------------------------------------------------------
    poster_before = _balance_wei(poster_addr)
    provider_before = _balance_wei(provider_addr)
    print("3. Pre-settlement balances:")
    print(f"   poster    {poster_before} wei")
    print(f"   provider  {provider_before} wei\n")

    # ------------------------------------------------------------------
    # 4. Poster opens a task
    # ------------------------------------------------------------------
    print("4. Posting task (max_price 1 TNZO, type=inference)...")
    posted = tenzro_rpc.post_task(
        title="Sentiment analysis: 2 reviews",
        description="Score sentiment 1-5 for each input review.",
        task_type="inference",
        budget_wei=POST_PRICE_WEI,
        poster=poster_addr,
        input_text='["Great product!", "Needs improvement."]',
        preferred_model_id="gemma3-270m",
    )
    task_id = posted["task_id"]
    print(f"   task_id {task_id}")
    print(f"   status  {posted.get('status')}\n")

    # ------------------------------------------------------------------
    # 5. Provider submits a quote
    # ------------------------------------------------------------------
    print("5. Provider quotes at 0.9 TNZO...")
    quote = tenzro_rpc.quote_task(
        task_id=task_id,
        provider=provider_addr,
        price_wei=QUOTE_PRICE_WEI,
        model_id="gemma3-270m",
        confidence=90,
        estimated_duration_secs=45,
    )
    print(f"   price {quote.get('price')} wei, model {quote.get('model_id')}\n")

    # ------------------------------------------------------------------
    # 6. Poster assigns, locking quoted price
    # ------------------------------------------------------------------
    print("6. Poster assigns task to provider (locks 0.9 TNZO)...")
    assignment = tenzro_rpc.assign_task(
        task_id=task_id,
        provider=provider_addr,
        quoted_price_wei=QUOTE_PRICE_WEI,
    )
    print(f"   assignment: {assignment}\n")

    # ------------------------------------------------------------------
    # 7. Provider completes — settlement fires on-chain
    # ------------------------------------------------------------------
    print("7. Completing task (triggers on-chain TNZO transfer)...")
    receipt = tenzro_rpc.complete_task(
        task_id=task_id,
        output='[{"review":"Great product!","score":5},'
        '{"review":"Needs improvement.","score":2}]',
    )
    print(f"   status     {receipt.get('status')}")
    print(f"   settlement {receipt.get('settlement')}\n")

    # ------------------------------------------------------------------
    # 8. Reconcile via tenzro_getBalance
    # ------------------------------------------------------------------
    print("8. Post-settlement balances:")
    poster_after = _balance_wei(poster_addr)
    provider_after = _balance_wei(provider_addr)
    print(
        f"   poster    {poster_after} wei  (Δ -{poster_before - poster_after} wei)"
    )
    print(
        f"   provider  {provider_after} wei  (Δ +{provider_after - provider_before} wei)"
    )

    # Cross-VM view of the provider's settled balance
    print("\n9. Provider balance via cross-VM views (pointer model):")
    mv = tenzro_rpc.get_token_balance_all_vms(provider_addr)
    print(mv)

    print("\n=== Settlement cycle complete ===")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
