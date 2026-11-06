"""Talk to one node: read its chain id and a balance, then dry-run a TNZO
transfer. The dry run asks the node to encode the transaction's signing
payload and checks that it is the transaction built here; nothing is signed
or submitted, so it needs no key.

    python examples/local_node.py
      TENZRO_RPC_URL   the node (default http://127.0.0.1:8545, the chain `tenzro dev` serves)
      TENZRO_ACCOUNT   the account to read and send from (0x + 64 hex)
"""

import os
import sys

from tenzro import RpcClient, RpcError, TypedTransaction, TypedTxClient


def main() -> None:
    endpoint = os.environ.get("TENZRO_RPC_URL", "http://127.0.0.1:8545")
    account = os.environ.get("TENZRO_ACCOUNT", "0x" + "11" * 32)
    with RpcClient(endpoint) as node:
        chain_id = int(node.eth_chain_id(), 16)
        print(f"chain id {chain_id}, height {int(node.eth_block_number(), 16)}")
        print(f"balance of {account}: {node.get_balance([account])}")

        tx = TypedTransaction(kind="Transfer", fields={"amount": 1000}, to="0x" + "22" * 32)
        prepared = TypedTxClient(node).prepare(account, tx)
        request = prepared["request"]
        print(f"dry run: nonce {request['nonce']}, chain id {request['chain_id']}, digest {prepared['digest']}")


if __name__ == "__main__":
    try:
        main()
    except RpcError as e:
        sys.exit(f"node error {e.code}: {e.message}")
