#!/usr/bin/env python3
"""
Tenzro MCP Client -- Python Example

Demonstrates connecting to a Tenzro node's MCP server and calling tools
for wallets, identity, NFTs, bridge quotes, compliance checks, and events.

Usage:
    pip install mcp
    python3 python-client.py
"""

import asyncio
import json
import os

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MCP_ENDPOINT = os.environ.get(
    "TENZRO_MCP_URL", "https://mcp.tenzro.network/mcp"
)


async def main():
    print("=== Tenzro MCP Client (Python) ===\n")

    # 1. Connect to MCP server (Streamable HTTP transport)
    print("1. Connecting to MCP server...")
    async with streamablehttp_client(MCP_ENDPOINT) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("   Connected.\n")

            # 2. List available tools
            print("2. Available tools:")
            tools_result = await session.list_tools()
            print(f"   {len(tools_result.tools)} tools available")
            for tool in tools_result.tools[:10]:
                print(f"   - {tool.name}: {tool.description}")
            if len(tools_result.tools) > 10:
                print(f"   ... and {len(tools_result.tools) - 10} more\n")

            # 3. Get node status
            print("3. Node status:")
            status = await session.call_tool("get_node_status", arguments={})
            print(f"   {format_content(status.content)}\n")

            # 4. Create a wallet
            print("4. Creating wallet:")
            wallet = await session.call_tool(
                "create_wallet", arguments={"key_type": "ed25519"}
            )
            print(f"   {format_content(wallet.content)}\n")

            # 5. Get balance
            print("5. Getting balance:")
            balance = await session.call_tool(
                "get_balance",
                arguments={
                    "address": "0x0000000000000000000000000000000000000000"
                },
            )
            print(f"   {format_content(balance.content)}\n")

            # 6. Register identity (TDIP)
            print("6. Registering identity:")
            identity = await session.call_tool(
                "register_identity",
                arguments={
                    "identity_type": "human",
                    "display_name": "MCP Test User",
                },
            )
            print(f"   {format_content(identity.content)}\n")

            # 7. Create NFT collection
            print("7. Creating NFT collection:")
            nft = await session.call_tool(
                "create_nft_collection",
                arguments={
                    "name": "Python Test NFTs",
                    "symbol": "PNFT",
                    "creator": "0x0000000000000000000000000000000000000001",
                    "standard": "erc721",
                },
            )
            print(f"   {format_content(nft.content)}\n")

            # 8. Bridge quote (LI.FI, 58+ chains)
            print("8. Getting bridge quote:")
            quote = await session.call_tool(
                "bridge_quote",
                arguments={
                    "from_chain": "ethereum",
                    "to_chain": "arbitrum",
                    "token": "USDC",
                    "amount": "1000000000",
                },
            )
            print(f"   {format_content(quote.content)}\n")

            # 9. Check compliance (ERC-3643)
            print("9. Checking compliance:")
            compliance = await session.call_tool(
                "check_compliance",
                arguments={
                    "token_id": "0x" + "00" * 31 + "01",
                    "from": "0x0000000000000000000000000000000000000001",
                    "to": "0x0000000000000000000000000000000000000002",
                    "amount": "1000000",
                },
            )
            print(f"   {format_content(compliance.content)}\n")

            # 10. Query events
            print("10. Querying events:")
            events = await session.call_tool(
                "get_events",
                arguments={
                    "filter": {"event_types": ["NewBlock"]},
                    "limit": 5,
                },
            )
            print(f"   {format_content(events.content)}\n")

            # 11. List AI models
            print("11. AI models:")
            models = await session.call_tool("list_models", arguments={})
            print(f"   {format_content(models.content)}\n")

            # 12. Request faucet
            print("12. Requesting faucet tokens:")
            faucet = await session.call_tool(
                "request_faucet",
                arguments={
                    "address": "0x0000000000000000000000000000000000000001"
                },
            )
            print(f"   {format_content(faucet.content)}\n")

    print("Done.")


def format_content(content) -> str:
    """Format MCP tool response content for display."""
    if isinstance(content, list):
        parts = []
        for item in content:
            if hasattr(item, "text"):
                parts.append(item.text)
            else:
                parts.append(str(item))
        return "\n   ".join(parts)
    return str(content)


if __name__ == "__main__":
    asyncio.run(main())
