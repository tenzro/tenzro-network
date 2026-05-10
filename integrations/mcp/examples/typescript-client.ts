/**
 * Tenzro MCP Client -- TypeScript Example
 *
 * Demonstrates connecting to a Tenzro node's MCP server and calling tools.
 *
 * Usage:
 *   npm install @modelcontextprotocol/sdk
 *   npx tsx typescript-client.ts
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const MCP_ENDPOINT =
  process.env.TENZRO_MCP_URL ?? "https://mcp.tenzro.network/mcp";

async function main() {
  console.log("=== Tenzro MCP Client ===\n");

  // 1. Connect to MCP server (Streamable HTTP transport, stateless)
  console.log("1. Connecting to MCP server...");
  const transport = new StreamableHTTPClientTransport(new URL(MCP_ENDPOINT));
  const client = new Client(
    { name: "tenzro-mcp-example", version: "1.0.0" },
    {}
  );
  await client.connect(transport);
  console.log("   Connected.\n");

  // 2. List available tools
  console.log("2. Available tools:");
  const { tools } = await client.listTools();
  for (const tool of tools) {
    console.log(`   - ${tool.name}: ${tool.description}`);
  }
  console.log();

  // 3. Get node status
  console.log("3. Node status:");
  const status = await client.callTool({
    name: "get_node_status",
    arguments: {},
  });
  console.log(`   ${formatContent(status.content)}\n`);

  // 4. Create a wallet
  console.log("4. Creating wallet:");
  const wallet = await client.callTool({
    name: "create_wallet",
    arguments: {},
  });
  console.log(`   ${formatContent(wallet.content)}\n`);

  // 5. Get balance
  console.log("5. Getting balance:");
  const balance = await client.callTool({
    name: "get_balance",
    arguments: {
      address: "0x0000000000000000000000000000000000000000",
    },
  });
  console.log(`   ${formatContent(balance.content)}\n`);

  // 6. Get block
  console.log("6. Getting block #0:");
  const block = await client.callTool({
    name: "get_block",
    arguments: { height: 0 },
  });
  console.log(`   ${formatContent(block.content)}\n`);

  // 7. Register identity
  console.log("7. Registering identity:");
  const identity = await client.callTool({
    name: "register_identity",
    arguments: {
      identity_type: "human",
      display_name: "MCP Test User",
    },
  });
  console.log(`   ${formatContent(identity.content)}\n`);

  // 8. List models
  console.log("8. Listing AI models:");
  const models = await client.callTool({
    name: "list_models",
    arguments: {},
  });
  console.log(`   ${formatContent(models.content)}\n`);

  // 9. Request faucet
  console.log("9. Requesting faucet tokens:");
  const faucet = await client.callTool({
    name: "request_faucet",
    arguments: {
      address: "0x0000000000000000000000000000000000000001",
    },
  });
  console.log(`   ${formatContent(faucet.content)}\n`);

  // 10. Create NFT collection
  console.log("10. Creating NFT collection:");
  const nftCollection = await client.callTool({
    name: "create_nft_collection",
    arguments: {
      name: "MCP Test NFTs",
      symbol: "MCPT",
      creator: "0x0000000000000000000000000000000000000001",
      standard: "erc721",
    },
  });
  console.log(`   ${formatContent(nftCollection.content)}\n`);

  // 11. Get bridge quote (LI.FI aggregator, 58+ chains)
  console.log("11. Getting bridge quote:");
  const quote = await client.callTool({
    name: "bridge_quote",
    arguments: {
      from_chain: "ethereum",
      to_chain: "arbitrum",
      token: "USDC",
      amount: "1000000000",
    },
  });
  console.log(`   ${formatContent(quote.content)}\n`);

  // 12. Check compliance (ERC-3643)
  console.log("12. Checking transfer compliance:");
  const compliance = await client.callTool({
    name: "check_compliance",
    arguments: {
      token_id: "0x0000000000000000000000000000000000000000000000000000000000000001",
      from: "0x0000000000000000000000000000000000000001",
      to: "0x0000000000000000000000000000000000000002",
      amount: "1000000",
    },
  });
  console.log(`   ${formatContent(compliance.content)}\n`);

  // 13. Query events
  console.log("13. Querying historical events:");
  const events = await client.callTool({
    name: "get_events",
    arguments: {
      filter: { event_types: ["NewBlock", "Transfer"] },
      limit: 10,
    },
  });
  console.log(`   ${formatContent(events.content)}\n`);

  // 14. Subscribe to events (returns streaming URLs)
  console.log("14. Subscribing to events:");
  const subscription = await client.callTool({
    name: "subscribe_events",
    arguments: {
      filter: { event_types: ["Transfer", "Log"] },
    },
  });
  console.log(`   ${formatContent(subscription.content)}\n`);

  await client.close();
  console.log("Done.");
}

function formatContent(content: unknown): string {
  if (Array.isArray(content)) {
    return content
      .map((c: { type?: string; text?: string }) =>
        c.type === "text" ? c.text : JSON.stringify(c)
      )
      .join("\n   ");
  }
  return JSON.stringify(content);
}

main().catch(console.error);
