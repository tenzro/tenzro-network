/**
 * Tenzro A2A Client — TypeScript Example
 *
 * Demonstrates how to interact with a Tenzro node via the A2A protocol.
 * Covers wallet, identity, inference, staking, tokens, agents, and marketplace.
 *
 * Usage:
 *   npx tsx typescript-client.ts
 *
 * Requirements:
 *   npm install
 *   # No extra dependencies needed — uses native fetch
 */

const A2A_ENDPOINT = process.env.TENZRO_A2A_URL ?? "https://a2a.tenzro.network";

interface A2aPart {
  type: string;
  text?: string;
  data?: unknown;
  mimeType?: string;
}

interface A2aMessage {
  role: "user" | "agent";
  parts: A2aPart[];
}

interface A2aTask {
  id: string;
  contextId: string;
  state: "Pending" | "Working" | "Completed" | "Cancelled";
  messages: A2aMessage[];
  history: A2aMessage[];
  createdAt: string;
  updatedAt: string;
}

interface JsonRpcResponse<T> {
  jsonrpc: "2.0";
  result?: T;
  error?: { code: number; message: string };
  id: number;
}

// --- Core A2A Client ---

async function getAgentCard() {
  const response = await fetch(`${A2A_ENDPOINT}/.well-known/agent.json`);
  if (!response.ok) throw new Error(`Failed to fetch agent card: ${response.status}`);
  return response.json();
}

async function sendTask(message: string): Promise<A2aTask> {
  const response = await fetch(`${A2A_ENDPOINT}/a2a`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tasks/send",
      params: {
        message: {
          role: "user",
          parts: [{ type: "text", text: message }],
        },
      },
      id: 1,
    }),
  });

  const json: JsonRpcResponse<A2aTask> = await response.json();

  if (json.error) {
    throw new Error(`A2A Error [${json.error.code}]: ${json.error.message}`);
  }

  return json.result!;
}

async function getTask(taskId: string): Promise<A2aTask> {
  const response = await fetch(`${A2A_ENDPOINT}/a2a`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tasks/get",
      params: { id: taskId },
      id: 2,
    }),
  });

  const json: JsonRpcResponse<A2aTask> = await response.json();
  if (json.error) throw new Error(`A2A Error: ${json.error.message}`);
  return json.result!;
}

async function listTasks(): Promise<A2aTask[]> {
  const response = await fetch(`${A2A_ENDPOINT}/a2a`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tasks/list",
      params: {},
      id: 3,
    }),
  });

  const json: JsonRpcResponse<A2aTask[]> = await response.json();
  if (json.error) throw new Error(`A2A Error: ${json.error.message}`);
  return json.result!;
}

function extractAgentResponse(task: A2aTask): string {
  for (const msg of [...task.messages].reverse()) {
    if (msg.role === "agent") {
      const textPart = msg.parts.find((p) => p.type === "text");
      if (textPart?.text) return textPart.text;
    }
  }
  return "(no agent response)";
}

// --- Demo helper ---

async function demo(label: string, message: string) {
  console.log(`\n${label}`);
  try {
    const task = await sendTask(message);
    console.log(`   Task: ${task.id} [${task.state}]`);
    console.log(`   Response: ${extractAgentResponse(task).slice(0, 200)}`);
  } catch (e: any) {
    console.log(`   Error: ${e.message}`);
  }
}

// --- Main ---

async function main() {
  console.log("=== Tenzro A2A Client ===\n");

  // 1. Discover agent capabilities
  console.log("1. Fetching Agent Card...");
  const card = await getAgentCard();
  console.log(`   Agent: ${card.name} v${card.version}`);
  console.log(`   Protocol: A2A ${card.protocolVersion}`);
  console.log(`   Skills (${card.skills?.length}):`);
  for (const s of card.skills ?? []) {
    console.log(`     - ${s.name} (${s.id})`);
  }

  // 2. Wallet operations
  await demo("2. Wallet — Check balance", "What is the balance of 0x0000000000000000000000000000000000000001?");

  // 3. Block queries
  await demo("3. Blockchain — Block height", "What is the current block height?");

  // 4. Node status
  await demo("4. Network — Node status", "What is the node status and peer count?");

  // 5. Identity
  await demo("5. Identity — Register DID", "Register a new identity named TestAgent");

  // 6. AI Models
  await demo("6. Inference — List models", "List available AI models");

  // 7. Staking
  await demo("7. Staking — Provider stats", "Get provider statistics");

  // 8. Token management
  await demo("8. Tokens — List tokens", "List all registered tokens");

  // 9. Task marketplace
  await demo("9. Marketplace — List tasks", "List open tasks in the marketplace");

  // 10. Agent marketplace
  await demo("10. Agent templates", "List available agent templates");

  // 11. Join as MicroNode
  await demo("11. Join — MicroNode", "Join the Tenzro Network as TestMicroNode");

  // 12. Faucet
  await demo("12. Faucet — Request tokens", "Request testnet faucet tokens");

  // 13. List all tasks created during this session
  console.log("\n13. Listing all tasks...");
  const tasks = await listTasks();
  console.log(`   Total tasks: ${tasks.length}`);
  for (const t of tasks.slice(0, 5)) {
    console.log(`   - ${t.id} [${t.state}]`);
  }
}

main().catch(console.error);
