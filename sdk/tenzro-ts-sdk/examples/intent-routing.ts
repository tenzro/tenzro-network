/**
 * Tenzro Network TypeScript SDK - Intent Routing
 *
 * Demonstrates the two intent-driven entry points, one layer above the
 * other:
 *
 *  - routeIntent   — resolve an intent to the best model without naming one.
 *                    Discovery only: no provider is dialed and no spend is
 *                    recorded, but the per-DID budget gate and wallet-balance
 *                    ceiling are still consulted.
 *  - chatByIntent  — resolve an intent to a model and run a chat completion
 *                    through the same path a named-model request takes.
 */

import { TenzroClient } from "../src/index";

async function main() {
  console.log("=== Tenzro SDK - Intent routing ===\n");

  const client = TenzroClient.local();

  // ==========================================================================
  // 1. Route an intent to the best model (discovery only)
  // ==========================================================================
  console.log("1. Routing a reasoning intent...");
  const decision = await client.inference.routeIntent({
    useCase: "reasoning",
    // budget is a decimal string in the smallest TNZO unit (u128 range).
    budget: "100000000000000000",
    optimize: 0.7,
    qualityFloor: "strong",
    estInputTokens: 400,
    estOutputTokens: 800,
  });
  console.log(`   Model: ${decision.model_id}`);
  console.log(`   Tier: ${decision.tier}`);
  console.log(`   Estimated cost: ${decision.estimated_cost} (smallest unit)`);
  console.log(`   Alternates: ${decision.alternates.join(", ")}`);
  console.log(`   Reason: ${decision.reason}\n`);

  // ==========================================================================
  // 2. Resolve a research intent and run the chat completion in one call
  // ==========================================================================
  console.log("2. Running a research intent as a chat completion...");
  const chat = await client.inference.chatByIntent({
    useCase: "research",
    optimize: 0.9,
    messages: [
      {
        role: "user",
        content: "Summarize the tradeoffs of BFT vs. Nakamoto consensus.",
      },
    ],
  });
  const route = (chat as { route?: { model_id?: string } }).route;
  if (route?.model_id) {
    console.log(`   Routed via: ${route.model_id}`);
  }
  console.log(`   Response: ${JSON.stringify(chat, null, 2)}\n`);

  console.log("\n=== Complete ===");
}

main().catch((error) => {
  console.error("Error:", error.message);
  if (error.code !== undefined) {
    console.error(`Error Code: ${error.code}`);
  }
  process.exit(1);
});
