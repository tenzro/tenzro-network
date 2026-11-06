/**
 * Talk to one node: read its chain id and a balance, then dry-run a TNZO
 * transfer. The dry run asks the node to encode the transaction's signing
 * payload and checks that it is the transaction built here; nothing is signed
 * or submitted, so it needs no key.
 *
 * Run with: `npx tsx examples/local-node.ts`
 *   TENZRO_RPC_URL   the node (default http://127.0.0.1:8545, the chain `tenzro dev` serves)
 *   TENZRO_ACCOUNT   the account to read and send from (0x + 64 hex)
 */

import { RpcCallError, TenzroClient } from "../src/index";

async function main(): Promise<void> {
  const endpoint = process.env.TENZRO_RPC_URL ?? "http://127.0.0.1:8545";
  const account = process.env.TENZRO_ACCOUNT ?? "0x" + "11".repeat(32);
  const client = new TenzroClient({ endpoint });

  const chainId = await client.getChainId();
  console.log(`chain id ${chainId}, height ${await client.getBlockNumber()}`);
  console.log(`balance of ${account}: ${await client.getBalance(account)} wei`);

  const prepared = await client.transactions.prepare(account, {
    kind: "Transfer",
    fields: { amount: 1000 },
    to: "0x" + "22".repeat(32),
  });
  console.log(`dry run: nonce ${prepared.request.nonce}, chain id ${prepared.request.chain_id}, digest ${prepared.digest}`);
}

main().catch((error: unknown) => {
  if (error instanceof RpcCallError) console.error(`node error ${error.code}: ${error.message}`);
  else console.error(error);
  process.exit(1);
});
