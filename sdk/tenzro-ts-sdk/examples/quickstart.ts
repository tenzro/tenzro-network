/**
 * Tenzro TypeScript SDK quickstart: read the chain, list models, run one
 * inference request, and send TNZO signed by this machine's TPM or Secure
 * Enclave key.
 *
 * Run with: `npx tsx examples/quickstart.ts`
 *   TENZRO_RPC_URL   one node to talk to; unset, the client finds the network's
 *                    staked RPC operators on chain and keeps those that agree
 *   TENZRO_SEND_TO   recipient account (0x + 64 hex); omit to skip the transfer
 */

import { HardwareKeySigner, TenzroClient, accountAddress, connectToNetwork, openHardwareSigner } from "../src/index";

async function main(): Promise<void> {
  const url = process.env.TENZRO_RPC_URL;
  const client = url ? new TenzroClient({ endpoint: url }) : await connectToNetwork();

  const height = await client.getBlockNumber();
  const finalized = await client.getFinalizedBlock();
  console.log(`height ${height}, finalized ${finalized}`);

  const models = await client.inference.listModels();
  console.log(`${models.length} models served`);
  if (models.length > 0) {
    const result = await client.inference.request(models[0].id, "Say hello in five words.", 32);
    console.log(result);
  }

  const to = process.env.TENZRO_SEND_TO;
  if (!to) return;

  // The key stays in the TPM or Secure Enclave; the optional @tenzro/device-key
  // package reaches it. Without hardware the SDK refuses to sign.
  const signer = openHardwareSigner({ label: "tenzro/wallet" });
  if (!(signer instanceof HardwareKeySigner)) throw new Error("no TPM or Secure Enclave on this machine");
  const from = "0x" + Buffer.from(await accountAddress(signer.p256PublicKey())).toString("hex");
  console.log(`sending from ${from}, balance ${await client.getBalance(from)} wei`);

  const txHash = await client.wallet.sendSelfCustody({ signer, to, value: 10n ** 18n });
  console.log(`sent 1 TNZO: ${txHash}`);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
