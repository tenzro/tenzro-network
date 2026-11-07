/**
 * Resolve a did:tenzro identifier: the W3C DID Document and the registry
 * record. Read-only; needs no key.
 *
 * Creating a DID is deliberately not shown: the key behind a did:tenzro
 * identifier is generated in a passkey authenticator, a TPM or a Secure
 * Enclave, and registration proves possession of it (docs/did-method-tenzro.md
 * section 3.1). `identity.registerHuman` takes that proof as an argument;
 * there is no key-less create call.
 *
 * Run with: `npx tsx examples/did-resolve.ts`
 *   TENZRO_RPC_URL   the node (default http://127.0.0.1:8545)
 *   TENZRO_DID       the DID to resolve (default: first listed on the node)
 */

import { RpcCallError, TenzroClient } from "../src/index";

async function main(): Promise<void> {
  const endpoint = process.env.TENZRO_RPC_URL ?? "http://127.0.0.1:8545";
  const client = new TenzroClient({ endpoint });

  let did = process.env.TENZRO_DID;
  if (!did) {
    const list = await client.identity.listIdentities();
    did = list.identities[0]?.did;
    if (!did) throw new Error("this node lists no identities; set TENZRO_DID");
  }
  console.log(`resolving ${did}`);

  const doc = await client.identity.resolveDidDocument(did);
  console.log(`document id: ${doc.id}`);
  for (const m of doc.verificationMethod ?? []) console.log(`  key ${m.id} (${m.type})`);

  try {
    const info = await client.identity.resolve(did);
    console.log(`record: status ${info.status}`);
  } catch (error) {
    if (!(error instanceof RpcCallError)) throw error;
    console.log(`no registry record on this node: ${error.message}`);
  }
}

main().catch((error: unknown) => {
  if (error instanceof RpcCallError) console.error(`node error ${error.code}: ${error.message}`);
  else console.error(error);
  process.exit(1);
});
