import * as anchor from "@coral-xyz/anchor";
import { PublicKey, SystemProgram } from "@solana/web3.js";

const REGISTRY_PROGRAM_ID = new PublicKey("8oo4J9tBB3Hna1jRQ3rWvJjojqM5DYTDJo5cejUuJy3C");

async function main() {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const idl = require("../idl/atom_engine.json");
  const atomProgram = new anchor.Program(idl, provider);
  const atomProgramId = atomProgram.programId;

  const [configPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("atom_config")],
    atomProgramId
  );

  console.log("=== Initializing ATOM Engine on Devnet ===");
  console.log("ATOM Program:", atomProgramId.toBase58());
  console.log("Config PDA:", configPda.toBase58());
  console.log("Registry Program:", REGISTRY_PROGRAM_ID.toBase58());
  console.log("Authority:", provider.wallet.publicKey.toBase58());

  const existing = await provider.connection.getAccountInfo(configPda);
  if (existing) {
    console.log("\nATOM Engine already initialized - skipping");
    const config = await atomProgram.account.atomConfig.fetch(configPda);
    console.log("  Authority:", (config.authority as PublicKey).toBase58());
    console.log("  Agent Registry:", (config.agentRegistryProgram as PublicKey).toBase58());
    return;
  }

  const tx = await atomProgram.methods
    .initializeConfig(REGISTRY_PROGRAM_ID)
    .accounts({
      authority: provider.wallet.publicKey,
      config: configPda,
      systemProgram: SystemProgram.programId,
    })
    .rpc();

  console.log("\nInitialize tx:", tx);

  const config = await atomProgram.account.atomConfig.fetch(configPda);
  console.log("\n=== ATOM Config ===");
  console.log("Authority:", (config.authority as PublicKey).toBase58());
  console.log("Agent Registry:", (config.agentRegistryProgram as PublicKey).toBase58());
}

main().then(() => {
  console.log("\nDone");
  process.exit(0);
}).catch((e) => {
  console.error("Error:", e.message || e);
  if (e.logs) console.error("Logs:", e.logs.join("\n"));
  process.exit(1);
});
