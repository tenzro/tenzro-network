/**
 * Initialize Localnet for Testing
 * Must be run FIRST before other tests to set up both programs.
 *
 * Agent Registry is deployed from target/deploy/ (local binary).
 * ATOM Engine is built locally. Both need initialization.
 */
import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import { AtomEngine } from "../types/atom_engine";
import { AgentRegistry8004 } from "../types/agent_registry_8004";
import { Keypair, SystemProgram, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { expect } from "chai";

import {
  MPL_CORE_PROGRAM_ID,
  ATOM_ENGINE_PROGRAM_ID,
  getRootConfigPda,
  getRegistryConfigPda,
  getAtomConfigPda,
  getRegistryProgram,
} from "./utils/helpers";

const BPF_LOADER_UPGRADEABLE = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");

describe("Initialize Localnet", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // ATOM Engine is in workspace
  const atomEngine = anchor.workspace.AtomEngine as Program<AtomEngine>;

  // Registry is deployed locally (not in workspace, loaded via IDL)
  const registry = getRegistryProgram(provider);

  let rootConfigPda: PublicKey;
  let collectionKeypair: Keypair;

  before(async () => {
    console.log("\n=== Localnet Initialization ===");
    console.log("Provider wallet:", provider.wallet.publicKey.toBase58());
    console.log("Registry Program ID:", registry.programId.toBase58());
    console.log("ATOM Engine ID:", atomEngine.programId.toBase58());

    [rootConfigPda] = getRootConfigPda(registry.programId);
    collectionKeypair = Keypair.generate();
  });

  it("Initialize Agent Registry (if needed)", async () => {
    const accountInfo = await provider.connection.getAccountInfo(rootConfigPda);
    if (accountInfo !== null) {
      console.log("Registry already initialized - skipping");
      const rootConfig = await registry.account.rootConfig.fetch(rootConfigPda);
      console.log("  Base Collection:", rootConfig.baseCollection.toBase58());
      return;
    }

    const [programDataPda] = PublicKey.findProgramAddressSync(
      [registry.programId.toBuffer()],
      BPF_LOADER_UPGRADEABLE
    );

    const [registryConfigPda] = getRegistryConfigPda(
      collectionKeypair.publicKey,
      registry.programId
    );

    console.log("Initializing Agent Registry...");
    console.log("  Root Config PDA:", rootConfigPda.toBase58());
    console.log("  Registry Config PDA:", registryConfigPda.toBase58());
    console.log("  Collection:", collectionKeypair.publicKey.toBase58());

    const tx = await registry.methods
      .initialize()
      .accounts({
        rootConfig: rootConfigPda,
        registryConfig: registryConfigPda,
        collection: collectionKeypair.publicKey,
        authority: provider.wallet.publicKey,
        programData: programDataPda,
        systemProgram: SystemProgram.programId,
        mplCoreProgram: MPL_CORE_PROGRAM_ID,
      })
      .signers([collectionKeypair])
      .rpc();

    console.log("Registry initialized:", tx);

    const rootConfig = await registry.account.rootConfig.fetch(rootConfigPda);
    expect(rootConfig.authority.toBase58()).to.equal(provider.wallet.publicKey.toBase58());
    console.log("  Base Collection:", rootConfig.baseCollection.toBase58());
  });

  it("Initialize ATOM Engine (if needed)", async () => {
    const [atomConfigPda] = getAtomConfigPda(atomEngine.programId);

    const accountInfo = await provider.connection.getAccountInfo(atomConfigPda);
    if (accountInfo !== null) {
      console.log("ATOM Engine already initialized - skipping");
      return;
    }

    console.log("Initializing ATOM Engine...");
    console.log("  Config PDA:", atomConfigPda.toBase58());
    console.log("  Agent Registry Program:", registry.programId.toBase58());

    const tx = await atomEngine.methods
      .initializeConfig(registry.programId)
      .accounts({
        config: atomConfigPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log("ATOM Initialize tx:", tx);

    const atomConfig = await atomEngine.account.atomConfig.fetch(atomConfigPda);
    expect(atomConfig.authority.toBase58()).to.equal(provider.wallet.publicKey.toBase58());
    expect(atomConfig.agentRegistryProgram.toBase58()).to.equal(registry.programId.toBase58());

    console.log("ATOM Engine initialized successfully!");
  });

  it("Display final state", async () => {
    console.log("\n=== Final Localnet State ===");

    // Root Config
    const rootConfig = await registry.account.rootConfig.fetch(rootConfigPda);
    console.log("\nRoot Config:");
    console.log("  Authority:", rootConfig.authority.toBase58());
    console.log("  Base Collection:", rootConfig.baseCollection.toBase58());

    // Registry Config
    const [registryConfigPda] = getRegistryConfigPda(
      rootConfig.baseCollection,
      registry.programId
    );
    const registryConfig = await registry.account.registryConfig.fetch(registryConfigPda);
    console.log("\nRegistry Config:");
    console.log("  Collection:", registryConfig.collection.toBase58());
    console.log("  Authority:", registryConfig.authority.toBase58());

    // ATOM Config
    const [atomConfigPda] = getAtomConfigPda(atomEngine.programId);
    const atomConfig = await atomEngine.account.atomConfig.fetch(atomConfigPda);
    console.log("\nATOM Config:");
    console.log("  Authority:", atomConfig.authority.toBase58());
    console.log("  Agent Registry Program:", atomConfig.agentRegistryProgram.toBase58());

    console.log("\n=== Localnet Ready for Testing ===\n");
  });
});
