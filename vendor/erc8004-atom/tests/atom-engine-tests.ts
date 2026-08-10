/**
 * ATOM Engine Tests - Standalone Program Tests
 * Tests for the atom-engine config and initialization
 *
 * ATOM = Agent Trust On-chain Model
 *
 * NOTE: updateStats/revokeStats require CPI from agent-registry.
 * Those are tested in the dedicated CPI test files:
 *   - atom-attack-vectors.ts
 *   - atom-griefing.ts
 *   - atom-hll-stuffing.ts
 *   - atom-iron-dome.ts
 *   - atom-phantom-swarm.ts
 *   - atom-security-audit.ts
 *   - atom-stress-tests.ts
 *   - atom-functional-validation.ts
 *   - atom-entropy-backfire.ts
 */
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AtomEngine } from "../types/atom_engine";
import { Keypair, SystemProgram, PublicKey, Transaction } from "@solana/web3.js";
import { expect } from "chai";

import {
  ATOM_ENGINE_PROGRAM_ID,
  getAtomConfigPda,
  getAtomStatsPda,
  randomHash,
  expectAnchorError,
} from "./utils/helpers";

async function fundKeypair(
  provider: anchor.AnchorProvider,
  keypair: Keypair,
  lamports: number
): Promise<void> {
  const tx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: provider.wallet.publicKey,
      toPubkey: keypair.publicKey,
      lamports,
    })
  );
  await provider.sendAndConfirm(tx);
}

describe("ATOM Engine Tests (Standalone)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.AtomEngine as Program<AtomEngine>;

  let atomConfigPda: PublicKey;
  let atomConfigBump: number;
  let unauthorizedUser: Keypair;

  const fakeAgentRegistryProgram = new PublicKey("3GGkAWC3mYYdud8GVBsKXK5QC9siXtFkWVZFYtbueVbC");

  before(async () => {
    [atomConfigPda, atomConfigBump] = getAtomConfigPda();

    unauthorizedUser = Keypair.generate();
    await fundKeypair(provider, unauthorizedUser, 0.1 * anchor.web3.LAMPORTS_PER_SOL);

    console.log("=== ATOM Engine Tests Setup ===");
    console.log("Program ID:", program.programId.toBase58());
    console.log("AtomConfig PDA:", atomConfigPda.toBase58());
  });

  // ============================================================================
  // CONFIG INITIALIZATION TESTS
  // ============================================================================
  describe("Config Initialization", () => {
    it("initializeConfig() creates AtomConfig if not exists", async () => {
      const configInfo = await provider.connection.getAccountInfo(atomConfigPda);

      if (!configInfo) {
        await program.methods
          .initializeConfig(fakeAgentRegistryProgram)
          .accounts({
            authority: provider.wallet.publicKey,
            config: atomConfigPda,
            systemProgram: SystemProgram.programId,
          })
          .rpc();

        console.log("AtomConfig initialized");
      } else {
        console.log("AtomConfig already exists, skipping initialization");
      }

      const config = await program.account.atomConfig.fetch(atomConfigPda);
      expect(config.authority.toBase58()).to.equal(provider.wallet.publicKey.toBase58());
      expect(config.paused).to.equal(false);
      expect(config.version).to.be.gte(0);
    });

    it("initializeConfig() fails if already initialized", async () => {
      try {
        await program.methods
          .initializeConfig(fakeAgentRegistryProgram)
          .accounts({
            authority: provider.wallet.publicKey,
            config: atomConfigPda,
            systemProgram: SystemProgram.programId,
          })
          .rpc();

        throw new Error("Should have failed");
      } catch (error: any) {
        expect(error.toString()).to.include("already in use");
      }
    });

    it("initializeConfig() fails for non-authority", async () => {
      try {
        await program.methods
          .initializeConfig(fakeAgentRegistryProgram)
          .accounts({
            authority: unauthorizedUser.publicKey,
            config: atomConfigPda,
            systemProgram: SystemProgram.programId,
          })
          .signers([unauthorizedUser])
          .rpc();

        throw new Error("Should have failed");
      } catch (error: any) {
        expect(error.toString()).to.not.include("Should have failed");
      }
    });
  });

  // ============================================================================
  // CONFIG UPDATE TESTS
  // ============================================================================
  describe("Config Updates", () => {
    it("updateConfig() updates parameters (authority only)", async () => {
      const configBefore = await program.account.atomConfig.fetch(atomConfigPda);
      const versionBefore = configBefore.version;

      await program.methods
        .updateConfig(
          15,    // alphaFast (valid: 1-100)
          null,  // alphaSlow
          null,  // alphaVolatility
          null,  // alphaArrival
          null,  // weightSybil
          null,  // weightBurst
          null,  // weightStagnation
          null,  // weightShock
          null,  // weightVolatility
          null,  // weightArrival
          null,  // diversityThreshold
          null,  // burstThreshold
          null,  // shockThreshold
          null,  // volatilityThreshold
          null,  // paused
        )
        .accounts({
          authority: provider.wallet.publicKey,
          config: atomConfigPda,
        })
        .rpc();

      const configAfter = await program.account.atomConfig.fetch(atomConfigPda);
      expect(configAfter.alphaFast).to.equal(15);
      expect(configAfter.version).to.equal(versionBefore + 1);
    });

    it("updateConfig() can pause/unpause engine", async () => {
      // Pause
      await program.methods
        .updateConfig(
          null, null, null, null, null, null, null, null, null, null,
          null, null, null, null, true
        )
        .accounts({
          authority: provider.wallet.publicKey,
          config: atomConfigPda,
        })
        .rpc();

      let config = await program.account.atomConfig.fetch(atomConfigPda);
      expect(config.paused).to.equal(true);

      // Unpause
      await program.methods
        .updateConfig(
          null, null, null, null, null, null, null, null, null, null,
          null, null, null, null, false
        )
        .accounts({
          authority: provider.wallet.publicKey,
          config: atomConfigPda,
        })
        .rpc();

      config = await program.account.atomConfig.fetch(atomConfigPda);
      expect(config.paused).to.equal(false);
    });

    it("updateConfig() fails for non-authority", async () => {
      try {
        await program.methods
          .updateConfig(
            20, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null
          )
          .accounts({
            authority: unauthorizedUser.publicKey,
            config: atomConfigPda,
          })
          .signers([unauthorizedUser])
          .rpc();

        throw new Error("Should have failed");
      } catch (error: any) {
        expect(error.toString()).to.include("Error");
      }
    });

    it("updateConfig() rejects alpha_fast out of bounds", async () => {
      try {
        await program.methods
          .updateConfig(
            0, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null
          )
          .accounts({
            authority: provider.wallet.publicKey,
            config: atomConfigPda,
          })
          .rpc();

        throw new Error("Should have failed");
      } catch (error: any) {
        expect(error.toString()).to.include("InvalidConfigParameter");
      }
    });

    it("updateConfig() rejects alpha_fast > 100", async () => {
      try {
        await program.methods
          .updateConfig(
            101, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null
          )
          .accounts({
            authority: provider.wallet.publicKey,
            config: atomConfigPda,
          })
          .rpc();

        throw new Error("Should have failed");
      } catch (error: any) {
        expect(error.toString()).to.include("InvalidConfigParameter");
      }
    });

    it("updateConfig() rejects weight_sybil > 50", async () => {
      try {
        await program.methods
          .updateConfig(
            null, null, null, null, 51, null, null, null, null, null,
            null, null, null, null, null
          )
          .accounts({
            authority: provider.wallet.publicKey,
            config: atomConfigPda,
          })
          .rpc();

        throw new Error("Should have failed");
      } catch (error: any) {
        expect(error.toString()).to.include("InvalidConfigParameter");
      }
    });

    it("updateConfig() accepts boundary values", async () => {
      await program.methods
        .updateConfig(
          1,     // alphaFast min
          100,   // alphaSlow max
          50,    // alphaVolatility mid
          null,  // alphaArrival
          50,    // weightSybil max
          0,     // weightBurst min
          null,  // weightStagnation
          null,  // weightShock
          null,  // weightVolatility
          null,  // weightArrival
          100,   // diversityThreshold max
          null,  // burstThreshold
          10000, // shockThreshold max
          null,  // volatilityThreshold
          null,  // paused
        )
        .accounts({
          authority: provider.wallet.publicKey,
          config: atomConfigPda,
        })
        .rpc();

      const config = await program.account.atomConfig.fetch(atomConfigPda);
      expect(config.alphaFast).to.equal(1);
      expect(config.alphaSlow).to.equal(100);
      expect(config.alphaVolatility).to.equal(50);
      expect(config.weightSybil).to.equal(50);
      expect(config.weightBurst).to.equal(0);
      expect(config.diversityThreshold).to.equal(100);
      expect(config.shockThreshold).to.equal(10000);
    });
  });

  // ============================================================================
  // ATOM STATS PDA DERIVATION TESTS
  // ============================================================================
  describe("PDA Derivation", () => {
    it("AtomStats PDA is deterministic for same asset", () => {
      const asset = Keypair.generate();
      const [pda1] = getAtomStatsPda(asset.publicKey);
      const [pda2] = getAtomStatsPda(asset.publicKey);
      expect(pda1.toBase58()).to.equal(pda2.toBase58());
    });

    it("AtomStats PDA differs for different assets", () => {
      const asset1 = Keypair.generate();
      const asset2 = Keypair.generate();
      const [pda1] = getAtomStatsPda(asset1.publicKey);
      const [pda2] = getAtomStatsPda(asset2.publicKey);
      expect(pda1.toBase58()).to.not.equal(pda2.toBase58());
    });

    it("AtomConfig PDA uses correct seed", () => {
      const [pda] = PublicKey.findProgramAddressSync(
        [Buffer.from("atom_config")],
        ATOM_ENGINE_PROGRAM_ID
      );
      const [helperPda] = getAtomConfigPda();
      expect(pda.toBase58()).to.equal(helperPda.toBase58());
    });
  });
});
