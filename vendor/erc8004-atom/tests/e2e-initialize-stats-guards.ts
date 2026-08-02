import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AgentRegistry8004 } from "../types/agent_registry_8004";
import { AtomEngine } from "../types/atom_engine";
import { Keypair, PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import { expect } from "chai";

import {
  MPL_CORE_PROGRAM_ID,
  getRegistryProgram,
  getRootConfigPda,
  getRegistryConfigPda,
  getAgentPda,
  getAtomConfigPda,
  getAtomStatsPda,
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

describe("E2E InitializeStats Guards", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const registryProgram = getRegistryProgram(provider) as Program<AgentRegistry8004>;
  const atomProgram = anchor.workspace.AtomEngine as Program<AtomEngine>;

  let rootConfigPda: PublicKey;
  let registryConfigPda: PublicKey;
  let collectionPubkey: PublicKey;
  let atomConfigPda: PublicKey;

  async function registerAgent(owner: Keypair, uri: string) {
    const asset = Keypair.generate();
    const [agentPda] = getAgentPda(asset.publicKey, registryProgram.programId);

    await registryProgram.methods
      .register(uri)
      .accountsPartial({
        rootConfig: rootConfigPda,
        registryConfig: registryConfigPda,
        agentAccount: agentPda,
        asset: asset.publicKey,
        collection: collectionPubkey,
        userCollectionAuthority: null,
        owner: owner.publicKey,
        payer: owner.publicKey,
        systemProgram: SystemProgram.programId,
        mplCoreProgram: MPL_CORE_PROGRAM_ID,
      })
      .signers([owner, asset])
      .rpc();

    const [statsPda] = getAtomStatsPda(asset.publicKey, atomProgram.programId);
    return { asset, statsPda };
  }

  before(async () => {
    [rootConfigPda] = getRootConfigPda(registryProgram.programId);
    const rootConfig = await registryProgram.account.rootConfig.fetch(rootConfigPda);
    collectionPubkey = rootConfig.baseCollection;
    [registryConfigPda] = getRegistryConfigPda(collectionPubkey, registryProgram.programId);
    [atomConfigPda] = getAtomConfigPda(atomProgram.programId);

    const atomConfigInfo = await provider.connection.getAccountInfo(atomConfigPda);
    if (!atomConfigInfo) {
      await atomProgram.methods
        .initializeConfig(registryProgram.programId)
        .accounts({
          authority: provider.wallet.publicKey,
          config: atomConfigPda,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    }
  });

  it("initializeStats() succeeds with the true Core owner + collection", async () => {
    const owner = Keypair.generate();
    await fundKeypair(provider, owner, 0.5 * anchor.web3.LAMPORTS_PER_SOL);

    const { asset, statsPda } = await registerAgent(
      owner,
      "https://example.com/atom/initialize-stats-ok"
    );

    await atomProgram.methods
      .initializeStats()
      .accounts({
        owner: owner.publicKey,
        asset: asset.publicKey,
        collection: collectionPubkey,
        config: atomConfigPda,
        stats: statsPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner])
      .rpc();

    const stats = await atomProgram.account.atomStats.fetch(statsPda);
    expect(stats.asset.toBase58()).to.equal(asset.publicKey.toBase58());
    expect(stats.collection.toBase58()).to.equal(collectionPubkey.toBase58());
    expect(stats.schemaVersion).to.equal(1);
  });

  it("initializeStats() rejects non-Core collection accounts", async () => {
    const owner = Keypair.generate();
    await fundKeypair(provider, owner, 0.5 * anchor.web3.LAMPORTS_PER_SOL);

    const { asset, statsPda } = await registerAgent(
      owner,
      "https://example.com/atom/initialize-stats-invalid-collection"
    );

    await expectAnchorError(
      atomProgram.methods
        .initializeStats()
        .accounts({
          owner: owner.publicKey,
          asset: asset.publicKey,
          collection: owner.publicKey,
          config: atomConfigPda,
          stats: statsPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner])
        .rpc(),
      "InvalidCollection"
    );
  });

  it("initializeStats() rejects collection mismatch even with Core-owned accounts", async () => {
    const owner = Keypair.generate();
    await fundKeypair(provider, owner, 0.5 * anchor.web3.LAMPORTS_PER_SOL);

    const { asset, statsPda } = await registerAgent(
      owner,
      "https://example.com/atom/initialize-stats-collection-mismatch"
    );

    await expectAnchorError(
      atomProgram.methods
        .initializeStats()
        .accounts({
          owner: owner.publicKey,
          asset: asset.publicKey,
          collection: asset.publicKey,
          config: atomConfigPda,
          stats: statsPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner])
        .rpc(),
      "CollectionMismatch"
    );
  });
});
