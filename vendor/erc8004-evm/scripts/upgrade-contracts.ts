import hre from "hardhat";

/**
 * Upgrade script for ERC-8004 UUPS upgradeable contracts
 *
 * This script demonstrates how to upgrade the implementation contracts
 * while preserving proxy addresses and storage
 *
 * Usage:
 * 1. Update the proxy addresses below
 * 2. Run: npx hardhat run scripts/upgrade-contracts.ts --network <network>
 */
async function main() {
  const { viem } = await hre.network.connect();
  const [deployer] = await viem.getWalletClients();

  // ========================================
  // CONFIGURATION: Update these addresses from deploy output
  // ========================================
  const IDENTITY_REGISTRY_PROXY = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512";
  const REPUTATION_REGISTRY_PROXY = "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9";
  const VALIDATION_REGISTRY_PROXY = "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707";

  console.log("Upgrading ERC-8004 Contracts");
  console.log("============================");
  console.log("Deployer:", deployer.account.address);
  console.log("");

  // Deploy new implementations
  console.log("Deploying new implementations...");
  console.log("");

  // IdentityRegistry V2
  console.log("1. Deploying IdentityRegistryUpgradeable V2...");
  const identityRegistryImplV2 = await viem.deployContract("IdentityRegistryUpgradeable");
  console.log("   New implementation:", identityRegistryImplV2.address);

  // ReputationRegistry V2
  console.log("2. Deploying ReputationRegistryUpgradeable V2...");
  const reputationRegistryImplV2 = await viem.deployContract("ReputationRegistryUpgradeable");
  console.log("   New implementation:", reputationRegistryImplV2.address);

  // ValidationRegistry V2
  console.log("3. Deploying ValidationRegistryUpgradeable V2...");
  const validationRegistryImplV2 = await viem.deployContract("ValidationRegistryUpgradeable");
  console.log("   New implementation:", validationRegistryImplV2.address);
  console.log("");

  // Get proxy instances
  const identityRegistry = await viem.getContractAt(
    "IdentityRegistryUpgradeable",
    IDENTITY_REGISTRY_PROXY
  );

  const reputationRegistry = await viem.getContractAt(
    "ReputationRegistryUpgradeable",
    REPUTATION_REGISTRY_PROXY
  );

  const validationRegistry = await viem.getContractAt(
    "ValidationRegistryUpgradeable",
    VALIDATION_REGISTRY_PROXY
  );

  // Perform upgrades (requires owner privileges)
  console.log("Upgrading proxies to new implementations...");
  console.log("");

  console.log("4. Upgrading IdentityRegistry...");
  const identityUpgradeTx = await identityRegistry.write.upgradeToAndCall([
    identityRegistryImplV2.address,
    "0x" // No initialization data needed
  ]);
  console.log("   Upgrade tx:", identityUpgradeTx);

  console.log("5. Upgrading ReputationRegistry...");
  const reputationUpgradeTx = await reputationRegistry.write.upgradeToAndCall([
    reputationRegistryImplV2.address,
    "0x"
  ]);
  console.log("   Upgrade tx:", reputationUpgradeTx);

  console.log("6. Upgrading ValidationRegistry...");
  const validationUpgradeTx = await validationRegistry.write.upgradeToAndCall([
    validationRegistryImplV2.address,
    "0x"
  ]);
  console.log("   Upgrade tx:", validationUpgradeTx);
  console.log("");

  // Verify upgrades
  console.log("Verifying upgrades...");
  console.log("=====================");

  const identityVersion = await identityRegistry.read.getVersion();
  console.log("IdentityRegistry version:", identityVersion);

  const reputationVersion = await reputationRegistry.read.getVersion();
  console.log("ReputationRegistry version:", reputationVersion);

  const validationVersion = await validationRegistry.read.getVersion();
  console.log("ValidationRegistry version:", validationVersion);
  console.log("");

  console.log("✅ All contracts upgraded successfully!");
  console.log("");
  console.log("New Implementation Addresses:");
  console.log("IdentityRegistry:", identityRegistryImplV2.address);
  console.log("ReputationRegistry:", reputationRegistryImplV2.address);
  console.log("ValidationRegistry:", validationRegistryImplV2.address);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
