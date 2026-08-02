//! Integration tests for tenzro-wallet

use tempfile::TempDir;
use tenzro_types::AssetId;
use tenzro_types::primitives::Address;
use tenzro_wallet::{
    builder::TransactionBuilder,
    provisioning::WalletProvisioner,
    service::{TenzroWalletService, WalletServiceConfig},
    traits::WalletService,
};

#[tokio::test]
async fn test_wallet_provisioning_and_signing() {
    // Create a wallet service
    let temp_dir = TempDir::new().unwrap();
    let config = WalletServiceConfig::new(temp_dir.path().to_path_buf());
    let service = TenzroWalletService::with_config(config).unwrap();

    // Provision a wallet
    let wallet = service.provision_wallet().await.unwrap();

    // Verify wallet properties
    assert_eq!(wallet.threshold, 2);
    assert_eq!(wallet.total_shares, 3);
    assert!(wallet.can_sign());

    // Sign raw data using sign_data
    let data = b"test data for signing";
    let signature = service.sign_data(&wallet.wallet_id, data).await.unwrap();

    // Hybrid signature: classical leg (sign_data uses MPC threshold combine —
    // returns the combined classical signature) + mandatory ML-DSA-65 leg.
    assert!(!signature.classical.is_empty());
    assert_eq!(signature.pq.len(), 3309);
}

#[tokio::test]
async fn test_wallet_transaction_signing() {
    let temp_dir = TempDir::new().unwrap();
    let config = WalletServiceConfig::new(temp_dir.path().to_path_buf());
    let service = TenzroWalletService::with_config(config).unwrap();

    let wallet = service.provision_wallet().await.unwrap();

    // Build a valid transaction using the builder. `from_wallet_pq` binds both
    // the classical sender address and the wallet's ML-DSA-65 verifying key
    // into the transaction so `sign_transaction` can match them at signing.
    let nonce = service.next_nonce(&wallet.address);
    let tx = TransactionBuilder::default_chain()
        .from_wallet_pq(&wallet)
        .to(Address::new([2u8; 32]))
        .nonce(nonce)
        .transfer(1000)
        .build_validated()
        .unwrap();

    // Sign the transaction (validates, signs with MPC, verifies signature,
    // then signs ML-DSA-65 over the same Transaction::hash() preimage).
    let signature = service
        .sign_transaction(&wallet.wallet_id, &tx)
        .await
        .unwrap();

    assert!(!signature.classical.is_empty());
    assert_eq!(signature.pq.len(), 3309);
}

#[tokio::test]
async fn test_balance_tracking() {
    let temp_dir = TempDir::new().unwrap();
    let config = WalletServiceConfig::new(temp_dir.path().to_path_buf());
    let service = TenzroWalletService::with_config(config).unwrap();

    let wallet = service.provision_wallet().await.unwrap();

    // Check initial balance
    let balance = service
        .get_balance(&wallet.address, &AssetId::tnzo())
        .await
        .unwrap();
    assert_eq!(balance.available, 0);

    // Add some balance
    let tracker = service.balance_tracker();
    tracker.add_balance(&wallet.address, &AssetId::tnzo(), 1000);

    // Check updated balance
    let balance = service
        .get_balance(&wallet.address, &AssetId::tnzo())
        .await
        .unwrap();
    assert_eq!(balance.available, 1000);
}

#[test]
fn test_provisioner_custom_config() {
    use tenzro_crypto::KeyType;
    use tenzro_wallet::provisioning::ProvisioningConfig;

    // Custom 3-of-5 FROST config (FROST-Ed25519 per RFC 9591).
    let config = ProvisioningConfig::new(3, 5).unwrap();

    let provisioner = WalletProvisioner::with_config(config).unwrap();
    let wallet = provisioner.provision_wallet().unwrap();

    assert_eq!(wallet.threshold, 3);
    assert_eq!(wallet.total_shares, 5);
    assert_eq!(wallet.key_type(), KeyType::Ed25519);
}

#[tokio::test]
async fn test_multiple_wallets() {
    let temp_dir = TempDir::new().unwrap();
    let config = WalletServiceConfig::new(temp_dir.path().to_path_buf());
    let service = TenzroWalletService::with_config(config).unwrap();

    // Provision multiple wallets
    let wallet1 = service.provision_wallet().await.unwrap();
    let wallet2 = service.provision_wallet().await.unwrap();
    let wallet3 = service.provision_wallet().await.unwrap();

    // All should have unique IDs and addresses
    assert_ne!(wallet1.wallet_id, wallet2.wallet_id);
    assert_ne!(wallet2.wallet_id, wallet3.wallet_id);
    assert_ne!(wallet1.address, wallet2.address);
    assert_ne!(wallet2.address, wallet3.address);

    // List wallets
    let wallets = service.list_wallets().await.unwrap();
    assert_eq!(wallets.len(), 3);
}

#[tokio::test]
async fn test_asset_support() {
    let temp_dir = TempDir::new().unwrap();
    let config = WalletServiceConfig::new(temp_dir.path().to_path_buf());
    let service = TenzroWalletService::with_config(config).unwrap();

    let wallet = service.provision_wallet().await.unwrap();

    // Check default assets
    assert!(wallet.supports_asset(&AssetId::tnzo()));
    assert!(wallet.supports_asset(&AssetId::from("USDT")));
    assert!(wallet.supports_asset(&AssetId::from("USDC")));

    // Supported assets should be available
    let assets = service.supported_assets().await;
    assert!(assets.contains(&AssetId::tnzo()));
}
