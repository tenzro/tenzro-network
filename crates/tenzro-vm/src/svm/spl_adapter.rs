//! SPL Token Adapter for wTNZO on SVM
//!
//! Provides an SPL-compatible token interface for TNZO on the Solana VM.
//! Following Neon EVM's ERC20ForSPL pattern, this adapter maps SPL Token Program
//! instructions to the native TnzoToken balance layer.
//!
//! # Architecture
//!
//! - SPL tokens use 9 decimals (u64 amounts) vs native TNZO's 18 decimals (u128)
//! - Balances are stored as Associated Token Accounts (ATAs) per-owner
//! - The adapter reads/writes through the unified TnzoToken layer
//! - Decimal conversion uses truncation (not rounding) to prevent inflation
//!
//! # SPL Token Program Instructions
//!
//! | Instruction | Description |
//! |-------------|-------------|
//! | InitializeMint | Create the wTNZO mint (at genesis) |
//! | Transfer | Transfer wTNZO between accounts |
//! | MintTo | Mint wTNZO (bridge deposit only) |
//! | Burn | Burn wTNZO (bridge withdraw only) |
//! | GetBalance | Query account balance |

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::sync::Arc;
use tenzro_token::{TnzoToken, native_to_spl, spl_to_native, SPL_DECIMALS};
use tenzro_types::primitives::Address;
use tracing::debug;

/// The wTNZO SPL mint address (32 bytes, deterministic PDA)
pub const WTNZO_SPL_MINT: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x57; // 'W'
    bytes[1] = 0x54; // 'T'
    bytes[2] = 0x4E; // 'N'
    bytes[3] = 0x5A; // 'Z'
    bytes[4] = 0x4F; // 'O'
    bytes
};

/// SPL Token Program ID (well-known)
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x06; // Matches Solana's TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA prefix byte
    bytes[1] = 0xdd;
    bytes[2] = 0xf6;
    bytes
};

/// SPL instruction discriminators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplInstruction {
    /// Initialize a new mint
    InitializeMint = 0,
    /// Initialize a new token account
    InitializeAccount = 1,
    /// Transfer tokens between accounts
    Transfer = 3,
    /// Approve delegate
    Approve = 4,
    /// Revoke delegate
    Revoke = 5,
    /// Mint tokens to an account
    MintTo = 7,
    /// Burn tokens from an account
    Burn = 8,
    /// Close an account
    CloseAccount = 9,
    /// Get balance (Tenzro extension)
    GetBalance = 200,
}

impl SplInstruction {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(SplInstruction::InitializeMint),
            1 => Some(SplInstruction::InitializeAccount),
            3 => Some(SplInstruction::Transfer),
            4 => Some(SplInstruction::Approve),
            5 => Some(SplInstruction::Revoke),
            7 => Some(SplInstruction::MintTo),
            8 => Some(SplInstruction::Burn),
            9 => Some(SplInstruction::CloseAccount),
            200 => Some(SplInstruction::GetBalance),
            _ => None,
        }
    }
}

/// Represents an Associated Token Account (ATA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAccount {
    /// The mint this account is associated with
    pub mint: [u8; 32],
    /// The owner of this token account
    pub owner: [u8; 32],
    /// Balance in SPL units (9 decimals)
    pub amount: u64,
    /// Delegate authority (if any)
    pub delegate: Option<[u8; 32]>,
    /// Delegated amount
    pub delegated_amount: u64,
    /// Whether the account is frozen
    pub is_frozen: bool,
}

impl TokenAccount {
    /// Creates a new token account for wTNZO
    pub fn new(owner: [u8; 32]) -> Self {
        Self {
            mint: WTNZO_SPL_MINT,
            owner,
            amount: 0,
            delegate: None,
            delegated_amount: 0,
            is_frozen: false,
        }
    }
}

/// SPL Token Adapter for wTNZO
///
/// Bridges SPL Token Program operations to the native TnzoToken layer.
/// Handles decimal conversion (18 -> 9) and ATA management.
pub struct SplTokenAdapter {
    /// Reference to the native TNZO token
    token: Arc<TnzoToken>,
    /// Mint authority (system PDA — no private key)
    mint_authority: [u8; 32],
}

impl SplTokenAdapter {
    /// Creates a new SPL token adapter
    pub fn new(token: Arc<TnzoToken>) -> Self {
        // Derive mint authority PDA: SHA256("tenzro-spl-authority" ++ WTNZO_SPL_MINT)
        let authority = derive_mint_authority();
        Self {
            token,
            mint_authority: authority,
        }
    }

    /// Returns the mint authority address
    pub fn mint_authority(&self) -> &[u8; 32] {
        &self.mint_authority
    }

    /// Returns the wTNZO mint info
    pub fn mint_info(&self) -> SplMintInfo {
        SplMintInfo {
            mint_address: WTNZO_SPL_MINT,
            decimals: SPL_DECIMALS,
            supply: native_to_spl(self.token.total_supply()).unwrap_or(0),
            mint_authority: Some(self.mint_authority),
            freeze_authority: None,
        }
    }

    /// Gets the SPL balance for an owner (reading from native layer + decimal conversion)
    pub fn balance_of(&self, owner: &[u8; 32]) -> u64 {
        let address = Address::new(*owner);
        let native_balance = self.token.balance_of(&address);
        native_to_spl(native_balance).unwrap_or(0)
    }

    /// Transfers SPL tokens between accounts
    ///
    /// Converts the SPL amount (9 decimals) to native (18 decimals) and executes
    /// the transfer through the TnzoToken layer.
    pub fn transfer(
        &self,
        from: &[u8; 32],
        to: &[u8; 32],
        spl_amount: u64,
    ) -> std::result::Result<(), String> {
        if spl_amount == 0 {
            return Ok(());
        }

        let native_amount = spl_to_native(spl_amount);
        let from_addr = Address::new(*from);
        let to_addr = Address::new(*to);

        self.token
            .transfer(&from_addr, &to_addr, native_amount)
            .map_err(|e| e.to_string())?;

        debug!(
            "SPL transfer: {} -> {}, spl_amount={}, native_amount={}",
            hex::encode(from),
            hex::encode(to),
            spl_amount,
            native_amount
        );

        Ok(())
    }

    /// Derives the Associated Token Account address for an owner
    pub fn derive_ata(owner: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"tenzro-ata:");
        hasher.update(owner);
        hasher.update(WTNZO_SPL_MINT);
        hasher.update(SPL_TOKEN_PROGRAM_ID);
        let result = hasher.finalize();
        let mut ata = [0u8; 32];
        ata.copy_from_slice(&result);
        ata
    }

    /// Processes an SPL instruction
    pub fn process_instruction(
        &self,
        instruction_data: &[u8],
        accounts: &[[u8; 32]],
    ) -> std::result::Result<Vec<u8>, String> {
        if instruction_data.is_empty() {
            return Err("Empty instruction data".to_string());
        }

        let instruction = SplInstruction::from_byte(instruction_data[0])
            .ok_or_else(|| format!("Unknown SPL instruction: {}", instruction_data[0]))?;

        match instruction {
            SplInstruction::Transfer => {
                if accounts.len() < 3 || instruction_data.len() < 9 {
                    return Err("Transfer: insufficient accounts or data".to_string());
                }
                let amount = u64::from_le_bytes(
                    instruction_data[1..9]
                        .try_into()
                        .map_err(|_| "Invalid amount encoding".to_string())?,
                );
                // accounts[0] = source, accounts[1] = destination, accounts[2] = authority
                self.transfer(&accounts[0], &accounts[1], amount)?;
                Ok(Vec::new())
            }
            SplInstruction::GetBalance => {
                if accounts.is_empty() {
                    return Err("GetBalance: need account address".to_string());
                }
                let balance = self.balance_of(&accounts[0]);
                Ok(balance.to_le_bytes().to_vec())
            }
            SplInstruction::MintTo => {
                if accounts.len() < 2 || instruction_data.len() < 9 {
                    return Err("MintTo: insufficient accounts or data".to_string());
                }
                let amount = u64::from_le_bytes(
                    instruction_data[1..9]
                        .try_into()
                        .map_err(|_| "Invalid amount encoding".to_string())?,
                );
                // Only the mint authority can mint
                if accounts.len() >= 3 && accounts[2] != self.mint_authority {
                    return Err("MintTo: unauthorized — not mint authority".to_string());
                }
                // In the pointer model, minting SPL tokens means the native balance
                // was already credited. This is a no-op acknowledgment.
                debug!(
                    "SPL MintTo: {} tokens to {}, native layer already credited",
                    amount,
                    hex::encode(accounts[1])
                );
                Ok(Vec::new())
            }
            SplInstruction::Burn => {
                if accounts.len() < 2 || instruction_data.len() < 9 {
                    return Err("Burn: insufficient accounts or data".to_string());
                }
                let amount = u64::from_le_bytes(
                    instruction_data[1..9]
                        .try_into()
                        .map_err(|_| "Invalid amount encoding".to_string())?,
                );
                // In the pointer model, burning SPL tokens is a no-op acknowledgment.
                // The actual burn happens in the native layer via cross-VM bridge.
                debug!(
                    "SPL Burn: {} tokens from {}, handled by native layer",
                    amount,
                    hex::encode(accounts[0])
                );
                Ok(Vec::new())
            }
            _ => {
                // InitializeMint, InitializeAccount, Approve, Revoke, CloseAccount
                // are administrative operations handled at genesis or by the adapter
                debug!("SPL instruction {:?}: no-op in pointer model", instruction);
                Ok(Vec::new())
            }
        }
    }
}

/// Mint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplMintInfo {
    pub mint_address: [u8; 32],
    pub decimals: u8,
    pub supply: u64,
    pub mint_authority: Option<[u8; 32]>,
    pub freeze_authority: Option<[u8; 32]>,
}

/// Derives the mint authority PDA
fn derive_mint_authority() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"tenzro-spl-authority");
    hasher.update(WTNZO_SPL_MINT);
    let result = hasher.finalize();
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&result);
    authority
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> SplTokenAdapter {
        let token = Arc::new(TnzoToken::new());
        let treasury = Address::new([0xFF; 32]);
        token.set_treasury_address(treasury);

        // Mint 1000 TNZO to test account
        let account = Address::new([1u8; 32]);
        token
            .mint(&account, 1_000_000_000_000_000_000_000u128, &treasury) // 1000 TNZO
            .unwrap();

        SplTokenAdapter::new(token)
    }

    #[test]
    fn test_balance_conversion() {
        let adapter = setup();
        let owner = [1u8; 32];
        let spl_balance = adapter.balance_of(&owner);
        // 1000 TNZO at 18 decimals = 1000 * 10^18 native
        // SPL balance at 9 decimals = 1000 * 10^9
        assert_eq!(spl_balance, 1_000_000_000_000u64); // 1000 * 10^9
    }

    #[test]
    fn test_transfer() {
        let adapter = setup();
        let from = [1u8; 32];
        let to = [2u8; 32];

        // Transfer 100 SPL tokens (= 100 * 10^9 SPL units)
        let spl_amount = 100_000_000_000u64; // 100 tokens in SPL units
        adapter.transfer(&from, &to, spl_amount).unwrap();

        // Check balances
        let from_balance = adapter.balance_of(&from);
        let to_balance = adapter.balance_of(&to);
        assert_eq!(from_balance, 900_000_000_000u64); // 900 tokens
        assert_eq!(to_balance, 100_000_000_000u64); // 100 tokens
    }

    #[test]
    fn test_process_transfer_instruction() {
        let adapter = setup();
        let from = [1u8; 32];
        let to = [2u8; 32];
        let authority = [1u8; 32]; // Same as from

        let amount: u64 = 50_000_000_000; // 50 tokens
        let mut instruction = vec![SplInstruction::Transfer as u8];
        instruction.extend_from_slice(&amount.to_le_bytes());

        let result = adapter
            .process_instruction(&instruction, &[from, to, authority])
            .unwrap();
        assert!(result.is_empty());

        assert_eq!(adapter.balance_of(&to), 50_000_000_000u64);
    }

    #[test]
    fn test_process_get_balance() {
        let adapter = setup();
        let owner = [1u8; 32];

        let instruction = vec![SplInstruction::GetBalance as u8];
        let result = adapter
            .process_instruction(&instruction, &[owner])
            .unwrap();

        let balance = u64::from_le_bytes(result[..8].try_into().unwrap());
        assert_eq!(balance, 1_000_000_000_000u64);
    }

    #[test]
    fn test_derive_ata_deterministic() {
        let owner = [42u8; 32];
        let ata1 = SplTokenAdapter::derive_ata(&owner);
        let ata2 = SplTokenAdapter::derive_ata(&owner);
        assert_eq!(ata1, ata2);
    }

    #[test]
    fn test_derive_ata_different_owners() {
        let owner1 = [1u8; 32];
        let owner2 = [2u8; 32];
        let ata1 = SplTokenAdapter::derive_ata(&owner1);
        let ata2 = SplTokenAdapter::derive_ata(&owner2);
        assert_ne!(ata1, ata2);
    }

    #[test]
    fn test_mint_info() {
        let adapter = setup();
        let info = adapter.mint_info();
        assert_eq!(info.decimals, 9);
        assert_eq!(info.mint_address, WTNZO_SPL_MINT);
        assert!(info.mint_authority.is_some());
        assert!(info.supply > 0);
    }
}
