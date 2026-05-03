//! CIP-56 DAML Token Template for TNZO on Canton
//!
//! Implements the Canton CIP-56 token standard for enterprise settlement.
//! CIP-56 differs from ERC-20 in several key ways:
//!
//! - **Two-step transfers**: Sender creates a TransferInstruction, receiver must accept
//! - **Privacy**: Only parties involved in a transfer see the transfer details
//! - **Compliance**: KYC/AML rules are embedded at the token level
//! - **Atomic DvP**: Delivery-vs-Payment settlement in a single atomic operation
//!
//! In the pointer model, TNZO DAML holdings represent the same underlying balance
//! as native TNZO. The adapter translates Canton Ledger API v2 commands into
//! TnzoToken operations.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_token::TnzoToken;
use tenzro_types::primitives::Address;
use tracing::{debug, info};

/// CIP-56 template identifiers
pub const TNZO_HOLDING_TEMPLATE: &str = "Tenzro.Token:TnzoHolding";
pub const TNZO_TRANSFER_FACTORY_TEMPLATE: &str = "Tenzro.Token:TnzoTransferFactory";
pub const TNZO_TRANSFER_INSTRUCTION_TEMPLATE: &str = "Tenzro.Token:TnzoTransferInstruction";

/// CIP-56 holding record
///
/// Represents a TNZO balance held by a party on Canton.
/// The balance reads from the native TnzoToken layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TnzoHolding {
    /// The party that owns this holding
    pub owner: String,
    /// The admin party (Tenzro Network)
    pub admin: String,
    /// Balance amount as string (DAML uses arbitrary-precision Decimal)
    pub amount: String,
    /// Contract ID (assigned by Canton)
    pub contract_id: Option<String>,
}

/// CIP-56 transfer instruction
///
/// Created by the sender, must be accepted by the receiver.
/// This two-step process prevents unwanted deposits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TnzoTransferInstruction {
    /// Sender party
    pub sender: String,
    /// Receiver party
    pub receiver: String,
    /// Amount to transfer (string representation of Decimal)
    pub amount: String,
    /// Reference/memo (optional)
    pub reference: Option<String>,
    /// Contract ID (assigned by Canton)
    pub contract_id: Option<String>,
    /// Status of the transfer instruction
    pub status: TransferStatus,
}

/// Transfer instruction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferStatus {
    /// Awaiting receiver acceptance
    Pending,
    /// Receiver accepted, transfer executed
    Accepted,
    /// Receiver or sender rejected
    Rejected,
    /// Expired (not accepted within time window)
    Expired,
}

/// CIP-56 Token Adapter for Canton/DAML
///
/// Bridges Canton Ledger API v2 commands to the native TnzoToken layer.
pub struct Cip56TokenAdapter {
    /// Reference to the native TNZO token
    token: Arc<TnzoToken>,
    /// Admin party identifier (Tenzro Network)
    admin_party: String,
}

impl Cip56TokenAdapter {
    /// Creates a new CIP-56 adapter
    pub fn new(token: Arc<TnzoToken>, admin_party: String) -> Self {
        Self { token, admin_party }
    }

    /// Returns the admin party
    pub fn admin_party(&self) -> &str {
        &self.admin_party
    }

    /// Gets the holding for a party
    ///
    /// Reads from the native TnzoToken balance and returns it as a CIP-56 Holding.
    pub fn get_holding(&self, owner_party: &str) -> TnzoHolding {
        // Map party identifier to Tenzro address
        let address = party_to_address(owner_party);
        let balance = self.token.balance_of(&address);

        // Convert to decimal string (18 decimal places)
        let whole = balance / tenzro_token::NATIVE_UNIT;
        let frac = balance % tenzro_token::NATIVE_UNIT;

        let amount = if frac == 0 {
            format!("{}.0", whole)
        } else {
            format!("{}.{:018}", whole, frac)
                .trim_end_matches('0')
                .to_string()
        };

        TnzoHolding {
            owner: owner_party.to_string(),
            admin: self.admin_party.clone(),
            amount,
            contract_id: None,
        }
    }

    /// Creates a transfer instruction (step 1 of CIP-56 two-step transfer)
    ///
    /// Returns a `TnzoTransferInstruction` in Pending status.
    /// The receiver must call `accept_transfer` to execute.
    pub fn create_transfer_instruction(
        &self,
        sender: &str,
        receiver: &str,
        amount_str: &str,
        reference: Option<&str>,
    ) -> Result<TnzoTransferInstruction, String> {
        // Validate sender has sufficient balance
        let amount = parse_decimal_amount(amount_str)?;
        let sender_addr = party_to_address(sender);
        let balance = self.token.balance_of(&sender_addr);

        if balance < amount {
            return Err(format!(
                "Insufficient balance: have {}, need {}",
                balance, amount
            ));
        }

        let instruction = TnzoTransferInstruction {
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            amount: amount_str.to_string(),
            reference: reference.map(|s| s.to_string()),
            contract_id: None,
            status: TransferStatus::Pending,
        };

        info!(
            "CIP-56 transfer instruction created: {} -> {} amount={}",
            sender, receiver, amount_str
        );

        Ok(instruction)
    }

    /// Accepts a transfer instruction (step 2 of CIP-56 two-step transfer)
    ///
    /// Executes the actual balance transfer in the native layer.
    pub fn accept_transfer(
        &self,
        instruction: &mut TnzoTransferInstruction,
        accepting_party: &str,
    ) -> Result<(), String> {
        if instruction.status != TransferStatus::Pending {
            return Err(format!(
                "Transfer instruction is {:?}, not Pending",
                instruction.status
            ));
        }

        if accepting_party != instruction.receiver {
            return Err(format!(
                "Only the receiver ({}) can accept, not {}",
                instruction.receiver, accepting_party
            ));
        }

        let amount = parse_decimal_amount(&instruction.amount)?;
        let from_addr = party_to_address(&instruction.sender);
        let to_addr = party_to_address(&instruction.receiver);

        self.token
            .transfer(&from_addr, &to_addr, amount)
            .map_err(|e| e.to_string())?;

        instruction.status = TransferStatus::Accepted;

        info!(
            "CIP-56 transfer accepted: {} -> {} amount={}",
            instruction.sender, instruction.receiver, instruction.amount
        );

        Ok(())
    }

    /// Rejects a transfer instruction
    pub fn reject_transfer(
        &self,
        instruction: &mut TnzoTransferInstruction,
        rejecting_party: &str,
    ) -> Result<(), String> {
        if instruction.status != TransferStatus::Pending {
            return Err(format!(
                "Transfer instruction is {:?}, not Pending",
                instruction.status
            ));
        }

        if rejecting_party != instruction.receiver && rejecting_party != instruction.sender {
            return Err("Only sender or receiver can reject".to_string());
        }

        instruction.status = TransferStatus::Rejected;
        debug!(
            "CIP-56 transfer rejected by {}: {} -> {} amount={}",
            rejecting_party, instruction.sender, instruction.receiver, instruction.amount
        );

        Ok(())
    }

    /// Builds a Canton Ledger API v2 create command for a TnzoHolding
    pub fn build_create_holding_command(
        &self,
        owner: &str,
        amount: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "commands": [{
                "Create": {
                    "templateId": TNZO_HOLDING_TEMPLATE,
                    "createArguments": {
                        "owner": owner,
                        "admin": self.admin_party,
                        "amount": amount
                    }
                }
            }]
        })
    }

    /// Builds a Canton Ledger API v2 exercise command for Transfer choice
    pub fn build_transfer_command(
        &self,
        holding_contract_id: &str,
        new_owner: &str,
        amount: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "commands": [{
                "Exercise": {
                    "templateId": TNZO_HOLDING_TEMPLATE,
                    "contractId": holding_contract_id,
                    "choice": "Transfer",
                    "choiceArgument": {
                        "newOwner": new_owner,
                        "transferAmount": amount
                    }
                }
            }]
        })
    }
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Maps a Canton party identifier to a Tenzro Address
///
/// Party IDs in Canton are strings like "Alice::1234" or hex-encoded keys.
/// We hash the party ID to produce a deterministic 32-byte address.
fn party_to_address(party: &str) -> Address {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"tenzro-daml-party:");
    hasher.update(party.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Address::new(bytes)
}

/// Parses a decimal string amount into native 18-decimal u128
///
/// Supports formats: "1.5", "100", "0.000001", "1000000.123456789012345678"
fn parse_decimal_amount(s: &str) -> Result<u128, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty amount string".to_string());
    }

    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 2 {
        return Err("Invalid decimal format".to_string());
    }

    let whole: u128 = parts[0]
        .parse()
        .map_err(|_| format!("Invalid whole part: {}", parts[0]))?;

    let frac: u128 = if parts.len() == 2 {
        let frac_str = parts[1];
        if frac_str.len() > 18 {
            return Err("Too many decimal places (max 18)".to_string());
        }
        // Pad with zeros to 18 decimal places
        let padded = format!("{:0<18}", frac_str);
        padded
            .parse()
            .map_err(|_| format!("Invalid fractional part: {}", frac_str))?
    } else {
        0
    };

    let amount = whole
        .checked_mul(tenzro_token::NATIVE_UNIT)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| "Amount overflow".to_string())?;

    Ok(amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Cip56TokenAdapter {
        let token = Arc::new(TnzoToken::new());
        let treasury = Address::new([0xFF; 32]);
        token.set_treasury_address(treasury);

        // Fund parties via their hashed addresses
        let alice_addr = party_to_address("Alice::1234");
        let bob_addr = party_to_address("Bob::5678");
        token
            .mint(&alice_addr, 1000 * tenzro_token::NATIVE_UNIT, &treasury)
            .unwrap();
        token
            .mint(&bob_addr, 500 * tenzro_token::NATIVE_UNIT, &treasury)
            .unwrap();

        Cip56TokenAdapter::new(token, "TenzroAdmin::0001".to_string())
    }

    #[test]
    fn test_get_holding() {
        let adapter = setup();
        let holding = adapter.get_holding("Alice::1234");
        assert_eq!(holding.owner, "Alice::1234");
        assert_eq!(holding.amount, "1000.0");
    }

    #[test]
    fn test_two_step_transfer() {
        let adapter = setup();

        // Step 1: Create transfer instruction
        let mut instruction = adapter
            .create_transfer_instruction("Alice::1234", "Bob::5678", "100.0", Some("payment"))
            .unwrap();
        assert_eq!(instruction.status, TransferStatus::Pending);

        // Step 2: Accept transfer
        adapter
            .accept_transfer(&mut instruction, "Bob::5678")
            .unwrap();
        assert_eq!(instruction.status, TransferStatus::Accepted);

        // Verify balances
        let alice = adapter.get_holding("Alice::1234");
        let bob = adapter.get_holding("Bob::5678");
        assert_eq!(alice.amount, "900.0");
        assert_eq!(bob.amount, "600.0");
    }

    #[test]
    fn test_reject_transfer() {
        let adapter = setup();

        let mut instruction = adapter
            .create_transfer_instruction("Alice::1234", "Bob::5678", "100.0", None)
            .unwrap();

        adapter
            .reject_transfer(&mut instruction, "Bob::5678")
            .unwrap();
        assert_eq!(instruction.status, TransferStatus::Rejected);

        // Balance unchanged
        let alice = adapter.get_holding("Alice::1234");
        assert_eq!(alice.amount, "1000.0");
    }

    #[test]
    fn test_insufficient_balance() {
        let adapter = setup();
        let result =
            adapter.create_transfer_instruction("Alice::1234", "Bob::5678", "2000.0", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_unauthorized_accept() {
        let adapter = setup();
        let mut instruction = adapter
            .create_transfer_instruction("Alice::1234", "Bob::5678", "100.0", None)
            .unwrap();

        // Charlie can't accept Bob's transfer
        let result = adapter.accept_transfer(&mut instruction, "Charlie::9999");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_decimal_amount() {
        assert_eq!(
            parse_decimal_amount("1.0").unwrap(),
            tenzro_token::NATIVE_UNIT
        );
        assert_eq!(
            parse_decimal_amount("100").unwrap(),
            100 * tenzro_token::NATIVE_UNIT
        );
        assert_eq!(
            parse_decimal_amount("0.5").unwrap(),
            tenzro_token::NATIVE_UNIT / 2
        );
        assert_eq!(
            parse_decimal_amount("1.000000000000000001").unwrap(),
            tenzro_token::NATIVE_UNIT + 1
        );
    }

    #[test]
    fn test_build_commands() {
        let adapter = setup();

        let cmd = adapter.build_create_holding_command("Alice::1234", "100.0");
        assert!(cmd["commands"][0]["Create"]["templateId"]
            .as_str()
            .unwrap()
            .contains("TnzoHolding"));

        let cmd = adapter.build_transfer_command("contract-123", "Bob::5678", "50.0");
        assert!(cmd["commands"][0]["Exercise"]["choice"]
            .as_str()
            .unwrap()
            == "Transfer");
    }

    #[test]
    fn test_party_to_address_deterministic() {
        let addr1 = party_to_address("Alice::1234");
        let addr2 = party_to_address("Alice::1234");
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_party_to_address_different() {
        let addr1 = party_to_address("Alice::1234");
        let addr2 = party_to_address("Bob::5678");
        assert_ne!(addr1, addr2);
    }
}
