//! TIP-20 stablecoin types and ABI encoding for Tempo network
//!
//! TIP-20 tokens are ERC-20 compatible tokens on the Tempo blockchain.
//! This module provides ABI encoding helpers for common ERC-20 function calls
//! so we can interact with TIP-20 contracts via `eth_call` and `eth_sendRawTransaction`.

use serde::{Deserialize, Serialize};

/// ERC-20 function selector for `balanceOf(address)` — keccak256("balanceOf(address)")[:4]
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

/// ERC-20 function selector for `transfer(address,uint256)` — keccak256("transfer(address,uint256)")[:4]
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// ERC-20 function selector for `approve(address,uint256)` — keccak256("approve(address,uint256)")[:4]
const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// ERC-20 function selector for `decimals()` — keccak256("decimals()")[:4]
const DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];

/// A TIP-20 token on the Tempo network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tip20Token {
    /// Token symbol (e.g., "USDC", "USDT")
    pub symbol: String,
    /// Token name
    pub name: String,
    /// Contract address on Tempo
    pub address: String,
    /// Decimal places
    pub decimals: u8,
}

impl Tip20Token {
    /// Creates a USDC token definition
    pub fn usdc(address: impl Into<String>) -> Self {
        Self {
            symbol: "USDC".to_string(),
            name: "USD Coin".to_string(),
            address: address.into(),
            decimals: 6,
        }
    }

    /// Creates a USDT token definition
    pub fn usdt(address: impl Into<String>) -> Self {
        Self {
            symbol: "USDT".to_string(),
            name: "Tether USD".to_string(),
            address: address.into(),
            decimals: 6,
        }
    }
}

/// Balance of a TIP-20 token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tip20Balance {
    /// Token symbol
    pub symbol: String,
    /// Balance in smallest unit
    pub balance: u128,
    /// Token decimals
    pub decimals: u8,
}

impl Tip20Balance {
    /// Returns the balance as a human-readable string
    pub fn display_amount(&self) -> String {
        let divisor = 10u128.pow(self.decimals as u32);
        let whole = self.balance / divisor;
        let frac = self.balance % divisor;
        format!("{}.{:0>width$}", whole, frac, width = self.decimals as usize)
    }
}

/// ABI-encodes a `balanceOf(address)` call for an ERC-20/TIP-20 token
///
/// The address is left-padded to 32 bytes as per Solidity ABI encoding.
pub fn encode_balance_of(address: &str) -> Vec<u8> {
    let addr_bytes = parse_address_bytes(address);
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&BALANCE_OF_SELECTOR);
    // Left-pad address to 32 bytes
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(&addr_bytes);
    calldata
}

/// ABI-encodes a `transfer(address,uint256)` call for an ERC-20/TIP-20 token
pub fn encode_transfer(to: &str, amount: u128) -> Vec<u8> {
    let to_bytes = parse_address_bytes(to);
    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&TRANSFER_SELECTOR);
    // Left-pad address to 32 bytes
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(&to_bytes);
    // Left-pad uint256 amount to 32 bytes
    let mut amount_bytes = [0u8; 32];
    let amount_be = amount.to_be_bytes();
    amount_bytes[16..].copy_from_slice(&amount_be);
    calldata.extend_from_slice(&amount_bytes);
    calldata
}

/// ABI-encodes an `approve(address,uint256)` call for an ERC-20/TIP-20 token
pub fn encode_approve(spender: &str, amount: u128) -> Vec<u8> {
    let spender_bytes = parse_address_bytes(spender);
    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&APPROVE_SELECTOR);
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(&spender_bytes);
    let mut amount_bytes = [0u8; 32];
    let amount_be = amount.to_be_bytes();
    amount_bytes[16..].copy_from_slice(&amount_be);
    calldata.extend_from_slice(&amount_bytes);
    calldata
}

/// ABI-encodes a `decimals()` call
pub fn encode_decimals() -> Vec<u8> {
    DECIMALS_SELECTOR.to_vec()
}

/// Decodes a uint256 return value from an `eth_call` hex response
///
/// The response is a hex string like "0x0000...00001e8480" representing a 256-bit integer.
pub fn decode_uint256(hex_result: &str) -> u128 {
    let clean = hex_result.strip_prefix("0x").unwrap_or(hex_result);
    // Take the last 32 hex chars (16 bytes = u128) since TIP-20 balances fit in u128
    if clean.len() >= 32 {
        let last_32 = &clean[clean.len().saturating_sub(32)..];
        u128::from_str_radix(last_32, 16).unwrap_or(0)
    } else {
        u128::from_str_radix(clean, 16).unwrap_or(0)
    }
}

/// Parses an Ethereum-style hex address (with or without 0x prefix) into 20 bytes
fn parse_address_bytes(address: &str) -> [u8; 20] {
    let clean = address.strip_prefix("0x").unwrap_or(address);
    let bytes = hex::decode(clean).unwrap_or_default();
    let mut result = [0u8; 20];
    let len = bytes.len().min(20);
    result[20 - len..].copy_from_slice(&bytes[..len]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_amount() {
        let balance = Tip20Balance {
            symbol: "USDC".to_string(),
            balance: 1_500_000, // 1.5 USDC
            decimals: 6,
        };
        assert_eq!(balance.display_amount(), "1.500000");
    }

    #[test]
    fn test_zero_balance() {
        let balance = Tip20Balance {
            symbol: "USDC".to_string(),
            balance: 0,
            decimals: 6,
        };
        assert_eq!(balance.display_amount(), "0.000000");
    }

    #[test]
    fn test_encode_balance_of() {
        let calldata = encode_balance_of("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        // Should be 4-byte selector + 32-byte padded address = 36 bytes
        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[0..4], &BALANCE_OF_SELECTOR);
        // First 12 bytes of the address param should be zero padding
        assert_eq!(&calldata[4..16], &[0u8; 12]);
    }

    #[test]
    fn test_encode_transfer() {
        let calldata = encode_transfer("0x1234567890abcdef1234567890abcdef12345678", 1_000_000);
        // Should be 4-byte selector + 32-byte address + 32-byte amount = 68 bytes
        assert_eq!(calldata.len(), 68);
        assert_eq!(&calldata[0..4], &TRANSFER_SELECTOR);
    }

    #[test]
    fn test_decode_uint256() {
        // 1,000,000 = 0xF4240
        let hex = "0x00000000000000000000000000000000000000000000000000000000000f4240";
        assert_eq!(decode_uint256(hex), 1_000_000);

        assert_eq!(decode_uint256("0x0"), 0);
        assert_eq!(decode_uint256("0x1"), 1);
    }

    #[test]
    fn test_parse_address_bytes() {
        let addr = parse_address_bytes("0x0000000000000000000000000000000000000001");
        assert_eq!(addr[19], 1);
        assert_eq!(addr[..19], [0u8; 19]);
    }
}
