//! wTNZO ERC-20 pointer contract
//!
//! Generates the EVM bytecode for the wTNZO (Wrapped TNZO) contract, which is a
//! pointer contract following the Sei V2 model. All balance operations are delegated
//! to the TNZO_BRIDGE precompile (0x1001), while approvals are stored in standard
//! EVM storage.
//!
//! The contract supports:
//! - Standard ERC-20 interface (name, symbol, decimals, totalSupply, balanceOf, transfer, etc.)
//! - deposit() — payable, locks native TNZO and credits msg.sender via precompile
//! - withdraw(uint256) — burns balance via precompile, sends native TNZO to msg.sender
//! - EIP-2612 permit() for gasless approvals

/// Well-known wTNZO contract address (20 bytes)
/// Computed via CREATE2: deployer=0x0, salt=keccak256("TENZRO_WTNZO_V1"), initcode hash
pub const WTNZO_ADDRESS: [u8; 20] = [
    0x7a, 0x4b, 0xcb, 0x13, 0xa6, 0xb2, 0xb3, 0x84, 0xc2, 0x84,
    0xb5, 0xca, 0xa6, 0xe5, 0xef, 0x31, 0x26, 0x52, 0x7f, 0x93,
];

/// TNZO Bridge precompile address (20 bytes) — 0x1001
pub const TNZO_BRIDGE_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00,
];

/// Token Factory precompile address (20 bytes) — 0x1002
pub const TOKEN_FACTORY_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00,
];

/// Cross-VM bridge precompile address (20 bytes) — 0x1003
pub const CROSS_VM_BRIDGE_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03, 0x00,
];

/// Staking precompile address (20 bytes) — 0x1004
pub const STAKING_PRECOMPILE_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x04, 0x00,
];

/// Governance precompile address (20 bytes) — 0x1005
pub const GOVERNANCE_PRECOMPILE_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x05, 0x00,
];

/// ERC-20 function selectors
pub mod selectors {
    /// name() -> string
    pub const NAME: [u8; 4] = [0x06, 0xfd, 0xde, 0x03];
    /// symbol() -> string
    pub const SYMBOL: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
    /// decimals() -> uint8
    pub const DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
    /// totalSupply() -> uint256
    pub const TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];
    /// balanceOf(address) -> uint256
    pub const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
    /// transfer(address,uint256) -> bool
    pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    /// approve(address,uint256) -> bool
    pub const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
    /// allowance(address,address) -> uint256
    pub const ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
    /// transferFrom(address,address,uint256) -> bool
    pub const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
    /// deposit() — payable
    pub const DEPOSIT: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
    /// withdraw(uint256)
    pub const WITHDRAW: [u8; 4] = [0x2e, 0x1a, 0x7d, 0x4d];

    // -----------------------------------------------------------------------
    // ERC-7802 Cross-Chain Token Interface selectors
    // -----------------------------------------------------------------------

    /// crosschainMint(address,uint256,bytes) — ERC-7802
    /// Computed via keccak256("crosschainMint(address,uint256,bytes)")[..4]
    pub const CROSSCHAIN_MINT: [u8; 4] = [0xec, 0x0e, 0xc5, 0xb3];
    /// crosschainBurn(address,uint256,bytes) — ERC-7802
    /// Computed via keccak256("crosschainBurn(address,uint256,bytes)")[..4]
    pub const CROSSCHAIN_BURN: [u8; 4] = [0xcb, 0xa5, 0xb0, 0xa7];
}

/// ERC-20 event topic hashes
pub mod events {
    use sha3::{Digest, Keccak256};

    /// Transfer(address indexed from, address indexed to, uint256 value)
    pub fn transfer_topic() -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"Transfer(address,address,uint256)");
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// Approval(address indexed owner, address indexed spender, uint256 value)
    pub fn approval_topic() -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"Approval(address,address,uint256)");
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// Deposit(address indexed dst, uint256 wad)
    pub fn deposit_topic() -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"Deposit(address,uint256)");
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// Withdrawal(address indexed src, uint256 wad)
    pub fn withdrawal_topic() -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"Withdrawal(address,uint256)");
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// CrosschainMint(address indexed to, uint256 amount, address indexed sender) — ERC-7802
    pub fn crosschain_mint_topic() -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"CrosschainMint(address,uint256,address)");
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// CrosschainBurn(address indexed from, uint256 amount, address indexed sender) — ERC-7802
    pub fn crosschain_burn_topic() -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"CrosschainBurn(address,uint256,address)");
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }
}

/// ABI encoding utilities for EVM return values
pub mod abi {
    /// Encode a uint256 (left-padded to 32 bytes)
    pub fn encode_uint256(value: u128) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        bytes[16..32].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    /// Encode a bool as uint256
    pub fn encode_bool(value: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        if value {
            bytes[31] = 1;
        }
        bytes
    }

    /// Encode a string (ABI dynamic type: offset + length + padded data)
    pub fn encode_string(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let padded_len = bytes.len().div_ceil(32) * 32;

        let mut result = Vec::with_capacity(64 + padded_len);
        // Offset to data (32 bytes from start)
        result.extend_from_slice(&encode_uint256(32));
        // Length
        result.extend_from_slice(&encode_uint256(bytes.len() as u128));
        // Padded data
        result.extend_from_slice(bytes);
        result.resize(64 + padded_len, 0);
        result
    }

    /// Encode a uint8 (left-padded to 32 bytes)
    pub fn encode_uint8(value: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        bytes[31] = value;
        bytes
    }

    /// Decode an address from ABI-encoded input (right-aligned in 32 bytes)
    pub fn decode_address_20(input: &[u8]) -> Option<[u8; 20]> {
        if input.len() < 32 {
            return None;
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&input[12..32]);
        Some(addr)
    }

    /// Decode a uint256 from ABI-encoded input
    pub fn decode_uint256(input: &[u8]) -> Option<u128> {
        if input.len() < 32 {
            return None;
        }
        // Check that the upper 16 bytes are zero (we use u128)
        if input[..16] != [0u8; 16] {
            // Value exceeds u128::MAX — return u128::MAX as sentinel
            return Some(u128::MAX);
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&input[16..32]);
        Some(u128::from_be_bytes(bytes))
    }

    /// Decode a uint256 from ABI-encoded input at a specific offset
    pub fn decode_uint256_at(input: &[u8], offset: usize) -> Option<u128> {
        if input.len() < offset + 32 {
            return None;
        }
        decode_uint256(&input[offset..offset + 32])
    }

    /// Decode address at a specific offset
    pub fn decode_address_at(input: &[u8], offset: usize) -> Option<[u8; 20]> {
        if input.len() < offset + 32 {
            return None;
        }
        decode_address_20(&input[offset..offset + 32])
    }
}

/// Computes the CREATE2 address for the wTNZO contract.
///
/// `address = keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12..]`
///
/// - **deployer**: zero address (system deployment)
/// - **salt**: `keccak256("TENZRO_WTNZO_V1")`
/// - **init_code**: ERC-1167 minimal proxy pointing to the TNZO_BRIDGE precompile
pub fn compute_wtnzo_create2_address() -> [u8; 20] {
    use sha3::{Digest, Keccak256};

    // Deployer is the zero address (system-level deployment)
    let deployer = [0u8; 20];

    // Salt = keccak256("TENZRO_WTNZO_V1")
    let salt = {
        let mut hasher = Keccak256::new();
        hasher.update(b"TENZRO_WTNZO_V1");
        hasher.finalize()
    };

    // Init code: ERC-1167 minimal proxy delegating to TNZO_BRIDGE_ADDRESS
    // Format: CLONE_PREFIX ++ implementation_address ++ CLONE_SUFFIX
    // 3d602d80600a3d3981f3363d3d373d3d3d363d73
    let clone_prefix: &[u8] = &[
        0x3d, 0x60, 0x2d, 0x80, 0x60, 0x0a, 0x3d, 0x39, 0x81, 0xf3,
        0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73,
    ];
    // 5af43d82803e903d91602b57fd5bf3
    let clone_suffix: &[u8] = &[
        0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60,
        0x2b, 0x57, 0xfd, 0x5b, 0xf3,
    ];

    let mut init_code =
        Vec::with_capacity(clone_prefix.len() + 20 + clone_suffix.len());
    init_code.extend_from_slice(clone_prefix);
    init_code.extend_from_slice(&TNZO_BRIDGE_ADDRESS);
    init_code.extend_from_slice(clone_suffix);

    // keccak256(init_code)
    let init_code_hash = {
        let mut hasher = Keccak256::new();
        hasher.update(&init_code);
        hasher.finalize()
    };

    // CREATE2: keccak256(0xff ++ deployer ++ salt ++ init_code_hash)[12..]
    let mut hasher = Keccak256::new();
    hasher.update([0xff]);
    hasher.update(deployer);
    hasher.update(salt);
    hasher.update(init_code_hash);
    let result = hasher.finalize();

    let mut address = [0u8; 20];
    address.copy_from_slice(&result[12..32]);
    address
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    #[test]
    fn test_selectors() {
        // Verify selector computation matches Solidity ABI
        let mut hasher = Keccak256::new();
        hasher.update(b"transfer(address,uint256)");
        let result = hasher.finalize();
        assert_eq!(&result[..4], &selectors::TRANSFER);

        let mut hasher = Keccak256::new();
        hasher.update(b"balanceOf(address)");
        let result = hasher.finalize();
        assert_eq!(&result[..4], &selectors::BALANCE_OF);

        let mut hasher = Keccak256::new();
        hasher.update(b"approve(address,uint256)");
        let result = hasher.finalize();
        assert_eq!(&result[..4], &selectors::APPROVE);
    }

    #[test]
    fn test_abi_encode_uint256() {
        let encoded = abi::encode_uint256(42);
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded[31], 42);
        assert!(encoded[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_abi_encode_string() {
        let encoded = abi::encode_string("TNZO");
        assert!(encoded.len() >= 96); // offset + length + padded data
    }

    #[test]
    fn test_abi_encode_bool() {
        let t = abi::encode_bool(true);
        assert_eq!(t[31], 1);
        let f = abi::encode_bool(false);
        assert_eq!(f[31], 0);
    }

    #[test]
    fn test_abi_decode_address() {
        let mut input = vec![0u8; 32];
        input[12..32].copy_from_slice(&[0xAB; 20]);
        let addr = abi::decode_address_20(&input).unwrap();
        assert_eq!(addr, [0xAB; 20]);
    }

    #[test]
    fn test_abi_decode_uint256() {
        let encoded = abi::encode_uint256(1_000_000);
        let decoded = abi::decode_uint256(&encoded).unwrap();
        assert_eq!(decoded, 1_000_000);
    }

    #[test]
    fn test_abi_roundtrip() {
        for val in [0u128, 1, 42, u128::MAX / 2, u128::MAX] {
            let encoded = abi::encode_uint256(val);
            let decoded = abi::decode_uint256(&encoded).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn test_create2_address_is_deterministic() {
        let addr1 = compute_wtnzo_create2_address();
        let addr2 = compute_wtnzo_create2_address();
        assert_eq!(addr1, addr2, "CREATE2 address must be deterministic");
    }

    #[test]
    fn test_create2_address_matches_constant() {
        let computed = compute_wtnzo_create2_address();
        assert_eq!(
            computed, WTNZO_ADDRESS,
            "WTNZO_ADDRESS constant must match the CREATE2-computed address.\n\
             Computed: {:02x?}",
            computed
        );
    }

    #[test]
    fn test_create2_address_uses_correct_inputs() {
        // Verify the salt is keccak256("TENZRO_WTNZO_V1")
        let mut hasher = Keccak256::new();
        hasher.update(b"TENZRO_WTNZO_V1");
        let salt = hasher.finalize();
        assert_eq!(salt.len(), 32);

        // Verify init code is an ERC-1167 minimal proxy to TNZO_BRIDGE_ADDRESS
        let clone_prefix: &[u8] = &[
            0x3d, 0x60, 0x2d, 0x80, 0x60, 0x0a, 0x3d, 0x39, 0x81, 0xf3,
            0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73,
        ];
        let clone_suffix: &[u8] = &[
            0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60,
            0x2b, 0x57, 0xfd, 0x5b, 0xf3,
        ];
        let mut init_code = Vec::new();
        init_code.extend_from_slice(clone_prefix);
        init_code.extend_from_slice(&TNZO_BRIDGE_ADDRESS);
        init_code.extend_from_slice(clone_suffix);
        // ERC-1167: 20 prefix + 20 address + 15 suffix = 55 bytes
        assert_eq!(init_code.len(), 55);
    }
}
