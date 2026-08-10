//! ERC-7683 gasless cross-chain order verification (Permit2 witness).
//!
//! Per the ratified ERC-7683 standard (<https://www.erc7683.org/spec>), a
//! `GaslessCrossChainOrder` is **not** signed as a bare EIP-712 struct — it is
//! signed via Uniswap **Permit2** `permitWitnessTransferFrom`, with the order
//! as the EIP-712 *witness*. The user's single signature therefore authorizes
//! both the input-token transfer and the order itself. Implementing a plain
//! EIP-712-over-the-struct check would reject every signature a real ERC-7683
//! wallet (Across / UniswapX / Eco) produces — so this module reproduces the
//! exact Permit2 witness digest.
//!
//! ## Digest construction (Permit2 `SignatureTransfer`)
//!
//! ```text
//! domainSeparator = keccak256(abi.encode(
//!     keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
//!     keccak256("Permit2"), chainId, PERMIT2_ADDRESS))          // Permit2 domain has NO version
//!
//! tokenPermissions = keccak256(abi.encode(
//!     keccak256("TokenPermissions(address token,uint256 amount)"), token, amount))
//!
//! witness = keccak256(abi.encode(GASLESS_ORDER_TYPEHASH,
//!     originSettler, user, nonce, originChainId, openDeadline, fillDeadline,
//!     orderDataType, keccak256(orderData)))
//!
//! structHash = keccak256(abi.encode(PERMIT_WITNESS_TYPEHASH,
//!     tokenPermissions, spender, permit2Nonce, deadline, witness))
//!
//! digest = keccak256(0x1901 || domainSeparator || structHash)
//! ```
//!
//! The `PermitWitnessTransferFrom` type string appends referenced structs in
//! EIP-712 **alphabetical** order (`GaslessCrossChainOrder` before
//! `TokenPermissions`).
//!
//! ## Verification status
//!
//! The encoding follows the spec exactly. It is verified here by a
//! self-consistent sign→recover round-trip. It has **not** been cross-checked
//! against a reference signature produced by a live Permit2/ERC-7683 wallet —
//! doing so requires such a vector (or a deployed Permit2 to sign against). The
//! `orderData` field is hashed as opaque `bytes` (`keccak256(orderData)`); a
//! settler whose witness type inlines a *parsed* order-data struct must extend
//! the type string accordingly.

use sha3::{Digest, Keccak256};

/// Canonical Uniswap Permit2 deployment address (identical on every chain).
pub const PERMIT2_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xD4, 0x73, 0x03, 0x0F, 0x11, 0x6d, 0xDE, 0xE9, 0xF6, 0xB4,
    0x3a, 0xC7, 0x8B, 0xA3,
];

/// `keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)")`.
const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,uint256 chainId,address verifyingContract)";

/// `keccak256("TokenPermissions(address token,uint256 amount)")`.
const TOKEN_PERMISSIONS_TYPE: &str = "TokenPermissions(address token,uint256 amount)";

/// The ERC-7683 gasless-order witness struct type.
const GASLESS_ORDER_TYPE: &str = "GaslessCrossChainOrder(address originSettler,address user,uint256 nonce,uint256 originChainId,uint32 openDeadline,uint32 fillDeadline,bytes32 orderDataType,bytes orderData)";

/// The full Permit2 `PermitWitnessTransferFrom` type string for this witness.
/// Referenced structs are appended alphabetically: `GaslessCrossChainOrder`
/// then `TokenPermissions`.
const PERMIT_WITNESS_TYPE: &str = "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,GaslessCrossChainOrder witness)GaslessCrossChainOrder(address originSettler,address user,uint256 nonce,uint256 originChainId,uint32 openDeadline,uint32 fillDeadline,bytes32 orderDataType,bytes orderData)TokenPermissions(address token,uint256 amount)";

/// An ERC-7683 `GaslessCrossChainOrder` (standard field shape). `uint256`
/// fields are big-endian 32-byte values; addresses are 20 bytes.
#[derive(Debug, Clone)]
pub struct GaslessOrder {
    pub origin_settler: [u8; 20],
    pub user: [u8; 20],
    pub nonce: [u8; 32],
    pub origin_chain_id: [u8; 32],
    pub open_deadline: u32,
    pub fill_deadline: u32,
    pub order_data_type: [u8; 32],
    pub order_data: Vec<u8>,
}

/// The Permit2 envelope the order rides on (`permitWitnessTransferFrom`).
#[derive(Debug, Clone)]
pub struct Permit2Witness {
    pub token: [u8; 20],
    pub amount: [u8; 32],
    pub spender: [u8; 20],
    pub permit2_nonce: [u8; 32],
    pub deadline: [u8; 32],
    /// EIP-712 domain chain id (the chain Permit2 is deployed on).
    pub chain_id: u64,
}

/// Verification errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Erc7683Error {
    /// `v`/recovery id was invalid, or the point did not recover.
    Recovery,
    /// Recovered signer address did not equal `order.user`.
    WrongSigner,
}

fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Left-pad a 20-byte address into a 32-byte EIP-712 word.
fn word_addr(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// A `uint32` as a 32-byte big-endian EIP-712 word.
fn word_u32(v: u32) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[28..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_u256(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Compute the Permit2 witness EIP-712 digest the user signs for this order.
pub fn eip712_digest(order: &GaslessOrder, w: &Permit2Witness) -> [u8; 32] {
    // domainSeparator
    let mut dom = Vec::with_capacity(32 * 4);
    dom.extend_from_slice(&keccak(EIP712_DOMAIN_TYPE.as_bytes()));
    dom.extend_from_slice(&keccak(b"Permit2"));
    dom.extend_from_slice(&word_u256(w.chain_id));
    dom.extend_from_slice(&word_addr(&PERMIT2_ADDRESS));
    let domain_separator = keccak(&dom);

    // TokenPermissions hash
    let mut tp = Vec::with_capacity(32 * 3);
    tp.extend_from_slice(&keccak(TOKEN_PERMISSIONS_TYPE.as_bytes()));
    tp.extend_from_slice(&word_addr(&w.token));
    tp.extend_from_slice(&w.amount);
    let token_permissions = keccak(&tp);

    // witness (order) hash
    let mut wit = Vec::with_capacity(32 * 9);
    wit.extend_from_slice(&keccak(GASLESS_ORDER_TYPE.as_bytes()));
    wit.extend_from_slice(&word_addr(&order.origin_settler));
    wit.extend_from_slice(&word_addr(&order.user));
    wit.extend_from_slice(&order.nonce);
    wit.extend_from_slice(&order.origin_chain_id);
    wit.extend_from_slice(&word_u32(order.open_deadline));
    wit.extend_from_slice(&word_u32(order.fill_deadline));
    wit.extend_from_slice(&order.order_data_type);
    wit.extend_from_slice(&keccak(&order.order_data));
    let witness = keccak(&wit);

    // PermitWitnessTransferFrom struct hash
    let mut sh = Vec::with_capacity(32 * 6);
    sh.extend_from_slice(&keccak(PERMIT_WITNESS_TYPE.as_bytes()));
    sh.extend_from_slice(&token_permissions);
    sh.extend_from_slice(&word_addr(&w.spender));
    sh.extend_from_slice(&w.permit2_nonce);
    sh.extend_from_slice(&w.deadline);
    sh.extend_from_slice(&witness);
    let struct_hash = keccak(&sh);

    // EIP-712 digest: 0x1901 || domainSeparator || structHash
    let mut pre = Vec::with_capacity(2 + 64);
    pre.extend_from_slice(&[0x19, 0x01]);
    pre.extend_from_slice(&domain_separator);
    pre.extend_from_slice(&struct_hash);
    keccak(&pre)
}

/// Recover the Ethereum address that produced `signature` over this order's
/// Permit2 witness digest.
pub fn recover_signer(
    order: &GaslessOrder,
    w: &Permit2Witness,
    signature: &[u8; 65],
) -> Result<[u8; 20], Erc7683Error> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let v = signature[64];
    let y_parity = if v >= 27 { v - 27 } else { v };
    let recovery_id = RecoveryId::try_from(y_parity).map_err(|_| Erc7683Error::Recovery)?;
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature[..64]);
    let sig = Signature::from_bytes(&sig_bytes.into()).map_err(|_| Erc7683Error::Recovery)?;

    let digest = eip712_digest(order, w);
    let vk = VerifyingKey::recover_from_prehash(&digest, &sig, recovery_id)
        .map_err(|_| Erc7683Error::Recovery)?;
    let encoded = vk.to_sec1_point(false);
    let addr_hash = keccak(&encoded.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&addr_hash[12..32]);
    Ok(addr)
}

/// Verify an ERC-7683 gasless order: the Permit2-witness signature must recover
/// to `order.user`. Returns the recovered address on success.
pub fn verify_gasless_order(
    order: &GaslessOrder,
    w: &Permit2Witness,
    signature: &[u8; 65],
) -> Result<[u8; 20], Erc7683Error> {
    let recovered = recover_signer(order, w, signature)?;
    if recovered == order.user {
        Ok(recovered)
    } else {
        Err(Erc7683Error::WrongSigner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{SigningKey, VerifyingKey};
    use sha3::{Digest, Keccak256};

    fn evm_address(sk: &SigningKey) -> [u8; 20] {
        let vk = VerifyingKey::from(sk);
        let enc = vk.to_sec1_point(false);
        let h = Keccak256::digest(&enc.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..32]);
        a
    }

    #[test]
    fn permit2_witness_round_trip_recovers_user() {
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let user = evm_address(&sk);

        let order = GaslessOrder {
            origin_settler: [0x11; 20],
            user,
            nonce: {
                let mut n = [0u8; 32];
                n[31] = 7;
                n
            },
            origin_chain_id: {
                let mut c = [0u8; 32];
                c[30] = 0x0a; // chain 2560 — arbitrary
                c
            },
            open_deadline: 1_900_000_000,
            fill_deadline: 1_900_000_500,
            order_data_type: [0xAB; 32],
            order_data: b"opaque-order-data".to_vec(),
        };
        let w = Permit2Witness {
            token: [0x22; 20],
            amount: {
                let mut a = [0u8; 32];
                a[28..].copy_from_slice(&1_000_000u32.to_be_bytes());
                a
            },
            spender: [0x33; 20],
            permit2_nonce: [0x01; 32],
            deadline: {
                let mut d = [0u8; 32];
                d[28..].copy_from_slice(&1_900_000_000u32.to_be_bytes());
                d
            },
            chain_id: 8453,
        };

        // Sign the witness digest exactly as a Permit2 wallet would.
        let digest = eip712_digest(&order, &w);
        let (sig, rid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut sig65 = sig.to_bytes().to_vec();
        sig65.push(rid.to_byte());
        let sig65: [u8; 65] = sig65.try_into().unwrap();

        assert_eq!(verify_gasless_order(&order, &w, &sig65), Ok(user));

        // Tampering the order (different fill_deadline) breaks recovery→user.
        let mut bad = order.clone();
        bad.fill_deadline += 1;
        assert_eq!(
            verify_gasless_order(&bad, &w, &sig65),
            Err(Erc7683Error::WrongSigner)
        );

        // A wrong-length signature is rejected cleanly.
        // (recover_signer takes a fixed [u8;65], so length is enforced by the type.)
    }

    #[test]
    fn typehash_strings_are_alphabetically_ordered() {
        // EIP-712 requires referenced structs appended in alphabetical order:
        // GaslessCrossChainOrder (G) must precede TokenPermissions (T).
        let g = PERMIT_WITNESS_TYPE.find("GaslessCrossChainOrder(").unwrap();
        let t = PERMIT_WITNESS_TYPE.find("TokenPermissions(").unwrap();
        assert!(g < t, "referenced structs must be alphabetical");
    }
}
