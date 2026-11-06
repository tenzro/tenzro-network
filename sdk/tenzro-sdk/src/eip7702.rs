//! Standard EIP-7702 set-code transactions (type `0x04`), built for an
//! external secp256k1 signer.
//!
//! The SDK holds no signing key. It produces the two digests a wallet or
//! hardware signer signs (the authorization digest and the transaction
//! digest) and assembles the signed bytes from the signatures it is handed.
//! The raw bytes go to `eth_sendRawTransaction`; the node recovers the sender
//! and every authority from their signatures and installs the delegation
//! designator in the authority's code.
//!
//! ```text
//! authorization digest = keccak256(0x05 || rlp([chain_id, address, nonce]))
//! transaction digest   = keccak256(0x04 || rlp([chain_id, nonce, max_priority_fee_per_gas,
//!                          max_fee_per_gas, gas_limit, to, value, data, access_list,
//!                          authorization_list]))
//! raw transaction      = 0x04 || rlp([...same fields..., y_parity, r, s])
//! ```

use sha3::{Digest, Keccak256};

/// The transaction type byte of a set-code transaction.
pub const SET_CODE_TX_TYPE: u8 = 0x04;
/// The domain byte of an authorization digest.
pub const AUTHORIZATION_MAGIC: u8 = 0x05;

/// A secp256k1 signature as a wallet returns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaSignature {
    /// Recovery bit, 0 or 1.
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// An unsigned authorization: the authority lets `address`'s code run as its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorization {
    /// The chain the authorization is valid on (0 = every chain).
    pub chain_id: u64,
    /// The delegate contract.
    pub address: [u8; 20],
    /// The authority's account nonce at the time the transaction executes.
    pub nonce: u64,
}

impl Authorization {
    /// The digest the authority signs.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut out = vec![AUTHORIZATION_MAGIC];
        out.extend_from_slice(&rlp_list(&[
            rlp_uint(self.chain_id as u128),
            rlp_bytes(&self.address),
            rlp_uint(self.nonce as u128),
        ]));
        Keccak256::digest(&out).into()
    }

    /// Attaches the authority's signature over [`Self::signing_hash`].
    pub fn into_signed(self, signature: EcdsaSignature) -> SignedAuthorization {
        SignedAuthorization {
            authorization: self,
            signature,
        }
    }
}

/// An authorization with its authority's signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedAuthorization {
    pub authorization: Authorization,
    pub signature: EcdsaSignature,
}

impl SignedAuthorization {
    fn rlp(&self) -> Vec<u8> {
        let a = &self.authorization;
        let s = &self.signature;
        rlp_list(&[
            rlp_uint(a.chain_id as u128),
            rlp_bytes(&a.address),
            rlp_uint(a.nonce as u128),
            rlp_uint(s.y_parity as u128),
            rlp_word(&s.r),
            rlp_word(&s.s),
        ])
    }
}

/// One access-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListItem {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// A set-code transaction before the sender signs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCodeTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// A set-code transaction always has a destination.
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
    /// At least one signed authorization.
    pub authorization_list: Vec<SignedAuthorization>,
}

impl SetCodeTransaction {
    fn fields(&self) -> Vec<Vec<u8>> {
        let access: Vec<Vec<u8>> = self
            .access_list
            .iter()
            .map(|i| {
                let keys: Vec<Vec<u8>> = i.storage_keys.iter().map(|k| rlp_bytes(k)).collect();
                rlp_list(&[rlp_bytes(&i.address), rlp_list(&keys)])
            })
            .collect();
        let auths: Vec<Vec<u8>> = self
            .authorization_list
            .iter()
            .map(SignedAuthorization::rlp)
            .collect();
        vec![
            rlp_uint(self.chain_id as u128),
            rlp_uint(self.nonce as u128),
            rlp_uint(self.max_priority_fee_per_gas),
            rlp_uint(self.max_fee_per_gas),
            rlp_uint(self.gas_limit as u128),
            rlp_bytes(&self.to),
            rlp_uint(self.value),
            rlp_bytes(&self.data),
            rlp_list(&access),
            rlp_list(&auths),
        ]
    }

    /// The digest the sender signs. Refuses a transaction with no
    /// authorization, which the network does not admit.
    pub fn signing_hash(&self) -> Result<[u8; 32], &'static str> {
        if self.authorization_list.is_empty() {
            return Err("a set-code transaction needs at least one authorization");
        }
        let mut out = vec![SET_CODE_TX_TYPE];
        out.extend_from_slice(&rlp_list(&self.fields()));
        Ok(Keccak256::digest(&out).into())
    }

    /// The raw signed transaction for `eth_sendRawTransaction`, given the
    /// sender's signature over [`Self::signing_hash`].
    pub fn encode_signed(&self, signature: &EcdsaSignature) -> Result<Vec<u8>, &'static str> {
        self.signing_hash()?;
        let mut fields = self.fields();
        fields.push(rlp_uint(signature.y_parity as u128));
        fields.push(rlp_word(&signature.r));
        fields.push(rlp_word(&signature.s));
        let mut out = vec![SET_CODE_TX_TYPE];
        out.extend_from_slice(&rlp_list(&fields));
        Ok(out)
    }
}

/// The hash a wallet and the node record a raw transaction under.
pub fn transaction_hash(raw: &[u8]) -> [u8; 32] {
    Keccak256::digest(raw).into()
}

/// The code an authority carries once its delegation is installed:
/// `0xef0100 || address`.
pub fn delegation_designator(address: &[u8; 20]) -> [u8; 23] {
    let mut out = [0u8; 23];
    out[..3].copy_from_slice(&[0xef, 0x01, 0x00]);
    out[3..].copy_from_slice(address);
    out
}

fn rlp_length_prefix(len: usize, short: u8, long: u8) -> Vec<u8> {
    if len < 56 {
        vec![short + len as u8]
    } else {
        let be = (len as u64).to_be_bytes();
        let start = be.iter().position(|b| *b != 0).unwrap_or(7);
        let mut out = vec![long + (8 - start) as u8];
        out.extend_from_slice(&be[start..]);
        out
    }
}

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = rlp_length_prefix(b.len(), 0x80, 0xb7);
    out.extend_from_slice(b);
    out
}

fn rlp_uint(v: u128) -> Vec<u8> {
    let be = v.to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(be.len());
    rlp_bytes(&be[start..])
}

/// A signature scalar is an integer: leading zero bytes are dropped.
fn rlp_word(w: &[u8; 32]) -> Vec<u8> {
    let start = w.iter().position(|b| *b != 0).unwrap_or(w.len());
    rlp_bytes(&w[start..])
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = items.concat();
    let mut out = rlp_length_prefix(body.len(), 0xc0, 0xf7);
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../fixtures/eip7702/vectors.json");

    fn h<const N: usize>(v: &Value) -> [u8; N] {
        hex::decode(v.as_str().unwrap().trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn sig(v: &Value) -> EcdsaSignature {
        EcdsaSignature {
            y_parity: v["y_parity"].as_u64().unwrap() as u8,
            r: h(&v["r"]),
            s: h(&v["s"]),
        }
    }

    #[test]
    fn builds_the_wallet_reference_vector_byte_for_byte() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let a = &v["authorization"];
        let auth = Authorization {
            chain_id: a["chain_id"].as_u64().unwrap(),
            address: h(&a["address"]),
            nonce: a["nonce"].as_u64().unwrap(),
        };
        assert_eq!(auth.signing_hash(), h::<32>(&a["signing_hash"]));

        let t = &v["transaction"];
        let item = &t["access_list"][0];
        let tx = SetCodeTransaction {
            chain_id: t["chain_id"].as_u64().unwrap(),
            nonce: t["nonce"].as_u64().unwrap(),
            max_priority_fee_per_gas: t["max_priority_fee_per_gas"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            max_fee_per_gas: t["max_fee_per_gas"].as_str().unwrap().parse().unwrap(),
            gas_limit: t["gas_limit"].as_u64().unwrap(),
            to: h(&t["to"]),
            value: t["value"].as_str().unwrap().parse().unwrap(),
            data: hex::decode(t["data"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
            access_list: vec![AccessListItem {
                address: h(&item["address"]),
                storage_keys: vec![h(&item["storage_keys"][0])],
            }],
            authorization_list: vec![auth.into_signed(sig(a))],
        };
        assert_eq!(tx.signing_hash().unwrap(), h::<32>(&t["signing_hash"]));
        let raw = tx.encode_signed(&sig(t)).unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(&raw)),
            t["raw"].as_str().unwrap()
        );
        assert_eq!(transaction_hash(&raw), h::<32>(&t["hash"]));
    }

    #[test]
    fn a_transaction_without_authorizations_is_refused() {
        let tx = SetCodeTransaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 21_000,
            to: [0; 20],
            value: 0,
            data: vec![],
            access_list: vec![],
            authorization_list: vec![],
        };
        assert!(tx.signing_hash().is_err());
        assert!(
            tx.encode_signed(&EcdsaSignature {
                y_parity: 0,
                r: [1; 32],
                s: [1; 32]
            })
            .is_err()
        );
    }

    #[test]
    fn the_designator_is_the_magic_and_the_address() {
        let d = delegation_designator(&[0x7a; 20]);
        assert_eq!(&d[..3], &[0xef, 0x01, 0x00]);
        assert_eq!(&d[3..], &[0x7a; 20]);
    }
}
