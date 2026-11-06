// SPDX-License-Identifier: Apache-2.0
//! An agent's account on every chain, derived from its DID.
//!
//! Each chain family places the account where its own deterministic
//! deployment puts it, from the DID's salt
//! `sha256("tenzro/omni-account/v1" || did)` and the family's deployment of
//! the agent account code on that chain ([`AccountDeployment`], governed
//! configuration). On EVM chains the deployment is identical everywhere, so an
//! agent has one address on all of them. Addresses are computed, never stored.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::{Keccak256, Sha3_256};

/// Domain of the per-DID salt.
pub const SALT_DOMAIN: &[u8] = b"tenzro/omni-account/v1";

/// A chain family, by its CAIP-2 namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Eip155,
    Solana,
    Sui,
    Aptos,
    Stellar,
    Cosmos,
    Tvm,
}

impl Family {
    /// The family of a CAIP-2 id (`namespace:reference`).
    pub fn of(caip2: &str) -> Option<Self> {
        let (ns, reference) = caip2.split_once(':')?;
        if reference.is_empty() {
            return None;
        }
        Some(match ns {
            "eip155" => Self::Eip155,
            "solana" => Self::Solana,
            "sui" => Self::Sui,
            "aptos" => Self::Aptos,
            "stellar" => Self::Stellar,
            "cosmos" => Self::Cosmos,
            "tvm" => Self::Tvm,
            _ => return None,
        })
    }
}

/// Where the agent account code is deployed on one chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum AccountDeployment {
    /// The account factory and the init code hash of the account proxy it
    /// deploys with CREATE2.
    Eip155 {
        factory: [u8; 20],
        init_code_hash: [u8; 32],
    },
    /// The agent account program (immutable).
    Solana { program_id: [u8; 32] },
    /// The registry object accounts are derived objects of.
    Sui { registry: [u8; 32] },
    /// The address that creates the accounts as named objects.
    Aptos { creator: [u8; 32] },
    /// The network passphrase and the factory contract that deploys accounts.
    Stellar {
        network_passphrase: String,
        factory: [u8; 32],
    },
    /// The bech32 prefix, the factory that instantiates accounts with
    /// instantiate2, and the checksum of the account code.
    Cosmos {
        hrp: String,
        factory: Vec<u8>,
        code_checksum: [u8; 32],
    },
    /// The workchain and the representation hash and depth of the account
    /// code cell.
    Tvm {
        workchain: i8,
        code_hash: [u8; 32],
        code_depth: u16,
    },
}

impl AccountDeployment {
    pub fn family(&self) -> Family {
        match self {
            Self::Eip155 { .. } => Family::Eip155,
            Self::Solana { .. } => Family::Solana,
            Self::Sui { .. } => Family::Sui,
            Self::Aptos { .. } => Family::Aptos,
            Self::Stellar { .. } => Family::Stellar,
            Self::Cosmos { .. } => Family::Cosmos,
            Self::Tvm { .. } => Family::Tvm,
        }
    }
}

/// One chain agents may hold accounts on, as governance configures it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAccountChain {
    /// The chain, CAIP-2.
    pub caip2: String,
    /// Where the account code is deployed there.
    pub deployment: AccountDeployment,
    /// Whether grants may be issued for the chain. A chain whose deployment
    /// is still a placeholder stays closed.
    pub open: bool,
    /// The bridge route whose deliveries prove the accounts' reports back
    /// (unspent budget, actions, relayed voids). Without one, a grant's whole
    /// budget counts as spent and no paid relay is opened.
    #[serde(default)]
    pub report_route: Option<ReportRoute>,
}

/// A bridge route, by its transport and the chain's name on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportRoute {
    pub adapter: crate::bridge_route::BridgeRouteAdapter,
    pub source_chain: String,
}

impl AgentAccountChain {
    /// Storage key of the chain's record.
    pub fn storage_key(caip2: &str) -> String {
        format!("agent_account_chain:{caip2}")
    }

    /// The record's rules: a supported chain whose deployment is of its
    /// family.
    pub fn validate(&self) -> Result<(), OmniError> {
        let family =
            Family::of(&self.caip2).ok_or_else(|| OmniError::UnknownChain(self.caip2.clone()))?;
        if family != self.deployment.family() {
            return Err(OmniError::WrongFamily(self.deployment.family(), family));
        }
        if let AccountDeployment::Cosmos { hrp, .. } = &self.deployment
            && bech32::Hrp::parse(hrp).is_err()
        {
            return Err(OmniError::Malformed("bech32 prefix"));
        }
        Ok(())
    }
}

/// An agent's account on one chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmniAddress {
    /// The chain, CAIP-2.
    pub caip2: String,
    /// The address as the chain writes it.
    pub address: String,
    /// The address's bytes.
    #[serde(with = "crate::remote_grant::hex_bytes")]
    pub raw: Vec<u8>,
}

impl OmniAddress {
    /// CAIP-10: `namespace:reference:address`.
    pub fn caip10(&self) -> String {
        format!("{}:{}", self.caip2, self.address)
    }

    /// The 32-byte form a grant's `account` field holds: the address
    /// left-padded, or the SHA-256 of a longer one.
    pub fn account_word(&self) -> [u8; 32] {
        if self.raw.len() > 32 {
            return Sha256::digest(&self.raw).into();
        }
        let mut out = [0u8; 32];
        let n = self.raw.len().min(32);
        out[32 - n..].copy_from_slice(&self.raw[self.raw.len() - n..]);
        out
    }

    /// An EVM or Solana account from its CAIP-10 id.
    pub fn from_caip10(caip10: &str) -> Option<Self> {
        let (caip2, address) = caip10.rsplit_once(':')?;
        let raw = match caip2.split_once(':')?.0 {
            "eip155" => hex::decode(address.trim_start_matches("0x"))
                .ok()
                .filter(|b| b.len() == 20)?,
            "solana" => bs58::decode(address)
                .into_vec()
                .ok()
                .filter(|b| b.len() == 32)?,
            _ => return None,
        };
        Some(Self {
            caip2: caip2.to_string(),
            address: address.to_string(),
            raw,
        })
    }

    /// The ERC-7930 interoperable address, for the families with a binary
    /// chain profile (EVM and Solana).
    pub fn erc7930(&self) -> Option<Vec<u8>> {
        let (ns, reference) = self.caip2.split_once(':')?;
        let (chain_type, chain_ref): ([u8; 2], Vec<u8>) = match ns {
            "eip155" => {
                let id: u64 = reference.parse().ok()?;
                let b = id.to_be_bytes();
                let first = b.iter().position(|x| *x != 0).unwrap_or(7);
                ([0x00, 0x00], b[first..].to_vec())
            }
            "solana" => ([0x00, 0x02], bs58::decode(reference).into_vec().ok()?),
            _ => return None,
        };
        let mut out = vec![0x00, 0x01];
        out.extend_from_slice(&chain_type);
        out.push(u8::try_from(chain_ref.len()).ok()?);
        out.extend_from_slice(&chain_ref);
        out.push(u8::try_from(self.raw.len()).ok()?);
        out.extend_from_slice(&self.raw);
        Some(out)
    }
}

/// Why no address was derived.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OmniError {
    #[error("{0} is not a CAIP-2 id of a supported chain family")]
    UnknownChain(String),
    #[error("the deployment is for {0:?}, the chain is {1:?}")]
    WrongFamily(Family, Family),
    #[error("the deployment is malformed: {0}")]
    Malformed(&'static str),
}

/// The per-DID salt.
pub fn salt(did: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SALT_DOMAIN);
    h.update(did.as_bytes());
    h.finalize().into()
}

/// The account of `did` on `caip2` under `deployment`.
pub fn omni_address(
    did: &str,
    caip2: &str,
    deployment: &AccountDeployment,
) -> Result<OmniAddress, OmniError> {
    let family = Family::of(caip2).ok_or_else(|| OmniError::UnknownChain(caip2.to_string()))?;
    if family != deployment.family() {
        return Err(OmniError::WrongFamily(deployment.family(), family));
    }
    let s = salt(did);
    let (address, raw) = match deployment {
        AccountDeployment::Eip155 {
            factory,
            init_code_hash,
        } => {
            let mut h = Keccak256::new();
            h.update([0xff]);
            h.update(factory);
            h.update(s);
            h.update(init_code_hash);
            let raw = h.finalize()[12..].to_vec();
            (eip55(&raw), raw)
        }
        AccountDeployment::Solana { program_id } => {
            let seed = Sha256::digest(did.as_bytes());
            let raw = solana_pda(&[b"agent", &seed], program_id)
                .ok_or(OmniError::Malformed("no program address"))?;
            (bs58::encode(raw).into_string(), raw.to_vec())
        }
        AccountDeployment::Sui { registry } => {
            let raw = sui_derived_address(registry, &s);
            (format!("0x{}", hex::encode(raw)), raw.to_vec())
        }
        AccountDeployment::Aptos { creator } => {
            let mut h = Sha3_256::new();
            h.update(creator);
            h.update(s);
            h.update([0xfe]);
            let raw: [u8; 32] = h.finalize().into();
            (format!("0x{}", hex::encode(raw)), raw.to_vec())
        }
        AccountDeployment::Stellar {
            network_passphrase,
            factory,
        } => {
            let raw = stellar_contract_id(network_passphrase, factory, &s);
            (stellar_strkey(0x10, &raw), raw.to_vec())
        }
        AccountDeployment::Cosmos {
            hrp,
            factory,
            code_checksum,
        } => {
            let raw = instantiate2(code_checksum, factory, &s);
            let hrp = bech32::Hrp::parse(hrp).map_err(|_| OmniError::Malformed("bech32 prefix"))?;
            let text = bech32::encode::<bech32::Bech32>(hrp, &raw)
                .map_err(|_| OmniError::Malformed("bech32"))?;
            (text, raw.to_vec())
        }
        AccountDeployment::Tvm {
            workchain,
            code_hash,
            code_depth,
        } => {
            let raw = ton_state_init_hash(
                code_hash,
                *code_depth,
                &crate::remote_grant::agent_hash(did),
                &crate::remote_grant::state_tree_key(did, caip2),
            );
            (format!("{workchain}:{}", hex::encode(raw)), raw.to_vec())
        }
    };
    Ok(OmniAddress {
        caip2: caip2.to_string(),
        address,
        raw,
    })
}

/// The EIP-55 mixed-case form of a 20-byte address.
pub fn eip55(raw: &[u8]) -> String {
    let lower = hex::encode(raw);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

/// A Solana program address: the first bump from 255 down whose hash is off
/// the Ed25519 curve.
fn solana_pda(seeds: &[&[u8]], program_id: &[u8; 32]) -> Option<[u8; 32]> {
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program_id);
        h.update(b"ProgramDerivedAddress");
        let candidate: [u8; 32] = h.finalize().into();
        if curve25519_dalek::edwards::CompressedEdwardsY(candidate)
            .decompress()
            .is_none()
        {
            return Some(candidate);
        }
    }
    None
}

/// A Sui derived object's address: the dynamic field id of the key
/// `0x2::derived_object::DerivedObjectKey<vector<u8>>(key)` under `parent`.
fn sui_derived_address(parent: &[u8; 32], key: &[u8; 32]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest as _};
    // BCS of the key: a vector<u8> of 32 bytes.
    let mut key_bcs = vec![32u8];
    key_bcs.extend_from_slice(key);
    // BCS of its type tag.
    let mut tag = vec![7u8];
    let mut framework = [0u8; 32];
    framework[31] = 2;
    tag.extend_from_slice(&framework);
    for ident in ["derived_object", "DerivedObjectKey"] {
        tag.push(ident.len() as u8);
        tag.extend_from_slice(ident.as_bytes());
    }
    tag.extend_from_slice(&[1, 6, 1]);
    let mut h = Blake2b::<U32>::new();
    h.update([0xf0]);
    h.update(parent);
    h.update((key_bcs.len() as u64).to_le_bytes());
    h.update(&key_bcs);
    h.update(&tag);
    h.finalize().into()
}

/// A Soroban contract id deployed by `deployer` with `salt`: SHA-256 of the
/// XDR `HashIdPreimage::ContractId` from that address.
fn stellar_contract_id(network_passphrase: &str, deployer: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let network_id = Sha256::digest(network_passphrase.as_bytes());
    let mut h = Sha256::new();
    h.update(8i32.to_be_bytes()); // ENVELOPE_TYPE_CONTRACT_ID
    h.update(network_id);
    h.update(0i32.to_be_bytes()); // CONTRACT_ID_PREIMAGE_FROM_ADDRESS
    h.update(1i32.to_be_bytes()); // SC_ADDRESS_TYPE_CONTRACT
    h.update(deployer);
    h.update(salt);
    h.finalize().into()
}

/// A Stellar StrKey: base32 of the version byte, the payload and its
/// CRC16-XModem (little-endian).
pub fn stellar_strkey(version: u8, payload: &[u8; 32]) -> String {
    let mut b = vec![version];
    b.extend_from_slice(payload);
    let mut crc: u16 = 0;
    for byte in &b {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    b.extend_from_slice(&crc.to_le_bytes());
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in b {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// CosmWasm's instantiate2 address for code `checksum`, instantiated by
/// `creator` with `salt` and no message binding.
fn instantiate2(checksum: &[u8; 32], creator: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut key = b"wasm\0".to_vec();
    for part in [checksum.as_slice(), creator, salt.as_slice(), &[]] {
        key.extend_from_slice(&(part.len() as u64).to_be_bytes());
        key.extend_from_slice(part);
    }
    let typ = Sha256::digest(b"module");
    let mut h = Sha256::new();
    h.update(typ);
    h.update(key);
    h.finalize().into()
}

/// The representation hash of a TON `StateInit` with the account code and
/// the data cell `agent || tree_key` (512 bits, no refs).
fn ton_state_init_hash(
    code_hash: &[u8; 32],
    code_depth: u16,
    agent: &[u8; 32],
    tree_key: &[u8; 32],
) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update([0u8, 128]);
    d.update(agent);
    d.update(tree_key);
    let data_hash: [u8; 32] = d.finalize().into();
    // StateInit: no split depth, not special, code and data present, no
    // library: bits 0 0 1 1 0, padded with a 1 and zeros.
    let mut h = Sha256::new();
    h.update([2u8, 1, 0b0011_0100]);
    h.update(code_depth.to_be_bytes());
    h.update(0u16.to_be_bytes());
    h.update(code_hash);
    h.update(data_hash);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:tenzro:agent:example";

    fn evm() -> AccountDeployment {
        AccountDeployment::Eip155 {
            factory: [0x42; 20],
            init_code_hash: [0x24; 32],
        }
    }

    #[test]
    fn an_agent_has_one_address_on_every_evm_chain() {
        let a = omni_address(DID, "eip155:1", &evm()).unwrap();
        for chain in ["eip155:8453", "eip155:42161"] {
            assert_eq!(omni_address(DID, chain, &evm()).unwrap().address, a.address);
        }
        assert_ne!(
            omni_address("did:tenzro:agent:other", "eip155:1", &evm())
                .unwrap()
                .address,
            a.address
        );
        assert_eq!(a.caip10(), format!("eip155:1:{}", a.address));
        let erc = a.erc7930().unwrap();
        assert_eq!(&erc[..6], &[0x00, 0x01, 0x00, 0x00, 0x01, 0x01]);
        assert_eq!(erc[6], 20);
        assert_eq!(&erc[7..], a.raw.as_slice());
    }

    #[test]
    fn a_caip10_id_renders_as_erc7930() {
        let a = OmniAddress::from_caip10("eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
            .unwrap();
        assert_eq!(
            hex::encode(a.erc7930().unwrap()),
            "00010000010114d8da6bf26964af9d7eed9e03e53415d37aa96045"
        );
        assert!(OmniAddress::from_caip10("bip122:000000000019d6689c085ae165831e93:1abc").is_none());
    }

    #[test]
    fn eip55_matches_the_reference_vectors() {
        for v in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        ] {
            assert_eq!(eip55(&hex::decode(&v[2..]).unwrap()), v);
        }
    }

    #[test]
    fn a_deployment_of_another_family_is_refused() {
        assert_eq!(
            omni_address(DID, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", &evm()),
            Err(OmniError::WrongFamily(Family::Eip155, Family::Solana))
        );
        assert!(matches!(
            omni_address(DID, "bip122:000000000019d6689c085ae165831e93", &evm()),
            Err(OmniError::UnknownChain(_))
        ));
    }

    #[test]
    fn a_solana_account_is_off_the_curve() {
        let dep = AccountDeployment::Solana {
            program_id: [7; 32],
        };
        let a = omni_address(DID, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", &dep).unwrap();
        assert!(
            curve25519_dalek::edwards::CompressedEdwardsY(a.raw.clone().try_into().unwrap())
                .decompress()
                .is_none()
        );
        let erc = a.erc7930().unwrap();
        assert_eq!(&erc[..4], &[0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn stellar_strkeys_follow_the_reference_encoding() {
        // The all-zero account key, a widely published StrKey.
        assert_eq!(
            stellar_strkey(0x30, &[0; 32]),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        );
    }
}
