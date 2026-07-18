//! BitVM2 two-way-peg adapter (Citrea Clementine).
//!
//! Clementine is the BitVM2-based trust-minimised Bitcoin bridge that
//! Citrea uses to peg native BTC into a non-Bitcoin chain and back. The
//! mechanism is fundamentally optimistic: an operator advances a peg-out
//! by claiming on the destination chain, anyone can challenge with a fraud
//! proof, and BitVM2 forces the operator to either reveal a valid SNARK
//! through Bitcoin-script-level execution or be slashed via a pre-signed
//! disconnect transaction. The Tenzro side mirrors that state machine so
//! `tenzro-node` can observe peg-in/peg-out lifecycles, expose them to
//! relayers, and gate downstream balance mutations on the optimistic
//! settlement window.
//!
//! Source-of-truth for the design is Citrea's Clementine whitepaper
//! (eprint.iacr.org/2025/776) and the public "Tangerine upgrade" notes
//! activating BitVM2 on Clementine. Clementine v2 (Garbled Circuits + TOOP)
//! is in research. This adapter exposes the v1 + BitVM2 surface and
//! parameterises the verifier so a future v2 swap is a config change.

use std::collections::HashMap;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{BridgeError, Result};
use tenzro_types::primitives::Hash;

/// Citrea-shaped network ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitVm2Network {
    /// Bitcoin mainnet + Citrea mainnet (Jan 2026 launch).
    Mainnet,
    /// Bitcoin testnet4 + Citrea testnet.
    Testnet,
    /// Local regtest.
    Regtest,
}

/// Adapter configuration.
#[derive(Debug, Clone)]
pub struct BitVm2Config {
    /// Network selector.
    pub network: BitVm2Network,
    /// Citrea sequencer RPC the adapter polls for state.
    pub sequencer_rpc: String,
    /// Bitcoin Core / Esplora RPC used for UTXO + tx queries.
    pub bitcoin_rpc: String,
    /// The 32-byte commitment to the operator set under Clementine's
    /// pre-signed disconnect protocol. Updates require a Citrea governance
    /// proposal.
    pub operator_set_commitment: [u8; 32],
    /// Optimistic settlement window in Bitcoin blocks. Clementine's
    /// published value is `7 * 144` ≈ one week.
    pub settlement_window_blocks: u32,
    /// Choice of verifier: BitVM2 (mainnet, today) or Garbled-Circuit
    /// (Clementine v2, R&D).
    pub verifier: ClementineVerifierKind,
}

/// Verifier kind. The state machine is identical; only the script-side
/// challenge differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ClementineVerifierKind {
    /// BitVM2 — production.
    #[default]
    BitVm2,
    /// Garbled-Circuit + TOOP — Clementine v2 R&D.
    GarbledCircuitToop,
}

/// Peg-in request: user locked BTC into Clementine's federation address
/// and is claiming the equivalent mint on the destination chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegIn {
    /// Stable id (`SHA-256("tenzro/bitvm2/pegin" || btc_txid)`).
    pub id: Hash,
    /// Bitcoin txid (LE bytes, as stored in Bitcoin's reference impl).
    pub btc_txid: [u8; 32],
    /// Output index of the lock UTXO.
    pub btc_vout: u32,
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// Destination address on the receiving chain.
    pub recipient: String,
    /// Status.
    pub status: PegInStatus,
}

/// Lifecycle states for peg-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PegInStatus {
    /// Lock UTXO observed but not yet confirmed.
    Pending,
    /// Lock UTXO confirmed past Clementine's safety threshold.
    Confirmed,
    /// Mint on destination chain executed.
    Minted,
    /// Mint refused (lock invalid, operator-set rotation, etc.).
    Rejected,
}

/// Peg-out request: user burnt the wrapped asset on the destination chain
/// and is claiming Bitcoin back from one of Clementine's operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOut {
    /// Stable id (`SHA-256("tenzro/bitvm2/pegout" || dest_tx_hash || amount)`).
    pub id: Hash,
    /// Destination-chain tx hash for the burn.
    pub dest_burn_tx: Hash,
    /// Burnt amount in satoshis equivalent.
    pub amount_sats: u64,
    /// Bitcoin destination address (witness script as base58/bech32).
    pub btc_destination: String,
    /// Operator who advanced this peg-out.
    pub operator: Option<String>,
    /// Status.
    pub status: PegOutStatus,
}

/// Lifecycle states for peg-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PegOutStatus {
    /// Burn observed on destination chain.
    Requested,
    /// An operator broadcast the BTC payment to `btc_destination`.
    OperatorAdvanced,
    /// Settlement window passed without challenge.
    Settled,
    /// A challenger broadcast a BitVM2 challenge; operator must respond.
    Challenged,
    /// Operator failed challenge; pre-signed disconnect tx confiscated
    /// their bond.
    Slashed,
}

/// Adapter state.
#[derive(Debug)]
pub struct BitVm2Adapter {
    config: BitVm2Config,
    pegins: RwLock<HashMap<Hash, PegIn>>,
    pegouts: RwLock<HashMap<Hash, PegOut>>,
}

impl BitVm2Adapter {
    /// Build a new adapter.
    pub fn new(config: BitVm2Config) -> Self {
        Self {
            config,
            pegins: RwLock::new(HashMap::new()),
            pegouts: RwLock::new(HashMap::new()),
        }
    }

    /// Adapter config.
    pub fn config(&self) -> &BitVm2Config {
        &self.config
    }

    /// Compute a peg-in id.
    pub fn pegin_id(btc_txid: &[u8; 32]) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/bitvm2/pegin");
        h.update(btc_txid);
        let digest: [u8; 32] = h.finalize().into();
        Hash::new(digest)
    }

    /// Compute a peg-out id.
    pub fn pegout_id(dest_burn_tx: &Hash, amount_sats: u64) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/bitvm2/pegout");
        h.update(dest_burn_tx.as_bytes());
        h.update(amount_sats.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        Hash::new(digest)
    }

    /// Record a freshly observed peg-in.
    pub fn observe_pegin(
        &self,
        btc_txid: [u8; 32],
        btc_vout: u32,
        amount_sats: u64,
        recipient: impl Into<String>,
    ) -> Result<Hash> {
        if amount_sats == 0 {
            return Err(BridgeError::ConfigurationError(
                "amount_sats must be non-zero".into(),
            ));
        }
        let id = Self::pegin_id(&btc_txid);
        let pegin = PegIn {
            id,
            btc_txid,
            btc_vout,
            amount_sats,
            recipient: recipient.into(),
            status: PegInStatus::Pending,
        };
        self.pegins.write().insert(id, pegin);
        Ok(id)
    }

    /// Advance a peg-in to `Confirmed`. Callers gate on Bitcoin
    /// confirmations + Clementine operator-set proof.
    pub fn confirm_pegin(&self, id: &Hash) -> Result<()> {
        let mut pegins = self.pegins.write();
        let pegin = pegins
            .get_mut(id)
            .ok_or_else(|| BridgeError::TransferNotFound(format!("{:?}", id)))?;
        if pegin.status != PegInStatus::Pending {
            return Err(BridgeError::ConfigurationError(
                "peg-in is not in Pending state".into(),
            ));
        }
        pegin.status = PegInStatus::Confirmed;
        Ok(())
    }

    /// Mark the destination-chain mint complete.
    pub fn mint_pegin(&self, id: &Hash) -> Result<()> {
        let mut pegins = self.pegins.write();
        let pegin = pegins
            .get_mut(id)
            .ok_or_else(|| BridgeError::TransferNotFound(format!("{:?}", id)))?;
        if pegin.status != PegInStatus::Confirmed {
            return Err(BridgeError::ConfigurationError(
                "peg-in is not Confirmed".into(),
            ));
        }
        pegin.status = PegInStatus::Minted;
        Ok(())
    }

    /// Record a peg-out request.
    pub fn request_pegout(
        &self,
        dest_burn_tx: Hash,
        amount_sats: u64,
        btc_destination: impl Into<String>,
    ) -> Result<Hash> {
        if amount_sats == 0 {
            return Err(BridgeError::ConfigurationError(
                "amount_sats must be non-zero".into(),
            ));
        }
        let id = Self::pegout_id(&dest_burn_tx, amount_sats);
        let pegout = PegOut {
            id,
            dest_burn_tx,
            amount_sats,
            btc_destination: btc_destination.into(),
            operator: None,
            status: PegOutStatus::Requested,
        };
        self.pegouts.write().insert(id, pegout);
        Ok(id)
    }

    /// Operator advanced the peg-out (broadcast BTC tx).
    pub fn operator_advance(&self, id: &Hash, operator: impl Into<String>) -> Result<()> {
        let mut pegouts = self.pegouts.write();
        let pegout = pegouts
            .get_mut(id)
            .ok_or_else(|| BridgeError::TransferNotFound(format!("{:?}", id)))?;
        if pegout.status != PegOutStatus::Requested {
            return Err(BridgeError::ConfigurationError(
                "peg-out is not in Requested state".into(),
            ));
        }
        pegout.operator = Some(operator.into());
        pegout.status = PegOutStatus::OperatorAdvanced;
        Ok(())
    }

    /// Settle a peg-out (settlement window elapsed without challenge).
    pub fn settle_pegout(&self, id: &Hash) -> Result<()> {
        let mut pegouts = self.pegouts.write();
        let pegout = pegouts
            .get_mut(id)
            .ok_or_else(|| BridgeError::TransferNotFound(format!("{:?}", id)))?;
        if pegout.status != PegOutStatus::OperatorAdvanced {
            return Err(BridgeError::ConfigurationError(
                "peg-out is not in OperatorAdvanced state".into(),
            ));
        }
        pegout.status = PegOutStatus::Settled;
        Ok(())
    }

    /// File a BitVM2 challenge against a peg-out claim.
    pub fn challenge_pegout(&self, id: &Hash) -> Result<()> {
        let mut pegouts = self.pegouts.write();
        let pegout = pegouts
            .get_mut(id)
            .ok_or_else(|| BridgeError::TransferNotFound(format!("{:?}", id)))?;
        if pegout.status != PegOutStatus::OperatorAdvanced {
            return Err(BridgeError::ConfigurationError(
                "peg-out cannot be challenged in its current state".into(),
            ));
        }
        pegout.status = PegOutStatus::Challenged;
        Ok(())
    }

    /// Operator failed the challenge — slash via Clementine's pre-signed
    /// disconnect tx.
    pub fn slash_operator(&self, id: &Hash) -> Result<()> {
        let mut pegouts = self.pegouts.write();
        let pegout = pegouts
            .get_mut(id)
            .ok_or_else(|| BridgeError::TransferNotFound(format!("{:?}", id)))?;
        if pegout.status != PegOutStatus::Challenged {
            return Err(BridgeError::ConfigurationError(
                "peg-out is not Challenged".into(),
            ));
        }
        pegout.status = PegOutStatus::Slashed;
        Ok(())
    }

    /// Read a peg-in.
    pub fn get_pegin(&self, id: &Hash) -> Option<PegIn> {
        self.pegins.read().get(id).cloned()
    }

    /// Read a peg-out.
    pub fn get_pegout(&self, id: &Hash) -> Option<PegOut> {
        self.pegouts.read().get(id).cloned()
    }

    /// List peg-ins.
    pub fn list_pegins(&self) -> Vec<PegIn> {
        self.pegins.read().values().cloned().collect()
    }

    /// List peg-outs.
    pub fn list_pegouts(&self) -> Vec<PegOut> {
        self.pegouts.read().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BitVm2Config {
        BitVm2Config {
            network: BitVm2Network::Testnet,
            sequencer_rpc: "https://citrea-testnet.example".into(),
            bitcoin_rpc: "https://bitcoin-testnet4.example".into(),
            operator_set_commitment: [0x42; 32],
            settlement_window_blocks: 7 * 144,
            verifier: ClementineVerifierKind::BitVm2,
        }
    }

    #[test]
    fn pegin_lifecycle() {
        let a = BitVm2Adapter::new(cfg());
        let id = a
            .observe_pegin([7u8; 32], 0, 100_000_000, "tnzro_user")
            .unwrap();
        assert_eq!(a.get_pegin(&id).unwrap().status, PegInStatus::Pending);
        a.confirm_pegin(&id).unwrap();
        a.mint_pegin(&id).unwrap();
        assert_eq!(a.get_pegin(&id).unwrap().status, PegInStatus::Minted);
    }

    #[test]
    fn pegin_rejects_zero_amount() {
        let a = BitVm2Adapter::new(cfg());
        let err = a.observe_pegin([3u8; 32], 0, 0, "x").unwrap_err();
        assert!(matches!(err, BridgeError::ConfigurationError(_)));
    }

    #[test]
    fn pegout_settle_path() {
        let a = BitVm2Adapter::new(cfg());
        let id = a
            .request_pegout(Hash::new([1u8; 32]), 50_000_000, "bc1q...test")
            .unwrap();
        a.operator_advance(&id, "operator-0").unwrap();
        a.settle_pegout(&id).unwrap();
        assert_eq!(a.get_pegout(&id).unwrap().status, PegOutStatus::Settled);
    }

    #[test]
    fn pegout_challenge_slash_path() {
        let a = BitVm2Adapter::new(cfg());
        let id = a
            .request_pegout(Hash::new([2u8; 32]), 60_000_000, "bc1q...slash")
            .unwrap();
        a.operator_advance(&id, "operator-1").unwrap();
        a.challenge_pegout(&id).unwrap();
        a.slash_operator(&id).unwrap();
        assert_eq!(a.get_pegout(&id).unwrap().status, PegOutStatus::Slashed);
    }

    #[test]
    fn pegout_settle_rejected_without_advance() {
        let a = BitVm2Adapter::new(cfg());
        let id = a
            .request_pegout(Hash::new([3u8; 32]), 70_000_000, "bc1q...x")
            .unwrap();
        let err = a.settle_pegout(&id).unwrap_err();
        assert!(matches!(err, BridgeError::ConfigurationError(_)));
    }

    #[test]
    fn list_returns_all() {
        let a = BitVm2Adapter::new(cfg());
        a.observe_pegin([1u8; 32], 0, 1, "x").unwrap();
        a.observe_pegin([2u8; 32], 0, 2, "y").unwrap();
        assert_eq!(a.list_pegins().len(), 2);
    }
}
