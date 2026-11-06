//! Spending from a Bitcoin deposit route's descriptor: withdrawals.
//!
//! The deposit descriptor is a Taproot output whose key path nobody can use
//! (its internal key is the standard provably-unspendable point) and whose one
//! script path needs `threshold` of the route's `signers` (BIP-340 keys):
//!
//! ```text
//! tr(NUMS, multi_a(threshold, signer_1, ..., signer_n))
//! ```
//!
//! Bitcoin cannot check a proof of Tenzro's state, so no script can make a
//! spend depend on a burn here. What this module makes exact is everything
//! else: Tenzro tracks every output the descriptor holds, and a withdrawal is
//! a transaction derived only from consensus state (the outputs it spends, the
//! recipient, the amount and the governed fee rate), so its id, and with it
//! the change output it returns to the descriptor, is fixed before anyone
//! signs. Signers sign that transaction and nothing else; the signatures over
//! its BIP-341 digests, from `threshold` signers, complete it. The trust that
//! remains is that `threshold` of the signers do not sign a spend Tenzro did
//! not order.
//!
//! A withdrawal pays the recipient its amount less the fee, and returns any
//! change to the descriptor; change below the dust limit is refused rather
//! than given away, so the descriptor holds exactly what the route records.

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

use super::bitcoin::{Transaction, TxIn, TxOut, sha256d};
use super::canonical::{Reader, Writer};
use crate::error::{BridgeError, Result};

/// The x coordinate of the provably unspendable internal key (BIP-341).
pub const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Smallest output a withdrawal creates (the standard dust limit of a
/// Taproot output).
pub const DUST: u64 = 330;

/// Most outputs one withdrawal spends.
pub const MAX_INPUTS: usize = 64;

/// The sequence every withdrawal input carries (replaceable, no lock).
const INPUT_SEQUENCE: u32 = 0xffff_fffd;

const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGADD: u8 = 0xba;
const OP_NUMEQUAL: u8 = 0x9c;
const LEAF_VERSION: u8 = 0xc0;

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("bitcoin withdrawal: {}", what.into()))
}

fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let t = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn compact_size(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => [vec![0xfd], (n as u16).to_le_bytes().to_vec()].concat(),
        _ => [vec![0xfe], (n as u32).to_le_bytes().to_vec()].concat(),
    }
}

/// The point with x coordinate `x` and an even y (BIP-340 `lift_x`).
fn lift_x(x: &[u8; 32]) -> Result<ProjectivePoint> {
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(x);
    let pk = k256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| bad("a signer key is not on the curve"))?;
    Ok(pk.to_projective())
}

/// The governed deposit descriptor. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositDescriptor {
    /// The signers' BIP-340 keys, in the order the script checks them.
    pub signers: Vec<[u8; 32]>,
    /// How many must sign.
    pub threshold: u32,
}

impl DepositDescriptor {
    /// The tapscript leaf: each key checked in turn, the valid signatures
    /// counted, and the count compared with the threshold.
    pub fn leaf_script(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(self.signers.len() * 34 + 4);
        for (i, k) in self.signers.iter().enumerate() {
            s.push(32);
            s.extend_from_slice(k);
            s.push(if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD });
        }
        match self.threshold {
            n @ 1..=16 => s.push(0x50 + n as u8),
            n => {
                let mut b: Vec<u8> = n.to_le_bytes().into_iter().collect();
                while b.len() > 1 && b[b.len() - 1] == 0 && b[b.len() - 2] & 0x80 == 0 {
                    b.pop();
                }
                if b.last().is_some_and(|l| l & 0x80 != 0) {
                    b.push(0);
                }
                s.push(b.len() as u8);
                s.extend_from_slice(&b);
            }
        }
        s.push(OP_NUMEQUAL);
        s
    }

    /// The leaf's hash (BIP-341 `TapLeaf`).
    pub fn leaf_hash(&self) -> [u8; 32] {
        let script = self.leaf_script();
        tagged(
            "TapLeaf",
            &[&[LEAF_VERSION], &compact_size(script.len()), &script],
        )
    }

    /// The output key's x coordinate and whether its y is odd.
    fn output_key(&self) -> Result<([u8; 32], bool)> {
        let internal = lift_x(&NUMS)?;
        let t = tagged("TapTweak", &[&NUMS, &self.leaf_hash()]);
        let tweak: Scalar = Option::from(Scalar::from_repr(t.into()))
            .ok_or_else(|| bad("the tweak is out of range"))?;
        let q = (internal + ProjectivePoint::GENERATOR * tweak).to_affine();
        let x: [u8; 32] = q.x().into();
        Ok((x, bool::from(q.y_is_odd())))
    }

    /// The output script deposits pay: `OP_1 <output key>`.
    pub fn script_pubkey(&self) -> Result<Vec<u8>> {
        let (x, _) = self.output_key()?;
        Ok([&[0x51, 0x20][..], &x].concat())
    }

    /// The control block that reveals the leaf when spending.
    pub fn control_block(&self) -> Result<Vec<u8>> {
        let (_, odd) = self.output_key()?;
        Ok([&[LEAF_VERSION | u8::from(odd)][..], &NUMS].concat())
    }

    /// The descriptor as Bitcoin Core and wallets read it, with its checksum.
    pub fn descriptor(&self) -> String {
        let keys: Vec<String> = self.signers.iter().map(hex::encode).collect();
        let body = format!(
            "tr({},multi_a({},{}))",
            hex::encode(NUMS),
            self.threshold,
            keys.join(",")
        );
        let sum = descriptor_checksum(&body);
        format!("{body}#{sum}")
    }

    /// Witness bytes one input carries once `threshold` signers signed.
    fn witness_len(&self) -> usize {
        let script = self.leaf_script().len();
        let items = self.signers.len() + 2;
        compact_size(items).len()
            + self.threshold as usize * 65
            + (self.signers.len() - self.threshold as usize)
            + compact_size(script).len()
            + script
            + 1
            + 33
    }
}

/// The BIP-380 descriptor checksum.
pub fn descriptor_checksum(desc: &str) -> String {
    const INPUT: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GEN: [u64; 5] = [
        0xf5dee51989,
        0xa9fdca3312,
        0x1bab10e32d,
        0x3706b1677a,
        0x644d626ffd,
    ];
    fn polymod(c: u64, v: u64) -> u64 {
        let top = c >> 35;
        let mut c = ((c & 0x7ffffffff) << 5) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                c ^= g;
            }
        }
        c
    }
    let mut c = 1u64;
    let mut cls = 0u64;
    let mut count = 0;
    for ch in desc.chars() {
        let pos = INPUT.find(ch).unwrap_or(0) as u64;
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        count += 1;
        if count == 3 {
            c = polymod(c, cls);
            cls = 0;
            count = 0;
        }
    }
    if count > 0 {
        c = polymod(c, cls);
    }
    for _ in 0..8 {
        c = polymod(c, 0);
    }
    c ^= 1;
    (0..8)
        .map(|i| CHARSET[((c >> (5 * (7 - i))) & 31) as usize] as char)
        .collect()
}

/// An output the descriptor holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utxo {
    /// The transaction id (internal byte order).
    pub txid: [u8; 32],
    /// The output's index.
    pub vout: u32,
    /// Its value in satoshis.
    pub value: u64,
}

/// Encode the descriptor's outputs, oldest first, after their count.
pub fn encode_utxos(utxos: &[Utxo]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32_be(utxos.len() as u32);
    for u in utxos {
        w.raw(&u.txid).u32_be(u.vout).u64_be(u.value);
    }
    w.into_bytes()
}

/// Decode what [`encode_utxos`] wrote.
pub fn decode_utxos(bytes: &[u8]) -> Result<Vec<Utxo>> {
    let mut r = Reader::new(bytes);
    let n = r.u32_be()? as usize;
    if n > bytes.len() / 44 {
        return Err(bad("the output set is truncated"));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(Utxo {
            txid: r.array()?,
            vout: r.u32_be()?,
            value: r.u64_be()?,
        });
    }
    r.finish()?;
    Ok(out)
}

/// A withdrawal: the unsigned transaction and the values of the outputs it
/// spends, which every signature commits to.
///
/// ```text
/// tx u32 length + the transaction without witness data | values u64 * inputs
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    pub tx: Transaction,
    pub values: Vec<u64>,
}

impl Withdrawal {
    /// The record's encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.be_bytes(&self.tx.encode());
        for v in &self.values {
            w.u64_be(*v);
        }
        w.into_bytes()
    }

    /// Decode a record, refusing any other layout.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let tx = Transaction::decode(r.be_bytes(super::bitcoin::MAX_TX_LEN)?)?;
        let values = (0..tx.inputs.len())
            .map(|_| r.u64_be())
            .collect::<Result<Vec<_>>>()?;
        r.finish()?;
        Ok(Self { tx, values })
    }

    /// The transaction id, fixed before any signature exists.
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.tx.encode())
    }

    /// The BIP-341 digest input `index` is signed over: the default sighash
    /// of a script-path spend of the descriptor's leaf.
    pub fn sighash(&self, desc: &DepositDescriptor, index: usize) -> Result<[u8; 32]> {
        if index >= self.tx.inputs.len() || self.values.len() != self.tx.inputs.len() {
            return Err(bad("no such input"));
        }
        let spk = desc.script_pubkey()?;
        let sha = |parts: &mut dyn Iterator<Item = Vec<u8>>| {
            let mut h = Sha256::new();
            for p in parts {
                h.update(p);
            }
            <[u8; 32]>::from(h.finalize())
        };
        let prevouts = sha(&mut self.tx.inputs.iter().map(|i| i.prevout.to_vec()));
        let amounts = sha(&mut self.values.iter().map(|v| v.to_le_bytes().to_vec()));
        let scripts = sha(&mut self
            .values
            .iter()
            .map(|_| [compact_size(spk.len()), spk.clone()].concat()));
        let sequences = sha(&mut self
            .tx
            .inputs
            .iter()
            .map(|i| i.sequence.to_le_bytes().to_vec()));
        let outputs = sha(&mut self.tx.outputs.iter().map(|o| {
            [
                o.value.to_le_bytes().to_vec(),
                compact_size(o.script.len()),
                o.script.clone(),
            ]
            .concat()
        }));
        let mut m = Vec::with_capacity(256);
        m.push(0x00); // epoch
        m.push(0x00); // SIGHASH_DEFAULT
        m.extend_from_slice(&self.tx.version.to_le_bytes());
        m.extend_from_slice(&self.tx.lock_time.to_le_bytes());
        m.extend_from_slice(&prevouts);
        m.extend_from_slice(&amounts);
        m.extend_from_slice(&scripts);
        m.extend_from_slice(&sequences);
        m.extend_from_slice(&outputs);
        m.push(0x02); // script path, no annex
        m.extend_from_slice(&(index as u32).to_le_bytes());
        m.extend_from_slice(&desc.leaf_hash());
        m.push(0x00); // key version
        m.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // no OP_CODESEPARATOR
        Ok(tagged("TapSighash", &[&m]))
    }

    /// The signed transaction, ready to broadcast: every input's witness
    /// holds, for each signer in reverse script order, its signature or an
    /// empty item. `signatures[i]` maps a signer's key to its signature over
    /// input `i`. Each signature is verified, and every input needs
    /// `threshold` of them.
    pub fn assemble(
        &self,
        desc: &DepositDescriptor,
        signatures: &[Vec<([u8; 32], [u8; 64])>],
    ) -> Result<Vec<u8>> {
        if signatures.len() != self.tx.inputs.len() {
            return Err(bad("one set of signatures per input"));
        }
        let script = desc.leaf_script();
        let control = desc.control_block()?;
        let mut witnesses = Vec::with_capacity(self.tx.inputs.len());
        for (i, sigs) in signatures.iter().enumerate() {
            let digest = self.sighash(desc, i)?;
            let mut items: Vec<Vec<u8>> = Vec::with_capacity(desc.signers.len() + 2);
            let mut valid = 0u32;
            for key in desc.signers.iter().rev() {
                match sigs.iter().find(|(k, _)| k == key) {
                    Some((_, sig)) => {
                        verify_schnorr(key, &digest, sig)?;
                        valid += 1;
                        items.push(sig.to_vec());
                    }
                    None => items.push(Vec::new()),
                }
            }
            if valid < desc.threshold {
                return Err(bad(format!(
                    "input {i} has {valid} of the {} signatures it needs",
                    desc.threshold
                )));
            }
            items.push(script.clone());
            items.push(control.clone());
            witnesses.push(items);
        }

        let base = self.tx.encode();
        // version | marker 0x00 | flag 0x01 | inputs and outputs | witnesses | lock_time
        let mut out = Vec::with_capacity(base.len() + 256 * witnesses.len());
        out.extend_from_slice(&base[..4]);
        out.extend_from_slice(&[0x00, 0x01]);
        out.extend_from_slice(&base[4..base.len() - 4]);
        for items in &witnesses {
            out.extend_from_slice(&compact_size(items.len()));
            for item in items {
                out.extend_from_slice(&compact_size(item.len()));
                out.extend_from_slice(item);
            }
        }
        out.extend_from_slice(&base[base.len() - 4..]);
        Ok(out)
    }
}

/// Verify a BIP-340 signature by `key` over the 32-byte `digest`.
pub fn verify_schnorr(key: &[u8; 32], digest: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
    use k256::schnorr::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_bytes(key.into())
        .map_err(|_| bad("a signer key is not a BIP-340 key"))?;
    let sig = Signature::try_from(&sig[..]).map_err(|_| bad("a malformed signature"))?;
    vk.verify_raw(digest, &sig)
        .map_err(|_| bad("a signature does not verify"))
}

/// Whether `script` is a standard output script a withdrawal may pay:
/// P2PKH, P2SH, P2WPKH, P2WSH or P2TR.
pub fn is_standard_destination(script: &[u8]) -> bool {
    matches!(
        script,
        [0x76, 0xa9, 0x14, .., 0x88, 0xac] if script.len() == 25
    ) || matches!(script, [0xa9, 0x14, .., 0x87] if script.len() == 23)
        || matches!(script, [0x00, 0x14, ..] if script.len() == 22)
        || matches!(script, [0x00, 0x20, ..] if script.len() == 34)
        || matches!(script, [0x51, 0x20, ..] if script.len() == 34)
}

/// Plan the withdrawal of `amount` satoshis to `recipient` from `utxos`
/// (oldest first) at `fee_rate` satoshis per virtual byte: the transaction,
/// and the descriptor's outputs once it is made (those it did not spend,
/// then its change).
///
/// The recipient receives `amount` less the fee; whatever the spent outputs
/// hold beyond `amount` returns to the descriptor as change, which must not
/// be dust.
pub fn plan_withdrawal(
    desc: &DepositDescriptor,
    utxos: &[Utxo],
    recipient: &[u8],
    amount: u64,
    fee_rate: u64,
) -> Result<(Withdrawal, Vec<Utxo>)> {
    let deposit_script = desc.script_pubkey()?;
    if !is_standard_destination(recipient) || recipient == deposit_script.as_slice() {
        return Err(bad(
            "the recipient must be a standard output script other than the deposit script",
        ));
    }
    let mut spent = 0u64;
    let mut take = 0;
    while spent < amount {
        let u = utxos
            .get(take)
            .ok_or_else(|| bad("the descriptor holds less than the amount"))?;
        spent = spent
            .checked_add(u.value)
            .ok_or_else(|| bad("value overflow"))?;
        take += 1;
    }
    if take > MAX_INPUTS {
        return Err(bad(format!(
            "the withdrawal would spend more than {MAX_INPUTS} outputs; withdraw less"
        )));
    }
    let change = spent - amount;
    if change != 0 && change < DUST {
        return Err(match spent.checked_sub(DUST) {
            Some(most) if most > 0 => bad(format!(
                "the change of {change} satoshis would be dust; withdraw {spent} or at most {most}"
            )),
            _ => bad(format!(
                "the change of {change} satoshis would be dust; withdraw {spent}"
            )),
        });
    }
    let inputs: Vec<TxIn> = utxos[..take]
        .iter()
        .map(|u| {
            let mut prevout = [0u8; 36];
            prevout[..32].copy_from_slice(&u.txid);
            prevout[32..].copy_from_slice(&u.vout.to_le_bytes());
            TxIn {
                prevout,
                script_sig: Vec::new(),
                sequence: INPUT_SEQUENCE,
            }
        })
        .collect();
    let mut outputs = vec![TxOut {
        value: 0,
        script: recipient.to_vec(),
    }];
    if change > 0 {
        outputs.push(TxOut {
            value: change,
            script: deposit_script,
        });
    }
    let mut tx = Transaction {
        version: 2,
        inputs,
        outputs,
        lock_time: 0,
    };

    // Weight: the base serialization counts four times, the segwit marker,
    // flag and witnesses once each.
    let weight = tx.encode().len() * 4 + 2 + take * desc.witness_len();
    let fee = (weight as u64)
        .div_ceil(4)
        .checked_mul(fee_rate)
        .ok_or_else(|| bad("fee overflow"))?;
    let pay = amount
        .checked_sub(fee)
        .filter(|p| *p >= DUST)
        .ok_or_else(|| {
            bad(format!(
                "the amount does not cover the fee of {fee} satoshis and a non-dust payment"
            ))
        })?;
    tx.outputs[0].value = pay;

    let withdrawal = Withdrawal {
        values: utxos[..take].iter().map(|u| u.value).collect(),
        tx,
    };
    let mut remaining = utxos[take..].to_vec();
    if change > 0 {
        remaining.push(Utxo {
            txid: withdrawal.txid(),
            vout: 1,
            value: change,
        });
    }
    Ok((withdrawal, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> k256::schnorr::SigningKey {
        k256::schnorr::SigningKey::from_bytes(&[seed; 32].into()).unwrap()
    }

    fn desc(n: u8, k: u32) -> DepositDescriptor {
        DepositDescriptor {
            signers: (1..=n)
                .map(|i| <[u8; 32]>::from(key(i).verifying_key().to_bytes()))
                .collect(),
            threshold: k,
        }
    }

    fn sign(seed: u8, digest: &[u8; 32]) -> [u8; 64] {
        key(seed).sign_raw(digest, &[0u8; 32]).unwrap().to_bytes()
    }

    #[test]
    fn the_descriptor_checksum_matches_the_reference() {
        // From the descriptor documentation of Bitcoin Core.
        assert_eq!(
            descriptor_checksum("addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)"),
            "02wpgw69"
        );
    }

    /// A withdrawal whose change would be dust from outputs holding less
    /// than the dust limit is refused, without underflowing the advice.
    #[test]
    fn dust_change_from_small_outputs_is_refused_without_underflow() {
        let d = desc(3, 2);
        let utxos = vec![Utxo {
            txid: [1; 32],
            vout: 0,
            value: 200,
        }];
        let recipient = [&[0x00, 0x14][..], &[9u8; 20]].concat();
        assert!(plan_withdrawal(&d, &utxos, &recipient, 100, 2).is_err());
    }

    #[test]
    fn a_withdrawal_is_planned_exactly_and_signed_by_the_threshold() {
        let d = desc(3, 2);
        let script = d.script_pubkey().unwrap();
        assert_eq!(script.len(), 34);
        let utxos = vec![
            Utxo {
                txid: [1; 32],
                vout: 0,
                value: 40_000,
            },
            Utxo {
                txid: [2; 32],
                vout: 3,
                value: 70_000,
            },
            Utxo {
                txid: [3; 32],
                vout: 1,
                value: 5_000,
            },
        ];
        let recipient = [&[0x00, 0x14][..], &[9u8; 20]].concat();
        let (w, rest) = plan_withdrawal(&d, &utxos, &recipient, 100_000, 2).unwrap();
        assert_eq!(w.tx.inputs.len(), 2);
        assert_eq!(
            w.tx.outputs[1],
            TxOut {
                value: 10_000,
                script: script.clone()
            }
        );
        let fee = 100_000 - w.tx.outputs[0].value;
        assert!(fee > 0 && fee < 2_000, "fee {fee}");
        assert_eq!(
            rest,
            vec![
                utxos[2],
                Utxo {
                    txid: w.txid(),
                    vout: 1,
                    value: 10_000
                }
            ]
        );
        assert_eq!(Withdrawal::decode(&w.encode()).unwrap(), w);

        let sigs = |signers: &[u8]| -> Vec<Vec<([u8; 32], [u8; 64])>> {
            (0..w.tx.inputs.len())
                .map(|i| {
                    let digest = w.sighash(&d, i).unwrap();
                    signers
                        .iter()
                        .map(|s| (d.signers[*s as usize - 1], sign(*s, &digest)))
                        .collect()
                })
                .collect()
        };
        let signed = w.assemble(&d, &sigs(&[1, 3])).unwrap();
        assert_eq!(&signed[4..6], &[0x00, 0x01]);
        // One signer is not enough, and a signature over another input is
        // refused.
        assert!(w.assemble(&d, &sigs(&[2])).is_err());
        let mut swapped = sigs(&[1, 3]);
        swapped.swap(0, 1);
        assert!(w.assemble(&d, &swapped).is_err());

        // Dust change and a non-standard destination are refused.
        assert!(plan_withdrawal(&d, &utxos, &recipient, 39_900, 2).is_err());
        assert!(plan_withdrawal(&d, &utxos, &script, 1_000, 2).is_err());
        assert!(plan_withdrawal(&d, &utxos, &[0x6a, 0x00], 1_000, 2).is_err());
        assert!(plan_withdrawal(&d, &utxos, &recipient, 200_000, 2).is_err());
    }
}
