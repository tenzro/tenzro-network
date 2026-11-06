//! The preimage statement in Halo2 (PLONKish arithmetization, inner-product
//! argument commitments over the Pasta curves).
//!
//! This is an independent implementation of the same statement the Plonky3
//! systems prove ([`crate::circuits::preimage`]): for a circuit's 32-byte
//! domain label `D`, public inputs `(digest, binding)` and a private 32-byte
//! witness `w`,
//!
//! ```text
//! digest == SHA3-256(D || w)
//! ```
//!
//! Nothing is shared with the Plonky3 code: the arithmetization (a PLONKish
//! circuit with custom gates and copy constraints instead of an AIR), the
//! field (the 255-bit Pallas scalar field), the polynomial commitment (an
//! inner-product argument, with no trusted setup), the transcript hash
//! (BLAKE2b) and the Keccak-f constraints themselves are all separate code.
//! A defect in one implementation therefore does not produce an accepting
//! proof in the other.
//!
//! # Circuit
//!
//! Every Keccak-f state bit is a cell. The permutation is built from three
//! gates over boolean inputs, each of which forces a boolean output:
//!
//! - `xor3`: `out = a ⊕ b ⊕ c`, written `a+b+c-2(ab+ac+bc)+4abc`;
//! - `chi`: `out = a ⊕ (¬b ∧ c)`, written `a+t-2at` with `t = (1-b)c`;
//! - `chi_not`: `1 - chi`, used where the round constant flips a bit.
//!
//! Theta is two `xor3` per column parity bit and one `xor3` per state bit;
//! rho and pi are only wiring (copy constraints); chi and iota are one gate
//! per bit. The absorbed block is fixed except for the 256 witness bits:
//! domain, padding and zero lanes are copies of constant cells, and the
//! witness bits carry a booleanity gate. The first 256 output bits are
//! constrained equal to the digest bits of the instance column. The binding
//! bits follow in the same instance column; they are not constrained, but the
//! instance column is committed to in the transcript, so a proof made for one
//! binding does not verify for another.
//!
//! The proof is zero-knowledge: Halo2 blinds every advice column.

use std::sync::OnceLock;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{
        Advice, Circuit as Halo2Circuit, Column, ConstraintSystem, Error, Expression, Fixed,
        Instance, ProvingKey, Selector, SingleVerifier, create_proof, keygen_pk, keygen_vk,
        verify_proof,
    },
    poly::{Rotation, commitment::Params},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};

use crate::circuits::Circuit;
use crate::circuits::preimage::WORD_BYTES;

/// Rows of the circuit: `2^K`.
pub const K: u32 = 14;

/// Gate slots per row. Each slot is four advice cells `(a, b, c, out)`.
const SLOTS: usize = 8;

/// Bits in the Keccak-f state.
const STATE_BITS: usize = 1600;

/// SHA3-256 rate in bytes.
const RATE_BYTES: usize = 136;

/// Keccak-f[1600] round constants.
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rho rotation offsets, indexed `[x][y]`.
const RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// Index of bit `z` of lane `(x, y)`.
fn bit(x: usize, y: usize, z: usize) -> usize {
    (x + 5 * y) * 64 + z
}

/// Why a Halo2 proof could not be produced or was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum Halo2Error {
    /// The prover failed.
    #[error("halo2 prover failed: {0:?}")]
    Prove(Error),
    /// The verifier rejected the proof.
    #[error("halo2 verifier rejected the proof: {0:?}")]
    Rejected(Error),
}

/// The Halo2 circuit for one preimage statement.
#[derive(Clone)]
struct PreimageCircuit {
    domain: [u8; WORD_BYTES],
    witness: Value<[u8; WORD_BYTES]>,
}

#[derive(Clone, Debug)]
struct PreimageConfig {
    cells: [[Column<Advice>; 4]; SLOTS],
    xor3: [Selector; SLOTS],
    chi: [Selector; SLOTS],
    chi_not: [Selector; SLOTS],
    boolean: [Selector; SLOTS],
    instance: Column<Instance>,
}

type Bit = AssignedCell<Fp, Fp>;

#[derive(Clone, Copy)]
enum Gate {
    Xor3,
    Chi,
    ChiNot,
}

fn xor3(a: Fp, b: Fp, c: Fp) -> Fp {
    let two = Fp::from(2);
    let four = Fp::from(4);
    a + b + c - two * (a * b + a * c + b * c) + four * a * b * c
}

fn chi(a: Fp, b: Fp, c: Fp) -> Fp {
    let t = (Fp::ONE - b) * c;
    a + t - Fp::from(2) * a * t
}

/// Assigns gates one after another into the slots of a single region.
struct Assigner<'r, 'a> {
    region: &'r mut Region<'a, Fp>,
    config: &'r PreimageConfig,
    next: usize,
}

impl Assigner<'_, '_> {
    fn slot(&mut self) -> (usize, usize) {
        let n = self.next;
        self.next += 1;
        (n / SLOTS, n % SLOTS)
    }

    fn constant(&mut self, value: u64) -> Result<Bit, Error> {
        let (row, slot) = self.slot();
        self.region.assign_advice_from_constant(
            || "constant",
            self.config.cells[slot][0],
            row,
            Fp::from(value),
        )
    }

    fn witness_bit(&mut self, value: Value<Fp>) -> Result<Bit, Error> {
        let (row, slot) = self.slot();
        self.config.boolean[slot].enable(&mut *self.region, row)?;
        self.region
            .assign_advice(|| "witness bit", self.config.cells[slot][0], row, || value)
    }

    fn gate(&mut self, gate: Gate, a: &Bit, b: &Bit, c: &Bit) -> Result<Bit, Error> {
        let (row, slot) = self.slot();
        let cols = self.config.cells[slot];
        let selector = match gate {
            Gate::Xor3 => self.config.xor3[slot],
            Gate::Chi => self.config.chi[slot],
            Gate::ChiNot => self.config.chi_not[slot],
        };
        selector.enable(&mut *self.region, row)?;
        a.copy_advice(|| "a", &mut *self.region, cols[0], row)?;
        b.copy_advice(|| "b", &mut *self.region, cols[1], row)?;
        c.copy_advice(|| "c", &mut *self.region, cols[2], row)?;
        let out = a
            .value()
            .zip(b.value())
            .zip(c.value())
            .map(|((a, b), c)| match gate {
                Gate::Xor3 => xor3(*a, *b, *c),
                Gate::Chi => chi(*a, *b, *c),
                Gate::ChiNot => Fp::ONE - chi(*a, *b, *c),
            });
        self.region.assign_advice(|| "out", cols[3], row, || out)
    }
}

impl PreimageCircuit {
    /// The absorbed block's fixed bits: domain, SHA3 padding, zero lanes.
    /// `None` marks a witness bit.
    fn block_bit(&self, i: usize) -> Option<u64> {
        let byte = i / 8;
        if (WORD_BYTES..2 * WORD_BYTES).contains(&byte) {
            return None;
        }
        let mut block = [0u8; 200];
        block[..WORD_BYTES].copy_from_slice(&self.domain);
        block[2 * WORD_BYTES] = 0x06;
        block[RATE_BYTES - 1] |= 0x80;
        Some(((block[byte] >> (i % 8)) & 1) as u64)
    }

    fn permute(&self, a: &mut Assigner<'_, '_>, mut state: Vec<Bit>) -> Result<Vec<Bit>, Error> {
        for rc in ROUND_CONSTANTS {
            // Theta: column parities, then every bit xors two of them.
            let mut parity = Vec::with_capacity(5 * 64);
            for x in 0..5 {
                for z in 0..64 {
                    let first = a.gate(
                        Gate::Xor3,
                        &state[bit(x, 0, z)],
                        &state[bit(x, 1, z)],
                        &state[bit(x, 2, z)],
                    )?;
                    parity.push(a.gate(
                        Gate::Xor3,
                        &first,
                        &state[bit(x, 3, z)],
                        &state[bit(x, 4, z)],
                    )?);
                }
            }
            let mut theta = Vec::with_capacity(STATE_BITS);
            for y in 0..5 {
                for x in 0..5 {
                    for z in 0..64 {
                        theta.push(a.gate(
                            Gate::Xor3,
                            &state[bit(x, y, z)],
                            &parity[((x + 4) % 5) * 64 + z],
                            &parity[((x + 1) % 5) * 64 + (z + 63) % 64],
                        )?);
                    }
                }
            }
            // Rho and pi: B[y, 2x+3y] = rot(A[x, y], RHO[x][y]); wiring only.
            let mut b: Vec<Option<Bit>> = vec![None; STATE_BITS];
            for x in 0..5 {
                for y in 0..5 {
                    let r = RHO[x][y] as usize;
                    for z in 0..64 {
                        let target = bit(y, (2 * x + 3 * y) % 5, (z + r) % 64);
                        b[target] = Some(theta[bit(x, y, z)].clone());
                    }
                }
            }
            let b: Vec<Bit> = b
                .into_iter()
                .map(|c| c.expect("pi is a permutation"))
                .collect();
            // Chi, with iota folded into lane (0, 0).
            let mut next = Vec::with_capacity(STATE_BITS);
            for y in 0..5 {
                for x in 0..5 {
                    for z in 0..64 {
                        let flip = x == 0 && y == 0 && (rc >> z) & 1 == 1;
                        next.push(a.gate(
                            if flip { Gate::ChiNot } else { Gate::Chi },
                            &b[bit(x, y, z)],
                            &b[bit((x + 1) % 5, y, z)],
                            &b[bit((x + 2) % 5, y, z)],
                        )?);
                    }
                }
            }
            state = next;
        }
        Ok(state)
    }
}

impl Halo2Circuit<Fp> for PreimageCircuit {
    type Config = PreimageConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            domain: self.domain,
            witness: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> PreimageConfig {
        let cells = [(); SLOTS].map(|_| {
            [(); 4].map(|_| {
                let c = meta.advice_column();
                meta.enable_equality(c);
                c
            })
        });
        let xor3 = [(); SLOTS].map(|_| meta.selector());
        let chi = [(); SLOTS].map(|_| meta.selector());
        let chi_not = [(); SLOTS].map(|_| meta.selector());
        let boolean = [(); SLOTS].map(|_| meta.selector());
        let constants: Column<Fixed> = meta.fixed_column();
        meta.enable_constant(constants);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let one = || Expression::Constant(Fp::ONE);
        let two = || Expression::Constant(Fp::from(2));
        let four = || Expression::Constant(Fp::from(4));
        for slot in 0..SLOTS {
            let [ca, cb, cc, co] = cells[slot];
            meta.create_gate("xor3", |meta| {
                let s = meta.query_selector(xor3[slot]);
                let a = meta.query_advice(ca, Rotation::cur());
                let b = meta.query_advice(cb, Rotation::cur());
                let c = meta.query_advice(cc, Rotation::cur());
                let out = meta.query_advice(co, Rotation::cur());
                let value = a.clone() + b.clone() + c.clone()
                    - two()
                        * (a.clone() * b.clone() + a.clone() * c.clone() + b.clone() * c.clone())
                    + four() * a * b * c;
                vec![s * (value - out)]
            });
            meta.create_gate("chi", |meta| {
                let s = meta.query_selector(chi[slot]);
                let a = meta.query_advice(ca, Rotation::cur());
                let b = meta.query_advice(cb, Rotation::cur());
                let c = meta.query_advice(cc, Rotation::cur());
                let out = meta.query_advice(co, Rotation::cur());
                let t = (one() - b) * c;
                vec![s * (a.clone() + t.clone() - two() * a * t - out)]
            });
            meta.create_gate("chi_not", |meta| {
                let s = meta.query_selector(chi_not[slot]);
                let a = meta.query_advice(ca, Rotation::cur());
                let b = meta.query_advice(cb, Rotation::cur());
                let c = meta.query_advice(cc, Rotation::cur());
                let out = meta.query_advice(co, Rotation::cur());
                let t = (one() - b) * c;
                vec![s * (one() - (a.clone() + t.clone() - two() * a * t) - out)]
            });
            meta.create_gate("boolean", |meta| {
                let s = meta.query_selector(boolean[slot]);
                let a = meta.query_advice(ca, Rotation::cur());
                vec![s * a.clone() * (one() - a)]
            });
        }

        PreimageConfig {
            cells,
            xor3,
            chi,
            chi_not,
            boolean,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: PreimageConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let digest_bits = layouter.assign_region(
            || "keccak-f",
            |mut region| {
                let mut a = Assigner {
                    region: &mut region,
                    config: &config,
                    next: 0,
                };
                let zero = a.constant(0)?;
                let one = a.constant(1)?;
                let mut state = Vec::with_capacity(STATE_BITS);
                for i in 0..STATE_BITS {
                    state.push(match self.block_bit(i) {
                        Some(0) => zero.clone(),
                        Some(_) => one.clone(),
                        None => {
                            let j = i - 8 * WORD_BYTES;
                            a.witness_bit(
                                self.witness
                                    .map(|w| Fp::from(((w[j / 8] >> (j % 8)) & 1) as u64)),
                            )?
                        }
                    });
                }
                let out = self.permute(&mut a, state)?;
                Ok(out.into_iter().take(8 * WORD_BYTES).collect::<Vec<_>>())
            },
        )?;
        for (row, cell) in digest_bits.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, row)?;
        }
        Ok(())
    }
}

/// The instance column: digest bits, then binding bits, little-endian
/// within each byte.
fn instance(digest: &[u8; WORD_BYTES], binding: &[u8; WORD_BYTES]) -> Vec<Fp> {
    digest
        .iter()
        .chain(binding.iter())
        .flat_map(|byte| (0..8).map(move |j| Fp::from(((byte >> j) & 1) as u64)))
        .collect()
}

fn params() -> &'static Params<EqAffine> {
    static PARAMS: OnceLock<Params<EqAffine>> = OnceLock::new();
    PARAMS.get_or_init(|| Params::new(K))
}

fn proving_key(circuit: Circuit) -> &'static ProvingKey<EqAffine> {
    static KEYS: [OnceLock<ProvingKey<EqAffine>>; 2] = [OnceLock::new(), OnceLock::new()];
    let slot = match circuit {
        Circuit::Identity => 0,
        Circuit::Settlement => 1,
    };
    KEYS[slot].get_or_init(|| {
        let shape = PreimageCircuit {
            domain: circuit.domain(),
            witness: Value::unknown(),
        };
        let vk = keygen_vk(params(), &shape).expect("the circuit fits in 2^K rows");
        keygen_pk(params(), vk, &shape).expect("the circuit fits in 2^K rows")
    })
}

/// Prove knowledge of `witness` for `circuit`, bound to `binding`.
pub fn prove(
    circuit: Circuit,
    witness: &[u8; WORD_BYTES],
    binding: &[u8; WORD_BYTES],
) -> Result<Vec<u8>, Halo2Error> {
    let instance = instance(&circuit.digest(witness), binding);
    let c = PreimageCircuit {
        domain: circuit.domain(),
        witness: Value::known(*witness),
    };
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        params(),
        proving_key(circuit),
        &[c],
        &[&[&instance[..]]],
        rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(Halo2Error::Prove)?;
    Ok(transcript.finalize())
}

/// Verify a Halo2 proof of `circuit` for `(digest, binding)`.
pub fn verify(
    circuit: Circuit,
    proof: &[u8],
    digest: &[u8; WORD_BYTES],
    binding: &[u8; WORD_BYTES],
) -> Result<(), Halo2Error> {
    let instance = instance(digest, binding);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    verify_proof(
        params(),
        proving_key(circuit).get_vk(),
        SingleVerifier::new(params()),
        &[&[&instance[..]]],
        &mut transcript,
    )
    .map_err(Halo2Error::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    /// The constraints are satisfied by the true SHA3-256 digest of the
    /// domain and witness, and by nothing else.
    #[test]
    fn circuit_constraints_hold_exactly_for_the_true_digest() {
        let witness = [0x3c; WORD_BYTES];
        let binding = [0x5d; WORD_BYTES];
        let circuit = PreimageCircuit {
            domain: Circuit::Settlement.domain(),
            witness: Value::known(witness),
        };
        let honest = instance(&Circuit::Settlement.digest(&witness), &binding);
        MockProver::run(K, &circuit, vec![honest.clone()])
            .unwrap()
            .assert_satisfied();

        // One flipped digest bit is unsatisfiable.
        let mut wrong = honest;
        wrong[17] = Fp::ONE - wrong[17];
        assert!(
            MockProver::run(K, &circuit, vec![wrong])
                .unwrap()
                .verify()
                .is_err()
        );
    }
}
