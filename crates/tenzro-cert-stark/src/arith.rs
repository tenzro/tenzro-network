//! The lattice arithmetic of ML-DSA verification as lookup-connected
//! tables.
//!
//! A compact certificate reveals, for every signer, the challenge seed `c~`
//! and the high bits `w1`; the verifier checks `c~ = H(mu || w1Encode(w1))`
//! itself and derives the challenge `c` from `c~`. What remains, and what
//! these tables prove for each committee slot, is that some `z` with
//! `||z||_inf < gamma1 - beta` and some hint `h` with at most `omega` bits
//! give `UseHint(h, NTT^-1(A-hat . NTT(z) - NTT(c) . NTT(t1 2^d))) = w1`:
//!
//! - [`Table::Source`] puts `z` on the wire bus, norm-checked;
//! - [`Table::Forward`] runs the forward NTT of each `z` polynomial and
//!   [`Table::Inverse`] the inverse NTT of each row, one butterfly per row,
//!   reading and writing the wire bus by (slot, polynomial, stage, index)
//!   tags;
//! - [`Table::Combine`] forms each row's NTT-domain sum against the key's
//!   matrix (preprocessed per epoch, already scaled by `256^-1` so the
//!   inverse NTT needs no final scaling) plus the public challenge term, then
//!   reduces the matching `w'_approx` coefficient to canonical form,
//!   decomposes it, applies the hint and counts hint bits;
//! - [`Table::Range`] is the 16-bit range table every bound is looked up in.
//!
//! The public values (challenge term and `w1`) enter [`Table::Combine`] as
//! one periodic column the verifier evaluates itself. A slot that did not
//! sign has all-zero public values and proves the zero signature.
//!
//! Values between stages are kept below about `2^23` rather than below `q`:
//! every congruence holds mod `q` and nothing wraps in Goldilocks. Only
//! `w'_approx` is reduced to `[0, q)`, where Decompose needs it canonical.

use std::sync::Arc;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder, SymbolicExpression};
use p3_air::{Air, AirBuilder, BaseAir, BaseLeaf, PeriodicAirBuilder, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::LookupAir;
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_matrix::dense::RowMajorMatrix;

use super::mldsa::{self, BETA, GAMMA1, GAMMA2, K, L, N, OMEGA, Poly, Q};

/// Name of the bus carrying polynomial coefficients between tables.
pub const WIRE: &str = "wire";
/// Name of the bus every 16-bit range check is looked up on.
pub const RANGE: &str = "range16";

/// NTT stages per polynomial (the input plus eight layers).
const STAGES: u64 = 9;
/// Polynomial ids on the wire: the five `z`, then the six rows of `w`.
const POLY_W0: u64 = L as u64;
const POLYS: u64 = (L + K) as u64;
/// Shift of `w1` in the packed public value `challenge term + 2^24 w1`.
const W1_SHIFT: u64 = 1 << 24;

/// The wire tag of coefficient `idx` of polynomial `poly` at `stage` in slot
/// `slot`.
fn tag(slot: usize, poly: u64, stage: u64, idx: usize) -> u64 {
    ((slot as u64 * POLYS + poly) * STAGES + stage) * N as u64 + idx as u64
}

/// `256^-1 mod q`.
const N_INV: u64 = 8_347_681;

fn mulq(a: u64, b: u64) -> u64 {
    a * b % Q as u64
}

/// Splits `v < 2^(16 + hi_bits)` into its low 16 bits and the rest, the
/// rest shifted so that a 16-bit range check bounds it.
fn limbs(v: u64, hi_bits: u32) -> (u64, u64) {
    debug_assert!(v < 1 << (16 + hi_bits), "{v} exceeds {} bits", 16 + hi_bits);
    (v & 0xffff, (v >> 16) << (16 - hi_bits))
}

fn padded(rows: usize) -> usize {
    rows.next_power_of_two().max(16)
}

// ---------------------------------------------------------------------------
// The butterfly schedule.
// ---------------------------------------------------------------------------

/// One butterfly of one NTT pass.
#[derive(Clone, Copy, Debug)]
struct Butterfly {
    zeta: u64,
    layer: u64,
    j: usize,
    len: usize,
}

/// The 8 x 128 butterflies of FIPS 204 Algorithm 41 (`inverse = false`) or
/// 42 (`inverse = true`), in execution order.
fn schedule(inverse: bool) -> Vec<Butterfly> {
    let zetas: Vec<u64> = (0..N)
        .map(|k| {
            let brv = (k as u8).reverse_bits() as u64;
            let mut r = 1u64;
            for _ in 0..brv {
                r = mulq(r, 1753);
            }
            r
        })
        .collect();
    let mut out = Vec::with_capacity(1024);
    if inverse {
        let mut m = N;
        let mut len = 1usize;
        let mut layer = 0u64;
        while len < N {
            let mut start = 0;
            while start < N {
                m -= 1;
                let zeta = Q as u64 - zetas[m];
                for j in start..start + len {
                    out.push(Butterfly {
                        zeta,
                        layer,
                        j,
                        len,
                    });
                }
                start += 2 * len;
            }
            len *= 2;
            layer += 1;
        }
    } else {
        let mut m = 0usize;
        let mut len = 128usize;
        let mut layer = 0u64;
        while len >= 1 {
            let mut start = 0;
            while start < N {
                m += 1;
                let zeta = zetas[m];
                for j in start..start + len {
                    out.push(Butterfly {
                        zeta,
                        layer,
                        j,
                        len,
                    });
                }
                start += 2 * len;
            }
            len /= 2;
            layer += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tables.
// ---------------------------------------------------------------------------

/// One table of the arithmetic proof.
#[derive(Clone, Debug)]
pub enum Table {
    /// 16-bit range table.
    Range(RangeTable),
    /// Forward NTT butterflies over `z`.
    Forward(ButterflyTable),
    /// Inverse NTT butterflies over each row of `w`.
    Inverse(ButterflyTable),
    /// `z`.
    Source(SourceTable),
    /// NTT-domain sums, canonical reduction, Decompose and UseHint.
    Combine(CombineTable),
}

/// The 16-bit range table: row `i` holds `i` and how many lookups hit it.
#[derive(Clone, Debug, Default)]
pub struct RangeTable {
    num_lookups: usize,
}

/// Butterfly rows for `slots` slots.
#[derive(Clone, Debug)]
pub struct ButterflyTable {
    slots: usize,
    inverse: bool,
    height: usize,
    num_lookups: usize,
}

/// Source rows for `slots` slots.
#[derive(Clone, Debug)]
pub struct SourceTable {
    slots: usize,
    height: usize,
    num_lookups: usize,
}

/// Combine rows: the key's matrix per slot and the packed public values.
#[derive(Clone, Debug)]
pub struct CombineTable {
    /// Per slot, `256^-1 * A-hat[r][s][i] mod q`, indexed `[r][s][i]`.
    constants: Arc<Vec<[[Poly; L]; K]>>,
    /// Per row, `challenge term + 2^24 w1`; zero on padding rows.
    public: Vec<u64>,
    height: usize,
    num_lookups: usize,
}

impl ButterflyTable {
    fn polys(&self) -> usize {
        if self.inverse { K } else { L }
    }
}

/// The key constants of `keys`, one slot each.
pub fn key_constants(keys: &[mldsa::PublicKey]) -> Vec<[[Poly; L]; K]> {
    keys.iter()
        .map(|key| {
            let mut ka = [[[0u32; N]; L]; K];
            for (r, row) in ka.iter_mut().enumerate() {
                for (s, poly) in row.iter_mut().enumerate() {
                    let hat = mldsa::ntt(key.a[r][s]);
                    for i in 0..N {
                        poly[i] = mulq(N_INV, hat[i] as u64) as u32;
                    }
                }
            }
            ka
        })
        .collect()
}

/// The packed public value of coefficient `i` of row `r`: the scaled
/// challenge term at NTT index `i` plus `2^24 w1[r][i]`.
pub fn packed_public(challenge_term: &[Poly; K], w1: &[Poly; K], r: usize, i: usize) -> u64 {
    let ct = mulq(N_INV, (Q - challenge_term[r][i]) as u64 % Q as u64);
    ct + W1_SHIFT * w1[r][i] as u64
}

/// The tables for `slots` committee slots with the given key constants and
/// per-row packed public values (see [`packed_public`]; rows in slot, row,
/// index order, zero for a slot that did not sign).
pub fn tables(constants: Arc<Vec<[[Poly; L]; K]>>, public_rows: &[u64]) -> Vec<Table> {
    let slots = constants.len();
    let combine_height = padded(slots * K * N);
    let mut public = vec![0u64; combine_height];
    public[..public_rows.len()].copy_from_slice(public_rows);
    vec![
        Table::Range(RangeTable::default()),
        Table::Forward(ButterflyTable {
            slots,
            inverse: false,
            height: padded(slots * L * 1024),
            num_lookups: 0,
        }),
        Table::Inverse(ButterflyTable {
            slots,
            inverse: true,
            height: padded(slots * K * 1024),
            num_lookups: 0,
        }),
        Table::Source(SourceTable {
            slots,
            height: padded(slots * L * N),
            num_lookups: 0,
        }),
        Table::Combine(CombineTable {
            constants,
            public,
            height: combine_height,
            num_lookups: 0,
        }),
    ]
}

impl Table {
    /// Rows of this table.
    pub fn height(&self) -> usize {
        match self {
            Self::Range(_) => 1 << 16,
            Self::Forward(t) | Self::Inverse(t) => t.height,
            Self::Source(t) => t.height,
            Self::Combine(t) => t.height,
        }
    }
}

// Butterfly main columns.
const B_A: usize = 0;
const B_B: usize = 1;
const B_X: usize = 2;
const B_T: usize = 3;
const B_KT: usize = 4;
const B_S1: usize = 5;
const B_S2: usize = 6;
const B_A2: usize = 7;
const B_B2: usize = 8;
const B_LIMBS: usize = 9; // lo/hi pairs for x, t, kt, a2, b2
const B_WIDTH: usize = B_LIMBS + 10;
// Butterfly preprocessed columns.
const BP_ZETA: usize = 0;
const BP_TAG_A: usize = 1;
const BP_TAG_B: usize = 2;
const BP_TAG_A2: usize = 3;
const BP_TAG_B2: usize = 4;
const BP_ACTIVE: usize = 5;
const BP_MULT_OUT: usize = 6;
const BP_WIDTH: usize = 7;
/// Bits above the low 16 each butterfly value may use.
const HI7: u32 = 7;

// Source main columns: value on the wire, centered value, negative flag,
// the two norm slacks.
const S_V: usize = 0;
const S_C: usize = 1;
const S_NEG: usize = 2;
const S_N1: usize = 3;
const S_N2: usize = 4;
const S_LIMBS: usize = 5; // lo/hi for n1, n2
const S_WIDTH: usize = S_LIMBS + 4;
const SP_TAG: usize = 0;
const SP_ACTIVE: usize = 1;
const SP_WIDTH: usize = 2;
/// Bound on a `z` coefficient's magnitude.
const Z_BOUND: i64 = (GAMMA1 - BETA - 1) as i64;

// Combine main columns.
const C_Z: usize = 0; // five zhat values
const C_CT: usize = C_Z + L; // scaled challenge term
const C_V: usize = C_CT + 1;
const C_K: usize = C_V + 1;
const C_W: usize = C_K + 1;
const C_U: usize = C_W + 1; // high bits before the edge case
const C_E: usize = C_U + 1; // edge flag
const C_R0: usize = C_E + 1; // centered low bits, stored shifted by GAMMA2 - 1
const C_H: usize = C_R0 + 1;
const C_G: usize = C_H + 1; // effective low bits positive
const C_M: usize = C_G + 1; // wrap of the hinted high bits: -1, 0 or 1
const C_W1: usize = C_M + 1;
const C_Y: usize = C_W1 + 1; // |effective low bits| certificate for g
const C_COUNT: usize = C_Y + 1; // running hint count in the slot
const C_LIMBS: usize = C_COUNT + 1;
/// Limb pairs, in order: v, k, ct, w, q-1-w, r0s, 2g2-1-r0s, y.
const C_HI: [u32; 8] = [HI7, HI_K, HI7, HI7, HI7, 3, 3, 3];
const C_WIDTH: usize = C_LIMBS + 2 * C_HI.len();
/// Bits above the low 16 of a combination quotient (the sum is below 2^50).
const HI_K: u32 = 11;
// Combine preprocessed columns.
const CP_A: usize = 0; // five matrix constants
const CP_TAG_Z: usize = CP_A + L; // five
const CP_TAG_OUT: usize = CP_TAG_Z + L;
const CP_TAG_W: usize = CP_TAG_OUT + 1;
const CP_FIRST: usize = CP_TAG_W + 1;
const CP_LAST: usize = CP_FIRST + 1;
const CP_ACTIVE: usize = CP_LAST + 1;
const CP_WIDTH: usize = CP_ACTIVE + 1;

impl<F: Field> BaseAir<F> for Table {
    fn width(&self) -> usize {
        match self {
            Self::Range(_) => 1,
            Self::Forward(_) | Self::Inverse(_) => B_WIDTH,
            Self::Source(_) => S_WIDTH,
            Self::Combine(_) => C_WIDTH,
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(match self {
            Self::Range(_) => RowMajorMatrix::new((0..1u64 << 16).map(F::from_u64).collect(), 1),
            Self::Forward(t) | Self::Inverse(t) => t.preprocessed(),
            Self::Source(t) => t.preprocessed(),
            Self::Combine(t) => t.preprocessed(),
        })
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Combine(_) => vec![CP_FIRST],
            _ => vec![],
        }
    }

    fn num_periodic_columns(&self) -> usize {
        match self {
            Self::Combine(_) => 1,
            _ => 0,
        }
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        match self {
            Self::Combine(t) => vec![t.public.iter().map(|v| F::from_u64(*v)).collect()],
            _ => vec![],
        }
    }
}

impl ButterflyTable {
    fn preprocessed<F: Field>(&self) -> RowMajorMatrix<F> {
        let mut m = vec![F::ZERO; self.height * BP_WIDTH];
        let sched = schedule(self.inverse);
        let (first_poly, final_mult) = if self.inverse {
            (POLY_W0, 1)
        } else {
            (0, K as u64)
        };
        let mut row = 0;
        for slot in 0..self.slots {
            for p in 0..self.polys() as u64 {
                let poly = first_poly + p;
                for b in &sched {
                    let r = &mut m[row * BP_WIDTH..(row + 1) * BP_WIDTH];
                    let (s_in, s_out) = (b.layer, b.layer + 1);
                    r[BP_ZETA] = F::from_u64(b.zeta);
                    r[BP_TAG_A] = F::from_u64(tag(slot, poly, s_in, b.j));
                    r[BP_TAG_B] = F::from_u64(tag(slot, poly, s_in, b.j + b.len));
                    r[BP_TAG_A2] = F::from_u64(tag(slot, poly, s_out, b.j));
                    r[BP_TAG_B2] = F::from_u64(tag(slot, poly, s_out, b.j + b.len));
                    r[BP_ACTIVE] = F::ONE;
                    // The last forward stage feeds one combine row per row
                    // of `w`; the last inverse stage feeds one.
                    r[BP_MULT_OUT] = F::from_u64(if s_out == STAGES - 1 { final_mult } else { 1 });
                    row += 1;
                }
            }
        }
        RowMajorMatrix::new(m, BP_WIDTH)
    }
}

impl SourceTable {
    fn preprocessed<F: Field>(&self) -> RowMajorMatrix<F> {
        let mut m = vec![F::ZERO; self.height * SP_WIDTH];
        let mut row = 0;
        for slot in 0..self.slots {
            for poly in 0..L as u64 {
                for i in 0..N {
                    let r = &mut m[row * SP_WIDTH..(row + 1) * SP_WIDTH];
                    r[SP_TAG] = F::from_u64(tag(slot, poly, 0, i));
                    r[SP_ACTIVE] = F::ONE;
                    row += 1;
                }
            }
        }
        RowMajorMatrix::new(m, SP_WIDTH)
    }
}

impl CombineTable {
    #[allow(clippy::needless_range_loop)] // r, s and i index the constant table, the trace row and the tags together
    fn preprocessed<F: Field>(&self) -> RowMajorMatrix<F> {
        let mut m = vec![F::ZERO; self.height * CP_WIDTH];
        let mut row = 0;
        for (slot, constants) in self.constants.iter().enumerate() {
            for r in 0..K {
                for i in 0..N {
                    let p = &mut m[row * CP_WIDTH..(row + 1) * CP_WIDTH];
                    for s in 0..L {
                        p[CP_A + s] = F::from_u64(constants[r][s][i] as u64);
                        p[CP_TAG_Z + s] = F::from_u64(tag(slot, s as u64, STAGES - 1, i));
                    }
                    p[CP_TAG_OUT] = F::from_u64(tag(slot, POLY_W0 + r as u64, 0, i));
                    p[CP_TAG_W] = F::from_u64(tag(slot, POLY_W0 + r as u64, STAGES - 1, i));
                    p[CP_FIRST] = F::from_bool(r == 0 && i == 0);
                    p[CP_LAST] = F::from_bool(r == K - 1 && i == N - 1);
                    p[CP_ACTIVE] = F::ONE;
                    row += 1;
                }
            }
        }
        // Padding rows start a slot of their own so the count never carries
        // into them.
        for r in row..self.height {
            m[r * CP_WIDTH + CP_FIRST] = F::ONE;
        }
        RowMajorMatrix::new(m, CP_WIDTH)
    }
}

/// Asserts `v = lo + 2^hi_bits * hs` for the limb pair `(lo, hs)` starting
/// at `at`. Both limbs are range-checked to 16 bits, so `v` is a
/// non-negative integer below `2^16 + 2^(16 + hi_bits)`: non-negative is
/// what the constraints rely on; the upper end keeps sums from wrapping.
fn recompose<AB: AirBuilder>(
    builder: &mut AB,
    v: AB::Expr,
    row: &[AB::Var],
    at: usize,
    hi_bits: u32,
) {
    let lo: AB::Expr = row[at].into();
    let hs: AB::Expr = row[at + 1].into();
    builder.assert_eq(v, lo + hs * AB::Expr::from_u64(1 << hi_bits));
}

impl<AB: PeriodicAirBuilder> Air<AB> for Table
where
    AB::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Range(_) => {}
            Self::Forward(_) => eval_butterfly(builder, false),
            Self::Inverse(_) => eval_butterfly(builder, true),
            Self::Source(_) => eval_source(builder),
            Self::Combine(_) => eval_combine(builder),
        }
    }
}

fn eval_butterfly<AB: AirBuilder>(builder: &mut AB, inverse: bool)
where
    AB::F: PrimeField64,
{
    let main = builder.main();
    let row: Vec<AB::Var> = main.current_slice().to_vec();
    let pre: Vec<AB::Var> = builder.preprocessed().current_slice().to_vec();
    let q = AB::Expr::from_u64(Q as u64);
    let v = |c: usize| -> AB::Expr { row[c].into() };
    let zeta: AB::Expr = pre[BP_ZETA].into();
    builder.assert_bool(v(B_S1));
    builder.assert_bool(v(B_S2));
    // zeta * x = t + q * kt
    builder.assert_eq(zeta * v(B_X), v(B_T) + q.clone() * v(B_KT));
    if inverse {
        // x = a - b + q s2, a2 = a + b - q s1, b2 = t
        builder.assert_eq(v(B_X), v(B_A) - v(B_B) + q.clone() * v(B_S2));
        builder.assert_eq(v(B_A2), v(B_A) + v(B_B) - q * v(B_S1));
        builder.assert_eq(v(B_B2), v(B_T));
    } else {
        // x = b, a2 = a + t - q s1, b2 = a - t + q s2
        builder.assert_eq(v(B_X), v(B_B));
        builder.assert_eq(v(B_A2), v(B_A) + v(B_T) - q.clone() * v(B_S1));
        builder.assert_eq(v(B_B2), v(B_A) - v(B_T) + q * v(B_S2));
    }
    for (k, col) in [B_X, B_T, B_KT, B_A2, B_B2].into_iter().enumerate() {
        recompose(builder, v(col), &row, B_LIMBS + 2 * k, HI7);
    }
}

fn eval_source<AB: AirBuilder>(builder: &mut AB)
where
    AB::F: PrimeField64,
{
    let main = builder.main();
    let row: Vec<AB::Var> = main.current_slice().to_vec();
    let pre: Vec<AB::Var> = builder.preprocessed().current_slice().to_vec();
    let v = |c: usize| -> AB::Expr { row[c].into() };
    let active: AB::Expr = pre[SP_ACTIVE].into();
    let q = AB::Expr::from_u64(Q as u64);
    builder.assert_bool(v(S_NEG));
    // The wire value is the centered value lifted to [0, q + bound).
    builder.assert_eq(v(S_V), v(S_C) + q * v(S_NEG));
    // |zc| <= bound, via zc + bound and bound - zc both non-negative.
    let bound = AB::Expr::from_u64(Z_BOUND as u64);
    builder.assert_zero(active.clone() * (v(S_N1) - v(S_C) - bound.clone()));
    builder.assert_zero(active * (v(S_N2) - bound + v(S_C)));
    recompose(builder, v(S_N1), &row, S_LIMBS, 4);
    recompose(builder, v(S_N2), &row, S_LIMBS + 2, 4);
}

fn eval_combine<AB: PeriodicAirBuilder>(builder: &mut AB)
where
    AB::F: PrimeField64,
{
    let main = builder.main();
    let row: Vec<AB::Var> = main.current_slice().to_vec();
    let next: Vec<AB::Var> = main.next_slice().to_vec();
    let pre: Vec<AB::Var> = builder.preprocessed().current_slice().to_vec();
    let pre_next_first: AB::Expr = builder.preprocessed().next_slice()[CP_FIRST].into();
    let public: AB::Expr = builder.periodic_values()[0].into();
    let v = |c: usize| -> AB::Expr { row[c].into() };
    let one = AB::Expr::ONE;
    let q = AB::Expr::from_u64(Q as u64);

    // The NTT-domain sum: A-hat . zhat + ct = v + q k.
    let mut sum = v(C_CT);
    for s in 0..L {
        sum += AB::Expr::from(pre[CP_A + s]) * v(C_Z + s);
    }
    builder.assert_eq(sum, v(C_V) + q * v(C_K));
    // The public value: ct + 2^24 w1, with ct below 2^24 and w1 below 16,
    // so both halves are determined.
    builder.assert_eq(public, v(C_CT) + AB::Expr::from_u64(W1_SHIFT) * v(C_W1));

    // Hint count: starts at h on a slot's first row and accumulates; the
    // omega bound is a lookup on the slot's last row.
    let first: AB::Expr = pre[CP_FIRST].into();
    builder.when(first).assert_eq(v(C_COUNT), v(C_H));
    builder.when_transition().assert_zero(
        (one.clone() - pre_next_first)
            * (AB::Expr::from(next[C_COUNT]) - v(C_COUNT) - AB::Expr::from(next[C_H])),
    );

    let alpha = AB::Expr::from_u64(2 * GAMMA2 as u64);
    let g2m1 = AB::Expr::from_u64(GAMMA2 as u64 - 1);
    let hi = |k: usize| C_HI[k];
    let limb = |k: usize| C_LIMBS + 2 * k;
    recompose(builder, v(C_V), &row, limb(0), hi(0));
    recompose(builder, v(C_K), &row, limb(1), hi(1));
    recompose(builder, v(C_CT), &row, limb(2), hi(2));
    let active: AB::Expr = pre[CP_ACTIVE].into();
    let mut b = builder.when(active);
    for c in [C_E, C_H, C_G] {
        b.assert_bool(v(c));
    }
    // 0 <= w <= q - 1: both w and q - 1 - w are non-negative.
    recompose(&mut b, v(C_W), &row, limb(3), hi(3));
    recompose(
        &mut b,
        AB::Expr::from_u64(Q as u64 - 1) - v(C_W),
        &row,
        limb(4),
        hi(4),
    );
    // w = (u + 16 e) alpha + r0 with r0 = r0s - (gamma2 - 1) and
    // 0 <= r0s <= 2 gamma2 - 1, so r0 is w's centered residue.
    let r0 = v(C_R0) - g2m1;
    b.assert_eq(
        v(C_W),
        (v(C_U) + AB::Expr::from_u64(16) * v(C_E)) * alpha + r0.clone(),
    );
    recompose(&mut b, v(C_R0), &row, limb(5), hi(5));
    recompose(
        &mut b,
        AB::Expr::from_u64(2 * GAMMA2 as u64 - 1) - v(C_R0),
        &row,
        limb(6),
        hi(6),
    );
    // u is zero at the edge (u and 15 - u are range-checked by lookup).
    b.assert_zero(v(C_E) * v(C_U));
    // Effective low bits: at the edge, r0 - 1.
    let r0e = r0 - v(C_E);
    // g = [r0e > 0]: y = g (r0e - 1) + (1 - g)(-r0e) is non-negative.
    b.assert_eq(
        v(C_Y),
        v(C_G) * (r0e.clone() - one.clone()) - (one.clone() - v(C_G)) * r0e,
    );
    recompose(&mut b, v(C_Y), &row, limb(7), hi(7));
    // w1 = r1e + h (2g - 1) + 16 m with m in {-1, 0, 1}; w1 and 15 - w1 are
    // range-checked by lookup, so w1 is (r1e + h (2g - 1)) mod 16.
    let m = v(C_M);
    b.assert_zero(m.clone() * (m.clone() - one.clone()) * (m.clone() + one.clone()));
    b.assert_eq(
        v(C_W1),
        v(C_U) + v(C_H) * (AB::Expr::from_u64(2) * v(C_G) - one) + AB::Expr::from_u64(16) * m,
    );
}

// ---------------------------------------------------------------------------
// Lookups.
// ---------------------------------------------------------------------------

fn var<F: Field>(v: p3_air::symbolic::SymbolicVariable<F>) -> SymbolicExpression<F> {
    v.into()
}

fn constant<F: Field>(c: u64) -> SymbolicExpression<F> {
    SymbolicExpression::Leaf(BaseLeaf::Constant(F::from_u64(c)))
}

type Interaction<F> = (Vec<SymbolicExpression<F>>, SymbolicExpression<F>, Direction);

impl<F: Field> LookupAir<F> for Table {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let n = match self {
            Self::Range(t) => &mut t.num_lookups,
            Self::Forward(t) | Self::Inverse(t) => &mut t.num_lookups,
            Self::Source(t) => &mut t.num_lookups,
            Self::Combine(t) => &mut t.num_lookups,
        };
        let idx = *n;
        *n += 1;
        vec![idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Range(t) => t.num_lookups = 0,
            Self::Forward(t) | Self::Inverse(t) => t.num_lookups = 0,
            Self::Source(t) => t.num_lookups = 0,
            Self::Combine(t) => t.num_lookups = 0,
        }
        let layout = AirLayout {
            main_width: BaseAir::<F>::width(self),
            preprocessed_width: BaseAir::<F>::preprocessed_trace(self).map_or(0, |m| m.width),
            num_periodic_columns: BaseAir::<F>::num_periodic_columns(self),
            ..Default::default()
        };
        let b = SymbolicAirBuilder::<F>::new(layout);
        let main: Vec<SymbolicExpression<F>> =
            b.main().current_slice().iter().map(|x| var(*x)).collect();
        let pre: Vec<SymbolicExpression<F>> = b
            .preprocessed()
            .current_slice()
            .iter()
            .map(|x| var(*x))
            .collect();
        let mut lookups = Vec::new();
        // Range checks in pairs: each pair of limb columns is one lookup.
        let range_pairs = |first: usize,
                           pairs: usize,
                           active: SymbolicExpression<F>|
         -> Vec<[Interaction<F>; 2]> {
            (0..pairs)
                .map(|k| {
                    [
                        (
                            vec![main[first + 2 * k].clone()],
                            active.clone(),
                            Direction::Receive,
                        ),
                        (
                            vec![main[first + 2 * k + 1].clone()],
                            active.clone(),
                            Direction::Receive,
                        ),
                    ]
                })
                .collect()
        };
        match self {
            Self::Range(_) => {
                let l = LookupAir::register_lookup(
                    self,
                    Kind::Global(RANGE.into()),
                    &[(vec![pre[0].clone()], main[0].clone(), Direction::Send)],
                );
                lookups.push(l);
            }
            Self::Forward(_) | Self::Inverse(_) => {
                let act = pre[BP_ACTIVE].clone();
                let mult = pre[BP_MULT_OUT].clone();
                let wire_in = [
                    (
                        vec![pre[BP_TAG_A].clone(), main[B_A].clone()],
                        act.clone(),
                        Direction::Receive,
                    ),
                    (
                        vec![pre[BP_TAG_B].clone(), main[B_B].clone()],
                        act.clone(),
                        Direction::Receive,
                    ),
                ];
                let wire_out = [
                    (
                        vec![pre[BP_TAG_A2].clone(), main[B_A2].clone()],
                        mult.clone(),
                        Direction::Send,
                    ),
                    (
                        vec![pre[BP_TAG_B2].clone(), main[B_B2].clone()],
                        mult,
                        Direction::Send,
                    ),
                ];
                lookups.push(LookupAir::register_lookup(
                    self,
                    Kind::Global(WIRE.into()),
                    &wire_in,
                ));
                lookups.push(LookupAir::register_lookup(
                    self,
                    Kind::Global(WIRE.into()),
                    &wire_out,
                ));
                for pair in range_pairs(B_LIMBS, 5, act) {
                    lookups.push(LookupAir::register_lookup(
                        self,
                        Kind::Global(RANGE.into()),
                        &pair,
                    ));
                }
            }
            Self::Source(_) => {
                let act = pre[SP_ACTIVE].clone();
                lookups.push(LookupAir::register_lookup(
                    self,
                    Kind::Global(WIRE.into()),
                    &[(
                        vec![pre[SP_TAG].clone(), main[S_V].clone()],
                        act.clone(),
                        Direction::Send,
                    )],
                ));
                for pair in range_pairs(S_LIMBS, 2, act) {
                    lookups.push(LookupAir::register_lookup(
                        self,
                        Kind::Global(RANGE.into()),
                        &pair,
                    ));
                }
            }
            Self::Combine(_) => {
                let act = pre[CP_ACTIVE].clone();
                let mut ins: Vec<Interaction<F>> = (0..L)
                    .map(|s| {
                        (
                            vec![pre[CP_TAG_Z + s].clone(), main[C_Z + s].clone()],
                            act.clone(),
                            Direction::Receive,
                        )
                    })
                    .collect();
                ins.push((
                    vec![pre[CP_TAG_W].clone(), main[C_W].clone()],
                    act.clone(),
                    Direction::Receive,
                ));
                for chunk in ins.chunks(2) {
                    lookups.push(LookupAir::register_lookup(
                        self,
                        Kind::Global(WIRE.into()),
                        chunk,
                    ));
                }
                lookups.push(LookupAir::register_lookup(
                    self,
                    Kind::Global(WIRE.into()),
                    &[(
                        vec![pre[CP_TAG_OUT].clone(), main[C_V].clone()],
                        act.clone(),
                        Direction::Send,
                    )],
                ));
                for pair in range_pairs(C_LIMBS, C_HI.len(), act.clone()) {
                    lookups.push(LookupAir::register_lookup(
                        self,
                        Kind::Global(RANGE.into()),
                        &pair,
                    ));
                }
                // u and w1 lie in [0, 16): both they and 15 minus them are
                // non-negative 16-bit values.
                for col in [C_U, C_W1] {
                    let pair = [
                        (vec![main[col].clone()], act.clone(), Direction::Receive),
                        (
                            vec![constant::<F>(15) - main[col].clone()],
                            act.clone(),
                            Direction::Receive,
                        ),
                    ];
                    lookups.push(LookupAir::register_lookup(
                        self,
                        Kind::Global(RANGE.into()),
                        &pair,
                    ));
                }
                // At most omega hint bits: omega - count below 2^16 on a
                // slot's last row.
                let last = pre[CP_LAST].clone();
                let slack = constant::<F>(OMEGA as u64) - main[C_COUNT].clone();
                lookups.push(LookupAir::register_lookup(
                    self,
                    Kind::Global(RANGE.into()),
                    &[(vec![slack], last, Direction::Receive)],
                ));
            }
        }
        lookups
    }
}

// ---------------------------------------------------------------------------
// Witness generation.
// ---------------------------------------------------------------------------

/// One slot's private inputs: `z`, the hint bits and the challenge term
/// (all zero for a slot that did not sign).
pub struct SlotInput {
    /// Response, centered.
    pub z: [[i32; N]; L],
    /// Hint bits.
    pub h: [[bool; N]; K],
    /// `NTT(c) * NTT(t1 2^d)`, see [`mldsa::challenge_term`].
    pub challenge_term: [Poly; K],
}

impl SlotInput {
    /// The inputs of a slot that did not sign.
    pub fn absent() -> Self {
        Self {
            z: [[0; N]; L],
            h: [[false; N]; K],
            challenge_term: [[0; N]; K],
        }
    }
}

type G = Goldilocks;

fn g(v: u64) -> G {
    G::from_u64(v)
}

fn gi(v: i64) -> G {
    if v >= 0 {
        G::from_u64(v as u64)
    } else {
        -G::from_u64((-v) as u64)
    }
}

/// The traces of [`tables`] for `slots`, and each slot's `w1`.
pub fn traces(
    constants: &[[[Poly; L]; K]],
    slots: &[SlotInput],
) -> (Vec<RowMajorMatrix<G>>, Vec<[Poly; K]>) {
    let n = slots.len();
    let mut range_counts = vec![0u64; 1 << 16];
    let mut count = |x: u64| {
        range_counts[x as usize] += 1;
    };

    // Source rows, and the stage-0 values of every forward NTT.
    let src_height = padded(n * L * N);
    let mut src = vec![G::ZERO; src_height * S_WIDTH];
    let mut row = 0;
    let mut stage0: Vec<[Poly; L]> = Vec::with_capacity(n);
    for s in slots {
        let mut polys = [[0u32; N]; L];
        for (p, poly) in polys.iter_mut().enumerate() {
            for (i, coeff) in poly.iter_mut().enumerate() {
                let c = s.z[p][i] as i64;
                let neg = c < 0;
                let vq = (c + if neg { Q as i64 } else { 0 }) as u64;
                *coeff = vq as u32;
                let r = &mut src[row * S_WIDTH..(row + 1) * S_WIDTH];
                r[S_V] = g(vq);
                r[S_C] = gi(c);
                r[S_NEG] = G::from_bool(neg);
                let n1 = (c + Z_BOUND) as u64;
                let n2 = (Z_BOUND - c) as u64;
                let (l1, h1) = limbs(n1, 4);
                let (l2, h2) = limbs(n2, 4);
                r[S_N1] = g(n1);
                r[S_N2] = g(n2);
                r[S_LIMBS] = g(l1);
                r[S_LIMBS + 1] = g(h1);
                r[S_LIMBS + 2] = g(l2);
                r[S_LIMBS + 3] = g(h2);
                for x in [l1, h1, l2, h2] {
                    count(x);
                }
                row += 1;
            }
        }
        stage0.push(polys);
    }

    let fwd_height = padded(n * L * 1024);
    let inv_height = padded(n * K * 1024);
    let mut fwd_trace = vec![G::ZERO; fwd_height * B_WIDTH];
    let mut inv_trace = vec![G::ZERO; inv_height * B_WIDTH];
    let fwd = schedule(false);
    let inv = schedule(true);
    let butterfly = |trace: &mut [G],
                     row: usize,
                     count: &mut dyn FnMut(u64),
                     b: &Butterfly,
                     inverse: bool,
                     vals: &mut Poly| {
        let (a, bb) = (vals[b.j] as u64, vals[b.j + b.len] as u64);
        let (x, s2) = if inverse {
            let d = a as i64 - bb as i64;
            if d < 0 {
                ((d + Q as i64) as u64, 1u64)
            } else {
                (d as u64, 0u64)
            }
        } else {
            (bb, 0)
        };
        let prod = b.zeta * x;
        let (t, kt) = (prod % Q as u64, prod / Q as u64);
        let (a2, s1, b2, s2) = if inverse {
            let sum = a + bb;
            let s1 = (sum >= Q as u64) as u64;
            (sum - s1 * Q as u64, s1, t, s2)
        } else {
            let sum = a + t;
            let s1 = (sum >= Q as u64) as u64;
            let diff = a as i64 - t as i64;
            let s2 = (diff < 0) as u64;
            (
                sum - s1 * Q as u64,
                s1,
                (diff + s2 as i64 * Q as i64) as u64,
                s2,
            )
        };
        let r = &mut trace[row * B_WIDTH..(row + 1) * B_WIDTH];
        for (c, val) in [
            (B_A, a),
            (B_B, bb),
            (B_X, x),
            (B_T, t),
            (B_KT, kt),
            (B_S1, s1),
            (B_S2, s2),
            (B_A2, a2),
            (B_B2, b2),
        ] {
            r[c] = g(val);
        }
        for (k, val) in [x, t, kt, a2, b2].into_iter().enumerate() {
            let (lo, hi) = limbs(val, HI7);
            r[B_LIMBS + 2 * k] = g(lo);
            r[B_LIMBS + 2 * k + 1] = g(hi);
            count(lo);
            count(hi);
        }
        vals[b.j] = a2 as u32;
        vals[b.j + b.len] = b2 as u32;
    };

    let combine_height = padded(n * K * N);
    let mut comb = vec![G::ZERO; combine_height * C_WIDTH];
    let mut w1_out = Vec::with_capacity(n);
    let (mut frow, mut irow, mut crow) = (0, 0, 0);
    for (slot, s) in slots.iter().enumerate() {
        let mut hats = stage0[slot];
        for vals in hats.iter_mut() {
            for b in &fwd {
                butterfly(&mut fwd_trace, frow, &mut count, b, false, vals);
                frow += 1;
            }
        }
        // The NTT-domain sums of every row, then each row's inverse NTT.
        let mut sums = [[0u32; N]; K];
        let mut combos: Vec<[u64; 3]> = Vec::with_capacity(K * N);
        for r in 0..K {
            for i in 0..N {
                let ct = mulq(N_INV, (Q - s.challenge_term[r][i]) as u64 % Q as u64);
                let mut sum = ct;
                for (sidx, hat) in hats.iter().enumerate() {
                    sum += constants[slot][r][sidx][i] as u64 * hat[i] as u64;
                }
                sums[r][i] = (sum % Q as u64) as u32;
                combos.push([ct, sum % Q as u64, sum / Q as u64]);
            }
        }
        let mut w_approx = sums;
        for vals in w_approx.iter_mut() {
            for b in &inv {
                butterfly(&mut inv_trace, irow, &mut count, b, true, vals);
                irow += 1;
            }
        }
        let mut w1 = [[0u32; N]; K];
        let mut hint_count = 0u64;
        for r in 0..K {
            for i in 0..N {
                let [ct, v, k] = combos[r * N + i];
                let w = w_approx[r][i];
                // The centered residue before Decompose's edge adjustment:
                // w = (u + 16 e) alpha + r0raw.
                let alpha = 2 * GAMMA2 as i32;
                let mut r0raw = (w as i32).rem_euclid(alpha);
                if r0raw > alpha / 2 {
                    r0raw -= alpha;
                }
                let edge = w as i32 - r0raw == Q as i32 - 1;
                let (u, e) = if edge {
                    (0u64, 1u64)
                } else {
                    (((w as i32 - r0raw) / alpha) as u64, 0u64)
                };
                let r0e = if edge { r0raw - 1 } else { r0raw };
                debug_assert_eq!(mldsa::decompose(w), (u as u32, r0e));
                let h = s.h[r][i];
                let gpos = r0e > 0;
                let y = (if gpos { r0e - 1 } else { -r0e }) as u64;
                let w1c = mldsa::use_hint(h, w) as u64;
                let m = w1c as i64 - u as i64 - if h { if gpos { 1 } else { -1 } } else { 0 };
                debug_assert!(m % 16 == 0 && m.abs() <= 16);
                w1[r][i] = w1c as u32;
                hint_count += h as u64;
                let d = &mut comb[crow * C_WIDTH..(crow + 1) * C_WIDTH];
                for (sidx, hat) in hats.iter().enumerate() {
                    d[C_Z + sidx] = g(hat[i] as u64);
                }
                let r0s = (r0raw + GAMMA2 as i32 - 1) as u64;
                d[C_CT] = g(ct);
                d[C_V] = g(v);
                d[C_K] = g(k);
                d[C_W] = g(w as u64);
                d[C_U] = g(u);
                d[C_E] = g(e);
                d[C_R0] = g(r0s);
                d[C_H] = G::from_bool(h);
                d[C_G] = G::from_bool(gpos);
                d[C_M] = gi(m / 16);
                d[C_W1] = g(w1c);
                d[C_Y] = g(y);
                d[C_COUNT] = g(hint_count);
                let values = [
                    v,
                    k,
                    ct,
                    w as u64,
                    Q as u64 - 1 - w as u64,
                    r0s,
                    2 * GAMMA2 as u64 - 1 - r0s,
                    y,
                ];
                for (idx, val) in values.into_iter().enumerate() {
                    let (lo, hi) = limbs(val, C_HI[idx]);
                    d[C_LIMBS + 2 * idx] = g(lo);
                    d[C_LIMBS + 2 * idx + 1] = g(hi);
                    count(lo);
                    count(hi);
                }
                for x in [u, 15 - u, w1c, 15 - w1c] {
                    count(x);
                }
                crow += 1;
            }
        }
        count(OMEGA as u64 - hint_count);
        w1_out.push(w1);
    }

    // Padding rows of every table are all zero, which satisfies every
    // constraint.
    let range_trace = RowMajorMatrix::new(range_counts.iter().map(|c| g(*c)).collect(), 1);
    let traces = vec![
        range_trace,
        RowMajorMatrix::new(fwd_trace, B_WIDTH),
        RowMajorMatrix::new(inv_trace, B_WIDTH),
        RowMajorMatrix::new(src, S_WIDTH),
        RowMajorMatrix::new(comb, C_WIDTH),
    ];
    (traces, w1_out)
}
