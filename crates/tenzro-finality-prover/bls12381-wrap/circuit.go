// SPDX-License-Identifier: Apache-2.0

// Package main wraps a Tenzro finality proof for chains that verify Groth16
// over BLS12-381 but not over BN254.
//
// A Tenzro finality proof is a Groth16 proof over BN254 that RISC Zero's
// recursion circuit accepted a receipt of the finality program. The wrap
// circuit, over BLS12-381, verifies that proof with BN254 arithmetic emulated
// in its own field. Its public inputs are the two 128-bit halves of the
// receipt claim, so a chain recomputes them from the journal exactly as the
// BN254 clients do and checks one BLS12-381 pairing equation.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// RISC Zero's recursion circuit parameters the finality proofs are made under.
var (
	controlRoot    = mustHex("a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56")
	bn254ControlID = mustHex("04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0")
	postState      = mustHex("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2")
	selector       = []byte{0x73, 0xc4, 0x57, 0xba}
)

// The recursion circuit's Groth16 verifying key: alpha (G1), beta, gamma and
// delta (G2, in the precompile order x_im, x_re, y_im, y_re) and the input
// commitments IC0..IC5 (G1).
var (
	vkAlpha = [2]string{
		"20491192805390485299153009773594534940189261866228447918068658471970481763042",
		"9383485363053290200918347156157836566562967994039712273449902621266178545958",
	}
	vkBeta = [4]string{
		"4252822878758300859123897981450591353533073413197771768651442665752259397132",
		"6375614351688725206403948262868962793625744043794305715222011528459656738731",
		"21847035105528745403288232691147584728191162732299865338377159692350059136679",
		"10505242626370262277552901082094356697409835680220590971873171140371331206856",
	}
	vkGamma = [4]string{
		"11559732032986387107991004021392285783925812861821192530917403151452391805634",
		"10857046999023057135944570762232829481370756359578518086990519993285655852781",
		"4082367875863433681332203403145435568316851327593401208105741076214120093531",
		"8495653923123431417604973247489272438418190587263600148770280649306958101930",
	}
	vkDelta = [4]string{
		"1668323501672964604911431804142266013250380587483576094566949227275849579036",
		"12043754404802191763554326994664886008979042643626290185762540825416902247219",
		"7710631539206257456743780535472368339139328733484942210876916214502466455394",
		"13740680757317479711909903993315946540841369848973133181051452051592786724563",
	}
	vkIC = [6][2]string{
		{"8446592859352799428420270221449902464741693648963397251242447530457567083492", "1064796367193003797175961162477173481551615790032213185848276823815288302804"},
		{"3179835575189816632597428042194253779818690147323192973511715175294048485951", "20895841676865356752879376687052266198216014795822152491318012491767775979074"},
		{"5332723250224941161709478398807683311971555792614491788690328996478511465287", "21199491073419440416471372042641226693637837098357067793586556692319371762571"},
		{"12457994489566736295787256452575216703923664299075106359829199968023158780583", "19706766271952591897761291684837117091856807401404423804318744964752784280790"},
		{"19617808913178163826953378459323299110911217259216006187355745713323154132237", "21663537384585072695701846972542344484111393047775983928357046779215877070466"},
		{"6834578911681792552110317589222010969491336870276623105249474534788043166867", "15060583660288623605191393599883223885678013570733629274538391874953353488393"},
	}
)

type (
	innerProof = stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	innerVK    = stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
)

// Wrap is the wrap circuit: the BN254 proof is private, the claim halves are
// public, and the recursion circuit's verifying key is a constant.
type Wrap struct {
	Proof   innerProof
	ClaimLo frontend.Variable `gnark:",public"`
	ClaimHi frontend.Variable `gnark:",public"`
	vk      innerVK           `gnark:"-"`
}

// Define checks the BN254 proof against the public inputs the recursion
// circuit takes: the control root's halves, the claim's halves (each below
// 2^128) and the BN254 control id.
func (c *Wrap) Define(api frontend.API) error {
	fr, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	c0, c1 := split(controlRoot)
	public := []emulated.Element[sw_bn254.ScalarField]{
		*fr.NewElement(c0),
		*fr.NewElement(c1),
		*fr.FromBits(api.ToBinary(c.ClaimLo, 128)...),
		*fr.FromBits(api.ToBinary(c.ClaimHi, 128)...),
		*fr.NewElement(new(big.Int).SetBytes(bn254ControlID)),
	}
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	return verifier.AssertProof(c.vk, c.Proof, stdgroth16.Witness[sw_bn254.ScalarField]{Public: public}, stdgroth16.WithSubgroupCheck())
}

// NewCircuit is the circuit with its constant verifying key, for compiling.
func NewCircuit() (*Wrap, error) {
	vk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursionVerifyingKey())
	if err != nil {
		return nil, err
	}
	return &Wrap{vk: vk}, nil
}

// Assignment is the witness wrapping `seal`, a proof of the receipt with
// claim `claim`.
func Assignment(seal []byte, claim [32]byte) (*Wrap, error) {
	p, err := ProofFromSeal(seal)
	if err != nil {
		return nil, err
	}
	proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](p)
	if err != nil {
		return nil, err
	}
	lo, hi := split(claim[:])
	return &Wrap{Proof: proof, ClaimLo: lo, ClaimHi: hi}, nil
}

func recursionVerifyingKey() groth16.VerifyingKey {
	vk := new(groth16bn254.VerifyingKey)
	vk.G1.Alpha = g1(vkAlpha[0], vkAlpha[1])
	vk.G2.Beta = g2(vkBeta)
	vk.G2.Gamma = g2(vkGamma)
	vk.G2.Delta = g2(vkDelta)
	vk.G1.K = make([]bn254.G1Affine, len(vkIC))
	for i, p := range vkIC {
		vk.G1.K[i] = g1(p[0], p[1])
	}
	if err := vk.Precompute(); err != nil {
		panic(err)
	}
	return vk
}

// ProofFromSeal reads a seal as the EVM verifier takes it: the selector, then
// the words of A (G1), B (G2, precompile order) and C (G1).
func ProofFromSeal(seal []byte) (*groth16bn254.Proof, error) {
	if len(seal) != 4+8*32 {
		return nil, errors.New("a seal is the selector and eight words")
	}
	if string(seal[:4]) != string(selector) {
		return nil, errors.New("the seal is for another verifier")
	}
	w := func(i int) []byte { return seal[4+32*i : 4+32*(i+1)] }
	var p groth16bn254.Proof
	p.Ar.X.SetBytes(w(0))
	p.Ar.Y.SetBytes(w(1))
	p.Bs.X.A1.SetBytes(w(2))
	p.Bs.X.A0.SetBytes(w(3))
	p.Bs.Y.A1.SetBytes(w(4))
	p.Bs.Y.A0.SetBytes(w(5))
	p.Krs.X.SetBytes(w(6))
	p.Krs.Y.SetBytes(w(7))
	if !p.Ar.IsInSubGroup() || !p.Bs.IsInSubGroup() || !p.Krs.IsInSubGroup() {
		return nil, errors.New("a seal point is not in its group")
	}
	return &p, nil
}

// ClaimDigest is the digest of a successful receipt claim of `imageID` with
// journal `journal`.
func ClaimDigest(imageID [32]byte, journal []byte) [32]byte {
	tag := func(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
	jd := sha256.Sum256(journal)
	h := sha256.New()
	h.Write(tag("risc0.Output"))
	h.Write(jd[:])
	h.Write(make([]byte, 32))
	h.Write(binary.LittleEndian.AppendUint16(nil, 2))
	output := h.Sum(nil)
	h = sha256.New()
	h.Write(tag("risc0.ReceiptClaim"))
	h.Write(make([]byte, 32))
	h.Write(imageID[:])
	h.Write(postState)
	h.Write(output)
	h.Write(make([]byte, 8))
	h.Write(binary.LittleEndian.AppendUint16(nil, 4))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// split is a digest as the recursion circuit takes it: its bytes reversed,
// then the low and the high 128 bits.
func split(d []byte) (*big.Int, *big.Int) {
	r := make([]byte, 32)
	for i := range r {
		r[i] = d[31-i]
	}
	return new(big.Int).SetBytes(r[16:]), new(big.Int).SetBytes(r[:16])
}

func g1(x, y string) bn254.G1Affine {
	var p bn254.G1Affine
	p.X.SetString(x)
	p.Y.SetString(y)
	return p
}

func g2(c [4]string) bn254.G2Affine {
	var p bn254.G2Affine
	p.X.A1.SetString(c[0])
	p.X.A0.SetString(c[1])
	p.Y.A1.SetString(c[2])
	p.Y.A0.SetString(c[3])
	return p
}

func mustHex(s string) []byte {
	var out []byte
	if _, err := fmt.Sscanf(s, "%x", &out); err != nil {
		panic(err)
	}
	return out
}
