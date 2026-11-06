// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
)

// VerifyingKeyJSON is the wrap circuit's verifying key with every point
// compressed (G1 48 bytes, G2 96 bytes), as a verifying chain stores it: the
// Groth16 key with its input commitments for the constant, the two claim
// halves and the commitment challenge, and the commitment's key.
type VerifyingKeyJSON struct {
	Alpha               string    `json:"alpha"`
	Beta                string    `json:"beta"`
	Gamma               string    `json:"gamma"`
	Delta               string    `json:"delta"`
	IC                  [4]string `json:"ic"`
	CommitmentG         string    `json:"commitment_g"`
	CommitmentGSigmaNeg string    `json:"commitment_g_sigma_neg"`
}

func ExportVK(vk *groth16bls.VerifyingKey) (VerifyingKeyJSON, error) {
	if len(vk.G1.K) != 4 || len(vk.CommitmentKeys) != 1 || len(vk.PublicAndCommitmentCommitted) != 1 ||
		len(vk.PublicAndCommitmentCommitted[0]) != 0 {
		return VerifyingKeyJSON{}, fmt.Errorf("the wrap key has %d input commitments and %d commitments over %v",
			len(vk.G1.K), len(vk.CommitmentKeys), vk.PublicAndCommitmentCommitted)
	}
	g1 := func(p bls.G1Affine) string { b := p.Bytes(); return hex.EncodeToString(b[:]) }
	g2 := func(p bls.G2Affine) string { b := p.Bytes(); return hex.EncodeToString(b[:]) }
	return VerifyingKeyJSON{
		Alpha:               g1(vk.G1.Alpha),
		Beta:                g2(vk.G2.Beta),
		Gamma:               g2(vk.G2.Gamma),
		Delta:               g2(vk.G2.Delta),
		IC:                  [4]string{g1(vk.G1.K[0]), g1(vk.G1.K[1]), g1(vk.G1.K[2]), g1(vk.G1.K[3])},
		CommitmentG:         g2(vk.CommitmentKeys[0].G),
		CommitmentGSigmaNeg: g2(vk.CommitmentKeys[0].GSigmaNeg),
	}, nil
}

// VerifyWrapped checks a wrapped proof the way a verifying chain does:
// recompute the claim halves from the journal and the challenge h from the
// commitment M, then check the commitment's proof of knowledge
// e(M, G sigma^-1) e(PoK, G) = 1 and
// e(A, B) = e(alpha, beta) e(IC0 + lo IC1 + hi IC2 + h IC3 + M, gamma) e(C, delta).
func VerifyWrapped(vk VerifyingKeyJSON, w WrappedProof) error {
	journal, err := hex.DecodeString(w.Journal)
	if err != nil {
		return err
	}
	id, err := hex.DecodeString(w.ImageID)
	if err != nil || len(id) != 32 {
		return errors.New("image id is 32 bytes")
	}
	claim := ClaimDigest([32]byte(id), journal)
	lo, hi := split(claim[:])
	g1 := func(s string) (p bls.G1Affine, err error) {
		b, err := hex.DecodeString(s)
		if err == nil {
			_, err = p.SetBytes(b)
		}
		return
	}
	g2 := func(s string) (p bls.G2Affine, err error) {
		b, err := hex.DecodeString(s)
		if err == nil {
			_, err = p.SetBytes(b)
		}
		return
	}
	var p1 [9]bls.G1Affine
	for i, s := range []string{w.A, w.C, w.Commitment, w.CommitmentPok, vk.Alpha, vk.IC[0], vk.IC[1], vk.IC[2], vk.IC[3]} {
		if p1[i], err = g1(s); err != nil {
			return err
		}
	}
	a, c, m, pok, alpha, ic := p1[0], p1[1], p1[2], p1[3], p1[4], p1[5:]
	var p2 [6]bls.G2Affine
	for i, s := range []string{w.B, vk.Beta, vk.Gamma, vk.Delta, vk.CommitmentG, vk.CommitmentGSigmaNeg} {
		if p2[i], err = g2(s); err != nil {
			return err
		}
	}
	b, beta, gamma, delta, cg, cgs := p2[0], p2[1], p2[2], p2[3], p2[4], p2[5]
	mc := m.Bytes()
	h := CommitmentChallenge(mc[:], nil)
	ok, err := bls.PairingCheck([]bls.G1Affine{m, pok}, []bls.G2Affine{cgs, cg})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the commitment's proof of knowledge failed")
	}
	var kSum, t bls.G1Affine
	kSum.Add(&ic[0], &m)
	t.ScalarMultiplication(&ic[1], lo)
	kSum.Add(&kSum, &t)
	t.ScalarMultiplication(&ic[2], hi)
	kSum.Add(&kSum, &t)
	t.ScalarMultiplication(&ic[3], h.BigInt(new(big.Int)))
	kSum.Add(&kSum, &t)
	var negA bls.G1Affine
	negA.Neg(&a)
	ok, err = bls.PairingCheck([]bls.G1Affine{negA, alpha, kSum, c}, []bls.G2Affine{b, beta, gamma, delta})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the pairing check failed")
	}
	return nil
}
