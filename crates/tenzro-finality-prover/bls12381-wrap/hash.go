// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha256"
	"hash"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// The commitment challenge: the wrap circuit commits to its internal range
// and product checks, and the challenge for that commitment is derived from
// the commitment by the prover and recomputed by the verifier. It hashes the
// commitment in compressed form, so a chain that holds only compressed points
// recomputes it exactly:
//
//	h = (sha256(D || 0 || C) || sha256(D || 1 || C)[:16]) mod r
//
// with D the domain below and C the 48-byte compressed commitment.
const commitmentDomain = "tenzro/finality-wrap/commitment"

type commitmentHash struct{ buf []byte }

// NewCommitmentHash is the challenge function prover and verifier share. It
// reads the uncompressed commitment the proof system writes.
func NewCommitmentHash() hash.Hash { return &commitmentHash{} }

func (h *commitmentHash) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return len(p), nil
}

func (h *commitmentHash) Sum(b []byte) []byte {
	var c bls.G1Affine
	if _, err := c.SetBytes(h.buf[:bls.SizeOfG1AffineUncompressed]); err != nil {
		panic("the commitment is not a point")
	}
	compressed := c.Bytes()
	e := CommitmentChallenge(compressed[:], h.buf[bls.SizeOfG1AffineUncompressed:])
	out := e.Bytes()
	return append(b, out[:]...)
}

func (h *commitmentHash) Reset()         { h.buf = h.buf[:0] }
func (h *commitmentHash) Size() int      { return fr.Bytes }
func (h *commitmentHash) BlockSize() int { return sha256.BlockSize }

// CommitmentChallenge is the challenge for the compressed commitment `c`
// and any public inputs it covers.
func CommitmentChallenge(c []byte, publics []byte) fr.Element {
	part := func(i byte) []byte {
		h := sha256.New()
		h.Write([]byte(commitmentDomain))
		h.Write([]byte{i})
		h.Write(c)
		h.Write(publics)
		return h.Sum(nil)
	}
	wide := append(part(0), part(1)[:16]...)
	v := new(big.Int).SetBytes(wide)
	v.Mod(v, fr.Modulus())
	var e fr.Element
	e.SetBigInt(v)
	return e
}
