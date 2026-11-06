// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/test"
)

// A real finality proof of a test build of the finality program.
const recorded = "../../tenzro-vm/tests/fixtures/finality_proof.json"

func recordedProof(t *testing.T) (FinalityProof, []byte, [32]byte) {
	var fp FinalityProof
	if err := readJSON(recorded, &fp); err != nil {
		t.Fatal(err)
	}
	seal, _ := hex.DecodeString(fp.EvmSeal[2:])
	journal, _ := hex.DecodeString(fp.Journal)
	id, _ := hex.DecodeString(fp.ImageID)
	return fp, seal, ClaimDigest([32]byte(id), journal)
}

func TestTheRecordedProofSatisfiesTheWrapCircuit(t *testing.T) {
	_, seal, claim := recordedProof(t)
	c, err := NewCircuit()
	if err != nil {
		t.Fatal(err)
	}
	a, err := Assignment(seal, claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(c, a, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func TestAnotherClaimDoesNotSatisfyTheWrapCircuit(t *testing.T) {
	_, seal, claim := recordedProof(t)
	claim[0] ^= 1
	c, _ := NewCircuit()
	a, err := Assignment(seal, claim)
	if err != nil {
		t.Fatal(err)
	}
	if test.IsSolved(c, a, ecc.BLS12_381.ScalarField()) == nil {
		t.Fatal("a proof of one claim satisfied the circuit for another")
	}
}

func TestASealOffTheCurveIsRefused(t *testing.T) {
	_, seal, _ := recordedProof(t)
	seal[4+31] ^= 1
	if _, err := ProofFromSeal(seal); err == nil {
		t.Fatal("a point off the curve was read")
	}
	seal[4+31] ^= 1
	seal[0] = 0
	if _, err := ProofFromSeal(seal); err == nil {
		t.Fatal("a seal for another verifier was read")
	}
}

// Proves the wrap of the recorded proof end to end with a one-party key
// (test only; real keys come from the ceremony), checks it as a verifying
// chain does, and writes the TON contract's test fixture. Run with
// WRAP_PROVE=1; it needs several GB of memory and minutes of CPU.
func TestProveAndVerifyTheRecordedProof(t *testing.T) {
	if os.Getenv("WRAP_PROVE") == "" {
		t.Skip("set WRAP_PROVE=1")
	}
	fp, _, _ := recordedProof(t)
	ccs, err := Compile()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("constraints %d", ccs.GetNbConstraints())
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	w, err := Wrapped(ccs, pk, fp)
	if err != nil {
		t.Fatal(err)
	}
	vkj, err := ExportVK(vk.(*groth16bls.VerifyingKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWrapped(vkj, *w); err != nil {
		t.Fatal(err)
	}
	bad := *w
	bad.Journal = bad.Journal[:2*8*32] + "5f" + bad.Journal[2*8*32+2:]
	if VerifyWrapped(vkj, bad) == nil {
		t.Fatal("a journal the proof does not commit verified")
	}
	tampered := *w
	tampered.Commitment = w.CommitmentPok
	if VerifyWrapped(vkj, tampered) == nil {
		t.Fatal("a proof with another commitment verified")
	}
	if out := os.Getenv("WRAP_FIXTURE"); out != "" {
		if err := writeJSON(out, map[string]any{"vk": vkj, "proof": w}); err != nil {
			t.Fatal(err)
		}
	}
}
