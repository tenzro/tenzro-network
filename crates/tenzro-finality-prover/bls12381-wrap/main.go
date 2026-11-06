// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const usage = `tenzro-finality-wrap-bls: Tenzro finality proofs over BLS12-381

  info                                      constraints and domain of the wrap circuit
  phase1-init  -out F                       start phase 1 of the key ceremony
  phase1-contribute -in F -out G            add a contribution to phase 1
  phase2-init  -beacon B -out F P1...       verify phase 1 and start phase 2
  phase2-contribute -in F -out G            add a contribution to phase 2
  seal -phase2 F -beacon B -pk K -vk V P2...  verify phase 2 and write the keys
  prove -pk K -proof P [-out O]             wrap a finality proof (JSON with journal, evm_seal, image_id)
  verify -vk V -proof O                     check a wrapped proof
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "info":
		err = info()
	case "phase1-init":
		err = phase1Init(args)
	case "phase1-contribute":
		err = contribute(args, new(mpcsetup.Phase1))
	case "phase2-init":
		err = phase2Init(args)
	case "phase2-contribute":
		err = contribute(args, new(mpcsetup.Phase2))
	case "seal":
		err = seal(args)
	case "prove":
		err = prove(args)
	case "verify":
		err = verify(args)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// Compile the wrap circuit.
func Compile() (*cs.R1CS, error) {
	c, err := NewCircuit()
	if err != nil {
		return nil, err
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return nil, err
	}
	return ccs.(*cs.R1CS), nil
}

func info() error {
	ccs, err := Compile()
	if err != nil {
		return err
	}
	fmt.Printf("constraints %d, public inputs %d, domain %d\n", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints())))
	return nil
}

func phase1Init(args []string) error {
	fs := flag.NewFlagSet("phase1-init", flag.ExitOnError)
	out := fs.String("out", "", "file to write")
	_ = fs.Parse(args)
	ccs, err := Compile()
	if err != nil {
		return err
	}
	var p mpcsetup.Phase1
	p.Initialize(ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints())))
	return writeFile(*out, &p)
}

type contribution interface {
	io.ReaderFrom
	io.WriterTo
	Contribute()
}

func contribute(args []string, p contribution) error {
	fs := flag.NewFlagSet("contribute", flag.ExitOnError)
	in := fs.String("in", "", "the last contribution")
	out := fs.String("out", "", "file to write")
	_ = fs.Parse(args)
	if err := readFile(*in, p); err != nil {
		return err
	}
	p.Contribute()
	return writeFile(*out, p)
}

// Verify phase 1 and start phase 2: writes the phase-1 commons beside the
// first phase-2 state.
func phase2Init(args []string) error {
	fs := flag.NewFlagSet("phase2-init", flag.ExitOnError)
	beacon := fs.String("beacon", "", "public randomness fixed after the last phase-1 contribution (hex)")
	out := fs.String("out", "", "file to write")
	_ = fs.Parse(args)
	ccs, err := Compile()
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(*beacon)
	if err != nil || len(b) == 0 {
		return errors.New("a beacon is required")
	}
	contribs, err := readAll[mpcsetup.Phase1](fs.Args())
	if err != nil {
		return err
	}
	commons, err := mpcsetup.VerifyPhase1(ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints())), b, contribs...)
	if err != nil {
		return fmt.Errorf("phase 1: %w", err)
	}
	var p mpcsetup.Phase2
	p.Initialize(ccs, &commons)
	if err := writeFile(*out+".commons", &commons); err != nil {
		return err
	}
	return writeFile(*out, &p)
}

func seal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	phase2 := fs.String("phase2", "", "the phase2-init output (its .commons file is read)")
	beacon := fs.String("beacon", "", "public randomness fixed after the last phase-2 contribution (hex)")
	pkOut := fs.String("pk", "", "proving key to write")
	vkOut := fs.String("vk", "", "verifying key to write (JSON)")
	_ = fs.Parse(args)
	ccs, err := Compile()
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(*beacon)
	if err != nil || len(b) == 0 {
		return errors.New("a beacon is required")
	}
	var commons mpcsetup.SrsCommons
	if err := readFile(*phase2+".commons", &commons); err != nil {
		return err
	}
	contribs, err := readAll[mpcsetup.Phase2](fs.Args())
	if err != nil {
		return err
	}
	pk, vk, err := mpcsetup.VerifyPhase2(ccs, &commons, b, contribs...)
	if err != nil {
		return fmt.Errorf("phase 2: %w", err)
	}
	if err := writeFile(*pkOut, pk); err != nil {
		return err
	}
	exported, err := ExportVK(vk.(*groth16bls.VerifyingKey))
	if err != nil {
		return err
	}
	return writeJSON(*vkOut, exported)
}

// FinalityProof is the prover's output for one checkpoint.
type FinalityProof struct {
	Journal string `json:"journal"`
	EvmSeal string `json:"evm_seal"`
	ImageID string `json:"image_id"`
}

// WrappedProof is a finality proof over BLS12-381: the journal, the claim
// halves it implies, the proof points and the circuit's commitment with its
// proof of knowledge, every point compressed.
type WrappedProof struct {
	Journal       string `json:"journal"`
	ImageID       string `json:"image_id"`
	ClaimLo       string `json:"claim_lo"`
	ClaimHi       string `json:"claim_hi"`
	A             string `json:"a"`
	B             string `json:"b"`
	C             string `json:"c"`
	Commitment    string `json:"commitment"`
	CommitmentPok string `json:"commitment_pok"`
}

func prove(args []string) error {
	fs := flag.NewFlagSet("prove", flag.ExitOnError)
	pkIn := fs.String("pk", "", "proving key")
	proofIn := fs.String("proof", "", "finality proof JSON")
	out := fs.String("out", "", "wrapped proof to write (stdout if empty)")
	_ = fs.Parse(args)
	ccs, err := Compile()
	if err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BLS12_381)
	if err := readFile(*pkIn, pk); err != nil {
		return err
	}
	var fp FinalityProof
	if err := readJSON(*proofIn, &fp); err != nil {
		return err
	}
	w, err := Wrapped(ccs, pk, fp)
	if err != nil {
		return err
	}
	return writeJSON(*out, w)
}

// Wrapped proves the wrap of `fp` with `pk`.
func Wrapped(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, fp FinalityProof) (*WrappedProof, error) {
	journal, err := hex.DecodeString(strings.TrimPrefix(fp.Journal, "0x"))
	if err != nil {
		return nil, err
	}
	sealBytes, err := hex.DecodeString(strings.TrimPrefix(fp.EvmSeal, "0x"))
	if err != nil {
		return nil, err
	}
	id, err := hex.DecodeString(strings.TrimPrefix(fp.ImageID, "0x"))
	if err != nil || len(id) != 32 {
		return nil, errors.New("image id is 32 bytes")
	}
	claim := ClaimDigest([32]byte(id), journal)
	assignment, err := Assignment(sealBytes, claim)
	if err != nil {
		return nil, err
	}
	wit, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, err
	}
	start := time.Now()
	proof, err := groth16.Prove(ccs, pk, wit, backend.WithProverHashToFieldFunction(NewCommitmentHash()))
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	fmt.Fprintf(os.Stderr, "proved in %s\n", time.Since(start))
	p := proof.(*groth16bls.Proof)
	lo, hi := split(claim[:])
	if len(p.Commitments) != 1 {
		return nil, fmt.Errorf("the wrap proof carries %d commitments, not one", len(p.Commitments))
	}
	a, b, c := p.Ar.Bytes(), p.Bs.Bytes(), p.Krs.Bytes()
	cm, pok := p.Commitments[0].Bytes(), p.CommitmentPok.Bytes()
	return &WrappedProof{
		Commitment:    hex.EncodeToString(cm[:]),
		CommitmentPok: hex.EncodeToString(pok[:]),
		Journal: hex.EncodeToString(journal),
		ImageID: hex.EncodeToString(id),
		ClaimLo: fmt.Sprintf("%032x", lo),
		ClaimHi: fmt.Sprintf("%032x", hi),
		A:       hex.EncodeToString(a[:]),
		B:       hex.EncodeToString(b[:]),
		C:       hex.EncodeToString(c[:]),
	}, nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	vkIn := fs.String("vk", "", "verifying key JSON")
	proofIn := fs.String("proof", "", "wrapped proof JSON")
	_ = fs.Parse(args)
	var vk VerifyingKeyJSON
	if err := readJSON(*vkIn, &vk); err != nil {
		return err
	}
	var w WrappedProof
	if err := readJSON(*proofIn, &w); err != nil {
		return err
	}
	if err := VerifyWrapped(vk, w); err != nil {
		return err
	}
	fmt.Println("valid")
	return nil
}

func readAll[T any, P interface {
	*T
	io.ReaderFrom
}](files []string) ([]*T, error) {
	out := make([]*T, len(files))
	for i, f := range files {
		out[i] = new(T)
		if err := readFile(f, P(out[i])); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readFile(path string, v io.ReaderFrom) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = v.ReadFrom(f)
	return err
}

func writeFile(path string, v io.WriterTo) error {
	if path == "" {
		return errors.New("an output file is required")
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := v.WriteTo(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if path == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
