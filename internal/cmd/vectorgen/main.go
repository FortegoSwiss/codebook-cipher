// Command vectorgen produces the checked-in JSON conformance vectors next to
// the layer each one specifies.
// Run it from the repository root:
//
//	go run ./internal/cmd/vectorgen
//
// This is a one-time (or rare, deliberate re-run) golden-sample generator,
// not part of the test suite. Its output is reviewed and committed as fixed
// vectors; tests embed them directly and never invoke this generator. Except
// for the RFC-anchored raw ChaCha20 bytes, it deliberately uses the effective
// production implementation. Re-run and re-review deliberately if, and only
// if, the v1 vectors need to be extended; never re-run it merely to hide a
// divergence found by the tests.
// The JSON schema below is declared again, independently, by each test that
// reads these files. That duplication is deliberate: a renamed field here must
// break those tests loudly, rather than travel through a shared type and be
// decoded into a zero value nobody notices.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20"

	"github.com/FortegoSwiss/codebook-cipher"
	"github.com/FortegoSwiss/codebook-cipher/internal/permutation"
	"github.com/FortegoSwiss/codebook-cipher/wordlist"
	"github.com/FortegoSwiss/codebook-cipher/wordlist/bip39"
)

const (
	permutationVectorsDir = "internal/permutation"
	wordlistVectorsDir    = "wordlist"
)

func main() {
	writeJSON(filepath.Join(permutationVectorsDir, "keystream.v1.json"), generateKeystreamVectors())
	writeJSON(filepath.Join(permutationVectorsDir, "draws.v1.json"), generateDrawVectors())
	writeJSON(filepath.Join(permutationVectorsDir, "permutations.v1.json"), generatePermutationVectors())
	writeJSON(filepath.Join(wordlistVectorsDir, "wordlist.v1.json"), generateWordListVectors())
	writeJSON("lookup.v1.json", generateLookupVectors())

	fmt.Println("wrote conformance vectors")
}

func writeJSON(name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(name, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// --- helpers -----------------------------------------------------------

func seedBytes(fill func(i int) byte) [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = fill(i)
	}
	return s
}

func namedSeeds() map[string][32]byte {
	return map[string][32]byte{
		"seed-all-zero":  seedBytes(func(i int) byte { return 0x00 }),
		"seed-ascending": seedBytes(func(i int) byte { return byte(i) }),
		"seed-all-ff":    seedBytes(func(i int) byte { return 0xFF }),
	}
}

// rawKeystream derives the externally anchored ChaCha20 test samples
// directly from x/crypto. It does not generate application-level vectors.
func rawKeystream(key [32]byte, n int) []byte {
	var nonce [chacha20.NonceSize]byte // fixed all-zero nonce
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		panic(err)
	}
	out := make([]byte, n)
	c.XORKeyStream(out, out)
	return out
}

// --- keystream.json ------------------------------------------------------

type keystreamVector struct {
	Name         string `json:"name"`
	SeedHex      string `json:"seedHex"`
	KeystreamHex string `json:"keystreamHex"`
}

type keystreamFile struct {
	Version     int               `json:"version"`
	Description string            `json:"description"`
	Vectors     []keystreamVector `json:"vectors"`
}

func generateKeystreamVectors() keystreamFile {
	names := []string{"seed-all-zero", "seed-ascending", "seed-all-ff"}
	seeds := namedSeeds()

	var vecs []keystreamVector
	for _, name := range names {
		seed := seeds[name]
		ks := rawKeystream(seed, 128) // two ChaCha20 blocks
		vecs = append(vecs, keystreamVector{
			Name:         name,
			SeedHex:      hex.EncodeToString(seed[:]),
			KeystreamHex: hex.EncodeToString(ks),
		})
	}

	return keystreamFile{
		Version: 1,
		Description: "Raw ChaCha20-IETF (RFC 8439) keystream bytes for representative " +
			"32-byte seeds, key=seed, nonce=12 zero bytes, initial counter=0. 128 " +
			"bytes = two consecutive 64-byte blocks (counter 0 and counter 1), " +
			"consumed in order with no gaps. " +
			"The seed-all-zero vector's first block is byte-identical to RFC 8439 " +
			"Appendix A.1 Test Vector #1 (key=0, nonce=0, counter=0), and its second " +
			"block to Test Vector #2 (counter=1) -- independently confirming that " +
			"this stream is a conformant, correctly counter-incrementing ChaCha20-IETF " +
			"keystream.",
		Vectors: vecs,
	}
}

// --- draws.json ----------------------------------------------------------

type draw struct {
	ValueHex string `json:"valueHex"` // big-endian uint16, as drawn from the stream
	Value    uint32 `json:"value"`
	Accepted bool   `json:"accepted"`
}

type shuffleStep struct {
	I      int    `json:"i"`
	Range  uint32 `json:"range"`
	Limit  uint32 `json:"limit"`
	Draws  []draw `json:"draws"` // in stream order; last entry is always accepted
	J      uint32 `json:"j"`
	SwapPI uint32 `json:"before_p_i"`
	SwapPJ uint32 `json:"before_p_j"`
}

type drawVectorSet struct {
	Name  string        `json:"name"`
	Seed  string        `json:"seedHex"`
	Size  int           `json:"size"`
	Steps []shuffleStep `json:"steps"`
}

type drawsFile struct {
	Version     int             `json:"version"`
	Description string          `json:"description"`
	Sets        []drawVectorSet `json:"sets"`
}

// traceShuffle records selected steps from the effective production shuffle.
// The trace hook is internal to the repository and runs inside
// permutation.Generate's implementation; this command contains no second
// Fisher-Yates or rejection-sampling implementation.
func traceShuffle(seed [32]byte, size int, recordSteps int) (steps []shuffleStep, finalP []uint32) {
	p, err := permutation.Trace(seed[:], size, func(i int, rng, limit uint32, draws []uint32, j, swapPI, swapPJ uint32) {
		if len(steps) >= recordSteps {
			return
		}
		step := shuffleStep{I: i, Range: rng, Limit: limit, J: j, SwapPI: swapPI, SwapPJ: swapPJ}
		for _, value := range draws {
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], uint16(value))
			step.Draws = append(step.Draws, draw{
				ValueHex: hex.EncodeToString(b[:]),
				Value:    value,
				Accepted: value < limit,
			})
		}
		steps = append(steps, step)
	})
	if err != nil {
		panic(err)
	}
	finalP = make([]uint32, p.Len())
	for i := range finalP {
		value, ok := p.At(i)
		if !ok {
			panic(fmt.Sprintf("production permutation index %d out of range", i))
		}
		finalP[i] = uint32(value)
	}
	return steps, finalP
}

func generateDrawVectors() drawsFile {
	seeds := namedSeeds()

	// First few steps for a representative mid-size shuffle.
	seed2048 := seeds["seed-all-zero"]
	steps2048, _ := traceShuffle(seed2048, 2048, 5)

	// A complete small shuffle, so that the smallest ranges are covered.
	// range=3 is the sharpest rejection boundary in the whole algorithm --
	// limit = 21845*3 = 65535, so exactly one raw value out of 65536 is
	// rejected -- and range=2 and range=4 are powers of two, where limit is
	// exactly 65536 and nothing is ever rejected.
	seedSmall := seeds["seed-all-zero"]
	stepsSmall, _ := traceShuffle(seedSmall, 4, 3)

	// The first steps at the maximum size, covering the upper boundary:
	// range=65536 gives limit=65536, so every 16-bit draw is accepted.
	seedMax := seeds["seed-all-zero"]
	stepsMax, _ := traceShuffle(seedMax, 65536, 3)

	// Scan a larger shuffle to find and record a genuine rejected draw,
	// since rejection probability per step is small (0 for power-of-two
	// ranges, otherwise (65536 mod range)/65536).
	seedReject := seeds["seed-ascending"]
	allSteps, _ := traceShuffle(seedReject, 2048, 2048)
	var rejectionSteps []shuffleStep
	for _, s := range allSteps {
		if len(s.Draws) > 1 { // more than one draw means at least one rejection occurred
			rejectionSteps = append(rejectionSteps, s)
			if len(rejectionSteps) == 3 {
				break
			}
		}
	}

	return drawsFile{
		Version: 1,
		Description: "Fisher-Yates draw traces. Each step " +
			"lists every 16-bit big-endian draw attempted for that i (in stream " +
			"order), flagged accepted/rejected, followed by the accepted j and the " +
			"pre-swap values. A draw is accepted when it is below " +
			"limit = floor(65536 / range) * range, with range = i + 1, and then " +
			"j = draw mod range; a rejected draw still consumes its two keystream " +
			"bytes. 'first-steps' sets show the algorithm's start (i = size-1 " +
			"descending); 'all-steps-size-4' is a complete small shuffle covering " +
			"the smallest ranges, including range=3, the sharpest rejection " +
			"boundary (limit=65535, one raw value in 65536 rejected); " +
			"'first-steps-size-65536' covers the upper boundary, where " +
			"limit=65536 and no draw can be rejected; 'rejection-examples' shows " +
			"steps where a draw was rejected and a fresh one required, found by " +
			"scanning a full shuffle for size=2048.",
		Sets: []drawVectorSet{
			{Name: "all-steps-size-4-seed-all-zero", Seed: hex.EncodeToString(seedSmall[:]), Size: 4, Steps: stepsSmall},
			{Name: "first-steps-size-2048-seed-all-zero", Seed: hex.EncodeToString(seed2048[:]), Size: 2048, Steps: steps2048},
			{Name: "first-steps-size-65536-seed-all-zero", Seed: hex.EncodeToString(seedMax[:]), Size: 65536, Steps: stepsMax},
			{Name: "rejection-examples-size-2048-seed-ascending", Seed: hex.EncodeToString(seedReject[:]), Size: 2048, Steps: rejectionSteps},
		},
	}
}

// --- permutations.json ----------------------------------------------------

func permutationHash(p []uint32) [32]byte {
	h := sha256.New()
	var buf [2]byte
	for _, v := range p {
		binary.BigEndian.PutUint16(buf[:], uint16(v))
		h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type sampleEntry struct {
	Index       int `json:"index"`
	MappedIndex int `json:"mappedIndex"`
}

type permutationVector struct {
	Name            string        `json:"name"`
	SeedHex         string        `json:"seedHex"`
	Size            int           `json:"size"`
	PermutationHash string        `json:"permutationHash"`
	Full            []uint32      `json:"full,omitempty"`
	Sample          []sampleEntry `json:"sample,omitempty"`
}

type permutationsFile struct {
	Version     int                 `json:"version"`
	Description string              `json:"description"`
	Vectors     []permutationVector `json:"vectors"`
}

func generatePermutationVectors() permutationsFile {
	seed := seedBytes(func(i int) byte { return 0x00 })

	small := []int{1, 2, 3, 4}
	boundary := []int{1024, 2048, 65536}

	var vecs []permutationVector
	for _, size := range small {
		_, full := traceShuffle(seed, size, 0)
		hash := permutationHash(full)
		vecs = append(vecs, permutationVector{
			Name:            fmt.Sprintf("size-%d-seed-all-zero", size),
			SeedHex:         hex.EncodeToString(seed[:]),
			Size:            size,
			PermutationHash: hex.EncodeToString(hash[:]),
			Full:            full,
		})
	}

	for _, size := range boundary {
		_, full := traceShuffle(seed, size, 0)
		hash := permutationHash(full)

		sampleIdx := []int{0, 1, size / 2, size - 2, size - 1}
		var sample []sampleEntry
		for _, i := range sampleIdx {
			sample = append(sample, sampleEntry{Index: i, MappedIndex: int(full[i])})
		}

		vecs = append(vecs, permutationVector{
			Name:            fmt.Sprintf("size-%d-seed-all-zero", size),
			SeedHex:         hex.EncodeToString(seed[:]),
			Size:            size,
			PermutationHash: hex.EncodeToString(hash[:]),
			Sample:          sample,
		})
	}

	return permutationsFile{
		Version: 1,
		Description: "Final permutations. permutationHash is SHA-256 over the " +
			"big-endian uint16 encoding of every P[i], in array order. " +
			"'full' gives the complete P array (P[index] = mappedIndex) for " +
			"small sizes; larger sizes give only permutationHash plus a small " +
			"'sample' of spot-checkable (index, mappedIndex) pairs. Every " +
			"vector here also satisfies the forward/reverse invariant " +
			"Inverse(P)[P[i]] = i for all i, which is exercised by this " +
			"repository's own tests (internal/permutation/permutation_test.go) rather than re-encoded " +
			"per-index in this file for the large sizes.",
		Vectors: vecs,
	}
}

// --- wordlist.json -------------------------------------------------------

type wordListVector struct {
	Name       string   `json:"name"`
	Words      []string `json:"words,omitempty"` // only for the small worked example
	Count      int      `json:"count"`
	DigestHex  string   `json:"digestHex"`
	DigestNote string   `json:"digestNote,omitempty"`
}

type wordListFile struct {
	Version     int              `json:"version"`
	Description string           `json:"description"`
	Vectors     []wordListVector `json:"vectors"`
}

func generateWordListVectors() wordListFile {
	small, err := wordlist.New([]string{"alpha", "bravo", "charlie"})
	if err != nil {
		panic(err)
	}
	smallDigest := small.Digest()

	english := bip39.English()
	englishDigest := english.Digest()

	return wordListFile{
		Version: 1,
		Description: "Word list digests: SHA-256 over a " +
			"4-byte little-endian entry count, followed by each entry as a 4-byte " +
			"little-endian byte length and its raw bytes, in word list " +
			"order. 'synthetic-3-word' is a minimal worked example implementers can " +
			"reproduce by hand; 'bip39-english' is the canonical 2048-word list " +
			"shipped in github.com/FortegoSwiss/codebook-cipher/wordlist/bip39.",
		Vectors: []wordListVector{
			{
				Name:      "synthetic-3-word",
				Words:     []string{"alpha", "bravo", "charlie"},
				Count:     small.Len(),
				DigestHex: hex.EncodeToString(smallDigest[:]),
			},
			{
				Name:       "bip39-english",
				Count:      english.Len(),
				DigestHex:  hex.EncodeToString(englishDigest[:]),
				DigestNote: "word list itself is not repeated here; see bip39/wordlist.txt in this repository",
			},
		},
	}
}

// --- lookup.json -----------------------------------------------------------

type lookupVector struct {
	Name                 string   `json:"name"`
	SeedHex              string   `json:"seedHex"`
	SourceWordListDigest string   `json:"sourceWordListDigestHex"`
	TargetWordListDigest string   `json:"targetWordListDigestHex"`
	SourceWords          []string `json:"sourceWords,omitempty"`
	TargetWords          []string `json:"targetWords,omitempty"`
	Word                 string   `json:"word"`
	Index                int      `json:"index"`
	MappedIndex          int      `json:"mappedIndex"`
	MappedWord           string   `json:"mappedWord"`
	ReverseWord          string   `json:"reverseWord"`
}

type lookupFile struct {
	Version     int            `json:"version"`
	Description string         `json:"description"`
	Vectors     []lookupVector `json:"vectors"`
}

func generateLookupVectors() lookupFile {
	seed := seedBytes(func(i int) byte { return 0x00 })
	english := bip39.English()
	shortSource, err := wordlist.New([]string{"alpha", "bravo", "charlie"})
	if err != nil {
		panic(err)
	}
	shortTarget, err := wordlist.New([]string{"01", "02", "03"})
	if err != nil {
		panic(err)
	}

	vecs := lookupVectors(seed, english, english, []string{"abandon", "zoo"}, "bip39-english-seed-all-zero-")
	synthetic := lookupVectors(seed, shortSource, shortTarget, []string{"alpha"}, "synthetic-source-to-code-seed-all-zero-")
	for i := range synthetic {
		synthetic[i].SourceWords = shortSource.Words()
		synthetic[i].TargetWords = shortTarget.Words()
	}
	vecs = append(vecs, synthetic...)

	return lookupFile{
		Version: 1,
		Description: "Complete word-level CodeBook lookup examples binding a generated " +
			"permutation to ordered source and target word lists, per the " +
			"exact-behaviour rules in README.md. reverseWord must equal " +
			"word in every vector.",
		Vectors: vecs,
	}
}

func lookupVectors(seed [32]byte, source, target wordlist.List, words []string, namePrefix string) []lookupVector {
	cb, err := codebook.New(seed[:], source, target)
	if err != nil {
		panic(err)
	}
	reversed := cb.Reverse()

	var vecs []lookupVector
	for _, word := range words {
		index, err := source.Index(word)
		if err != nil {
			panic(err)
		}
		mappedWord, err := cb.Lookup(word)
		if err != nil {
			panic(err)
		}
		mappedIndex, err := target.Index(mappedWord)
		if err != nil {
			panic(err)
		}
		reverseWord, err := reversed.Lookup(mappedWord)
		if err != nil {
			panic(err)
		}
		sourceDigest := source.Digest()
		targetDigest := target.Digest()
		vecs = append(vecs, lookupVector{
			Name:                 namePrefix + word,
			SeedHex:              hex.EncodeToString(seed[:]),
			SourceWordListDigest: hex.EncodeToString(sourceDigest[:]),
			TargetWordListDigest: hex.EncodeToString(targetDigest[:]),
			Word:                 word,
			Index:                index,
			MappedIndex:          mappedIndex,
			MappedWord:           mappedWord,
			ReverseWord:          reverseWord,
		})
	}
	return vecs
}
