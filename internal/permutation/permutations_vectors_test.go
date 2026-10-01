package permutation

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

//go:embed permutations.v1.json
var permutationVectorsJSON []byte

// TestVectorsPermutations verifies final permutations against the checked-in
// permutation hashes, full arrays, and spot-check samples.
func TestVectorsPermutations(t *testing.T) {
	var file struct {
		Version int `json:"version"`
		Vectors []struct {
			Name            string `json:"name"`
			SeedHex         string `json:"seedHex"`
			Size            int    `json:"size"`
			PermutationHash string `json:"permutationHash"`
			Full            []int  `json:"full,omitempty"`
			Sample          []struct {
				Index       int `json:"index"`
				MappedIndex int `json:"mappedIndex"`
			} `json:"sample,omitempty"`
		} `json:"vectors"`
	}
	loadVectors(t, permutationVectorsJSON, &file)
	if len(file.Vectors) == 0 {
		t.Fatal("no permutation vectors loaded")
	}

	for _, vec := range file.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			seed := decodeHex(t, "seedHex", vec.SeedHex)

			p, err := Generate(seed, vec.Size)
			if err != nil {
				t.Fatalf("Generate(size=%d): %v", vec.Size, err)
			}
			if p.Len() != vec.Size {
				t.Fatalf("permutation length = %d, want %d", p.Len(), vec.Size)
			}

			if got := permutationHash(t, p); got != vec.PermutationHash {
				t.Fatalf("permutationHash mismatch:\n got  %s\n want %s", got, vec.PermutationHash)
			}

			for i, want := range vec.Full {
				got, ok := p.At(i)
				if !ok {
					t.Fatalf("At(%d): out of range", i)
				}
				if got != want {
					t.Fatalf("P[%d] = %d, want %d (full array mismatch)", i, got, want)
				}
			}

			for _, s := range vec.Sample {
				got, ok := p.At(s.Index)
				if !ok {
					t.Fatalf("At(%d): out of range", s.Index)
				}
				if got != s.MappedIndex {
					t.Fatalf("P[%d] = %d, want %d (sample mismatch)", s.Index, got, s.MappedIndex)
				}
			}
		})
	}
}

// permutationHash implements the vector format: SHA-256 over the big-endian
// uint16 encoding of every P[i], in array order.
func permutationHash(t *testing.T, p P) string {
	t.Helper()
	h := sha256.New()
	var buf [2]byte
	for i := 0; i < p.Len(); i++ {
		v, ok := p.At(i)
		if !ok {
			t.Fatalf("At(%d): out of range", i)
		}
		binary.BigEndian.PutUint16(buf[:], uint16(v))
		h.Write(buf[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}
