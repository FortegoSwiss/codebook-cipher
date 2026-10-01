// Conformance-vector test for complete word-level CodeBook lookups. Expected
// values are never computed here — they are only loaded from the checked-in
// lookup vector and compared.
//
// The layers underneath have their own vector tests next to them:
// internal/permutation covers the keystream, the draws and the permutations,
// and wordlist covers the digest.
package codebook_test

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/FortegoSwiss/codebook-cipher"
	"github.com/FortegoSwiss/codebook-cipher/wordlist"
	"github.com/FortegoSwiss/codebook-cipher/wordlist/bip39"
)

//go:embed lookup.v1.json
var lookupVectorsJSON []byte

// TestVectorsLookup verifies complete word-level lookups in both directions,
// through the public API only. Vectors either carry their word lists inline or
// reference the canonical English BIP-39 list by digest.
func TestVectorsLookup(t *testing.T) {
	var file struct {
		Version int `json:"version"`
		Vectors []struct {
			Name         string   `json:"name"`
			SeedHex      string   `json:"seedHex"`
			SourceDigest string   `json:"sourceWordListDigestHex"`
			TargetDigest string   `json:"targetWordListDigestHex"`
			SourceWords  []string `json:"sourceWords,omitempty"`
			TargetWords  []string `json:"targetWords,omitempty"`
			Word         string   `json:"word"`
			Index        int      `json:"index"`
			MappedIndex  int      `json:"mappedIndex"`
			MappedWord   string   `json:"mappedWord"`
			ReverseWord  string   `json:"reverseWord"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(lookupVectorsJSON, &file); err != nil {
		t.Fatalf("loading vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no lookup vectors loaded")
	}

	// listFor resolves a vector's word list: inline words when the vector
	// carries them, otherwise the canonical English BIP-39 list. Either way the
	// digest must match, since the vector is only meaningful against the exact
	// list it was generated over.
	listFor := func(t *testing.T, side string, words []string, wantDigest string) wordlist.List {
		t.Helper()
		l := bip39.English()
		if len(words) > 0 {
			var err error
			if l, err = wordlist.New(words); err != nil {
				t.Fatalf("%s wordlist.New: %v", side, err)
			}
		}
		digest := l.Digest()
		if got := hex.EncodeToString(digest[:]); got != wantDigest {
			t.Fatalf("%s word list digest = %s, vector expects %s", side, got, wantDigest)
		}
		return l
	}

	for _, vec := range file.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			source := listFor(t, "source", vec.SourceWords, vec.SourceDigest)
			target := listFor(t, "target", vec.TargetWords, vec.TargetDigest)

			seed, err := hex.DecodeString(vec.SeedHex)
			if err != nil {
				t.Fatalf("decoding seedHex: %v", err)
			}
			cb, err := codebook.New(seed, source, target)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			index, err := source.Index(vec.Word)
			if err != nil {
				t.Fatalf("Index(%q): %v", vec.Word, err)
			}
			if index != vec.Index {
				t.Fatalf("index = %d, want %d", index, vec.Index)
			}

			mappedWord, err := cb.Lookup(vec.Word)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", vec.Word, err)
			}
			if mappedWord != vec.MappedWord {
				t.Fatalf("Lookup(%q) = %q, want %q", vec.Word, mappedWord, vec.MappedWord)
			}

			mappedIndex, err := target.Index(mappedWord)
			if err != nil {
				t.Fatalf("target Index(%q): %v", mappedWord, err)
			}
			if mappedIndex != vec.MappedIndex {
				t.Fatalf("mappedIndex = %d, want %d", mappedIndex, vec.MappedIndex)
			}

			reverseWord, err := cb.Reverse().Lookup(mappedWord)
			if err != nil {
				t.Fatalf("Reverse().Lookup(%q): %v", mappedWord, err)
			}
			if reverseWord != vec.ReverseWord {
				t.Fatalf("Reverse().Lookup(%q) = %q, want %q", mappedWord, reverseWord, vec.ReverseWord)
			}
			if reverseWord != vec.Word {
				t.Fatalf("round trip for %q produced %q", vec.Word, reverseWord)
			}
		})
	}
}
