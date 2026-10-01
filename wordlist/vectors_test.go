// Conformance-vector test for the word list digest. The frozen digests come
// only from the checked-in vectors and are never computed here. The encoding
// rule that produces them is a different matter: the test restates it, so that
// a wrong-but-self-consistent implementation and vector set cannot agree with
// each other unnoticed.
//
// This is an external test package because it covers both digest vectors: the
// synthetic worked example and the canonical English BIP-39 list, whose
// package imports this one.
package wordlist_test

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/FortegoSwiss/codebook-cipher/wordlist"
	"github.com/FortegoSwiss/codebook-cipher/wordlist/bip39"
)

//go:embed wordlist.v1.json
var wordlistVectorsJSON []byte

// TestVectorsDigest verifies List.Digest against both checked-in digest
// vectors.
func TestVectorsDigest(t *testing.T) {
	var file struct {
		Version int `json:"version"`
		Vectors []struct {
			Name      string   `json:"name"`
			Words     []string `json:"words,omitempty"`
			Count     int      `json:"count"`
			DigestHex string   `json:"digestHex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(wordlistVectorsJSON, &file); err != nil {
		t.Fatalf("loading vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no word list vectors loaded")
	}

	seen := make(map[string]bool, len(file.Vectors))
	for _, vec := range file.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			seen[vec.Name] = true

			var l wordlist.List
			if vec.Name == "bip39-english" {
				l = bip39.English()
			} else {
				var err error
				if l, err = wordlist.New(vec.Words); err != nil {
					t.Fatalf("wordlist.New: %v", err)
				}
			}

			if l.Len() != vec.Count {
				t.Fatalf("Len() = %d, want %d", l.Len(), vec.Count)
			}

			digest := l.Digest()
			got := hex.EncodeToString(digest[:])

			// Compared: the frozen value.
			if got != vec.DigestHex {
				t.Fatalf("Digest mismatch:\n got  %s\n want %s", got, vec.DigestHex)
			}
			// Derived: the encoding rule from README's "Exact behaviour",
			// recomputed here so the test states it rather than only echoing
			// what the implementation produced.
			if want := recomputeDigest(l.Words()); got != want {
				t.Fatalf("Digest does not follow the documented encoding:\n got  %s\n want %s", got, want)
			}
		})
	}

	for _, name := range []string{"synthetic-3-word", "bip39-english"} {
		if !seen[name] {
			t.Errorf("%s vector not found in wordlist.json", name)
		}
	}
}

// recomputeDigest is an independent statement of the digest encoding described
// under "Exact behaviour" in README.md: SHA-256 over a 4-byte little-endian
// word count, followed by each word as a 4-byte little-endian byte length and
// its raw bytes, in list order. It deliberately shares no code with the
// implementation it checks.
func recomputeDigest(words []string) string {
	h := sha256.New()

	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(len(words)))
	h.Write(buf[:])

	for _, w := range words {
		binary.LittleEndian.PutUint32(buf[:], uint32(len(w)))
		h.Write(buf[:])
		h.Write([]byte(w))
	}
	return hex.EncodeToString(h.Sum(nil))
}
