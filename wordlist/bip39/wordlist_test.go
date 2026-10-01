package bip39

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
)

// canonicalEnglishSHA256 is the SHA-256 of the canonical English BIP-39 word
// list as published upstream (bitcoin/bips, bip-0039/english.txt): 2048
// newline-separated words with a trailing newline. It is an external constant,
// not derived from anything in this repository — asserting it is what makes
// English() demonstrably the canonical list rather than merely a list we
// copied. The word list digest vector in wordlist/wordlist.v1.json is
// generated from this same file and so cannot establish this on its own.
const canonicalEnglishSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

func TestEmbeddedWordlistIsCanonical(t *testing.T) {
	sum := sha256.Sum256([]byte(englishWordlist))
	if got := hex.EncodeToString(sum[:]); got != canonicalEnglishSHA256 {
		t.Fatalf("embedded wordlist.txt SHA-256 = %s, want %s (upstream canonical english.txt)",
			got, canonicalEnglishSHA256)
	}
}

// TestEnglishIsSortedAndUnique guards the two structural properties BIP-39
// requires of the English list, independently of the hash above.
func TestEnglishIsSortedAndUnique(t *testing.T) {
	words := strings.Split(strings.TrimRight(englishWordlist, "\n"), "\n")
	if !sort.StringsAreSorted(words) {
		t.Error("word list is not in ascending lexicographic order")
	}
	seen := make(map[string]bool, len(words))
	for _, w := range words {
		if seen[w] {
			t.Fatalf("duplicate word %q", w)
		}
		seen[w] = true
	}
}

func TestEnglishLength(t *testing.T) {
	v := English()
	if v.Len() != 2048 {
		t.Fatalf("Len() = %d, want 2048", v.Len())
	}
}

func TestEnglishBoundaryWords(t *testing.T) {
	v := English()

	first, err := v.Word(0)
	if err != nil {
		t.Fatalf("Word(0): %v", err)
	}
	if first != "abandon" {
		t.Fatalf("Word(0) = %q, want %q", first, "abandon")
	}

	last, err := v.Word(v.Len() - 1)
	if err != nil {
		t.Fatalf("Word(%d): %v", v.Len()-1, err)
	}
	if last != "zoo" {
		t.Fatalf("Word(%d) = %q, want %q", v.Len()-1, last, "zoo")
	}
}

func TestEnglishIndexRoundTrip(t *testing.T) {
	v := English()
	for _, w := range []string{"abandon", "ability", "castle", "orange", "zebra", "zoo"} {
		idx, err := v.Index(w)
		if err != nil {
			t.Fatalf("Index(%q): %v", w, err)
		}
		got, err := v.Word(idx)
		if err != nil {
			t.Fatalf("Word(%d): %v", idx, err)
		}
		if got != w {
			t.Fatalf("round trip for %q: Word(Index(%q)) = %q", w, w, got)
		}
	}
}

func TestEnglishDigestStable(t *testing.T) {
	first := English().Digest()
	second := English().Digest()
	if first != second {
		t.Fatalf("English() digest is not stable across calls")
	}
}
