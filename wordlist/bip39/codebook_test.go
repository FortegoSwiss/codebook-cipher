package bip39_test

import (
	"testing"

	"github.com/FortegoSwiss/codebook-cipher"
	"github.com/FortegoSwiss/codebook-cipher/wordlist/bip39"
)

func TestCodeBookRoundTripEnglish(t *testing.T) {
	words := bip39.English()

	seed := make([]byte, codebook.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	cb, err := codebook.New(seed, words, words)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, w := range []string{"abandon", "ability", "castle", "orange", "zebra", "zoo"} {
		mapped, err := cb.Lookup(w)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", w, err)
		}
		back, err := cb.Reverse().Lookup(mapped)
		if err != nil {
			t.Fatalf("Reverse().Lookup(%q): %v", mapped, err)
		}
		if back != w {
			t.Fatalf("round trip for %q: Reverse().Lookup(Lookup(%q)) = %q", w, w, back)
		}
	}
}
