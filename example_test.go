package codebook_test

import (
	"fmt"

	"github.com/FortegoSwiss/codebook-cipher"
	"github.com/FortegoSwiss/codebook-cipher/wordlist/bip39"
)

// This example generates a CodeBook from the canonical English BIP-39 word
// list to itself, then looks up a word in both directions.
// In real use, seed must come from a trusted source — this package neither
// generates nor stores seeds itself.
func Example() {
	seed := make([]byte, codebook.SeedSize) // all-zero here only to keep the example deterministic

	words := bip39.English()
	cb, err := codebook.New(seed, words, words)
	if err != nil {
		panic(err)
	}

	mapped, err := cb.Lookup("abandon")
	if err != nil {
		panic(err)
	}
	fmt.Println(mapped)

	back, err := cb.Reverse().Lookup(mapped)
	if err != nil {
		panic(err)
	}
	fmt.Println(back)

	// Output:
	// eye
	// abandon
}
