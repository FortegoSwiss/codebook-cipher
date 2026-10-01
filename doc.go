// Package codebook generates deterministic, reproducible mappings between
// compatible word lists from a 32-byte seed.
//
// A CodeBook maps every word of a source word list to exactly one word of a
// target word list, one-to-one and invertibly. Applied to a sequence of words
// it acts as a substitution cipher: the result is a new sequence drawn from
// the target word list, meaningless without the CodeBook and reversible with
// it.
//
//	words := bip39.English()
//	cb, err := codebook.New(seed, words, words)
//	mapped, err := cb.Lookup("abandon")
//	back, err := cb.Reverse().Lookup(mapped)
//
// The permutation is derived from the seed via ChaCha20-IETF and a descending
// Fisher-Yates shuffle, using only the seed and the word lists' shared
// length — the words themselves never enter the derivation. The algorithm is
// frozen for v1: the same seed and length always produce the same
// permutation in every conforming implementation, in any language, no matter
// which word lists of that length are supplied. Reproducing a specific
// CodeBook therefore requires the seed together with the exact word lists it
// was built from; this package defines no serialisation format for a
// CodeBook, and never needs one.
//
// The package generates and looks up permutations, and does nothing else. It
// neither generates nor derives seeds, and it has no notion of what the words
// it maps represent.
//
// See README.md for the model, use, and compatibility guarantees.
package codebook
