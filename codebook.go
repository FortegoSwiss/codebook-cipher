package codebook

import (
	"errors"
	"iter"

	"github.com/FortegoSwiss/codebook-cipher/internal/permutation"
	"github.com/FortegoSwiss/codebook-cipher/wordlist"
	"github.com/FortegoSwiss/codebook-cipher/wordlist/bip39"
)

// SeedSize is the exact, required length in bytes of a seed.
const SeedSize = 32

// MaxWords is the largest word list a CodeBook can be built over. The limit
// comes from the algorithm, not from the word list: each Fisher-Yates draw
// reads two keystream bytes and so addresses at most 65,536 positions. A
// longer word list is perfectly valid; it just cannot have a CodeBook
// generated over it.
const MaxWords = 65536

// These bounds are the public face of the generator's own limits. Restating
// them here rather than aliasing keeps the internal package out of this
// package's documented API; the assertions below fail to compile if the two
// ever drift apart.
const (
	_ = uint(SeedSize - permutation.SeedSize)
	_ = uint(permutation.SeedSize - SeedSize)
	_ = uint(MaxWords - permutation.MaxSize)
	_ = uint(permutation.MaxSize - MaxWords)
)

var (
	// ErrInvalidSeedSize is returned by New when the seed is not exactly
	// SeedSize bytes long.
	ErrInvalidSeedSize = errors.New("codebook: seed must be exactly 32 bytes")
	// ErrEmptyWordList is returned by New when either word list has no words.
	ErrEmptyWordList = errors.New("codebook: word lists must contain at least one word")
	// ErrIncompatibleWordLists is returned by New when the source and target
	// word lists do not have the same number of entries.
	ErrIncompatibleWordLists = errors.New("codebook: source and target word lists must have the same length")
	// ErrTooManyWords is returned by New when either word list has more than
	// MaxWords words, which the algorithm cannot permute.
	ErrTooManyWords = errors.New("codebook: word list must not exceed 65536 words")
)

// CodeBook binds a deterministic index permutation to a source and target word
// list. It maps each source word to exactly one target word, one-to-one and
// invertibly. It is generated deterministically from a 32-byte seed.
//
// A CodeBook is immutable once constructed and safe for concurrent use.
//
// The zero CodeBook is empty and valid to use: both its word lists are the
// zero wordlist.List, so Lookup rejects every word with
// wordlist.ErrUnknownWord and Entries yields no entries. New never returns
// one, since it rejects empty word lists.
type CodeBook struct {
	forward permutation.P
	inverse permutation.P
	source  wordlist.List
	target  wordlist.List
}

// Entry is one source-to-target mapping in a CodeBook.
type Entry struct {
	Source string
	Target string
}

// New generates the CodeBook for the given 32-byte seed from source to target.
//
// The seed must be exactly SeedSize bytes; anything else is rejected with
// ErrInvalidSeedSize. Both word lists must hold between one and MaxWords words
// and have the same length. Equal length makes lists algorithmically
// compatible; their contents and ordering remain significant.
// The seed is used only during construction; New does not retain it, and the
// returned CodeBook holds no reference to it, so the caller may overwrite its
// buffer immediately after New returns. That says nothing about memory during
// the call itself: the ChaCha20 keystream derived from the seed necessarily
// exists in memory for the duration of New.
//
// The permutation depends only on the seed and the word lists' shared
// length, never on their contents: two different word-list pairs of the same
// length produce the identical underlying permutation under the same seed,
// merely relabelled through each pair's own words. A seed therefore
// corresponds to exactly one permutation per length, not to a specific
// word-list pair — reproducing a specific CodeBook requires the seed
// together with the exact word lists used to build it, in this and in every
// other conforming implementation. The caller is responsible for pinning
// which word lists go with which seed (for example, by index); New cannot
// detect that the wrong word lists were supplied as long as their lengths
// match. See README.md.
func New(seed []byte, source, target wordlist.List) (CodeBook, error) {
	if len(seed) != SeedSize {
		return CodeBook{}, ErrInvalidSeedSize
	}
	switch {
	case source.Len() == 0 || target.Len() == 0:
		return CodeBook{}, ErrEmptyWordList
	case source.Len() != target.Len():
		return CodeBook{}, ErrIncompatibleWordLists
	case source.Len() > MaxWords:
		return CodeBook{}, ErrTooManyWords
	}

	p, err := permutation.Generate(seed, source.Len())
	if err != nil {
		if errors.Is(err, permutation.ErrInvalidSeedSize) {
			return CodeBook{}, ErrInvalidSeedSize
		}
		return CodeBook{}, err
	}

	return CodeBook{
		forward: p,
		inverse: p.Inverse(),
		source:  source,
		target:  target,
	}, nil
}

// NewBIP39English generates a CodeBook that maps the canonical English BIP-39
// word list to itself. It is a convenience constructor for the Fortego
// CodeBook cipher's primary use case.
func NewBIP39English(seed []byte) (CodeBook, error) {
	words := bip39.English()
	return New(seed, words, words)
}

// Lookup maps a source word to its corresponding target word. A word not in
// the source word list is rejected with wordlist.ErrUnknownWord.
func (c CodeBook) Lookup(source string) (string, error) {
	i, err := c.source.Index(source)
	if err != nil {
		return "", err
	}
	j, ok := c.forward.At(i)
	if !ok {
		panic("codebook: permutation shorter than the source word list")
	}
	return c.target.Word(j)
}

// Reverse returns an immutable view of this CodeBook in the other direction.
// It swaps the source and target word lists and uses the inverse permutation;
// it does not generate a new permutation or copy any word list data.
func (c CodeBook) Reverse() CodeBook {
	return CodeBook{
		forward: c.inverse,
		inverse: c.forward,
		source:  c.target,
		target:  c.source,
	}
}

// Entries yields source-to-target mappings in source word-list order. The
// sequence is lazy and allocation-free apart from the Entry values yielded to
// its consumer. It yields exactly as many entries as the source word list has
// words, unless its consumer stops early.
//
// Entries panics if the CodeBook's internal lengths disagree, which New makes
// impossible. The alternative would be to end the sequence early, and a
// silently short cipher table is the one failure a printed CodeBook must never
// have: it would encipher a word that can never be deciphered again.
func (c CodeBook) Entries() iter.Seq[Entry] {
	return func(yield func(Entry) bool) {
		for i := 0; i < c.source.Len(); i++ {
			source, err := c.source.Word(i)
			if err != nil {
				panic("codebook: source word list shorter than its own length: " + err.Error())
			}
			mappedIndex, ok := c.forward.At(i)
			if !ok {
				panic("codebook: permutation shorter than the source word list")
			}
			target, err := c.target.Word(mappedIndex)
			if err != nil {
				panic("codebook: target word list shorter than the source word list: " + err.Error())
			}
			if !yield(Entry{Source: source, Target: target}) {
				return
			}
		}
	}
}
