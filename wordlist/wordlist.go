// Package wordlist provides an immutable, ordered list of unique words and a
// digest that identifies its exact contents and order.
//
// A word list says only what its name says: which words exist, in which
// order, and that each appears exactly once. It imposes no upper bound on the
// number of words — that limit belongs to whatever algorithm consumes the
// list, not to the list itself.
package wordlist

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

var (
	// ErrEmpty is returned when a word list would contain no words at all.
	ErrEmpty = errors.New("wordlist: must contain at least one word")
	// ErrEmptyWord is returned when a word is the empty string.
	ErrEmptyWord = errors.New("wordlist: words must not be empty")
	// ErrDuplicateWord is returned when a word repeats an earlier one.
	ErrDuplicateWord = errors.New("wordlist: words must not repeat")
	// ErrUnknownWord is returned when a word is not present in the list.
	ErrUnknownWord = errors.New("wordlist: word not found")
	// ErrInvalidIndex is returned when an index is outside the list's range.
	ErrInvalidIndex = errors.New("wordlist: index out of range")
)

// List is an immutable, ordered list of words bound to positional indices
// 0..Len()-1. Words are treated as opaque byte sequences and compared
// byte-for-byte: construction performs no encoding validation and no
// normalisation of any kind — no case folding, no whitespace trimming, no
// Unicode normalisation.
//
// The zero List is empty and valid to query; every lookup on it fails. A List
// is safe for concurrent use.
type List struct {
	words  []string
	index  map[string]int
	digest [32]byte
}

// New constructs a List from words. The slice is defensively copied, so later
// changes by the caller cannot affect the List. An empty list, an empty word,
// or a repeated word is rejected with an error.
//
// New imposes no upper bound on len(words); a consumer that cannot handle
// arbitrarily long lists enforces its own limit.
func New(words []string) (List, error) {
	if len(words) == 0 {
		return List{}, ErrEmpty
	}

	cp := make([]string, len(words))
	copy(cp, words)

	idx := make(map[string]int, len(cp))
	for i, w := range cp {
		if w == "" {
			return List{}, ErrEmptyWord
		}
		if _, exists := idx[w]; exists {
			return List{}, ErrDuplicateWord
		}
		idx[w] = i
	}

	return List{
		words:  cp,
		index:  idx,
		digest: digest(cp),
	}, nil
}

// Len returns the number of words in the list.
func (l List) Len() int {
	return len(l.words)
}

// Word returns the word at index i. An out-of-range i is rejected with
// ErrInvalidIndex.
func (l List) Word(i int) (string, error) {
	if i < 0 || i >= len(l.words) {
		return "", ErrInvalidIndex
	}
	return l.words[i], nil
}

// Index returns the position of word in the list. An unknown word is rejected
// with ErrUnknownWord.
func (l List) Index(word string) (int, error) {
	i, ok := l.index[word]
	if !ok {
		return 0, ErrUnknownWord
	}
	return i, nil
}

// Words returns a copy of the list's words in order.
func (l List) Words() []string {
	out := make([]string, len(l.words))
	copy(out, l.words)
	return out
}

// Digest returns the normative digest of the list, so that two parties can
// confirm they hold the same words in the same order.
func (l List) Digest() [32]byte {
	return l.digest
}

// digest computes the normative SHA-256 digest: a 4-byte little-endian word
// count, followed by
// each word as a 4-byte little-endian byte length and its raw bytes, in list
// order.
func digest(words []string) [32]byte {
	h := sha256.New()

	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(len(words)))
	h.Write(buf[:])

	for _, w := range words {
		binary.LittleEndian.PutUint32(buf[:], uint32(len(w)))
		h.Write(buf[:])
		h.Write([]byte(w))
	}

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
