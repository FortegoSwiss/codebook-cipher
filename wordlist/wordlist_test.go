package wordlist

import (
	"errors"
	"strconv"
	"testing"
)

func TestNewValid(t *testing.T) {
	words := []string{"alpha", "bravo", "charlie"}
	v, err := New(words)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", v.Len())
	}
	for i, w := range words {
		got, err := v.Word(i)
		if err != nil {
			t.Fatalf("Word(%d): %v", i, err)
		}
		if got != w {
			t.Fatalf("Word(%d) = %q, want %q", i, got, w)
		}
		idx, err := v.Index(w)
		if err != nil {
			t.Fatalf("Index(%q): %v", w, err)
		}
		if idx != i {
			t.Fatalf("Index(%q) = %d, want %d", w, idx, i)
		}
	}
}

func TestNewRejectsEmptyList(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrEmpty) {
		t.Errorf("New(nil) error = %v, want ErrEmpty", err)
	}
	if _, err := New([]string{}); !errors.Is(err, ErrEmpty) {
		t.Errorf("New([]) error = %v, want ErrEmpty", err)
	}
}

// TestNewHasNoUpperBound pins the deliberate absence of a size ceiling here.
// The 65,536-word limit is a property of the CodeBook algorithm, not of a
// word list, and lives in the codebook package. A longer list must remain a
// perfectly valid word list.
func TestNewHasNoUpperBound(t *testing.T) {
	const oversizedForCodeBook = 65536 + 1

	words := make([]string, oversizedForCodeBook)
	for i := range words {
		words[i] = "word" + strconv.Itoa(i)
	}

	l, err := New(words)
	if err != nil {
		t.Fatalf("New(len=%d): %v, want no error", len(words), err)
	}
	if l.Len() != oversizedForCodeBook {
		t.Fatalf("Len() = %d, want %d", l.Len(), oversizedForCodeBook)
	}
	if _, err := l.Index("word65536"); err != nil {
		t.Fatalf("Index on an oversized list: %v", err)
	}
}

func TestNewRejectsEmptyWord(t *testing.T) {
	_, err := New([]string{"alpha", "", "charlie"})
	if !errors.Is(err, ErrEmptyWord) {
		t.Errorf("error = %v, want ErrEmptyWord", err)
	}
}

func TestNewRejectsDuplicates(t *testing.T) {
	_, err := New([]string{"alpha", "bravo", "alpha"})
	if !errors.Is(err, ErrDuplicateWord) {
		t.Errorf("error = %v, want ErrDuplicateWord", err)
	}
}

func TestNewNoImplicitNormalisation(t *testing.T) {
	// "Alpha", "alpha" and " alpha" must all be treated as distinct,
	// exact entries: no case folding, no trimming.
	v, err := New([]string{"Alpha", "alpha", " alpha"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v.Len() != 3 {
		t.Fatalf("Len() = %d, want 3 (entries must not be folded together)", v.Len())
	}
	if _, err := v.Index("ALPHA"); !errors.Is(err, ErrUnknownWord) {
		t.Errorf("Index(%q) error = %v, want ErrUnknownWord", "ALPHA", err)
	}
}

func TestNewDefensiveCopy(t *testing.T) {
	words := []string{"alpha", "bravo"}
	v, err := New(words)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	words[0] = "mutated"

	got, err := v.Word(0)
	if err != nil {
		t.Fatalf("Word(0): %v", err)
	}
	if got != "alpha" {
		t.Fatalf("List aliased caller's slice: Word(0) = %q, want %q", got, "alpha")
	}
}

func TestWordInvalidIndex(t *testing.T) {
	v, err := New([]string{"alpha", "bravo"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, idx := range []int{-1, 2, 100} {
		if _, err := v.Word(idx); !errors.Is(err, ErrInvalidIndex) {
			t.Errorf("Word(%d) error = %v, want ErrInvalidIndex", idx, err)
		}
	}
}

func TestDigest(t *testing.T) {
	v1, err := New([]string{"alpha", "bravo", "charlie"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v2, err := New([]string{"alpha", "bravo", "charlie"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v1.Digest() != v2.Digest() {
		t.Fatalf("identical word lists produced different digests")
	}

	reordered, err := New([]string{"bravo", "alpha", "charlie"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v1.Digest() == reordered.Digest() {
		t.Fatalf("reordered word list produced the same digest; order must be significant")
	}

	different, err := New([]string{"alpha", "bravo", "delta"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v1.Digest() == different.Digest() {
		t.Fatalf("different word list content produced the same digest")
	}
}
