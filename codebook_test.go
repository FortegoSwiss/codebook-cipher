package codebook

import (
	"errors"
	"strconv"
	"testing"

	"github.com/FortegoSwiss/codebook-cipher/wordlist"
	"github.com/FortegoSwiss/codebook-cipher/wordlist/bip39"
)

func testSeed(fill byte) []byte {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = fill
	}
	return seed
}

func testWordList(t *testing.T, words ...string) wordlist.List {
	t.Helper()
	l, err := wordlist.New(words)
	if err != nil {
		t.Fatalf("wordlist.New: %v", err)
	}
	return l
}

func testCodeBook(t *testing.T, fill byte, source, target []string) CodeBook {
	t.Helper()
	cb, err := New(testSeed(fill), testWordList(t, source...), testWordList(t, target...))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cb
}

func TestNewRejectsInvalidSeedSize(t *testing.T) {
	words := testWordList(t, "alpha", "bravo", "charlie")
	for _, n := range []int{0, 1, 31, 33, 64} {
		if _, err := New(make([]byte, n), words, words); !errors.Is(err, ErrInvalidSeedSize) {
			t.Errorf("New(seed of %d bytes) error = %v, want ErrInvalidSeedSize", n, err)
		}
	}
}

func TestNewRejectsEmptyAndIncompatibleWordLists(t *testing.T) {
	nonEmpty := testWordList(t, "alpha")
	if _, err := New(testSeed(0x10), wordlist.List{}, nonEmpty); !errors.Is(err, ErrEmptyWordList) {
		t.Fatalf("New(empty source) error = %v, want ErrEmptyWordList", err)
	}
	if _, err := New(testSeed(0x10), nonEmpty, wordlist.List{}); !errors.Is(err, ErrEmptyWordList) {
		t.Fatalf("New(empty target) error = %v, want ErrEmptyWordList", err)
	}
	if _, err := New(testSeed(0x10), nonEmpty, testWordList(t, "one", "two")); !errors.Is(err, ErrIncompatibleWordLists) {
		t.Fatalf("New(different lengths) error = %v, want ErrIncompatibleWordLists", err)
	}
}

func TestNewRejectsOversizedWordLists(t *testing.T) {
	words := make([]string, MaxWords+1)
	for i := range words {
		words[i] = "word" + strconv.Itoa(i)
	}
	l, err := wordlist.New(words)
	if err != nil {
		t.Fatalf("wordlist.New(%d words) = %v", len(words), err)
	}
	if _, err := New(testSeed(0x17), l, l); !errors.Is(err, ErrTooManyWords) {
		t.Fatalf("New(%d words) error = %v, want ErrTooManyWords", l.Len(), err)
	}
}

func TestNewDoesNotRetainSeed(t *testing.T) {
	source := testWordList(t, "alpha", "bravo", "charlie")
	target := testWordList(t, "01", "02", "03")
	seed := testSeed(0x11)
	cb, err := New(seed, source, target)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before, err := cb.Lookup("alpha")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	for i := range seed {
		seed[i] = 0
	}
	after, err := cb.Lookup("alpha")
	if err != nil {
		t.Fatalf("Lookup after seed wipe: %v", err)
	}
	if after != before {
		t.Fatalf("CodeBook changed after caller wiped the seed: %q then %q", before, after)
	}
}

func TestNewIsDeterministic(t *testing.T) {
	source := []string{"alpha", "bravo", "charlie", "delta"}
	target := []string{"01", "02", "03", "04"}
	a := testCodeBook(t, 0x12, source, target)
	b := testCodeBook(t, 0x12, source, target)
	aEntries, bEntries := collect(a.Entries()), collect(b.Entries())
	if len(aEntries) != len(bEntries) {
		t.Fatalf("deterministic CodeBooks yielded different entry counts")
	}
	for i := range aEntries {
		if aEntries[i] != bEntries[i] {
			t.Fatalf("same seed and word lists disagree at entry %d: %#v != %#v", i, aEntries[i], bEntries[i])
		}
	}
}

func TestNewBIP39EnglishMatchesGenericConstructor(t *testing.T) {
	seed := testSeed(0x18)
	got, err := NewBIP39English(seed)
	if err != nil {
		t.Fatalf("NewBIP39English: %v", err)
	}
	words := bip39.English()
	want, err := New(seed, words, words)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	gotEntries, wantEntries := collect(got.Entries()), collect(want.Entries())
	if len(gotEntries) != len(wantEntries) {
		t.Fatalf("NewBIP39English yielded %d entries, generic New yielded %d", len(gotEntries), len(wantEntries))
	}
	for i := range gotEntries {
		if gotEntries[i] != wantEntries[i] {
			t.Fatalf("entry %d = %#v, want %#v", i, gotEntries[i], wantEntries[i])
		}
	}
}

func TestLookupBindsDistinctCompatibleWordLists(t *testing.T) {
	source := []string{"alpha", "bravo", "charlie", "delta", "echo"}
	target := []string{"01", "02", "03", "04", "05"}
	cb := testCodeBook(t, 0x13, source, target)

	seenTargets := make(map[string]bool, len(target))
	for _, word := range source {
		mapped, err := cb.Lookup(word)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", word, err)
		}
		seenTargets[mapped] = true
		back, err := cb.Reverse().Lookup(mapped)
		if err != nil {
			t.Fatalf("Reverse().Lookup(%q): %v", mapped, err)
		}
		if back != word {
			t.Fatalf("Reverse().Lookup(Lookup(%q)) = %q", word, back)
		}
	}
	if len(seenTargets) != len(target) {
		t.Fatalf("Lookup produced %d distinct targets, want %d", len(seenTargets), len(target))
	}
}

func TestEntriesFollowSourceOrderAndReverseTargetOrder(t *testing.T) {
	source := []string{"alpha", "bravo", "charlie", "delta"}
	target := []string{"01", "02", "03", "04"}
	cb := testCodeBook(t, 0x14, source, target)

	var entries []Entry
	for entry := range cb.Entries() {
		entries = append(entries, entry)
	}
	if len(entries) != len(source) {
		t.Fatalf("Entries yielded %d entries, want %d", len(entries), len(source))
	}
	for i, entry := range entries {
		if entry.Source != source[i] {
			t.Errorf("Entries()[%d].Source = %q, want %q", i, entry.Source, source[i])
		}
		mapped, err := cb.Lookup(entry.Source)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", entry.Source, err)
		}
		if entry.Target != mapped {
			t.Errorf("Entries()[%d].Target = %q, Lookup = %q", i, entry.Target, mapped)
		}
	}

	for i, entry := range collect(cb.Reverse().Entries()) {
		if entry.Source != target[i] {
			t.Errorf("Reverse().Entries()[%d].Source = %q, want %q", i, entry.Source, target[i])
		}
		mapped, err := cb.Reverse().Lookup(entry.Source)
		if err != nil {
			t.Fatalf("Reverse().Lookup(%q): %v", entry.Source, err)
		}
		if entry.Target != mapped {
			t.Errorf("Reverse().Entries()[%d].Target = %q, Lookup = %q", i, entry.Target, mapped)
		}
	}
}

func TestReverseIsAnInvolution(t *testing.T) {
	cb := testCodeBook(t, 0x15, []string{"alpha", "bravo"}, []string{"01", "02"})
	for _, word := range []string{"alpha", "bravo"} {
		want, err := cb.Lookup(word)
		if err != nil {
			t.Fatal(err)
		}
		got, err := cb.Reverse().Reverse().Lookup(word)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("Reverse().Reverse().Lookup(%q) = %q, want %q", word, got, want)
		}
	}
}

func TestLookupRejectsUnknownSourceWord(t *testing.T) {
	cb := testCodeBook(t, 0x16, []string{"alpha", "bravo"}, []string{"01", "02"})
	if _, err := cb.Lookup("nonexistent"); !errors.Is(err, wordlist.ErrUnknownWord) {
		t.Errorf("Lookup(unknown) error = %v, want wordlist.ErrUnknownWord", err)
	}
}

func collect(seq func(func(Entry) bool)) []Entry {
	var entries []Entry
	seq(func(entry Entry) bool {
		entries = append(entries, entry)
		return true
	})
	return entries
}

// TestEntriesPanicsOnBrokenInvariant pins that a CodeBook whose lengths
// disagree fails loudly instead of yielding a short table. New cannot produce
// such a value, so the test has to assemble one directly — which is the point:
// the guard must survive any future refactor that could break the invariant.
func TestEntriesPanicsOnBrokenInvariant(t *testing.T) {
	full := testWordList(t, "alpha", "bravo", "charlie")
	short := testWordList(t, "01", "02")

	good, err := New(testSeed(0x21), full, full)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A 3-element permutation over a 2-word target list: entry 3 has nowhere
	// to point.
	broken := CodeBook{
		forward: good.forward,
		inverse: good.inverse,
		source:  full,
		target:  short,
	}

	defer func() {
		if recover() == nil {
			t.Fatal("Entries returned normally over an inconsistent CodeBook, want panic")
		}
	}()
	for range broken.Entries() { //nolint:revive // draining is the point
	}
}

// TestEntriesStopsEarlyWithoutSideEffects pins that breaking out of Entries
// midway leaves the CodeBook usable: each call to Entries builds its sequence
// fresh rather than advancing any state shared with the CodeBook, so an early
// stop neither panics nor affects a later call.
func TestEntriesStopsEarlyWithoutSideEffects(t *testing.T) {
	source := []string{"alpha", "bravo", "charlie", "delta", "echo"}
	target := []string{"01", "02", "03", "04", "05"}
	cb := testCodeBook(t, 0x22, source, target)

	const stopAfter = 2
	var stopped []Entry
	for entry := range cb.Entries() {
		stopped = append(stopped, entry)
		if len(stopped) == stopAfter {
			break
		}
	}
	if len(stopped) != stopAfter {
		t.Fatalf("early break collected %d entries, want %d", len(stopped), stopAfter)
	}

	full := collect(cb.Entries())
	if len(full) != len(source) {
		t.Fatalf("Entries() after an earlier early stop yielded %d entries, want %d", len(full), len(source))
	}
	for i, entry := range stopped {
		if entry != full[i] {
			t.Errorf("entry %d after early stop = %#v, want %#v", i, entry, full[i])
		}
	}
}
