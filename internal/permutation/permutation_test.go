package permutation

import (
	"errors"
	"strconv"
	"testing"
)

// testSeed returns a SeedSize-byte seed of repeated fill bytes.
func testSeed(fill byte) []byte {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = fill
	}
	return seed
}

// mustGenerate generates a permutation or fails the test.
func mustGenerate(t *testing.T, fill byte, size int) P {
	t.Helper()
	p, err := Generate(testSeed(fill), size)
	if err != nil {
		t.Fatalf("Generate(size=%d): %v", size, err)
	}
	return p
}

func TestGenerateInvalidSize(t *testing.T) {
	for _, size := range []int{-1, 0, MaxSize + 1, 1_000_000} {
		_, err := Generate(testSeed(0x01), size)
		if !errors.Is(err, ErrInvalidSize) {
			t.Errorf("Generate(size=%d) error = %v, want ErrInvalidSize", size, err)
		}
	}
}

func TestGenerateInvalidSeedSize(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		_, err := Generate(make([]byte, n), 8)
		if !errors.Is(err, ErrInvalidSeedSize) {
			t.Errorf("Generate(seed of %d bytes) error = %v, want ErrInvalidSeedSize", n, err)
		}
	}
}

func TestGenerateSizeOneIsIdentity(t *testing.T) {
	p := mustGenerate(t, 0x02, 1)
	if p.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", p.Len())
	}
	v, ok := p.At(0)
	if !ok {
		t.Fatalf("At(0): out of range")
	}
	if v != 0 {
		t.Fatalf("At(0) = %d, want 0 (identity)", v)
	}
}

func TestGenerateIsBijection(t *testing.T) {
	for _, size := range []int{2, 3, 7, 64, 1024, 2048} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			p := mustGenerate(t, 0x03, size)
			seen := make([]bool, size)
			for i := 0; i < size; i++ {
				v, ok := p.At(i)
				if !ok {
					t.Fatalf("At(%d): out of range", i)
				}
				if v < 0 || v >= size {
					t.Fatalf("At(%d) = %d, out of range [0,%d)", i, v, size)
				}
				if seen[v] {
					t.Fatalf("value %d produced by more than one index; not a bijection", v)
				}
				seen[v] = true
			}
		})
	}
}

func TestGenerateDeterministic(t *testing.T) {
	p1 := mustGenerate(t, 0x04, 2048)
	p2 := mustGenerate(t, 0x04, 2048)
	for i := 0; i < 2048; i++ {
		a, _ := p1.At(i)
		b, _ := p2.At(i)
		if a != b {
			t.Fatalf("same seed produced different permutations at index %d: %d != %d", i, a, b)
		}
	}
}

func TestGenerateDifferentSeedsDiffer(t *testing.T) {
	p1 := mustGenerate(t, 0x05, 2048)
	p2 := mustGenerate(t, 0x06, 2048)
	differs := false
	for i := 0; i < 2048; i++ {
		a, _ := p1.At(i)
		b, _ := p2.At(i)
		if a != b {
			differs = true
			break
		}
	}
	if !differs {
		t.Fatalf("two different seeds produced an identical permutation")
	}
}

// TestGeneratePermutationDoesNotRetainSeed pins that generation copies
// whatever it needs out of the caller's buffer before returning.
func TestGenerateDoesNotRetainSeed(t *testing.T) {
	seed := testSeed(0x07)
	p1, err := Generate(seed, 256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for i := range seed {
		seed[i] = 0x00
	}
	p2 := mustGenerate(t, 0x07, 256)
	for i := 0; i < 256; i++ {
		a, _ := p1.At(i)
		b, _ := p2.At(i)
		if a != b {
			t.Fatalf("permutation changed after the caller wiped its seed, at index %d", i)
		}
	}
}

func TestInverse(t *testing.T) {
	for _, size := range []int{1, 2, 3, 64, 2048} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			p := mustGenerate(t, 0x08, size)
			inv := p.Inverse()
			if inv.Len() != size {
				t.Fatalf("Inverse().Len() = %d, want %d", inv.Len(), size)
			}
			for i := 0; i < size; i++ {
				forward, ok := p.At(i)
				if !ok {
					t.Fatalf("At(%d): out of range", i)
				}
				back, ok := inv.At(forward)
				if !ok {
					t.Fatalf("Inverse().At(%d): out of range", forward)
				}
				if back != i {
					t.Fatalf("Inverse().At(At(%d)) = %d, want %d", i, back, i)
				}
			}
		})
	}
}

func TestAtInvalidIndex(t *testing.T) {
	p := mustGenerate(t, 0x09, 10)
	for _, idx := range []int{-1, 10, 11, 1000} {
		if _, ok := p.At(idx); ok {
			t.Errorf("At(%d) reported ok, want out of range", idx)
		}
	}
}

func TestGenerateMaxSizeNoPanic(t *testing.T) {
	p := mustGenerate(t, 0x0A, MaxSize)
	if p.Len() != MaxSize {
		t.Fatalf("Len() = %d, want %d", p.Len(), MaxSize)
	}
}
