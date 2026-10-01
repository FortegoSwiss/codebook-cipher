// Package permutation implements the seed-to-permutation core: a ChaCha20-IETF
// keystream driving a descending Fisher-Yates shuffle with unbiased rejection
// sampling. The exact-behaviour rules it implements are stated in README.md
// and pinned by the conformance vectors beside this package.
//
// It is internal on purpose. A permutation of bare indices is a step towards
// a CodeBook, not something a user of this module should hold: the public API
// deals in words and word lists. Identifiers are exported here only so the
// root package and the conformance-vector tests can reach them.
package permutation

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

// SeedSize is the exact, required length in bytes of a seed.
const SeedSize = 32

// MinSize and MaxSize are the inclusive bounds on a permutation's size. The
// upper bound follows from the two-byte draw width.
const (
	MinSize = 1
	MaxSize = 65536
)

var (
	// ErrInvalidSeedSize is returned when a seed is not exactly SeedSize
	// bytes long.
	ErrInvalidSeedSize = errors.New("codebook: seed must be exactly 32 bytes")
	// ErrInvalidSize is returned when a requested size is outside
	// MinSize..MaxSize.
	ErrInvalidSize = errors.New("codebook: size must be between 1 and 65536")
)

// P is a deterministic, seed-generated bijection over the index range
// 0..Len()-1, applied in the forward direction P[index] = mappedIndex.
type P struct {
	p []uint32
}

// stepObserver, if non-nil, is invoked after each Fisher-Yates step with the
// step index i, the candidate range and rejection-sampling limit, every raw
// 16-bit draw attempted for that step in stream order (the last entry is
// always the accepted one), and the resulting accepted j. It exists so the
// conformance-vector tests can verify the algorithm's documented intermediate
// behaviour against draws.v1.json. It is used only by the internal Trace
// helper, so ordinary Generate callers carry neither the callback nor its
// allocations.
type stepObserver func(i int, rng, limit uint32, draws []uint32, j, swapPI, swapPJ uint32)

// Generate deterministically derives a permutation of the given size from a
// SeedSize-byte seed. The
// same (seed, size) pair always produces the same permutation. The seed is
// not retained.
func Generate(seed []byte, size int) (P, error) {
	return generate(seed, size, nil)
}

// Trace generates a permutation using the same implementation as Generate and
// calls observe after every shuffle step. It exists for repository-internal
// golden-vector generation and verification; internal packages are not part
// of this module's public API.
func Trace(seed []byte, size int, observe func(i int, rng, limit uint32, draws []uint32, j, swapPI, swapPJ uint32)) (P, error) {
	return generate(seed, size, stepObserver(observe))
}

// generate is the shared implementation behind Generate and Trace.
func generate(seed []byte, size int, observe stepObserver) (P, error) {
	if len(seed) != SeedSize {
		return P{}, ErrInvalidSeedSize
	}
	if size < MinSize || size > MaxSize {
		return P{}, ErrInvalidSize
	}

	p := make([]uint32, size)
	for i := range p {
		p[i] = uint32(i)
	}

	if size == 1 {
		return P{p: p}, nil
	}

	stream, err := newKeystream(seed)
	if err != nil {
		// Unreachable: key and nonce lengths above are fixed and valid.
		return P{}, fmt.Errorf("codebook: chacha20 init: %w", err)
	}

	for i := size - 1; i >= 1; i-- {
		rng := uint32(i) + 1
		limit := (65536 / rng) * rng

		var j uint32
		var draws []uint32
		for {
			v := stream.draw16()
			if observe != nil {
				draws = append(draws, v)
			}
			if v >= limit {
				continue
			}
			j = v % rng
			break
		}
		if observe != nil {
			observe(i, rng, limit, draws, j, p[i], p[j])
		}

		p[uint32(i)], p[j] = p[j], p[uint32(i)]
	}

	return P{p: p}, nil
}

// Len returns the permutation's size.
func (p P) Len() int {
	return len(p.p)
}

// At returns the forward mapping of index: P[index]. ok is false if index is
// out of range. Reporting that as a bool rather than an error keeps the
// public sentinel errors in the root package, where users can see them.
func (p P) At(index int) (value int, ok bool) {
	if index < 0 || index >= len(p.p) {
		return 0, false
	}
	return int(p.p[index]), true
}

// Inverse returns the inverse permutation q, satisfying q[P[i]] = i for every
// valid i. Computing the inverse consumes no keystream and performs no
// additional cryptographic operations; it is a pure function of the
// already-generated permutation.
func (p P) Inverse() P {
	inv := make([]uint32, len(p.p))
	for i, v := range p.p {
		inv[v] = uint32(i)
	}
	return P{p: inv}
}

// keystream draws successive big-endian uint16 values from a ChaCha20
// keystream, two bytes at a time, in stream order.
type keystream struct {
	cipher *chacha20.Cipher
}

// newKeystream creates the exact stream used by Generate: ChaCha20-IETF with
// seed as its key, an all-zero 96-bit nonce, and the initial counter at zero.
func newKeystream(seed []byte) (*keystream, error) {
	var nonce [chacha20.NonceSize]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(seed, nonce[:])
	if err != nil {
		return nil, err
	}
	return &keystream{cipher: cipher}, nil
}

// read advances the stream by len(dst) bytes and writes those bytes to dst.
func (k *keystream) read(dst []byte) {
	clear(dst)
	k.cipher.XORKeyStream(dst, dst)
}

func (k *keystream) draw16() uint32 {
	var out [2]byte
	k.read(out[:])
	return uint32(binary.BigEndian.Uint16(out[:]))
}
