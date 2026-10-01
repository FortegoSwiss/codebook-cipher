# Fortego CodeBook Cipher

The Fortego CodeBook Cipher is a manual, reversible
[substitution cipher](https://en.wikipedia.org/wiki/Substitution_cipher) for
wallet seed phrases, or mnemonics, defined by
[Bitcoin Improvement Proposal 39 (BIP-39)](https://bips.dev/39/). It was developed for Fortego's backup service to address a
simple tension: a mnemonic must remain recoverable, but a copied [plaintext](https://csrc.nist.gov/glossary/term/plaintext)
mnemonic gives its holder full access to the wallet.

The cipher replaces each of the 2,048 BIP-39 words with exactly one BIP-39
word. The result can be written down as ordinary words, while the
separate lookup table, called a CodeBook, supplies the replacement needed
to interpret them. The
user can encipher and decipher word by word with a printed table, without
software, arithmetic, or an online service.

One table has two presentations. In the forward presentation, an original word
gives its replacement. In the reversed presentation, a replacement word gives
its original. Both are views of one [permutation](https://en.wikipedia.org/wiki/Permutation); no second cipher or secret is
needed for deciphering. A word-for-word substitution preserves the BIP-39 word
list but not its [checksum](https://bips.dev/39/#generating-the-mnemonic),
so the [ciphertext](https://csrc.nist.gov/glossary/term/ciphertext) is generally
not itself a valid mnemonic.

A [seed](https://csrc.nist.gov/glossary/term/seed) is the input that determines
the table. This library's CodeBook seed is separate from the wallet seed
represented by the mnemonic.

> **Security note:** A CodeBook is a reversible substitution system, not a
> replacement for secure seed generation, wallet backups, or separate storage
> of secrets. Anyone who obtains the ciphertext and its matching CodeBook (or
> its seed) can recover the mnemonic.
>
> When creating a backup, map the words as they are transcribed from the
> wallet, then immediately perform an independent reverse-mapping pass and
> have the wallet validate the recovered mnemonic. This checks both
> transcription and mapping before the backup is relied upon.

A repeated plaintext word produces the same replacement word, so ciphertext
reveals repetitions and word positions. A known original/replacement pair
reveals that mapping everywhere the same table is used. Reusing a CodeBook for
several backups combines those observations and increases exposure. Use a
separate table per backup and keep each table separate from its ciphertext.
The substitution has no authentication: an attacker can change words without
an integrity tag, and a recovered mnemonic's checksum is not proof of origin.
A cryptographic permutation generator does not remove these substitution limits.
All published example seeds and mnemonics are synthetic and must never be used
for a wallet. See [security policy](SECURITY.md) for reporting and review status.

> **Checksum note:** The BIP-39 checksum belongs to the plaintext mnemonic.
> Mapping preserves the word list but normally invalidates that checksum, so a
> wallet can validate only the mnemonic recovered after reverse mapping. The
> checksum detects many mistakes; it does not authenticate the ciphertext.

The algorithm's exact behaviour is pinned by conformance vectors: fixed
inputs paired with their expected outputs. They let implementations check
that the same seed and word lists reproduce the same CodeBook.

---

- [Use from Go](#use-from-go): installation, lookup, and custom word lists.
- [How the permutation is derived](#how-the-permutation-is-derived): algorithm and exact behaviour.
- [Specification and conformance vectors](#specification-and-conformance-vectors): implementation boundaries and vector provenance.
- [Algorithm and module versions](#algorithm-and-module-versions): output stability and Go API compatibility.

---

## Use from Go

### Quick start

Install the [Go module](https://go.dev/doc/modules/gomod-ref). The example
creates a CodeBook from a seed, looks up a word in both directions, and
lists the forward table:

```sh
go get github.com/FortegoSwiss/codebook-cipher
```

```go
package main

import (
	"fmt"

	"github.com/FortegoSwiss/codebook-cipher"
)

func main() {
	seed := make([]byte, codebook.SeedSize) // placeholder only; use a secure seed
	cb, err := codebook.NewBIP39English(seed)
	if err != nil {
		panic(err)
	}

	// Encipher or decipher one word.
	ciphertext, err := cb.Lookup("abandon")
	if err != nil {
		panic(err)
	}
	plaintext, err := cb.Reverse().Lookup(ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println(ciphertext, plaintext)

	// Render the forward lookup table.
	for entry := range cb.Entries() {
		fmt.Println(entry.Source, entry.Target)
	}
}
```

### Custom word lists

The library also supports custom word lists. A list has ordered, unique,
non-empty entries, treated as exact byte sequences: there is no [case folding](https://www.unicode.org/versions/latest/core-spec/chapter-3/),
whitespace trimming, or [Unicode normalisation](https://www.unicode.org/reports/tr15/). Source and target lists must
have the same length. A CodeBook supports 1 to 65,536 entries;
`wordlist.List` itself has no such upper bound.
Custom lists are made with `wordlist.New`; `wordlist.List.Digest` identifies
their exact contents and order.

## How the permutation is derived

A permutation `P` maps source entry `i` to target entry `P[i]`. A 32-byte
seed and the word lists' shared length deterministically derive `P`; the
words themselves never enter the derivation. The same seed reproduces the
same `P` for any word lists of that length. A seed therefore corresponds to
one permutation per length, rather than to a specific word-list pair.

To recreate a table, retain its seed and the exact word lists used to build
it. Callers must pin the word lists associated with each seed themselves,
for example by index. The package cannot detect a word-list mismatch when
the lists have matching lengths.

[Fisher–Yates](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle)
generates `P`: it starts with the identity order, walks backward through the
indices, and swaps each index with a uniformly chosen earlier index. This makes
every possible permutation equally likely.

Each swap needs a uniformly chosen number in a shrinking range. A direct
`value % range` is biased whenever the number of raw values is not divisible
by `range`: for example, 65,536 values reduced modulo 3 produce remainder 0
once more often than remainders 1 and 2. [Rejection sampling](https://en.wikipedia.org/wiki/Rejection_sampling) discards the few
excess values so every possible swap index remains equally likely.

[ChaCha20](https://www.rfc-editor.org/info/rfc8439/#section-2.3) turns the 32-byte seed into a deterministic, uniformly distributed
byte stream from which these values are drawn. A continuous stream is a natural
fit because rejection sampling occasionally discards a value and needs another;
the total number of consumed draws is therefore not known in advance.

### Exact behaviour

These rules and the fixed, language-independent vectors linked below define
the behaviour; the Go code follows them rather than defining them. Together
they are what a second implementation needs in order to match byte for byte.

- **[Keystream](https://www.rfc-editor.org/info/rfc8439/#section-2.4).** Use the
  Internet Engineering Task Force (IETF) variant of ChaCha20, specified in
  [Request for Comments 8439 (RFC 8439)](https://www.rfc-editor.org/rfc/rfc8439),
  with the 32-byte seed as the key, a 96-bit all-zero
  [nonce](https://csrc.nist.gov/glossary/term/nonce), and an initial
  block counter of zero. Bytes are consumed in order with no gaps.
- **Draws.** Each shuffle step reads two keystream bytes and interprets them
  as an unsigned 16-bit [big-endian integer](https://en.wikipedia.org/wiki/Endianness). This two-byte representation limits
  a CodeBook to 65,536 entries.
- **Rejection.** For a step over `range` candidates, compute the acceptance
  limit and, for an accepted draw, the swap index:

  ```text
  limit = floor(65536 / range) * range
  j = draw mod range
  ```

  Accept a draw only when it is below `limit`. Discard a draw at or above
  `limit` and read a fresh one; a discarded draw still consumes its two bytes.
- **Order.** `i` runs from `n - 1` down to `1`, with `range = i + 1`, swapping
  `P[i]` and `P[j]`. A one-word list yields the identity permutation and
  consumes no keystream at all.
- **Word list digest.** Use the
  [256-bit Secure Hash Algorithm (SHA-256)](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
  over a 4-byte [little-endian](https://en.wikipedia.org/wiki/Endianness) word count,
  followed by each word as a 4-byte little-endian byte length and its raw
  bytes, in list order.
- **Permutation hash.** Used only to keep the vectors compact: SHA-256 over
  the big-endian uint16 encoding of every `P[i]`, in order.
- **Seed use.** The seed is used directly as the ChaCha20 key, with the
  all-zero nonce and counter described above. That construction is safe only
  because a CodeBook seed has exactly one job: generating that one CodeBook's
  permutation. A seed must never be reused for any other purpose — as a key
  elsewhere, or to derive another CodeBook with a different meaning — since
  doing so would repeat the same (key, nonce) pair the ChaCha20 keystream
  depends on being unique.

Tests compare against the vectors; never regenerate them merely to make a
failing test pass. `go run ./internal/cmd/vectorgen` is a manual
golden-sample generator: except for the RFC-anchored raw ChaCha20 samples, it
uses the effective Go implementation to produce candidate [JavaScript Object Notation (JSON)](https://www.rfc-editor.org/info/rfc8259/) changes for
review. It is never run by the tests.

## Specification and conformance vectors

The specification has three parts. Each has a Go implementation, [property
tests](https://pkg.go.dev/testing/quick) that state what must hold, and conformance vectors that pin exact
values:

| Part | Implementation | Vectors |
|---|---|---|
| Seed to permutation | `internal/permutation` | [`keystream.v1.json`](internal/permutation/keystream.v1.json), [`draws.v1.json`](internal/permutation/draws.v1.json), [`permutations.v1.json`](internal/permutation/permutations.v1.json) |
| Word lists and their digest | [`wordlist`](wordlist/) | [`wordlist.v1.json`](wordlist/wordlist.v1.json) |
| Binding the two into a CodeBook | root package | [`lookup.v1.json`](lookup.v1.json) |

Two of the vector files are anchored outside this repository, so that a shared
misconception cannot make everything here agree with itself and still be
wrong: `keystream.v1.json` reproduces RFC 8439 Appendix A.1 test vectors #1
and #2 byte for byte, and the embedded BIP-39 word list is checked against the
published upstream file's SHA-256.

All other pinned values are **project-normative**, meaning frozen output
from this implementation rather than externally standardized values:

- All values in `draws.v1.json`, `permutations.v1.json`, and `lookup.v1.json`.
- The `seed-ascending` and `seed-all-ff` vectors in `keystream.v1.json`.
  Only `seed-all-zero` is RFC-anchored, as described above.
- Every `digestHex` in `wordlist.v1.json`, including `bip39-english`.
  That entry's word list is externally anchored, but its digest uses this
  project's `List.Digest()` encoding; it is not a published digest.

These values were produced with
[`internal/cmd/vectorgen`](internal/cmd/vectorgen/README.md). Reproducing them
confirms agreement with this codebase's algorithm, not compliance with an
external standard. Each file's `description` field states its provenance.

`internal/permutation` is deliberately not exposed as a Go [application programming interface (API)](https://en.wikipedia.org/wiki/API). What is
normative is the algorithm described above, not that package — the package is
one expression of it, and keeping it internal only says "do not couple your Go
code to it".

## Algorithm and module versions

Two different versions are in play, and they are independent:

- **The algorithm version** is the `v1` in the vector file names and in each
  file's `version` field. It says: this seed and these word lists produce this
  table. Nothing that changes the output of a previously valid input can ship
  under `v1` — that would require a new, explicitly named algorithm version and
  a new vector set alongside the old one.
- **The module version** is the [Git tag](https://git-scm.com/docs/git-tag), and follows
  [Go module versioning semantics](https://go.dev/doc/modules/version-numbers) for
  the API. A `v2.0.0` tag would mean the Go API changed. It says nothing about
  the cipher: a CodeBook produced under `v1.0.0` still resolves identically.

Frozen means the algorithm and its output, as pinned by the rules and vectors
above. The Go API is *not* covered by that promise before a `v1.0.0` tag
exists; after it, ordinary Go module compatibility applies.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
