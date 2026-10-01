# CodeBook conformance vector generator

A [CodeBook](../../../README.md) is Fortego's table for replacing mnemonic
words. Its conformance tests compare the implementation's results with
fixed input/output examples, called vectors or golden samples.

`vectorgen` produces these checked-in samples in
[JavaScript Object Notation (JSON)](https://www.rfc-editor.org/info/rfc8259/).
Use it to propose reviewable changes when intentionally adding a new vector.

## Generated files

Run from the [Go module](https://go.dev/doc/modules/gomod-ref) root, the generator writes these files beside the layer
each one covers:

- `internal/permutation/keystream.v1.json`
- `internal/permutation/draws.v1.json`
- `internal/permutation/permutations.v1.json`
- `wordlist/wordlist.v1.json`
- `lookup.v1.json`

## How the samples are used

The test suite embeds those files and never invokes this command. That makes
the checked-in values fixed expectations: a change in the effective
implementation fails a test until a reviewer explicitly accepts and commits a
corresponding vector change.

Except for `keystream.v1.json`, whose raw [ChaCha20](https://www.rfc-editor.org/info/rfc8439/#section-2.3)
bytes are anchored to [Request for Comments 8439 (RFC 8439)](https://www.rfc-editor.org/rfc/rfc8439), the generator deliberately calls the effective production
implementation. It is not a second implementation of the cipher. Its purpose
is to propose reviewable golden-sample changes when a new vector is
intentionally added.

## Generate and review an intentional change

Do not run the generator merely to make a failing vector test pass. First
determine whether the implementation or the frozen v1 expectation is wrong.

For an intentional extension, run this command from the module root:

```sh
go run ./internal/cmd/vectorgen
```

Inspect the JSON diff, then run:

```sh
go test -race -count=1 ./...
go vet ./...
```

For the algorithm rules and versioning policy, see the repository's
[`README.md`](../../../README.md).
