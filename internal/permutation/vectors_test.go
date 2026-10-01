// Shared helpers for the conformance-vector tests in this package.
//
// Each vector test declares only the part of the JSON schema it reads. That
// duplication is deliberate: a renamed generator field must break the test
// loudly instead of being decoded through a shared schema into a zero value.
package permutation

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func loadVectors(t *testing.T, data []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("loading vectors: %v", err)
	}
}

func decodeHex(t *testing.T, field, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %s: %v", field, err)
	}
	return b
}
