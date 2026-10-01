package permutation

import (
	_ "embed"
	"encoding/hex"
	"testing"
)

//go:embed keystream.v1.json
var keystreamVectorsJSON []byte

// TestVectorsKeystream verifies that the actual keystream used by Generate
// reproduces the checked-in bytes. The vectors anchor the ChaCha20-IETF
// key/nonce/counter convention independently of this implementation.
func TestVectorsKeystream(t *testing.T) {
	var file struct {
		Version int `json:"version"`
		Vectors []struct {
			Name         string `json:"name"`
			SeedHex      string `json:"seedHex"`
			KeystreamHex string `json:"keystreamHex"`
		} `json:"vectors"`
	}
	loadVectors(t, keystreamVectorsJSON, &file)
	if len(file.Vectors) == 0 {
		t.Fatal("no keystream vectors loaded")
	}

	for _, vec := range file.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			seed := decodeHex(t, "seedHex", vec.SeedHex)
			want := decodeHex(t, "keystreamHex", vec.KeystreamHex)

			stream, err := newKeystream(seed)
			if err != nil {
				t.Fatalf("newKeystream: %v", err)
			}
			got := make([]byte, len(want))
			stream.read(got)

			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("keystream mismatch:\n got  %x\n want %x", got, want)
			}
		})
	}
}
