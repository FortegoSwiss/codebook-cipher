package permutation

import (
	_ "embed"
	"testing"
)

//go:embed draws.v1.json
var drawVectorsJSON []byte

// TestVectorsDraws drives the real generator and verifies every recorded step
// (i, range, limit, the full accept/reject draw sequence, and the accepted j)
// against the checked-in trace. It observes the production rejection-sampling
// loop directly, not a reimplementation of it.
func TestVectorsDraws(t *testing.T) {
	var file struct {
		Version int `json:"version"`
		Sets    []struct {
			Name    string `json:"name"`
			SeedHex string `json:"seedHex"`
			Size    int    `json:"size"`
			Steps   []struct {
				I     int    `json:"i"`
				Range uint32 `json:"range"`
				Limit uint32 `json:"limit"`
				Draws []struct {
					Value    uint32 `json:"value"`
					Accepted bool   `json:"accepted"`
				} `json:"draws"`
				J int `json:"j"`
			} `json:"steps"`
		} `json:"sets"`
	}
	loadVectors(t, drawVectorsJSON, &file)
	if len(file.Sets) == 0 {
		t.Fatal("no draw vector sets loaded")
	}

	for _, set := range file.Sets {
		t.Run(set.Name, func(t *testing.T) {
			seed := decodeHex(t, "seedHex", set.SeedHex)

			wantByI := make(map[int]int, len(set.Steps))
			for idx, s := range set.Steps {
				wantByI[s.I] = idx
			}
			checked := make(map[int]bool, len(wantByI))

			_, err := Trace(seed, set.Size, func(i int, rng, limit uint32, draws []uint32, j, _, _ uint32) {
				idx, ok := wantByI[i]
				if !ok {
					return
				}
				want := set.Steps[idx]
				checked[i] = true

				if wantRange := uint32(i) + 1; rng != wantRange {
					t.Errorf("i=%d: range = %d, want i+1 = %d", i, rng, wantRange)
				}
				if wantLimit := (65536 / rng) * rng; limit != wantLimit {
					t.Errorf("i=%d: limit = %d, want floor(65536/%d)*%d = %d", i, limit, rng, rng, wantLimit)
				}
				if len(draws) == 0 {
					t.Errorf("i=%d: no draws recorded", i)
					return
				}
				accepted := draws[len(draws)-1]
				if wantJ := accepted % rng; j != wantJ {
					t.Errorf("i=%d: j = %d, want %d mod %d = %d", i, j, accepted, rng, wantJ)
				}
				for k, d := range draws {
					isLast := k == len(draws)-1
					if got := d < limit; got != isLast {
						t.Errorf("i=%d draw[%d] = %d: accepted = %v, but only the last draw may be accepted", i, k, d, got)
					}
				}

				if rng != want.Range {
					t.Errorf("i=%d: range = %d, want %d", i, rng, want.Range)
				}
				if limit != want.Limit {
					t.Errorf("i=%d: limit = %d, want %d", i, limit, want.Limit)
				}
				if int(j) != want.J {
					t.Errorf("i=%d: j = %d, want %d", i, j, want.J)
				}
				if len(draws) != len(want.Draws) {
					t.Errorf("i=%d: got %d draws, want %d", i, len(draws), len(want.Draws))
					return
				}
				for k, d := range draws {
					wd := want.Draws[k]
					if d != wd.Value {
						t.Errorf("i=%d draw[%d]: value = %d, want %d", i, k, d, wd.Value)
					}
					if accepted := d < limit; accepted != wd.Accepted {
						t.Errorf("i=%d draw[%d]: accepted = %v, want %v", i, k, accepted, wd.Accepted)
					}
				}
			})
			if err != nil {
				t.Fatalf("Generate(size=%d): %v", set.Size, err)
			}

			for i := range wantByI {
				if !checked[i] {
					t.Errorf("step i=%d from the vector set was never taken", i)
				}
			}
		})
	}
}
