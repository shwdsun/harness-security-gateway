package targetmanifest

import (
	"encoding/json"
	"errors"
	"testing"
)

// Captured from the unchanged v1 implementation before applying the v2
// proposal. This pins a historical value, not two paths through new code.
func TestV1FingerprintCompatibility(t *testing.T) {
	got, err := validManifest().Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	const want = "4aa942a8111c2ed61b6060fc4b7a4cb6e4eeb0d3f59dd6facb28c6f7ceeaea26"
	if got != want {
		t.Fatalf("v1 fingerprint changed: got %s want %s", got, want)
	}
}

// A representable new data contract must not silently become executable
// through the original production type and decoder.
func TestV1EntryPointsRejectVersionTwo(t *testing.T) {
	manifest := validManifest()
	manifest.Schema = "harness-target/v2"
	if err := manifest.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v1 Validate accepted v2: %v", err)
	}
	if _, err := manifest.Fingerprint(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v1 Fingerprint accepted v2: %v", err)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err == nil {
		t.Fatal("v1 Decode accepted v2")
	}
}
