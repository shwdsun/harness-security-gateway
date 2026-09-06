package targetmanifest

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

func TestDefinitionRetainsOriginalAuthorityAndPrivateViews(t *testing.T) {
	v1 := validManifest()
	v2 := validManifestV2()
	first, err := FromV1(v1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := FromV2(v2)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		definition Definition
		original   any
	}{
		{first, v1}, {second, v2},
	} {
		d := fixture.definition
		before, err := d.Fingerprint()
		if err != nil {
			t.Fatal(err)
		}
		originalBytes, err := json.Marshal(fixture.original)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(d)
		if err != nil || !bytes.Equal(data, originalBytes) {
			t.Fatalf("source wire changed: %s %v", data, err)
		}
		decoded, err := DecodeDefinition(data)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := decoded.Fingerprint()
		if got != before {
			t.Fatal("round trip changed authority")
		}
		view := d.Common()
		view.Runner.RequiredFeatures[0] = runnerwire.Feature("untrusted")
		view.PolicyRef = "untrusted"
		if original, ok := d.Manifest(); ok {
			original.Runner.RequiredFeatures[0] = runnerwire.Feature("untrusted")
		}
		if original, ok := d.ManifestV2(); ok {
			original.Runner.RequiredFeatures[0] = runnerwire.Feature("untrusted")
		}
		clone := d.Clone()
		cloneView := clone.Common()
		cloneView.Runner.RequiredFeatures[0] = runnerwire.Feature("untrusted")
		got, _ = d.Fingerprint()
		if got != before {
			t.Fatal("mutable read view changed retained authority")
		}
		if err := json.Unmarshal([]byte(`{"schema":"harness-target/v99"}`), &d); err == nil {
			t.Fatal("unknown schema accepted")
		}
		got, _ = d.Fingerprint()
		if got != before {
			t.Fatal("failed decode replaced valid definition")
		}
	}
	before1, _ := first.Fingerprint()
	before2, _ := second.Fingerprint()
	if before1 == before2 {
		t.Fatal("v1 and v2 authority domains collapsed")
	}
	v1.Runner.RequiredFeatures[0] = runnerwire.Feature("caller-mutated")
	v2.Runner.RequiredFeatures[0] = runnerwire.Feature("caller-mutated")
	after1, _ := first.Fingerprint()
	after2, _ := second.Fingerprint()
	if before1 != after1 || before2 != after2 {
		t.Fatal("constructor retained caller-owned slices")
	}
	if _, ok := second.Manifest(); ok {
		t.Fatal("v2 was projected into v1")
	}
}

func TestDefinitionStrictDispatchAndClosedZero(t *testing.T) {
	for _, data := range []string{
		`null`, `{}`, `{"schema":null}`,
		`{"Schema":"harness-target/v2"}`,
		`{"schema":"harness-target/v2","Schema":"harness-target/v1"}`,
		`{"schema":"harness-target/v2","schema":"harness-target/v2"}`,
	} {
		if _, err := DecodeDefinition([]byte(data)); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
	zero := Definition{}
	if err := zero.Validate(); err == nil {
		t.Fatal("accepted zero")
	}
	if _, err := zero.Fingerprint(); err == nil {
		t.Fatal("hashed zero")
	}
	if _, err := json.Marshal(zero); err == nil {
		t.Fatal("encoded zero")
	}
	if _, err := FromV1(Manifest{}); err == nil {
		t.Fatal("wrapped invalid v1")
	}
	if _, err := FromV2(ManifestV2{}); err == nil {
		t.Fatal("wrapped invalid v2")
	}
}
