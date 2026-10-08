package targetmanifest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// These independent checks use a valid new_only baseline, so a malformed
// none state cannot be rejected merely because opaque_resume is forbidden.
func TestV2StateShapeCannotHideBehindSessionFailure(t *testing.T) {
	data, err := json.Marshal(newOnlyV2(NoRunnerState()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeV2(data); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{
		`{"kind":"none","ref":null}`, `{"kind":"none","ref":""}`,
		`{"kind":"none","ref":"s"}`, `{"kind":"none","Ref":null}`,
		`{"kind":"none","extra":null}`, `{"kind":"none","kind":"none"}`,
	} {
		t.Run(state, func(t *testing.T) {
			payload := strings.Replace(string(data), `{"kind":"none"}`, state, 1)
			if _, err := DecodeV2([]byte(payload)); err == nil {
				t.Fatal("accepted malformed state with otherwise valid session policy")
			}
		})
	}
}

func TestV2RejectsCaseAliasedAuthorityFields(t *testing.T) {
	data, err := json.Marshal(newOnlyV2(PersistentRunnerState("state-one")))
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string]string{
		"state alias": strings.Replace(string(data), `"runner_state":`, `"RUNNER_STATE":`, 1),
		"state overwrite": strings.Replace(string(data), `"runner_state":{"kind":"persistent","ref":"state-one"}`,
			`"runner_state":{"kind":"persistent","ref":"state-one"},"RUNNER_STATE":{"kind":"none"}`, 1),
		"id overwrite": strings.Replace(string(data), `"id":"project-codex"`, `"id":"project-codex","ID":"other"`, 1),
		"runner alias": strings.Replace(string(data), `"family":`, `"Family":`, 1),
		"limit alias":  strings.Replace(string(data), `"timeout_seconds":`, `"TIMEOUT_SECONDS":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if payload == string(data) {
				t.Fatal("test mutation did not apply")
			}
			if _, err := DecodeV2([]byte(payload)); err == nil {
				t.Fatal("accepted aliased authority field")
			}
			before := newOnlyV2(NoRunnerState())
			manifest := before
			if err := json.Unmarshal([]byte(payload), &manifest); err == nil {
				t.Fatal("plain JSON decode bypassed the v2 field boundary")
			}
			if !reflect.DeepEqual(manifest, before) {
				t.Fatal("failed manifest decode changed the previous value")
			}
		})
	}
}

func FuzzDecodeV2(f *testing.F) {
	for _, manifest := range []ManifestV2{
		validManifestV2(), newOnlyV2(NoRunnerState()), newOnlyV2(PersistentRunnerState("state-one")),
	} {
		data, err := json.Marshal(manifest)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	for _, payload := range []string{`null`, `{}`, `{"runner_state":{"kind":"none","ref":null}}`} {
		f.Add([]byte(payload))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		manifest, err := DecodeV2(data)
		if err != nil {
			return
		}
		fingerprint, err := manifest.Fingerprint()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeV2(encoded)
		if err != nil {
			t.Fatal(err)
		}
		got, err := again.Fingerprint()
		if err != nil || got != fingerprint {
			t.Fatalf("roundtrip changed semantics: %s != %s, %v", got, fingerprint, err)
		}
	})
}

func TestRunnerStateUnmarshalIsStrictAndAtomic(t *testing.T) {
	for _, payload := range []string{
		`{"kind":"none","kind":"none"}`,
		`{"kind":"persistent","ref":"one","ref":"two"}`,
		`{"kind":"none","ref":null}`, `null`, `[]`, `{"kind":"None"}`,
	} {
		t.Run(payload, func(t *testing.T) {
			before := PersistentRunnerState("unchanged")
			state := before
			if err := json.Unmarshal([]byte(payload), &state); err == nil {
				t.Fatal("accepted invalid standalone state")
			}
			if state != before {
				t.Fatal("failed decode mutated the existing state")
			}
		})
	}
}
