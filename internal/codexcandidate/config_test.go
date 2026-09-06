package codexcandidate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
)

func example(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../config/codex-candidate.example.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func encode(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestExampleIsBlockedAndCannotBeMutated(t *testing.T) {
	data := example(t)
	c, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Check(false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "blocked" || r.Configuration != "valid" || r.LocalMetadata != "not_checked" || len(r.ExecutionBlockers) != 7 || r.ProfileFingerprint != codexprofile.ContractFingerprintV2 || len(r.ConfigurationFingerprint) != len(Schema)+1+64 {
		t.Fatalf("report = %+v", r)
	}
	const golden = "codex-candidate/v1:17ffcd464336784004102fc378eb5c002c6cbc677f72e4090778f8b87173d6d8"
	if r.ConfigurationFingerprint != golden || r.TargetFingerprint != "314d86eb48340ea156b2ef0f4647391b301b3e6bdd39df352e460d7b41de5687" {
		t.Fatalf("golden changed: %+v", r)
	}
	r.Status = "ready"
	r.ExecutionBlockers[0] = "invented-proof"
	clear(data)
	again, _ := c.Check(false)
	if again.Status != "blocked" || again.ExecutionBlockers[0] != "image_provenance" {
		t.Fatal("output/input aliases candidate")
	}
	if _, err := (Candidate{}).Check(true); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero candidate accepted")
	}
	if strings.Contains(string(encode(t, r)), "/srv/") {
		t.Fatal("report leaked local path")
	}
}

func TestJSONBoundaryAndScope(t *testing.T) {
	data := string(example(t))
	changes := map[string]string{
		"embedded target case": strings.Replace(data, `"runner_state":`, `"Runner_State":`, 1),
		"embedded none ref":    strings.Replace(data, `{"kind": "none"}`, `{"kind": "none", "ref": "forbidden"}`, 1),
		"unknown":              strings.Replace(data, `"schema":`, `"extra": "PRIVATE_SENTINEL", "schema":`, 1),
		"duplicate":            strings.Replace(data, `"schema":`, `"schema": "codex-candidate/v1", "schema":`, 1),
		"case":                 strings.Replace(data, `"profile_id":`, `"Profile_ID":`, 1),
		"alias":                strings.Replace(data, `"profile_id":`, `"PROFILE_ID": "anything", "profile_id":`, 1),
		"null":                 strings.Replace(data, `"profile_id": "codex.chatgpt-personal-messaging-v2"`, `"profile_id": null`, 1),
		"nested case":          strings.Replace(data, `"slot_ref":`, `"SLOT_REF":`, 1),
		"nested null":          strings.Replace(data, `"generation": 1`, `"generation": null`, 1),
		"scope":                strings.Replace(data, `"workspace_ref": "project-main"`, `"workspace_ref": "different"`, 1),
		"auth scope":           strings.Replace(data, `"auth_profile_ref": "codex.chatgpt-file-personal-v1"`, `"auth_profile_ref": "builtin.none"`, 1),
		"zero generation":      strings.Replace(data, `"generation": 1`, `"generation": 0`, 1),
		"negative generation":  strings.Replace(data, `"generation": 1`, `"generation": -1`, 1),
		"fraction generation":  strings.Replace(data, `"generation": 1`, `"generation": 1.5`, 1),
		"overflow generation":  strings.Replace(data, `"generation": 1`, `"generation": 18446744073709551616`, 1),
		"directory traversal":  strings.Replace(data, `"directory": "codex-project-main"`, `"directory": "../codex"`, 1),
		"directory alias":      strings.Replace(data, `"directory": "codex-project-main"`, `"directory": "Codex"`, 1),
		"slot path":            strings.Replace(data, `"slot_ref": "personal-codex"`, `"slot_ref": "/tmp/token"`, 1),
		"relative path":        strings.Replace(data, `"path": "/srv/hsg/workspaces/project-main"`, `"path": "relative"`, 1),
		"unclean path":         strings.Replace(data, `"path": "/srv/hsg/workspaces/project-main"`, `"path": "/srv/hsg/../workspace"`, 1),
		"filesystem root":      strings.Replace(data, `"root": "/srv/hsg/credentials"`, `"root": "/"`, 1),
		"overlap":              strings.Replace(data, `"root": "/srv/hsg/credentials"`, `"root": "/srv/hsg/workspaces"`, 1),
		"ready claim":          strings.Replace(data, `"schema":`, `"ready": true, "schema":`, 1),
		"trailing":             data + ` {}`,
		"invalid utf8":         data + string([]byte{255}),
		"oversize":             strings.Repeat(" ", MaxBytes) + data,
	}
	for name, changed := range changes {
		t.Run(name, func(t *testing.T) {
			_, err := Decode([]byte(changed))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), "PRIVATE_SENTINEL") || strings.Contains(err.Error(), "/srv/") {
				t.Fatal("diagnostic leaked input")
			}
		})
	}
}

// Every leaf is either rejected or changes the complete configuration digest;
// no newly added authority-bearing config/target field silently escapes it.
func TestEveryConfigurationLeafIsBound(t *testing.T) {
	data := example(t)
	base, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	count := 0
	var visit func(map[string]any)
	visit = func(current map[string]any) {
		for key, value := range current {
			if nested, ok := value.(map[string]any); ok {
				visit(nested)
				continue
			}
			count++
			switch v := value.(type) {
			case string:
				current[key] = v + "-changed"
			case float64:
				current[key] = v + 1
			case []any:
				current[key] = []any{"progress.text"}
			default:
				t.Fatalf("new untested field type %T", value)
			}
			changed, err := Decode(encode(t, object))
			if err == nil && changed.fingerprint == base.fingerprint {
				t.Fatalf("field %s not bound", key)
			}
			current[key] = value
		}
	}
	visit(object)
	if count < 35 {
		t.Fatalf("too few fields covered: %d", count)
	}
	// Whitespace and key ordering are not authority changes.
	reordered, err := Decode(encode(t, object))
	if err != nil || reordered.fingerprint != base.fingerprint {
		t.Fatalf("canonical fingerprint: %v", err)
	}
}

func TestLoadRejectsSpecialFilesAndRedactsErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "PRIVATE_PATH")
	if err := os.WriteFile(file, example(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dir, filepath.Join(dir, "missing-private-path")} {
		if _, err := Load(path); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), dir) {
			t.Fatalf("load error = %v", err)
		}
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file); !errors.Is(err, ErrInvalid) {
		t.Fatalf("writable config accepted: %v", err)
	}
}

func TestEveryFieldRequiresExplicitNonNullValue(t *testing.T) {
	var object map[string]any
	if err := json.Unmarshal(example(t), &object); err != nil {
		t.Fatal(err)
	}
	var visit func(map[string]any)
	visit = func(current map[string]any) {
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		for _, key := range keys {
			value := current[key]
			current[key] = nil
			if _, err := Decode(encode(t, object)); err == nil {
				t.Fatalf("null %s accepted", key)
			}
			delete(current, key)
			if _, err := Decode(encode(t, object)); err == nil {
				t.Fatalf("missing %s accepted", key)
			}
			current[key] = value
			if nested, ok := value.(map[string]any); ok {
				visit(nested)
			}
		}
	}
	visit(object)
}

func TestGenerationRangeAndSlotNames(t *testing.T) {
	data := string(example(t))
	for _, literal := range []string{"0", "-1", "1.0", "1e3", "9223372036854775808"} {
		if _, err := Decode([]byte(strings.Replace(data, `"generation": 1`, `"generation": `+literal, 1))); err == nil {
			t.Fatalf("generation %s accepted", literal)
		}
	}
	if _, err := Decode([]byte(strings.Replace(data, `"generation": 1`, `"generation": 9223372036854775807`, 1))); err != nil {
		t.Fatalf("max signed generation: %v", err)
	}
	for _, name := range []string{"", ".", "..", ".hidden", "auth.json", "a/b", "a\\b"} {
		c, err := Decode(example(t))
		if err != nil {
			t.Fatal(err)
		}
		cfg := c.config
		cfg.Credential.Directory = name
		if _, err := Decode(encode(t, cfg)); err == nil {
			t.Fatalf("directory %q accepted", name)
		}
	}
}
