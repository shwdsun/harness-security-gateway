package codexprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func syntheticOwnerAuth(account, subject, timestamp string) []byte {
	claims, _ := json.Marshal(map[string]any{"sub": subject, "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account}})
	token := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims) + ".synthetic"
	data, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil, "last_refresh": timestamp,
		"tokens": map[string]string{"access_token": "SYNTHETIC_ACCESS_SECRET", "refresh_token": "SYNTHETIC_REFRESH_SECRET", "id_token": token, "account_id": account}})
	return data
}

func TestOwnerAuthClosedManagedShapeAndPrivateViews(t *testing.T) {
	data := syntheticOwnerAuth("account-one", "subject-one", "2026-09-19T00:00:00Z")
	a, err := ParseOwnerAuth(data)
	if err != nil {
		t.Fatal(err)
	}
	access, account, err := a.ProviderIdentity()
	if err != nil || access != "SYNTHETIC_ACCESS_SECRET" || account != "account-one" {
		t.Fatal("incorrect owner-only projection")
	}
	copy, err := a.NativeInput()
	if err != nil || !bytes.Equal(copy, data) {
		t.Fatal("incorrect native input")
	}
	copy[0] = 'x'
	data[0] = 'x'
	again, err := a.NativeInput()
	if err != nil || again[0] != '{' {
		t.Fatal("caller mutated private auth state")
	}
	for _, value := range []any{a, *a} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("auth state serialized")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%d", "%f", "%x", "%q", "%#+v"} {
			out := fmt.Sprintf(format, value)
			if strings.Contains(out, "SYNTHETIC") || strings.Contains(out, "account-one") || strings.Contains(out, "subject-one") {
				t.Fatal("secret in diagnostic")
			}
		}
	}
	var zero OwnerAuth
	if json.Unmarshal([]byte(`{}`), &zero) == nil {
		t.Fatal("wire populated auth state")
	}
	for _, v := range []*OwnerAuth{nil, &zero} {
		if _, _, err := v.ProviderIdentity(); err == nil {
			t.Fatal("empty identity accepted")
		}
		if _, err := v.NativeInput(); err == nil {
			t.Fatal("empty native input accepted")
		}
	}
}

func TestOwnerAuthRejectsAmbiguousOrUnsupportedStorage(t *testing.T) {
	good := syntheticOwnerAuth("account-one", "subject-one", "2026-09-19T00:00:00Z")
	cases := map[string][]byte{
		"missing": nil, "null": []byte(`null`), "trailing": append(bytes.Clone(good), []byte(` {}`)...),
		"duplicate":         bytes.Replace(good, []byte(`"auth_mode":"chatgpt"`), []byte(`"auth_mode":"chatgpt","auth_mode":"chatgpt"`), 1),
		"case alias":        bytes.Replace(good, []byte(`"auth_mode"`), []byte(`"AUTH_MODE"`), 1),
		"key login":         bytes.Replace(good, []byte(`"OPENAI_API_KEY":null`), []byte(`"OPENAI_API_KEY":"SYNTHETIC_SECRET"`), 1),
		"other mode":        bytes.Replace(good, []byte(`"chatgpt"`), []byte(`"api_key"`), 1),
		"unknown":           bytes.Replace(good, []byte(`"auth_mode"`), []byte(`"SYNTHETIC_SECRET_FIELD"`), 1),
		"empty access":      bytes.Replace(good, []byte(`"SYNTHETIC_ACCESS_SECRET"`), []byte(`""`), 1),
		"null access":       bytes.Replace(good, []byte(`"SYNTHETIC_ACCESS_SECRET"`), []byte(`null`), 1),
		"header injection":  bytes.Replace(good, []byte(`"SYNTHETIC_ACCESS_SECRET"`), []byte(`"token\r\ninject"`), 1),
		"access bound":      bytes.Replace(good, []byte(`SYNTHETIC_ACCESS_SECRET`), bytes.Repeat([]byte("x"), 8193), 1),
		"wrong account":     bytes.Replace(good, []byte(`"account_id":"account-one"`), []byte(`"account_id":"other"`), 1),
		"invalid timestamp": bytes.Replace(good, []byte(`2026-09-19T00:00:00Z`), []byte(`not-a-time`), 1),
		"size bound":        bytes.Repeat([]byte("x"), maxOwnerAuthBytes+1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ParseOwnerAuth(data)
			if got != nil || err != ErrOwnerAuth {
				t.Fatal("invalid state accepted or underlying diagnostic retained")
			}
		})
	}
}

func TestOwnerAuthUpdatePreservesAccountAndRejectsRollback(t *testing.T) {
	before := syntheticOwnerAuth("account-one", "subject-one", "2026-09-19T00:00:00Z")
	for _, candidate := range [][]byte{before, syntheticOwnerAuth("account-one", "subject-one", "2026-09-19T00:00:01Z")} {
		if _, err := ValidateOwnerAuthUpdate(before, candidate); err != nil {
			t.Fatal("unchanged token strings wrongly required to rotate")
		}
	}
	for _, candidate := range [][]byte{nil, syntheticOwnerAuth("account-two", "subject-one", "2026-09-19T00:00:01Z"),
		syntheticOwnerAuth("account-one", "subject-two", "2026-09-19T00:00:01Z"),
		syntheticOwnerAuth("account-one", "subject-one", "2026-09-18T23:59:59Z")} {
		if got, err := ValidateOwnerAuthUpdate(before, candidate); got != nil || err != ErrOwnerAuth {
			t.Fatal("invalid transition accepted")
		}
	}
	if _, err := ValidateOwnerAuthUpdate(nil, before); err != ErrOwnerAuth {
		t.Fatal("missing baseline accepted")
	}
}
