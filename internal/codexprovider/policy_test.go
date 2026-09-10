package codexprovider

import (
	"net/http/httptest"
	"strings"
	"testing"
)

const inferenceBody = `{"model":"gpt-5.6-sol","reasoning":{"effort":"medium"},"stream":true,"store":false,"tools":[]}`

func TestOperationProjection(t *testing.T) {
	for _, name := range []string{"valid", "host", "query", "url-alias", "duplicate-auth", "compression", "upgrade", "forwarded", "model-case", "duplicate-model", "effort", "background", "store", "store-absent", "store-null", "tier", "provider-tool"} {
		t.Run(name, func(t *testing.T) {
			body := inferenceBody
			switch name {
			case "model-case":
				body = strings.Replace(body, `"model"`, `"Model"`, 1)
			case "duplicate-model":
				body = strings.Replace(body, `"model":`, `"model":"wrong","model":`, 1)
			case "effort":
				body = strings.Replace(body, `"medium"`, `"high"`, 1)
			case "background":
				body = strings.Replace(body, `"store":false`, `"store":false,"background":true`, 1)
			case "store":
				body = strings.Replace(body, `"store":false`, `"store":true`, 1)
			case "store-absent":
				body = strings.Replace(body, `"store":false,`, "", 1)
			case "store-null":
				body = strings.Replace(body, `"store":false`, `"store":null`, 1)
			case "tier":
				body = strings.Replace(body, `"store":false`, `"store":false,"service_tier":"priority"`, 1)
			case "provider-tool":
				body = strings.Replace(body, `"tools":[]`, `"tools":[{"type":"web_search"}]`, 1)
			}
			r := httptest.NewRequest("POST", "/backend-api/codex/responses", strings.NewReader(body))
			r.Host = "chatgpt.com"
			r.Header.Set("Authorization", "Bearer synthetic-only")
			r.Header.Set("Chatgpt-Account-Id", "synthetic-account")
			r.Header.Set("Content-Type", "application/json")
			switch name {
			case "host":
				r.Host = "elsewhere.invalid"
			case "query":
				r.RequestURI += "?redirect=elsewhere"
				r.URL.RawQuery = "redirect=elsewhere"
			case "url-alias":
				r.URL.RawPath = "/backend-api/codex/%72esponses"
			case "duplicate-auth":
				r.Header.Add("Authorization", "Bearer other")
			case "compression":
				r.Header.Set("Content-Encoding", "zstd")
			case "upgrade":
				r.Header.Set("Upgrade", "websocket")
			case "forwarded":
				r.Header.Set("X-Forwarded-Host", "elsewhere.invalid")
			}
			got, err := project(r, []byte(body))
			if (err == nil) != (name == "valid") {
				t.Fatalf("projection accepted=%v", err == nil)
			}
			if name == "valid" && (got.Operation != Inference || got.Header.Get("Content-Length") != "" || string(got.Body) != body) {
				t.Fatal("projection changed operation/data")
			}
		})
	}
}

func TestRefreshAndClosedRoutes(t *testing.T) {
	for _, row := range []struct {
		method, host, path, body string
		op                       Operation
		valid                    bool
	}{
		{"POST", "auth.openai.com", "/oauth/token", `{"grant_type":"refresh_token","client_id":"app_EMoamEEZ73f0CkXaXp7hrann","refresh_token":"synthetic-only"}`, Refresh, true},
		{"POST", "auth.openai.com", "/oauth/token", `{"grant_type":"authorization_code","client_id":"app_EMoamEEZ73f0CkXaXp7hrann","refresh_token":"synthetic-only"}`, 0, false},
		{"GET", "chatgpt.com", "/backend-api/wham/settings/user", "", Settings, true},
		{"GET", "chatgpt.com", "/backend-api/codex/models?client_version=0.151.0", "", Catalog, true},
		{"GET", "chatgpt.com", "/backend-api/codex/models?client_version=other", "", 0, false},
		{"POST", "api.openai.com", "/v1/responses", inferenceBody, 0, false},
	} {
		r := httptest.NewRequest(row.method, row.path, strings.NewReader(row.body))
		r.Host = row.host
		if row.body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if row.op == Catalog {
			r.Header.Set("Authorization", "Bearer synthetic-only")
			r.Header.Set("Chatgpt-Account-Id", "synthetic-account")
		}
		got, err := project(r, []byte(row.body))
		if (err == nil) != row.valid || (err == nil && got.Operation != row.op) {
			t.Fatalf("closed route %s %s", row.method, row.path)
		}
	}
}
