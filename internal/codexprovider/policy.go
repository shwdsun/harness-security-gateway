// Package codexprovider owns the fixed subscription HTTPS operation boundary.
// It is a blocked canary candidate, not a selectable production target.
package codexprovider

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const (
	PolicyID       = "codex-subscription-https-candidate/v1"
	MaxBodyBytes   = 2 << 20
	MaxHeaderBytes = 16 << 10
	MaxConnections = 16
	MaxConcurrent  = 4
	HeaderTimeout  = 2 * time.Second
	IdleTimeout    = 45 * time.Second
)

var ErrDenied = errors.New("codexprovider: operation denied")

type Operation uint8

const (
	Refresh Operation = iota + 1
	Catalog
	Inference
	Settings // Always a local 404; never an upstream operation.
)

// Request has no URL, host, method or transport selector. Only the closed
// operation maps to those values in the fixed upstream implementation.
type Request struct {
	Operation Operation
	Header    http.Header
	Body      []byte
}

func route(op Operation) (method, host, path string) {
	switch op {
	case Refresh:
		return "POST", "auth.openai.com", "/oauth/token"
	case Catalog:
		return "GET", "chatgpt.com", "/backend-api/codex/models?client_version=0.151.0"
	case Inference:
		return "POST", "chatgpt.com", "/backend-api/codex/responses"
	default:
		return "", "", ""
	}
}

// project strips framing and rejects authority/framing aliases before the
// second parser or any upstream I/O. The native client's data stays untrusted.
func project(r *http.Request, body []byte) (Request, error) {
	if r == nil || r.URL == nil || r.Proto != "HTTP/1.1" || r.URL.IsAbs() || r.URL.Host != "" || r.URL.User != nil ||
		r.URL.RawPath != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.Opaque != "" ||
		len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.ContentLength != int64(len(body)) || len(body) > MaxBodyBytes {
		return Request{}, ErrDenied
	}
	header := make(http.Header)
	allowed := map[string]bool{}
	for _, name := range strings.Fields("Accept Authorization Chatgpt-Account-Id Content-Length Content-Type Originator Session-Id Thread-Id User-Agent X-Client-Request-Id X-Codex-Turn-Metadata X-Codex-Window-Id X-Openai-Internal-Codex-Responses-Lite Cache-Control") {
		allowed[name] = true
	}
	size := len(r.RequestURI) + len(r.Host) + 32
	for name, values := range r.Header {
		if !allowed[name] || len(values) != 1 || len(values[0]) > 8192 || strings.ContainsAny(values[0], "\r\n\x00") {
			return Request{}, ErrDenied
		}
		size += len(name) + len(values[0]) + 4
		if name != "Content-Length" {
			header[name] = append([]string(nil), values...)
		}
	}
	if size > MaxHeaderBytes {
		return Request{}, ErrDenied
	}
	var op Operation
	switch {
	case r.Host == "auth.openai.com" && r.Method == "POST" && r.RequestURI == "/oauth/token":
		op = Refresh
		var fields map[string]string
		if header.Get("Content-Type") != "application/json" || header.Get("Authorization") != "" || header.Get("Chatgpt-Account-Id") != "" ||
			strictjson.Decode(body, 8192, 4, &fields) != nil || len(fields) != 3 || fields["grant_type"] != "refresh_token" ||
			fields["client_id"] != "app_EMoamEEZ73f0CkXaXp7hrann" || !opaqueValue(fields["refresh_token"], 8192) {
			return Request{}, ErrDenied
		}
	case r.Host == "chatgpt.com" && r.Method == "GET" && r.RequestURI == "/backend-api/codex/models?client_version=0.151.0" && len(body) == 0:
		op = Catalog
	case r.Host == "chatgpt.com" && r.Method == "POST" && r.RequestURI == "/backend-api/codex/responses":
		op = Inference
		if header.Get("Content-Type") != "application/json" || !validInference(body) {
			return Request{}, ErrDenied
		}
	case r.Host == "chatgpt.com" && r.Method == "GET" && r.RequestURI == "/backend-api/wham/settings/user" && len(body) == 0:
		op = Settings
	default:
		return Request{}, ErrDenied
	}
	if op == Catalog || op == Inference {
		auth := header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || !opaqueValue(strings.TrimPrefix(auth, "Bearer "), 8192) || !opaqueValue(header.Get("Chatgpt-Account-Id"), 256) {
			return Request{}, ErrDenied
		}
	}
	return Request{Operation: op, Header: header, Body: append([]byte(nil), body...)}, nil
}

func opaqueValue(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func validInference(body []byte) bool {
	var fields map[string]json.RawMessage
	if strictjson.Decode(body, MaxBodyBytes, 32, &fields) != nil || fields == nil {
		return false
	}
	for key := range fields {
		for _, name := range []string{"model", "reasoning", "stream", "store", "background", "service_tier", "tools"} {
			if key != name && strings.EqualFold(key, name) {
				return false
			}
		}
	}
	var model string
	var stream bool
	var reasoning map[string]json.RawMessage
	if json.Unmarshal(fields["model"], &model) != nil || model != codexprofile.ModelNameV1 || json.Unmarshal(fields["stream"], &stream) != nil || !stream ||
		json.Unmarshal(fields["reasoning"], &reasoning) != nil || reasoning == nil {
		return false
	}
	for key := range reasoning {
		if key != "effort" && strings.EqualFold(key, "effort") {
			return false
		}
	}
	var effort string
	if json.Unmarshal(reasoning["effort"], &effort) != nil || effort != codexprofile.ModelReasoningEffortV1 {
		return false
	}
	// No asynchronous job, server-side persistence or accelerated tier is
	// admitted by this local canary. Content itself remains provider-visible.
	// Absence must not delegate the persistence choice to an upstream default.
	if string(fields["store"]) != "false" {
		return false
	}
	for _, key := range []string{"store", "background"} {
		if raw, ok := fields[key]; ok {
			var value bool
			if string(raw) == "null" || json.Unmarshal(raw, &value) != nil || value {
				return false
			}
		}
	}
	if raw, ok := fields["service_tier"]; ok && string(raw) != "null" {
		var tier string
		if json.Unmarshal(raw, &tier) != nil || tier != "default" {
			return false
		}
	}
	// Native Code Mode supplies local custom/function tools, not provider-side
	// web/computer/search execution. Empty top-level tools are normal in Lite.
	if raw, ok := fields["tools"]; ok && string(raw) != "null" {
		var tools []struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &tools) != nil {
			return false
		}
		for _, tool := range tools {
			if tool.Type != "custom" && tool.Type != "function" {
				return false
			}
		}
	}
	return true
}
