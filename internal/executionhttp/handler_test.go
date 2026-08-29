package executionhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
)

type fakeService struct {
	start  func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error)
	get    func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error)
	cancel func(context.Context, executionwire.CancelRunRequest) (executionwire.RunStatus, error)
}

func (service *fakeService) StartRun(ctx context.Context, request executionwire.StartRunRequest) (executionwire.RunStatus, error) {
	return service.start(ctx, request)
}

func (service *fakeService) GetRun(ctx context.Context, request executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
	return service.get(ctx, request)
}

func (service *fakeService) CancelRun(ctx context.Context, request executionwire.CancelRunRequest) (executionwire.RunStatus, error) {
	return service.cancel(ctx, request)
}

func testHandler(t *testing.T, service *fakeService) http.Handler {
	t.Helper()
	handler, err := NewHandler(service)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func post(path, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "http://local"+path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestHandlerRoutesClosedOperations(t *testing.T) {
	service := &fakeService{
		start: func(_ context.Context, request executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			if request.RunID != "run_001" || request.TargetID != "target" {
				t.Fatalf("start request = %#v", request)
			}
			return executionwire.RunStatus{RunID: request.RunID, State: executionwire.RunStateAccepted}, nil
		},
		get: func(_ context.Context, request executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
			return executionwire.GetRunResponse{
				Status: executionwire.RunStatus{RunID: request.RunID, State: executionwire.RunStateAccepted},
				Events: []executionwire.RunEvent{},
			}, nil
		},
		cancel: func(_ context.Context, request executionwire.CancelRunRequest) (executionwire.RunStatus, error) {
			return executionwire.RunStatus{RunID: request.RunID, State: executionwire.RunStateCancelled, LastEventSeq: 1}, nil
		},
	}
	handler := testHandler(t, service)

	tests := []struct {
		path       string
		body       string
		wantStatus int
		wantBody   string
	}{
		{
			PathStartRun,
			`{"run_id":"run_001","target_id":"target","expected_revision":"r1","session_scope_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","input":{"media_type":"text/plain","text":"inspect"},"deadline":"2026-08-16T13:00:00Z"}`,
			http.StatusAccepted,
			`{"run_id":"run_001","state":"accepted","last_event_seq":0}`,
		},
		{PathGetRun, `{"run_id":"run_001"}`, http.StatusOK,
			`{"status":{"run_id":"run_001","state":"accepted","last_event_seq":0},"events":[]}`},
		{PathCancelRun, `{"run_id":"run_001"}`, http.StatusOK,
			`{"run_id":"run_001","state":"cancelled","last_event_seq":1}`},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, post(test.path, test.body))
		if recorder.Code != test.wantStatus || strings.TrimSpace(recorder.Body.String()) != test.wantBody {
			t.Fatalf("%s response = %d %q, want %d %q", test.path, recorder.Code, recorder.Body.String(), test.wantStatus, test.wantBody)
		}
		if got := recorder.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("%s Content-Type = %q", test.path, got)
		}
	}
}

func TestHandlerRejectsTransportAndSchemaViolationsBeforeService(t *testing.T) {
	called := false
	service := &fakeService{
		start: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			called = true
			return executionwire.RunStatus{}, nil
		},
	}
	handler := testHandler(t, service)
	tests := []struct {
		name       string
		request    *http.Request
		wantStatus int
		wantCode   string
	}{
		{"wrong method", httptest.NewRequest(http.MethodGet, "http://local"+PathStartRun, nil), http.StatusMethodNotAllowed, "method_not_allowed"},
		{"unknown path", post("/v1/authority", `{}`), http.StatusNotFound, "not_found"},
		{"query", post(PathStartRun+"?image=evil", `{}`), http.StatusNotFound, "not_found"},
		{"wrong content type", httptest.NewRequest(http.MethodPost, "http://local"+PathStartRun, strings.NewReader(`{}`)), http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"unknown field", post(PathStartRun, `{"run_id":"run_001","docker_args":[]}`), http.StatusBadRequest, "invalid_request"},
		{"duplicate field", post(PathStartRun, `{"run_id":"run_001","run_id":"run_002"}`), http.StatusBadRequest, "invalid_request"},
		{"invalid value", post(PathStartRun, `{"run_id":"bad/id","target_id":"target","expected_revision":"r1","input":{"media_type":"text/plain","text":"x"},"deadline":"2026-08-16T13:00:00Z"}`), http.StatusBadRequest, "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, test.request)
			if recorder.Code != test.wantStatus || !strings.Contains(recorder.Body.String(), `"error":"`+test.wantCode+`"`) {
				t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
			}
		})
	}
	if called {
		t.Fatal("service was called for an invalid request")
	}
}

func TestHandlerMapsOnlyClosedServiceErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"target", NewServiceError(ErrorTargetNotFound, errors.New("sensitive detail")), http.StatusNotFound, "target_not_found"},
		{"workspace", NewServiceError(ErrorWorkspaceBusy, nil), http.StatusConflict, "workspace_busy"},
		{"unavailable", NewServiceError(ErrorUnavailable, nil), http.StatusServiceUnavailable, "unavailable"},
		{"plain internal", errors.New("database path and secret"), http.StatusInternalServerError, "internal"},
		{"forged code becomes internal", &ServiceError{Code: "raw_secret"}, http.StatusInternalServerError, "internal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testHandler(t, &fakeService{
				get: func(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
					return executionwire.GetRunResponse{}, test.err
				},
			})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, post(PathGetRun, `{"run_id":"run_001"}`))
			if recorder.Code != test.wantStatus || strings.TrimSpace(recorder.Body.String()) != `{"error":"`+test.wantCode+`"}` {
				t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "sensitive") || strings.Contains(recorder.Body.String(), "database") {
				t.Fatalf("response leaked cause: %q", recorder.Body.String())
			}
		})
	}
}

func TestHandlerRejectsInvalidServiceOutput(t *testing.T) {
	handler := testHandler(t, &fakeService{
		start: func(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error) {
			return executionwire.RunStatus{RunID: "run_001", State: "invented"}, nil
		},
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, post(PathStartRun,
		`{"run_id":"run_001","target_id":"target","expected_revision":"r1","session_scope_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","input":{"media_type":"text/plain","text":"x"},"deadline":"2026-08-16T13:00:00Z"}`))
	if recorder.Code != http.StatusInternalServerError || strings.TrimSpace(recorder.Body.String()) != `{"error":"internal"}` {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestNewHandlerRejectsNilService(t *testing.T) {
	if _, err := NewHandler(nil); err == nil {
		t.Fatal("NewHandler(nil) unexpectedly succeeded")
	}
}
