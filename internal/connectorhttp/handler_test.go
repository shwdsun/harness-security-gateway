package connectorhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
)

type fakeService struct {
	ingest   func(context.Context, connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error)
	claim    func(context.Context, connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error)
	complete func(context.Context, connectorwire.DeliveryCompleteV1) error
}

func (service *fakeService) Ingest(ctx context.Context, event connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error) {
	if service.ingest == nil {
		return connectorwire.InboundReceiptV1{}, errors.New("unexpected ingest call")
	}
	return service.ingest(ctx, event)
}

func (service *fakeService) Claim(ctx context.Context, claim connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
	if service.claim == nil {
		return connectorwire.DeliveryClaimResultV1{}, errors.New("unexpected claim call")
	}
	return service.claim(ctx, claim)
}

func (service *fakeService) Complete(ctx context.Context, completion connectorwire.DeliveryCompleteV1) error {
	if service.complete == nil {
		return errors.New("unexpected complete call")
	}
	return service.complete(ctx, completion)
}

func testHandler(t *testing.T, service Service) http.Handler {
	t.Helper()
	handler, err := NewHandler(service)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func post(path, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "http://local"+path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func validEventJSON() string {
	return `{"event_id":"event/1","actor_ref":"user/1","conversation_ref":"dm/1","message_ref":"message/1","occurred_at_unix_ms":1786900000000,"content":{"type":"text","text":"hello"}}`
}

func validCompletionJSON() string {
	return `{"delivery_id":"delivery/1","lease_token":"lease/1","outcome":"delivered","provider_message_ref":"provider/1"}`
}

func validDelivery() connectorwire.OutboundTextV1 {
	return connectorwire.OutboundTextV1{
		DeliveryID:         "delivery/1",
		LeaseToken:         "lease/1",
		LeaseExpiresUnixMS: 1786900000000,
		ConversationRef:    "dm/1",
		ReplyToRef:         "message/1",
		Content:            connectorwire.PlainTextV1{MediaType: "text/plain", Text: "done"},
	}
}

func TestHandlerRoutesOnlyThreeBoundOperations(t *testing.T) {
	service := &fakeService{
		ingest: func(_ context.Context, event connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error) {
			if event.EventID != "event/1" || event.ActorRef != "user/1" {
				t.Fatalf("event = %#v", event)
			}
			return connectorwire.InboundReceiptV1{
				EventID: event.EventID, Disposition: connectorwire.InboundAccepted, RunID: "run/1",
			}, nil
		},
		claim: func(_ context.Context, claim connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
			if claim.Limit != 2 {
				t.Fatalf("claim = %#v", claim)
			}
			// The handler canonicalizes the natural zero/empty result to [].
			return connectorwire.DeliveryClaimResultV1{}, nil
		},
		complete: func(_ context.Context, completion connectorwire.DeliveryCompleteV1) error {
			if completion.DeliveryID != "delivery/1" || completion.LeaseToken != "lease/1" {
				t.Fatalf("completion = %#v", completion)
			}
			return nil
		},
	}
	handler := testHandler(t, service)

	tests := []struct {
		path        string
		body        string
		wantStatus  int
		wantBody    string
		contentType string
	}{
		{
			path: PathIngest, body: validEventJSON(), wantStatus: http.StatusAccepted,
			wantBody: `{"event_id":"event/1","disposition":"accepted","run_id":"run/1"}`, contentType: "application/json",
		},
		{
			path: PathClaim, body: `{"limit":2}`, wantStatus: http.StatusOK,
			wantBody: `{"deliveries":[]}`, contentType: "application/json",
		},
		{path: PathComplete, body: validCompletionJSON(), wantStatus: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, post(test.path, test.body))
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body %q", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if strings.TrimSpace(recorder.Body.String()) != test.wantBody {
				t.Fatalf("body = %q, want %q", recorder.Body.String(), test.wantBody)
			}
			if got := recorder.Header().Get("Content-Type"); got != test.contentType {
				t.Fatalf("Content-Type = %q, want %q", got, test.contentType)
			}
		})
	}
}

func TestHandlerRejectsTransportIdentityAndSchemaViolations(t *testing.T) {
	called := 0
	service := &fakeService{
		ingest: func(context.Context, connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error) {
			called++
			return connectorwire.InboundReceiptV1{}, nil
		},
		claim: func(context.Context, connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
			called++
			return connectorwire.DeliveryClaimResultV1{}, nil
		},
		complete: func(context.Context, connectorwire.DeliveryCompleteV1) error {
			called++
			return nil
		},
	}
	handler := testHandler(t, service)

	identityHeader := post(PathIngest, validEventJSON())
	identityHeader.Header.Set("X-Connector-ID", "forged-instance")
	tests := []struct {
		name       string
		request    *http.Request
		wantStatus int
		wantCode   string
	}{
		{"wrong method", httptest.NewRequest(http.MethodGet, "http://local"+PathClaim, nil), http.StatusMethodNotAllowed, "method_not_allowed"},
		{"unknown path", post("/v1/connectors/admin", `{}`), http.StatusNotFound, "not_found"},
		{"query identity", post(PathClaim+"?connector_id=forged", `{"limit":1}`), http.StatusNotFound, "not_found"},
		{"header identity", identityHeader, http.StatusBadRequest, "invalid_request"},
		{"wrong content type", httptest.NewRequest(http.MethodPost, "http://local"+PathClaim, strings.NewReader(`{"limit":1}`)), http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"identity in DTO", post(PathClaim, `{"limit":1,"connector_id":"forged"}`), http.StatusBadRequest, "invalid_request"},
		{"unknown nested field", post(PathIngest, strings.Replace(validEventJSON(), `"text":"hello"`, `"text":"hello","raw_payload":{}`, 1)), http.StatusBadRequest, "invalid_request"},
		{"duplicate field", post(PathClaim, `{"limit":1,"limit":2}`), http.StatusBadRequest, "invalid_request"},
		{"missing delivery ID", post(PathComplete, `{"lease_token":"lease/1","outcome":"delivered","provider_message_ref":"provider/1"}`), http.StatusBadRequest, "invalid_request"},
		{"oversized body", post(PathClaim, strings.Repeat(" ", MaxClaimRequestBytes+1)), http.StatusRequestEntityTooLarge, "request_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, test.request)
			if recorder.Code != test.wantStatus || strings.TrimSpace(recorder.Body.String()) != `{"error":"`+test.wantCode+`"}` {
				t.Fatalf("response = %d %q, want %d %q", recorder.Code, recorder.Body.String(), test.wantStatus, test.wantCode)
			}
			if test.name == "wrong method" && recorder.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("Allow = %q", recorder.Header().Get("Allow"))
			}
		})
	}
	if called != 0 {
		t.Fatalf("service called %d times for invalid requests", called)
	}
}

func TestHandlerMapsOnlyClosedServiceErrorsWithoutCause(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"forbidden", NewServiceError(ErrorForbidden, errors.New("platform token abc")), http.StatusForbidden, "forbidden"},
		{"action", NewServiceError(ErrorActionUnsupported, nil), http.StatusUnprocessableEntity, "action_unsupported"},
		{"event conflict", NewServiceError(ErrorEventConflict, nil), http.StatusConflict, "event_conflict"},
		{"event expired", NewServiceError(ErrorEventExpired, nil), http.StatusGone, "event_expired"},
		{"quota exceeded", NewServiceError(ErrorQuotaExceeded, nil), http.StatusTooManyRequests, "quota_exceeded"},
		{"run in progress", NewServiceError(ErrorRunInProgress, nil), http.StatusConflict, "run_in_progress"},
		{"delivery", NewServiceError(ErrorDeliveryNotFound, nil), http.StatusNotFound, "delivery_not_found"},
		{"lease", NewServiceError(ErrorLeaseLost, nil), http.StatusConflict, "lease_lost"},
		{"unavailable", NewServiceError(ErrorUnavailable, nil), http.StatusServiceUnavailable, "unavailable"},
		{"explicit internal", NewServiceError(ErrorInternal, errors.New("database /secret/path")), http.StatusInternalServerError, "internal"},
		{"plain error", errors.New("database /secret/path"), http.StatusInternalServerError, "internal"},
		{"forged code", &ServiceError{Code: "provider_secret", Cause: errors.New("token")}, http.StatusInternalServerError, "internal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testHandler(t, &fakeService{
				claim: func(context.Context, connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
					return connectorwire.DeliveryClaimResultV1{}, test.err
				},
			})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, post(PathClaim, `{"limit":1}`))
			wantBody := `{"error":"` + test.wantCode + `"}`
			if recorder.Code != test.wantStatus || strings.TrimSpace(recorder.Body.String()) != wantBody {
				t.Fatalf("response = %d %q, want %d %q", recorder.Code, recorder.Body.String(), test.wantStatus, wantBody)
			}
			if strings.Contains(recorder.Body.String(), "secret") || strings.Contains(recorder.Body.String(), "token") {
				t.Fatalf("response leaked Cause: %q", recorder.Body.String())
			}
		})
	}

	cause := errors.New("sensitive")
	serviceError := NewServiceError(ErrorForbidden, cause)
	if !errors.Is(serviceError, cause) || strings.Contains(serviceError.Error(), "sensitive") {
		t.Fatalf("ServiceError unwrap/error = %v", serviceError)
	}
}

func TestHandlerRejectsInvalidOrOversizedServiceOutput(t *testing.T) {
	t.Run("invalid receipt", func(t *testing.T) {
		handler := testHandler(t, &fakeService{
			ingest: func(context.Context, connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error) {
				return connectorwire.InboundReceiptV1{EventID: "different", Disposition: "invented"}, nil
			},
		})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, post(PathIngest, validEventJSON()))
		assertInternalResponse(t, recorder)
	})

	t.Run("mismatched receipt event", func(t *testing.T) {
		handler := testHandler(t, &fakeService{
			ingest: func(context.Context, connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error) {
				return connectorwire.InboundReceiptV1{EventID: "different", Disposition: connectorwire.InboundDuplicate}, nil
			},
		})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, post(PathIngest, validEventJSON()))
		assertInternalResponse(t, recorder)
	})

	t.Run("invalid claimed delivery", func(t *testing.T) {
		delivery := validDelivery()
		delivery.Content.Text = ""
		handler := testHandler(t, &fakeService{
			claim: func(context.Context, connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
				return connectorwire.DeliveryClaimResultV1{Deliveries: []connectorwire.OutboundTextV1{delivery}}, nil
			},
		})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, post(PathClaim, `{"limit":1}`))
		assertInternalResponse(t, recorder)
	})

	t.Run("claim exceeds requested limit", func(t *testing.T) {
		delivery := validDelivery()
		second := delivery
		second.DeliveryID = "delivery/2"
		second.LeaseToken = "lease/2"
		handler := testHandler(t, &fakeService{
			claim: func(context.Context, connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
				return connectorwire.DeliveryClaimResultV1{Deliveries: []connectorwire.OutboundTextV1{delivery, second}}, nil
			},
		})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, post(PathClaim, `{"limit":1}`))
		assertInternalResponse(t, recorder)
	})

	t.Run("encoded claim exceeds response bound", func(t *testing.T) {
		delivery := validDelivery()
		delivery.Content.Text = strings.Repeat("\x01", connectorwire.MaxTextBytes)
		deliveries := make([]connectorwire.OutboundTextV1, 6)
		for index := range deliveries {
			deliveries[index] = delivery
			deliveries[index].DeliveryID += string(rune('a' + index))
			deliveries[index].LeaseToken += string(rune('a' + index))
		}
		handler := testHandler(t, &fakeService{
			claim: func(context.Context, connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
				return connectorwire.DeliveryClaimResultV1{Deliveries: deliveries}, nil
			},
		})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, post(PathClaim, `{"limit":6}`))
		assertInternalResponse(t, recorder)
	})
}

func TestNewHandlerRejectsNilService(t *testing.T) {
	if _, err := NewHandler(nil); err == nil {
		t.Fatal("NewHandler(nil) error = nil")
	}
}

func assertInternalResponse(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Code != http.StatusInternalServerError || strings.TrimSpace(recorder.Body.String()) != `{"error":"internal"}` {
		t.Fatalf("response = %d %q, want internal", recorder.Code, recorder.Body.String())
	}
}
