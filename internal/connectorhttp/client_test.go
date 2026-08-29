package connectorhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func response(status int, contentType, body string) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func validEvent() connectorwire.InboundEventV1 {
	return connectorwire.InboundEventV1{
		EventID: "event/1", ActorRef: "user/1", ConversationRef: "dm/1", MessageRef: "message/1",
		OccurredAtUnixMS: 1786900000000,
		Content:          connectorwire.InboundContentV1{Type: connectorwire.ContentTypeText, Text: "hello"},
	}
}

func validCompletion() connectorwire.DeliveryCompleteV1 {
	return connectorwire.DeliveryCompleteV1{
		DeliveryID: "delivery/1", LeaseToken: "lease/1", Outcome: connectorwire.DeliveryDelivered,
		ProviderMessageRef: "provider/1",
	}
}

func TestClientUsesFixedOperationsWithoutConnectorIdentityOrRetries(t *testing.T) {
	calls := 0
	client, err := newClientWithDoer(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost || request.URL.RawQuery != "" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}
		for name := range request.Header {
			if strings.Contains(strings.ToLower(name), "connector-id") {
				t.Fatalf("identity header = %q", name)
			}
		}
		if request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("Content-Type = %q", request.Header.Get("Content-Type"))
		}
		data, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatalf("read request: %v", readErr)
		}

		switch calls {
		case 1:
			if request.URL.Path != PathIngest {
				t.Fatalf("ingest path = %q", request.URL.Path)
			}
			var event connectorwire.InboundEventV1
			if decodeErr := connectorwire.DecodeStrict(data, MaxIngestRequestBytes, &event); decodeErr != nil || event.EventID != "event/1" {
				t.Fatalf("event = %#v, error = %v", event, decodeErr)
			}
			return response(http.StatusAccepted, "application/json; charset=utf-8", `{"event_id":"event/1","disposition":"accepted","run_id":"run/1"}`), nil
		case 2:
			if request.URL.Path != PathClaim {
				t.Fatalf("claim path = %q", request.URL.Path)
			}
			var claim connectorwire.DeliveryClaimV1
			if decodeErr := connectorwire.DecodeStrict(data, MaxClaimRequestBytes, &claim); decodeErr != nil || claim.Limit != 1 {
				t.Fatalf("claim = %#v, error = %v", claim, decodeErr)
			}
			return response(http.StatusOK, "application/json", `{"deliveries":[{"delivery_id":"delivery/1","lease_token":"lease/1","lease_expires_unix_ms":1786900000000,"conversation_ref":"dm/1","content":{"media_type":"text/plain","text":"done"}}]}`), nil
		case 3:
			if request.URL.Path != PathComplete {
				t.Fatalf("complete path = %q", request.URL.Path)
			}
			var completion connectorwire.DeliveryCompleteV1
			if decodeErr := connectorwire.DecodeStrict(data, MaxCompleteRequestBytes, &completion); decodeErr != nil || completion.DeliveryID != "delivery/1" {
				t.Fatalf("completion = %#v, error = %v", completion, decodeErr)
			}
			return response(http.StatusNoContent, "", ""), nil
		default:
			t.Fatalf("unexpected retry/call %d", calls)
			return nil, nil
		}
	}))
	if err != nil {
		t.Fatalf("newClientWithDoer() error = %v", err)
	}

	receipt, err := client.Ingest(context.Background(), validEvent())
	if err != nil || receipt.RunID != "run/1" {
		t.Fatalf("Ingest() = %#v, %v", receipt, err)
	}
	claim, err := client.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1})
	if err != nil || len(claim.Deliveries) != 1 || claim.Deliveries[0].DeliveryID != "delivery/1" {
		t.Fatalf("Claim() = %#v, %v", claim, err)
	}
	if err := client.Complete(context.Background(), validCompletion()); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestClientAndHandlerRoundTrip(t *testing.T) {
	completed := false
	handler := testHandler(t, &fakeService{
		ingest: func(_ context.Context, event connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error) {
			return connectorwire.InboundReceiptV1{EventID: event.EventID, Disposition: connectorwire.InboundDuplicate}, nil
		},
		claim: func(context.Context, connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
			return connectorwire.DeliveryClaimResultV1{Deliveries: []connectorwire.OutboundTextV1{}}, nil
		},
		complete: func(context.Context, connectorwire.DeliveryCompleteV1) error {
			completed = true
			return nil
		},
	})
	client, err := newClientWithDoer(handlerDoer{handler: handler})
	if err != nil {
		t.Fatalf("newClientWithDoer() error = %v", err)
	}

	receipt, err := client.Ingest(context.Background(), validEvent())
	if err != nil || receipt.Disposition != connectorwire.InboundDuplicate {
		t.Fatalf("Ingest() = %#v, %v", receipt, err)
	}
	result, err := client.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1})
	if err != nil || result.Deliveries == nil || len(result.Deliveries) != 0 {
		t.Fatalf("Claim() = %#v, %v", result, err)
	}
	if err := client.Complete(context.Background(), validCompletion()); err != nil || !completed {
		t.Fatalf("Complete() = %v, completed %t", err, completed)
	}
}

type handlerDoer struct {
	handler http.Handler
}

func (doer handlerDoer) Do(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	doer.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func TestClientRejectsInvalidLocalInputBeforeTransport(t *testing.T) {
	calls := 0
	client, err := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusInternalServerError, "application/json", `{"error":"internal"}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	event := validEvent()
	event.EventID = ""
	if _, err := client.Ingest(context.Background(), event); err == nil {
		t.Fatal("invalid Ingest() error = nil")
	}
	if _, err := client.Claim(context.Background(), connectorwire.DeliveryClaimV1{}); err == nil {
		t.Fatal("invalid Claim() error = nil")
	}
	completion := validCompletion()
	completion.DeliveryID = ""
	if err := client.Complete(context.Background(), completion); err == nil {
		t.Fatal("completion without DeliveryID error = nil")
	}
	if _, err := client.Ingest(nil, validEvent()); err == nil {
		t.Fatal("nil-context Ingest() error = nil")
	}
	if calls != 0 {
		t.Fatalf("transport called %d times", calls)
	}
}

func TestClientStrictlyBoundsAndDecodesSuccessfulResponses(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{"unknown field", "application/json", `{"event_id":"event/1","disposition":"accepted","authority":"connector-a"}`},
		{"duplicate field", "application/json", `{"event_id":"event/1","event_id":"event/2","disposition":"accepted"}`},
		{"invalid disposition", "application/json", `{"event_id":"event/1","disposition":"invented"}`},
		{"mismatched event", "application/json", `{"event_id":"event/2","disposition":"duplicate"}`},
		{"wrong media type", "text/plain", `{"event_id":"event/1","disposition":"accepted"}`},
		{"oversized", "application/json", strings.Repeat(" ", MaxIngestResponseBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusAccepted, test.contentType, test.body), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Ingest(context.Background(), validEvent()); err == nil {
				t.Fatal("Ingest() error = nil")
			}
		})
	}

	t.Run("claim null array", func(t *testing.T) {
		client, _ := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, "application/json", `{"deliveries":null}`), nil
		}))
		if _, err := client.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1}); err == nil {
			t.Fatal("Claim() error = nil")
		}
	})

	t.Run("claim exceeds requested limit", func(t *testing.T) {
		body := `{"deliveries":[` +
			`{"delivery_id":"delivery/1","lease_token":"lease/1","lease_expires_unix_ms":1,"conversation_ref":"dm/1","content":{"media_type":"text/plain","text":"one"}},` +
			`{"delivery_id":"delivery/2","lease_token":"lease/2","lease_expires_unix_ms":1,"conversation_ref":"dm/1","content":{"media_type":"text/plain","text":"two"}}]}`
		client, _ := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, "application/json", body), nil
		}))
		if _, err := client.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1}); err == nil {
			t.Fatal("Claim() error = nil")
		}
	})

	t.Run("complete body forbidden", func(t *testing.T) {
		client, _ := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusNoContent, "", `{}`), nil
		}))
		if err := client.Complete(context.Background(), validCompletion()); err == nil {
			t.Fatal("Complete() error = nil")
		}
	})
}

func TestClientRemoteProblemsAreBoundedClosedAndRedacted(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantCode    string
	}{
		{"closed", "application/json", `{"error":"lease_lost"}`, "lease_lost"},
		{"unknown field", "application/json", `{"error":"lease_lost","detail":"secret"}`, "invalid_error_response"},
		{"unknown code", "application/json", `{"error":"database_secret"}`, "invalid_error_response"},
		{"duplicate", "application/json", `{"error":"lease_lost","error":"internal"}`, "invalid_error_response"},
		{"wrong media", "text/plain", `secret`, "invalid_error_response"},
		{"oversized", "application/json", strings.Repeat("x", maxProblemBytes+1), "invalid_error_response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusConflict, test.contentType, test.body), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, callErr := client.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1})
			var remote *RemoteError
			if !errors.As(callErr, &remote) || remote.StatusCode != http.StatusConflict || remote.Code != test.wantCode {
				t.Fatalf("error = %#v, want RemoteError %q", callErr, test.wantCode)
			}
			if strings.Contains(callErr.Error(), "secret") || strings.Contains(callErr.Error(), "database") {
				t.Fatalf("error leaked body: %v", callErr)
			}
		})
	}
}

func TestClientConstructionAndTransportFailures(t *testing.T) {
	if _, err := newClientWithDoer(nil); err == nil {
		t.Fatal("newClientWithDoer(nil) error = nil")
	}
	if _, err := NewClient("relative.sock", time.Second); !errors.Is(err, localhttp.ErrNonAbsoluteSocket) {
		t.Fatalf("NewClient(relative) error = %v, want ErrNonAbsoluteSocket", err)
	}
	if _, err := NewClient("/tmp/agentd.sock", 0); err == nil {
		t.Fatal("NewClient(zero timeout) error = nil")
	}

	calls := 0
	client, _ := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("dial failed once")
	}))
	if _, err := client.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1}); err == nil || !strings.Contains(err.Error(), "dial failed once") {
		t.Fatalf("transport error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want no retry", calls)
	}

	nilResponseClient, _ := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, nil
	}))
	if _, err := nilResponseClient.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1}); err == nil {
		t.Fatal("nil response error = nil")
	}

	nilBodyClient, _ := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}}, nil
	}))
	if _, err := nilBodyClient.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1}); err == nil {
		t.Fatal("nil body error = nil")
	}
}
