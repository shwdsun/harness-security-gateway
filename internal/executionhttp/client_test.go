package executionhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) Do(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func response(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestStartRunUsesFixedOperationAndStrictResponse(t *testing.T) {
	client, err := newClientWithDoer(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != PathStartRun {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
		data, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		decoded, decodeErr := executionwire.DecodeStartRunRequest(data)
		if decodeErr != nil || decoded.RunID != "run_001" {
			t.Fatalf("decoded request = %#v, err = %v", decoded, decodeErr)
		}
		return response(http.StatusAccepted, "application/json; charset=utf-8",
			`{"run_id":"run_001","state":"accepted","last_event_seq":0}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	status, err := client.StartRun(context.Background(), executionwire.StartRunRequest{
		RunID:              "run_001",
		TargetID:           "target_a",
		ExpectedRevision:   "revision_1",
		SessionScopeDigest: strings.Repeat("a", 64),
		Input: executionwire.TextInput{
			MediaType: executionwire.MediaTypeTextPlain,
			Text:      "inspect project",
		},
		Deadline: time.Date(2026, 8, 16, 13, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("StartRun() error = %v", err)
	}
	if status.RunID != "run_001" || status.State != executionwire.RunStateAccepted {
		t.Fatalf("status = %#v", status)
	}
}

func TestGetAndCancelDecodeOnlyTheirClosedResponseTypes(t *testing.T) {
	call := 0
	client, err := newClientWithDoer(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		call++
		switch call {
		case 1:
			if request.URL.Path != PathGetRun {
				t.Fatalf("get path = %q", request.URL.Path)
			}
			return response(http.StatusOK, "application/json",
				`{"status":{"run_id":"run_001","state":"accepted","last_event_seq":0},"events":[]}`), nil
		case 2:
			if request.URL.Path != PathCancelRun {
				t.Fatalf("cancel path = %q", request.URL.Path)
			}
			return response(http.StatusOK, "application/json",
				`{"run_id":"run_001","state":"cancelled","last_event_seq":1}`), nil
		default:
			t.Fatal("unexpected request")
			return nil, nil
		}
	}))
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := client.GetRun(context.Background(), executionwire.GetRunRequest{RunID: "run_001"})
	if err != nil || snapshot.Status.State != executionwire.RunStateAccepted {
		t.Fatalf("GetRun() = %#v, err = %v", snapshot, err)
	}
	status, err := client.CancelRun(context.Background(), executionwire.CancelRunRequest{RunID: "run_001"})
	if err != nil || status.State != executionwire.RunStateCancelled {
		t.Fatalf("CancelRun() = %#v, err = %v", status, err)
	}
}

func TestRemoteProblemIsBoundedAndClosed(t *testing.T) {
	tests := []struct {
		name string
		resp *http.Response
		code string
	}{
		{"valid", response(http.StatusConflict, "application/json", `{"error":"workspace_busy"}`), "workspace_busy"},
		{"unknown field", response(http.StatusConflict, "application/json", `{"error":"busy","detail":"secret"}`), "invalid_error_response"},
		{"unsafe code", response(http.StatusConflict, "application/json", `{"error":"raw failure text"}`), "invalid_error_response"},
		{"wrong media", response(http.StatusConflict, "text/plain", `workspace busy`), "invalid_error_response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return test.resp, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.GetRun(context.Background(), executionwire.GetRunRequest{RunID: "run_001"})
			var remote *RemoteError
			if !errors.As(err, &remote) || remote.StatusCode != http.StatusConflict || remote.Code != test.code {
				t.Fatalf("error = %#v, want RemoteError code %q", err, test.code)
			}
		})
	}
}

func TestSuccessfulResponseRejectsUnknownFieldsAndOversize(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"unknown", `{"run_id":"run_001","state":"accepted","last_event_seq":0,"authority":"docker"}`},
		{"oversize", strings.Repeat(" ", executionwire.MaxResponseBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusAccepted, "application/json", test.body), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.StartRun(context.Background(), executionwire.StartRunRequest{
				RunID: "run_001", TargetID: "target", ExpectedRevision: "r1",
				SessionScopeDigest: strings.Repeat("a", 64),
				Input:              executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "x"},
				Deadline:           time.Date(2026, 8, 16, 13, 0, 0, 0, time.UTC),
			})
			if err == nil {
				t.Fatal("StartRun() unexpectedly succeeded")
			}
		})
	}
}

func TestClientRejectsInvalidLocalInputsAndTransportFailures(t *testing.T) {
	if _, err := newClientWithDoer(nil); err == nil {
		t.Fatal("newClientWithDoer(nil) unexpectedly succeeded")
	}
	client, err := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetRun(context.Background(), executionwire.GetRunRequest{}); err == nil {
		t.Fatal("invalid request unexpectedly succeeded")
	}
	if _, err := client.GetRun(context.Background(), executionwire.GetRunRequest{RunID: "run_001"}); err == nil || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("transport error = %v", err)
	}

	missingBody, err := newClientWithDoer(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingBody.GetRun(context.Background(), executionwire.GetRunRequest{RunID: "run_001"}); err == nil || !strings.Contains(err.Error(), "body is missing") {
		t.Fatalf("missing response body error = %v", err)
	}
}
