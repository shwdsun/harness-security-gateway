// Package executionhttp defines the small HTTP binding for executionwire.
//
// The transport is HTTP/1.1 over a Unix socket. The three fixed operations are
// intentionally RPC-shaped: request identifiers remain in strict JSON bodies,
// and no untrusted identifier is interpolated into a URL path.
package executionhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const (
	PathStartRun  = "/v1/runs/start"
	PathGetRun    = "/v1/runs/get"
	PathCancelRun = "/v1/runs/cancel"

	maxProblemBytes = 4 << 10
	maxProblemDepth = 4
)

type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client invokes sandboxd. It does not retry: run idempotency and dispatch
// recovery belong to agentd's durable state machine.
type Client struct {
	http doer
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	client, err := localhttp.NewClient(socketPath, timeout)
	if err != nil {
		return nil, err
	}
	return newClientWithDoer(client)
}

func newClientWithDoer(doer doer) (*Client, error) {
	if doer == nil {
		return nil, errors.New("executionhttp: nil HTTP client")
	}
	return &Client{http: doer}, nil
}

func (c *Client) StartRun(ctx context.Context, request executionwire.StartRunRequest) (executionwire.RunStatus, error) {
	var response executionwire.RunStatus
	err := c.call(ctx, PathStartRun, &request, http.StatusAccepted, executionwire.MaxResponseBytes, func(data []byte) error {
		decoded, err := executionwire.DecodeRunStatus(data)
		response = decoded
		return err
	})
	return response, err
}

func (c *Client) GetRun(ctx context.Context, request executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
	var response executionwire.GetRunResponse
	err := c.call(ctx, PathGetRun, &request, http.StatusOK, executionwire.MaxResponseBytes, func(data []byte) error {
		decoded, err := executionwire.DecodeGetRunResponse(data)
		response = decoded
		return err
	})
	return response, err
}

func (c *Client) CancelRun(ctx context.Context, request executionwire.CancelRunRequest) (executionwire.RunStatus, error) {
	var response executionwire.RunStatus
	err := c.call(ctx, PathCancelRun, &request, http.StatusOK, executionwire.MaxResponseBytes, func(data []byte) error {
		decoded, err := executionwire.DecodeRunStatus(data)
		response = decoded
		return err
	})
	return response, err
}

type decodeResponse func([]byte) error

func (c *Client) call(
	ctx context.Context,
	path string,
	request executionwireValidatable,
	wantStatus int,
	maxResponse int,
	decode decodeResponse,
) error {
	if c == nil || c.http == nil {
		return errors.New("executionhttp: client is not initialized")
	}
	if ctx == nil {
		return errors.New("executionhttp: nil context")
	}
	body, err := executionwire.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	httpRequest, err := localhttp.NewRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpResponse, err := c.http.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("call sandboxd: %w", err)
	}
	if httpResponse == nil {
		return errors.New("call sandboxd: nil HTTP response")
	}
	if httpResponse.Body == nil {
		return errors.New("call sandboxd: HTTP response body is missing")
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != wantStatus {
		return decodeRemoteError(httpResponse)
	}
	if err := requireJSON(httpResponse.Header); err != nil {
		return err
	}
	data, err := readBounded(httpResponse.Body, maxResponse)
	if err != nil {
		return err
	}
	if err := decode(data); err != nil {
		return fmt.Errorf("decode sandboxd response: %w", err)
	}
	return nil
}

// This local interface mirrors executionwire's sealed validation surface
// without widening executionwire.Marshal to arbitrary values.
type executionwireValidatable interface {
	Validate() error
}

// RemoteError is a stable, bounded failure returned by sandboxd. It contains
// no raw runtime, harness, or database error text.
type RemoteError struct {
	StatusCode int
	Code       string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("sandboxd request failed: HTTP %d: %s", e.StatusCode, e.Code)
}

func decodeRemoteError(response *http.Response) error {
	if err := requireJSON(response.Header); err != nil {
		return &RemoteError{StatusCode: response.StatusCode, Code: "invalid_error_response"}
	}
	data, err := readBounded(response.Body, maxProblemBytes)
	if err != nil {
		return &RemoteError{StatusCode: response.StatusCode, Code: "invalid_error_response"}
	}
	var problem struct {
		Error string `json:"error"`
	}
	if err := strictjson.Decode(data, maxProblemBytes, maxProblemDepth, &problem); err != nil || !validProblemCode(problem.Error) {
		return &RemoteError{StatusCode: response.StatusCode, Code: "invalid_error_response"}
	}
	return &RemoteError{StatusCode: response.StatusCode, Code: problem.Error}
}

func requireJSON(header http.Header) error {
	mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("sandboxd response Content-Type is not application/json")
	}
	return nil
}

func readBounded(reader io.Reader, limit int) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("sandboxd response body is missing")
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read sandboxd response: %w", err)
	}
	if len(data) > limit {
		return nil, errors.New("sandboxd response exceeds byte limit")
	}
	return data, nil
}

func validProblemCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || index > 0 && (char == '_' || char == '-') {
			continue
		}
		return false
	}
	return !strings.HasSuffix(value, "_") && !strings.HasSuffix(value, "-")
}

// Compile-time checks keep the request types on the expected validation
// surface when executionwire evolves.
var (
	_ executionwireValidatable = (*executionwire.StartRunRequest)(nil)
	_ executionwireValidatable = (*executionwire.GetRunRequest)(nil)
	_ executionwireValidatable = (*executionwire.CancelRunRequest)(nil)
)
