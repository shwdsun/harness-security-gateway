// Package connectorhttp binds connectorwire's three operations to HTTP/1.1
// over one connector-specific Unix socket. Neither requests nor transport
// metadata carry connector identity; the selected socket is the identity.
package connectorhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const (
	PathIngest   = "/v1/events/ingest"
	PathClaim    = "/v1/deliveries/claim"
	PathComplete = "/v1/deliveries/complete"

	MaxIngestRequestBytes   = 256 << 10
	MaxIngestResponseBytes  = 4 << 10
	MaxClaimRequestBytes    = 1 << 10
	MaxClaimResponseBytes   = connectorwire.MaxPayloadBytes
	MaxCompleteRequestBytes = 8 << 10

	maxProblemBytes = 4 << 10
	maxProblemDepth = 4
)

type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client talks to the agentd listener dedicated to its connector instance. It
// never retries automatically; durable event deduplication and delivery lease
// recovery do not belong in an in-memory HTTP client.
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
		return nil, errors.New("connectorhttp: nil HTTP client")
	}
	return &Client{http: doer}, nil
}

func (c *Client) Ingest(ctx context.Context, event connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error) {
	var receipt connectorwire.InboundReceiptV1
	err := c.callJSON(
		ctx,
		PathIngest,
		&event,
		MaxIngestRequestBytes,
		http.StatusAccepted,
		MaxIngestResponseBytes,
		func(data []byte) error {
			return connectorwire.DecodeStrict(data, MaxIngestResponseBytes, &receipt)
		},
	)
	if err == nil && receipt.EventID != event.EventID {
		return connectorwire.InboundReceiptV1{}, errors.New("agentd response event_id does not match request")
	}
	return receipt, err
}

func (c *Client) Claim(ctx context.Context, claim connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error) {
	var result connectorwire.DeliveryClaimResultV1
	err := c.callJSON(
		ctx,
		PathClaim,
		&claim,
		MaxClaimRequestBytes,
		http.StatusOK,
		MaxClaimResponseBytes,
		func(data []byte) error {
			return connectorwire.DecodeStrict(data, MaxClaimResponseBytes, &result)
		},
	)
	if err == nil && len(result.Deliveries) > claim.Limit {
		return connectorwire.DeliveryClaimResultV1{}, errors.New("agentd response exceeds requested delivery limit")
	}
	return result, err
}

func (c *Client) Complete(ctx context.Context, completion connectorwire.DeliveryCompleteV1) error {
	if c == nil || c.http == nil {
		return errors.New("connectorhttp: client is not initialized")
	}
	if ctx == nil {
		return errors.New("connectorhttp: nil context")
	}
	body, err := marshalRequest(&completion, MaxCompleteRequestBytes)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	request, err := localhttp.NewRequest(ctx, http.MethodPost, PathComplete, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("call agentd: %w", err)
	}
	if response == nil {
		return errors.New("call agentd: nil HTTP response")
	}
	if response.Body == nil {
		return errors.New("call agentd: HTTP response body is missing")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return decodeRemoteError(response)
	}
	data, err := readBounded(response.Body, 0)
	if err != nil {
		return err
	}
	if len(data) != 0 {
		return errors.New("agentd completion response must not have a body")
	}
	return nil
}

type decodeResponse func([]byte) error

func (c *Client) callJSON(
	ctx context.Context,
	path string,
	request connectorwireValidatable,
	maxRequestBytes int,
	wantStatus int,
	maxResponseBytes int,
	decode decodeResponse,
) error {
	if c == nil || c.http == nil {
		return errors.New("connectorhttp: client is not initialized")
	}
	if ctx == nil {
		return errors.New("connectorhttp: nil context")
	}
	body, err := marshalRequest(request, maxRequestBytes)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	httpRequest, err := localhttp.NewRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpResponse, err := c.http.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("call agentd: %w", err)
	}
	if httpResponse == nil {
		return errors.New("call agentd: nil HTTP response")
	}
	if httpResponse.Body == nil {
		return errors.New("call agentd: HTTP response body is missing")
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != wantStatus {
		return decodeRemoteError(httpResponse)
	}
	if err := requireJSON(httpResponse.Header); err != nil {
		return err
	}
	data, err := readBounded(httpResponse.Body, maxResponseBytes)
	if err != nil {
		return err
	}
	if err := decode(data); err != nil {
		return fmt.Errorf("decode agentd response: %w", err)
	}
	return nil
}

type connectorwireValidatable interface {
	Validate() error
}

func marshalRequest(value connectorwireValidatable, maxBytes int) ([]byte, error) {
	if value == nil {
		return nil, errors.New("nil request")
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	if len(data) > maxBytes {
		return nil, errors.New("request exceeds endpoint byte limit")
	}
	return data, nil
}

// RemoteError is a stable, bounded failure returned by the connector-specific
// agentd listener. It never includes the server's internal Cause.
type RemoteError struct {
	StatusCode int
	Code       string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("agentd connector request failed: HTTP %d: %s", e.StatusCode, e.Code)
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
	if err := strictjson.Decode(data, maxProblemBytes, maxProblemDepth, &problem); err != nil || !validRemoteProblemCode(problem.Error) {
		return &RemoteError{StatusCode: response.StatusCode, Code: "invalid_error_response"}
	}
	return &RemoteError{StatusCode: response.StatusCode, Code: problem.Error}
}

func requireJSON(header http.Header) error {
	mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("agentd response Content-Type is not application/json")
	}
	return nil
}

func readBounded(reader io.Reader, limit int) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("agentd response body is missing")
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read agentd response: %w", err)
	}
	if len(data) > limit {
		return nil, errors.New("agentd response exceeds byte limit")
	}
	return data, nil
}

func validRemoteProblemCode(code string) bool {
	if validServiceErrorCode(ErrorCode(code)) {
		return true
	}
	switch code {
	case "not_found", "method_not_allowed", "unsupported_media_type", "request_too_large", "invalid_request":
		return true
	default:
		return false
	}
}

var (
	_ connectorwireValidatable = (*connectorwire.InboundEventV1)(nil)
	_ connectorwireValidatable = (*connectorwire.DeliveryClaimV1)(nil)
	_ connectorwireValidatable = (*connectorwire.DeliveryCompleteV1)(nil)
)
