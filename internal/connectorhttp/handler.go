package connectorhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
)

// Service is agentd's complete HTTP-facing operation set for one connector
// instance. Connector identity is already bound by the dedicated Unix socket;
// it is intentionally absent from every method argument.
type Service interface {
	Ingest(context.Context, connectorwire.InboundEventV1) (connectorwire.InboundReceiptV1, error)
	Claim(context.Context, connectorwire.DeliveryClaimV1) (connectorwire.DeliveryClaimResultV1, error)
	Complete(context.Context, connectorwire.DeliveryCompleteV1) error
}

type ErrorCode string

const (
	ErrorForbidden         ErrorCode = "forbidden"
	ErrorActionUnsupported ErrorCode = "action_unsupported"
	ErrorEventConflict     ErrorCode = "event_conflict"
	ErrorEventExpired      ErrorCode = "event_expired"
	ErrorQuotaExceeded     ErrorCode = "quota_exceeded"
	ErrorRunInProgress     ErrorCode = "run_in_progress"
	ErrorDeliveryNotFound  ErrorCode = "delivery_not_found"
	ErrorLeaseLost         ErrorCode = "lease_lost"
	ErrorUnavailable       ErrorCode = "unavailable"
	ErrorInternal          ErrorCode = "internal"
)

// ServiceError maps a local service failure to one closed public code. Cause
// remains available to local diagnostics and is never serialized.
type ServiceError struct {
	Code  ErrorCode
	Cause error
}

func NewServiceError(code ErrorCode, cause error) *ServiceError {
	if !validServiceErrorCode(code) {
		code = ErrorInternal
	}
	return &ServiceError{Code: code, Cause: cause}
}

func (e *ServiceError) Error() string {
	if e == nil {
		return "connector service error: internal"
	}
	return "connector service error: " + string(e.Code)
}

func (e *ServiceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type Handler struct {
	service Service
}

func NewHandler(service Service) (*Handler, error) {
	if service == nil {
		return nil, errors.New("connectorhttp: nil service")
	}
	return &Handler{service: service}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if h == nil || h.service == nil {
		localhttp.WriteProblem(writer, http.StatusInternalServerError, string(ErrorInternal))
		return
	}
	if request == nil || request.URL == nil || request.URL.RawQuery != "" {
		localhttp.WriteProblem(writer, http.StatusNotFound, "not_found")
		return
	}
	if containsConnectorIdentityHeader(request.Header) {
		localhttp.WriteProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		localhttp.WriteProblem(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	switch request.URL.Path {
	case PathIngest:
		h.handleIngest(writer, request)
	case PathClaim:
		h.handleClaim(writer, request)
	case PathComplete:
		h.handleComplete(writer, request)
	default:
		localhttp.WriteProblem(writer, http.StatusNotFound, "not_found")
	}
}

func (h *Handler) handleIngest(writer http.ResponseWriter, request *http.Request) {
	var input connectorwire.InboundEventV1
	if !readRequest(writer, request, MaxIngestRequestBytes, &input) {
		return
	}
	receipt, err := h.service.Ingest(request.Context(), input)
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	if err := receipt.Validate(); err != nil || receipt.EventID != input.EventID {
		localhttp.WriteProblem(writer, http.StatusInternalServerError, string(ErrorInternal))
		return
	}
	writeSuccessJSON(writer, http.StatusAccepted, receipt, MaxIngestResponseBytes)
}

func (h *Handler) handleClaim(writer http.ResponseWriter, request *http.Request) {
	var input connectorwire.DeliveryClaimV1
	if !readRequest(writer, request, MaxClaimRequestBytes, &input) {
		return
	}
	result, err := h.service.Claim(request.Context(), input)
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	// A service with no available work naturally returns its zero result. The
	// wire representation remains an explicit JSON array, never null.
	if result.Deliveries == nil {
		result.Deliveries = []connectorwire.OutboundTextV1{}
	}
	if err := result.Validate(); err != nil || len(result.Deliveries) > input.Limit {
		localhttp.WriteProblem(writer, http.StatusInternalServerError, string(ErrorInternal))
		return
	}
	writeSuccessJSON(writer, http.StatusOK, result, MaxClaimResponseBytes)
}

func (h *Handler) handleComplete(writer http.ResponseWriter, request *http.Request) {
	var input connectorwire.DeliveryCompleteV1
	if !readRequest(writer, request, MaxCompleteRequestBytes, &input) {
		return
	}
	if err := h.service.Complete(request.Context(), input); err != nil {
		writeServiceError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type requestValue interface {
	Validate() error
}

func readRequest(writer http.ResponseWriter, request *http.Request, maxBytes int, value requestValue) bool {
	if err := localhttp.ReadJSON(request, maxBytes, connectorwire.MaxJSONDepth, value); err != nil {
		switch {
		case errors.Is(err, localhttp.ErrContentType):
			localhttp.WriteProblem(writer, http.StatusUnsupportedMediaType, "unsupported_media_type")
		case errors.Is(err, localhttp.ErrBodyTooLarge):
			localhttp.WriteProblem(writer, http.StatusRequestEntityTooLarge, "request_too_large")
		default:
			localhttp.WriteProblem(writer, http.StatusBadRequest, "invalid_request")
		}
		return false
	}
	if err := value.Validate(); err != nil {
		localhttp.WriteProblem(writer, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func writeSuccessJSON(writer http.ResponseWriter, status int, value any, maxBytes int) {
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > maxBytes {
		localhttp.WriteProblem(writer, http.StatusInternalServerError, string(ErrorInternal))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(data, '\n'))
}

func writeServiceError(writer http.ResponseWriter, err error) {
	var serviceError *ServiceError
	if !errors.As(err, &serviceError) || serviceError == nil || !validServiceErrorCode(serviceError.Code) {
		localhttp.WriteProblem(writer, http.StatusInternalServerError, string(ErrorInternal))
		return
	}
	localhttp.WriteProblem(writer, statusForServiceError(serviceError.Code), string(serviceError.Code))
}

func validServiceErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorForbidden, ErrorActionUnsupported, ErrorEventConflict, ErrorEventExpired, ErrorQuotaExceeded, ErrorRunInProgress,
		ErrorDeliveryNotFound, ErrorLeaseLost, ErrorUnavailable, ErrorInternal:
		return true
	default:
		return false
	}
}

func statusForServiceError(code ErrorCode) int {
	switch code {
	case ErrorForbidden:
		return http.StatusForbidden
	case ErrorActionUnsupported:
		return http.StatusUnprocessableEntity
	case ErrorEventConflict, ErrorLeaseLost, ErrorRunInProgress:
		return http.StatusConflict
	case ErrorEventExpired:
		return http.StatusGone
	case ErrorQuotaExceeded:
		return http.StatusTooManyRequests
	case ErrorDeliveryNotFound:
		return http.StatusNotFound
	case ErrorUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func containsConnectorIdentityHeader(header http.Header) bool {
	for name := range header {
		normalized := strings.ToLower(name)
		if normalized == "connector-id" || strings.Contains(normalized, "connector-id") {
			return true
		}
	}
	return false
}

var (
	_ requestValue = (*connectorwire.InboundEventV1)(nil)
	_ requestValue = (*connectorwire.DeliveryClaimV1)(nil)
	_ requestValue = (*connectorwire.DeliveryCompleteV1)(nil)
	_ http.Handler = (*Handler)(nil)
)
