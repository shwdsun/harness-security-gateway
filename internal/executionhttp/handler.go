package executionhttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
)

// Service is sandboxd's complete HTTP-facing operation set. Runtime policy,
// target resolution, and persistence remain behind this interface.
type Service interface {
	StartRun(context.Context, executionwire.StartRunRequest) (executionwire.RunStatus, error)
	GetRun(context.Context, executionwire.GetRunRequest) (executionwire.GetRunResponse, error)
	CancelRun(context.Context, executionwire.CancelRunRequest) (executionwire.RunStatus, error)
}

type ErrorCode string

const (
	ErrorTargetNotFound   ErrorCode = "target_not_found"
	ErrorRevisionMismatch ErrorCode = "revision_mismatch"
	ErrorRunNotFound      ErrorCode = "run_not_found"
	ErrorInvalidSession   ErrorCode = "invalid_session"
	ErrorWorkspaceBusy    ErrorCode = "workspace_busy"
	ErrorConflict         ErrorCode = "conflict"
	ErrorInvalidState     ErrorCode = "invalid_state"
	ErrorUnavailable      ErrorCode = "unavailable"
	ErrorInternal         ErrorCode = "internal"
)

// ServiceError lets sandboxd map an internal failure to a closed public code.
// Cause is available to local diagnostics but is never serialized.
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
		return "sandboxd service error: internal"
	}
	return "sandboxd service error: " + string(e.Code)
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
		return nil, errors.New("executionhttp: nil service")
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
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		localhttp.WriteProblem(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	switch request.URL.Path {
	case PathStartRun:
		h.handleStart(writer, request)
	case PathGetRun:
		h.handleGet(writer, request)
	case PathCancelRun:
		h.handleCancel(writer, request)
	default:
		localhttp.WriteProblem(writer, http.StatusNotFound, "not_found")
	}
}

func (h *Handler) handleStart(writer http.ResponseWriter, request *http.Request) {
	var input executionwire.StartRunRequest
	if !readRequest(writer, request, &input) {
		return
	}
	status, err := h.service.StartRun(request.Context(), input)
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	if err := status.Validate(); err != nil {
		localhttp.WriteProblem(writer, http.StatusInternalServerError, string(ErrorInternal))
		return
	}
	_ = localhttp.WriteJSON(writer, http.StatusAccepted, status)
}

func (h *Handler) handleGet(writer http.ResponseWriter, request *http.Request) {
	var input executionwire.GetRunRequest
	if !readRequest(writer, request, &input) {
		return
	}
	response, err := h.service.GetRun(request.Context(), input)
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	if err := response.Validate(); err != nil {
		localhttp.WriteProblem(writer, http.StatusInternalServerError, string(ErrorInternal))
		return
	}
	_ = localhttp.WriteJSON(writer, http.StatusOK, response)
}

func (h *Handler) handleCancel(writer http.ResponseWriter, request *http.Request) {
	var input executionwire.CancelRunRequest
	if !readRequest(writer, request, &input) {
		return
	}
	status, err := h.service.CancelRun(request.Context(), input)
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	if err := status.Validate(); err != nil {
		localhttp.WriteProblem(writer, http.StatusInternalServerError, string(ErrorInternal))
		return
	}
	_ = localhttp.WriteJSON(writer, http.StatusOK, status)
}

type requestValue interface {
	Validate() error
}

func readRequest(writer http.ResponseWriter, request *http.Request, value requestValue) bool {
	if err := localhttp.ReadJSON(request, executionwire.MaxRequestBytes, executionwire.MaxJSONDepth, value); err != nil {
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
	case ErrorTargetNotFound, ErrorRevisionMismatch, ErrorRunNotFound,
		ErrorInvalidSession, ErrorWorkspaceBusy, ErrorConflict,
		ErrorInvalidState, ErrorUnavailable, ErrorInternal:
		return true
	default:
		return false
	}
}

func statusForServiceError(code ErrorCode) int {
	switch code {
	case ErrorTargetNotFound, ErrorRunNotFound:
		return http.StatusNotFound
	case ErrorRevisionMismatch, ErrorInvalidSession, ErrorWorkspaceBusy,
		ErrorConflict, ErrorInvalidState:
		return http.StatusConflict
	case ErrorUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

var (
	_ requestValue = (*executionwire.StartRunRequest)(nil)
	_ requestValue = (*executionwire.GetRunRequest)(nil)
	_ requestValue = (*executionwire.CancelRunRequest)(nil)
	_ http.Handler = (*Handler)(nil)
)
