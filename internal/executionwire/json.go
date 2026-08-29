package executionwire

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

type validatable interface {
	Validate() error
}

func decode(data []byte, maxBytes int, dst validatable) error {
	if err := strictjson.Decode(data, maxBytes, MaxJSONDepth, dst); err != nil {
		return err
	}
	if err := dst.Validate(); err != nil {
		return err
	}
	return nil
}

func DecodeStartRunRequest(data []byte) (StartRunRequest, error) {
	var request StartRunRequest
	return request, decode(data, MaxRequestBytes, &request)
}

func DecodeCancelRunRequest(data []byte) (CancelRunRequest, error) {
	var request CancelRunRequest
	return request, decode(data, MaxRequestBytes, &request)
}

func DecodeGetRunRequest(data []byte) (GetRunRequest, error) {
	var request GetRunRequest
	return request, decode(data, MaxRequestBytes, &request)
}

func DecodeRunStatus(data []byte) (RunStatus, error) {
	var status RunStatus
	return status, decode(data, MaxResponseBytes, &status)
}

func DecodeRunEvent(data []byte) (RunEvent, error) {
	var event RunEvent
	return event, decode(data, MaxResponseBytes, &event)
}

func DecodeGetRunResponse(data []byte) (GetRunResponse, error) {
	var response GetRunResponse
	return response, decode(data, MaxResponseBytes, &response)
}

// Marshal validates a wire DTO before encoding it. It accepts only the closed
// executionwire types that implement Validate.
func Marshal(value validatable) ([]byte, error) {
	if value == nil || isNilPointer(value) {
		return nil, fmt.Errorf("executionwire: nil value")
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode execution wire JSON: %w", err)
	}
	return encoded, nil
}

func isNilPointer(value any) bool {
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
