package runnerwire

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

var ErrUnexpectedFrameType = errors.New("unexpected HRP/1 frame type")

type discriminator struct {
	Protocol string    `json:"protocol"`
	Type     FrameType `json:"type"`
}

// DecodeFrame strictly decodes one HRP/1 JSON value. It rejects invalid UTF-8,
// duplicate keys at any depth, unknown fields, trailing JSON, excessive depth,
// excessive size, unknown frame types, and values that fail semantic checks.
func DecodeFrame(data []byte) (Frame, error) {
	var raw json.RawMessage
	if err := strictjson.Decode(data, MaxFrameBytes, MaxJSONDepth, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFrame, err)
	}

	var kind discriminator
	if err := json.Unmarshal(raw, &kind); err != nil {
		return nil, fmt.Errorf("%w: decode discriminator: %w", ErrInvalidFrame, err)
	}
	if kind.Protocol != ProtocolV1 {
		return nil, invalid("protocol", fmt.Sprintf("must be %q", ProtocolV1))
	}

	var frame Frame
	switch kind.Type {
	case TypeRunnerReady:
		frame = &RunnerReady{}
	case TypeRunStart:
		frame = &RunStart{}
	case TypeRunStarted:
		frame = &RunStarted{}
	case TypeRunProgress:
		frame = &RunProgress{}
	case TypeRunCompleted:
		frame = &RunCompleted{}
	case TypeRunFailed:
		frame = &RunFailed{}
	case TypeRunCancelled:
		frame = &RunCancelled{}
	default:
		return nil, fmt.Errorf("%w: %w %q", ErrInvalidFrame, ErrUnexpectedFrameType, kind.Type)
	}
	if err := strictjson.Decode(raw, MaxFrameBytes, MaxJSONDepth, frame); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFrame, err)
	}
	if err := frame.Validate(); err != nil {
		return nil, err
	}
	return frame, nil
}

// DecodeRunnerFrame accepts only the runner-to-sandboxd direction.
func DecodeRunnerFrame(data []byte) (RunnerFrame, error) {
	frame, err := DecodeFrame(data)
	if err != nil {
		return nil, err
	}
	runner, ok := frame.(RunnerFrame)
	if !ok {
		return nil, fmt.Errorf("%w: got %q on runner channel", ErrUnexpectedFrameType, frame.FrameType())
	}
	return runner, nil
}

// DecodeControllerFrame accepts only the sandboxd-to-runner direction.
func DecodeControllerFrame(data []byte) (ControllerFrame, error) {
	frame, err := DecodeFrame(data)
	if err != nil {
		return nil, err
	}
	controller, ok := frame.(ControllerFrame)
	if !ok {
		return nil, fmt.Errorf("%w: got %q on controller channel", ErrUnexpectedFrameType, frame.FrameType())
	}
	return controller, nil
}

// MarshalFrame validates and encodes one frame without a trailing newline.
func MarshalFrame(frame Frame) ([]byte, error) {
	if frame == nil || (reflect.ValueOf(frame).Kind() == reflect.Pointer && reflect.ValueOf(frame).IsNil()) {
		return nil, invalid("frame", "must not be null")
	}
	if err := frame.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(frame)
	if err != nil {
		return nil, fmt.Errorf("marshal HRP/1 frame: %w", err)
	}
	if len(data) > MaxFrameBytes {
		return nil, fmt.Errorf("%w: encoded frame exceeds %d bytes", ErrInvalidFrame, MaxFrameBytes)
	}
	return data, nil
}
