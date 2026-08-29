package strictjson

import (
	"errors"
	"strings"
	"testing"
)

type fixture struct {
	Name   string `json:"name"`
	Nested struct {
		Value int `json:"value"`
	} `json:"nested"`
}

func TestDecodeAcceptsOneStrictValue(t *testing.T) {
	var got fixture
	err := Decode([]byte(`{"name":"demo","nested":{"value":7}}`), 1024, 8, &got)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.Name != "demo" || got.Nested.Value != 7 {
		t.Fatalf("Decode() = %#v", got)
	}
}

func TestDecodeRejectsDuplicateNestedKey(t *testing.T) {
	var got fixture
	err := Decode([]byte(`{"name":"demo","nested":{"value":1,"value":2}}`), 1024, 8, &got)
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("Decode() error = %v, want ErrDuplicateKey", err)
	}
}

func TestDecodeRejectsUnknownField(t *testing.T) {
	var got fixture
	err := Decode([]byte(`{"name":"demo","nested":{"value":1},"extra":true}`), 1024, 8, &got)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Decode() error = %v, want unknown field", err)
	}
}

func TestDecodeRejectsTrailingValue(t *testing.T) {
	var got fixture
	err := Decode([]byte(`{"name":"demo","nested":{"value":1}} {}`), 1024, 8, &got)
	if !errors.Is(err, ErrTrailingData) {
		t.Fatalf("Decode() error = %v, want ErrTrailingData", err)
	}
}

func TestDecodeEnforcesLimits(t *testing.T) {
	var got fixture
	if err := Decode([]byte(`{"name":"demo","nested":{"value":1}}`), 3, 8, &got); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("byte limit error = %v", err)
	}
	if err := Decode([]byte(`{"name":"demo","nested":{"value":1}}`), 1024, 1, &got); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("depth limit error = %v", err)
	}
}
