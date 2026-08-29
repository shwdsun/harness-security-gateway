package secureid

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestGenerateUsesDeterministicUnpaddedBase64URL(t *testing.T) {
	entropy := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	got, err := generate(bytes.NewReader(entropy), "run", len(entropy), MinIDEntropyBytes)
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	const want = "run_AAECAwQFBgcICQoLDA0ODw"
	if got != want {
		t.Fatalf("generate() = %q, want %q", got, want)
	}
	assertSafeValue(t, got)
}

func TestPrefixGrammar(t *testing.T) {
	valid := []string{"r", "run", "run1", "abcdefghijkl"}
	for _, prefix := range valid {
		t.Run("valid_"+prefix, func(t *testing.T) {
			if _, err := generate(bytes.NewReader(make([]byte, MinIDEntropyBytes)), prefix, MinIDEntropyBytes, MinIDEntropyBytes); err != nil {
				t.Fatalf("generate(%q) error = %v", prefix, err)
			}
		})
	}

	invalid := []string{
		"",
		"1run",
		"Run",
		"run-id",
		"run_id",
		"run id",
		"abcdefghijklmn",
		"会话",
	}
	for _, prefix := range invalid {
		t.Run("invalid_"+prefix, func(t *testing.T) {
			if _, err := generate(bytes.NewReader(make([]byte, MinIDEntropyBytes)), prefix, MinIDEntropyBytes, MinIDEntropyBytes); !errors.Is(err, ErrInvalidPrefix) {
				t.Fatalf("generate(%q) error = %v, want ErrInvalidPrefix", prefix, err)
			}
		})
	}
}

func TestEntropyBounds(t *testing.T) {
	tests := []struct {
		name    string
		minimum int
		size    int
		wantErr bool
	}{
		{name: "ID below 128 bits", minimum: MinIDEntropyBytes, size: MinIDEntropyBytes - 1, wantErr: true},
		{name: "ID exactly 128 bits", minimum: MinIDEntropyBytes, size: MinIDEntropyBytes},
		{name: "token below 192 bits", minimum: MinTokenEntropyBytes, size: MinTokenEntropyBytes - 1, wantErr: true},
		{name: "token exactly 192 bits", minimum: MinTokenEntropyBytes, size: MinTokenEntropyBytes},
		{name: "maximum", minimum: MinIDEntropyBytes, size: MaxEntropyBytes},
		{name: "over maximum", minimum: MinIDEntropyBytes, size: MaxEntropyBytes + 1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := generate(bytes.NewReader(make([]byte, test.size)), "test", test.size, test.minimum)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidEntropy) {
					t.Fatalf("generate() error = %v, want ErrInvalidEntropy", err)
				}
				if value != "" {
					t.Fatalf("generate() value = %q on error", value)
				}
				return
			}
			if err != nil {
				t.Fatalf("generate() error = %v", err)
			}
			assertSafeValue(t, value)
		})
	}
}

func TestNewIDAndTokenApplyDifferentMinimums(t *testing.T) {
	if _, err := NewID("custom", MinIDEntropyBytes); err != nil {
		t.Fatalf("NewID() error = %v", err)
	}
	if _, err := NewToken("custom", MinIDEntropyBytes); !errors.Is(err, ErrInvalidEntropy) {
		t.Fatalf("NewToken(128 bits) error = %v, want ErrInvalidEntropy", err)
	}
	if _, err := NewToken("custom", MinTokenEntropyBytes); err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
}

func TestDefaultHelpersHaveExpectedPrefixesAndLengths(t *testing.T) {
	tests := []struct {
		name         string
		prefix       string
		entropyBytes int
		generate     func() (string, error)
	}{
		{name: "run", prefix: "run", entropyBytes: MinIDEntropyBytes, generate: NewRunID},
		{name: "delivery", prefix: "delivery", entropyBytes: MinIDEntropyBytes, generate: NewDeliveryID},
		{name: "session", prefix: "session", entropyBytes: MinIDEntropyBytes, generate: NewSessionRef},
		{name: "lease", prefix: "lease", entropyBytes: MinTokenEntropyBytes, generate: NewLeaseToken},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := test.generate()
			if err != nil {
				t.Fatalf("helper error = %v", err)
			}
			wantLength := len(test.prefix) + 1 + rawBase64URLLength(test.entropyBytes)
			if len(value) != wantLength {
				t.Fatalf("len(value) = %d, want %d (%q)", len(value), wantLength, value)
			}
			if !strings.HasPrefix(value, test.prefix+"_") {
				t.Fatalf("value = %q, want prefix %q", value, test.prefix+"_")
			}
			assertSafeValue(t, value)
		})
	}
}

func TestRandomValuesUniquenessSmoke(t *testing.T) {
	const samples = 1024
	seen := make(map[string]struct{}, samples)
	for index := 0; index < samples; index++ {
		value, err := NewRunID()
		if err != nil {
			t.Fatalf("NewRunID() at %d error = %v", index, err)
		}
		if _, duplicate := seen[value]; duplicate {
			t.Fatalf("duplicate value at %d: %q", index, value)
		}
		seen[value] = struct{}{}
	}
}

var errEntropySource = errors.New("entropy source failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errEntropySource
}

func TestGeneratePropagatesEntropyFailure(t *testing.T) {
	value, err := generate(failingReader{}, "run", MinIDEntropyBytes, MinIDEntropyBytes)
	if value != "" {
		t.Fatalf("generate() value = %q on error", value)
	}
	if !errors.Is(err, ErrRandomRead) || !errors.Is(err, errEntropySource) {
		t.Fatalf("generate() error = %v, want ErrRandomRead and source error", err)
	}

	value, err = generate(bytes.NewReader(make([]byte, MinIDEntropyBytes-1)), "run", MinIDEntropyBytes, MinIDEntropyBytes)
	if value != "" || !errors.Is(err, ErrRandomRead) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short reader = %q, %v; want empty, ErrRandomRead, ErrUnexpectedEOF", value, err)
	}

	value, err = generate(nil, "run", MinIDEntropyBytes, MinIDEntropyBytes)
	if value != "" || !errors.Is(err, ErrRandomRead) {
		t.Fatalf("nil reader = %q, %v; want empty, ErrRandomRead", value, err)
	}
}

func assertSafeValue(t *testing.T, value string) {
	t.Helper()
	if strings.ContainsAny(value, "= \t\r\n") {
		t.Fatalf("value contains padding or whitespace: %q", value)
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' {
			continue
		}
		t.Fatalf("value contains non-base64url-safe byte %#x: %q", char, value)
	}
}

func rawBase64URLLength(bytes int) int {
	fullGroups := bytes / 3
	remainder := bytes % 3
	length := fullGroups * 4
	if remainder == 1 {
		length += 2
	} else if remainder == 2 {
		length += 3
	}
	return length
}
