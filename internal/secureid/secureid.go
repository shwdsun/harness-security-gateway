// Package secureid generates compact opaque identifiers and capability tokens.
// Values use a short, validated type prefix followed by unpadded base64url
// entropy, so they are safe in the project's JSON and identifier grammars.
package secureid

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	MaxPrefixBytes = 12

	// Persistent identifiers have at least 128 bits of collision resistance.
	MinIDEntropyBytes = 16
	// Capability tokens have at least 192 bits of entropy.
	MinTokenEntropyBytes = 24
	MaxEntropyBytes      = 64

	defaultIDEntropyBytes    = MinIDEntropyBytes
	defaultTokenEntropyBytes = MinTokenEntropyBytes
)

var (
	ErrInvalidPrefix  = errors.New("invalid secure ID prefix")
	ErrInvalidEntropy = errors.New("invalid secure ID entropy size")
	ErrRandomRead     = errors.New("secure random read failed")
)

// NewID returns prefix_<random>, with at least 128 random bits. It is intended
// for persistent identifiers whose primary security property is collision
// resistance. Prefix must be a lower-case ASCII label: [a-z][a-z0-9]*.
func NewID(prefix string, entropyBytes int) (string, error) {
	return generate(rand.Reader, prefix, entropyBytes, MinIDEntropyBytes)
}

// NewToken returns prefix_<random>, with at least 192 random bits. Use it for
// bearer capabilities such as outbox lease tokens.
func NewToken(prefix string, entropyBytes int) (string, error) {
	return generate(rand.Reader, prefix, entropyBytes, MinTokenEntropyBytes)
}

func NewRunID() (string, error) {
	return NewID("run", defaultIDEntropyBytes)
}

func NewDeliveryID() (string, error) {
	return NewID("delivery", defaultIDEntropyBytes)
}

func NewSessionRef() (string, error) {
	return NewID("session", defaultIDEntropyBytes)
}

func NewLeaseToken() (string, error) {
	return NewToken("lease", defaultTokenEntropyBytes)
}

// generate takes its reader as an argument only to make entropy failures and
// exact encodings testable. Production entry points always use crypto/rand.Reader.
func generate(reader io.Reader, prefix string, entropyBytes, minimumEntropyBytes int) (string, error) {
	if err := validatePrefix(prefix); err != nil {
		return "", err
	}
	if entropyBytes < minimumEntropyBytes || entropyBytes > MaxEntropyBytes {
		return "", fmt.Errorf(
			"%w: must be between %d and %d bytes",
			ErrInvalidEntropy,
			minimumEntropyBytes,
			MaxEntropyBytes,
		)
	}
	if reader == nil {
		return "", fmt.Errorf("%w: nil entropy reader", ErrRandomRead)
	}

	entropy := make([]byte, entropyBytes)
	if _, err := io.ReadFull(reader, entropy); err != nil {
		return "", fmt.Errorf("%w: %w", ErrRandomRead, err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(entropy), nil
}

func validatePrefix(prefix string) error {
	if len(prefix) == 0 || len(prefix) > MaxPrefixBytes {
		return fmt.Errorf("%w: must contain between 1 and %d bytes", ErrInvalidPrefix, MaxPrefixBytes)
	}
	for index := 0; index < len(prefix); index++ {
		char := prefix[index]
		if char >= 'a' && char <= 'z' {
			continue
		}
		if index > 0 && char >= '0' && char <= '9' {
			continue
		}
		return fmt.Errorf("%w: must match [a-z][a-z0-9]*", ErrInvalidPrefix)
	}
	return nil
}
