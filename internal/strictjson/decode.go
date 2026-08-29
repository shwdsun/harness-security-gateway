// Package strictjson provides bounded JSON decoding for trust-boundary DTOs.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var (
	ErrTooLarge     = errors.New("json payload exceeds byte limit")
	ErrTooDeep      = errors.New("json payload exceeds nesting limit")
	ErrDuplicateKey = errors.New("json payload contains a duplicate object key")
	ErrInvalidUTF8  = errors.New("json payload is not valid UTF-8")
	ErrTrailingData = errors.New("json payload contains trailing data")
)

// Decode validates framing and then decodes one JSON value into dst. Object
// keys must be unique and fields unknown to dst are rejected.
func Decode(data []byte, maxBytes, maxDepth int, dst any) error {
	if maxBytes <= 0 || maxDepth <= 0 {
		return errors.New("strictjson: limits must be positive")
	}
	if len(data) > maxBytes {
		return ErrTooLarge
	}
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}
	if dst == nil {
		return errors.New("strictjson: nil destination")
	}

	check := json.NewDecoder(bytes.NewReader(data))
	check.UseNumber()
	if err := scanValue(check, 1, maxDepth); err != nil {
		return err
	}
	if err := expectEOF(check); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if err := expectEOF(dec); err != nil {
		return err
	}
	return nil
}

func scanValue(dec *json.Decoder, depth, maxDepth int) error {
	if depth > maxDepth {
		return ErrTooDeep
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("scan JSON: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return fmt.Errorf("scan object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("scan object key: expected string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
			}
			seen[key] = struct{}{}
			if err := scanValue(dec, depth+1, maxDepth); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("close object: %w", err)
		}
	case '[':
		for dec.More() {
			if err := scanValue(dec, depth+1, maxDepth); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("close array: %w", err)
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
	return nil
}

func expectEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); err == nil {
		return ErrTrailingData
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("scan trailing JSON: %w", err)
	}
	return nil
}
