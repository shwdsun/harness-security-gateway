// Package sessionauth defines the provider-neutral authorization scope carried
// across the agentd/sandboxd boundary as a one-way digest.
package sessionauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	DigestBytes        = 64
	MaxIdentifierBytes = 256
	MaxTargetIDBytes   = 128
	MaxRevisionBytes   = 160

	digestDomain = "harness-gateway.session-scope/v1"
)

var ErrInvalidScope = errors.New("invalid session authorization scope")

// Scope is the complete Exact Binding Authorization identity for one resumable
// session. PolicyRevision is deliberately absent: BindingFingerprint already
// commits to the exact binding while unrelated policy edits are not revocation.
type Scope struct {
	BindingFingerprint string
	ConnectorID        string
	ActorRef           string
	ConversationRef    string
	TargetID           string
	TargetRevision     string
}

// Digest validates and hashes every scope field using a canonical,
// domain-separated JSON representation. The digest is evidence carried by the
// authenticated agentd peer, not a bearer capability or a secret.
func Digest(scope Scope) (string, error) {
	if err := Validate(scope); err != nil {
		return "", err
	}
	canonical := struct {
		Domain             string `json:"domain"`
		BindingFingerprint string `json:"binding_fingerprint"`
		ConnectorID        string `json:"connector_id"`
		ActorRef           string `json:"actor_ref"`
		ConversationRef    string `json:"conversation_ref"`
		TargetID           string `json:"target_id"`
		TargetRevision     string `json:"target_revision"`
	}{
		Domain:             digestDomain,
		BindingFingerprint: scope.BindingFingerprint,
		ConnectorID:        scope.ConnectorID,
		ActorRef:           scope.ActorRef,
		ConversationRef:    scope.ConversationRef,
		TargetID:           scope.TargetID,
		TargetRevision:     scope.TargetRevision,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("canonicalize session scope: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func Validate(scope Scope) error {
	if err := ValidateDigest(scope.BindingFingerprint); err != nil {
		return fmt.Errorf("%w: binding fingerprint", ErrInvalidScope)
	}
	for _, item := range []struct {
		value string
		limit int
	}{
		{scope.ConnectorID, MaxIdentifierBytes},
		{scope.ActorRef, MaxIdentifierBytes},
		{scope.ConversationRef, MaxIdentifierBytes},
		{scope.TargetID, MaxTargetIDBytes},
		{scope.TargetRevision, MaxRevisionBytes},
	} {
		if !validIdentifier(item.value, item.limit) {
			return ErrInvalidScope
		}
	}
	return nil
}

// ValidateDigest accepts only the canonical lowercase SHA-256 representation.
func ValidateDigest(value string) error {
	if len(value) != DigestBytes {
		return ErrInvalidScope
	}
	for index := range value {
		character := value[index]
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return ErrInvalidScope
	}
	return nil
}

func validIdentifier(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}
