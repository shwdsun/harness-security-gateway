package executionwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const startRunFingerprintDomain = "harness-gateway.executionwire.StartRun/v2"

// StartRunFingerprint returns a stable, domain-separated SHA-256 fingerprint
// of every semantic StartRun field. Equivalent deadlines with different time
// zone offsets normalize to the same UTC representation.
func StartRunFingerprint(request StartRunRequest) (string, error) {
	if err := request.Validate(); err != nil {
		return "", err
	}

	canonical := struct {
		Domain             string    `json:"domain"`
		RunID              string    `json:"run_id"`
		TargetID           string    `json:"target_id"`
		ExpectedRevision   string    `json:"expected_revision"`
		SessionScopeDigest string    `json:"session_scope_digest"`
		SessionRef         *string   `json:"session_ref"`
		MediaType          MediaType `json:"media_type"`
		Text               string    `json:"text"`
		Deadline           string    `json:"deadline"`
	}{
		Domain:             startRunFingerprintDomain,
		RunID:              request.RunID,
		TargetID:           request.TargetID,
		ExpectedRevision:   request.ExpectedRevision,
		SessionScopeDigest: request.SessionScopeDigest,
		SessionRef:         request.SessionRef,
		MediaType:          request.Input.MediaType,
		Text:               request.Input.Text,
		Deadline:           request.Deadline.UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("canonicalize StartRun: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
