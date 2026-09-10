//go:build !linux || !amd64 || !codexintegration

package main

import (
	"errors"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
)

func prepareCodex(sandboxconfig.Config) (executionSetup, error) {
	return executionSetup{}, errors.New("fixed Codex startup requires the Linux/amd64 codexintegration build; no startup effects performed")
}

func holdEnrollmentSource(string, string) (enrollmentSource, error) {
	return nil, errEnrollment
}
