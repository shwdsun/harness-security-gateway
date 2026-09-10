//go:build linux && amd64 && codexintegration

package main

import (
	"errors"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func prepareCodex(config sandboxconfig.Config) (executionSetup, error) {
	runtime, pin, err := dockerruntime.NewConfiguredCodex(config)
	if err != nil {
		return executionSetup{}, err
	}
	return codexExecution(config, runtime, pin), nil
}

func holdEnrollmentSource(root, directory string) (enrollmentSource, error) {
	return credentialsource.Hold(root, directory)
}

func codexExecution(config sandboxconfig.Config, runtime *dockerruntime.Runtime, pin string) executionSetup {
	manifest := config.Targets[0].Clone()
	fingerprint, _ := manifest.Fingerprint()
	binding, scope := config.Codex.Credential, config.Codex.Scope.SessionScope()
	return executionSetup{
		bindings: []credentialsource.Binding{binding},
		runtime:  func() (*dockerruntime.Runtime, error) { return runtime, nil },
		authority: func(m targetmanifest.Definition, fp string) (sandboxservice.ResolvedAuthority, error) {
			actual, err := m.Fingerprint()
			if err != nil || m.ID() != manifest.ID() || m.Revision() != manifest.Revision() || fp != fingerprint || actual != fp {
				return sandboxservice.ResolvedAuthority{}, errors.New("fixed Codex authority does not match the configured revision")
			}
			return sandboxservice.ResolvedAuthority{RevisionPin: pin,
				RunnerState: sandboxstore.RunnerStateOwnership{Kind: targetmanifest.RunnerStateNone},
				Credential: &sandboxservice.ResolvedCredential{
					Ref: sandboxstore.CredentialRef{SlotRef: binding.SlotRef, Generation: int64(binding.Generation)}, Scope: scope}}, nil
		},
	}
}
