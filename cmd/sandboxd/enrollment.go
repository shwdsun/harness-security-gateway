package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/privatefs"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
)

var errEnrollment = errors.New("credential enrollment incomplete; preserve the configured source and database for exact inspection")

// This mode owns the same user-global lock as serve. It never starts a
// listener/controller, retires history, chooses a generation, or logs in.
func enrollCredential(ctx context.Context, config sandboxconfig.Config) (returned error) {
	if ctx == nil || ctx.Err() != nil || config.Schema != sandboxconfig.SchemaCodexV1 {
		return errEnrollment
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	setup, err := prepareExecution(config)
	if err != nil {
		return err
	}
	if err := privatefs.EnsureParent(config.ProcessLockPath(), 0o700); err != nil {
		return err
	}
	lock, err := processlock.Acquire(config.ProcessLockPath())
	if err != nil {
		return fmt.Errorf("acquire sandboxd ownership for enrollment: %w", err)
	}
	defer func() {
		if lock.Close() != nil {
			returned = errEnrollment
		}
	}()
	if err := prepareFilesystem(config); err != nil {
		return err
	}
	db, err := sandboxstore.Open(ctx, config.StateDatabase)
	if err != nil {
		return errEnrollment
	}
	defer func() {
		if db.Close() != nil {
			returned = errEnrollment
		}
	}()
	runtime, err := setup.runtime()
	if err != nil {
		return errEnrollment
	}
	return enrollSource(ctx, db, config.Codex.Credential, config.Codex.Scope.SessionScope(),
		func(ctx context.Context) (bool, error) {
			refs, err := runtime.ListManaged(ctx)
			return len(refs) == 0, err
		}, holdEnrollmentSource)
}

type enrollmentSource interface {
	CaptureProof() (string, credentialsource.Proof, error)
	Validate() error
	Close() error
}

// Caller retains global mutation ownership. The private test seam replaces
// only physical observation and runtime inventory, never the enrollment store.
func enrollSource(ctx context.Context, db *sandboxstore.Store, binding credentialsource.Binding, scope sessionauth.Scope,
	emptyRuntime func(context.Context) (bool, error), hold func(string, string) (enrollmentSource, error)) error {
	runs, err := db.ListUnreconciled(ctx)
	if err != nil || len(runs) != 0 {
		return errEnrollment
	}
	empty, err := emptyRuntime(ctx)
	if err != nil || !empty {
		return errEnrollment
	}
	digest, err := sessionauth.Digest(scope)
	if err != nil {
		return errEnrollment
	}
	held, err := hold(binding.Root, binding.Directory)
	if err != nil || held == nil {
		if held != nil {
			_ = held.Close()
		}
		return errEnrollment
	}
	source, proof, err := held.CaptureProof()
	if err != nil || held.Validate() != nil {
		_ = held.Close()
		return errEnrollment
	}
	generation := sandboxstore.CredentialGeneration{SlotRef: binding.SlotRef, Generation: int64(binding.Generation),
		SourceDigest: source, WorkspaceRef: binding.WorkspaceRef, AuthProfileRef: binding.AuthProfileRef, ScopeDigest: digest}
	err = db.RegisterCredentialEnrollment(ctx, generation, proof)
	validationErr := held.Validate()
	closeErr := held.Close()
	if err != nil {
		return errEnrollment
	} // Preserve any uncertain exact commit.
	if validationErr != nil || closeErr != nil {
		_ = db.RevokeCredentialGeneration(ctx, sandboxstore.CredentialRef{SlotRef: generation.SlotRef, Generation: generation.Generation})
		return errEnrollment
	}
	return nil
}
