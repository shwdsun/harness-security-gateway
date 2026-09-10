// Package sandboxservice composes sandboxd's immutable target registry with
// its runtime reconciliation store. It implements the execution HTTP service
// without starting containers or background runtime work.
package sandboxservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

// Registry is the small, consumer-owned view sandboxservice needs. The
// concrete targetregistry.Registry satisfies it.
type Registry interface {
	Entries() []targetregistry.Entry
	Resolve(id, expectedRevision string) (targetregistry.Entry, error)
}

// Store is the small, consumer-owned persistence view sandboxservice needs.
// The concrete sandboxstore.Store satisfies it.
type Store interface {
	RegisterEnrolledTargetAuthorities(context.Context, []sandboxstore.EnrolledTargetAuthority) error
	RegisterStart(ctx context.Context, request executionwire.StartRunRequest, resolvedRevision, workspaceID string, writable bool, sessionPolicy sandboxstore.SessionPolicy) (sandboxstore.Run, bool, error)
	GetSnapshot(ctx context.Context, runID string) (executionwire.GetRunResponse, error)
	MarkCancelling(ctx context.Context, runID string) (sandboxstore.Run, error)
}

type Clock func() time.Time

// RevisionPinFunc returns the durable security fingerprint for one already
// validated manifest fingerprint. Consumers can bind local runtime and storage
// authorities without making sandboxservice depend on their configuration.
type RevisionPinFunc func(manifest targetmanifest.Definition, manifestFingerprint string) (string, error)

// RunnerStateOwnershipFunc reports explicit none, or resolves persistent state
// to a durable path fingerprint and a pre-registration absence observation.
// This callback is required for the legacy credential-free construction path;
// WithAuthorityResolver instead supplies ownership with the rest of authority.
type RunnerStateOwnershipFunc func(
	manifest targetmanifest.Definition,
) (sandboxstore.RunnerStateOwnership, error)

type Option func(*options) error

type options struct {
	clock             Clock
	revisionPin       RevisionPinFunc
	authorityResolver AuthorityResolverFunc
}

// WithClock injects a clock for deadline checks. Service always normalizes its
// result to UTC.
func WithClock(clock Clock) Option {
	return func(config *options) error {
		if clock == nil {
			return errors.New("sandboxservice: nil clock")
		}
		config.clock = clock
		return nil
	}
}

// WithRevisionPin supplies a consumer-owned revision pin. It is evaluated
// exactly once per registry entry during New; the validated result is then
// frozen for the lifetime of the service.
func WithRevisionPin(revisionPin RevisionPinFunc) Option {
	return func(config *options) error {
		if revisionPin == nil || config.authorityResolver != nil {
			return errors.New("sandboxservice: missing or conflicting revision pin function")
		}
		config.revisionPin = revisionPin
		return nil
	}
}

type Service struct {
	registry   Registry
	store      Store
	clock      Clock
	registered map[targetKey]registeredTarget
}

type targetKey struct {
	id       string
	revision string
}

type registeredTarget struct {
	manifestFingerprint string
	revisionPin         string
}

// New validates and durably pins every registry target revision before it
// returns a usable service. A reused revision with changed manifest semantics
// or a changed consumer-supplied authority binding fails closed through
// sandboxstore.ErrConflict.
// WithAuthorityResolver requires a nil runnerStateOwnership callback. Both
// construction paths use strict whole-registry enrollment-aware registration.
func New(
	ctx context.Context,
	registry Registry,
	store Store,
	runnerStateOwnership RunnerStateOwnershipFunc,
	supplied ...Option,
) (*Service, error) {
	if ctx == nil {
		return nil, errors.New("sandboxservice: nil context")
	}
	if nilInterface(registry) {
		return nil, errors.New("sandboxservice: nil target registry")
	}
	if nilInterface(store) {
		return nil, errors.New("sandboxservice: nil sandbox store")
	}
	config := options{
		clock: func() time.Time { return time.Now().UTC() },
	}
	for index, option := range supplied {
		if option == nil {
			return nil, fmt.Errorf("sandboxservice: option %d is nil", index)
		}
		if err := option(&config); err != nil {
			return nil, fmt.Errorf("sandboxservice: apply option %d: %w", index, err)
		}
	}
	if (config.authorityResolver == nil) == (runnerStateOwnership == nil) {
		return nil, errors.New("sandboxservice: select exactly one authority resolver or runner-state callback")
	}

	entries := registry.Entries()
	if len(entries) == 0 {
		return nil, errors.New("sandboxservice: target registry is empty")
	}
	registered := make(map[targetKey]registeredTarget, len(entries))
	registrations := make([]sandboxstore.EnrolledTargetAuthority, 0, len(entries))
	for index, entry := range entries {
		if err := entry.Manifest.Validate(); err != nil {
			return nil, fmt.Errorf("sandboxservice: invalid target entry %d: %w", index, err)
		}
		fingerprint, err := entry.Manifest.Fingerprint()
		if err != nil {
			return nil, fmt.Errorf("sandboxservice: fingerprint target entry %d: %w", index, err)
		}
		if fingerprint != entry.Fingerprint {
			return nil, fmt.Errorf("sandboxservice: target entry %d fingerprint is inconsistent", index)
		}
		key := targetKey{id: entry.Manifest.ID(), revision: entry.Manifest.Revision()}
		if _, exists := registered[key]; exists {
			return nil, fmt.Errorf("sandboxservice: duplicate target revision in entry %d", index)
		}
		resolved, err := config.resolveAuthority(entry.Manifest, fingerprint, runnerStateOwnership)
		if err != nil {
			return nil, fmt.Errorf("sandboxservice: resolve authority for target entry %d: %w", index, err)
		}
		revisionPin, ownership := resolved.RevisionPin, resolved.RunnerState
		if err := validateRevisionPin(revisionPin); err != nil {
			return nil, fmt.Errorf("sandboxservice: target entry %d revision pin: %w", index, err)
		}
		if ownership.Kind != entry.Manifest.RunnerState().Kind() {
			return nil, fmt.Errorf("sandboxservice: target entry %d runner-state kind is inconsistent", index)
		}
		if ref, persistent := entry.Manifest.RunnerState().PersistentRef(); persistent {
			if ref != ownership.Ref {
				return nil, fmt.Errorf("sandboxservice: target entry %d runner-state ref is inconsistent", index)
			}
			if err := validateRevisionPin(ownership.PathDigest); err != nil {
				return nil, fmt.Errorf("sandboxservice: target entry %d runner-state path digest: %w", index, err)
			}
		} else if ownership.Ref != "" || ownership.PathDigest != "" || ownership.PathAbsent {
			return nil, fmt.Errorf("sandboxservice: target entry %d none carries ownership evidence", index)
		}
		frozen := registeredTarget{
			manifestFingerprint: fingerprint,
			revisionPin:         revisionPin,
		}
		registered[key] = frozen
		registration := sandboxstore.EnrolledTargetAuthority{Target: sandboxstore.TargetAuthority{
			TargetID:              key.id,
			TargetRevision:        key.revision,
			RevisionPin:           frozen.revisionPin,
			RunnerStateKind:       ownership.Kind,
			RunnerStateRef:        ownership.Ref,
			RunnerStatePathDigest: ownership.PathDigest,
			StatePathAbsent:       ownership.PathAbsent,
		}}
		if err := bindResolvedCredential(entry.Manifest, resolved.Credential, &registration); err != nil {
			return nil, fmt.Errorf("sandboxservice: target entry %d: %w", index, err)
		}
		registrations = append(registrations, registration)
	}
	if err := store.RegisterEnrolledTargetAuthorities(ctx, registrations); err != nil {
		return nil, mapInitStoreError(err)
	}

	return &Service{
		registry:   registry,
		store:      store,
		clock:      config.clock,
		registered: registered,
	}, nil
}

func (s *Service) StartRun(ctx context.Context, request executionwire.StartRunRequest) (executionwire.RunStatus, error) {
	if err := s.ready(ctx); err != nil {
		return executionwire.RunStatus{}, internal(err)
	}
	if err := request.Validate(); err != nil {
		return executionwire.RunStatus{}, serviceError(executionhttp.ErrorInvalidState, err)
	}
	entry, err := s.registry.Resolve(request.TargetID, request.ExpectedRevision)
	if err != nil {
		return executionwire.RunStatus{}, mapRegistryError(err)
	}
	if err := s.verifyResolved(request, entry); err != nil {
		return executionwire.RunStatus{}, internal(err)
	}
	if !request.Deadline.After(s.clock().UTC()) {
		return executionwire.RunStatus{}, serviceError(
			executionhttp.ErrorInvalidState,
			errors.New("StartRun deadline has expired"),
		)
	}
	if request.SessionRef != nil && entry.Manifest.Common().SessionMode != targetmanifest.SessionOpaqueResume {
		return executionwire.RunStatus{}, serviceError(
			executionhttp.ErrorInvalidSession,
			errors.New("target does not permit session resume"),
		)
	}

	writable := entry.Manifest.Common().WorkspaceMode == targetmanifest.WorkspaceReadWrite
	run, _, err := s.store.RegisterStart(
		ctx,
		request,
		entry.Manifest.Revision(),
		entry.Manifest.Common().WorkspaceRef,
		writable,
		sandboxstore.SessionPolicy{
			Mode:          entry.Manifest.Common().SessionMode,
			MaxAgeSeconds: entry.Manifest.Common().Limits.MaxSessionAgeSeconds,
			MaxTurns:      int64(entry.Manifest.Common().Limits.MaxSessionTurns),
		},
	)
	if err != nil {
		return executionwire.RunStatus{}, mapStartStoreError(err)
	}
	if run.RunID != request.RunID {
		return executionwire.RunStatus{}, internal(errors.New("store returned a different run ID"))
	}
	return statusFromRun(run)
}

func (s *Service) GetRun(ctx context.Context, request executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
	if err := s.ready(ctx); err != nil {
		return executionwire.GetRunResponse{}, internal(err)
	}
	if err := request.Validate(); err != nil {
		return executionwire.GetRunResponse{}, serviceError(executionhttp.ErrorInvalidState, err)
	}
	response, err := s.store.GetSnapshot(ctx, request.RunID)
	if err != nil {
		return executionwire.GetRunResponse{}, mapRunStoreError(err)
	}
	if response.Status.RunID != request.RunID {
		return executionwire.GetRunResponse{}, internal(errors.New("store returned a different run ID"))
	}
	if err := response.Validate(); err != nil {
		return executionwire.GetRunResponse{}, internal(err)
	}
	return response, nil
}

func (s *Service) CancelRun(ctx context.Context, request executionwire.CancelRunRequest) (executionwire.RunStatus, error) {
	if err := s.ready(ctx); err != nil {
		return executionwire.RunStatus{}, internal(err)
	}
	if err := request.Validate(); err != nil {
		return executionwire.RunStatus{}, serviceError(executionhttp.ErrorInvalidState, err)
	}
	run, err := s.store.MarkCancelling(ctx, request.RunID)
	if err != nil {
		return executionwire.RunStatus{}, mapCancelStoreError(err)
	}
	if run.RunID != request.RunID {
		return executionwire.RunStatus{}, internal(errors.New("store returned a different run ID"))
	}
	return statusFromRun(run)
}

func (s *Service) verifyResolved(request executionwire.StartRunRequest, entry targetregistry.Entry) error {
	if err := entry.Manifest.Validate(); err != nil {
		return err
	}
	computedFingerprint, err := entry.Manifest.Fingerprint()
	if err != nil {
		return err
	}
	if computedFingerprint != entry.Fingerprint {
		return errors.New("registry returned an inconsistent target fingerprint")
	}
	if entry.Manifest.ID() != request.TargetID || entry.Manifest.Revision() != request.ExpectedRevision {
		return errors.New("registry returned a mismatched target")
	}
	key := targetKey{id: entry.Manifest.ID(), revision: entry.Manifest.Revision()}
	registered, exists := s.registered[key]
	if !exists || registered.manifestFingerprint != entry.Fingerprint {
		return errors.New("resolved target revision was not initialized")
	}
	return nil
}

func (s *Service) ready(ctx context.Context) error {
	if s == nil || nilInterface(s.registry) || nilInterface(s.store) || s.clock == nil || s.registered == nil {
		return errors.New("sandboxservice: service is not initialized")
	}
	if ctx == nil {
		return errors.New("sandboxservice: nil context")
	}
	return nil
}

func statusFromRun(run sandboxstore.Run) (executionwire.RunStatus, error) {
	status := executionwire.RunStatus{
		RunID:        run.RunID,
		State:        run.State,
		LastEventSeq: run.LastEventSeq,
	}
	if err := status.Validate(); err != nil {
		return executionwire.RunStatus{}, internal(err)
	}
	return status, nil
}

func mapRegistryError(err error) error {
	switch {
	case errors.Is(err, targetregistry.ErrTargetNotFound):
		return serviceError(executionhttp.ErrorTargetNotFound, err)
	case errors.Is(err, targetregistry.ErrRevisionMismatch):
		return serviceError(executionhttp.ErrorRevisionMismatch, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return serviceError(executionhttp.ErrorUnavailable, err)
	default:
		return internal(err)
	}
}

func mapStartStoreError(err error) error {
	switch {
	case errors.Is(err, sandboxstore.ErrWorkspaceBusy):
		return serviceError(executionhttp.ErrorWorkspaceBusy, err)
	case errors.Is(err, sandboxstore.ErrSessionBusy):
		return serviceError(executionhttp.ErrorConflict, err)
	case errors.Is(err, sandboxstore.ErrConflict):
		return serviceError(executionhttp.ErrorConflict, err)
	case errors.Is(err, sandboxstore.ErrRevisionMismatch):
		return serviceError(executionhttp.ErrorRevisionMismatch, err)
	case errors.Is(err, sandboxstore.ErrSessionNotFound), errors.Is(err, sandboxstore.ErrSessionScope):
		return serviceError(executionhttp.ErrorInvalidSession, err)
	case errors.Is(err, sandboxstore.ErrCredentialAuthority):
		return serviceError(executionhttp.ErrorPolicyDenied, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return serviceError(executionhttp.ErrorUnavailable, err)
	default:
		return internal(err)
	}
}

func mapInitStoreError(err error) error {
	switch {
	case errors.Is(err, sandboxstore.ErrConflict),
		errors.Is(err, sandboxstore.ErrRunnerStateOwnershipUnknown):
		return serviceError(executionhttp.ErrorConflict, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return serviceError(executionhttp.ErrorUnavailable, err)
	default:
		return internal(err)
	}
}

func mapRunStoreError(err error) error {
	switch {
	case errors.Is(err, sandboxstore.ErrNotFound):
		return serviceError(executionhttp.ErrorRunNotFound, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return serviceError(executionhttp.ErrorUnavailable, err)
	default:
		return internal(err)
	}
}

func mapCancelStoreError(err error) error {
	switch {
	case errors.Is(err, sandboxstore.ErrNotFound):
		return serviceError(executionhttp.ErrorRunNotFound, err)
	case errors.Is(err, sandboxstore.ErrIllegalTransition):
		return serviceError(executionhttp.ErrorInvalidState, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return serviceError(executionhttp.ErrorUnavailable, err)
	default:
		return internal(err)
	}
}

func internal(cause error) error {
	return serviceError(executionhttp.ErrorInternal, cause)
}

func serviceError(code executionhttp.ErrorCode, cause error) error {
	return executionhttp.NewServiceError(code, cause)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validateRevisionPin(value string) error {
	if len(value) != sha256.Size*2 {
		return errors.New("must be 64 lowercase hexadecimal characters")
	}
	for index := 0; index < len(value); index++ {
		if value[index] >= '0' && value[index] <= '9' || value[index] >= 'a' && value[index] <= 'f' {
			continue
		}
		return errors.New("must be 64 lowercase hexadecimal characters")
	}
	return nil
}

var (
	_ executionhttp.Service = (*Service)(nil)
	_ Registry              = (*targetregistry.Registry)(nil)
	_ Store                 = (*sandboxstore.Store)(nil)
)
