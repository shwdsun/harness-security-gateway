// Package sandboxcontroller owns sandboxd's single-worker runtime lifecycle.
// Durable request registration remains in sandboxservice; this package holds a
// bounded, prompt-bearing in-memory offer only while a Run is queued or active.
package sandboxcontroller

import (
	"context"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/hostepoch"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

const (
	DefaultQueueCapacity = 8
	MaxQueueCapacity     = 64

	defaultCleanupTimeout = 20 * time.Second
	defaultWaitGrace      = 250 * time.Millisecond
	defaultReconcileEvery = 250 * time.Millisecond
)

var (
	ErrQueueFull     = errors.New("sandboxcontroller: offer queue is full")
	ErrClosed        = errors.New("sandboxcontroller: controller is closed")
	ErrNotAccepted   = errors.New("sandboxcontroller: run is not durably accepted")
	ErrOfferConflict = errors.New("sandboxcontroller: run offer conflicts with durable request")
	ErrCleanup       = errors.New("sandboxcontroller: runtime cleanup failed")
	// ErrRuntimeIntentUnresolved means a prior Create may still complete in
	// this host boot. Keeping the durable intent and workspace authority is the
	// only safe outcome until an exact container appears or the host reboots.
	ErrRuntimeIntentUnresolved = errors.New("sandboxcontroller: runtime intent is unresolved")
)

// DurableService is the already-initialized sandboxservice surface.
type DurableService interface {
	executionhttp.Service
}

// Registry is the immutable target view required by the executor.
type Registry interface {
	Resolve(id, expectedRevision string) (targetregistry.Entry, error)
}

// Store is the consumer-owned persistence surface. No method accepts a prompt.
type Store interface {
	GetRun(ctx context.Context, runID string) (sandboxstore.Run, error)
	BeginRuntimeIntent(ctx context.Context, runID, bootID string) (sandboxstore.Run, bool, error)
	ClearRuntimeIntent(ctx context.Context, runID string) (sandboxstore.Run, error)
	SetRuntimeRef(ctx context.Context, runID, runtimeRef string) (sandboxstore.Run, error)
	AppendEvent(ctx context.Context, event executionwire.RunEvent, mapping *sandboxstore.SessionMapping) (sandboxstore.Run, error)
	ResolveSessionForRun(ctx context.Context, runID, sessionRef, targetID, targetRevision, sessionScopeDigest string) (string, error)
	ConfirmRuntimeStopped(ctx context.Context, runID string) (sandboxstore.Run, error)
	ListUnreconciled(ctx context.Context) ([]sandboxstore.Run, error)
}

// Process is the narrow attached HRP process surface used by the controller.
type Process interface {
	Input() io.WriteCloser
	Output() io.ReadCloser
	Diagnostics() io.ReadCloser
	Wait() error
}

// Runtime contains no caller-selected Docker flags, paths, or options.
type Runtime interface {
	ListManaged(ctx context.Context) ([]string, error)
	Create(ctx context.Context, runID string, manifest targetmanifest.Manifest) (string, error)
	LookupIntent(ctx context.Context, runID string, manifest targetmanifest.Manifest) (ref string, found bool, err error)
	AttachStart(ctx context.Context, ref string) (Process, error)
	Inspect(ctx context.Context, ref string) (dockerruntime.Inspection, error)
	Stop(ctx context.Context, ref string) error
	Kill(ctx context.Context, ref string) error
	RemoveStopped(ctx context.Context, ref string) error
}

type BridgeFunc func(
	ctx context.Context,
	request executionwire.StartRunRequest,
	manifest targetmanifest.Manifest,
	resolvedVendorToken *string,
	runnerOutput io.Reader,
	runnerInput io.Writer,
	sink runnerbridge.Sink,
) error

type SessionRefGenerator func() (string, error)
type Clock func() time.Time
type BootIDSource func() (string, error)

type Option func(*options) error

type options struct {
	queueCapacity  int
	cleanupTimeout time.Duration
	waitGrace      time.Duration
	reconcileEvery time.Duration
	bridge         BridgeFunc
	sessionRef     SessionRefGenerator
	clock          Clock
	bootIDSource   BootIDSource
}

func WithQueueCapacity(capacity int) Option {
	return func(config *options) error {
		if capacity < 1 || capacity > MaxQueueCapacity {
			return errors.New("sandboxcontroller: queue capacity is outside the fixed bound")
		}
		config.queueCapacity = capacity
		return nil
	}
}

func WithCleanupTimeout(timeout time.Duration) Option {
	return func(config *options) error {
		if timeout <= 0 || timeout > time.Minute {
			return errors.New("sandboxcontroller: cleanup timeout is outside the fixed bound")
		}
		config.cleanupTimeout = timeout
		return nil
	}
}

func WithWaitGrace(grace time.Duration) Option {
	return func(config *options) error {
		if grace <= 0 || grace > 5*time.Second {
			return errors.New("sandboxcontroller: process wait grace is outside the fixed bound")
		}
		config.waitGrace = grace
		return nil
	}
}

func WithReconcileInterval(interval time.Duration) Option {
	return func(config *options) error {
		if interval < 10*time.Millisecond || interval > 30*time.Second {
			return errors.New("sandboxcontroller: reconcile interval is outside the fixed bound")
		}
		config.reconcileEvery = interval
		return nil
	}
}

func WithBridge(bridge BridgeFunc) Option {
	return func(config *options) error {
		if bridge == nil {
			return errors.New("sandboxcontroller: nil bridge")
		}
		config.bridge = bridge
		return nil
	}
}

func WithSessionRefGenerator(generator SessionRefGenerator) Option {
	return func(config *options) error {
		if generator == nil {
			return errors.New("sandboxcontroller: nil session ref generator")
		}
		config.sessionRef = generator
		return nil
	}
}

func WithClock(clock Clock) Option {
	return func(config *options) error {
		if clock == nil {
			return errors.New("sandboxcontroller: nil clock")
		}
		config.clock = clock
		return nil
	}
}

// WithBootIDSource replaces the Linux boot-ID reader. It exists primarily for
// deterministic tests; New still validates the returned value through the
// same canonical hostepoch grammar used by the store.
func WithBootIDSource(source BootIDSource) Option {
	return func(config *options) error {
		if source == nil {
			return errors.New("sandboxcontroller: nil boot ID source")
		}
		config.bootIDSource = source
		return nil
	}
}

func loadBootID(source BootIDSource) (string, error) {
	if source == nil {
		return "", errors.New("sandboxcontroller: nil boot ID source")
	}
	bootID, err := source()
	if err != nil {
		return "", errors.New("sandboxcontroller: host boot identifier is unavailable")
	}
	if err := hostepoch.Validate(bootID); err != nil {
		return "", errors.New("sandboxcontroller: host boot identifier is invalid")
	}
	return bootID, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
