package sandboxcontroller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/hostepoch"
	"github.com/shwdsun/harness-security-gateway/internal/runnerbridge"
	"github.com/shwdsun/harness-security-gateway/internal/secureid"
)

type offerPhase uint8

const (
	phaseQueued offerPhase = iota + 1
	phaseActive
	phaseReconciling
)

type offeredRun struct {
	fingerprint string
	phase       offerPhase
	cancel      context.CancelFunc
}

type Controller struct {
	durable  DurableService
	registry Registry
	store    Store
	runtime  Runtime

	bridge         BridgeFunc
	sessionRef     SessionRefGenerator
	clock          Clock
	bootID         string
	cleanupTimeout time.Duration
	waitGrace      time.Duration
	reconcileEvery time.Duration

	rootCtx       context.Context
	rootCancel    context.CancelFunc
	queue         chan executionwire.StartRunRequest
	workerDone    chan struct{}
	reconcileWake chan struct{}
	reconcileDone chan struct{}

	mu               sync.Mutex
	closing          bool
	offered          map[string]*offeredRun
	desired          map[string]terminalSpec
	certainNoRuntime map[string]bool
	startsInFlight   int
	startsDrained    chan struct{}
	startsClosed     bool
}

func New(
	ctx context.Context,
	durable DurableService,
	registry Registry,
	store Store,
	runtime Runtime,
	supplied ...Option,
) (*Controller, error) {
	if ctx == nil {
		return nil, errors.New("sandboxcontroller: nil context")
	}
	if nilInterface(durable) || nilInterface(registry) || nilInterface(store) || nilInterface(runtime) {
		return nil, errors.New("sandboxcontroller: missing dependency")
	}
	config := options{
		queueCapacity:  DefaultQueueCapacity,
		cleanupTimeout: defaultCleanupTimeout,
		waitGrace:      defaultWaitGrace,
		reconcileEvery: defaultReconcileEvery,
		bridge:         runnerbridge.Run,
		sessionRef:     secureid.NewSessionRef,
		clock:          func() time.Time { return time.Now().UTC() },
		bootIDSource:   hostepoch.Current,
	}
	for index, option := range supplied {
		if option == nil {
			return nil, fmt.Errorf("sandboxcontroller: option %d is nil", index)
		}
		if err := option(&config); err != nil {
			return nil, fmt.Errorf("sandboxcontroller: apply option %d: %w", index, err)
		}
	}
	bootID, err := loadBootID(config.bootIDSource)
	if err != nil {
		return nil, err
	}

	rootCtx, rootCancel := context.WithCancel(context.Background())
	controller := &Controller{
		durable:          durable,
		registry:         registry,
		store:            store,
		runtime:          runtime,
		bridge:           config.bridge,
		sessionRef:       config.sessionRef,
		clock:            config.clock,
		bootID:           bootID,
		cleanupTimeout:   config.cleanupTimeout,
		waitGrace:        config.waitGrace,
		reconcileEvery:   config.reconcileEvery,
		rootCtx:          rootCtx,
		rootCancel:       rootCancel,
		queue:            make(chan executionwire.StartRunRequest, config.queueCapacity),
		workerDone:       make(chan struct{}),
		reconcileWake:    make(chan struct{}, 1),
		reconcileDone:    make(chan struct{}),
		offered:          make(map[string]*offeredRun),
		desired:          make(map[string]terminalSpec),
		certainNoRuntime: make(map[string]bool),
		startsDrained:    make(chan struct{}),
	}
	// DB-known runtime references and pending Create authority must be
	// reconciled before the broad inventory sweep. In particular, inventory
	// must never remove the only evidence for a same-boot pending intent before
	// its exact LookupIntent boundary has run.
	if err := controller.reconcile(ctx); err != nil {
		rootCancel()
		return nil, err
	}
	if err := controller.reconcileManaged(ctx); err != nil {
		rootCancel()
		return nil, err
	}
	go controller.worker()
	go controller.reconcileLoop()
	return controller, nil
}

// Offer places one already-durable full request into bounded volatile memory.
// The request fingerprint must exactly match the accepted durable row.
func (c *Controller) Offer(ctx context.Context, request executionwire.StartRunRequest) error {
	if c == nil || c.store == nil || c.queue == nil {
		return ErrClosed
	}
	if ctx == nil {
		return ErrNotAccepted
	}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("%w: invalid request", ErrNotAccepted)
	}
	fingerprint, err := executionwire.StartRunFingerprint(request)
	if err != nil {
		return fmt.Errorf("%w: fingerprint request", ErrNotAccepted)
	}

	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return ErrClosed
	}
	if existing := c.offered[request.RunID]; existing != nil {
		if existing.fingerprint != fingerprint {
			c.mu.Unlock()
			return ErrOfferConflict
		}
		if existing.phase == phaseReconciling {
			c.mu.Unlock()
			return ErrNotAccepted
		}
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	run, err := c.store.GetRun(ctx, request.RunID)
	if err != nil {
		return err
	}
	if run.Fingerprint != fingerprint {
		return ErrOfferConflict
	}
	if run.State != executionwire.RunStateAccepted {
		return ErrNotAccepted
	}

	request = cloneRequest(request)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return ErrClosed
	}
	if existing := c.offered[request.RunID]; existing != nil {
		if existing.fingerprint != fingerprint {
			return ErrOfferConflict
		}
		if existing.phase == phaseReconciling {
			return ErrNotAccepted
		}
		return nil
	}
	select {
	case c.queue <- request:
		c.offered[request.RunID] = &offeredRun{fingerprint: fingerprint, phase: phaseQueued}
		return nil
	default:
		return ErrQueueFull
	}
}

func (c *Controller) StartRun(ctx context.Context, request executionwire.StartRunRequest) (executionwire.RunStatus, error) {
	if !c.beginStart() {
		return executionwire.RunStatus{}, executionhttp.NewServiceError(executionhttp.ErrorUnavailable, ErrClosed)
	}
	defer c.endStart()
	status, err := c.durable.StartRun(ctx, request)
	if err != nil {
		return executionwire.RunStatus{}, err
	}
	if status.State != executionwire.RunStateAccepted {
		return status, nil
	}
	if err := c.Offer(ctx, request); err != nil {
		switch {
		case errors.Is(err, ErrNotAccepted):
			// Cancellation may commit between durable Start and Offer. Never
			// return the earlier accepted snapshot after a newer state was
			// durably observed.
			latest, getErr := c.durable.GetRun(ctx, executionwire.GetRunRequest{RunID: request.RunID})
			if getErr != nil {
				return executionwire.RunStatus{}, getErr
			}
			if latest.Status.RunID != request.RunID {
				return executionwire.RunStatus{}, executionhttp.NewServiceError(
					executionhttp.ErrorInternal,
					errors.New("sandboxcontroller: durable service returned a mismatched run"),
				)
			}
			if latest.Status.State == executionwire.RunStateAccepted {
				return executionwire.RunStatus{}, executionhttp.NewServiceError(
					executionhttp.ErrorUnavailable,
					errors.New("sandboxcontroller: run reconciliation is in progress"),
				)
			}
			return latest.Status, nil
		case errors.Is(err, ErrQueueFull), errors.Is(err, ErrClosed),
			errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return executionwire.RunStatus{}, executionhttp.NewServiceError(executionhttp.ErrorUnavailable, err)
		case errors.Is(err, ErrOfferConflict):
			return executionwire.RunStatus{}, executionhttp.NewServiceError(executionhttp.ErrorConflict, err)
		default:
			return executionwire.RunStatus{}, executionhttp.NewServiceError(executionhttp.ErrorInternal, err)
		}
	}
	return status, nil
}

// BeginClose atomically closes the durable Start gate. Callers should invoke
// it before beginning HTTP drain so no late handler can register a Run after
// Close's final reconciliation snapshot.
func (c *Controller) BeginClose() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closing = true
	c.closeStartDrainLocked()
	c.mu.Unlock()
}

func (c *Controller) GetRun(ctx context.Context, request executionwire.GetRunRequest) (executionwire.GetRunResponse, error) {
	return c.durable.GetRun(ctx, request)
}

func (c *Controller) CancelRun(ctx context.Context, request executionwire.CancelRunRequest) (executionwire.RunStatus, error) {
	status, err := c.durable.CancelRun(ctx, request)
	if err != nil {
		return executionwire.RunStatus{}, err
	}
	if status.State == executionwire.RunStateCancelling {
		c.mu.Lock()
		if offered := c.offered[request.RunID]; offered != nil && offered.phase == phaseActive && offered.cancel != nil {
			offered.cancel()
		}
		c.mu.Unlock()
		c.signalReconcile()
	}
	return status, nil
}

func (c *Controller) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("sandboxcontroller: nil close context")
	}
	c.mu.Lock()
	c.closing = true
	c.closeStartDrainLocked()
	c.rootCancel()
	c.mu.Unlock()
	if err := waitDone(ctx, c.startsDrained); err != nil {
		return err
	}
	if err := waitDone(ctx, c.workerDone); err != nil {
		return err
	}
	if err := waitDone(ctx, c.reconcileDone); err != nil {
		return err
	}
	if err := c.reconcile(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	for len(c.queue) > 0 {
		<-c.queue
	}
	clear(c.offered)
	c.mu.Unlock()
	return nil
}

func (c *Controller) beginStart() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return false
	}
	c.startsInFlight++
	return true
}

func (c *Controller) endStart() {
	c.mu.Lock()
	if c.startsInFlight > 0 {
		c.startsInFlight--
	}
	c.closeStartDrainLocked()
	c.mu.Unlock()
}

func (c *Controller) closeStartDrainLocked() {
	if c.closing && c.startsInFlight == 0 && !c.startsClosed {
		close(c.startsDrained)
		c.startsClosed = true
	}
}

func (c *Controller) worker() {
	defer close(c.workerDone)
	for {
		// The attached Docker CLI exiting is not proof that its container has
		// stopped. Keep the single execution lane closed while any durable row
		// can still represent a live runtime. This also protects read-only
		// workspaces: their harness state remains writable and may be shared by
		// consecutive Runs even though they do not hold a workspace writer lock.
		if !c.waitForRuntimeQuiescence(c.rootCtx) {
			return
		}
		select {
		case <-c.rootCtx.Done():
			return
		case request := <-c.queue:
			if c.rootCtx.Err() != nil {
				return
			}
			c.executeOffer(request)
		}
	}
}

// waitForRuntimeQuiescence is the fail-closed execution gate. Reconciliation
// may run concurrently, but only the worker calls Create/AttachStart. Once the
// durable ref or intent disappears, cleanup has crossed its proof boundary;
// until then a later Run must not enter the runtime, even for another or a
// read-only workspace.
func (c *Controller) waitForRuntimeQuiescence(ctx context.Context) bool {
	for {
		queryCtx, cancel := context.WithTimeout(ctx, c.cleanupTimeout)
		runs, err := c.store.ListUnreconciled(queryCtx)
		cancel()
		blocked := err != nil
		if err == nil {
			for _, run := range runs {
				if run.RuntimeRef != nil || run.RuntimeIntentPending ||
					run.State == executionwire.RunStateRunning ||
					run.State == executionwire.RunStateCancelling {
					blocked = true
					break
				}
			}
		}
		if !blocked {
			return true
		}

		c.signalReconcile()
		timer := time.NewTimer(c.reconcileEvery)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return false
		case <-timer.C:
		}
	}
}

func (c *Controller) executeOffer(request executionwire.StartRunRequest) {
	runCtx, cancel := context.WithDeadline(c.rootCtx, request.Deadline)
	c.mu.Lock()
	offered := c.offered[request.RunID]
	if offered == nil || offered.phase == phaseReconciling {
		c.mu.Unlock()
		cancel()
		return
	}
	offered.phase = phaseActive
	offered.cancel = cancel
	c.mu.Unlock()

	defer func() {
		cancel()
		c.mu.Lock()
		delete(c.offered, request.RunID)
		c.mu.Unlock()
		c.signalReconcile()
	}()
	c.execute(runCtx, cancel, request)
}

func waitDone(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func cloneRequest(request executionwire.StartRunRequest) executionwire.StartRunRequest {
	if request.SessionRef != nil {
		value := *request.SessionRef
		request.SessionRef = &value
	}
	return request
}

var _ executionhttp.Service = (*Controller)(nil)
