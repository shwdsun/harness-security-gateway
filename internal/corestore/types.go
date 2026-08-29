package corestore

import (
	"context"
	"errors"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/secureid"
)

const (
	MaxIDBytes         = 256
	MaxTargetIDBytes   = 128
	MaxRevisionBytes   = 160
	MaxSessionRefBytes = 512
	SHA256HexBytes     = 64
	MaxTextBytes       = 32 * 1024
	MaxClaimLimit      = 20
	MaxReconcileRuns   = 100
)

var (
	ErrInvalid                           = errors.New("invalid core store input")
	ErrConflict                          = errors.New("core store conflict")
	ErrNotFound                          = errors.New("core store record not found")
	ErrDispatchLost                      = errors.New("run dispatch lease is no longer active")
	ErrStartUnprepared                   = errors.New("run start parameters are not prepared")
	ErrLeaseLost                         = errors.New("delivery lease is no longer active")
	ErrInvalidTransition                 = errors.New("invalid run state transition")
	ErrEventExpired                      = errors.New("inbound event is outside the retained replay horizon")
	ErrQuotaExceeded                     = errors.New("core store admission quota exceeded")
	ErrUnsafeLegacyAdmissionState        = errors.New("legacy nonterminal Run lacks exact binding evidence")
	ErrUnsafeLegacyDeliveryState         = errors.New("legacy delivery lacks Run-derived disclosure scope")
	ErrUnsafeLegacySessionState          = errors.New("legacy session state lacks exact binding scope")
	ErrUnsafeLegacySessionLifecycleState = errors.New("legacy session scope has multiple nonterminal Runs")
	ErrSessionScopeBusy                  = errors.New("session scope already has a nonterminal Run")
)

type Clock func() time.Time

type LeaseTokenSource func() (string, error)

type Options struct {
	Clock         Clock
	NewLeaseToken LeaseTokenSource
	// RetryDelay is the agentd-owned exponential backoff base. Connectors
	// classify a failure but cannot choose when a delivery becomes claimable.
	RetryDelay time.Duration
	Admission  AdmissionOptions
}

// AdmissionOptions are mandatory operator-selected bounds. Corestore has no
// production defaults because replay guarantees and storage capacity must be
// chosen from deployment evidence, not hidden library guesses.
type AdmissionOptions struct {
	AcceptWindow                      time.Duration
	ReceiptWindow                     time.Duration
	FutureSkew                        time.Duration
	MaxReceiptsPerConnector           int64
	MaxQueuedRunsPerConnector         int64
	MaxNonTerminalRunsPerConnector    int64
	MaxPendingDeliveriesPerConnector  int64
	MaxRetainedInputBytesPerConnector int64
	MaxDatabasePages                  int64
}

func defaultClock() time.Time { return time.Now().UTC() }

func defaultLeaseToken() (string, error) {
	return secureid.NewLeaseToken()
}

type PayloadHash [32]byte

type RunState string

const (
	RunQueued      RunState = "queued"
	RunDispatching RunState = "dispatching"
	RunRunning     RunState = "running"
	RunCompleted   RunState = "completed"
	RunFailed      RunState = "failed"
	RunCancelled   RunState = "cancelled"
	RunInterrupted RunState = "interrupted"
)

type RunFailureCode string

const (
	RunFailureTargetUnavailable  RunFailureCode = "target_unavailable"
	RunFailureRevisionMismatch   RunFailureCode = "revision_mismatch"
	RunFailureInvalidSession     RunFailureCode = "invalid_session"
	RunFailurePolicyDenied       RunFailureCode = "policy_denied"
	RunFailureDeadlineExceeded   RunFailureCode = "deadline_exceeded"
	RunFailureOutputLimit        RunFailureCode = "output_limit_exceeded"
	RunFailureRunnerFailed       RunFailureCode = "runner_failed"
	RunFailureProtocolViolation  RunFailureCode = "protocol_violation"
	RunFailureRuntimeInterrupted RunFailureCode = "runtime_interrupted"
	RunFailureInternal           RunFailureCode = "internal"
)

type IngestTextRunInput struct {
	ConnectorID string
	EventID     string
	PayloadHash PayloadHash
	// LegacyPayloadHash supports exact replay of allow receipts created before
	// the endpoint Connector was folded into the v2 hash. New receipts always
	// persist PayloadHash with version 2.
	LegacyPayloadHash PayloadHash
	ActorRef          string
	ConversationRef   string
	MessageRef        string
	OccurredAtUnixMS  int64
	Text              string
}

// TextRunAuthorization is evaluated only after replay lookup. This makes the
// current policy irrelevant to an exact retained replay.
type TextRunAuthorization struct {
	TargetID           string
	TargetRevision     string
	BindingFingerprint string
	PolicyRevision     string
}

type TextRunAuthorizer func() (TextRunAuthorization, error)
type RunIDSource func() (string, error)

type IngestResult struct {
	Run       Run
	Duplicate bool
}

type Run struct {
	ID                   string
	ConnectorID          string
	EventID              string
	ActorRef             string
	ConversationRef      string
	MessageRef           string
	TargetID             string
	TargetRevision       string
	BindingFingerprint   string
	PolicyRevision       string
	InputText            string
	State                RunState
	DispatchToken        string
	DispatchExpiresAt    time.Time
	DispatchAttemptCount int
	StartPrepared        bool
	StartSessionRef      *string
	StartDeadline        time.Time
	OutputText           *string
	FailureCode          *RunFailureCode
	ResultSessionRef     *string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type FinishRunInput struct {
	RunID            string
	DispatchToken    string
	State            RunState
	OutputText       string
	FailureCode      RunFailureCode
	ResultSessionRef string
}

type PrepareRunStartInput struct {
	RunID         string
	DispatchToken string
	SessionRef    *string
	Deadline      time.Time
}

// PreparedRunStart is the immutable part of StartRun that is not already on
// Run. Callers must build the sandbox request from this returned value rather
// than from their proposal, because Deadline is normalized to milliseconds.
type PreparedRunStart struct {
	SessionRef *string
	Deadline   time.Time
}

type SessionKey struct {
	BindingFingerprint string
	ConnectorID        string
	ActorRef           string
	ConversationRef    string
	TargetID           string
	TargetRevision     string
}

type Session struct {
	SessionKey
	Ref       string
	UpdatedAt time.Time
}

type TextDeliveryInput struct {
	ID   string
	Text string
}

type DeliveryState string

const (
	DeliveryPending         DeliveryState = "pending"
	DeliveryLeased          DeliveryState = "leased"
	DeliveryDelivered       DeliveryState = "delivered"
	DeliveryPermanentFailed DeliveryState = "permanent_failed"
)

type DeliveryFailureCode string

const (
	DeliveryFailureTemporary            DeliveryFailureCode = "temporary_failure"
	DeliveryFailureRateLimited          DeliveryFailureCode = "rate_limited"
	DeliveryFailureRecipientUnavailable DeliveryFailureCode = "recipient_unavailable"
	DeliveryFailureContentRejected      DeliveryFailureCode = "content_rejected"
	DeliveryFailureNotAuthorized        DeliveryFailureCode = "not_authorized"
	DeliveryFailureConnectorInternal    DeliveryFailureCode = "connector_internal"
)

type TextDelivery struct {
	ID                 string
	RunID              string
	ConnectorID        string
	ConversationRef    string
	ReplyToRef         string
	Text               string
	State              DeliveryState
	LeaseToken         string
	LeaseExpiresAt     time.Time
	AttemptCount       int
	AvailableAt        time.Time
	ProviderMessageRef string
	FailureCode        DeliveryFailureCode
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type DeliveryOutcome string

const (
	DeliveryOutcomeDelivered        DeliveryOutcome = "delivered"
	DeliveryOutcomeRetry            DeliveryOutcome = "retry"
	DeliveryOutcomePermanentFailure DeliveryOutcome = "permanent_failure"
)

type CompleteDeliveryInput struct {
	ConnectorID        string
	DeliveryID         string
	LeaseToken         string
	Outcome            DeliveryOutcome
	ProviderMessageRef string
	FailureCode        DeliveryFailureCode
}

// Store's public operation set is intentionally explicit. This compile-time
// assertion also documents which methods are safe for agentd to compose.
type Operations interface {
	IngestTextRun(context.Context, IngestTextRunInput, TextRunAuthorizer, RunIDSource) (IngestResult, error)
	GetRun(context.Context, string) (Run, error)
	ListRunningRuns(context.Context, int) ([]Run, error)
	ClaimQueuedRun(context.Context, time.Duration) (Run, bool, error)
	PrepareRunStart(context.Context, PrepareRunStartInput) (PreparedRunStart, error)
	MarkRunRunning(context.Context, string, string) error
	FinishRun(context.Context, FinishRunInput, *TextDeliveryInput) error
	GetSession(context.Context, SessionKey) (Session, bool, error)
	ClaimTextDeliveries(context.Context, string, int, time.Duration) ([]TextDelivery, error)
	CompleteDelivery(context.Context, CompleteDeliveryInput) error
}
