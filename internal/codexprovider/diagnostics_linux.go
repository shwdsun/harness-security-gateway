package codexprovider

// Diagnostics is bounded, non-authoritative metadata for the local canary.
// It contains no request/response bytes, native output or source error strings.
// Joined describes this endpoint's workers only, not whole-Run cleanup.
type Diagnostics struct {
	Opened        bool                 `json:"opened"`
	Stopped       bool                 `json:"stopped"`
	Joined        bool                 `json:"joined"`
	CleanupFailed bool                 `json:"cleanup_failed"`
	Exchanges     []ExchangeDiagnostic `json:"exchanges"`
}

// Stage is the last attempted stage when Finished is true. An unfinished
// exchange has only an admission observation. HTTP status is upstream metadata,
// not proof of authentication, response completion or model success.
type ExchangeDiagnostic struct {
	Operation      string `json:"operation"`
	Stage          string `json:"stage"`
	UpstreamStatus int    `json:"upstream_status,omitempty"`
	Finished       bool   `json:"finished"`
	Cancelled      bool   `json:"cancelled"`
}

func (e *Endpoint) Diagnostics() Diagnostics {
	e.mu.Lock()
	defer e.mu.Unlock()
	d := Diagnostics{Opened: e.opened, Stopped: e.closed, CleanupFailed: e.cleanupFailed,
		Exchanges: append([]ExchangeDiagnostic{}, e.diagnostics...)}
	select {
	case <-e.done:
		d.Joined = true
	default:
	}
	return d
}

func diagnosticOperation(op Operation) string {
	switch op {
	case Refresh:
		return "refresh"
	case Catalog:
		return "catalog"
	case Inference:
		return "inference"
	case Settings:
		return "settings"
	default:
		return "unknown"
	}
}

func diagnosticStatus(status int) int {
	if status >= 100 && status <= 599 {
		return status
	}
	return 0
}

// Only this package constructs these failures, using literal stages. Preserve
// errors.Is(ErrUpstream) without keeping or formatting an underlying error.
type upstreamFailure struct {
	stage  string
	status int
}

func (upstreamFailure) Error() string { return ErrUpstream.Error() }
func (upstreamFailure) Unwrap() error { return ErrUpstream }
