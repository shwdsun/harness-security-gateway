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
// UpstreamAuthorized records local dispatch permission, not successful I/O.
// For operation_rejected, Reason identifies the earlier latched rejection;
// upstream status/media are absent because no new upstream response was observed.
type ExchangeDiagnostic struct {
	Operation          string `json:"operation"`
	Stage              string `json:"stage"`
	Reason             string `json:"reason,omitempty"`
	MediaClass         string `json:"media_class,omitempty"`
	UpstreamAuthorized bool   `json:"upstream_authorized,omitempty"`
	UpstreamStatus     int    `json:"upstream_status,omitempty"`
	ResponseProtocol   string `json:"response_protocol,omitempty"`
	ContentTypeState   string `json:"content_type_state,omitempty"`
	ResponseFraming    string `json:"response_framing,omitempty"`
	DeclaredBody       string `json:"declared_body,omitempty"`
	BodyPrefix         string `json:"body_prefix,omitempty"`
	BodyProbeEnd       string `json:"body_probe_end,omitempty"`
	Finished           bool   `json:"finished"`
	Cancelled          bool   `json:"cancelled"`
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

func diagnosticRejection(reason responseRejection) string {
	switch reason {
	case rejectionUpgrade:
		return "protocol_upgrade"
	case rejectionContentEncoding:
		return "content_encoding"
	case rejectionLocation:
		return "location"
	case rejectionTrailer:
		return "trailer"
	case rejectionContentTypeMissing:
		return "content_type_missing"
	case rejectionContentTypeInvalid:
		return "content_type_invalid"
	case rejectionMediaType:
		return "media_type_mismatch"
	default:
		return ""
	}
}

// Never retain the original MIME string or parameters in diagnostics.
func diagnosticMedia(media string) string {
	switch media {
	case "application/json":
		return "json"
	case "text/event-stream":
		return "event_stream"
	case "text/html":
		return "html"
	default:
		return "other"
	}
}
