package codexprovider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	rejectedPrefixBytes   = 512
	rejectedPrefixTimeout = time.Second
)

// Only closed classifications survive the upstream parser. These fields never
// select policy, route, authority or whether a response may reach the client.
type wireMetadata struct {
	protocol, contentType, framing, length string
}

func responseMetadata(r *http.Response) wireMetadata {
	m := wireMetadata{protocol: "other", contentType: "absent", framing: "unknown", length: "unknown"}
	if r.ProtoMajor == 1 && r.ProtoMinor == 1 {
		m.protocol = "http_1_1"
	} else if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		m.protocol = "http_1_0"
	}
	values := r.Header.Values("Content-Type")
	if len(values) > 0 {
		m.contentType = "single"
		if values[0] == "" {
			m.contentType = "empty"
		}
		if len(values) > 1 {
			m.contentType = "multiple"
			if values[0] == "" {
				m.contentType = "multiple_first_empty"
			}
		}
	}
	if len(r.TransferEncoding) == 1 && r.TransferEncoding[0] == "chunked" {
		m.framing = "chunked"
	} else if r.ContentLength >= 0 {
		m.framing = "fixed"
	} else if r.Close {
		m.framing = "close_delimited"
	}
	if r.ContentLength == 0 {
		m.length = "zero"
	} else if r.ContentLength > 0 {
		m.length = "positive"
	}
	return m
}

// Called only after an HTTP-200 MIME rejection has been latched. It uses the
// same owned socket/worker, no retry or extra I/O authority. Skip arbitrary test
// responders: only the fixed transport supplies a deadline-enforcing socket.
func (d *ExchangeDiagnostic) observeRejectedBody(ctx context.Context, response io.ReadCloser) {
	b, ok := response.(*upstreamBody)
	if !ok || b.body == nil {
		return
	}
	if ctx.Err() != nil {
		d.BodyProbeEnd = "cancelled"
		return
	}
	if b.conn.SetReadDeadline(deadline(ctx, rejectedPrefixTimeout)) != nil {
		d.BodyProbeEnd = "read_error"
		return
	}
	var prefix [rejectedPrefixBytes]byte
	// Read the decoded body directly: upstreamBody.Read would reset the deadline
	// on each read and defeat this diagnostic's absolute one-second limit.
	n, empty := 0, 0
	var err error
	for n < len(prefix) {
		var read int
		read, err = b.body.Read(prefix[n:])
		n += read
		if err != nil {
			break
		}
		if read == 0 {
			empty++
			if empty == 3 {
				err = io.ErrNoProgress
				break
			}
		} else {
			empty = 0
		}
	}
	d.BodyProbeEnd = "read_error"
	var netErr net.Error
	switch {
	case ctx.Err() != nil:
		d.BodyProbeEnd = "cancelled"
	case err == io.EOF:
		d.BodyProbeEnd = "eof"
	case err == nil && n == len(prefix):
		d.BodyProbeEnd = "limit"
	case errors.As(err, &netErr) && netErr.Timeout():
		d.BodyProbeEnd = "timeout"
	}
	if n > 0 {
		d.BodyPrefix = classifyBodyPrefix(prefix[:n])
	} else if d.BodyProbeEnd == "eof" {
		d.BodyPrefix = "empty"
	}
}

// A bounded prefix hint, not MIME detection or a parser for provider payloads.
// In particular json_like/event_stream_like never authorize body forwarding.
func classifyBodyPrefix(prefix []byte) string {
	prefix = bytes.TrimPrefix(prefix, []byte{0xef, 0xbb, 0xbf})
	prefix = bytes.TrimLeft(prefix, " \t\r\n")
	if len(prefix) == 0 {
		return "whitespace"
	}
	if prefix[0] == '{' || prefix[0] == '[' {
		return "json_like"
	}
	for _, field := range []string{"data:", "event:", "id:", "retry:", ":"} {
		if bytes.HasPrefix(prefix, []byte(field)) {
			return "event_stream_like"
		}
	}
	lower := bytes.ToLower(prefix)
	if bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html")) {
		return "html_like"
	}
	return "other"
}
