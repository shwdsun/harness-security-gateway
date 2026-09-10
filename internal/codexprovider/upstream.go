//go:build linux

package codexprovider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"
)

// Response policy is a closed internal result. Diagnostic strings and upstream
// header/body values never select subsequent dispatch authority.
type responseRejection uint8

const (
	rejectionNone responseRejection = iota
	rejectionUpgrade
	rejectionContentEncoding
	rejectionLocation
	rejectionTrailer
	rejectionContentTypeMissing
	rejectionContentTypeInvalid
	rejectionMediaType
)

// Preserve errors.Is(ErrUpstream) without retaining an underlying error or
// rejected response values. Only a typed rejection latches operation admission.
type upstreamFailure struct {
	stage     string
	status    int
	rejection responseRejection
}

func (upstreamFailure) Error() string { return ErrUpstream.Error() }
func (upstreamFailure) Unwrap() error { return ErrUpstream }

// One exact HTTPS exchange. No ambient proxy, redirect, retry, WebSocket,
// cookie jar or generic RoundTripper. Cancellation closes the owned socket.
func liveResponse(ctx context.Context, request Request) (Response, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	return upstreamResponse(ctx, request, dialer.DialContext, nil)
}

// The private dial/root seam is used only by local transport tests. Live
// construction fixes the standard dialer and system certificate roots.
func upstreamResponse(ctx context.Context, request Request, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) (Response, error) {
	method, host, path := route(request.Operation)
	if method == "" {
		return Response{}, ErrDenied
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return Response{}, upstreamFailure{stage: "upstream_dial"}
	}
	secure := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	owned := &upstreamBody{conn: secure}
	owned.stop = context.AfterFunc(ctx, func() { _ = owned.closeSocket() })
	success := false
	defer func() {
		if !success {
			_ = owned.Close()
		}
	}()
	if secure.SetDeadline(deadline(ctx, IdleTimeout)) != nil || secure.HandshakeContext(ctx) != nil {
		return Response{}, upstreamFailure{stage: "upstream_tls"}
	}
	r, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, bytes.NewReader(request.Body))
	if err != nil {
		return Response{}, upstreamFailure{stage: "upstream_request"}
	}
	r.Header = request.Header.Clone()
	r.Close = true
	if r.Write(secure) != nil {
		return Response{}, upstreamFailure{stage: "upstream_write"}
	}
	limited := &io.LimitedReader{R: secure, N: MaxHeaderBytes}
	response, err := http.ReadResponse(bufio.NewReader(limited), r)
	if err != nil {
		return Response{}, upstreamFailure{stage: "upstream_headers"}
	}
	owned.body = response.Body
	owned.metadata = responseMetadata(response)
	// Transfer every parsed response to the endpoint, including rejections.
	// It must latch rejection before diagnostic reads or socket cleanup.
	success = true
	result := Response{Status: response.StatusCode, Body: owned}
	// The application body is independently bounded after decomposing HTTP
	// framing. No decompression is enabled or accepted here.
	limited.N = MaxBodyBytes + MaxHeaderBytes
	// Keep the existing rejection policy and report its first matching predicate.
	failure := upstreamFailure{stage: "upstream_policy", status: diagnosticStatus(response.StatusCode)}
	switch {
	case response.StatusCode == 101:
		failure.rejection = rejectionUpgrade
	case response.Header.Get("Content-Encoding") != "":
		failure.rejection = rejectionContentEncoding
	case response.Header.Get("Location") != "":
		failure.rejection = rejectionLocation
	case len(response.Trailer) != 0:
		failure.rejection = rejectionTrailer
	}
	if failure.rejection != rejectionNone {
		return result, failure
	}
	contentType := response.Header.Get("Content-Type")
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil && response.StatusCode == 200 {
		failure.rejection = rejectionContentTypeInvalid
		if contentType == "" {
			failure.rejection = rejectionContentTypeMissing
		}
		return result, failure
	}
	result.MediaType = media
	return result, nil
}

type upstreamBody struct {
	conn     net.Conn
	body     io.ReadCloser
	once     sync.Once
	stop     func() bool
	err      error
	metadata wireMetadata
}

func (b *upstreamBody) Read(p []byte) (int, error) {
	if b.body == nil {
		return 0, ErrUpstream
	}
	if b.conn.SetReadDeadline(time.Now().Add(IdleTimeout)) != nil {
		return 0, ErrUpstream
	}
	return b.body.Read(p)
}
func (b *upstreamBody) Close() error {
	err := b.closeSocket()
	if b.stop != nil {
		b.stop()
	}
	return err
}
func (b *upstreamBody) closeSocket() error {
	b.once.Do(func() {
		// Close the socket before the HTTP body: its drain must not wait for a
		// remote peer. No transport pool/goroutine survives this per-call owner.
		b.err = b.conn.Close()
		if errors.Is(b.err, net.ErrClosed) {
			b.err = nil
		}
	})
	return b.err
}
