//go:build linux

package bootstrapgate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReleaseVerifiesBeforePermitAndPreservesHRP(t *testing.T) {
	input := new(bytes.Buffer)
	output := strings.NewReader(Ready + "later HRP bytes")
	verified := false
	err := Release(context.Background(), input, output, func(context.Context) error {
		if input.Len() != 0 {
			t.Fatal("permit preceded verification")
		}
		verified = true
		return nil
	}, func() { t.Error("successful launch interrupted") })
	remaining, _ := io.ReadAll(output)
	if err != nil || !verified || input.String() != Permit || string(remaining) != "later HRP bytes" {
		t.Fatal("private phase consumed HRP or omitted verification")
	}
}

func TestReleaseRejectsBadReadinessAndVerificationFailure(t *testing.T) {
	for _, ready := range []string{"", "hsg-bootstrap/v1 ready", "hsg-bootstrap/v2 ready\n", Ready} {
		input := new(bytes.Buffer)
		calls := 0
		err := Release(context.Background(), input, strings.NewReader(ready), func(context.Context) error {
			calls++
			return errors.New("receiver mismatch")
		}, func() {})
		if err == nil || input.Len() != 0 || (ready != Ready && calls != 0) {
			t.Fatal("unverified permit")
		}
	}
}

func TestReleaseCancellationInterruptsOwnedReadWithoutPermit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	input := new(bytes.Buffer)
	started := make(chan struct{})
	done := make(chan error, 1)
	var aborts atomic.Int32
	go func() {
		close(started)
		done <- Release(ctx, input, reader, func(context.Context) error { return nil }, func() { aborts.Add(1); _ = reader.Close() })
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil || input.Len() != 0 {
			t.Fatal("cancelled readiness granted permit")
		}
	case <-time.After(time.Second):
		t.Fatal("owned read survived cancellation")
	}
}

func TestReleaseCancellationDuringVerificationDeniesPermit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := new(bytes.Buffer)
	err := Release(ctx, input, strings.NewReader(Ready), func(context.Context) error { cancel(); return nil }, func() {})
	if err == nil || input.Len() != 0 {
		t.Fatal("cancelled verification granted permit")
	}
}

func TestReleaseDoesNotRetryPartialPermit(t *testing.T) {
	writer := &partialPermitWriter{}
	err := Release(context.Background(), writer, strings.NewReader(Ready), func(context.Context) error { return nil }, func() {})
	if err == nil || writer.calls != 1 || writer.bytes != 3 {
		t.Fatal("partial permit was accepted or retried")
	}
}

type partialPermitWriter struct{ calls, bytes int }

func (w *partialPermitWriter) Write(p []byte) (int, error) {
	w.calls++
	w.bytes += 3
	return 3, io.ErrClosedPipe
}

func TestReleaseCancellationInterruptsPermitWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	verified := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Release(ctx, writer, strings.NewReader(Ready), func(context.Context) error { close(verified); return nil }, func() { _ = writer.Close() })
	}()
	<-verified
	// One received byte proves the write was dispatched before cancellation.
	if _, err := io.ReadFull(reader, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled partial write reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("permit write survived cancellation")
	}
}
