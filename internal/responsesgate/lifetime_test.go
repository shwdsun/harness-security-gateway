package responsesgate

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type observedBody struct {
	io.ReadCloser
	once   sync.Once
	closed chan struct{}
}

func (b *observedBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { close(b.closed) })
	return err
}

type joiningBody struct {
	io.ReadCloser
	done <-chan struct{}
}

func (b joiningBody) Close() error {
	<-b.done
	return b.ReadCloser.Close()
}

func TestNormalCompletionCancelsAndJoinsProducer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		joined := make(chan struct{})
		f := newFixture(t, func(ctx context.Context, _ Request) (Response, error) {
			go func() { <-ctx.Done(); close(joined) }()
			r := sseResponse(testSSE)
			r.Body = joiningBody{ReadCloser: r.Body, done: joined}
			return r, nil
		})
		f.open(t)
		start := time.Now()
		got := f.exchange(f.request(testBody))
		if got.err != nil || got.status != 200 || got.body != testSSE {
			t.Fatal("normal completion failed")
		}
		<-joined
		if time.Since(start) >= IdleTimeout {
			t.Fatal("normal cleanup depended on the idle timeout")
		}
	})
}

func TestConstructionRequiresOwnedDeadline(t *testing.T) {
	fn := func(context.Context, Request) (Response, error) { return sseResponse(testSSE), nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, test := range []struct {
		ctx  context.Context
		host string
		fn   Responder
	}{
		{nil, "fixture", fn}, {context.Background(), "fixture", fn},
		{ctx, "http://fixture", fn}, {ctx, "fixture\r\nInjected: yes", fn}, {ctx, "fixture", nil},
	} {
		if _, err := NewSynthetic(test.ctx, test.host, test.fn); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid construction accepted")
		}
	}
	cancel()
	if _, err := NewSynthetic(ctx, "fixture", fn); !errors.Is(err, ErrConfiguration) {
		t.Fatal("expired owner accepted")
	}
}

func TestStopRetainsCleanupObligationUntilResponderReturns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		body := &observedBody{ReadCloser: io.NopCloser(strings.NewReader(testSSE)), closed: make(chan struct{})}
		f := newFixture(t, func(ctx context.Context, _ Request) (Response, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			<-release // Deliberately delay cooperative cleanup after cancellation.
			r := sseResponse("")
			r.Body = body
			return r, nil
		})
		f.open(t)
		clientDone := make(chan exchange, 1)
		go func() { clientDone <- f.exchange(f.request(testBody)) }()
		<-started
		f.gate.Stop()
		<-cancelled
		synctest.Wait()
		select {
		case <-f.served:
			t.Fatal("cleanup reported before responder returned")
		default:
		}
		close(release)
		<-f.served
		<-body.closed
		got := <-clientDone
		if got.status == 200 && got.err == nil {
			t.Fatal("cancelled exchange looked complete")
		}
	})
}

func TestHeaderBodyAndResponderIdleDeadlines(t *testing.T) {
	for _, mode := range []string{"header", "body", "responder", "stream"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				closed := make(chan struct{})
				f := newFixture(t, func(ctx context.Context, _ Request) (Response, error) {
					calls.Add(1)
					if mode == "responder" {
						<-ctx.Done()
						close(closed)
						return Response{}, ctx.Err()
					}
					if mode == "stream" {
						reader, writer := io.Pipe()
						go func() { <-ctx.Done(); _ = writer.Close() }()
						r := sseResponse("")
						r.Body = &observedBody{ReadCloser: reader, closed: closed}
						return r, nil
					}
					return sseResponse(testSSE), nil
				})
				f.open(t)
				if mode == "header" || mode == "body" {
					conn, err := f.listener.dial()
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					prefix := "POST /v1/responses HTTP/1.1\r\n"
					wait := HeaderTimeout
					if mode == "body" {
						raw := f.request(testBody)
						prefix, wait = raw[:len(raw)-len(testBody)+1], IdleTimeout
					}
					if _, err := io.WriteString(conn, prefix); err != nil {
						t.Fatal(err)
					}
					time.Sleep(wait + time.Millisecond)
					synctest.Wait()
					var b [1]byte
					if _, err := conn.Read(b[:]); err == nil {
						t.Fatal("stalled input remained live")
					}
					if calls.Load() != 0 {
						t.Fatal("partial request dispatched")
					}
				} else {
					got := f.exchange(f.request(testBody)) // Fake time advances while I/O blocks.
					<-closed
					if got.status == 200 && got.err == nil {
						t.Fatal("idle source looked complete")
					}
					if calls.Load() != 1 {
						t.Fatal("idle source retried")
					}
				}
			})
		})
	}
}

func TestRunDeadlineAndClientDisconnectCancelActiveWork(t *testing.T) {
	for _, mode := range []string{"run-deadline", "client-disconnect"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started, cancelled := make(chan struct{}), make(chan struct{})
				f := fixtureWithDeadline(t, func(ctx context.Context, _ Request) (Response, error) {
					close(started)
					<-ctx.Done()
					close(cancelled)
					return Response{}, ctx.Err()
				}, time.Second)
				f.open(t)
				conn, err := f.listener.dial()
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err := io.WriteString(conn, f.request(testBody)); err != nil {
					t.Fatal(err)
				}
				<-started
				if mode == "client-disconnect" {
					_ = conn.Close()
				} else {
					time.Sleep(time.Second)
				}
				<-cancelled
				if mode == "client-disconnect" {
					f.gate.Stop()
				}
				<-f.served
				if !errors.Is(f.gate.Open(), ErrClosed) {
					t.Fatal("cancelled Run reopened")
				}
			})
		})
	}
}

type closeFailureBody struct{ io.ReadCloser }

func (b closeFailureBody) Close() error {
	_ = b.ReadCloser.Close()
	return errors.New("private-close-failure")
}

type closeFailureConn struct{ net.Conn }

func (c closeFailureConn) Close() error {
	_ = c.Conn.Close()
	return errors.New("private-close-failure")
}

type closeFailureListener struct {
	*pipeListener
	where string
}

func (l closeFailureListener) Accept() (net.Conn, error) {
	c, err := l.pipeListener.Accept()
	if err == nil && l.where == "connection" {
		return closeFailureConn{c}, nil
	}
	return c, err
}

func (l closeFailureListener) Close() error {
	_ = l.pipeListener.Close()
	if l.where == "listener" {
		return errors.New("private-close-failure")
	}
	return nil
}

func TestCleanupFailureRemainsAnObligation(t *testing.T) {
	for _, where := range []string{"body", "connection", "listener"} {
		t.Run(where, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			g, err := NewSynthetic(ctx, "hsg-fixture.test", func(context.Context, Request) (Response, error) {
				r := sseResponse(testSSE)
				if where == "body" {
					r.Body = closeFailureBody{r.Body}
				}
				return r, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Stop()
			if err := g.Open(); err != nil {
				t.Fatal(err)
			}
			listener := newPipeListener()
			f := &fixture{gate: g, listener: listener}
			done := make(chan error, 1)
			go func() { done <- g.Serve(closeFailureListener{listener, where}) }()
			_ = f.exchange(f.request(testBody))
			g.Stop()
			select {
			case err := <-done:
				if !errors.Is(err, ErrCleanup) || strings.Contains(err.Error(), "private-close-failure") {
					t.Fatalf("cleanup verdict: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cleanup fault was not returned")
			}
			if !errors.Is(g.Open(), ErrClosed) {
				t.Fatal("failed cleanup reactivated")
			}
		})
	}
}
