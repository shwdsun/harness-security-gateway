//go:build linux && codexintegration

package codexadapter

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
)

func TestCodexControllerDeadlineRunner(t *testing.T) {
	if os.Getenv("HSG_CODEX_CONTROLLER_DEADLINE_RUNNER") != "1" {
		t.Skip("owned synthetic native-deadline Runner only")
	}
	controllerRunnerNamespace(t)
	stream := &controllerRunnerIO{input: os.Stdin, output: os.Stdout}
	toolsConfigurationConsumerIO(t, codexprofile.CLIBinaryPathV3, "command-deadline", true, stream)
	t.Fatal("native deadline Runner survived outer teardown")
}

// No producer goroutine or unbounded queue: Read itself waits for one fixed
// heartbeat or cancellation; Close interrupts it synchronously. The existing
// Gate still enforces request/stream/idle/byte budgets and owns teardown.
type deadlineHeartbeatBody struct {
	ctx      context.Context
	done     chan struct{}
	once     sync.Once
	pending  []byte
	sequence int
}

func newDeadlineHeartbeatBody(ctx context.Context) *deadlineHeartbeatBody {
	// Comments do not necessarily reset a client's application-event timer.
	// Start one fixed unfinished message; only bounded whitespace deltas follow.
	return &deadlineHeartbeatBody{ctx: ctx, done: make(chan struct{}), sequence: 3, pending: []byte(
		"event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_hsg_deadline_wait\",\"status\":\"in_progress\",\"output\":[]}}\n\n" +
			"event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"sequence_number\":1,\"output_index\":0,\"item\":{\"id\":\"msg_hsg_deadline_wait\",\"type\":\"message\",\"role\":\"assistant\",\"status\":\"in_progress\",\"content\":[]}}\n\n" +
			"event: response.content_part.added\ndata: {\"type\":\"response.content_part.added\",\"sequence_number\":2,\"output_index\":0,\"content_index\":0,\"item_id\":\"msg_hsg_deadline_wait\",\"part\":{\"type\":\"output_text\",\"text\":\"\",\"annotations\":[]}}\n\n")}
}

func (b *deadlineHeartbeatBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(b.pending) == 0 {
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-b.ctx.Done():
			return 0, io.EOF
		case <-b.done:
			return 0, io.EOF
		case <-timer.C:
			b.pending = []byte(fmt.Sprintf("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":%d,\"output_index\":0,\"content_index\":0,\"item_id\":\"msg_hsg_deadline_wait\",\"delta\":\" \"}\n\n", b.sequence))
			b.sequence++
		}
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}

func (b *deadlineHeartbeatBody) Close() error { b.once.Do(func() { close(b.done) }); return nil }

func TestDeadlineHeartbeatClose(t *testing.T) {
	for _, mode := range []string{"close", "context"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := newDeadlineHeartbeatBody(ctx)
			defer body.Close()
			var prefix [4096]byte
			if n, err := body.Read(prefix[:]); err != nil || n == 0 {
				t.Fatal("missing fixed stream prefix", err)
			}
			started, finished := make(chan struct{}), make(chan error, 1)
			go func() {
				close(started)
				var p [64]byte
				n, err := body.Read(p[:])
				if n != 0 {
					finished <- io.ErrUnexpectedEOF
				} else {
					finished <- err
				}
			}()
			<-started
			if mode == "close" {
				_ = body.Close()
				_ = body.Close()
			} else {
				cancel()
			}
			select {
			case err := <-finished:
				if err != io.EOF {
					t.Fatal("interrupted heartbeat read:", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("heartbeat read did not unblock on teardown")
			}
		})
	}
}
