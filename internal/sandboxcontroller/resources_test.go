package sandboxcontroller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

func (r *fakeRuntime) CloseRunResources(context.Context, string) error { return nil }

type heldResourceRuntime struct {
	*fakeRuntime
	blocked, joined atomic.Bool
	joins           atomic.Int32
	beforeCreate    bool
}

func (r *heldResourceRuntime) CloseRunResources(_ context.Context, _ string) error {
	r.joins.Add(1)
	if r.blocked.Load() {
		return errors.New("owned producer has not joined")
	}
	r.joined.Store(true)
	return nil
}
func (r *heldResourceRuntime) CreateWithCredential(ctx context.Context, id string, manifest targetmanifest.Definition, h *credentialsource.Handoff) (string, error) {
	if r.beforeCreate {
		return "", dockerruntime.ErrInvalidArgument
	}
	return r.fakeRuntime.CreateWithCredential(ctx, id, manifest, h)
}

// Container absence and process-resource cleanup are separate observations.
// The same durable candidate and credential occupancy survive either failure.
func TestRunResourceJoinPrecedesCredentialCloseAndPublication(t *testing.T) {
	for _, beforeCreate := range []bool{false, true} {
		name := "removed-container"
		if beforeCreate {
			name = "failed-before-create"
		}
		t.Run(name, func(t *testing.T) {
			f := newCredentialExecutionFixture(t, true)
			r := &heldResourceRuntime{fakeRuntime: newFakeRuntime(), beforeCreate: beforeCreate}
			r.blocked.Store(true)
			h := &fakeCredentialHandle{source: f.gen.SourceDigest, proof: f.proof}
			h.onClose = func() error {
				if !r.joined.Load() {
					return errors.New("credential released before resource join")
				}
				return nil
			}
			c := f.controller(t, f.deps.store, r, func(string, string) (credentialHandle, error) { return h, nil })
			f.admit(t)
			if c.Offer(context.Background(), f.request) != nil {
				t.Fatal("offer")
			}
			run := awaitRun(t, f.deps.store, f.request.RunID, func(run sandboxstore.Run) bool { return run.TerminalPending && r.joins.Load() > 0 })
			if run.Output != nil || run.TerminalAt != nil || !run.CredentialLeaseHeld || h.closes.Load() != 0 {
				t.Fatal("unjoined resource released authority or result")
			}
			if run.RuntimeRef != nil {
				if _, err := r.Inspect(context.Background(), *run.RuntimeRef); !errors.Is(err, dockerruntime.ErrNotFound) {
					t.Fatal("case did not reach container absence")
				}
			}
			r.blocked.Store(false)
			run = awaitTerminal(t, f.deps.store, f.request.RunID)
			if run.CredentialLeaseHeld || run.TerminalPending || h.closes.Load() != 1 || !r.joined.Load() {
				t.Fatal("joined cleanup did not release exactly once")
			}
			want := executionwire.RunStateCompleted
			creates := 1
			if beforeCreate {
				want = executionwire.RunStateFailed
				creates = 0
			}
			if run.State != want || runtimeCreateCount(r.fakeRuntime, f.request.RunID) != creates {
				t.Fatal("cleanup retry changed outcome or recreated runtime")
			}
		})
	}
}
