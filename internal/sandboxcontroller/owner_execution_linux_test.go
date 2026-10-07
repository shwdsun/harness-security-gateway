//go:build linux

package sandboxcontroller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

type ownerExecutionHandle struct {
	*fakeCredentialHandle
	borrowed atomic.Int32
	cap      *credentialsource.OwnerAccess // Unusable physical capability; lifecycle seam only.
}

func (h *ownerExecutionHandle) BorrowForOwner(string, string, credentialsource.Binding, string, credentialsource.Proof) (*credentialsource.OwnerAccess, error) {
	h.borrowed.Add(1)
	return h.cap, h.Validate()
}
func (*ownerExecutionHandle) Handoff(string, string, credentialsource.Binding, string, credentialsource.Proof) (*credentialsource.Handoff, error) {
	return nil, errors.New("owner path must never mount original source")
}

type ownerExecutionRuntime struct {
	*fakeRuntime
	createOwner func(context.Context, string, targetmanifest.Definition, *credentialsource.OwnerAccess) (string, error)
	cleanup     func(context.Context, string) error
}

func (r *ownerExecutionRuntime) CreateWithOwner(ctx context.Context, id string, m targetmanifest.Definition, o *credentialsource.OwnerAccess) (string, error) {
	return r.createOwner(ctx, id, m, o)
}
func (r *ownerExecutionRuntime) CloseRunResources(ctx context.Context, id string) error {
	return r.cleanup(ctx, id)
}

func TestOwnerExecutionRetainsOriginalHealthAcrossJoinedResourceRemoval(t *testing.T) {
	for _, fault := range []string{"healthy", "taint", "join", "revoke", "lost-revoke-response"} {
		t.Run(fault, func(t *testing.T) {
			f := newCredentialExecutionFixtureFor(t, true, true)
			h := &ownerExecutionHandle{fakeCredentialHandle: &fakeCredentialHandle{source: f.gen.SourceDigest, proof: f.proof}, cap: &credentialsource.OwnerAccess{}}
			r := &ownerExecutionRuntime{fakeRuntime: newFakeRuntime()}
			store := &credentialFaultStore{Store: f.deps.store}
			var joined, retired atomic.Bool
			var cleanups, revokes atomic.Int32
			r.createOwner = func(ctx context.Context, id string, m targetmanifest.Definition, cap *credentialsource.OwnerAccess) (string, error) {
				run, err := store.GetRun(ctx, id)
				if err != nil || cap != h.cap || h.borrowed.Load() != 1 || !run.RuntimeIntentPending || !run.CredentialLeaseHeld {
					return "", errors.New("owner Create preceded admission/proof/intent")
				}
				return r.fakeRuntime.Create(ctx, id, m)
			}
			r.cleanup = func(ctx context.Context, id string) error {
				if _, err := r.Inspect(ctx, fakeContainerRef(id)); !errors.Is(err, dockerruntime.ErrNotFound) {
					return errors.New("finalization preceded container absence")
				}
				if fault != "healthy" {
					h.changed.Store(true)
				}
				if cleanups.Add(1) == 1 && fault == "join" {
					return errors.New("synthetic unjoined helper")
				}
				joined.Store(true)
				return nil
			}
			store.revoke = func(ctx context.Context, id string) error {
				if !joined.Load() || h.closed.Load() {
					return errors.New("retirement outside joined/held phase")
				}
				first := revokes.Add(1) == 1
				if first && fault == "revoke" {
					return errors.New("synthetic revoke failure")
				}
				if err := store.Store.RevokeRunCredential(ctx, id); err != nil {
					return err
				}
				retired.Store(true)
				if first && fault == "lost-revoke-response" {
					return errors.New("synthetic lost revoke response")
				}
				return nil
			}
			h.onClose = func() error {
				if !joined.Load() || (fault != "healthy" && !retired.Load()) {
					return errors.New("held source released before joins/retirement")
				}
				return nil
			}
			c := f.controller(t, store, r, func(string, string) (credentialHandle, error) { return h, nil })
			f.admit(t)
			if err := c.Offer(context.Background(), f.request); err != nil {
				t.Fatal(err)
			}
			run := awaitTerminal(t, f.deps.store, f.request.RunID)
			if run.CredentialLeaseHeld || c.hasRetainedCredentials() || h.closes.Load() != 1 || runtimeCreateCount(r.fakeRuntime, run.RunID) != 1 {
				t.Fatal("owner cleanup/retry released or repeated authority")
			}
			f.request.RunID = "successor"
			_, _, err := store.RegisterStart(context.Background(), f.request, f.request.ExpectedRevision, f.gen.WorkspaceRef, false, sandboxstore.SessionPolicy{Mode: targetmanifest.SessionNewOnly})
			if (err != nil) != (fault != "healthy") {
				t.Fatal("resource deletion erased taint or retired healthy source", err)
			}
		})
	}
}
