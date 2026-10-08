//go:build linux && amd64 && codexintegration

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxcontroller"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// Every other Runtime method intentionally remains nil: this test exercises
// ordinary idle startup and never-dispatched recovery, not container execution.
type idleRuntime struct{ sandboxcontroller.Runtime }

func (idleRuntime) LookupIntent(context.Context, string, targetmanifest.Definition) (string, bool, error) {
	return "", false, nil
}

func (idleRuntime) ListManaged(context.Context) ([]string, error)   { return []string{}, nil }
func (idleRuntime) CloseRunResources(context.Context, string) error { return nil }

func TestCodexStartupUsesEnrolledScopeAndExistingRestartRules(t *testing.T) {
	ctx := context.Background()
	c := startupCodexConfig(t)
	db := enrollmentDB(t, c)
	registry, err := c.Registry()
	if err != nil {
		t.Fatal(err)
	}
	setup := codexExecution(c, nil, strings.Repeat("a", 64)) // Synthetic resolved artifact pin.
	register := func() (*sandboxservice.Service, error) {
		return sandboxservice.New(ctx, registry, db, nil, sandboxservice.WithAuthorityResolver(setup.authority))
	}
	if _, err := register(); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatal("startup implicitly enrolled missing proof", err)
	}
	f := &enrollmentFixture{source: strings.Repeat("a", 64)}
	b := c.Codex.Credential
	if err := enrollSource(ctx, db, b, c.Codex.Scope.SessionScope(), func(context.Context) (bool, error) { return true, nil }, func(string, string) (enrollmentSource, error) { return f, nil }); err != nil {
		t.Fatal(err)
	}
	service, err := register()
	if err != nil {
		t.Fatal(err)
	}
	startController := func() *sandboxcontroller.Controller {
		controller, err := sandboxcontroller.New(ctx, service, registry, db, idleRuntime{}, sandboxcontroller.WithCredentialBindings(setup.bindings))
		if err != nil {
			t.Fatal(err)
		}
		return controller
	}
	controller := startController()
	if err := controller.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sandboxstore.Open(ctx, c.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service, err = register()
	if err != nil {
		t.Fatal("idle restart required another enrollment", err)
	}
	controller = startController()
	digest, _ := sessionauth.Digest(c.Codex.Scope.SessionScope())
	request := executionwire.StartRunRequest{RunID: "configured-run", TargetID: c.Targets[0].ID(), ExpectedRevision: c.Targets[0].Revision(), SessionScopeDigest: digest,
		Input: executionwire.TextInput{MediaType: executionwire.MediaTypeTextPlain, Text: "synthetic input"}, Deadline: time.Now().UTC().Add(time.Minute)}
	wrong := request
	wrong.RunID = "wrong-scope"
	wrong.SessionScopeDigest = strings.Repeat("f", 64)
	if _, err := service.StartRun(ctx, wrong); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatal("wrong disclosure scope admitted", err)
	}
	if _, err := service.StartRun(ctx, request); err != nil {
		t.Fatal("idle restart retired the valid generation", err)
	}
	// A retained accepted Run must block enrollment before physical observation.
	if err := enrollSource(ctx, db, b, c.Codex.Scope.SessionScope(), func(context.Context) (bool, error) { t.Fatal("inventory reached with pending Run"); return true, nil }, func(string, string) (enrollmentSource, error) {
		t.Fatal("source opened with pending Run")
		return nil, nil
	}); err == nil {
		t.Fatal("pending Run did not block enrollment")
	}
	if err := controller.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sandboxstore.Open(ctx, c.StateDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service, err = register()
	if err != nil {
		t.Fatal(err)
	}
	controller = startController()
	defer controller.Close(ctx)
	retained, err := db.GetRun(ctx, request.RunID)
	if err != nil || retained.CredentialLeaseHeld || retained.RuntimeRef != nil || retained.RuntimeIntentPending || retained.State == executionwire.RunStateAccepted {
		t.Fatalf("restart did not finish never-dispatched cleanup: %+v %v", retained, err)
	}
	request.RunID = "after-interruption"
	if _, err := service.StartRun(ctx, request); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatal("interrupted enrollment revived", err)
	}
	if !f.closed {
		t.Fatal("explicit enrollment handle remained open")
	}
}

func TestCodexStartupFreezesAuthorityAndRejectsRevisionReuse(t *testing.T) {
	ctx := context.Background()
	c := startupCodexConfig(t)
	db := enrollmentDB(t, c)
	registry, _ := c.Registry()
	manifest := c.Targets[0].Clone()
	fp, _ := manifest.Fingerprint()
	setup := codexExecution(c, nil, strings.Repeat("a", 64))
	b := c.Codex.Credential
	scope := c.Codex.Scope.SessionScope()
	f := &enrollmentFixture{source: strings.Repeat("a", 64)}
	if err := enrollSource(ctx, db, b, scope, func(context.Context) (bool, error) { return true, nil }, func(string, string) (enrollmentSource, error) { return f, nil }); err != nil {
		t.Fatal(err)
	}
	register := func(s executionSetup) error {
		_, err := sandboxservice.New(ctx, registry, db, nil, sandboxservice.WithAuthorityResolver(s.authority))
		return err
	}
	if err := register(setup); err != nil {
		t.Fatal(err)
	}
	if err := register(codexExecution(c, nil, strings.Repeat("e", 64))); !errors.Is(err, sandboxstore.ErrConflict) {
		t.Fatal("changed runtime reused existing revision", err)
	}
	c.Codex.Scope.ActorRef = "unapproved"
	if err := register(codexExecution(c, nil, strings.Repeat("a", 64))); !errors.Is(err, sandboxstore.ErrCredentialAuthority) {
		t.Fatal("enrollment supplied expected scope", err)
	}
	c.Codex.Credential.Generation = 999
	authority, err := setup.authority(manifest, fp)
	if err != nil || authority.Credential.Ref.Generation != int64(b.Generation) || authority.Credential.Scope != scope {
		t.Fatal("caller mutation widened frozen authority", err)
	}
	// Fingerprint alone excludes revision. The resolver must check both.
	changed := manifest.Clone()
	data, _ := changed.ManifestV2()
	data.Revision = "different"
	changed, err = targetmanifest.FromV2(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.authority(changed, fp); err == nil {
		t.Fatal("manifest fingerprint bypassed revision")
	}
}
