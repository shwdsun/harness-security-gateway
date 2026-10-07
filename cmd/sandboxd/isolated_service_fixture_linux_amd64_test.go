//go:build linux && amd64 && codexintegration

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/privatefs"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxcontroller"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
)

// A concrete fixture for the remaining composed cases. Keep the executed Ready
// witness unchanged; use the same production setup, ownership and close order.
// This helper introduces neither a public runtime hook nor a generic harness.
type isolatedServiceFixture struct {
	ctx                                                        context.Context
	config                                                     sandboxconfig.Config
	setup                                                      executionSetup
	lock                                                       *processlock.Lock
	db                                                         *sandboxstore.Store
	adapter                                                    *sandboxcontroller.DockerRuntime
	durable                                                    *sandboxservice.Service
	controller                                                 *sandboxcontroller.Controller
	closed                                                     bool
	controllerClosed, storeClosed, artifactsClosed, lockClosed bool
}

var isolatedServiceFailedFixture *isolatedServiceFixture

func newIsolatedServiceFixture(t *testing.T, ctx context.Context, configPath, root string, before []byte) *isolatedServiceFixture {
	t.Helper()
	f := &isolatedServiceFixture{ctx: ctx}
	t.Cleanup(func() { f.close(t) })
	if isolatedReadyFailedOwner.lock != nil || isolatedServiceFailedFixture != nil {
		t.Fatal("failed owner retained; stop the entire fixture service")
	}
	config, err := sandboxconfig.Load(configPath)
	if err != nil || config.Schema != sandboxconfig.SchemaCodexV2 || config.Codex == nil ||
		config.Runtime.Endpoint != "unix:///run/user/1001/docker.sock" || config.Runtime.CLI != "/opt/hgw-v4-acceptance/docker/bin/docker" {
		t.Fatal("frozen composed configuration rejected")
	}
	for _, path := range []string{config.Socket, config.StateDatabase, config.WorkspaceRoot, config.RunnerStateRoot, config.Codex.ProviderRoot, config.Codex.Credential.Root} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !bytes.HasPrefix([]byte(path), []byte(root+"/")) {
			t.Fatal("mutable fixture path escaped its fixed root")
		}
	}
	f.config = config
	if _, err := os.Lstat(config.StateDatabase); !os.IsNotExist(err) {
		t.Fatal("fresh composed store required")
	}
	f.setup, err = prepareExecution(config)
	if err != nil || f.setup.startup == nil || f.setup.close == nil {
		t.Fatal("actual isolated construction rejected")
	}
	if privatefs.EnsureParent(config.ProcessLockPath(), 0700) != nil {
		t.Fatal("global lock parent unavailable")
	}
	f.lock, err = processlock.Acquire(config.ProcessLockPath())
	if err != nil {
		t.Fatal("global ownership unavailable")
	}
	if second, err := processlock.Acquire(config.ProcessLockPath()); !errors.Is(err, processlock.ErrLocked) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("global ownership is not exclusive")
	}
	if f.setup.startup() != nil {
		t.Fatal("actual startup gate rejected")
	}
	if _, err := os.Lstat(config.StateDatabase); !os.IsNotExist(err) {
		t.Fatal("store existed before startup")
	}
	if prepareFilesystem(config) != nil {
		t.Fatal("private filesystem preparation failed")
	}
	native, err := f.setup.runtime()
	if err != nil {
		t.Fatal("actual runtime unavailable")
	}
	f.adapter, err = sandboxcontroller.NewDockerRuntime(native)
	if err != nil {
		t.Fatal("actual runtime adapter unavailable")
	}
	binding := config.Codex.Credential
	if binding.Generation != 1 {
		t.Fatal("fixed synthetic generation required")
	}
	source, err := os.ReadFile(filepath.Join(binding.Root, binding.Directory, "auth.json"))
	defer clear(source)
	if err != nil || !bytes.Equal(source, before) {
		t.Fatal("source is not the frozen invalid synthetic credential")
	}
	f.db, err = sandboxstore.Open(ctx, config.StateDatabase)
	if err != nil {
		t.Fatal("store unavailable")
	}
	if err := enrollSource(ctx, f.db, binding, config.Codex.Scope.SessionScope(), func(ctx context.Context) (bool, error) {
		refs, err := native.ListManaged(ctx)
		return len(refs) == 0, err
	}, holdEnrollmentSource); err != nil {
		t.Fatal("actual source enrollment failed")
	}
	registry, err := config.Registry()
	if err != nil {
		t.Fatal("fixed registry unavailable")
	}
	f.durable, err = sandboxservice.New(ctx, registry, f.db, nil, sandboxservice.WithAuthorityResolver(f.setup.authority))
	if err != nil {
		t.Fatal("actual fixed revision authority unavailable")
	}
	return f
}

func (f *isolatedServiceFixture) close(t *testing.T) {
	t.Helper()
	if f.closed {
		return
	}
	f.closed = true
	if f.controller != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		err := f.controller.Close(ctx)
		cancel()
		f.controllerClosed = err == nil
		if err != nil {
			t.Error("controller join failed")
		}
	} else {
		f.controllerClosed = true
	}
	if f.db != nil && f.controllerClosed {
		f.storeClosed = f.db.Close() == nil
		if !f.storeClosed {
			t.Error("store close failed")
		}
	} else if f.db == nil {
		f.storeClosed = true
	}
	if f.setup.close != nil {
		f.artifactsClosed = f.setup.close() == nil
		if !f.artifactsClosed {
			t.Error("owner artifacts still borrowed")
		}
	} else {
		f.artifactsClosed = true
	}
	if f.lock != nil {
		if f.controllerClosed && f.storeClosed && f.artifactsClosed {
			f.lockClosed = f.lock.Close() == nil
			if !f.lockClosed {
				t.Error("global ownership close failed")
			}
		} else {
			// Retain the actual handles, including file finalizers, until the
			// whole owned service cgroup is stopped. Never create a takeover.
			isolatedReadyFailedOwner.lock, isolatedReadyFailedOwner.store, isolatedReadyFailedOwner.controller = f.lock, f.db, f.controller
		}
	} else {
		f.lockClosed = true
	}
	if !f.controllerClosed || !f.storeClosed || !f.artifactsClosed || !f.lockClosed {
		isolatedServiceFailedFixture = f
	}
}
