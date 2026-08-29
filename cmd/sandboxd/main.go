// Command sandboxd is the local execution authority. It owns the immutable
// target registry, runtime-reconciliation store, private runner storage, and
// the one rootless Docker endpoint used for ephemeral harness containers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/privatefs"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxcontroller"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
)

const (
	staleSocketProbe    = 250 * time.Millisecond
	httpShutdownTimeout = 5 * time.Second
	runShutdownTimeout  = 30 * time.Second
)

type options struct {
	configPath string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sandboxd: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	parsed, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	config, err := sandboxconfig.Load(parsed.configPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	return serve(ctx, config)
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("sandboxd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var parsed options
	flags.StringVar(&parsed.configPath, "config", "", "path to sandboxd JSON configuration")
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("positional arguments are not supported")
	}
	if parsed.configPath == "" {
		return options{}, errors.New("-config is required")
	}
	return parsed, nil
}

func serve(parent context.Context, config sandboxconfig.Config) error {
	if parent == nil {
		return errors.New("nil context")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if err := privatefs.EnsureParent(config.ProcessLockPath(), 0o700); err != nil {
		return fmt.Errorf("prepare global sandboxd ownership directory: %w", err)
	}
	owner, err := processlock.Acquire(config.ProcessLockPath())
	if err != nil {
		return fmt.Errorf("acquire sandboxd ownership: %w", err)
	}
	defer owner.Close()
	if err := prepareFilesystem(config); err != nil {
		return err
	}
	// Acquire the transport listener only after the persistent ownership lock and
	// before opening the reconciliation database or inspecting any runtime. The
	// file lock remains held after HTTP shutdown unlinks this socket.
	listener, err := acquireOwnership(config.Socket, config.PeerUID)
	if err != nil {
		return err
	}
	defer listener.Close()

	store, err := sandboxstore.Open(parent, config.StateDatabase)
	if err != nil {
		return fmt.Errorf("open sandbox store: %w", err)
	}
	defer store.Close()

	registry, err := config.Registry()
	if err != nil {
		return fmt.Errorf("build target registry: %w", err)
	}
	durable, err := sandboxservice.New(
		parent,
		registry,
		store,
		config.RunnerStateOwnership,
		sandboxservice.WithRevisionPin(config.RevisionSecurityFingerprint),
	)
	if err != nil {
		return fmt.Errorf("create durable sandbox service: %w", err)
	}
	// New state directories are created only after their durable exact owner is
	// committed. Conversely, an existing path without a matching owner makes
	// the registration above fail closed instead of being adopted from config.
	if err := prepareRunnerStateFilesystem(config); err != nil {
		return err
	}
	lockedRuntime, err := dockerruntime.New(config)
	if err != nil {
		return fmt.Errorf("create Docker runtime: %w", err)
	}
	runtimeAdapter, err := sandboxcontroller.NewDockerRuntime(lockedRuntime)
	if err != nil {
		return fmt.Errorf("adapt Docker runtime: %w", err)
	}
	controller, err := sandboxcontroller.New(parent, durable, registry, store, runtimeAdapter)
	if err != nil {
		return fmt.Errorf("create sandbox controller: %w", err)
	}
	controllerClosed := false
	defer func() {
		if controllerClosed {
			return
		}
		closeCtx, cancel := context.WithTimeout(context.Background(), runShutdownTimeout)
		defer cancel()
		_ = controller.Close(closeCtx)
	}()

	handler, err := executionhttp.NewHandler(controller)
	if err != nil {
		return fmt.Errorf("create execution handler: %w", err)
	}
	server := localhttp.NewServer(handler)

	serveResult := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveResult <- err
	}()

	var result error
	serveFinished := false
	select {
	case <-parent.Done():
	case result = <-serveResult:
		serveFinished = true
		if result == nil {
			result = errors.New("execution listener stopped unexpectedly")
		}
	}

	// Fence new durable Starts before draining HTTP. A handler that already
	// crossed the gate is tracked by Controller.Close, including the forced
	// close path below.
	controller.BeginClose()
	httpCtx, httpCancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	shutdownErr := server.Shutdown(httpCtx)
	httpCancel()
	if shutdownErr != nil {
		if result == nil {
			result = fmt.Errorf("shut down execution listener: %w", shutdownErr)
		}
		if err := server.Close(); err != nil && result == nil {
			result = fmt.Errorf("force close execution listener: %w", err)
		}
	}
	if !serveFinished {
		serveWait := time.NewTimer(httpShutdownTimeout)
		select {
		case serveErr := <-serveResult:
			serveFinished = true
			if serveErr != nil && result == nil {
				result = fmt.Errorf("stop execution listener: %w", serveErr)
			}
		case <-serveWait.C:
			if result == nil {
				result = errors.New("execution listener did not stop")
			}
		}
		if !serveWait.Stop() {
			select {
			case <-serveWait.C:
			default:
			}
		}
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), runShutdownTimeout)
	closeErr := controller.Close(closeCtx)
	if closeErr != nil && result == nil {
		result = fmt.Errorf("shut down sandbox controller: %w", closeErr)
	}
	closeCancel()
	controllerClosed = closeErr == nil

	if parent.Err() != nil && result == nil {
		return nil
	}
	return result
}

func acquireOwnership(socketPath string, peerUID localidentity.UID) (net.Listener, error) {
	if _, err := localhttp.RemoveStaleSocket(socketPath, staleSocketProbe); err != nil {
		return nil, fmt.Errorf("reconcile sandbox socket: %w", err)
	}
	listener, err := localhttp.Listen(socketPath, peerUID)
	if err != nil {
		return nil, fmt.Errorf("listen for agentd: %w", err)
	}
	return listener, nil
}

func prepareFilesystem(config sandboxconfig.Config) error {
	if err := privatefs.EnsureParent(config.Socket, 0o700); err != nil {
		return fmt.Errorf("prepare sandbox socket directory: %w", err)
	}
	if err := privatefs.EnsureParent(config.StateDatabase, 0o700); err != nil {
		return fmt.Errorf("prepare sandbox database directory: %w", err)
	}
	if err := privatefs.EnsureDir(config.WorkspaceRoot, 0o700); err != nil {
		return fmt.Errorf("prepare workspace root: %w", err)
	}
	if err := privatefs.EnsureDir(config.RunnerStateRoot, 0o700); err != nil {
		return fmt.Errorf("prepare runner-state root: %w", err)
	}
	for _, entry := range config.Workspaces {
		path, ok := config.WorkspacePath(entry.Ref)
		if !ok {
			return errors.New("configured workspace did not resolve")
		}
		if err := privatefs.EnsureDir(path, 0o700); err != nil {
			return fmt.Errorf("prepare approved workspace: %w", err)
		}
	}
	return nil
}

func prepareRunnerStateFilesystem(config sandboxconfig.Config) error {
	for _, target := range config.Targets {
		path, ok := config.RunnerStatePath(target.StateRef)
		if !ok {
			return errors.New("configured runner state did not resolve")
		}
		if err := privatefs.EnsureDir(path, 0o700); err != nil {
			return fmt.Errorf("prepare approved runner state: %w", err)
		}
	}
	return nil
}
