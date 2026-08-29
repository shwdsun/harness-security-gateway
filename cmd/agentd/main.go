// Command agentd is the durable messaging control plane. It owns one business
// SQLite database and one Unix listener per configured Connector instance; it
// never receives a runtime socket, workspace path, or model credential.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentdaemon"
	"github.com/shwdsun/harness-security-gateway/internal/agentdispatch"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/agentservice"
	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/executionhttp"
	"github.com/shwdsun/harness-security-gateway/internal/localhttp"
	"github.com/shwdsun/harness-security-gateway/internal/privatefs"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
)

const (
	controlRequestTimeout = 5 * time.Second
	dispatchPollInterval  = 200 * time.Millisecond
	staleSocketProbe      = 250 * time.Millisecond
	shutdownTimeout       = 5 * time.Second
)

type options struct {
	configPath string
}

type connectorEndpoint struct {
	listener net.Listener
	server   *http.Server
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "agentd: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, logOutput io.Writer) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if logOutput == nil {
		return errors.New("nil log output")
	}
	parsed, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	config, err := agentconfig.Load(parsed.configPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	return serve(ctx, config, log.New(logOutput, "agentd: ", log.LstdFlags|log.LUTC))
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("agentd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var parsed options
	flags.StringVar(&parsed.configPath, "config", "", "path to agentd JSON configuration")
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

func serve(parent context.Context, config agentconfig.Config, logger *log.Logger) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if logger == nil {
		return errors.New("nil logger")
	}
	owner, err := acquireCoreOwnership(config)
	if err != nil {
		return err
	}
	defer owner.Close()
	policy, err := agentpolicy.Compile(config)
	if err != nil {
		return fmt.Errorf("compile ingress policy: %w", err)
	}
	policyEndpoints := make(map[string]agentpolicy.Endpoint, len(config.Connectors))
	for _, connector := range config.Connectors {
		endpoint, endpointErr := policy.Endpoint(connector.ID)
		if endpointErr != nil {
			return fmt.Errorf("compile connector policy endpoint: %w", endpointErr)
		}
		policyEndpoints[connector.ID] = endpoint
	}
	if err := privatefs.EnsureParent(config.Database, 0o700); err != nil {
		return fmt.Errorf("prepare database directory: %w", err)
	}
	for _, connector := range config.Connectors {
		if err := privatefs.EnsureParent(connector.Socket, 0o700); err != nil {
			return fmt.Errorf("prepare connector socket directory: %w", err)
		}
	}

	store, err := corestore.Open(parent, config.Database, corestore.Options{
		Admission: corestore.AdmissionOptions{
			AcceptWindow:                      time.Duration(config.Ingress.AcceptWindowSeconds) * time.Second,
			ReceiptWindow:                     time.Duration(config.Ingress.ReceiptWindowSeconds) * time.Second,
			FutureSkew:                        time.Duration(config.Ingress.FutureSkewSeconds) * time.Second,
			MaxReceiptsPerConnector:           config.Ingress.MaxReceiptsPerConnector,
			MaxQueuedRunsPerConnector:         config.Ingress.MaxQueuedRunsPerConnector,
			MaxNonTerminalRunsPerConnector:    config.Ingress.MaxNonTerminalRunsPerConnector,
			MaxPendingDeliveriesPerConnector:  config.Ingress.MaxPendingDeliveriesPerConnector,
			MaxRetainedInputBytesPerConnector: config.Ingress.MaxRetainedInputBytesPerConnector,
			MaxDatabasePages:                  config.Ingress.MaxDatabasePages,
		},
	})
	if err != nil {
		return fmt.Errorf("open core store: %w", err)
	}
	defer store.Close()

	sandbox, err := executionhttp.NewClient(config.SandboxSocket, controlRequestTimeout)
	if err != nil {
		return fmt.Errorf("create sandbox client: %w", err)
	}
	dispatcher, err := agentdispatch.New(
		store,
		sandbox,
		time.Duration(config.RunDispatchLeaseSeconds)*time.Second,
		time.Duration(config.RunTimeoutSeconds)*time.Second,
	)
	if err != nil {
		return fmt.Errorf("create dispatcher: %w", err)
	}

	endpoints := make([]connectorEndpoint, 0, len(config.Connectors))
	defer func() { closeEndpoints(endpoints) }()
	for _, connector := range config.Connectors {
		service, err := agentservice.New(
			policyEndpoints[connector.ID],
			time.Duration(config.DeliveryLeaseSeconds)*time.Second,
			store,
		)
		if err != nil {
			return fmt.Errorf("create connector service: %w", err)
		}
		handler, err := connectorhttp.NewHandler(service)
		if err != nil {
			return fmt.Errorf("create connector handler: %w", err)
		}
		if _, err := localhttp.RemoveStaleSocket(connector.Socket, staleSocketProbe); err != nil {
			return fmt.Errorf("reconcile connector socket: %w", err)
		}
		listener, err := localhttp.Listen(connector.Socket, connector.PeerUID)
		if err != nil {
			return fmt.Errorf("listen for connector: %w", err)
		}
		endpoints = append(endpoints, connectorEndpoint{
			listener: listener,
			server:   localhttp.NewServer(handler),
		})
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errorsChannel := make(chan error, len(endpoints)+1)
	var workers sync.WaitGroup
	for _, endpoint := range endpoints {
		endpoint := endpoint
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := endpoint.server.Serve(endpoint.listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
				select {
				case errorsChannel <- fmt.Errorf("connector listener failed: %w", err):
				default:
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		err := agentdaemon.Run(ctx, dispatcher, dispatchPollInterval, func(code agentdispatch.ErrorCode) {
			logger.Printf("dispatch error: %s", code)
		})
		if ctx.Err() == nil {
			if err == nil {
				err = errors.New("dispatch supervisor stopped unexpectedly")
			}
			select {
			case errorsChannel <- err:
			default:
			}
		}
	}()

	var result error
	select {
	case <-ctx.Done():
	case result = <-errorsChannel:
		cancel()
	}

	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	for _, endpoint := range endpoints {
		if err := endpoint.server.Shutdown(shutdownContext); err != nil && result == nil {
			result = fmt.Errorf("shut down connector listener: %w", err)
		}
	}
	cancel()
	workers.Wait()
	if parent.Err() != nil {
		return nil
	}
	return result
}

func acquireCoreOwnership(config agentconfig.Config) (*processlock.Lock, error) {
	if err := privatefs.EnsureParent(config.ProcessLockPath(), 0o700); err != nil {
		return nil, fmt.Errorf("prepare Core authority lock directory: %w", err)
	}
	owner, err := processlock.Acquire(config.ProcessLockPath())
	if err != nil {
		return nil, fmt.Errorf("acquire Core authority: %w", err)
	}
	return owner, nil
}

func closeEndpoints(endpoints []connectorEndpoint) {
	for _, endpoint := range endpoints {
		if endpoint.server != nil {
			_ = endpoint.server.Close()
		}
		if endpoint.listener != nil {
			_ = endpoint.listener.Close()
		}
	}
}
