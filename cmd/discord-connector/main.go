// Command discord-connector is the private Discord Connector. It opens no
// listening socket: it polls one allowlisted channel outbound, hands normalized
// events to its dedicated agentd socket, and posts claimed replies back.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
	"github.com/shwdsun/harness-security-gateway/internal/discordconnector"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "discord-connector: %v\n", err)
		os.Exit(1)
	}
}

// The check receipt is a command result and goes to stdout, like sandboxd's.
// The cycle log is diagnostics and stays on stderr.
func run(ctx context.Context, arguments []string, output, logOutput io.Writer) error {
	flags := flag.NewFlagSet("discord-connector", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to connector JSON configuration")
	check := flags.Bool("check", false, "check configuration and the bot token file only")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not supported")
	}
	if *configPath == "" {
		return errors.New("-config is required")
	}
	config, err := discordconnector.Load(*configPath)
	if err != nil {
		return err
	}
	token, err := discordconnector.ReadToken(config.TokenFile)
	if err != nil {
		return err
	}
	// Installation needs to fail on a malformed configuration or an unsafe
	// token file before anything runs, so this path opens no state database,
	// makes no platform request and contacts no local peer.
	if *check {
		_, err := fmt.Fprintln(output, "configuration and bot token checked; no platform request, state or delivery performed")
		return err
	}
	timeout := time.Duration(config.RequestTimeoutMS) * time.Millisecond
	platform, err := discordconnector.NewAPI(config.APIBaseURL, token, timeout)
	if err != nil {
		return err
	}
	core, err := connectorhttp.NewClient(config.AgentdSocket, timeout)
	if err != nil {
		return err
	}
	store, err := discordconnector.OpenStore(ctx, config.StateDatabase)
	if err != nil {
		return err
	}
	defer store.Close()
	service, err := discordconnector.NewService(config, core, platform, store)
	if err != nil {
		return err
	}
	logger := log.New(logOutput, "discord-connector: ", log.LstdFlags|log.LUTC)
	// Failures are logged as bounded classifications; platform diagnostics and
	// message content never enter this log. The counters are reported on change
	// so that a Connector admitting nothing is visible without them.
	return service.Run(ctx,
		func(err error) { logger.Printf("cycle error: %v", err) },
		func(cycle discordconnector.Cycle) {
			logger.Printf("cycle counters: admitted=%d delivered=%d skipped=%s",
				cycle.Admitted, cycle.Delivered, cycle.SkipSummary())
		})
}
