//go:build linux && amd64 && codexintegration

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexcanary"
)

func main() { os.Exit(run()) }
func run() int {
	flags := flag.NewFlagSet("codex-provider-canary", flag.ContinueOnError)
	path := flags.String("config", "", "private canary.json")
	execute := flags.String("execute-plan", "", "explicitly arm the exact reviewed plan digest")
	recover := flags.String("recover-plan", "", "cleanup only; never dispatch or reopen a provider")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || *path == "" || (*execute != "" && *recover != "") {
		return 2
	}
	c, err := codexcanary.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary: invalid private configuration")
		return 1
	}
	if *execute == "" && *recover == "" {
		plan, _, err := codexcanary.Preflight(c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "canary: local preparation failed")
			return 1
		}
		if json.NewEncoder(os.Stdout).Encode(plan) != nil {
			return 1
		}
		return 3 // Read-only report is never an execution success.
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	approved := *execute
	if *recover != "" {
		approved = *recover
	}
	result, err := codexcanary.Execute(ctx, c, approved, *recover != "")
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary: incomplete; preserve state and inspect cleanup before any further run")
		return 1
	}
	return 0
}
