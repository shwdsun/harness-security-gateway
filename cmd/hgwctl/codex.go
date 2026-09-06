package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/shwdsun/harness-security-gateway/internal/codexcandidate"
)

var errCodexBlocked = errors.New("Codex execution is blocked; see execution_blockers in the report")
var errCodexUsage = errors.New("usage: hgwctl codex check -config FILE [-inspect]")

// This is an offline preflight, deliberately independent of Core maintenance.
func runCodex(arguments []string, output io.Writer) error {
	if len(arguments) < 2 || arguments[1] != "check" {
		return errCodexUsage
	}
	flags := flag.NewFlagSet("hgwctl codex check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "local Codex candidate configuration")
	inspect := flags.Bool("inspect", false, "also inspect local workspace and credential metadata; never read auth bytes")
	if flags.Parse(arguments[2:]) != nil || flags.NArg() != 0 || *path == "" {
		return errCodexUsage
	}
	candidate, err := codexcandidate.Load(*path)
	if err != nil {
		return err
	}
	report, err := candidate.Check(*inspect)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return err
	}
	return errCodexBlocked
}

func commandExitCode(err error) int {
	switch {
	case errors.Is(err, errCodexUsage):
		return 2
	case errors.Is(err, errCodexBlocked):
		return 3
	case err != nil:
		return 1
	default:
		return 0
	}
}
