// Command hgwctl exposes narrow, local-only offline operator procedures.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/processlock"
)

type sessionCommand struct {
	action             string
	configPath         string
	bindingID          string
	expectedSessionRef string
}

var errResetNotApplied = errors.New("session reset was not applied")

type statusOutput struct {
	Schema           string `json:"schema"`
	BindingID        string `json:"binding_id"`
	SessionPresent   bool   `json:"session_present"`
	SessionRef       string `json:"session_ref,omitempty"`
	UpdatedAtUnixMS  int64  `json:"updated_at_unix_ms,omitempty"`
	NonterminalRunID string `json:"nonterminal_run_id,omitempty"`
}

type resetOutput struct {
	Schema    string                       `json:"schema"`
	BindingID string                       `json:"binding_id"`
	Result    corestore.SessionResetResult `json:"result"`
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "hgwctl: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, output io.Writer) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if output == nil {
		return errors.New("nil output")
	}
	command, err := parseCommand(arguments)
	if err != nil {
		return err
	}
	config, err := agentconfig.Load(command.configPath)
	if err != nil {
		return fmt.Errorf("load agentd configuration: %w", err)
	}
	key, err := resolveSessionKey(config, command.bindingID)
	if err != nil {
		return err
	}
	owner, err := processlock.Acquire(config.ProcessLockPath())
	if err != nil {
		return fmt.Errorf("acquire offline Core authority: %w", err)
	}
	defer owner.Close()
	store, err := corestore.OpenCurrentForMaintenance(ctx, config.Database)
	if err != nil {
		return fmt.Errorf("open current Core database for maintenance: %w", err)
	}
	defer store.Close()

	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	switch command.action {
	case "status":
		status, err := store.InspectSession(ctx, key)
		if err != nil {
			return fmt.Errorf("inspect session: %w", err)
		}
		response := statusOutput{
			Schema: "hgwctl/session-status/v1", BindingID: command.bindingID,
			SessionPresent: status.Found, NonterminalRunID: status.NonterminalRunID,
		}
		if status.Found {
			response.SessionRef = status.Session.Ref
			response.UpdatedAtUnixMS = status.Session.UpdatedAt.UTC().UnixMilli()
		}
		return encoder.Encode(response)
	case "reset":
		result, err := store.ResetSession(ctx, key, command.expectedSessionRef)
		if err != nil {
			return fmt.Errorf("reset session: %w", err)
		}
		if err := encoder.Encode(resetOutput{
			Schema: "hgwctl/session-reset/v1", BindingID: command.bindingID, Result: result,
		}); err != nil {
			return err
		}
		if result != corestore.SessionResetDone {
			return fmt.Errorf("%w: %s", errResetNotApplied, result)
		}
		return nil
	default:
		return errors.New("unsupported session action")
	}
}

func parseCommand(arguments []string) (sessionCommand, error) {
	if len(arguments) < 2 || arguments[0] != "session" {
		return sessionCommand{}, errors.New("usage: hgwctl session status|reset [flags]")
	}
	command := sessionCommand{action: arguments[1]}
	flags := flag.NewFlagSet("hgwctl session "+command.action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&command.configPath, "config", "", "path to agentd JSON configuration")
	flags.StringVar(&command.bindingID, "binding", "", "operator binding ID")
	switch command.action {
	case "status":
	case "reset":
		flags.StringVar(&command.expectedSessionRef, "expected-session-ref", "", "expected opaque session reference")
	default:
		return sessionCommand{}, errors.New("session action must be status or reset")
	}
	if err := flags.Parse(arguments[2:]); err != nil {
		return sessionCommand{}, err
	}
	if flags.NArg() != 0 {
		return sessionCommand{}, errors.New("positional arguments are not supported")
	}
	if command.configPath == "" || command.bindingID == "" {
		return sessionCommand{}, errors.New("-config and -binding are required")
	}
	if command.action == "reset" && command.expectedSessionRef == "" {
		return sessionCommand{}, errors.New("-expected-session-ref is required for reset")
	}
	return command, nil
}

func resolveSessionKey(config agentconfig.Config, bindingID string) (corestore.SessionKey, error) {
	var selected *agentconfig.Binding
	for index := range config.Bindings {
		if config.Bindings[index].ID == bindingID {
			selected = &config.Bindings[index]
			break
		}
	}
	if selected == nil {
		return corestore.SessionKey{}, errors.New("unknown binding ID")
	}
	policy, err := agentpolicy.Compile(config)
	if err != nil {
		return corestore.SessionKey{}, fmt.Errorf("compile ingress policy: %w", err)
	}
	endpoint, err := policy.Endpoint(selected.ConnectorID)
	if err != nil {
		return corestore.SessionKey{}, fmt.Errorf("resolve binding Connector: %w", err)
	}
	decision, err := endpoint.Authorize(selected.ActorRef, selected.ConversationRef)
	if err != nil {
		return corestore.SessionKey{}, fmt.Errorf("resolve exact binding authority: %w", err)
	}
	if decision.TargetID != selected.Target.ID || decision.TargetRevision != selected.Target.Revision {
		return corestore.SessionKey{}, errors.New("compiled binding target mismatch")
	}
	return corestore.SessionKey{
		BindingFingerprint: decision.BindingFingerprint,
		ConnectorID:        selected.ConnectorID, ActorRef: selected.ActorRef,
		ConversationRef: selected.ConversationRef, TargetID: decision.TargetID,
		TargetRevision: decision.TargetRevision,
	}, nil
}
