package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/agentservice"
	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
)

const (
	crashChildCommand = "crash-child"
	demoRunID         = "run-demo-0001"
	demoConnectorID   = "discord-private"
	demoActorRef      = "discord:user:100"
	demoConversation  = "discord:dm:200"
	demoTargetID      = "workspace-codex"
	demoTargetRev     = "codex-r1"
	demoText          = "inspect the workspace; requested target=attacker"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == crashChildCommand {
		if err := runCrashChildArgs(os.Stdout, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "demo-security child: %v\n", err)
			os.Exit(2)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: demo-security")
		os.Exit(2)
	}
	executable, err := os.Executable()
	if err == nil {
		err = runDemo(os.Stdout, executable)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo-security: %v\n", err)
		os.Exit(1)
	}
}

func runDemo(output io.Writer, executable string) error {
	root, err := os.MkdirTemp("", "hgw-security-demo-")
	if err != nil {
		return fmt.Errorf("create private demo directory: %w", err)
	}
	defer os.RemoveAll(root)

	now := time.Now().UTC().Truncate(time.Millisecond)
	database := filepath.Join(root, "core.sqlite3")
	ctx := context.Background()

	if err := writeLine(output, "Harness Security Gateway security demo"); err != nil {
		return err
	}
	if err := writeLine(output, "  synthetic input through production wire -> immutable policy -> service -> SQLite; no network, Docker, or credentials"); err != nil {
		return err
	}

	store, service, _, runIDCalls, err := openDemoService(ctx, database, now, func() (string, error) {
		return "run-unexpected-before-admission", nil
	})
	if err != nil {
		return err
	}

	closeInitial := func() error {
		if store == nil {
			return nil
		}
		err := store.Close()
		store = nil
		return err
	}
	defer closeInitial()

	if err := proveClosedWire(now); err != nil {
		return err
	}
	if err := writeLine(output, "[PASS] 1/5 closed wire authority: target fields and arbitrary actions were rejected by the strict wire schema"); err != nil {
		return err
	}

	selectTarget, err := decodeEvent(selectTargetJSON(now))
	if err != nil {
		return fmt.Errorf("decode recognized select_target action: %w", err)
	}
	if _, err := service.Ingest(ctx, selectTarget); !hasServiceCode(err, connectorhttp.ErrorActionUnsupported) {
		return fmt.Errorf("select_target action was not closed as unsupported: %w", err)
	}
	if *runIDCalls != 0 {
		return errors.New("unsupported action minted a Run ID")
	}
	if err := writeLine(output, "[PASS] 2/5 closed control: select_target is recognized but unsupported; no Run was minted"); err != nil {
		return err
	}

	wrongBinding, err := decodeEvent(textEventJSON("event-wrong-binding", "discord:dm:999", demoText, now))
	if err != nil {
		return fmt.Errorf("decode wrong-binding event: %w", err)
	}
	if _, err := service.Ingest(ctx, wrongBinding); !hasServiceCode(err, connectorhttp.ErrorForbidden) {
		return fmt.Errorf("non-exact binding was not forbidden: %w", err)
	}
	if *runIDCalls != 0 {
		return errors.New("non-exact binding minted a Run ID")
	}
	if err := writeLine(output, "[PASS] 3/5 exact binding: actor/conversation tuple mismatch was denied; no Run was minted"); err != nil {
		return err
	}

	if err := closeInitial(); err != nil {
		return fmt.Errorf("close Core before crash process: %w", err)
	}
	accepted, err := admitThenKill(executable, database, now)
	if err != nil {
		return err
	}
	if accepted.Disposition != connectorwire.InboundAccepted || accepted.RunID != demoRunID {
		return fmt.Errorf("unexpected acknowledged admission: %#v", accepted)
	}

	reopened, replayService, reopenedEndpoint, replayRunIDCalls, err := openDemoService(ctx, database, now, func() (string, error) {
		return "run-unexpected-after-reopen", nil
	})
	if err != nil {
		return fmt.Errorf("reopen Core after SIGKILL: %w", err)
	}
	defer reopened.Close()

	replayEvent, err := decodeEvent(textEventJSON("event-accepted", demoConversation, demoText, now))
	if err != nil {
		return fmt.Errorf("decode replay event: %w", err)
	}
	replay, err := replayService.Ingest(ctx, replayEvent)
	if err != nil {
		return fmt.Errorf("replay acknowledged event after reopen: %w", err)
	}
	if replay.Disposition != connectorwire.InboundDuplicate || replay.RunID != accepted.RunID {
		return fmt.Errorf("replay did not resolve to the durable admission: %#v", replay)
	}
	if *replayRunIDCalls != 0 {
		return errors.New("exact replay minted a new Run ID")
	}
	run, err := reopened.GetRun(ctx, accepted.RunID)
	if err != nil {
		return fmt.Errorf("read durable Run after reopen: %w", err)
	}
	decision, err := reopenedEndpoint.Authorize(demoActorRef, demoConversation)
	if err != nil {
		return fmt.Errorf("resolve compiled binding after reopen: %w", err)
	}
	if err := verifyDurableRun(run, decision); err != nil {
		return err
	}
	if err := writeLine(output, "[PASS] 4/5 crash durability: exact child PID was SIGKILLed after the acceptance receipt; reopen replayed "+demoRunID); err != nil {
		return err
	}

	changed, err := decodeEvent(textEventJSON("event-accepted", demoConversation, "changed payload under retained event ID", now))
	if err != nil {
		return fmt.Errorf("decode conflicting replay: %w", err)
	}
	if _, err := replayService.Ingest(ctx, changed); !hasServiceCode(err, connectorhttp.ErrorEventConflict) {
		return fmt.Errorf("changed replay was not rejected as an event conflict: %w", err)
	}
	if *replayRunIDCalls != 0 {
		return errors.New("conflicting replay minted a new Run ID")
	}
	if err := writeLine(output, "[PASS] 5/5 replay integrity: exact replay deduplicated; changed payload under the event ID conflicted"); err != nil {
		return err
	}
	return writeLine(output, "RESULT: PASS (operator target "+demoTargetID+"@"+demoTargetRev+" remained authoritative)")
}

func proveClosedWire(now time.Time) error {
	var event connectorwire.InboundEventV1
	if err := connectorwire.DecodeStrict(targetInjectionJSON(now), 64<<10, &event); err == nil {
		return errors.New("connector wire accepted an injected target_id")
	}
	if err := connectorwire.DecodeStrict(arbitraryActionJSON(now), 64<<10, &event); err == nil {
		return errors.New("connector wire accepted an arbitrary action")
	}
	return nil
}

func openDemoService(
	ctx context.Context,
	database string,
	now time.Time,
	newRunID agentservice.RunIDSource,
) (*corestore.Store, *agentservice.Service, agentpolicy.Endpoint, *int, error) {
	config := demoConfig(database)
	policy, err := agentpolicy.Compile(config)
	if err != nil {
		return nil, nil, agentpolicy.Endpoint{}, nil, fmt.Errorf("compile immutable demo policy: %w", err)
	}
	endpoint, err := policy.Endpoint(demoConnectorID)
	if err != nil {
		return nil, nil, agentpolicy.Endpoint{}, nil, fmt.Errorf("bind demo connector endpoint: %w", err)
	}
	store, err := corestore.Open(ctx, database, corestore.Options{
		Clock: func() time.Time { return now },
		Admission: corestore.AdmissionOptions{
			AcceptWindow:                      5 * time.Minute,
			ReceiptWindow:                     time.Hour,
			FutureSkew:                        time.Minute,
			MaxReceiptsPerConnector:           128,
			MaxQueuedRunsPerConnector:         16,
			MaxNonTerminalRunsPerConnector:    32,
			MaxPendingDeliveriesPerConnector:  128,
			MaxRetainedInputBytesPerConnector: 4 << 20,
			MaxDatabasePages:                  16_384,
		},
	})
	if err != nil {
		return nil, nil, agentpolicy.Endpoint{}, nil, fmt.Errorf("open demo Core: %w", err)
	}
	runIDCalls := 0
	service, err := agentservice.NewWithRunIDSource(endpoint, 30*time.Second, store, func() (string, error) {
		runIDCalls++
		return newRunID()
	})
	if err != nil {
		_ = store.Close()
		return nil, nil, agentpolicy.Endpoint{}, nil, fmt.Errorf("construct connector-bound service: %w", err)
	}
	return store, service, endpoint, &runIDCalls, nil
}

func demoConfig(database string) agentconfig.Config {
	root := filepath.Dir(database)
	return agentconfig.Config{
		Schema:                  agentconfig.SchemaV3,
		Database:                database,
		SandboxSocket:           filepath.Join(root, "sandbox", "sandboxd.sock"),
		RunTimeoutSeconds:       300,
		DeliveryLeaseSeconds:    30,
		RunDispatchLeaseSeconds: 30,
		Ingress: agentconfig.Ingress{
			AcceptWindowSeconds:               300,
			ReceiptWindowSeconds:              3600,
			FutureSkewSeconds:                 60,
			MaxReceiptsPerConnector:           128,
			MaxQueuedRunsPerConnector:         16,
			MaxNonTerminalRunsPerConnector:    32,
			MaxPendingDeliveriesPerConnector:  128,
			MaxRetainedInputBytesPerConnector: 4 << 20,
			MaxDatabasePages:                  16_384,
		},
		Connectors: []agentconfig.Connector{{
			ID:           demoConnectorID,
			Socket:       filepath.Join(root, "connector", "agentd.sock"),
			PeerUID:      1000,
			SelfActorRef: "discord:bot:1",
		}},
		Bindings: []agentconfig.Binding{{
			ID:              "private-owner",
			ConnectorID:     demoConnectorID,
			ActorRef:        demoActorRef,
			ConversationRef: demoConversation,
			Target: agentconfig.TargetRef{
				ID:       demoTargetID,
				Revision: demoTargetRev,
			},
		}},
	}
}

func admitThenKill(executable, database string, now time.Time) (connectorwire.InboundReceiptV1, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, executable, crashChildCommand, database, strconv.FormatInt(now.UnixMilli(), 10))
	// The crash witness needs no inherited credentials or ambient configuration.
	command.Env = []string{}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return connectorwire.InboundReceiptV1{}, fmt.Errorf("open crash-child receipt pipe: %w", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return connectorwire.InboundReceiptV1{}, fmt.Errorf("start exact crash child: %w", err)
	}

	type decodeResult struct {
		receipt connectorwire.InboundReceiptV1
		err     error
	}
	decoded := make(chan decodeResult, 1)
	go func() {
		var receipt connectorwire.InboundReceiptV1
		err := json.NewDecoder(stdout).Decode(&receipt)
		decoded <- decodeResult{receipt: receipt, err: err}
	}()

	select {
	case result := <-decoded:
		if result.err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return connectorwire.InboundReceiptV1{}, childError("read acknowledged admission", result.err, stderr.String())
		}
		if err := result.receipt.Validate(); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return connectorwire.InboundReceiptV1{}, fmt.Errorf("validate crash-child receipt: %w", err)
		}
		if err := command.Process.Kill(); err != nil {
			_ = command.Wait()
			return connectorwire.InboundReceiptV1{}, fmt.Errorf("SIGKILL exact acknowledged child PID: %w", err)
		}
		waitErr := command.Wait()
		if !wasSIGKILL(waitErr) {
			return connectorwire.InboundReceiptV1{}, childError("verify exact child SIGKILL", waitErr, stderr.String())
		}
		return result.receipt, nil
	case <-ctx.Done():
		waitErr := command.Wait()
		return connectorwire.InboundReceiptV1{}, childError("wait for crash-child admission", errors.Join(ctx.Err(), waitErr), stderr.String())
	}
}

func runCrashChildArgs(output io.Writer, args []string) error {
	if len(args) != 2 {
		return errors.New("internal crash-child requires database and timestamp")
	}
	timestamp, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil || timestamp <= 0 {
		return errors.New("invalid internal crash-child timestamp")
	}
	return runCrashChild(output, args[0], time.UnixMilli(timestamp).UTC())
}

func runCrashChild(output io.Writer, database string, now time.Time) error {
	ctx := context.Background()
	store, service, _, runIDCalls, err := openDemoService(ctx, database, now, func() (string, error) {
		return demoRunID, nil
	})
	if err != nil {
		return err
	}
	defer store.Close()

	event, err := decodeEvent(textEventJSON("event-accepted", demoConversation, demoText, now))
	if err != nil {
		return fmt.Errorf("decode child admission event: %w", err)
	}
	receipt, err := service.Ingest(ctx, event)
	if err != nil {
		return fmt.Errorf("durably admit child event: %w", err)
	}
	if receipt.Disposition != connectorwire.InboundAccepted || receipt.RunID != demoRunID || *runIDCalls != 1 {
		return fmt.Errorf("unexpected child admission: %#v", receipt)
	}
	if err := json.NewEncoder(output).Encode(receipt); err != nil {
		return fmt.Errorf("acknowledge durable child admission: %w", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	<-stop
	return nil
}

func verifyDurableRun(run corestore.Run, decision agentpolicy.Decision) error {
	if run.ID != demoRunID || run.State != corestore.RunQueued || run.InputText != demoText {
		return fmt.Errorf("reopened Run content/state mismatch: %#v", run)
	}
	if run.TargetID != demoTargetID || run.TargetRevision != demoTargetRev ||
		run.TargetID != decision.TargetID || run.TargetRevision != decision.TargetRevision ||
		run.BindingFingerprint != decision.BindingFingerprint || run.PolicyRevision != decision.PolicyRevision {
		return errors.New("reopened Run lost immutable binding evidence")
	}
	return nil
}

func wasSIGKILL(err error) bool {
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ProcessState == nil {
		return false
	}
	status, ok := exitError.ProcessState.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

func childError(operation string, err error, stderr string) error {
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: %w (%s)", operation, err, detail)
}

func hasServiceCode(err error, code connectorhttp.ErrorCode) bool {
	var serviceError *connectorhttp.ServiceError
	return errors.As(err, &serviceError) && serviceError != nil && serviceError.Code == code
}

func decodeEvent(data []byte) (connectorwire.InboundEventV1, error) {
	var event connectorwire.InboundEventV1
	if err := connectorwire.DecodeStrict(data, 64<<10, &event); err != nil {
		return connectorwire.InboundEventV1{}, err
	}
	return event, nil
}

func textEventJSON(eventID, conversation, text string, now time.Time) []byte {
	return []byte(fmt.Sprintf(
		`{"event_id":%q,"actor_ref":%q,"conversation_ref":%q,"message_ref":"discord:message:400","occurred_at_unix_ms":%d,"content":{"type":"text","text":%q}}`,
		eventID, demoActorRef, conversation, now.UnixMilli(), text,
	))
}

func targetInjectionJSON(now time.Time) []byte {
	return []byte(fmt.Sprintf(
		`{"event_id":"event-target-injection","actor_ref":%q,"conversation_ref":%q,"message_ref":"discord:message:401","occurred_at_unix_ms":%d,"target_id":"attacker-target","content":{"type":"text","text":"hello"}}`,
		demoActorRef, demoConversation, now.UnixMilli(),
	))
}

func arbitraryActionJSON(now time.Time) []byte {
	return []byte(fmt.Sprintf(
		`{"event_id":"event-shell-action","actor_ref":%q,"conversation_ref":%q,"message_ref":"discord:message:402","occurred_at_unix_ms":%d,"content":{"type":"action","action":{"type":"shell"}}}`,
		demoActorRef, demoConversation, now.UnixMilli(),
	))
}

func selectTargetJSON(now time.Time) []byte {
	return []byte(fmt.Sprintf(
		`{"event_id":"event-select-target","actor_ref":%q,"conversation_ref":%q,"message_ref":"discord:message:403","occurred_at_unix_ms":%d,"content":{"type":"action","action":{"type":"select_target","target_alias":"default"}}}`,
		demoActorRef, demoConversation, now.UnixMilli(),
	))
}

func writeLine(output io.Writer, line string) error {
	if _, err := fmt.Fprintln(output, line); err != nil {
		return fmt.Errorf("write demo output: %w", err)
	}
	return nil
}
