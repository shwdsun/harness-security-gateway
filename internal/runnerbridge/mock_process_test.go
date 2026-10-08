package runnerbridge

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// Fake protocol frames alone cannot prove that the shipped mock artifact fits
// new_only: the legacy mock always returns a token. Compile and run the exact
// fixed-profile entrypoint with an empty environment and no state directory.
func TestV2NoneUsesRealFixedNewOnlyMockProcess(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "mock-new-only")
	buildCtx, cancelBuild := context.WithTimeout(context.Background(), time.Minute)
	defer cancelBuild()
	build := exec.CommandContext(buildCtx, "go", "build", "-mod=readonly", "-buildvcs=false", "-trimpath",
		"-ldflags=-X main.fixedSessionPolicy=new_only", "-o", binary, "./cmd/mock-runner")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile fixed mock: %v\n%s", err, output)
	}
	wire := validManifest(targetmanifest.SessionNewOnly)
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Replace(string(data), `"harness-target/v1"`, `"harness-target/v2"`, 1)
	document = strings.Replace(document, `"state_ref":"state"`, `"runner_state":{"kind":"none"}`, 1)
	target, err := targetmanifest.DecodeDefinition([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary)
	command.Env = []string{}
	command.Dir = t.TempDir()
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()
	var events []Emission
	bridgeErr := Run(ctx, validRequest(wire), target, nil, output, input,
		func(_ context.Context, event Emission) error { events = append(events, event); return nil })
	_ = input.Close()
	waitErr := command.Wait()
	if bridgeErr != nil || waitErr != nil {
		t.Fatalf("real mock/bridge: %v %v", bridgeErr, waitErr)
	}
	if len(events) != 3 || events[2].Event.Type != executionwire.RunEventCompleted ||
		events[2].VendorSessionToken != nil || events[2].Event.Result.SessionRef != nil {
		t.Fatalf("new-only mock lifecycle: %#v", events)
	}
}
