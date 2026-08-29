// mock-runner is the first executable HRP/1 conformance fixture. It has no
// network or listening surface: one run arrives on stdin and protocol-only
// frames leave on stdout.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

const (
	adapterFamily  = "mock"
	adapterVersion = "0.1.0"
	progressText   = "Mock runner processing input"
)

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		// Never copy untrusted protocol content or raw input to diagnostics.
		// sandboxd independently bounds stderr and classifies the failure.
		_, _ = fmt.Fprintln(os.Stderr, "mock-runner: protocol run failed")
		os.Exit(1)
	}
}

func run(input io.Reader, output io.Writer) error {
	if input == nil {
		return errors.New("mock-runner: nil input")
	}
	if output == nil {
		return errors.New("mock-runner: nil output")
	}

	encoder := runnerwire.NewEncoder(output)
	ready := &runnerwire.RunnerReady{
		Protocol: runnerwire.ProtocolV1,
		Type:     runnerwire.TypeRunnerReady,
		Adapter: runnerwire.Adapter{
			Family:  adapterFamily,
			Version: adapterVersion,
		},
		Features: []runnerwire.Feature{
			runnerwire.FeatureSessionResume,
			runnerwire.FeatureProgressText,
		},
	}
	if err := encoder.Encode(ready); err != nil {
		return fmt.Errorf("emit runner.ready: %w", err)
	}

	controllerFrame, err := runnerwire.NewDecoder(input).DecodeControllerFrame()
	if err != nil {
		return fmt.Errorf("receive run.start: %w", err)
	}
	start, ok := controllerFrame.(*runnerwire.RunStart)
	if !ok {
		return errors.New("receive run.start: unexpected controller frame")
	}

	events := []runnerwire.RunEvent{
		&runnerwire.RunStarted{
			Protocol: runnerwire.ProtocolV1,
			Type:     runnerwire.TypeRunStarted,
			RunID:    start.RunID,
			Seq:      1,
		},
		&runnerwire.RunProgress{
			Protocol: runnerwire.ProtocolV1,
			Type:     runnerwire.TypeRunProgress,
			RunID:    start.RunID,
			Seq:      2,
			Kind:     runnerwire.ProgressKindStatus,
			Text:     progressText,
		},
		&runnerwire.RunCompleted{
			Protocol: runnerwire.ProtocolV1,
			Type:     runnerwire.TypeRunCompleted,
			RunID:    start.RunID,
			Seq:      3,
			Output: runnerwire.TextContent{
				MediaType: runnerwire.MediaTypeTextPlain,
				Text:      deterministicOutput(start.Input.Text),
			},
			SessionToken: sessionToken(start),
		},
	}

	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("emit %s: %w", event.FrameType(), err)
		}
	}
	return nil
}

func deterministicOutput(input string) string {
	digest := sha256.Sum256([]byte(input))
	return "mock completed: input_sha256=" + hex.EncodeToString(digest[:])
}

func sessionToken(start *runnerwire.RunStart) string {
	if start.Session.Mode == runnerwire.SessionModeResume {
		return start.Session.Token
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("harness-gateway.mock-session/v1\x00"))
	_, _ = digest.Write([]byte(start.RunID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(start.TargetRevision))
	return "mock-" + hex.EncodeToString(digest.Sum(nil))
}
