//go:build linux && codexintegration

package codexadapter

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

// controllerRunnerIO uses real HRP stdio. Only this synthetic fixture delays its
// terminal frame until independent native-command and quiescence checks pass.
// Ready/started/progress are forwarded immediately, retaining the normal bridge.
type controllerRunnerIO struct {
	input   io.Reader
	output  io.Writer
	buffer  []byte
	pending []byte
	frames  []runnerwire.RunnerFrame
}

func (p *controllerRunnerIO) Write(data []byte) (int, error) {
	if len(p.buffer)+len(data) > 64<<10 {
		return 0, errors.New("synthetic HRP bound")
	}
	p.buffer = append(p.buffer, data...)
	for {
		end := bytes.IndexByte(p.buffer, '\n')
		if end < 0 {
			break
		}
		line := append([]byte(nil), p.buffer[:end+1]...)
		p.buffer = p.buffer[end+1:]
		frame, err := runnerwire.NewDecoder(bytes.NewReader(line)).DecodeRunnerFrame()
		if err != nil || len(p.pending) != 0 {
			return 0, errors.New("synthetic HRP framing")
		}
		p.frames = append(p.frames, frame)
		switch frame.(type) {
		case *runnerwire.RunnerReady, *runnerwire.RunStarted, *runnerwire.RunProgress:
			if n, err := p.output.Write(line); err != nil || n != len(line) {
				return 0, io.ErrShortWrite
			}
		default:
			p.pending = line
		}
	}
	return len(data), nil
}

func TestCodexControllerRunner(t *testing.T) {
	if os.Getenv("HSG_CODEX_CONTROLLER_RUNNER") != "1" {
		t.Skip("owned synthetic HRP runner only")
	}
	controllerRunnerNamespace(t)
	stream := &controllerRunnerIO{input: os.Stdin, output: os.Stdout}
	toolsConfigurationConsumerIO(t, codexprofile.CLIBinaryPathV3, "command-exec", true, stream)
	assertIntegrationQuiescence(t)
	if len(stream.buffer) != 0 || len(stream.pending) == 0 || len(stream.frames) != 3 {
		t.Fatal("incomplete synthetic HRP")
	}
	// Consumer cleanup can report a nonfatal testing error. os.Exit below would
	// bypass testing's failure result, so it must never release that terminal.
	if t.Failed() {
		t.FailNow()
	}
	if n, err := os.Stdout.Write(stream.pending); err != nil || n != len(stream.pending) {
		os.Exit(1)
	}
	os.Exit(0) // Prevent testing's PASS footer from becoming an extra HRP frame.
}

// The host observes the real tool lock and cancels through executionhttp.
// No timer/observer in this Runner initiates cancellation or releases terminal.
func TestCodexControllerCancelRunner(t *testing.T) {
	if os.Getenv("HSG_CODEX_CONTROLLER_CANCEL_RUNNER") != "1" {
		t.Skip("owned synthetic external-cancellation runner only")
	}
	controllerRunnerNamespace(t)
	stream := &controllerRunnerIO{input: os.Stdin, output: os.Stdout}
	toolsConfigurationConsumerIO(t, codexprofile.CLIBinaryPathV3, "command-cancel", true, stream)
	t.Fatal("external cancellation fixture survived outer teardown")
}

func controllerRunnerNamespace(t *testing.T) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil || os.Getpid() != 1 || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatal("requires owned offline PID-1 namespace")
	}
	if err := verifyToolsPackage(codexprofile.CLIBinaryPathV3); err != nil {
		t.Fatal(err)
	}
}
