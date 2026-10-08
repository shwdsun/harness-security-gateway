//go:build linux && codexintegration

package codexadapter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

type canaryCloseFunc func() error

func (f canaryCloseFunc) Close() error { return f() }

func TestCanaryWaitDiagnostics(t *testing.T) {
	for _, row := range []struct {
		name, message string
		native, relay bool
	}{
		{"native", "Codex native process failed", true, false},
		{"relay", "Codex provider relay failed", false, true},
		{"both", "Codex native process and provider relay failed", true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			var order []string
			launcher := launcherFunc(func(_ context.Context, invocation Invocation) (Process, error) {
				invocation.Stdout.Write([]byte("PRIVATE-NATIVE-OUTPUT"))
				invocation.Stderr.Write([]byte("PRIVATE-NATIVE-ERROR"))
				return &providerCanaryProcess{Process: processFunc(func() error {
					order = append(order, "native")
					if row.native {
						return errors.New("PRIVATE-NATIVE-WAIT")
					}
					return nil
				}), relay: canaryCloseFunc(func() error {
					order = append(order, "relay")
					if row.relay {
						return errors.New("PRIVATE-RELAY-CLOSE")
					}
					return nil
				})}, nil
			})
			frames, wire, err := execute(t, context.Background(), testStart(), testConfig(t), launcher)
			if err != nil {
				t.Fatal(err)
			}
			requireFailure(t, frames, 2, runnerwire.ErrorCodeHarnessError, row.message)
			if strings.Contains(wire, "PRIVATE") || strings.Join(order, ",") != "native,relay" {
				t.Fatal("source error leaked or relay was not joined after Wait")
			}
		})
	}
	p := providerCanaryProcess{Process: processFunc(func() error { return nil }), relay: canaryCloseFunc(func() error { return nil })}
	if p.Wait() != nil {
		t.Fatal("successful join became a failure")
	}
}
