// codex-runner is the new-only Codex HRP/1 adapter entrypoint. A runner image
// build must set codexModel with -ldflags -X; an unset model fails before the
// adapter emits readiness and therefore cannot drift to an ambient default.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/codexadapter"
)

var codexModel string

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	config := codexadapter.ProductionConfig(codexModel)
	if err := codexadapter.Run(ctx, os.Stdin, os.Stdout, config, codexadapter.ExecLauncher{}); err != nil {
		// The error may wrap untrusted protocol or provider details. Keep process
		// diagnostics constant; sandboxd bounds stderr and classifies the exit.
		_, _ = fmt.Fprintln(os.Stderr, "codex-runner: protocol run failed")
		os.Exit(1)
	}
}
