//go:build linux

// Fixed successor for one of two frozen offline provider lifecycle artifacts.
package main

import (
	"os"
	"syscall"
)

var mode = "complete" // The cancel artifact is separately built and hashed.

func main() {
	if len(os.Args) != 1 || (mode != "complete" && mode != "cancel") {
		os.Exit(125)
	}
	err := syscall.Exec("/hsg-canary", []string{"/hsg-canary", "-test.run=^TestCodexControllerProviderRunner$", "-test.timeout=90s"}, []string{
		"HOME=/nonexistent", "PATH=/opt/hsg/codex/bin:/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TMPDIR=/tmp",
		"HSG_CODEX_CONTROLLER_PROVIDER_RUNNER=1", "HSG_CODEX_CONTROLLER_PROVIDER_MODE=" + mode,
	})
	if err != nil {
		os.Exit(125)
	}
}
