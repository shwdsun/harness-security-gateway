//go:build linux

// Fixed HRP successor for the controller-owned offline integration fixture.
package main

import (
	"os"
	"syscall"
)

func main() {
	if len(os.Args) != 1 {
		os.Exit(125)
	}
	err := syscall.Exec("/hsg-canary", []string{"/hsg-canary", "-test.run=^TestCodexControllerRunner$", "-test.timeout=60s"}, []string{
		"HOME=/nonexistent", "PATH=/opt/hsg/codex/bin:/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TMPDIR=/tmp", "HSG_CODEX_CONTROLLER_RUNNER=1",
	})
	if err != nil {
		os.Exit(125)
	}
}
