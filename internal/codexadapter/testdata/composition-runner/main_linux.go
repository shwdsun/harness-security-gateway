//go:build linux

// Fixed successor for the offline composition fixture. Never shipped in a
// product image. No task or bootstrap frame can select its command or options.
package main

import (
	"os"
	"syscall"
)

func main() {
	if len(os.Args) != 1 {
		os.Exit(125)
	}
	err := syscall.Exec("/hsg-canary", []string{"/hsg-canary", "-test.run=^TestCodexSyntheticConsumerComposition$", "-test.v", "-test.timeout=45s"}, []string{
		"HOME=/nonexistent", "PATH=/opt/hsg/codex/bin:/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TMPDIR=/tmp", "HSG_CODEX_COMPOSITION_CANARY=1",
	})
	if err != nil {
		os.Exit(125)
	}
}
