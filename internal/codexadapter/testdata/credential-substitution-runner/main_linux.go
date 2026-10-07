//go:build linux

// Fixed offline experiment successor of the pinned UID helper.
package main

import (
	"os"
	"syscall"
)

func main() {
	if len(os.Args) != 1 || os.Getpid() != 1 || os.Geteuid() != 1000 {
		os.Exit(125)
	}
	if syscall.Exec("/probe.test", []string{"/probe.test", "-test.run=^TestCredentialSubstitutionClient$", "-test.v", "-test.timeout=75s"}, []string{
		"HOME=/nonexistent", "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "GOMAXPROCS=2", "HSG_CREDENTIAL_SUBSTITUTION_CLIENT=1",
	}) != nil {
		os.Exit(125)
	}
}
