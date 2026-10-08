//go:build linux

// Fixed successor of the pinned UID setup for an offline channel witness.
package main

import (
	"os"
	"syscall"
)

var mode = "complete" // Each mode is a separately built, frozen artifact.

func main() {
	if len(os.Args) != 1 || (mode != "complete" && mode != "owner-loss") {
		os.Exit(125)
	}
	if syscall.Exec("/native.test", []string{"/native.test", "-test.run=^TestProviderNativeClient$", "-test.v", "-test.timeout=75s"}, []string{
		"HOME=/nonexistent", "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "GOMAXPROCS=2",
		"HSG_PROVIDER_NATIVE_CLIENT=" + mode,
	}) != nil {
		os.Exit(125)
	}
}
