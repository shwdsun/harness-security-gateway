//go:build !linux

package codexadapter

import "os"

// The isolated runtime is Linux-only; an unknown mount property cannot admit it.
func packageReadOnlyFD(uintptr) bool                    { return false }
func packageReadOnlyDirectory(string, os.FileInfo) bool { return false }
