//go:build linux && !amd64

package credentialsource

import "os"

// The first native proof adapter implements the Linux x86_64 syscall ABI only.
func nativeIdentity([3]*os.File, [3]objectID) (kernelIdentity, error) {
	return kernelIdentity{}, ErrUnavailable
}
