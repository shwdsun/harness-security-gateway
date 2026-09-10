//go:build linux

package sandboxcontroller

import "github.com/shwdsun/harness-security-gateway/internal/credentialsource"

func openHeldCredential(root, directory string) (credentialHandle, error) {
	return credentialsource.Hold(root, directory)
}
