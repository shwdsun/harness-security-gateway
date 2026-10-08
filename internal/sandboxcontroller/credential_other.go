//go:build !linux

package sandboxcontroller

func openHeldCredential(_, _ string) (credentialHandle, error) {
	return nil, ErrCredentialUnavailable
}
