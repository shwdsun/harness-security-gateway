//go:build linux && !amd64

package credentialsource

func openMappedReceiver(*HeldSource, int, string, string, string, Proof, uint32) (Receiver, error) {
	return nil, ErrInvalidHandoff
}
