//go:build !linux || !amd64

package dockerruntime

import "context"

type bootstrapObserver struct{}

func (*Runtime) attestBootstrapObserver(context.Context) (bootstrapObserver, error) {
	return bootstrapObserver{}, ErrCredentialUnavailable
}
func (*Runtime) releaseCredentialBootstrap(context.Context, ContainerRef, targetSpec, *credentialLaunch, *Process) error {
	return ErrCredentialUnavailable
}
