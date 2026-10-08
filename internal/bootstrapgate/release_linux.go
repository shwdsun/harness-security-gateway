//go:build linux

package bootstrapgate

import (
	"context"
	"io"
)

// Release consumes the fixed private readiness frame, verifies the inert
// receiver, and writes one permit without reading any later HRP bytes. abort
// must interrupt the owned attach I/O (including an in-flight write); it does
// not replace the runtime owner's container cleanup. Cancellation never grants
// a retry: a partially written permit may already have reached the bootstrap.
func Release(ctx context.Context, input io.Writer, output io.Reader, verify func(context.Context) error, abort func()) error {
	if ctx == nil || input == nil || output == nil || verify == nil || abort == nil {
		return ErrDenied
	}
	bounded, cancel := context.WithTimeout(ctx, WaitLimit)
	defer cancel()
	interrupted := make(chan struct{})
	stop := context.AfterFunc(bounded, func() {
		abort()
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	ready := make([]byte, len(Ready))
	if bounded.Err() != nil {
		return ErrDenied
	}
	if _, err := io.ReadFull(output, ready); err != nil || string(ready) != Ready || bounded.Err() != nil {
		return ErrDenied
	}
	if err := verify(bounded); err != nil || bounded.Err() != nil {
		return ErrDenied
	}
	n, err := io.WriteString(input, Permit)
	if err != nil || n != len(Permit) || bounded.Err() != nil {
		return ErrDenied
	}
	return nil
}
