//go:build linux

// Package bootstrapgate implements the private, one-use pre-HRP launch phase.
// It carries no command, path, configuration or credential. The trusted runtime
// must independently verify the mounted source before sending Permit.
package bootstrapgate

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	Ready     = "hsg-bootstrap/v1 ready\n"
	Permit    = "hsg-bootstrap/v1 permit\n"
	WaitLimit = 10 * time.Second
)

var ErrDenied = errors.New("bootstrapgate: launch denied")

// Await reads exactly one permit without buffering subsequent HRP bytes. The
// caller must exec a fixed Runner only on success, preserving ordinary stdio.
// EOF, cancellation, timeout and a malformed or already queued extra frame
// cannot grant launch. A later permit is only invalid Runner input: this parser
// disappears on exec and cannot grant another launch.
func Await(ctx context.Context, input *os.File, output io.Writer) error {
	if ctx == nil || ctx.Err() != nil || input == nil || output == nil {
		return ErrDenied
	}
	fd, err := unix.FcntlInt(input.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return ErrDenied
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		_ = unix.Close(fd)
		return ErrDenied
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || unix.SetNonblock(fd, true) != nil {
		_ = unix.Close(fd)
		return ErrDenied
	}
	reader := os.NewFile(uintptr(fd), "bootstrap-input")
	defer func() {
		_ = unix.SetNonblock(fd, flags&unix.O_NONBLOCK != 0)
		_ = reader.Close()
	}()
	deadline := time.Now().Add(WaitLimit)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if reader.SetReadDeadline(deadline) != nil {
		return ErrDenied
	}
	stop := context.AfterFunc(ctx, func() { _ = reader.SetReadDeadline(time.Now()) })
	defer stop()
	if n, err := io.WriteString(output, Ready); err != nil || n != len(Ready) {
		return ErrDenied
	}
	frame := make([]byte, len(Permit))
	if _, err := io.ReadFull(reader, frame); err != nil || string(frame) != Permit || ctx.Err() != nil || !time.Now().Before(deadline) {
		return ErrDenied
	}
	queued, err := unix.IoctlGetInt(fd, unix.TIOCINQ)
	if err != nil || queued != 0 {
		return ErrDenied
	}
	return nil
}
