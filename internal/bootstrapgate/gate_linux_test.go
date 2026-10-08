//go:build linux

package bootstrapgate

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestGatePreservesPipeAndRejectsUnapprovedLaunch(t *testing.T) {
	for _, name := range []string{"permit", "eof", "partial", "wrong", "extra", "cancel", "deadline"} {
		t.Run(name, func(t *testing.T) {
			input, owner, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer owner.Close()
			ready, output, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer ready.Close()
			defer output.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if name == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
			}
			done := make(chan error, 1)
			go func() { done <- Await(ctx, input, output) }()
			if err := ready.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			frame := make([]byte, len(Ready))
			if _, err := io.ReadFull(ready, frame); err != nil || string(frame) != Ready {
				t.Fatalf("no ready phase: %v", err)
			}
			switch name {
			case "permit":
				_, err = io.WriteString(owner, Permit)
			case "eof":
				err = owner.Close()
			case "partial":
				_, err = io.WriteString(owner, Permit[:3])
				_ = owner.Close()
			case "wrong":
				_, err = io.WriteString(owner, strings.Replace(Permit, "permit", "denied", 1))
			case "extra":
				_, err = io.WriteString(owner, Permit+Permit)
			case "cancel":
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
				if (err == nil) != (name == "permit") {
					t.Fatalf("unexpected launch verdict: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("gate did not stop")
			}
			flags, err := unix.FcntlInt(input.Fd(), unix.F_GETFL, 0)
			if err != nil || flags&unix.O_NONBLOCK != 0 {
				t.Fatal("gate changed original pipe flags")
			}
			if name == "permit" {
				if _, err := io.WriteString(owner, "hrp"); err != nil {
					t.Fatal(err)
				}
				tail := make([]byte, 3)
				if _, err := io.ReadFull(input, tail); err != nil || string(tail) != "hrp" {
					t.Fatal("gate consumed later Runner input")
				}
			}
		})
	}
}
