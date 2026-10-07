//go:build linux && amd64

package codexprovider

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func waitNativeEOFMarker(t *testing.T, o *ownerNativeConsumer) *nativeAccountProcess {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if data, err := os.ReadFile(filepath.Join(o.root, "fixture-eof")); err == nil && string(data) == "EOF_AFTER_ACCOUNT\n" {
			o.mu.Lock()
			defer o.mu.Unlock()
			if o.active == nil || o.active.process == nil {
				t.Fatal("EOF barrier did not retain a live invocation")
			}
			return o.active.process
		}
		select {
		case <-timer.C:
			t.Fatal("helper did not reach post-account EOF barrier")
		case <-ticker.C:
		}
	}
}

func TestNativeConsumerNormalEOFGraceAndCancellation(t *testing.T) {
	files := nativeTestFiles(t)
	t.Run("natural", func(t *testing.T) {
		o, source := nativeTestConsumer(t, files, "delayed-eof")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		auth, refreshed, err := o.resolve(ctx, true)
		if err != nil || auth == nil || !refreshed || source.invalid || source.commits != 1 || o.active != nil {
			t.Fatal("normal delayed EOF was not accepted after complete refresh and joins")
		}
		entries, err := filepath.Glob(filepath.Join(o.root, "native-auth-*"))
		if err != nil || len(entries) != 0 {
			t.Fatal("normal EOF retained a private auth home")
		}
	})
	for _, action := range []string{"cancel", "close"} {
		t.Run(action, func(t *testing.T) {
			o, source := nativeTestConsumer(t, files, "delayed-eof")
			live, cancel := context.WithCancel(context.Background())
			defer cancel()
			resolved := make(chan error, 1)
			go func() { _, _, err := o.resolve(live, true); resolved <- err }()
			process := waitNativeEOFMarker(t, o)
			start := time.Now()
			if action == "cancel" {
				cancel()
			} else {
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				if err := o.close(cleanup); err != nil {
					stop()
					t.Fatal("close did not interrupt normal EOF wait")
				}
				stop()
			}
			select {
			case err := <-resolved:
				if err == nil {
					t.Fatal("post-EOF cancellation admitted a Commit")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation waited for the six-second natural EOF")
			}
			if time.Since(start) >= 3*time.Second || !source.invalid || source.commits != 0 || o.active != nil {
				t.Fatal("cancellation did not promptly reject and join before Commit")
			}
			process.stopMu.Lock()
			joined, forced := process.released, process.forced
			process.stopMu.Unlock()
			if !joined || !forced {
				t.Fatal("canceled normal wait did not join its forced cleanup")
			}
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if o.close(cleanup) != nil {
				t.Fatal("joined cancellation retained a cleanup obligation")
			}
		})
	}
}
