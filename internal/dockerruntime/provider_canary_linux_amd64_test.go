//go:build linux && amd64 && codexintegration

package dockerruntime

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

func TestCanaryObservation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("concrete non-root peer required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp(t.TempDir(), "p-")
	if err != nil {
		t.Fatal(err)
	}
	// Construction remains inert; no operation, credential or Docker is used.
	endpoint, err := codexprovider.NewLive(ctx, dir, localidentity.UID(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close(ctx)
	observation := &providerObservation{}
	if observation.snapshot() != nil {
		t.Fatal("missing endpoint presented as evidence")
	}
	observation.capture(endpoint)
	r := &Runtime{providers: map[string]runProvider{"canary": endpoint}}
	if err := r.CloseRunResources(ctx, "canary"); err != nil {
		t.Fatal(err)
	}
	if r.runProvider("canary") != nil {
		t.Fatal("diagnostics retained cleanup ownership")
	}
	d := observation.snapshot()
	if d == nil || !d.Joined || !d.Stopped || d.Opened || d.CleanupFailed || len(d.Exchanges) != 0 {
		t.Fatal("completed observation lost after ownership release")
	}
	observation.capture(endpoint)
	observation.capture(endpoint)
	if observation.snapshot() != nil {
		t.Fatal("multiple captures silently selected an endpoint")
	}
}
