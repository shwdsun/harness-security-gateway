//go:build linux && amd64 && codexintegration

package main

import (
	"context"
	"database/sql"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxstore"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestIsolatedNativeWindow(t *testing.T) {
	start := time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		now  time.Time
		want bool
	}{{start.Add(-time.Nanosecond), false}, {start, true}, {start.Add(24*time.Hour - 600*time.Second - time.Nanosecond), true}, {start.Add(24*time.Hour - 600*time.Second), false}} {
		if isolatedNativeWithinWindow(tc.now) != tc.want {
			t.Fatal("complete native service budget not reserved")
		}
	}
}

func TestIsolatedNativeProviderConnectionEvidence(t *testing.T) {
	tool := isolatedNativeProbe{ProviderConnectAttempted: true, ProviderConnectionClosed: true, ProviderConnectPath: "/run/hsg-provider.sock", ProviderConnectErrno: int(unix.EPERM), ProviderSocketDevice: 8, ProviderSocketInode: 17}
	control := isolatedNativeProbe{ProviderConnectAttempted: true, ProviderConnectionClosed: true, ProviderConnected: true, ProviderConnectErrno: 0, ProviderPeerUID: 1001, ProviderPeerPID: 77, ProviderSocketDevice: 8, ProviderSocketInode: 17}
	if !isolatedNativeProviderDenied(tool, control) {
		t.Fatal("paired live-object kernel denial rejected")
	}
	for _, code := range []int{0, int(unix.ENOENT), int(unix.ECONNREFUSED), int(unix.ETIMEDOUT), -1} {
		bad := tool
		bad.ProviderConnectErrno = code
		if isolatedNativeProviderDenied(bad, control) {
			t.Fatal("unobserved denial accepted", code)
		}
	}
	for _, fault := range []string{"connected", "not-attempted", "not-closed", "control-not-closed", "wrong-object", "wrong-peer", "dead-peer", "control-refused"} {
		badTool, badControl := tool, control
		switch fault {
		case "connected":
			badTool.ProviderConnected = true
		case "not-attempted":
			badTool.ProviderConnectAttempted = false
		case "not-closed":
			badTool.ProviderConnectionClosed = false
		case "control-not-closed":
			badControl.ProviderConnectionClosed = false
		case "wrong-object":
			badControl.ProviderSocketInode++
		case "wrong-peer":
			badControl.ProviderPeerUID = 0
		case "dead-peer":
			badControl.ProviderPeerPID = 0
		case "control-refused":
			badControl.ProviderConnected = false
		}
		if isolatedNativeProviderDenied(badTool, badControl) {
			t.Fatal("invalid paired provider observation accepted", fault)
		}
	}
}

func TestIsolatedNativeScanBoundary(t *testing.T) {
	needle := []byte("synthetic-owned-secret-canary")
	for _, kind := range []string{"clean", "secret", "symlink", "fifo", "oversize", "depth"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "file")
			switch kind {
			case "clean":
				if os.WriteFile(path, []byte("normal workspace content"), 0600) != nil {
					t.Fatal("fixture write failed")
				}
			case "secret":
				if os.WriteFile(path, append([]byte("prefix:"), needle...), 0600) != nil {
					t.Fatal("fixture write failed")
				}
			case "symlink":
				if os.Symlink(t.TempDir(), path) != nil {
					t.Fatal("fixture link failed")
				}
			case "fifo":
				if unix.Mkfifo(path, 0600) != nil {
					t.Fatal("fixture pipe failed")
				}
			case "oversize":
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				if f.Truncate(32<<20+1) != nil || f.Close() != nil {
					t.Fatal("fixture bound failed")
				}
			case "depth":
				for i := 0; i < 17; i++ {
					rootChild := filepath.Join(path, "d")
					if os.MkdirAll(rootChild, 0700) != nil {
						t.Fatal("fixture directory failed")
					}
					path = rootChild
				}
			}
			count, size, err := isolatedNativeScan([]string{root}, [][]byte{needle})
			if kind == "clean" {
				if err != nil || count != 1 || size != 24 {
					t.Fatal("positive scan control failed")
				}
			} else if err == nil {
				t.Fatal("unsafe scan surface accepted")
			}
		})
	}
}

func TestIsolatedNativeClosedEvidence(t *testing.T) {
	publication := filepath.Join(t.TempDir(), "published.json")
	if isolatedNativeWriteJSON(publication, struct{ Name string }{"fresh"}) != nil {
		t.Fatal("closed evidence publication failed")
	}
	before, err := os.ReadFile(publication)
	if err != nil || isolatedNativeWriteJSON(publication, struct{ Name string }{"replacement"}) == nil {
		t.Fatal("existing evidence replaced")
	}
	after, err := os.ReadFile(publication)
	if err != nil || string(before) != string(after) {
		t.Fatal("existing evidence changed")
	}
	root := t.TempDir()
	path := filepath.Join(root, "result.json")
	if os.WriteFile(path, []byte(`{"Name":"fresh"} {"Name":"inference401"}`), 0600) != nil {
		t.Fatal("fixture write failed")
	}
	var v struct{ Name string }
	if isolatedNativeReadJSON(path, &v, 1024) == nil {
		t.Fatal("two JSON documents accepted")
	}
	if os.WriteFile(path, []byte(`{"Name":"fresh","Unknown":true}`), 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if isolatedNativeReadJSON(path, &v, 1024) == nil {
		t.Fatal("unknown evidence fields accepted")
	}
	if os.WriteFile(path, []byte(`{"Name":"fresh"}`), 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if isolatedNativeReadJSON(path, &v, 1024) != nil || v.Name != "fresh" {
		t.Fatal("positive evidence control failed")
	}
	if isolatedNativeReadJSON(path, &v, 4) == nil {
		t.Fatal("oversized evidence accepted")
	}
	if os.Symlink(path, filepath.Join(root, "link")) != nil {
		t.Fatal("fixture link failed")
	}
	if isolatedNativeReadJSON(filepath.Join(root, "link"), &v, 1024) == nil {
		t.Fatal("linked evidence accepted")
	}
	pipe := filepath.Join(root, "pipe")
	if unix.Mkfifo(pipe, 0600) != nil {
		t.Fatal("fixture pipe failed")
	}
	done := make(chan bool, 1)
	go func() { done <- isolatedNativeReadJSON(pipe, &v, 1024) != nil && isolatedNativeFileSHA(pipe) == "" }()
	select {
	case refused := <-done:
		if !refused {
			t.Fatal("special evidence accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("evidence open blocked on FIFO")
	}
	if isolatedNativeFileSHA(filepath.Join(root, "link")) != "" || isolatedNativeFileSHA(path) == "" {
		t.Fatal("file hash evidence controls failed")
	}
}

// Exercise independent authority observation against revoked, occupied,
// superseded and incorrectly scoped records, without dispatching any Run.
func TestIsolatedNativeCurrentSource(t *testing.T) {
	t.Run("production-registration", func(t *testing.T) {
		ctx := context.Background()
		path := filepath.Join(t.TempDir(), "actual.db")
		store, err := sandboxstore.Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		g := sandboxstore.CredentialGeneration{SlotRef: "dedicated", Generation: 1, SourceDigest: strings.Repeat("b", 64), WorkspaceRef: "workspace", AuthProfileRef: "test.auth", ScopeDigest: strings.Repeat("c", 64)}
		proof := credentialsource.Proof{Scheme: credentialsource.EnrollmentScheme, RootObjectDigest: strings.Repeat("d", 64), SlotObjectDigest: strings.Repeat("e", 64), LocatorDigest: strings.Repeat("f", 64)}
		base := strings.Repeat("a", 64)
		a := sandboxstore.EnrolledTargetAuthority{Target: sandboxstore.TargetAuthority{TargetID: "enrolled-target", TargetRevision: "enrolled-r1", RevisionPin: base, RunnerStateKind: targetmanifest.RunnerStateNone, Credential: &sandboxstore.CredentialRef{SlotRef: g.SlotRef, Generation: g.Generation}}, Scope: &sandboxstore.CredentialTargetScope{WorkspaceRef: g.WorkspaceRef, AuthProfileRef: g.AuthProfileRef, ScopeDigest: g.ScopeDigest}}
		if store.RegisterCredentialEnrollment(ctx, g, proof) != nil || store.RegisterEnrolledTargetAuthorities(ctx, []sandboxstore.EnrolledTargetAuthority{a}) != nil {
			t.Fatal("actual registration failed")
		}
		pin := isolatedNativeEnrolledPin(base, g, proof)
		if pin != "a5d835db77f7eed9acc1a79901a276306431e1660545d2005213d19e5b4735f6" || isolatedNativeCurrentSource(ctx, path, g, a.Target.TargetID, a.Target.TargetRevision, pin) != nil {
			t.Fatal("actual enrolled pin observation failed")
		}
		if isolatedNativeCurrentSource(ctx, path, g, a.Target.TargetID, a.Target.TargetRevision, base) == nil {
			t.Fatal("base pin accepted as credential authority")
		}
		if store.RevokeCredentialGeneration(ctx, *a.Target.Credential) != nil || isolatedNativeCurrentSource(ctx, path, g, a.Target.TargetID, a.Target.TargetRevision, pin) == nil {
			t.Fatal("revoked actual enrollment accepted")
		}
	})
	for _, kind := range []string{"current", "revoked", "busy", "superseded", "wrong-pin", "wrong-scope"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			statements := []string{
				`CREATE TABLE credential_generations(slot_ref TEXT,generation INTEGER,source_digest TEXT,workspace_ref TEXT,auth_profile_ref TEXT,scope_digest TEXT)`,
				`CREATE TABLE target_credentials(target_id TEXT,target_revision TEXT,slot_ref TEXT,generation INTEGER)`,
				`CREATE TABLE target_revisions(target_id TEXT,revision TEXT,semantic_fingerprint TEXT)`,
				`CREATE TABLE credential_revocations(slot_ref TEXT,generation INTEGER)`,
				`CREATE TABLE credential_occupancy(slot_ref TEXT,source_digest TEXT)`,
				`INSERT INTO credential_generations VALUES('slot',1,'source','workspace','profile','scope')`,
				`INSERT INTO target_credentials VALUES('target','revision','slot',1)`,
				`INSERT INTO target_revisions VALUES('target','revision','pin')`,
			}
			for _, statement := range statements {
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			g := sandboxstore.CredentialGeneration{SlotRef: "slot", Generation: 1, SourceDigest: "source", WorkspaceRef: "workspace", AuthProfileRef: "profile", ScopeDigest: "scope"}
			pin := "pin"
			var mutation string
			switch kind {
			case "revoked":
				mutation = `INSERT INTO credential_revocations VALUES('slot',1)`
			case "busy":
				mutation = `INSERT INTO credential_occupancy VALUES('slot','source')`
			case "superseded":
				mutation = `INSERT INTO credential_generations VALUES('slot',2,'source','workspace','profile','scope')`
			case "wrong-pin":
				pin = "different"
			case "wrong-scope":
				g.ScopeDigest = "different"
			}
			if mutation != "" {
				if _, err := db.Exec(mutation); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = isolatedNativeCurrentSource(ctx, path, g, "target", "revision", pin)
			if (err == nil) != (kind == "current") {
				t.Fatal("current exact source authority misclassified")
			}
		})
	}
}
