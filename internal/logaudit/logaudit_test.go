package logaudit

import (
	"context"
	"database/sql"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/agentservice"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	_ "modernc.org/sqlite"
)

// marker is deliberately unlike any protocol value, so finding it anywhere
// means untrusted content escaped into a diagnostic.
const marker = "REDACTION-CANARY-8f3c1d"

// reviewed pins every string the long-lived services can write. A new or
// changed log line fails this test and must be reviewed instead of shipped.
var reviewed = map[string]map[string]bool{
	"cmd/agentd/main.go": {
		"agentd: %v\n": true, "agentd: ": true, "dispatch error: %s": true,
	},
	"cmd/sandboxd/main.go": {
		"sandboxd: %v\n": true,
		"configuration and fixed artifacts checked; no enrollment, runtime or provider operation performed": true,
	},
	"cmd/discord-connector/main.go": {
		"discord-connector: %v\n": true, "discord-connector: ": true, "cycle error: %v": true,
	},
}

func TestDeployedServiceLogSurfaceIsPinned(t *testing.T) {
	for file, permitted := range reviewed {
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", file), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch selector.Sel.Name {
			case "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln", "New":
			default:
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch receiver.Name {
			case "fmt", "log", "logger":
			default:
				return true
			}
			for _, argument := range call.Args {
				literal, ok := argument.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				if value, err := strconv.Unquote(literal.Value); err == nil && value != "" {
					found[value] = true
				}
			}
			return true
		})
		for value := range found {
			if !permitted[value] {
				t.Fatalf("%s writes an unreviewed diagnostic %q", file, value)
			}
		}
		for value := range permitted {
			if !found[value] {
				t.Fatalf("%s no longer contains the reviewed diagnostic %q", file, value)
			}
		}
	}
}

func denialChain(t *testing.T) (*agentservice.Service, string) {
	t.Helper()
	directory := t.TempDir()
	database := filepath.Join(directory, "core.sqlite3")
	config := agentconfig.Config{
		Schema: agentconfig.SchemaV3, Database: database,
		SandboxSocket:           filepath.Join(directory, "sandbox", "sandboxd.sock"),
		RunTimeoutSeconds:       300,
		DeliveryLeaseSeconds:    30,
		RunDispatchLeaseSeconds: 30,
		Ingress: agentconfig.Ingress{
			AcceptWindowSeconds: 300, ReceiptWindowSeconds: 3600, FutureSkewSeconds: 60,
			MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16,
			MaxNonTerminalRunsPerConnector: 32, MaxPendingDeliveriesPerConnector: 128,
			MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16_384,
		},
		Connectors: []agentconfig.Connector{{
			ID: "audit-connector", Socket: filepath.Join(directory, "connector", "agentd.sock"),
			PeerUID: localidentity.UID(os.Geteuid()), SelfActorRef: "bot",
		}},
		Bindings: []agentconfig.Binding{{
			ID: "audit-binding", ConnectorID: "audit-connector",
			ActorRef: "operator", ConversationRef: "private",
			Target: agentconfig.TargetRef{ID: "project-codex", Revision: "r1"},
		}},
	}
	policy, err := agentpolicy.Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policy.Endpoint("audit-connector")
	if err != nil {
		t.Fatal(err)
	}
	store, err := corestore.Open(context.Background(), database, corestore.Options{
		Admission: corestore.AdmissionOptions{
			AcceptWindow: 5 * time.Minute, ReceiptWindow: time.Hour, FutureSkew: time.Minute,
			MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16,
			MaxNonTerminalRunsPerConnector: 32, MaxPendingDeliveriesPerConnector: 128,
			MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16_384,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	service, err := agentservice.New(endpoint, 30*time.Second, store)
	if err != nil {
		t.Fatal(err)
	}
	return service, database
}

func event(id, actor, text string, occurred int64) connectorwire.InboundEventV1 {
	return connectorwire.InboundEventV1{
		EventID: id, ActorRef: actor, ConversationRef: "private", MessageRef: id,
		OccurredAtUnixMS: occurred,
		Content:          connectorwire.InboundContentV1{Type: connectorwire.ContentTypeText, Text: text},
	}
}

func TestDeniedEventTextNeverReachesAnErrorOrLogLine(t *testing.T) {
	service, database := denialChain(t)
	ctx := context.Background()
	now := time.Now().UTC().UnixMilli()
	if _, err := service.Ingest(ctx, event("audit-1", "operator", "benign admitted text", now)); err != nil {
		t.Fatalf("baseline admission failed: %v", err)
	}
	cases := map[string]connectorwire.InboundEventV1{
		"unbound actor":      event("audit-2", "intruder", marker+" unbound", now),
		"conflicting replay": event("audit-1", "operator", marker+" conflict", now),
		"oversize text":      event("audit-3", "operator", marker+strings.Repeat("a", connectorwire.MaxTextBytes), now),
		"stale event":        event("audit-4", "operator", marker+" stale", now-2*60*60*1000),
		"self actor":         event("audit-5", "bot", marker+" self", now),
	}
	for name, denied := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := service.Ingest(ctx, denied)
			if err == nil {
				t.Fatal("expected a denial")
			}
			// Everything an operator could see: the error, its verbose form and
			// the exact line the connector would log.
			for label, text := range map[string]string{
				"Error()":   err.Error(),
				"%v":        fmt.Sprintf("%v", err),
				"%+v":       fmt.Sprintf("%+v", err),
				"cycle log": fmt.Sprintf("cycle error: %v", fmt.Errorf("ingest event: %w", err)),
			} {
				if strings.Contains(text, marker) {
					t.Fatalf("%s disclosed denied message text: %s", label, text)
				}
			}
		})
	}
	db, err := sql.Open("sqlite", database+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT input_text FROM runs`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, marker) {
			t.Fatal("denied message text was retained in Core")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
