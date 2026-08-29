package agentconfig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
)

func fixture() Config {
	return Config{
		Schema:                  SchemaV3,
		Database:                "/var/lib/harness-gateway/agentd.sqlite3",
		SandboxSocket:           "/run/harness-gateway/sandboxd.sock",
		RunTimeoutSeconds:       300,
		DeliveryLeaseSeconds:    30,
		RunDispatchLeaseSeconds: 30,
		Ingress: Ingress{
			AcceptWindowSeconds: 300, ReceiptWindowSeconds: 3600, FutureSkewSeconds: 60,
			MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16,
			MaxNonTerminalRunsPerConnector: 32, MaxPendingDeliveriesPerConnector: 128,
			MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16_384,
		},
		Connectors: []Connector{{
			ID: "fake-personal", Socket: "/run/harness-gateway/connectors/fake-personal/agentd.sock",
			PeerUID: 1000, SelfActorRef: "user/bot",
		}},
		Bindings: []Binding{{
			ID: "operator-private", ConnectorID: "fake-personal",
			ActorRef: "user/demo", ConversationRef: "dm/demo",
			Target: TargetRef{ID: "project-codex", Revision: "project-codex-r1"},
		}},
	}
}

func TestIngressBoundsAreExplicitAndOrdered(t *testing.T) {
	tests := []func(*Config){
		func(config *Config) { config.Ingress = Ingress{} },
		func(config *Config) { config.Ingress.ReceiptWindowSeconds = config.Ingress.AcceptWindowSeconds },
		func(config *Config) {
			config.Ingress.MaxQueuedRunsPerConnector = config.Ingress.MaxNonTerminalRunsPerConnector + 1
		},
		func(config *Config) { config.Ingress.MaxDatabasePages = 63 },
	}
	for index, mutate := range tests {
		config := fixture()
		mutate(&config)
		if err := config.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d error = %v, want ErrInvalid", index, err)
		}
	}
}

func TestValidate(t *testing.T) {
	config := fixture()
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	config.Bindings = append(config.Bindings, Binding{
		ID: "duplicate-authority", ConnectorID: "fake-personal",
		ActorRef: "user/demo", ConversationRef: "dm/demo",
		Target: TargetRef{ID: "project-other", Revision: "r2"},
	})
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate exact binding error = %v", err)
	}
}

func TestProcessLockPathIsDatabaseScopedAndClean(t *testing.T) {
	config := fixture()
	config.Database = "/var/lib/harness-gateway/nested/../agentd.sqlite3"
	want := "/var/lib/harness-gateway/agentd.sqlite3.lock"
	if got := config.ProcessLockPath(); got != want {
		t.Fatalf("ProcessLockPath() = %q, want %q", got, want)
	}
}

func TestControlPathsRejectProcessLockCollisions(t *testing.T) {
	config := fixture()
	config.SandboxSocket = config.ProcessLockPath()
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("sandbox/process-lock collision error = %v, want ErrInvalid", err)
	}

	config = fixture()
	config.Connectors[0].Socket = config.ProcessLockPath()
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("connector/process-lock collision error = %v, want ErrInvalid", err)
	}
}

func TestSchemaAndBindingLabelsAreClosed(t *testing.T) {
	config := fixture()
	config.Schema = "agentd/v2"
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("legacy schema error = %v, want ErrInvalid", err)
	}
	config = fixture()
	second := config.Bindings[0]
	second.ActorRef = "user/second"
	config.Bindings = append(config.Bindings, second)
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate binding label error = %v, want ErrInvalid", err)
	}
}

func TestBindingsMustReferenceConnectorAndExcludeSelf(t *testing.T) {
	tests := []func(*Config){
		func(config *Config) { config.Bindings[0].ConnectorID = "missing" },
		func(config *Config) { config.Bindings[0].ActorRef = config.Connectors[0].SelfActorRef },
		func(config *Config) { config.Bindings[0].Target = TargetRef{} },
		func(config *Config) { config.Bindings = nil },
		func(config *Config) { config.Bindings[0].ActorRef = string([]byte{0xff}) },
		func(config *Config) { config.Connectors[0].SelfActorRef = string([]byte{0xfe}) },
	}
	for index, mutate := range tests {
		config := fixture()
		mutate(&config)
		if err := config.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d error = %v, want ErrInvalid", index, err)
		}
	}
}

func TestPeerUIDIsExplicitAndClosed(t *testing.T) {
	for _, uid := range []localidentity.UID{0, localidentity.NobodyUID, localidentity.InvalidUID} {
		config := fixture()
		config.Connectors[0].PeerUID = uid
		if err := config.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("UID %d error = %v, want ErrInvalid", uid, err)
		}
	}
	for _, uid := range []localidentity.UID{1, 1000, localidentity.NobodyUID - 1, localidentity.NobodyUID + 1, localidentity.InvalidUID - 1} {
		config := fixture()
		config.Connectors[0].PeerUID = uid
		if err := config.Validate(); err != nil {
			t.Fatalf("UID %d rejected: %v", uid, err)
		}
	}
}

func TestLoadRejectsNonIntegerAndOutOfRangePeerUID(t *testing.T) {
	directory := t.TempDir()
	data, err := json.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agentd.json")
	for _, value := range []string{"-1", "1.5", "4294967296", `"1000"`} {
		document := strings.Replace(string(data), `"peer_uid":1000`, `"peer_uid":`+value, 1)
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("peer_uid %s unexpectedly loaded", value)
		}
	}
	document := strings.Replace(string(data), `"peer_uid":1000,`, "", 1)
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing peer_uid error = %v, want ErrInvalid", err)
	}
}

func TestLoadResolvesRelativePathsAndRejectsUnknown(t *testing.T) {
	directory := t.TempDir()
	config := fixture()
	config.Database = "runtime/agentd.sqlite3"
	config.SandboxSocket = "runtime/sandboxd.sock"
	config.Connectors[0].Socket = "runtime/connectors/fake-personal/agentd.sock"
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agentd.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Database != filepath.Join(directory, "runtime/agentd.sqlite3") {
		t.Fatalf("Database = %q", loaded.Database)
	}

	bad := strings.TrimSuffix(string(data), "}") + `,"platform_token":"secret"}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestSocketPathsMustBeUnique(t *testing.T) {
	config := fixture()
	config.Connectors[0].Socket = config.SandboxSocket
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate socket error = %v", err)
	}
	config = fixture()
	config.SandboxSocket = config.Database
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("sandbox/database collision error = %v", err)
	}
	config = fixture()
	config.Connectors[0].Socket = config.Database
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("connector/database collision error = %v", err)
	}
	config = fixture()
	config.Connectors[0].Socket = "/var/lib/harness-gateway/connector.sock"
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("connector directory exposes database error = %v", err)
	}
	config = fixture()
	second := config.Connectors[0]
	second.ID = "fake-secondary"
	second.Socket = "/run/harness-gateway/connectors/fake-personal/nested/agentd.sock"
	config.Connectors = append(config.Connectors, second)
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("shared connector directory error = %v", err)
	}
}
