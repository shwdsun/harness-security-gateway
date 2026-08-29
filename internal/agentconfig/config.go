// Package agentconfig defines agentd's local operator configuration. It
// contains routing authority but never platform or model credentials.
package agentconfig

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const (
	SchemaV3        = "agentd/v3"
	MaxConfigBytes  = 1 << 20
	MaxJSONDepth    = 12
	MaxRefBytes     = 256
	MaxLeaseSeconds = 10 * 60
)

var ErrInvalid = errors.New("invalid agentd configuration")

type TargetRef struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

type Connector struct {
	ID           string            `json:"id"`
	Socket       string            `json:"socket"`
	PeerUID      localidentity.UID `json:"peer_uid"`
	SelfActorRef string            `json:"self_actor_ref"`
}

// Binding is one exact run.create grant. Binding ID is an operator label only;
// authorization identity is derived from the remaining authority fields.
type Binding struct {
	ID              string    `json:"id"`
	ConnectorID     string    `json:"connector_id"`
	ActorRef        string    `json:"actor_ref"`
	ConversationRef string    `json:"conversation_ref"`
	Target          TargetRef `json:"target"`
}

type Config struct {
	Schema                  string      `json:"schema"`
	Database                string      `json:"database"`
	SandboxSocket           string      `json:"sandbox_socket"`
	RunTimeoutSeconds       int64       `json:"run_timeout_seconds"`
	DeliveryLeaseSeconds    int64       `json:"delivery_lease_seconds"`
	RunDispatchLeaseSeconds int64       `json:"run_dispatch_lease_seconds"`
	Ingress                 Ingress     `json:"ingress"`
	Connectors              []Connector `json:"connectors"`
	Bindings                []Binding   `json:"bindings"`
}

// ProcessLockPath is derived from the exact Core database authority. Processes
// that can write the same database must acquire this persistent lock first.
func (c Config) ProcessLockPath() string {
	return filepath.Clean(c.Database) + ".lock"
}

// Ingress contains mandatory operator-selected replay and persistence bounds.
// No field has an implicit production default.
type Ingress struct {
	AcceptWindowSeconds               int64 `json:"accept_window_seconds"`
	ReceiptWindowSeconds              int64 `json:"receipt_window_seconds"`
	FutureSkewSeconds                 int64 `json:"future_skew_seconds"`
	MaxReceiptsPerConnector           int64 `json:"max_receipts_per_connector"`
	MaxQueuedRunsPerConnector         int64 `json:"max_queued_runs_per_connector"`
	MaxNonTerminalRunsPerConnector    int64 `json:"max_nonterminal_runs_per_connector"`
	MaxPendingDeliveriesPerConnector  int64 `json:"max_pending_deliveries_per_connector"`
	MaxRetainedInputBytesPerConnector int64 `json:"max_retained_input_bytes_per_connector"`
	MaxDatabasePages                  int64 `json:"max_database_pages"`
}

// Load decodes a config and resolves its local paths relative to the config
// file. The result contains absolute paths so later components cannot depend
// on process working directory.
func Load(path string) (Config, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve config path: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return Config{}, fmt.Errorf("inspect agentd config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&0o022 != 0 {
		return Config{}, fmt.Errorf("%w: config must be a regular file not writable by group or others", ErrInvalid)
	}
	file, err := os.Open(absolute)
	if err != nil {
		return Config{}, fmt.Errorf("open agentd config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read agentd config: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("%w: file exceeds byte limit", ErrInvalid)
	}
	var config Config
	if err := strictjson.Decode(data, MaxConfigBytes, MaxJSONDepth, &config); err != nil {
		return Config{}, err
	}
	base := filepath.Dir(absolute)
	config.Database, err = resolvePath(base, config.Database)
	if err != nil {
		return Config{}, invalid("database", err.Error())
	}
	config.SandboxSocket, err = resolvePath(base, config.SandboxSocket)
	if err != nil {
		return Config{}, invalid("sandbox_socket", err.Error())
	}
	for index := range config.Connectors {
		config.Connectors[index].Socket, err = resolvePath(base, config.Connectors[index].Socket)
		if err != nil {
			return Config{}, invalid(fmt.Sprintf("connectors[%d].socket", index), err.Error())
		}
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Schema != SchemaV3 {
		return invalid("schema", "must be agentd/v3")
	}
	if !filepath.IsAbs(c.Database) {
		return invalid("database", "must resolve to an absolute path")
	}
	if !filepath.IsAbs(c.SandboxSocket) {
		return invalid("sandbox_socket", "must resolve to an absolute path")
	}
	if filepath.Clean(c.Database) == filepath.Clean(c.SandboxSocket) {
		return invalid("sandbox_socket", "must not equal database")
	}
	processLock := c.ProcessLockPath()
	if processLock == filepath.Clean(c.Database) {
		return invalid("database", "must not equal process lock")
	}
	if processLock == filepath.Clean(c.SandboxSocket) {
		return invalid("sandbox_socket", "must not equal process lock")
	}
	if c.RunTimeoutSeconds < 1 || c.RunTimeoutSeconds > 24*60*60 {
		return invalid("run_timeout_seconds", "must be between 1 and 86400")
	}
	if c.DeliveryLeaseSeconds < 1 || c.DeliveryLeaseSeconds > MaxLeaseSeconds {
		return invalid("delivery_lease_seconds", "must be between 1 and 600")
	}
	if c.RunDispatchLeaseSeconds < 1 || c.RunDispatchLeaseSeconds > MaxLeaseSeconds {
		return invalid("run_dispatch_lease_seconds", "must be between 1 and 600")
	}
	if err := c.Ingress.validate(); err != nil {
		return err
	}
	if len(c.Connectors) == 0 {
		return invalid("connectors", "must not be empty")
	}
	seenIDs := make(map[string]struct{}, len(c.Connectors))
	seenPaths := map[string]string{
		filepath.Clean(c.Database):      "database",
		filepath.Clean(c.SandboxSocket): "sandbox_socket",
		processLock:                     "process_lock",
	}
	connectorDirs := make(map[string]string, len(c.Connectors))
	for index := range c.Connectors {
		connector := c.Connectors[index]
		field := fmt.Sprintf("connectors[%d]", index)
		if err := connector.PeerUID.Validate(); err != nil {
			return invalid(field+".peer_uid", err.Error())
		}
		if err := validateName(field+".id", connector.ID, 128); err != nil {
			return err
		}
		if _, exists := seenIDs[connector.ID]; exists {
			return invalid(field+".id", "is duplicated")
		}
		seenIDs[connector.ID] = struct{}{}
		if !filepath.IsAbs(connector.Socket) {
			return invalid(field+".socket", "must resolve to an absolute path")
		}
		cleanSocket := filepath.Clean(connector.Socket)
		if owner, exists := seenPaths[cleanSocket]; exists {
			return invalid(field+".socket", "duplicates "+owner)
		}
		seenPaths[cleanSocket] = field + ".socket"
		directory := filepath.Dir(cleanSocket)
		if directory == string(filepath.Separator) {
			return invalid(field+".socket", "must be inside a dedicated non-root directory")
		}
		if pathWithin(c.Database, directory) || pathWithin(c.SandboxSocket, directory) ||
			pathWithin(processLock, directory) {
			return invalid(field+".socket", "directory must not expose the database, process lock, or sandbox socket")
		}
		for existingDirectory, owner := range connectorDirs {
			if pathsOverlap(directory, existingDirectory) {
				return invalid(field+".socket", "directory overlaps "+owner)
			}
		}
		connectorDirs[directory] = field + ".socket"
		if err := connector.validate(field); err != nil {
			return err
		}
	}
	if len(c.Bindings) == 0 {
		return invalid("bindings", "must not be empty")
	}
	seenBindingIDs := make(map[string]struct{}, len(c.Bindings))
	type bindingKey struct {
		connectorID, actorRef, conversationRef string
	}
	seenBindings := make(map[bindingKey]struct{}, len(c.Bindings))
	connectorsByID := make(map[string]Connector, len(c.Connectors))
	for _, connector := range c.Connectors {
		connectorsByID[connector.ID] = connector
	}
	for index, binding := range c.Bindings {
		field := fmt.Sprintf("bindings[%d]", index)
		if err := validateName(field+".id", binding.ID, 128); err != nil {
			return err
		}
		if _, exists := seenBindingIDs[binding.ID]; exists {
			return invalid(field+".id", "is duplicated")
		}
		seenBindingIDs[binding.ID] = struct{}{}
		connector, exists := connectorsByID[binding.ConnectorID]
		if !exists {
			return invalid(field+".connector_id", "does not reference a configured connector")
		}
		if err := validateOpaqueRef(field+".actor_ref", binding.ActorRef); err != nil {
			return err
		}
		if binding.ActorRef == connector.SelfActorRef {
			return invalid(field+".actor_ref", "must not equal the connector self actor")
		}
		if err := validateOpaqueRef(field+".conversation_ref", binding.ConversationRef); err != nil {
			return err
		}
		if err := binding.Target.validate(field + ".target"); err != nil {
			return err
		}
		key := bindingKey{binding.ConnectorID, binding.ActorRef, binding.ConversationRef}
		if _, exists := seenBindings[key]; exists {
			return invalid(field, "duplicates an exact connector/actor/conversation binding")
		}
		seenBindings[key] = struct{}{}
	}
	return nil
}

func (i Ingress) validate() error {
	if i.AcceptWindowSeconds < 1 || i.AcceptWindowSeconds > 30*24*60*60 {
		return invalid("ingress.accept_window_seconds", "must be between 1 and 2592000")
	}
	if i.ReceiptWindowSeconds <= i.AcceptWindowSeconds || i.ReceiptWindowSeconds > 365*24*60*60 {
		return invalid("ingress.receipt_window_seconds", "must exceed accept_window_seconds and be at most 31536000")
	}
	if i.FutureSkewSeconds < 0 || i.FutureSkewSeconds > 24*60*60 {
		return invalid("ingress.future_skew_seconds", "must be between 0 and 86400")
	}
	for field, value := range map[string]int64{
		"max_receipts_per_connector":           i.MaxReceiptsPerConnector,
		"max_queued_runs_per_connector":        i.MaxQueuedRunsPerConnector,
		"max_nonterminal_runs_per_connector":   i.MaxNonTerminalRunsPerConnector,
		"max_pending_deliveries_per_connector": i.MaxPendingDeliveriesPerConnector,
	} {
		if value < 1 || value > 1_000_000_000 {
			return invalid("ingress."+field, "must be between 1 and 1000000000")
		}
	}
	if i.MaxQueuedRunsPerConnector > i.MaxNonTerminalRunsPerConnector {
		return invalid("ingress.max_queued_runs_per_connector", "must not exceed max_nonterminal_runs_per_connector")
	}
	if i.MaxRetainedInputBytesPerConnector < 32*1024 || i.MaxRetainedInputBytesPerConnector > 1<<40 {
		return invalid("ingress.max_retained_input_bytes_per_connector", "must be between 32768 and 1099511627776")
	}
	if i.MaxDatabasePages < 64 || i.MaxDatabasePages > 2_147_483_646 {
		return invalid("ingress.max_database_pages", "must be between 64 and 2147483646")
	}
	return nil
}

func (c Connector) validate(field string) error {
	return validateOpaqueRef(field+".self_actor_ref", c.SelfActorRef)
}

func (r TargetRef) validate(field string) error {
	if err := validateName(field+".id", r.ID, 128); err != nil {
		return err
	}
	return validateName(field+".revision", r.Revision, 160)
}

func validateOpaqueRef(field, value string) error {
	if value == "" || len(value) > MaxRefBytes || !utf8.ValidString(value) {
		return invalid(field, "has invalid byte length or encoding")
	}
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return invalid(field, "must not contain whitespace or control characters")
		}
	}
	return nil
}

func validateName(field, value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes {
		return invalid(field, "has invalid byte length")
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-_.:@", rune(char)) {
			continue
		}
		return invalid(field, "contains unsupported characters")
	}
	return nil
}

func resolvePath(base, value string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("must not be empty or contain NUL")
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(base, value)
	}
	return filepath.Clean(value), nil
}

func pathsOverlap(first, second string) bool {
	return pathWithin(first, second) || pathWithin(second, first)
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func invalid(field, problem string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalid, field, problem)
}
