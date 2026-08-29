// Package sandboxconfig loads sandboxd's local operator configuration.
// Authority-bearing paths exist only here; none are accepted on executionwire.
package sandboxconfig

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/shwdsun/harness-security-gateway/internal/localidentity"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
	"github.com/shwdsun/harness-security-gateway/internal/targetregistry"
)

const (
	SchemaV2       = "sandboxd/v2"
	MaxConfigBytes = 1 << 20
	MaxJSONDepth   = 14
	MaxNameBytes   = 128
)

var ErrInvalid = errors.New("invalid sandboxd configuration")

type RuntimeKind string

const RuntimeRootlessDocker RuntimeKind = "rootless-docker"

type Runtime struct {
	Kind       RuntimeKind `json:"kind"`
	Endpoint   string      `json:"endpoint"`
	CLI        string      `json:"cli"`
	SocketPath string      `json:"-"`
}

// StorageEntry maps an opaque logical ref to one safe directory component
// below an operator-approved root. Ref is never used as a filesystem path.
type StorageEntry struct {
	Ref       string `json:"ref"`
	Directory string `json:"directory"`
}

type Config struct {
	Schema          string                    `json:"schema"`
	Socket          string                    `json:"socket"`
	PeerUID         localidentity.UID         `json:"peer_uid"`
	StateDatabase   string                    `json:"state_database"`
	WorkspaceRoot   string                    `json:"workspace_root"`
	RunnerStateRoot string                    `json:"runner_state_root"`
	Runtime         Runtime                   `json:"runtime"`
	Workspaces      []StorageEntry            `json:"workspaces"`
	RunnerStates    []StorageEntry            `json:"runner_states"`
	Targets         []targetmanifest.Manifest `json:"targets"`
}

// ProcessLockPath is deliberately global to the current OS user. V1 permits
// exactly one sandboxd execution authority per user: a DB-scoped or
// socket-scoped lock would still allow two differently configured daemons to
// share a runtime or overlap workspaces.
func (c Config) ProcessLockPath() string {
	return filepath.Join(
		string(filepath.Separator),
		"run",
		"user",
		strconv.Itoa(os.Geteuid()),
		"harness-gateway-sandboxd.lock",
	)
}

func Load(path string) (Config, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve sandboxd config path: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return Config{}, fmt.Errorf("inspect sandboxd config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return Config{}, fmt.Errorf("%w: config must be a regular non-symlink file not writable by group or others", ErrInvalid)
	}
	file, err := os.Open(absolute)
	if err != nil {
		return Config{}, fmt.Errorf("open sandboxd config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read sandboxd config: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("%w: file exceeds byte limit", ErrInvalid)
	}
	var config Config
	if err := strictjson.Decode(data, MaxConfigBytes, MaxJSONDepth, &config); err != nil {
		return Config{}, err
	}
	base := filepath.Dir(absolute)
	for field, value := range map[string]*string{
		"socket":            &config.Socket,
		"state_database":    &config.StateDatabase,
		"workspace_root":    &config.WorkspaceRoot,
		"runner_state_root": &config.RunnerStateRoot,
	} {
		resolved, err := resolvePath(base, *value)
		if err != nil {
			return Config{}, invalid(field, err.Error())
		}
		*value = resolved
	}
	if config.Runtime.CLI != "" && !filepath.IsAbs(config.Runtime.CLI) {
		return Config{}, invalid("runtime.cli", "must be an absolute path")
	}
	socketPath, err := parseUnixEndpoint(config.Runtime.Endpoint)
	if err != nil {
		return Config{}, invalid("runtime.endpoint", err.Error())
	}
	config.Runtime.SocketPath = socketPath
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Schema != SchemaV2 {
		return invalid("schema", "must be sandboxd/v2")
	}
	if err := c.PeerUID.Validate(); err != nil {
		return invalid("peer_uid", err.Error())
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"socket", c.Socket},
		{"state_database", c.StateDatabase},
		{"workspace_root", c.WorkspaceRoot},
		{"runner_state_root", c.RunnerStateRoot},
		{"runtime.cli", c.Runtime.CLI},
		{"runtime.socket_path", c.Runtime.SocketPath},
	} {
		if !filepath.IsAbs(field.value) || strings.ContainsRune(field.value, '\x00') {
			return invalid(field.name, "must be an absolute NUL-free path")
		}
	}
	if c.WorkspaceRoot == string(filepath.Separator) || c.RunnerStateRoot == string(filepath.Separator) {
		return invalid("storage roots", "must not be the filesystem root")
	}
	if pathsOverlap(c.WorkspaceRoot, c.RunnerStateRoot) {
		return invalid("storage roots", "workspace and runner-state roots must not overlap")
	}
	controlPaths := []struct {
		name string
		path string
	}{
		{"socket", c.Socket},
		{"state_database", c.StateDatabase},
		{"process_lock", c.ProcessLockPath()},
		{"runtime.socket_path", c.Runtime.SocketPath},
		{"runtime.cli", c.Runtime.CLI},
	}
	for _, control := range controlPaths {
		if pathWithin(control.path, c.WorkspaceRoot) || pathWithin(control.path, c.RunnerStateRoot) {
			return invalid(control.name, "must not be inside runner storage")
		}
	}
	for first := range controlPaths {
		for second := first + 1; second < len(controlPaths); second++ {
			if filepath.Clean(controlPaths[first].path) == filepath.Clean(controlPaths[second].path) {
				return invalid(controlPaths[second].name, "must not equal "+controlPaths[first].name)
			}
		}
	}
	if c.Runtime.Kind != RuntimeRootlessDocker {
		return invalid("runtime.kind", "must be rootless-docker")
	}
	endpointSocketPath, err := parseUnixEndpoint(c.Runtime.Endpoint)
	if err != nil || endpointSocketPath != c.Runtime.SocketPath || c.Runtime.Endpoint != "unix://"+endpointSocketPath {
		return invalid("runtime.endpoint", "must be a canonical unix:///absolute/path endpoint")
	}
	expectedRuntimeSocket := filepath.Join(
		string(filepath.Separator), "run", "user", strconv.Itoa(os.Geteuid()), "docker.sock",
	)
	if c.Runtime.SocketPath != expectedRuntimeSocket {
		return invalid(
			"runtime.endpoint",
			"must be the current user's direct local rootless Docker socket unix://"+expectedRuntimeSocket,
		)
	}
	if err := validateCLI(c.Runtime.CLI); err != nil {
		return err
	}

	workspaceRefs, err := validateStorageEntries("workspaces", c.Workspaces)
	if err != nil {
		return err
	}
	stateRefs, err := validateStorageEntries("runner_states", c.RunnerStates)
	if err != nil {
		return err
	}
	if len(c.Targets) == 0 {
		return invalid("targets", "must not be empty")
	}
	if _, err := targetregistry.New(c.Targets); err != nil {
		return invalid("targets", err.Error())
	}
	usedTargetStates := make(map[string]int, len(c.Targets))
	for index, target := range c.Targets {
		if _, exists := workspaceRefs[target.WorkspaceRef]; !exists {
			return invalid(fmt.Sprintf("targets[%d].workspace_ref", index), "does not map to an approved workspace")
		}
		if _, exists := stateRefs[target.StateRef]; !exists {
			return invalid(fmt.Sprintf("targets[%d].state_ref", index), "does not map to approved runner state")
		}
		if previous, exists := usedTargetStates[target.StateRef]; exists {
			return invalid(
				fmt.Sprintf("targets[%d].state_ref", index),
				fmt.Sprintf("must not share runner state with targets[%d]", previous),
			)
		}
		usedTargetStates[target.StateRef] = index
	}
	return nil
}

func (c Config) Registry() (*targetregistry.Registry, error) {
	return targetregistry.New(c.Targets)
}

func (c Config) WorkspacePath(ref string) (string, bool) {
	return storagePath(c.WorkspaceRoot, c.Workspaces, ref)
}

func (c Config) RunnerStatePath(ref string) (string, bool) {
	return storagePath(c.RunnerStateRoot, c.RunnerStates, ref)
}

func storagePath(root string, entries []StorageEntry, ref string) (string, bool) {
	for _, entry := range entries {
		if entry.Ref == ref {
			return filepath.Join(root, entry.Directory), true
		}
	}
	return "", false
}

func validateStorageEntries(field string, entries []StorageEntry) (map[string]struct{}, error) {
	if len(entries) == 0 {
		return nil, invalid(field, "must not be empty")
	}
	refs := make(map[string]struct{}, len(entries))
	directories := make(map[string]struct{}, len(entries))
	for index, entry := range entries {
		item := fmt.Sprintf("%s[%d]", field, index)
		if err := validateLogicalRef(item+".ref", entry.Ref); err != nil {
			return nil, err
		}
		if err := validateDirectory(item+".directory", entry.Directory); err != nil {
			return nil, err
		}
		if field == "runner_states" {
			if err := validateRunnerStateName(item+".ref", entry.Ref); err != nil {
				return nil, err
			}
			if err := validateRunnerStateName(item+".directory", entry.Directory); err != nil {
				return nil, err
			}
		}
		if _, exists := refs[entry.Ref]; exists {
			return nil, invalid(item+".ref", "is duplicated")
		}
		if _, exists := directories[entry.Directory]; exists {
			return nil, invalid(item+".directory", "is duplicated")
		}
		refs[entry.Ref] = struct{}{}
		directories[entry.Directory] = struct{}{}
	}
	return refs, nil
}

// Runner-state refs and directory components use one canonical lowercase
// ASCII form. This makes byte-wise config/SQLite uniqueness agree with
// physical-name uniqueness on supported Linux filesystems which enable
// casefolding or Unicode normalization.
func validateRunnerStateName(field, value string) error {
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || strings.ContainsRune("-_.", rune(char)) {
			continue
		}
		return invalid(field, "must use canonical lowercase ASCII [a-z0-9._-]")
	}
	return nil
}

func validateLogicalRef(field, value string) error {
	if value == "" || len(value) > MaxNameBytes || value == "." || value == ".." {
		return invalid(field, "has invalid byte length or value")
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

func validateDirectory(field, value string) error {
	if err := validateLogicalRef(field, value); err != nil {
		return err
	}
	if strings.ContainsAny(value, ":@") {
		return invalid(field, "must be one portable directory component")
	}
	return nil
}

func validateCLI(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return invalid("runtime.cli", "cannot inspect executable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return invalid("runtime.cli", "must be an executable regular non-symlink file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return invalid("runtime.cli", "must not be writable by group or others")
	}
	return nil
}

func parseUnixEndpoint(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "unix" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("must be a unix:///absolute/path URI without query or fragment")
	}
	if !filepath.IsAbs(parsed.Path) || parsed.Path != filepath.Clean(parsed.Path) {
		return "", errors.New("must contain a clean absolute socket path")
	}
	return parsed.Path, nil
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
