// Package codexadapter translates one new-only HRP/1 Run into one fixed,
// non-interactive Codex CLI invocation. It is intentionally not an authority
// negotiation surface: every path and CLI option comes from local runner
// configuration, while the untrusted Run contributes only prompt text to the
// invocation contract. Image-level canaries must separately prove that the
// pinned CLI does not discover another context or extension surface.
package codexadapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/shwdsun/harness-security-gateway/internal/runnerwire"
)

const (
	AdapterFamily  = "codex"
	AdapterVersion = "0.1.0-new-only"

	maxCodexStdoutBytes = 8 << 20
	maxCodexStderrBytes = 64 << 10
	authFilename        = "auth.json"
	finalFilename       = "final.txt"
	finalWriteErrorText = "Failed to write last message file"
)

var (
	errInvalidConfig = errors.New("codex adapter: invalid configuration")
	errFinalOutput   = errors.New("codex adapter: invalid final output")
	errOutputLimit   = errors.New("codex adapter: diagnostic output limit exceeded")
)

// Config is baked into a reviewed runner image. None of these values may come
// from HRP, a message, a workspace file, or ambient process configuration.
type Config struct {
	Binary          string
	Model           string
	Workspace       string
	CodexHome       string
	OutputDirectory string
}

// ProductionConfig returns the closed filesystem contract for the first Codex
// adapter. CodexHome must be a writable, per-Run disposable directory. A future
// auth profile may bind only its dedicated auth.json into that directory; it
// must never persist the whole CODEX_HOME. Today's Docker runtime cannot express
// that reviewed profile, so the adapter remains disabled.
func ProductionConfig(model string) Config {
	return Config{
		Binary:          "/usr/local/bin/codex",
		Model:           model,
		Workspace:       "/workspace",
		CodexHome:       "/tmp/hgw-codex-home",
		OutputDirectory: "/tmp/hgw-codex-runner",
	}
}

// Invocation is the complete child-process request assembled by the adapter.
// Stdin contains the prompt; Args never do.
type Invocation struct {
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type Process interface {
	Wait() error
}

type Launcher interface {
	Start(context.Context, Invocation) (Process, error)
}

// Run serves exactly one HRP/1 lifecycle. Harness failures are represented by
// sanitized terminal frames and therefore return nil; only a broken HRP stream
// or local adapter contract returns an error.
func Run(ctx context.Context, input io.Reader, output io.Writer, config Config, launcher Launcher) error {
	if ctx == nil || input == nil || output == nil || launcher == nil {
		return fmt.Errorf("%w: missing dependency", errInvalidConfig)
	}
	if err := config.validate(); err != nil {
		return err
	}

	encoder := runnerwire.NewEncoder(output)
	if err := encoder.Encode(&runnerwire.RunnerReady{
		Protocol: runnerwire.ProtocolV1,
		Type:     runnerwire.TypeRunnerReady,
		Adapter: runnerwire.Adapter{
			Family:  AdapterFamily,
			Version: AdapterVersion,
		},
		Features: []runnerwire.Feature{},
	}); err != nil {
		return fmt.Errorf("codex adapter: emit ready: %w", err)
	}

	frame, err := runnerwire.NewDecoder(input).DecodeControllerFrame()
	if err != nil {
		return fmt.Errorf("codex adapter: receive start: %w", err)
	}
	start, ok := frame.(*runnerwire.RunStart)
	if !ok {
		return errors.New("codex adapter: unexpected controller frame")
	}
	if err := encoder.Encode(&runnerwire.RunStarted{
		Protocol: runnerwire.ProtocolV1,
		Type:     runnerwire.TypeRunStarted,
		RunID:    start.RunID,
		Seq:      1,
	}); err != nil {
		return fmt.Errorf("codex adapter: emit started: %w", err)
	}
	if start.Session.Mode != runnerwire.SessionModeNew || start.Session.Token != "" {
		return emitFailure(encoder, start.RunID, 2, runnerwire.ErrorCodePolicyDenied, "Codex target accepts new sessions only")
	}

	runCtx, cancel := context.WithDeadline(ctx, time.UnixMilli(start.DeadlineUnixMS))
	defer cancel()
	if runCtx.Err() != nil {
		return emitCancelled(encoder, start.RunID, 2)
	}

	if err := prepareCodexHome(config.CodexHome); err != nil {
		return emitFailure(encoder, start.RunID, 2, runnerwire.ErrorCodeRunnerInternal, "Codex runner could not prepare state")
	}
	finalFile, finalPath, err := prepareFinalFile(config.OutputDirectory)
	if err != nil {
		return emitFailure(encoder, start.RunID, 2, runnerwire.ErrorCodeRunnerInternal, "Codex runner could not prepare output")
	}
	defer finalFile.Close()

	stdout := &boundedDiscard{limit: maxCodexStdoutBytes, cancel: cancel}
	stderr := &boundedDiscard{limit: maxCodexStderrBytes, cancel: cancel, needle: []byte(finalWriteErrorText)}
	invocation := config.invocation(start.Input.Text, finalPath, stdout, stderr)
	process, err := launcher.Start(runCtx, invocation)
	if err != nil {
		return emitFailure(encoder, start.RunID, 2, runnerwire.ErrorCodeRunnerInternal, "Codex runner could not start")
	}

	waitErr := process.Wait()
	if stdout.Exceeded() || stderr.Exceeded() {
		return emitFailure(encoder, start.RunID, 2, runnerwire.ErrorCodeRunnerInternal, "Codex diagnostic output exceeded its limit")
	}
	if runCtx.Err() != nil {
		return emitCancelled(encoder, start.RunID, 2)
	}
	if waitErr != nil {
		return emitFailure(encoder, start.RunID, 2, runnerwire.ErrorCodeHarnessError, "Codex execution failed")
	}
	if stderr.Matched() {
		return emitFailure(encoder, start.RunID, 2, runnerwire.ErrorCodeRunnerInternal, "Codex result was unavailable")
	}
	result, err := readFinalFile(finalFile, finalPath)
	if err != nil {
		return emitFailure(encoder, start.RunID, 2, runnerwire.ErrorCodeRunnerInternal, "Codex result was unavailable")
	}
	completed := &runnerwire.RunCompleted{
		Protocol: runnerwire.ProtocolV1,
		Type:     runnerwire.TypeRunCompleted,
		RunID:    start.RunID,
		Seq:      2,
		Output: runnerwire.TextContent{
			MediaType: runnerwire.MediaTypeTextPlain,
			Text:      result,
		},
	}
	if err := encoder.Encode(completed); err != nil {
		return fmt.Errorf("codex adapter: emit completed: %w", err)
	}
	return nil
}

func (c Config) validate() error {
	for name, value := range map[string]string{
		"binary":           c.Binary,
		"workspace":        c.Workspace,
		"codex home":       c.CodexHome,
		"output directory": c.OutputDirectory,
	} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || !safeConfigPath(value) {
			return fmt.Errorf("%w: %s path", errInvalidConfig, name)
		}
	}
	if c.Workspace == c.CodexHome || pathContains(c.Workspace, c.CodexHome) || pathContains(c.CodexHome, c.Workspace) {
		return fmt.Errorf("%w: workspace and Codex home overlap", errInvalidConfig)
	}
	if pathsOverlap(c.OutputDirectory, c.Workspace) || pathsOverlap(c.OutputDirectory, c.CodexHome) {
		return fmt.Errorf("%w: output directory overlaps another trust domain", errInvalidConfig)
	}
	if pathsOverlap(c.Binary, c.Workspace) || pathsOverlap(c.Binary, c.CodexHome) || pathsOverlap(c.Binary, c.OutputDirectory) {
		return fmt.Errorf("%w: binary overlaps a writable trust domain", errInvalidConfig)
	}
	if c.Model == "" || len(c.Model) > 128 {
		return fmt.Errorf("%w: model", errInvalidConfig)
	}
	for index := 0; index < len(c.Model); index++ {
		char := c.Model[index]
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-._:", rune(char)) {
			continue
		}
		return fmt.Errorf("%w: model", errInvalidConfig)
	}
	return nil
}

func (c Config) invocation(prompt, finalPath string, stdout, stderr io.Writer) Invocation {
	return Invocation{
		Path: c.Binary,
		Args: []string{
			"exec",
			"--json",
			"--ephemeral",
			"--ignore-user-config",
			"--ignore-rules",
			"--strict-config",
			"--color", "never",
			"--sandbox", "workspace-write",
			"--model", c.Model,
			"--cd", c.Workspace,
			"--output-last-message", finalPath,
			"--config", `approval_policy="never"`,
			"--config", `sandbox_workspace_write.network_access=false`,
			"--config", `sandbox_workspace_write.exclude_slash_tmp=true`,
			"--config", `sandbox_workspace_write.exclude_tmpdir_env_var=true`,
			"--config", `shell_environment_policy.inherit="none"`,
			"--config", `shell_environment_policy.ignore_default_excludes=false`,
			"--config", `shell_environment_policy.set={PATH="/usr/local/bin:/usr/bin:/bin",LANG="C.UTF-8",LC_ALL="C.UTF-8",HOME="/nonexistent"}`,
			"--config", `projects={"` + c.Workspace + `"={trust_level="untrusted"}}`,
			"--config", `project_doc_max_bytes=0`,
			"--config", `web_search="disabled"`,
			"--config", `tools.web_search=false`,
			"--config", `forced_login_method="chatgpt"`,
			"--config", `cli_auth_credentials_store="file"`,
			"--config", `check_for_update_on_startup=false`,
			"--config", `allow_login_shell=false`,
			"--config", `apps._default.enabled=false`,
			"--config", `features.apps=false`,
			"--config", `features.auth_elicitation=false`,
			"--config", `features.browser_use=false`,
			"--config", `features.browser_use_external=false`,
			"--config", `features.browser_use_full_cdp_access=false`,
			"--config", `features.code_mode.enabled=false`,
			"--config", `features.code_mode_host=false`,
			"--config", `features.computer_use=false`,
			"--config", `features.fast_mode=false`,
			"--config", `features.goals=false`,
			"--config", `features.guardian_approval=false`,
			"--config", `features.hooks=false`,
			"--config", `features.image_generation=false`,
			"--config", `features.memories=false`,
			"--config", `features.multi_agent=false`,
			"--config", `features.network_proxy=false`,
			"--config", `features.plugin_sharing=false`,
			"--config", `features.plugins=false`,
			"--config", `features.recommended_plugins=false`,
			"--config", `features.remote_compaction_v2=false`,
			"--config", `features.remote_plugin=false`,
			"--config", `features.shell_snapshot=false`,
			"--config", `features.skill_mcp_dependency_install=false`,
			"--config", `features.skill_search=false`,
			"--config", `features.tool_call_mcp_elicitation=false`,
			"--config", `features.tool_suggest=false`,
			"--config", `features.unbounded_connection_retries=false`,
			"--config", `features.view_image=false`,
			"--config", `features.workspace_dependencies=false`,
			"--config", `feedback.enabled=false`,
			"--config", `history.persistence="none"`,
			"-",
		},
		Env: []string{
			"CODEX_HOME=" + c.CodexHome,
			"CODEX_SQLITE_HOME=" + c.OutputDirectory,
			"HOME=/nonexistent",
			"LANG=C.UTF-8",
			"LC_ALL=C.UTF-8",
			"PATH=/usr/local/bin:/usr/bin:/bin",
			"TERM=dumb",
		},
		Dir:    c.Workspace,
		Stdin:  strings.NewReader(prompt),
		Stdout: stdout,
		Stderr: stderr,
	}
}

// prepareCodexHome creates or attests the disposable per-Run Codex home. An
// existing directory is accepted only to support the future reviewed runtime
// shape in which auth.json is mounted before the runner starts. Runtime policy
// must still prove that this is a single-file bind rather than a persistent
// whole-directory mount. The pathname checks rely on the one-Run container
// invariant that no hostile same-UID process races setup before child launch.
func prepareCodexHome(directory string) error {
	parent := filepath.Dir(directory)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return errInvalidConfig
	}
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return errInvalidConfig
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil || resolvedDirectory != directory {
		return errInvalidConfig
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByEffectiveUser(info) {
		return errInvalidConfig
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > 1 {
		return errInvalidConfig
	}
	if len(entries) == 0 {
		return nil
	}
	if entries[0].Name() != authFilename {
		return errInvalidConfig
	}
	authInfo, err := os.Lstat(filepath.Join(directory, authFilename))
	if err != nil || authInfo.Mode()&os.ModeSymlink != 0 || !authInfo.Mode().IsRegular() || authInfo.Mode().Perm() != 0o600 || !ownedByEffectiveUser(authInfo) {
		return errInvalidConfig
	}
	stat, ok := authInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errInvalidConfig
	}
	return nil
}

func ownedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func prepareFinalFile(directory string) (*os.File, string, error) {
	parent := filepath.Dir(directory)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return nil, "", errFinalOutput
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, "", errFinalOutput
	}
	created, err := os.Lstat(directory)
	if err != nil || created.Mode()&os.ModeSymlink != 0 || !created.IsDir() || created.Mode().Perm() != 0o700 {
		return nil, "", errFinalOutput
	}
	path := filepath.Join(directory, finalFilename)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, "", errFinalOutput
	}
	return file, path, nil
}

func readFinalFile(file *os.File, path string) (string, error) {
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 {
		return "", errFinalOutput
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return "", errFinalOutput
	}
	if stat, ok := opened.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return "", errFinalOutput
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", errFinalOutput
	}
	data, err := io.ReadAll(io.LimitReader(file, runnerwire.MaxOutputTextBytes+1))
	if err != nil || len(data) > runnerwire.MaxOutputTextBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || len(bytes.TrimSpace(data)) == 0 {
		return "", errFinalOutput
	}
	return string(data), nil
}

func emitFailure(encoder *runnerwire.Encoder, runID string, seq uint64, code runnerwire.ErrorCode, message string) error {
	if err := encoder.Encode(&runnerwire.RunFailed{
		Protocol: runnerwire.ProtocolV1,
		Type:     runnerwire.TypeRunFailed,
		RunID:    runID,
		Seq:      seq,
		Error: runnerwire.Failure{
			Code:    code,
			Message: message,
		},
	}); err != nil {
		return fmt.Errorf("codex adapter: emit failure: %w", err)
	}
	return nil
}

func emitCancelled(encoder *runnerwire.Encoder, runID string, seq uint64) error {
	if err := encoder.Encode(&runnerwire.RunCancelled{
		Protocol: runnerwire.ProtocolV1,
		Type:     runnerwire.TypeRunCancelled,
		RunID:    runID,
		Seq:      seq,
	}); err != nil {
		return fmt.Errorf("codex adapter: emit cancellation: %w", err)
	}
	return nil
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func pathsOverlap(first, second string) bool {
	return first == second || pathContains(first, second) || pathContains(second, first)
}

func safeConfigPath(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f || value[index] == '"' || value[index] == '\\' {
			return false
		}
	}
	return true
}

type boundedDiscard struct {
	limit    int64
	written  int64
	exceeded bool
	cancel   context.CancelFunc
	needle   []byte
	scanTail []byte
	matched  bool
	mu       sync.Mutex
}

func (w *boundedDiscard) Write(value []byte) (int, error) {
	w.mu.Lock()
	if w.exceeded {
		w.mu.Unlock()
		return 0, errOutputLimit
	}
	w.scan(value)
	remaining := w.limit - w.written
	if int64(len(value)) > remaining {
		accepted := int(remaining)
		if accepted < 0 {
			accepted = 0
		}
		w.written += int64(accepted)
		w.exceeded = true
		cancel := w.cancel
		w.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return accepted, errOutputLimit
	}
	w.written += int64(len(value))
	w.mu.Unlock()
	return len(value), nil
}

func (w *boundedDiscard) Exceeded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exceeded
}

func (w *boundedDiscard) Matched() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.matched
}

func (w *boundedDiscard) scan(value []byte) {
	if w.matched || len(w.needle) == 0 {
		return
	}
	window := make([]byte, 0, len(w.scanTail)+len(value))
	window = append(window, w.scanTail...)
	window = append(window, value...)
	if bytes.Contains(window, w.needle) {
		w.matched = true
		w.scanTail = nil
		return
	}
	keep := len(w.needle) - 1
	if keep > len(window) {
		keep = len(window)
	}
	w.scanTail = append(w.scanTail[:0], window[len(window)-keep:]...)
}
