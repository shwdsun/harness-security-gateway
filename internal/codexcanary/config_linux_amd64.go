//go:build linux && amd64 && codexintegration

// Package codexcanary is a single local experiment, absent from default builds.
// Preflight is read-only; Execute/Recover require an explicit matching plan.
package codexcanary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/codexcandidate"
	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
	"github.com/shwdsun/harness-security-gateway/internal/codexprovider"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/executionwire"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

var ErrPreparation = errors.New("canary: preparation failed")
var ErrExecution = errors.New("canary: execution incomplete; preserve state for recovery")

type Config struct {
	Schema       string                             `json:"schema"`
	StateRoot    string                             `json:"state_root"`
	RunID        string                             `json:"run_id"`
	Runtime      dockerruntime.ProviderCanaryConfig `json:"runtime"`
	Continuation *Continuation                      `json:"continuation,omitempty"`
}

type Plan struct {
	Schema             string        `json:"schema"`
	Status             string        `json:"status"`
	Digest             string        `json:"plan_digest"`
	CandidatePin       string        `json:"candidate_pin"`
	CredentialMetadata string        `json:"credential_metadata"`
	Findings           []string      `json:"findings"`
	Effects            []string      `json:"effects_if_executed"`
	Limits             string        `json:"limits"`
	Confidentiality    string        `json:"confidentiality"`
	Continuation       *Continuation `json:"continuation,omitempty"`
}

func Load(path string) (Config, error) {
	c, _, err := loadConfigFile(path)
	if err != nil || !validMode(c) || path != configPath(c) {
		return Config{}, ErrPreparation
	}
	return c, nil
}

func loadConfigFile(path string) (Config, string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Config{}, "", ErrPreparation
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return Config{}, "", ErrPreparation
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return Config{}, "", ErrPreparation
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	var c Config
	if err != nil || strictjson.Decode(data, 64<<10, 16, &c) != nil {
		return Config{}, "", ErrPreparation
	}
	sum := sha256.Sum256(data)
	return c, hex.EncodeToString(sum[:]), nil
}

type preparation struct {
	runtime     *dockerruntime.Runtime
	diagnostics func() *codexprovider.Diagnostics
}

func Preflight(c Config) (Plan, *preparation, error) {
	return preflight(c, false)
}

func preflight(c Config, recovery bool) (Plan, *preparation, error) {
	if !validMode(c) || os.Geteuid() != 1000 || !filepath.IsAbs(c.StateRoot) || filepath.Clean(c.StateRoot) != c.StateRoot || c.StateRoot == "/" || strings.ContainsAny(c.StateRoot, "\x00,\r\n?#") || len(c.StateRoot) > 45 || (executionwire.GetRunRequest{RunID: c.RunID}).Validate() != nil {
		return Plan{}, nil, ErrPreparation
	}
	info, err := os.Lstat(c.StateRoot)
	resolved, resolveErr := filepath.EvalSymlinks(c.StateRoot)
	if err != nil || resolveErr != nil || resolved != c.StateRoot || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return Plan{}, nil, ErrPreparation
	}
	runtime := c.Runtime.Runtime
	if runtime.WorkspaceRoot != filepath.Join(c.StateRoot, "workspaces") || runtime.WorkspaceDirectory != "project" || runtime.Credential.Root != filepath.Join(c.StateRoot, "credentials") || runtime.Credential.Directory != "slot" || c.Runtime.ProviderRoot != filepath.Join(c.StateRoot, "provider") {
		return Plan{}, nil, ErrPreparation
	}
	// The in-process connector still uses Core's real configuration boundary.
	// Reject an invalid composition before reporting readiness or creating state.
	if _, err := agentpolicy.Compile(settings(c)); err != nil {
		return Plan{}, nil, ErrPreparation
	}
	r, pin, diagnostics, err := dockerruntime.NewProviderCanary(c.Runtime)
	if err != nil {
		return Plan{}, nil, ErrPreparation
	}
	data, err := json.Marshal(map[string]any{"schema": "codex-candidate/v1", "profile_id": codexprofile.IDV3, "target": runtime.Manifest, "workspace": map[string]string{"ref": runtime.Manifest.Common().WorkspaceRef, "path": filepath.Join(runtime.WorkspaceRoot, runtime.WorkspaceDirectory)}, "credential": runtime.Credential})
	if err != nil {
		return Plan{}, nil, ErrPreparation
	}
	candidate, err := codexcandidate.Decode(data)
	if err != nil {
		return Plan{}, nil, ErrPreparation
	}
	metadata, err := candidate.Check(true)
	if err != nil {
		return Plan{}, nil, ErrPreparation
	}
	plan := Plan{Schema: "hsg-provider-canary-plan/v1", Status: "awaiting_operator", CandidatePin: pin, CredentialMetadata: metadata.LocalMetadata, Findings: metadata.Findings,
		Effects: []string{"enroll and exclusively hold the dedicated auth.json object; native refresh may update it in place", "create one rootless network-none container from the fixed cached image; no image pull or host policy change", "send fixed prompt, native context and tool result to chatgpt.com; at most one auth.openai.com refresh, two catalog reads and bounded inference attempts", "write one private workspace marker and local Core/sandbox databases; fake ingress/delivery only", "join provider exchanges, remove the exact container, release credentials, then publish locally; preserve unresolved cleanup for explicit recovery"},
		Limits:  "one new-only Run; 300s execution ceiling; 16 total connections, 4 concurrent; 2MiB request/response body per connection; fixed gpt-5.6-sol/medium; no automatic second Run", Confidentiality: "credential-exposed-personal: the native client/tools may read the dedicated credential and send data through an allowed provider request; no credential-secrecy claim"}
	if metadata.LocalMetadata != "matches" {
		plan.Status = "blocked_local_metadata"
	}
	if c.Continuation != nil {
		previous, err := previousConfig(c)
		if err != nil {
			return Plan{}, nil, ErrPreparation
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if recovery {
			// The exact approved recovery may need SQLite to roll back its hot
			// journal. Check file identities here; check rows after opening the
			// pinned stores, before constructing any lifecycle owner.
			if !pinnedContinuation(c) || checkDatabaseIdentities(c) != nil {
				return Plan{}, nil, ErrPreparation
			}
			copy := *c.Continuation
			plan.Continuation = &copy
		} else {
			history, err := inspectHistory(ctx, c, previous)
			if err != nil {
				return Plan{}, nil, ErrPreparation
			}
			plan.Continuation = &history.pin
			if !pinnedContinuation(c) || *c.Continuation != history.pin {
				plan.Status = "blocked_lineage_pin"
			} else if history.used {
				plan.Status = "blocked_run_exists"
			} else if history.retired {
				plan.Status = "blocked_generation_retired"
			}
		}
		plan.Effects[0] = "preserve the enrolled source and existing databases; verify its held proof, retire the prior local generation and enroll the next generation for the new target; native refresh may update auth.json in place"
		plan.Effects[3] = "hold the private canary process lock; append one new Run to the retained Core/sandbox databases, write its distinct workspace marker and complete only its isolated local delivery"
	}
	data, err = json.Marshal(struct {
		Config      Config
		Pin, Prompt string
	}{c, pin, promptFor(c)})
	if err != nil {
		return Plan{}, nil, ErrPreparation
	}
	digest := sha256.Sum256(append([]byte("harness-security-gateway.live-canary-plan/v1\x00"), data...))
	plan.Digest = hex.EncodeToString(digest[:])
	return plan, &preparation{runtime: r, diagnostics: diagnostics}, nil
}

func prompt(runID string) string {
	return "This is a controlled integration canary in a disposable workspace. Use exec_command once to write exactly " + runID + " to /workspace/canary-marker.txt. Do not inspect credentials or other files, use network tools, spawn agents, or install anything. Then reply exactly HSG_REAL_CANARY_OK."
}

func promptFor(c Config) string {
	return strings.Replace(prompt(c.RunID), "canary-marker.txt", markerName(c), 1)
}

func markerName(c Config) string {
	if c.Continuation == nil {
		return "canary-marker.txt"
	}
	sum := sha256.Sum256([]byte(c.RunID))
	return "canary-" + hex.EncodeToString(sum[:]) + ".txt"
}

func connectorID(c Config) string {
	if c.Continuation == nil {
		return "canary"
	}
	sum := sha256.Sum256([]byte(c.RunID))
	return "canary-" + hex.EncodeToString(sum[:])
}

func configPath(c Config) string {
	if c.Schema == "hsg-provider-canary/v1" {
		return filepath.Join(c.StateRoot, "canary.json")
	}
	return filepath.Join(c.StateRoot, "plans", c.RunID+".json")
}

func validMode(c Config) bool {
	if c.Schema == "hsg-provider-canary/v1" {
		return c.Continuation == nil
	}
	return c.Schema == "hsg-provider-canary/v2" && c.Continuation != nil &&
		c.Continuation.PreviousRunID != c.RunID &&
		(executionwire.GetRunRequest{RunID: c.Continuation.PreviousRunID}).Validate() == nil &&
		(executionwire.GetRunRequest{RunID: c.RunID}).Validate() == nil
}
