package dockerruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// Only the opt-in integration constructor currently populates this template.
// Default executable configuration still constructs credential-free mocks.
type credentialSpec struct {
	pin           string
	binding       credentialsource.Binding
	bootstrap     string
	seccompPath   string
	seccompDigest string
	seccomp       []byte
	files         []credentialArtifact
	binds         []credentialBind
	provider      *providerSpec
}

type credentialArtifact struct{ path, digest string }
type credentialBind struct{ source, destination string }
type credentialLaunch struct {
	source   *credentialsource.Handoff
	runID    string
	observer bootstrapObserver
	started  bool
}

const credentialRunnerUID = 1000

func (s *credentialSpec) prepare(h *credentialsource.Handoff, runID, fingerprint string) error {
	if s == nil || h == nil || s.checkArtifacts() != nil || h.Claim(runID, fingerprint, s.binding) != nil {
		return ErrCredentialUnavailable
	}
	return nil
}

func (s *credentialSpec) checkArtifacts() error {
	for _, file := range append(append([]credentialArtifact(nil), s.files...), credentialArtifact{s.seccompPath, s.seccompDigest}) {
		st, err := os.Lstat(file.path)
		if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 512<<20 || st.Mode().Perm()&0o022 != 0 {
			return ErrCredentialUnavailable
		}
		f, err := os.OpenFile(file.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return ErrCredentialUnavailable
		}
		opened, err := f.Stat()
		if err != nil || !opened.Mode().IsRegular() || !os.SameFile(st, opened) {
			_ = f.Close()
			return ErrCredentialUnavailable
		}
		hash := sha256.New()
		n, copyErr := io.Copy(hash, io.LimitReader(f, (512<<20)+1))
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || n != st.Size() || hex.EncodeToString(hash.Sum(nil)) != file.digest {
			return ErrCredentialUnavailable
		}
	}
	return nil
}

func (s *credentialSpec) arguments() []string {
	args := []string{"--cap-add", "SETFCAP", "--security-opt", "seccomp=" + s.seccompPath,
		"--ipc", "none", "--entrypoint", "/hsg-uid-setup"}
	for _, mount := range s.binds {
		args = append(args, "--mount", "type=bind,src="+mount.source+",dst="+mount.destination+",bind-propagation=rprivate,readonly")
	}
	return append(args, "--mount", "type=bind,src="+filepath.Join(s.binding.Root, s.binding.Directory, "auth.json")+
		",dst="+credentialsource.MountedCredentialPath+",bind-propagation=rprivate")
}

// CreateWithCredential is available only for a frozen guarded template and a
// matching, one-use held-source capability. It never accepts a new mount path.
// Ambiguous Create keeps its normal durable-intent semantics; recovery can
// clean that container but cannot reconstruct a launch capability.
func (r *Runtime) CreateWithCredential(ctx context.Context, runID string, manifest targetmanifest.Definition, h *credentialsource.Handoff) (ContainerRef, error) {
	if r == nil || ctx == nil || h == nil {
		return "", ErrCredentialUnavailable
	}
	spec, exists := r.targets[targetKey{manifest.ID(), manifest.Revision()}]
	if !exists || spec.credential == nil {
		return "", ErrCredentialUnavailable
	}
	observer, err := r.attestBootstrapObserver(ctx)
	if err != nil {
		return "", err
	}
	ref, err := r.create(ctx, runID, manifest, h)
	if err != nil {
		return "", err
	}
	r.credentialMu.Lock()
	defer r.credentialMu.Unlock()
	if r.credentials == nil {
		r.credentials = make(map[ContainerRef]*credentialLaunch)
	}
	if r.credentials[ref] != nil {
		return "", uncertainCreate(ErrCredentialUnavailable)
	}
	r.credentials[ref] = &credentialLaunch{source: h, runID: runID, observer: observer}
	return ref, nil
}

func (r *Runtime) claimCredentialLaunch(ref ContainerRef) (*credentialLaunch, error) {
	r.credentialMu.Lock()
	defer r.credentialMu.Unlock()
	launch := r.credentials[ref]
	if launch == nil || launch.started {
		return nil, ErrCredentialUnavailable
	}
	launch.started = true
	return launch, nil
}

func (r *Runtime) forgetCredential(ref ContainerRef) {
	r.credentialMu.Lock()
	defer r.credentialMu.Unlock()
	if launch := r.credentials[ref]; launch != nil {
		launch.source.Close()
		delete(r.credentials, ref)
	}
}

func credentialError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrCredentialUnavailable, err)
	}
	return ErrCredentialUnavailable
}
