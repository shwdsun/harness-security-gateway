//go:build linux && amd64

package dockerruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/shwdsun/harness-security-gateway/internal/bootstrapgate"
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"golang.org/x/sys/unix"
)

type bootstrapObserver struct {
	pid       int
	namespace string
}

// A local Unix peer supplies kernel process identity, independently of Docker's
// inspect PID. A different PID view cannot authorize /proc receiver inspection.
func (r *Runtime) attestBootstrapObserver(ctx context.Context) (bootstrapObserver, error) {
	if err := r.ready(ctx); err != nil {
		return bootstrapObserver{}, err
	}
	if !strings.HasPrefix(r.endpoint, "unix:///") {
		return bootstrapObserver{}, ErrCredentialUnavailable
	}
	socket := strings.TrimPrefix(r.endpoint, "unix://")
	st, err := os.Lstat(socket)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		return bootstrapObserver{}, ErrCredentialUnavailable
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0o007 != 0 {
		return bootstrapObserver{}, ErrCredentialUnavailable
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return bootstrapObserver{}, credentialError(err)
	}
	defer conn.Close()
	local, ok := conn.(*net.UnixConn)
	if !ok {
		return bootstrapObserver{}, ErrCredentialUnavailable
	}
	raw, err := local.SyscallConn()
	if err != nil {
		return bootstrapObserver{}, ErrCredentialUnavailable
	}
	var cred *unix.Ucred
	var readErr error
	if err := raw.Control(func(fd uintptr) { cred, readErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || readErr != nil || cred == nil || cred.Pid <= 1 || cred.Uid != uint32(os.Geteuid()) {
		return bootstrapObserver{}, ErrCredentialUnavailable
	}
	self, err := os.Readlink("/proc/self/ns/pid")
	peer, peerErr := os.Readlink("/proc/" + strconv.Itoa(int(cred.Pid)) + "/ns/pid")
	if err != nil || peerErr != nil || self != peer {
		return bootstrapObserver{}, ErrCredentialUnavailable
	}
	return bootstrapObserver{int(cred.Pid), self}, nil
}

const bootstrapInspectFormat = `{"id":{{json .Id}},"pid":{{json .State.Pid}},"started":{{json .State.StartedAt}},"state":{{json .State.Status}}}`

type bootstrapRecord struct {
	ID      string         `json:"id"`
	PID     int            `json:"pid"`
	Started string         `json:"started"`
	State   ContainerState `json:"state"`
}

func (r *Runtime) inspectBootstrap(ctx context.Context, ref ContainerRef, expected bootstrapObserver) (bootstrapRecord, error) {
	observer, err := r.attestBootstrapObserver(ctx)
	if err != nil || observer != expected {
		return bootstrapRecord{}, ErrCredentialUnavailable
	}
	if _, _, err := r.inspectManaged(ctx, ref); err != nil {
		return bootstrapRecord{}, err
	}
	data, err := r.run(ctx, "inspect-bootstrap", "container", "inspect", "--format", bootstrapInspectFormat, string(ref))
	if err != nil {
		return bootstrapRecord{}, err
	}
	var record bootstrapRecord
	if strictjson.Decode(data, 4096, 3, &record) != nil || record.ID != string(ref) || record.PID <= 1 || record.State != StateRunning || record.Started == "" {
		return bootstrapRecord{}, ErrCredentialUnavailable
	}
	return record, nil
}

func (r *Runtime) releaseCredentialBootstrap(ctx context.Context, ref ContainerRef, spec targetSpec, launch *credentialLaunch, process *Process) error {
	var receiver credentialsource.Receiver
	stage := "readiness"
	defer func() {
		if receiver != nil {
			_ = receiver.Close()
		}
	}()
	err := bootstrapgate.Release(ctx, process.Stdin, process.Stdout, func(ctx context.Context) error {
		stage = "source"
		if err := launch.source.Validate(launch.runID, spec.fingerprint, spec.credential.binding); err != nil {
			return err
		}
		stage = "observer"
		first, err := r.inspectBootstrap(ctx, ref, launch.observer)
		if err != nil {
			return err
		}
		stage = "applied-policy"
		mountedSpec := spec
		endpoint := r.runProvider(launch.runID)
		if spec.credential.provider != nil {
			if endpoint == nil {
				return ErrCredentialUnavailable
			}
			mountedSpec = providerMounts(spec, endpoint)
		} else if endpoint != nil {
			return ErrCredentialUnavailable
		}
		if err := r.verifyCredentialPolicy(ctx, ref, mountedSpec); err != nil {
			return err
		}
		stage = "provider-mount"
		if endpoint != nil {
			if err := endpoint.VerifyMounted(first.PID); err != nil {
				return err
			}
		}
		stage = "receiver"
		receiver, err = launch.source.OpenReceiver(first.PID, string(ref), spec.credential.bootstrap, credentialRunnerUID)
		if err != nil {
			return err
		}
		stage = "revalidation"
		last, err := r.inspectBootstrap(ctx, ref, launch.observer)
		if err != nil || last != first {
			return ErrCredentialUnavailable
		}
		if err := receiver.Validate(); err != nil {
			return err
		}
		if err := launch.source.Validate(launch.runID, spec.fingerprint, spec.credential.binding); err != nil {
			return err
		}
		// No receiver descriptors survive the private phase. A close error denies
		// permit; only the controller can later close the original held source.
		if err := receiver.Close(); err != nil {
			return err
		}
		receiver = nil
		stage = "provider-open"
		if endpoint != nil {
			if err := endpoint.Open(); err != nil {
				return err
			}
		}
		stage = "permit"
		return nil
	}, process.abortAttach)
	if err != nil {
		// Retain a fixed local stage for diagnosis, never receiver paths, file
		// contents or raw daemon text. Public Run failure text stays sanitized.
		return &CommandError{Operation: "credential-" + stage, Kind: ErrCredentialUnavailable, Cause: credentialError(errors.Join(err, ctx.Err()))}
	}
	return nil
}

const credentialPolicyFormat = `{"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"user":{{json .Config.User}},"network":{{json .HostConfig.NetworkMode}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"cap_add":{{json .HostConfig.CapAdd}},"cap_drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"ipc":{{json .HostConfig.IpcMode}},"tmpfs":{{json .HostConfig.Tmpfs}},"mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{"type":{{json $m.Type}},"source":{{json $m.Source}},"destination":{{json $m.Destination}},"rw":{{json $m.RW}},"propagation":{{json $m.Propagation}}}{{end}}]}`

type credentialPolicyRecord struct {
	Entrypoint, Cmd      []string
	User, Network        string
	Readonly, Privileged bool
	CapAdd               []string `json:"cap_add"`
	CapDrop              []string `json:"cap_drop"`
	Security             []string
	IPC                  string
	Tmpfs                map[string]string
	Mounts               []credentialPolicyMount
}
type credentialPolicyMount struct {
	Type, Source, Destination string
	RW                        bool
	Propagation               string
}

func (r *Runtime) verifyCredentialPolicy(ctx context.Context, ref ContainerRef, spec targetSpec) error {
	data, err := r.run(ctx, "inspect-credential-policy", "container", "inspect", "--format", credentialPolicyFormat, string(ref))
	if err != nil {
		return err
	}
	var p credentialPolicyRecord
	if strictjson.Decode(data, commandStdoutLimit, 8, &p) != nil || len(p.Entrypoint) != 1 || p.Entrypoint[0] != "/hsg-uid-setup" || len(p.Cmd) != 0 || p.User != "0:0" || p.Network != "none" || !p.Readonly || p.Privileged || p.IPC != "none" ||
		len(p.CapAdd) != 1 || p.CapAdd[0] != "CAP_SETFCAP" || len(p.CapDrop) != 1 || p.CapDrop[0] != "ALL" || len(p.Security) != 2 || len(p.Tmpfs) != 1 || p.Tmpfs["/tmp"] != fmt.Sprintf("rw,nosuid,nodev,noexec,size=%d,mode=1777", 512<<20) {
		return ErrCredentialUnavailable
	}
	nnp, seccomp := false, false
	for _, option := range p.Security {
		switch {
		case option == "no-new-privileges=true":
			if nnp {
				return ErrCredentialUnavailable
			}
			nnp = true
		case strings.HasPrefix(option, "seccomp="):
			if seccomp || !sameSeccompJSON([]byte(strings.TrimPrefix(option, "seccomp=")), spec.credential.seccomp) {
				return ErrCredentialUnavailable
			}
			seccomp = true
		default:
			return ErrCredentialUnavailable
		}
	}
	if !nnp || !seccomp {
		return ErrCredentialUnavailable
	}
	wanted := map[string]credentialPolicyMount{
		"/workspace":                           {"bind", spec.workspacePath, "/workspace", true, "rprivate"},
		credentialsource.MountedCredentialPath: {"bind", filepath.Join(spec.credential.binding.Root, spec.credential.binding.Directory, "auth.json"), credentialsource.MountedCredentialPath, true, "rprivate"},
	}
	for _, mount := range spec.credential.binds {
		wanted[mount.destination] = credentialPolicyMount{"bind", mount.source, mount.destination, false, "rprivate"}
	}
	if len(p.Mounts) != len(wanted) {
		return ErrCredentialUnavailable
	}
	for _, mount := range p.Mounts {
		if expected, ok := wanted[mount.Destination]; !ok || expected != mount {
			return ErrCredentialUnavailable
		}
		delete(wanted, mount.Destination)
	}
	if len(wanted) != 0 {
		return ErrCredentialUnavailable
	}
	return nil
}

func sameSeccompJSON(a, b []byte) bool {
	canonical := func(data []byte) []byte {
		var raw json.RawMessage
		if strictjson.Decode(data, 64<<10, 12, &raw) != nil {
			return nil
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) != nil {
			return nil
		}
		if decoder.Decode(new(any)) != io.EOF {
			return nil
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil
		}
		return encoded
	}
	one, two := canonical(a), canonical(b)
	return len(one) != 0 && len(two) != 0 && bytes.Equal(one, two)
}
