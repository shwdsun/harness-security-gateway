package dockerruntime

import (
	"context"
	"errors"
	"strings"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const inspectFormat = `{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"state":{{json .State.Status}},"exit_code":{{json .State.ExitCode}},"labels":{{json .Config.Labels}}}`

type ContainerState string

const (
	StateCreated    ContainerState = "created"
	StateRunning    ContainerState = "running"
	StatePaused     ContainerState = "paused"
	StateRestarting ContainerState = "restarting"
	StateRemoving   ContainerState = "removing"
	StateExited     ContainerState = "exited"
	StateDead       ContainerState = "dead"
)

// Inspection contains only the closed runtime facts sandboxd needs. Docker's
// open-ended inspect object never crosses this package boundary.
type Inspection struct {
	Ref      ContainerRef
	State    ContainerState
	ExitCode int
}

type inspectRecord struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	State    ContainerState    `json:"state"`
	ExitCode int               `json:"exit_code"`
	Labels   map[string]string `json:"labels"`
}

// ParseContainerRef restores a persisted opaque reference. Only a complete,
// lowercase Docker ID is accepted; names and abbreviated IDs are forbidden.
func ParseContainerRef(value string) (ContainerRef, error) {
	if !validContainerID(value) {
		return "", ErrInvalidRef
	}
	return ContainerRef(value), nil
}

func parseContainerRef(output []byte) (ContainerRef, error) {
	value := string(output)
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
		value = strings.TrimSuffix(value, "\r")
	}
	if !validContainerID(value) {
		return "", ErrInvalidResponse
	}
	return ContainerRef(value), nil
}

func validContainerID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func validInternalIdentifier(value string) bool {
	if validContainerID(value) {
		return true
	}
	if len(value) != len(containerNamePrefix)+32 || !strings.HasPrefix(value, containerNamePrefix) {
		return false
	}
	for index := len(containerNamePrefix); index < len(value); index++ {
		char := value[index]
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func (r *Runtime) inspectIdentifier(ctx context.Context, identifier string) (inspectRecord, error) {
	if !validInternalIdentifier(identifier) {
		return inspectRecord{}, ErrInvalidRef
	}
	output, err := r.run(ctx, "inspect", "container", "inspect", "--format", inspectFormat, identifier)
	if err != nil {
		return inspectRecord{}, err
	}
	var record inspectRecord
	if err := strictjson.Decode(output, commandStdoutLimit, 6, &record); err != nil {
		return inspectRecord{}, ErrInvalidResponse
	}
	if !validContainerID(record.ID) || normalizeContainerName(record.Name) == "" ||
		record.Image == "" || record.Labels == nil || !record.State.valid() ||
		record.ExitCode < 0 || record.ExitCode > 255 {
		return inspectRecord{}, ErrInvalidResponse
	}
	return record, nil
}

func (state ContainerState) valid() bool {
	switch state {
	case StateCreated, StateRunning, StatePaused, StateRestarting,
		StateRemoving, StateExited, StateDead:
		return true
	default:
		return false
	}
}

func normalizeContainerName(value string) string {
	if strings.HasPrefix(value, "/") {
		value = strings.TrimPrefix(value, "/")
	}
	if !validInternalIdentifier(value) || validContainerID(value) {
		return ""
	}
	return value
}

func verifyExpected(record inspectRecord, name, image string, labels map[string]string) error {
	if normalizeContainerName(record.Name) != name || record.Image != image {
		return ErrForeignContainer
	}
	for key, expected := range labels {
		if record.Labels[key] != expected {
			return ErrForeignContainer
		}
	}
	return nil
}

func (r *Runtime) verifyManaged(record inspectRecord) (targetSpec, error) {
	if record.Labels[labelManaged] != "v1" {
		return targetSpec{}, ErrForeignContainer
	}
	runID := record.Labels[labelRunID]
	if validateRunID(runID) != nil {
		return targetSpec{}, ErrForeignContainer
	}
	key := targetKey{
		id:       record.Labels[labelTargetID],
		revision: record.Labels[labelTargetRevision],
	}
	spec, exists := r.targets[key]
	if !exists || record.Labels[labelTargetFingerprint] != spec.fingerprint || record.Image != spec.image {
		return targetSpec{}, ErrForeignContainer
	}
	if normalizeContainerName(record.Name) != deterministicName(runID) {
		return targetSpec{}, ErrForeignContainer
	}
	return spec, nil
}

func (r *Runtime) inspectManaged(ctx context.Context, ref ContainerRef) (inspectRecord, targetSpec, error) {
	if err := r.ready(ctx); err != nil {
		return inspectRecord{}, targetSpec{}, err
	}
	if _, err := ParseContainerRef(string(ref)); err != nil {
		return inspectRecord{}, targetSpec{}, err
	}
	if err := r.attestRootless(ctx); err != nil {
		return inspectRecord{}, targetSpec{}, err
	}
	record, err := r.inspectIdentifier(ctx, string(ref))
	if err != nil {
		if errors.Is(err, ErrCommandFailed) &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			present, probeErr := r.probeFullRef(ctx, ref)
			if probeErr != nil {
				return inspectRecord{}, targetSpec{}, probeErr
			}
			if !present {
				return inspectRecord{}, targetSpec{}, ErrNotFound
			}
		}
		return inspectRecord{}, targetSpec{}, err
	}
	if record.ID != string(ref) {
		return inspectRecord{}, targetSpec{}, ErrForeignContainer
	}
	spec, err := r.verifyManaged(record)
	if err != nil {
		return inspectRecord{}, targetSpec{}, err
	}
	return record, spec, nil
}

// probeFullRef is deliberately used only after public full-ID inspection
// fails. A successful, exact no-trunc listing can prove absence after a
// remove-response loss; deterministic-name Create adoption remains separate.
func (r *Runtime) probeFullRef(ctx context.Context, ref ContainerRef) (bool, error) {
	output, err := r.run(ctx, "probe",
		"container", "ls", "--all", "--no-trunc",
		"--filter", "id="+string(ref), "--format", "{{.ID}}")
	if err != nil {
		return false, err
	}
	if len(output) == 0 {
		return false, nil
	}
	listed, err := parseContainerRef(output)
	if err != nil || listed != ref {
		return false, ErrInvalidResponse
	}
	return true, nil
}

func (r *Runtime) Inspect(ctx context.Context, ref ContainerRef) (Inspection, error) {
	record, _, err := r.inspectManaged(ctx, ref)
	if err != nil {
		return Inspection{}, err
	}
	return Inspection{
		Ref:      ContainerRef(record.ID),
		State:    record.State,
		ExitCode: record.ExitCode,
	}, nil
}

func validateSpecStorage(spec targetSpec) error {
	if err := validateDirectory(spec.workspaceRoot, spec.workspaceRoot); err != nil {
		return err
	}
	if err := validateDirectory(spec.workspacePath, spec.workspaceRoot); err != nil {
		return err
	}
	if err := validateDirectory(spec.stateRoot, spec.stateRoot); err != nil {
		return err
	}
	if err := validatePrivateDirectory(spec.stateRoot); err != nil {
		return err
	}
	if err := validateDirectory(spec.statePath, spec.stateRoot); err != nil {
		return err
	}
	return validatePrivateDirectory(spec.statePath)
}
