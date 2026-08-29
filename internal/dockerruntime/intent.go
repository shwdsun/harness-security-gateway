package dockerruntime

import (
	"context"
	"errors"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

const intentListFormat = `{"id":{{json .ID}},"name":{{json .Names}}}`

type intentListRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// LookupIntent finds the container produced by one immutable Create intent.
// It never creates or mutates a container. found=false is returned only after
// a successful exact-name list proves that no such container exists.
func (r *Runtime) LookupIntent(
	ctx context.Context,
	runID string,
	manifest targetmanifest.Manifest,
) (ContainerRef, bool, error) {
	if err := r.ready(ctx); err != nil {
		return "", false, err
	}
	if err := validateRunID(runID); err != nil {
		return "", false, err
	}
	if err := manifest.Validate(); err != nil {
		return "", false, ErrInvalidArgument
	}
	if err := validateProfile(manifest); err != nil {
		return "", false, err
	}
	fingerprint, err := manifest.Fingerprint()
	if err != nil {
		return "", false, ErrInvalidArgument
	}
	spec, exists := r.targets[targetKey{id: manifest.ID, revision: manifest.Revision}]
	if !exists || spec.fingerprint != fingerprint || spec.image != manifest.Runner.Image {
		return "", false, ErrTargetNotConfigured
	}
	if err := r.attestRootless(ctx); err != nil {
		return "", false, err
	}
	return r.lookupIntentAttested(ctx, runID, manifest, fingerprint)
}

// lookupIntentAttested performs the closed identity/absence protocol after
// the caller has validated the immutable manifest and freshly attested the
// configured daemon. Create uses it after its own immediately preceding
// attestation so recovery does not introduce a different endpoint decision.
func (r *Runtime) lookupIntentAttested(
	ctx context.Context,
	runID string,
	manifest targetmanifest.Manifest,
	fingerprint string,
) (ContainerRef, bool, error) {
	name := deterministicName(runID)
	labels := expectedLabels(runID, manifest, fingerprint)
	record, err := r.inspectIdentifier(ctx, name)
	if err == nil {
		if verifyErr := verifyIntentRecord(record, name, manifest.Runner.Image, labels); verifyErr != nil {
			return "", false, verifyErr
		}
		return ContainerRef(record.ID), true, nil
	}
	if !errors.Is(err, ErrCommandFailed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", false, err
	}

	// Docker does not expose a typed not-found result through the CLI. A
	// successful exact-name listing is the second, independent observation that
	// turns an ambiguous inspect failure into a strict absence proof.
	ref, present, probeErr := r.probeExactName(ctx, name)
	if probeErr != nil {
		return "", false, probeErr
	}
	if !present {
		return "", false, nil
	}

	// The list proves presence but is deliberately too narrow to establish
	// ownership. Re-inspect the full ID and verify every immutable identity fact.
	record, err = r.inspectIdentifier(ctx, string(ref))
	if err != nil {
		return "", false, err
	}
	if record.ID != string(ref) {
		return "", false, ErrForeignContainer
	}
	if verifyErr := verifyIntentRecord(record, name, manifest.Runner.Image, labels); verifyErr != nil {
		return "", false, verifyErr
	}
	return ref, true, nil
}

func verifyIntentRecord(record inspectRecord, name, image string, labels map[string]string) error {
	if err := verifyExpected(record, name, image, labels); err != nil {
		return err
	}
	if !validContainerID(record.ID) {
		return ErrInvalidResponse
	}
	return nil
}

func (r *Runtime) probeExactName(ctx context.Context, name string) (ContainerRef, bool, error) {
	if !validInternalIdentifier(name) || validContainerID(name) {
		return "", false, ErrInvalidRef
	}
	output, err := r.run(ctx, "lookup-probe",
		"container", "ls", "--all", "--no-trunc",
		"--filter", "name=^/"+name+"$", "--format", intentListFormat)
	if err != nil {
		return "", false, err
	}
	if len(output) == 0 {
		return "", false, nil
	}
	var record intentListRecord
	if err := strictjson.Decode(output, commandStdoutLimit, 3, &record); err != nil {
		return "", false, ErrInvalidResponse
	}
	if !validContainerID(record.ID) || record.Name != name {
		return "", false, ErrInvalidResponse
	}
	return ContainerRef(record.ID), true, nil
}
