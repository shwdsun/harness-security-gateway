package dockerruntime

import (
	"bytes"
	"context"
	"sort"
)

const (
	managedListLimit  = 128
	managedListFormat = `{{.ID}}`
)

// ListManaged returns the opaque full IDs of every container carrying this
// runtime's managed-v1 label on the configured endpoint. The Docker listing is
// only a candidate set: every result is inspected and matched against an
// immutable, configured target before any reference is returned.
func (r *Runtime) ListManaged(ctx context.Context) ([]ContainerRef, error) {
	if err := r.ready(ctx); err != nil {
		return nil, err
	}
	if err := r.attestRootless(ctx); err != nil {
		return nil, err
	}

	output, err := r.run(ctx, "list-managed",
		"container", "ls", "--all", "--no-trunc",
		"--filter", "label="+labelManaged+"=v1",
		"--format", managedListFormat,
	)
	if err != nil {
		return nil, err
	}
	refs, err := parseManagedList(output)
	if err != nil {
		return nil, err
	}
	// Docker does not promise an order that is useful to reconciliation. Sort
	// before inspection as well as return so failures are deterministic.
	sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })

	for _, ref := range refs {
		record, inspectErr := r.inspectIdentifier(ctx, string(ref))
		if inspectErr != nil {
			return nil, inspectErr
		}
		if record.ID != string(ref) {
			return nil, ErrForeignContainer
		}
		if _, verifyErr := r.verifyManaged(record); verifyErr != nil {
			return nil, verifyErr
		}
	}
	return refs, nil
}

func parseManagedList(output []byte) ([]ContainerRef, error) {
	if len(output) == 0 {
		return []ContainerRef{}, nil
	}
	if output[len(output)-1] != '\n' || bytes.IndexByte(output, '\r') >= 0 {
		return nil, ErrInvalidResponse
	}

	lines := bytes.Split(output[:len(output)-1], []byte{'\n'})
	if len(lines) > managedListLimit {
		return nil, ErrInvalidResponse
	}
	refs := make([]ContainerRef, 0, len(lines))
	seen := make(map[ContainerRef]struct{}, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			return nil, ErrInvalidResponse
		}
		ref, err := ParseContainerRef(string(line))
		if err != nil {
			return nil, ErrInvalidResponse
		}
		if _, exists := seen[ref]; exists {
			return nil, ErrInvalidResponse
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	return refs, nil
}
