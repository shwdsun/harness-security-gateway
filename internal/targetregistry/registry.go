// Package targetregistry provides sandboxd's immutable in-memory view of
// operator-approved ExecutionTargets.
package targetregistry

import (
	"errors"
	"fmt"
	"sort"

	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

var (
	ErrTargetNotFound   = errors.New("target not found")
	ErrRevisionMismatch = errors.New("target revision mismatch")
	ErrDuplicateTarget  = errors.New("duplicate target ID")
)

type Entry struct {
	Manifest    targetmanifest.Manifest
	Fingerprint string
}

type Registry struct {
	entries map[string]Entry
}

func New(manifests []targetmanifest.Manifest) (*Registry, error) {
	if len(manifests) == 0 {
		return nil, errors.New("target registry must not be empty")
	}
	entries := make(map[string]Entry, len(manifests))
	for index, manifest := range manifests {
		if err := manifest.Validate(); err != nil {
			return nil, fmt.Errorf("targets[%d]: %w", index, err)
		}
		if _, exists := entries[manifest.ID]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateTarget, manifest.ID)
		}
		fingerprint, err := manifest.Fingerprint()
		if err != nil {
			return nil, fmt.Errorf("fingerprint targets[%d]: %w", index, err)
		}
		entries[manifest.ID] = Entry{Manifest: manifest, Fingerprint: fingerprint}
	}
	return &Registry{entries: entries}, nil
}

func (r *Registry) Resolve(id, expectedRevision string) (Entry, error) {
	if r == nil {
		return Entry{}, ErrTargetNotFound
	}
	entry, exists := r.entries[id]
	if !exists {
		return Entry{}, ErrTargetNotFound
	}
	if entry.Manifest.Revision != expectedRevision {
		return Entry{}, ErrRevisionMismatch
	}
	return entry, nil
}

func (r *Registry) Entries() []Entry {
	if r == nil {
		return nil
	}
	result := make([]Entry, 0, len(r.entries))
	for _, entry := range r.entries {
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Manifest.ID < result[j].Manifest.ID
	})
	return result
}
