// Package credentialsource owns the local credential binding vocabulary.
// A Binding is configuration, not a resolved source, lease, or readiness proof.
package credentialsource

// Binding names one dedicated auth.json slot. It carries no credential bytes.
// Keep field order and JSON names stable: the offline candidate digest uses it.
// Resolution, enrollment and exact-object runtime handoff are separate actions;
// the shape alone grants none of them.
type Binding struct {
	WorkspaceRef   string `json:"workspace_ref"`
	AuthProfileRef string `json:"auth_profile_ref"`
	SlotRef        string `json:"slot_ref"`
	Generation     uint64 `json:"generation"`
	Root           string `json:"root"`
	Directory      string `json:"directory"`
}
