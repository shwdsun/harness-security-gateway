//go:build linux

package credentialsource

// Handoff freezes the already admitted Run, exact manifest and local binding
// around this held source. Expected proof comes from the Run's enrolled row;
// construction does not enroll, mount, launch, read content or grant authority.
func (h *HeldSource) Handoff(runID, fingerprint string, binding Binding, source string, proof Proof) (*Handoff, error) {
	if h == nil || runID == "" || len(runID) > 128 || !digestText(fingerprint) ||
		binding.SlotRef == "" || binding.Generation == 0 || binding.WorkspaceRef == "" || binding.AuthProfileRef == "" {
		return nil, ErrInvalidHandoff
	}
	h.mu.Lock()
	matched := !h.closed && !h.invalid && h.rootPath == binding.Root && h.directory == binding.Directory
	h.mu.Unlock()
	if !matched || h.VerifyProof(source, proof) != nil {
		return nil, ErrInvalidHandoff
	}
	return &Handoff{state: &handoffState{
		runID: runID, fingerprint: fingerprint, binding: binding,
		verify: func() error { return h.VerifyProof(source, proof) },
		open: func(pid int, ref, bootstrap string, uid uint32) (Receiver, error) {
			return openMappedReceiver(h, pid, ref, bootstrap, source, proof, uid)
		},
	}}, nil
}
