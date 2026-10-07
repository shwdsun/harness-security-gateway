package dockerruntime

// ActivateOwner is called only with global process ownership, before durable
// stores/recovery. Legacy runtimes have no owner-native facility to activate.
func (r *Runtime) ActivateOwner() error {
	if r.ownerStartup != nil {
		return r.ownerStartup()
	}
	return nil
}

// CloseOwnerArtifacts fails while any helper-capable Run resource is borrowed.
func (r *Runtime) CloseOwnerArtifacts() error {
	if r.ownerArtifactsClose != nil {
		return r.ownerArtifactsClose()
	}
	return nil
}
