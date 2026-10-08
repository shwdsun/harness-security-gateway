//go:build !linux

package credentialsource

// No owner capability can be constructed on an unsupported platform.
type OwnerAccess struct{}

func (*OwnerAccess) Claim(string, string, Binding) error           { return ErrInvalidHandoff }
func (*OwnerAccess) ValidateClaimed(string, string, Binding) error { return ErrInvalidHandoff }
func (*OwnerAccess) Close()                                        {}
