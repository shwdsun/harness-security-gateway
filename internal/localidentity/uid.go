// Package localidentity defines the closed numeric OS identities accepted at
// local Unix-socket trust boundaries.
package localidentity

import (
	"errors"
	"fmt"
)

// UID is a Linux uid_t represented in versioned JSON as an integer.
type UID uint32

const (
	// NobodyUID is Linux's conventional overflow/nobody identity. It is not a
	// dedicated service principal and can alias unmapped user-namespace peers.
	NobodyUID UID = 65534
	// InvalidUID is (uid_t)-1, reserved by Linux APIs as an invalid/no-change
	// sentinel rather than a usable service identity.
	InvalidUID UID = ^UID(0)
)

var ErrInvalidUID = errors.New("invalid local peer UID")

// Validate accepts only a non-root, non-overflow, concrete Linux service UID.
func (uid UID) Validate() error {
	if uid == 0 || uid == NobodyUID || uid == InvalidUID {
		return fmt.Errorf("%w: must identify one non-root dedicated service user", ErrInvalidUID)
	}
	return nil
}

func (uid UID) Uint32() uint32 { return uint32(uid) }
