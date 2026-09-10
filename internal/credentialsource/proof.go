package credentialsource

import "errors"

const EnrollmentScheme = "linux-ext4-source/v1"

var ErrInvalidProof = errors.New("credentialsource: invalid enrollment proof")

// Proof is non-secret immutable enrollment data. SourceDigest belongs to the
// generation record separately. Neither a constructed Proof nor Validate
// grants authority; only trusted atomic enrollment may supply expected values.
// The portable data shape does not confer native filesystem support.
type Proof struct {
	Scheme           string
	RootObjectDigest string
	SlotObjectDigest string
	LocatorDigest    string
}

// Validate checks the closed scheme and canonical digest representation only.
// It reads no filesystem and does not establish scope, enrollment or readiness.
func (p Proof) Validate() error {
	if p.Scheme != EnrollmentScheme || !digestText(p.RootObjectDigest) ||
		!digestText(p.SlotObjectDigest) || !digestText(p.LocatorDigest) {
		return ErrInvalidProof
	}
	return nil
}

func digestText(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, b := range []byte(value) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
