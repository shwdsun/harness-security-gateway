package localidentity

import (
	"errors"
	"testing"
)

func TestUIDValidationIsClosed(t *testing.T) {
	for _, uid := range []UID{0, NobodyUID, InvalidUID} {
		if err := uid.Validate(); !errors.Is(err, ErrInvalidUID) {
			t.Fatalf("UID %d error = %v, want ErrInvalidUID", uid, err)
		}
	}
	for _, uid := range []UID{1, 1000, NobodyUID - 1, NobodyUID + 1, InvalidUID - 1} {
		if err := uid.Validate(); err != nil {
			t.Fatalf("UID %d rejected: %v", uid, err)
		}
	}
}
