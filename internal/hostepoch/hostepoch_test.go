package hostepoch

import (
	"errors"
	"testing"
)

func TestCurrentReturnsCanonicalBootID(t *testing.T) {
	value, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(value); err != nil {
		t.Fatalf("Current() = %q: %v", value, err)
	}
}

func TestValidate(t *testing.T) {
	valid := "01234567-89ab-cdef-0123-456789abcdef"
	if err := Validate(valid); err != nil {
		t.Fatalf("Validate(%q): %v", valid, err)
	}
	for _, value := range []string{
		"",
		valid + "0",
		"01234567_89ab-cdef-0123-456789abcdef",
		"01234567-89AB-cdef-0123-456789abcdef",
		"g1234567-89ab-cdef-0123-456789abcdef",
		"01234567-89ab-cdef-0123-456789abcde\n",
	} {
		if err := Validate(value); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Validate(%q) error = %v, want ErrInvalid", value, err)
		}
	}
}
