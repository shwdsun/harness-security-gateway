// Package hostepoch exposes the Linux boot identifier used to prove that a
// process from an earlier boot can no longer complete an in-flight mutation.
package hostepoch

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	bootIDPath     = "/proc/sys/kernel/random/boot_id"
	BootIDBytes    = 36
	maxBootIDInput = BootIDBytes + 1 // one optional trailing newline
)

var (
	ErrUnavailable = errors.New("hostepoch: boot identifier is unavailable")
	ErrInvalid     = errors.New("hostepoch: invalid boot identifier")
)

// Current returns the current Linux boot identifier in canonical lowercase
// UUID form. The procfs input is read through a fixed bound.
func Current() (string, error) {
	file, err := os.Open(bootIDPath)
	if err != nil {
		return "", fmt.Errorf("%w: open boot identifier", ErrUnavailable)
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxBootIDInput+1))
	if err != nil {
		return "", fmt.Errorf("%w: read boot identifier", ErrUnavailable)
	}
	if len(contents) == maxBootIDInput && contents[len(contents)-1] == '\n' {
		contents = contents[:len(contents)-1]
	}
	value := string(contents)
	if err := Validate(value); err != nil {
		return "", err
	}
	return value, nil
}

// Validate accepts exactly a canonical lowercase UUID. A boot identifier is
// an equality token, not a path or a general user-controlled identifier.
func Validate(value string) error {
	if len(value) != BootIDBytes {
		return ErrInvalid
	}
	for index, character := range []byte(value) {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return ErrInvalid
			}
		default:
			if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
				return ErrInvalid
			}
		}
	}
	return nil
}
