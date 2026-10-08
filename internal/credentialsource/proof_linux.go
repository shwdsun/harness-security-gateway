//go:build linux

package credentialsource

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var ErrProofMismatch = errors.New("credentialsource: enrollment proof mismatch")

// CaptureProof returns a fresh identity observation of the retained objects,
// with held/path validation before and after collection. It reads no auth
// contents and exposes no raw UUID, handle, FD or path. Failure latches this
// handle invalid, retaining its locks. This is not enrollment or a mount permit.
func (h *HeldSource) CaptureProof() (string, Proof, error) {
	return h.observeProof(nativeIdentity, nil)
}

// VerifyProof compares fresh kernel observations with trusted enrolled data.
// A mismatch invalidates this handle until Close, without releasing its locks
// or changing database occupancy/revocation. Malformed expectations are rejected
// before observation. Success does not attest Run scope, runtime or persistence.
func (h *HeldSource) VerifyProof(sourceDigest string, expected Proof) error {
	_, _, err := h.observeProof(nativeIdentity, &proofExpectation{sourceDigest, expected})
	return err
}

type proofExpectation struct {
	sourceDigest string
	proof        Proof
}

type fileHandle struct {
	kind int32
	data []byte
}

type kernelIdentity struct {
	uuid    []byte
	handles [3]fileHandle
}

// This seam is private and supplied explicitly only by package tests. Public
// methods always use nativeIdentity; no config/env/input can inject identity.
type identityReader func([3]*os.File, [3]objectID) (kernelIdentity, error)

func (h *HeldSource) observeProof(read identityReader, expected *proofExpectation) (string, Proof, error) {
	if h == nil {
		return "", Proof{}, ErrClosed
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.file == nil {
		return "", Proof{}, ErrClosed
	}
	if h.invalid {
		return "", Proof{}, ErrChanged
	}
	if expected != nil && (!digestText(expected.sourceDigest) || expected.proof.Validate() != nil) {
		return "", Proof{}, ErrInvalidProof
	}
	if h.validate() != nil {
		h.invalid = true
		return "", Proof{}, ErrChanged
	}
	observed, err := read([3]*os.File{h.root, h.slot, h.file}, h.identity)
	if err != nil {
		h.invalid = true
		return "", Proof{}, ErrUnavailable
	}
	var digests [3]string
	for i := range digests {
		digests[i], err = objectDigest(observed.uuid, observed.handles[i])
		if err != nil {
			h.invalid = true
			return "", Proof{}, ErrUnavailable
		}
	}
	locator, err := locatorDigest(h.rootPath, h.directory)
	if err != nil || h.validate() != nil {
		h.invalid = true
		return "", Proof{}, ErrChanged
	}
	proof := Proof{EnrollmentScheme, digests[0], digests[1], locator}
	if expected != nil && (expected.sourceDigest != digests[2] || expected.proof != proof) {
		h.invalid = true
		return "", Proof{}, ErrProofMismatch
	}
	return digests[2], proof, nil
}

func objectDigest(uuid []byte, handle fileHandle) (string, error) {
	if len(uuid) != 16 || handle.kind != 1 || len(handle.data) != 8 {
		return "", ErrUnavailable
	}
	var nonzero byte
	for _, b := range uuid {
		nonzero |= b
	}
	if nonzero == 0 {
		return "", ErrUnavailable
	}
	data := []byte("harness-security-gateway.credential-object/ext4-v1\x00")
	data = append(data, uuid...)
	data = binary.BigEndian.AppendUint32(data, uint32(handle.kind))
	data = binary.BigEndian.AppendUint32(data, uint32(len(handle.data)))
	data = append(data, handle.data...)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func locatorDigest(root, directory string) (string, error) {
	if !utf8.ValidString(root) || !rootName(root) || !slotName(directory) {
		return "", ErrUnsafe
	}
	data := []byte("harness-security-gateway.credential-locator/v1\x00")
	data = binary.BigEndian.AppendUint32(data, uint32(len(root)))
	data = append(data, root...)
	data = binary.BigEndian.AppendUint32(data, uint32(len(directory)))
	data = append(data, directory...)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

const maxMountInfoBytes = 2 << 20

// mountIsExt4 identifies exactly one record by held mount ID AND device.
// Paths, mount sources and optional fields are never used as authority or
// returned in errors. An oversized view or malformed/ambiguous matching record
// fails closed.
func mountIsExt4(r io.Reader, id objectID) bool {
	data, err := io.ReadAll(io.LimitReader(r, maxMountInfoBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxMountInfoBytes || data[len(data)-1] != '\n' {
		return false
	}
	found := false
	for _, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return false
		}
		mount, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || mount == 0 || strconv.FormatUint(mount, 10) != fields[0] {
			return false
		}
		if mount != id.mount {
			continue
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		device := strconv.FormatUint(uint64(id.deviceMajor), 10) + ":" + strconv.FormatUint(uint64(id.deviceMinor), 10)
		if found || separator < 6 || len(fields) != separator+4 || fields[separator+1] != "ext4" || fields[2] != device {
			return false
		}
		found = true
	}
	return found
}

func attestExt4(files [3]*os.File, ids [3]objectID) error {
	for _, id := range ids {
		if id.mount != ids[0].mount || id.deviceMajor != ids[0].deviceMajor || id.deviceMinor != ids[0].deviceMinor {
			return ErrUnavailable
		}
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(files[2].Fd()), &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
		return ErrUnavailable
	}
	mounts, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ErrUnavailable
	}
	defer mounts.Close()
	if !mountIsExt4(mounts, ids[0]) {
		return ErrUnavailable
	}
	return nil
}
