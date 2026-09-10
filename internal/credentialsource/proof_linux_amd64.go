//go:build linux && amd64

package credentialsource

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux x86_64 UAPI: _IOR(0x15, 0, struct fsuuid2), a length byte + 16 bytes.
// This read-only request and the fixed handle buffer deliberately have no
// capability escalation, open_by_handle_at, resize retry or legacy fallback.
const fsIOCGetFSUUID = 0x80111500

func nativeIdentity(files [3]*os.File, ids [3]objectID) (kernelIdentity, error) {
	if err := attestExt4(files, ids); err != nil {
		return kernelIdentity{}, err
	}
	uuid, err := filesystemUUID(files[2])
	if err != nil {
		return kernelIdentity{}, err
	}
	result := kernelIdentity{uuid: uuid}
	for i, file := range files {
		result.handles[i], err = descriptorHandle(file, ids[i].mount)
		if err != nil {
			return kernelIdentity{}, err
		}
	}
	// Reject an observed UUID change within collection as well as a changed
	// mount view. This remains an observation under the trusted-host assumption.
	again, err := filesystemUUID(files[2])
	if err != nil || string(again) != string(uuid) || attestExt4(files, ids) != nil {
		return kernelIdentity{}, ErrUnavailable
	}
	return result, nil
}

func filesystemUUID(file *os.File) ([]byte, error) {
	var response [17]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), fsIOCGetFSUUID, uintptr(unsafe.Pointer(&response[0])))
	runtime.KeepAlive(file)
	if errno != 0 || response[0] != 16 {
		return nil, ErrUnavailable
	}
	var nonzero byte
	for _, b := range response[1:] {
		nonzero |= b
	}
	if nonzero == 0 {
		return nil, ErrUnavailable
	}
	return response[1:], nil
}

func descriptorHandle(file *os.File, expectedMount uint64) (fileHandle, error) {
	response := struct {
		length uint32
		kind   int32
		data   [8]byte
	}{length: 8}
	var mount int32
	var empty [1]byte
	_, _, errno := unix.Syscall6(unix.SYS_NAME_TO_HANDLE_AT, file.Fd(), uintptr(unsafe.Pointer(&empty[0])),
		uintptr(unsafe.Pointer(&response)), uintptr(unsafe.Pointer(&mount)), unix.AT_EMPTY_PATH, 0)
	runtime.KeepAlive(file)
	if errno != 0 || response.length != 8 || response.kind != 1 || mount <= 0 || uint64(mount) != expectedMount {
		return fileHandle{}, ErrUnavailable
	}
	return fileHandle{response.kind, response.data[:]}, nil
}
