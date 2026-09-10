//go:build linux

package credentialsource

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	ErrUnsafe      = errors.New("credentialsource: unsafe source")
	ErrUnavailable = errors.New("credentialsource: required filesystem mechanism unavailable")
	ErrBusy        = errors.New("credentialsource: source already held")
	ErrChanged     = errors.New("credentialsource: held source invalidated")
	ErrClosed      = errors.New("credentialsource: source closed")
)

// HeldSource pins one local source and holds advisory locks on its slot and
// file. It must not be copied. It exposes neither credential bytes nor a mount
// path/FD. It is not a durable credential identity, enrollment or Run lease.
// Losing this handle never authorizes releasing the store's Run occupancy.
type HeldSource struct {
	mu        sync.Mutex
	rootPath  string
	directory string
	uid       uint32
	root      *os.File
	slot      *os.File
	file      *os.File
	identity  [3]objectID
	invalid   bool
	closed    bool
	closeErr  error
}

// objectID is only a comparison key while objects are held in this process and
// mount namespace. Never hash it into the store's permanent SourceDigest:
// device/inode and mount IDs may be reused after their lifetime ends.
type objectID struct {
	deviceMajor, deviceMinor uint32
	inode, mount             uint64
}

const beneath = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV
const statMask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_NLINK | unix.STATX_INO | unix.STATX_MNT_ID

// Hold accepts a trusted local canonical root and one slot directory component.
// It opens only an existing dedicated root/directory/auth.json. It reads no
// credential contents, creates or chmods nothing, and never follows configured
// symlinks or crosses a mount beneath the root. Unsupported mechanisms fail
// closed. The host, ancestors and mount namespace must remain trusted.
func Hold(root, directory string) (*HeldSource, error) {
	if os.Geteuid() == 0 || !rootName(root) || !slotName(directory) {
		return nil, ErrUnsafe
	}
	h := &HeldSource{rootPath: root, directory: directory, uid: uint32(os.Geteuid())}
	success := false
	defer func() {
		if !success {
			_ = h.Close()
		}
	}()
	var err error
	h.root, err = openRoot(root, h.uid)
	if err != nil {
		return nil, err
	}
	// Restrict this primitive to local filesystem families. In particular,
	// remote flock semantics are outside the supported contract. Overlay still
	// assumes trusted local backing storage and a stable mount namespace.
	var fs unix.Statfs_t
	if unix.Fstatfs(int(h.root.Fd()), &fs) != nil {
		return nil, ErrUnavailable
	}
	switch fs.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
	default:
		return nil, ErrUnavailable
	}
	h.slot, err = openBelow(h.root, directory, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	if _, err = privateObject(h.slot, h.uid, false); err != nil {
		return nil, err
	}
	// The slot lock also blocks cooperating re-acquisition after auth.json is
	// replaced. A lock solely on the old auth inode would not do that.
	if err = lock(h.slot); err != nil {
		return nil, err
	}
	pinned, err := openBelow(h.slot, "auth.json", unix.O_PATH)
	if err != nil {
		return nil, err
	}
	defer pinned.Close()
	id, err := privateObject(pinned, h.uid, true)
	if err != nil {
		return nil, err
	}
	// O_PATH first inspects even a substituted FIFO/device without opening it
	// for I/O. Reopen only that pinned, verified regular object through trusted
	// procfs, never the potentially replaced directory entry. No read is issued.
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(int(pinned.Fd())), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	h.file = os.NewFile(uintptr(fd), "credential-source")
	current, err := privateObject(h.file, h.uid, true)
	if err != nil || current != id {
		return nil, ErrUnsafe
	}
	if err = lock(h.file); err != nil {
		return nil, err
	}
	for i, f := range []*os.File{h.root, h.slot, h.file} {
		h.identity[i], err = privateObject(f, h.uid, i == 2)
		if err != nil {
			return nil, err
		}
	}
	if err = h.Validate(); err != nil {
		return nil, err
	}
	success = true
	return h, nil
}

// Validate compares fresh path resolution with held objects and checks both
// metadata and the dedicated slot's entry names. A failed observation latches
// invalidation; restoring a path cannot revive the handle. Locks remain held
// until Close. Success is an observation, not an atomic mount/start permit or
// proof of token refresh, durability, continuous exclusion or runtime cleanup.
func (h *HeldSource) Validate() error {
	if h == nil {
		return ErrClosed
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.file == nil {
		return ErrClosed
	}
	if h.invalid {
		return ErrChanged
	}
	if err := h.validate(); err != nil {
		h.invalid = true
		return ErrChanged
	}
	return nil
}

func (h *HeldSource) validate() error {
	for i, f := range []*os.File{h.root, h.slot, h.file} {
		id, err := privateObject(f, h.uid, i == 2)
		if err != nil || id != h.identity[i] {
			return ErrChanged
		}
	}
	root, err := openRoot(h.rootPath, h.uid)
	if err != nil {
		return err
	}
	defer root.Close()
	slot, err := openBelow(root, h.directory, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer slot.Close()
	file, err := openBelow(slot, "auth.json", unix.O_PATH)
	if err != nil {
		return err
	}
	defer file.Close()
	for i, f := range []*os.File{root, slot, file} {
		id, err := privateObject(f, h.uid, i == 2)
		if err != nil || id != h.identity[i] {
			return ErrChanged
		}
	}
	names, err := slot.Readdirnames(2)
	if err != nil && !errors.Is(err, io.EOF) || len(names) != 1 || names[0] != "auth.json" {
		return ErrChanged
	}
	return nil
}

// Close releases only process-local descriptors and advisory locks. The caller
// owns cleanup ordering; Close is never evidence that a runtime has stopped.
// It is idempotent and safe to call concurrently with Validate.
func (h *HeldSource) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return h.closeErr
	}
	h.closed = true
	for _, f := range []*os.File{h.file, h.slot, h.root} {
		if f != nil && f.Close() != nil {
			h.closeErr = ErrUnavailable
		}
	}
	return h.closeErr
}

func openBelow(parent *os.File, name string, flags int) (*os.File, error) {
	return openAt(int(parent.Fd()), name, flags, beneath)
}

func openAt(parent int, name string, flags int, resolve uint64) (*os.File, error) {
	fd, err := unix.Openat2(parent, name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: resolve})
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return nil, ErrUnavailable
		}
		return nil, ErrUnsafe
	}
	return os.NewFile(uintptr(fd), "credential-object"), nil
}

func openRoot(path string, uid uint32) (*os.File, error) {
	current, err := openAt(unix.AT_FDCWD, "/", unix.O_PATH|unix.O_DIRECTORY, unix.RESOLVE_NO_SYMLINKS)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(path[1:], "/")
	for i, part := range parts {
		st, err := metadata(current)
		if err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uid) ||
			(st.Mode&0o022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) {
			current.Close()
			return nil, ErrUnsafe
		}
		// Operator-selected ancestors may cross mounts (for example /home).
		// No symlink is allowed; crossings beneath the final root are forbidden.
		next, err := openAt(int(current.Fd()), part, unix.O_PATH|unix.O_DIRECTORY, unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS)
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
		if i == len(parts)-1 {
			if _, err := privateObject(current, uid, false); err != nil {
				current.Close()
				return nil, err
			}
		}
	}
	return current, nil
}

func metadata(f *os.File) (unix.Statx_t, error) {
	var st unix.Statx_t
	if unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, statMask, &st) != nil || st.Mask&statMask != statMask {
		return st, ErrUnavailable
	}
	return st, nil
}

func privateObject(f *os.File, uid uint32, file bool) (objectID, error) {
	st, err := metadata(f)
	if err != nil {
		return objectID{}, err
	}
	want := uint16(unix.S_IFDIR | 0o700)
	if file {
		want = unix.S_IFREG | 0o600
	}
	if st.Mode != want || st.Uid != uid || file && st.Nlink != 1 {
		return objectID{}, ErrUnsafe
	}
	return objectID{st.Dev_major, st.Dev_minor, st.Ino, st.Mnt_id}, nil
}

func lock(f *os.File) error {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return ErrBusy
		}
		return ErrUnavailable
	}
	return nil
}

func rootName(s string) bool {
	if !filepath.IsAbs(s) || s == "/" || len(s) > 4096 || s != filepath.Clean(s) {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func slotName(s string) bool {
	if len(s) == 0 || len(s) > 128 || strings.HasPrefix(s, ".") || s == "auth.json" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.", c)) {
			return false
		}
	}
	return true
}
