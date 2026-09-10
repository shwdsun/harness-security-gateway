//go:build linux && amd64

package credentialsource

import (
	"strings"
	"testing"
)

func TestContainerIdentityRequiresWholeInitAndCgroup(t *testing.T) {
	status := "Name:\tbootstrap\nUid:\t1000\t1000\t1000\t1000\nNSpid:\t1234\t1\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nTracerPid:\t0\n"
	if !containerInitStatus([]byte(status), 1234, 1000) {
		t.Fatal("valid init refused")
	}
	for _, bad := range []string{
		strings.Replace(status, "1234\t1", "1234\t2", 1), strings.Replace(status, "1234\t1", "1235\t1", 1),
		strings.Replace(status, "1000\t1000\t1000\t1000", "1000\t1001\t1000\t1000", 1),
		strings.Replace(status, "0000000000000000", "0000000000000001", 1),
		strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1),
		strings.Replace(status, "TracerPid:\t0", "TracerPid:\t99", 1), status + "NSpid:\t1234\t1\n",
		strings.Replace(status, "CapEff:\t0000000000000000\n", "", 1),
	} {
		if containerInitStatus([]byte(bad), 1234, 1000) {
			t.Fatal("unbound init accepted")
		}
	}
	ref := strings.Repeat("a", 64)
	base := "0::/user.slice/user-1000.slice/docker-" + ref + ".scope\n"
	if !containerCgroup([]byte(base), ref) || !containerCgroup([]byte("0::/user.slice/docker/"+ref+"\n"), ref) {
		t.Fatal("valid cgroup refused")
	}
	for _, bad := range []string{base + base, strings.TrimSuffix(base, "\n"), strings.Replace(base, ref, ref[:63], 1), strings.Replace(base, ".scope\n", ".scope/child\n", 1), strings.Replace(base, "0::", "1:cpu:", 1), strings.Replace(base, ref, strings.Repeat("b", 64), 1)} {
		if containerCgroup([]byte(bad), ref) {
			t.Fatal("unattributed cgroup accepted")
		}
	}
}

func TestMountedFileRequiresExactRWExt4ReceiverView(t *testing.T) {
	id := objectID{deviceMajor: 8, deviceMinor: 1, inode: 42, mount: 99}
	valid := "99 20 8:1 /owned/slot/auth.json /tmp/hgw-codex-home/auth.json rw,nosuid - ext4 /dev/example rw\n"
	if !credentialFileMount([]byte(valid), id) {
		t.Fatal("valid file mount refused")
	}
	for _, bad := range []string{valid + valid, strings.Replace(valid, "8:1", "8:2", 1), strings.Replace(valid, " - ext4 ", " - tmpfs ", 1), strings.Replace(valid, "/tmp/hgw-codex-home/auth.json", "/tmp/elsewhere", 1), strings.Replace(valid, "rw,nosuid", "ro,nosuid", 1), strings.Replace(valid, "rw,nosuid", "rw,ro", 1), strings.TrimSuffix(valid, "rw\n") + "ro\n", strings.Replace(valid, "/owned/slot/auth.json", "/", 1), strings.TrimSuffix(valid, "\n")} {
		if credentialFileMount([]byte(bad), id) {
			t.Fatal("unsupported mount accepted")
		}
	}
}
