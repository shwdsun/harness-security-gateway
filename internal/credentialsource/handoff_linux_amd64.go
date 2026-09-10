//go:build linux && amd64

package credentialsource

import (
	"os"
	"strconv"
	"strings"
)

func openMappedReceiver(h *HeldSource, pid int, ref, bootstrap, source string, proof Proof, uid uint32) (Receiver, error) {
	g, err := h.OpenContainerMount(pid, ref, bootstrap, source, proof)
	if err != nil {
		return nil, err
	}
	g.innerUID = uid
	if err := g.Validate(); err != nil {
		_ = g.Close()
		return nil, err
	}
	return g, nil
}

func (g *ContainerMount) validateMappedIdentity() error {
	if g.innerUID == 0 {
		return nil // Original component witness has no UID-transition template.
	}
	status, err := g.readProc("status", 16<<10)
	if err != nil {
		return mountFailure("bootstrap_privileges", err)
	}
	if !emptyBootstrapCapabilities(status) {
		return mountFailure("bootstrap_privileges", nil)
	}
	groupSeen := false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Gid:" {
			continue
		}
		if groupSeen || len(fields) != 5 {
			return mountFailure("bootstrap_group", nil)
		}
		groupSeen = true
		for _, value := range fields[1:] {
			if value != strconv.Itoa(os.Getegid()) {
				return mountFailure("bootstrap_group", nil)
			}
		}
	}
	if !groupSeen {
		return mountFailure("bootstrap_group", nil)
	}
	for _, item := range []struct {
		name string
		id   int
	}{{"uid_map", os.Geteuid()}, {"gid_map", os.Getegid()}} {
		data, err := g.readProc(item.name, 4096)
		fields := strings.Fields(string(data))
		if err != nil || len(fields) != 3 || fields[0] != strconv.FormatUint(uint64(g.innerUID), 10) ||
			fields[1] != strconv.Itoa(item.id) || fields[2] != "1" {
			return mountFailure("bootstrap_user_mapping", err)
		}
	}
	return nil
}

func emptyBootstrapCapabilities(status []byte) bool {
	want := map[string]bool{"CapInh:": false, "CapPrm:": false, "CapEff:": false, "CapBnd:": false, "CapAmb:": false}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		seen, needed := want[fields[0]]
		if !needed {
			continue
		}
		if seen || len(fields) != 2 || fields[1] != "0000000000000000" {
			return false
		}
		want[fields[0]] = true
	}
	for _, seen := range want {
		if !seen {
			return false
		}
	}
	return true
}
