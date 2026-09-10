//go:build linux && amd64

package dockerruntime

import "testing"

func TestSeccompComparisonPreservesExactNumericPolicy(t *testing.T) {
	original := []byte(`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["clone"],"args":[{"value":9007199254740993,"index":0}]}]}`)
	reordered := []byte(`{"syscalls":[{"args":[{"index":0,"value":9007199254740993}],"names":["clone"]}],"defaultAction":"SCMP_ACT_ERRNO"}`)
	if !sameSeccompJSON(original, reordered) {
		t.Fatal("key ordering changed the frozen policy")
	}
	for _, changed := range []string{
		`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["clone"],"args":[{"value":9007199254740992,"index":0}]}]}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","defaultAction":"SCMP_ACT_ALLOW","syscalls":[]}`,
		`{} {}`, "", `null`,
	} {
		if sameSeccompJSON(original, []byte(changed)) {
			t.Fatal("changed or malformed seccomp matched")
		}
	}
}
