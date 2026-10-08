//go:build linux

package codexprovider

import (
	"strings"
	"testing"
)

func TestOwnerStartupEvidenceRejectsOldOrUncontainedProcesses(t *testing.T) {
	good := serviceObservation{uid: 21002, euid: 21002, pid: 123, cgroup: "0::" + ownerServiceCgroup + "\n",
		uidMap: "         0          0 4294967295\n", mountRoot: true, boundaries: true, leaf: true, domain: "domain\n", members: "123\n",
		status: "Uid:\t21002\t21002\t21002\t21002\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n"}
	if p, err := verifyOwnerStartup(good); err != nil || p.pid != 123 {
		t.Fatal("closed service evidence rejected")
	}
	for name, mutate := range map[string]func(*serviceObservation){
		"namespace invisible member": func(o *serviceObservation) { o.members += "0\n" },
		"threaded domain":            func(o *serviceObservation) { o.domain = "threaded\n" },
		"old helper":                 func(o *serviceObservation) { o.members += "456\n" },
		"other cgroup":               func(o *serviceObservation) { o.cgroup = "0::/user.slice\n" },
		"namespace root":             func(o *serviceObservation) { o.cgroup = "0::/\n" },
		"delegated ancestor":         func(o *serviceObservation) { o.boundaries = false },
		"sub cgroup":                 func(o *serviceObservation) { o.leaf = false },
		"partial mount":              func(o *serviceObservation) { o.mountRoot = false },
		"mapped root":                func(o *serviceObservation) { o.uidMap = "0 21002 1\n" },
		"privileged owner":           func(o *serviceObservation) { o.uid = 0; o.euid = 0 },
		"saved root": func(o *serviceObservation) {
			o.status = strings.Replace(o.status, "21002\t21002\t21002\t21002", "21002\t21002\t0\t21002", 1)
		},
		"missing NNP": func(o *serviceObservation) {
			o.status = strings.Replace(o.status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1)
		},
		"capability": func(o *serviceObservation) {
			o.status = strings.Replace(o.status, "CapEff:\t0000000000000000", "CapEff:\t0000000000000001", 1)
		},
		"ambiguous status": func(o *serviceObservation) { o.status += "NoNewPrivs:\t1\n" },
		"owner absent":     func(o *serviceObservation) { o.members = "" },
	} {
		t.Run(name, func(t *testing.T) {
			o := good
			mutate(&o)
			if p, err := verifyOwnerStartup(o); p != nil || err != ErrOwnerAuth {
				t.Fatal("unverified startup capability issued")
			}
		})
	}
}
