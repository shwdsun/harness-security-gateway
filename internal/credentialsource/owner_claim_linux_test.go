//go:build linux

package credentialsource

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestOwnerClaimIsExactSharedAndOneUse(t *testing.T) {
	_, held, owner := ownerFixture(t)
	s := owner.state
	if owner.ValidateClaimed(s.runID, s.fingerprint, s.binding) == nil {
		t.Fatal("unclaimed runtime use")
	}
	wrong := s.binding
	wrong.Generation++
	if owner.Claim(s.runID, s.fingerprint, wrong) == nil {
		t.Fatal("wrong generation claimed")
	}
	copy := *owner
	var successes atomic.Int32
	var wg sync.WaitGroup
	for _, cap := range []*OwnerAccess{owner, &copy} {
		wg.Add(1)
		go func(o *OwnerAccess) {
			defer wg.Done()
			if o.Claim(s.runID, s.fingerprint, s.binding) == nil {
				successes.Add(1)
			}
		}(cap)
	}
	wg.Wait()
	if successes.Load() != 1 || owner.ValidateClaimed(s.runID, s.fingerprint, s.binding) != nil {
		t.Fatal("copy/concurrent Create authority repeated")
	}
	copy.Close()
	if owner.ValidateClaimed(s.runID, s.fingerprint, s.binding) == nil || owner.Claim(s.runID, s.fingerprint, s.binding) == nil {
		t.Fatal("closed borrow revived")
	}
	if held.Validate() != nil {
		t.Fatal("borrow close retired healthy original source")
	}
}
