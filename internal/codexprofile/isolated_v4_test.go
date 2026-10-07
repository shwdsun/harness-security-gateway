package codexprofile

import "testing"

func TestIsolatedContractCannotRelabelExposedProfiles(t *testing.T) {
	c := V4()
	fp, err := c.Fingerprint()
	const expected = "8edb914c08502d5b19682bdbdf661414e76301cf8ea61c91561b707d17219edc"
	if fp != expected || ContractFingerprintV4 != expected {
		t.Fatal("sealed V4 fingerprint drift")
	}
	if err != nil || fp == ContractFingerprintV3 || c.Classification == ClassificationV1 || c.Profiles.Auth == AuthProfileRefV1 || c.Runner.AdapterVersion == AdapterVersionV3 {
		t.Fatal("isolation authority reused exposed identity")
	}
	for _, mutate := range []func(*Contract){
		func(c *Contract) { c.Credential.Mount = CredentialMountV1 },
		func(c *Contract) { c.OwnerRuntime.LauncherSHA256 = "" },
		func(c *Contract) { c.OwnerRuntime.Readiness = "in-bootstrap" },
		func(c *Contract) { c.OwnerRuntime.Refresh = "client-request" },
		func(c *Contract) { c.Profiles.Auth = AuthProfileRefV1 },
	} {
		other := c
		mutate(&other)
		if other.Validate() == nil {
			t.Fatal("unsealed owner contract accepted")
		}
	}
	t.Log("V4 fingerprint", fp)
}
