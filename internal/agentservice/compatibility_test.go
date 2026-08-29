package agentservice

import "testing"

// These strings domain-separate persisted event fingerprints. They deliberately
// retain the pre-publication module name: changing them would silently break
// replay compatibility for existing state.
func TestInboundEventHashDomainsRemainStable(t *testing.T) {
	if inboundEventHashDomain != "harnessgateway.local/core/agentservice/inbound-event/v2" {
		t.Fatalf("inbound v2 hash domain changed: %q", inboundEventHashDomain)
	}
	if legacyInboundEventHashDomain != "harnessgateway.local/core/agentservice/inbound-event/v1" {
		t.Fatalf("inbound v1 hash domain changed: %q", legacyInboundEventHashDomain)
	}
}
