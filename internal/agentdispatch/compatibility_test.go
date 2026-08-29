package agentdispatch

import "testing"

// This string domain-separates deterministic delivery identifiers. It is a
// persisted compatibility identifier, not an import path.
func TestDeliveryIDDomainRemainsStable(t *testing.T) {
	if deliveryIDDomain != "harnessgateway.local/core/agentdispatch/text-delivery/v1" {
		t.Fatalf("delivery ID domain changed: %q", deliveryIDDomain)
	}
}
