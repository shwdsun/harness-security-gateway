package agentpolicy

import (
	"errors"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
)

func policyFixture() agentconfig.Config {
	return agentconfig.Config{
		Schema:                  agentconfig.SchemaV3,
		Database:                "/var/lib/hgw/agentd.sqlite3",
		SandboxSocket:           "/run/hgw/sandboxd.sock",
		RunTimeoutSeconds:       300,
		DeliveryLeaseSeconds:    30,
		RunDispatchLeaseSeconds: 30,
		Ingress: agentconfig.Ingress{
			AcceptWindowSeconds: 300, ReceiptWindowSeconds: 3600,
			FutureSkewSeconds: 60, MaxReceiptsPerConnector: 128,
			MaxQueuedRunsPerConnector: 16, MaxNonTerminalRunsPerConnector: 32,
			MaxPendingDeliveriesPerConnector:  128,
			MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16_384,
		},
		Connectors: []agentconfig.Connector{
			{ID: "discord-main", Socket: "/run/hgw/connectors/discord/agentd.sock", PeerUID: 1000, SelfActorRef: "discord:bot:1"},
			{ID: "matrix-main", Socket: "/run/hgw/connectors/matrix/agentd.sock", PeerUID: 1001, SelfActorRef: "matrix:bot:1"},
		},
		Bindings: []agentconfig.Binding{
			{
				ID: "discord-private", ConnectorID: "discord-main",
				ActorRef: "discord:user:100", ConversationRef: "discord:dm:200",
				Target: agentconfig.TargetRef{ID: "project-codex", Revision: "r1"},
			},
			{
				ID: "matrix-private", ConnectorID: "matrix-main",
				ActorRef: "matrix:user:100", ConversationRef: "matrix:room:200",
				Target: agentconfig.TargetRef{ID: "project-claude", Revision: "r2"},
			},
		},
	}
}

func TestExactBindingAuthorizationRejectsCartesianProduct(t *testing.T) {
	policy, err := Compile(policyFixture())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policy.Endpoint("discord-main")
	if err != nil {
		t.Fatal(err)
	}
	decision, err := endpoint.Authorize("discord:user:100", "discord:dm:200")
	if err != nil {
		t.Fatal(err)
	}
	if decision.TargetID != "project-codex" || decision.TargetRevision != "r1" ||
		len(decision.BindingFingerprint) != 64 || decision.PolicyRevision != policy.Revision() {
		t.Fatalf("decision = %#v", decision)
	}
	const expectedFingerprint = "9570bad2719b82d7030684ea1f686dbaa9e6228f2dbcdf699dfc5cabd9dbcbc7"
	if decision.BindingFingerprint != expectedFingerprint {
		t.Fatalf("binding fingerprint = %q, want %q", decision.BindingFingerprint, expectedFingerprint)
	}
	for _, tuple := range [][2]string{
		{"discord:user:999", "discord:dm:200"},
		{"discord:user:100", "discord:dm:999"},
		{"discord:user:999", "discord:dm:999"},
	} {
		if _, err := endpoint.Authorize(tuple[0], tuple[1]); !errors.Is(err, ErrNoBinding) {
			t.Fatalf("Authorize(%q,%q) error = %v, want ErrNoBinding", tuple[0], tuple[1], err)
		}
	}
	if _, err := endpoint.Authorize("discord:bot:1", "discord:dm:200"); !errors.Is(err, ErrSelfEvent) {
		t.Fatalf("self event error = %v, want ErrSelfEvent", err)
	}
}

func TestPolicyHashesAreStableAndAuthoritySensitive(t *testing.T) {
	config := policyFixture()
	first, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	const expectedPolicyRevision = "f8bf69f1aa2902befd5669eea08f5397495a8fd3c527aeda16c92c61fcff4eef"
	if first.Revision() != expectedPolicyRevision {
		t.Fatalf("policy revision = %q, want %q", first.Revision(), expectedPolicyRevision)
	}
	firstEndpoint, _ := first.Endpoint("discord-main")
	firstDecision, _ := firstEndpoint.Authorize("discord:user:100", "discord:dm:200")

	// Ordering, binding labels, socket paths, and non-policy operational limits
	// do not alter the ingress decision relation.
	config.Connectors[0], config.Connectors[1] = config.Connectors[1], config.Connectors[0]
	config.Bindings[0], config.Bindings[1] = config.Bindings[1], config.Bindings[0]
	config.Bindings[1].ID = "renamed-human-label"
	config.Connectors[1].Socket = "/run/hgw/connectors/discord-renamed/agentd.sock"
	config.RunTimeoutSeconds++
	second, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	secondEndpoint, _ := second.Endpoint("discord-main")
	secondDecision, _ := secondEndpoint.Authorize("discord:user:100", "discord:dm:200")
	if first.Revision() != second.Revision() ||
		firstDecision.BindingFingerprint != secondDecision.BindingFingerprint {
		t.Fatalf("non-authority mutation changed hashes: first=%#v second=%#v", firstDecision, secondDecision)
	}

	config.Connectors[1].PeerUID++
	peerChanged, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	peerEndpoint, _ := peerChanged.Endpoint("discord-main")
	peerDecision, _ := peerEndpoint.Authorize("discord:user:100", "discord:dm:200")
	if first.Revision() == peerChanged.Revision() ||
		firstDecision.BindingFingerprint != peerDecision.BindingFingerprint {
		t.Fatalf("peer authority mutation hashes: first=%#v peer=%#v", firstDecision, peerDecision)
	}
	config.Connectors[1].PeerUID--

	config.Bindings[1].Target.Revision = "r3"
	third, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	thirdEndpoint, _ := third.Endpoint("discord-main")
	thirdDecision, _ := thirdEndpoint.Authorize("discord:user:100", "discord:dm:200")
	if first.Revision() == third.Revision() ||
		firstDecision.BindingFingerprint == thirdDecision.BindingFingerprint {
		t.Fatalf("authority mutation did not change hashes: first=%#v third=%#v", firstDecision, thirdDecision)
	}
}

func TestCompiledPolicyOwnsConfigurationSnapshot(t *testing.T) {
	config := policyFixture()
	policy, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policy.Endpoint("discord-main")
	if err != nil {
		t.Fatal(err)
	}
	config.Bindings[0].ActorRef = "discord:user:mutated"
	config.Bindings[0].Target.ID = "mutated-target"
	config.Connectors[0].SelfActorRef = "discord:bot:mutated"
	decision, err := endpoint.Authorize("discord:user:100", "discord:dm:200")
	if err != nil || decision.TargetID != "project-codex" {
		t.Fatalf("compiled snapshot changed: %#v, %v", decision, err)
	}
	if _, err := policy.Endpoint("missing"); !errors.Is(err, ErrUnknownConnector) {
		t.Fatalf("unknown endpoint error = %v", err)
	}
}
