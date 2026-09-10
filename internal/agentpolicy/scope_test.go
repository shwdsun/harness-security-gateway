package agentpolicy

import (
	"errors"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/sessionauth"
)

func TestSessionScopeUsesFrozenExactBinding(t *testing.T) {
	config := policyFixture()
	policy, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policy.Endpoint("discord-main")
	if err != nil {
		t.Fatal(err)
	}
	want := sessionauth.Scope{
		BindingFingerprint: "9570bad2719b82d7030684ea1f686dbaa9e6228f2dbcdf699dfc5cabd9dbcbc7",
		ConnectorID:        "discord-main", ActorRef: "discord:user:100", ConversationRef: "discord:dm:200",
		TargetID: "project-codex", TargetRevision: "r1",
	}
	for range 2 {
		got, err := endpoint.SessionScope(want.ActorRef, want.ConversationRef)
		if err != nil || got != want {
			t.Fatalf("approved scope = %#v, %v", got, err)
		}
		if _, err := sessionauth.Digest(got); err != nil {
			t.Fatal(err)
		}
		// Mutating the source config or a returned value cannot change the
		// compiled endpoint used for independent enrollment/target resolution.
		config.Bindings[0].Target.Revision = "r2"
		got.TargetRevision = "caller-mutation"
	}
	changed, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	changedEndpoint, _ := changed.Endpoint("discord-main")
	next, err := changedEndpoint.SessionScope(want.ActorRef, want.ConversationRef)
	if err != nil || next.TargetRevision != "r2" || next.BindingFingerprint == want.BindingFingerprint {
		t.Fatalf("new binding did not change scope: %#v, %v", next, err)
	}
}

func TestSessionScopeNeverProjectsDeniedAuthority(t *testing.T) {
	policy, err := Compile(policyFixture())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, _ := policy.Endpoint("discord-main")
	for _, test := range []struct {
		actor, conversation string
		want                error
	}{
		{"discord:user:999", "discord:dm:200", ErrNoBinding},
		{"discord:user:100", "discord:dm:999", ErrNoBinding},
		{"discord:bot:1", "discord:dm:200", ErrSelfEvent},
		{"", "discord:dm:200", ErrInvalid},
	} {
		scope, err := endpoint.SessionScope(test.actor, test.conversation)
		if !errors.Is(err, test.want) || scope != (sessionauth.Scope{}) {
			t.Fatalf("denied pair projected scope: %#v, %v", scope, err)
		}
	}
	if scope, err := (Endpoint{}).SessionScope("actor", "conversation"); !errors.Is(err, ErrInvalid) || scope != (sessionauth.Scope{}) {
		t.Fatalf("zero endpoint projected scope: %#v, %v", scope, err)
	}
}
