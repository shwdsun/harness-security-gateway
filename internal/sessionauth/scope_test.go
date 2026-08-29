package sessionauth

import (
	"errors"
	"strings"
	"testing"
)

func validScope() Scope {
	return Scope{
		BindingFingerprint: strings.Repeat("a", 64),
		ConnectorID:        "discord-main",
		ActorRef:           "discord:user:100",
		ConversationRef:    "discord:channel:200",
		TargetID:           "codex-project",
		TargetRevision:     "revision-1",
	}
}

func TestDigestGoldenVectorAndEveryFieldIsSemantic(t *testing.T) {
	base := validScope()
	got, err := Digest(base)
	if err != nil {
		t.Fatal(err)
	}
	const want = "81a4ddc91debf2c86e9fcaaf470470866bc4eb27e7ea04249bb5968cfdf0c6a5"
	if got != want {
		t.Fatalf("Digest() = %q, want %q", got, want)
	}

	changes := map[string]func(*Scope){
		"binding":      func(scope *Scope) { scope.BindingFingerprint = strings.Repeat("b", 64) },
		"connector":    func(scope *Scope) { scope.ConnectorID += "-other" },
		"actor":        func(scope *Scope) { scope.ActorRef += "-other" },
		"conversation": func(scope *Scope) { scope.ConversationRef += "-other" },
		"target":       func(scope *Scope) { scope.TargetID += "-other" },
		"revision":     func(scope *Scope) { scope.TargetRevision += "-other" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			digest, err := Digest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if digest == got {
				t.Fatal("changed scope retained the original digest")
			}
		})
	}
}

func TestDigestRejectsInvalidScope(t *testing.T) {
	tests := map[string]func(*Scope){
		"binding":      func(scope *Scope) { scope.BindingFingerprint = strings.Repeat("A", 64) },
		"connector":    func(scope *Scope) { scope.ConnectorID = "" },
		"actor":        func(scope *Scope) { scope.ActorRef = "bad actor" },
		"conversation": func(scope *Scope) { scope.ConversationRef = "bad\nconversation" },
		"target":       func(scope *Scope) { scope.TargetID = strings.Repeat("t", MaxTargetIDBytes+1) },
		"revision":     func(scope *Scope) { scope.TargetRevision = strings.Repeat("r", MaxRevisionBytes+1) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			scope := validScope()
			change(&scope)
			if _, err := Digest(scope); !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("Digest() error = %v, want ErrInvalidScope", err)
			}
		})
	}
}
