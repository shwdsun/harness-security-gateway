package codexadapter

import (
	"io"
	"reflect"
	"testing"

	"github.com/shwdsun/harness-security-gateway/internal/codexprofile"
)

func TestIsolatedConfigPreservesNativeToolsAndInstructions(t *testing.T) {
	v3 := MessagingToolsConfig(codexprofile.ModelNameV1)
	v4 := IsolatedToolsConfig(codexprofile.ModelNameV1)
	p, instructions, err := v4.resolve()
	if err != nil || p.ID != codexprofile.IDV4 || instructions == "" {
		t.Fatal("isolated profile lost messaging authority", err)
	}
	old, oldInstructions, err := v3.resolve()
	if err != nil || oldInstructions != instructions || old.ToolRuntime != p.ToolRuntime {
		t.Fatal("isolated profile lost fixed native tool behavior")
	}
	a := v3.invocation("synthetic", instructions, "/tmp/final", io.Discard, io.Discard)
	b := v4.invocation("synthetic", instructions, "/tmp/final", io.Discard, io.Discard)
	if !reflect.DeepEqual(a.Args, b.Args) || !reflect.DeepEqual(a.Env, b.Env) || a.Path != b.Path {
		t.Fatal("isolation change altered native fixed invocation")
	}
}
