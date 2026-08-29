package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == crashChildCommand {
		if err := runCrashChildArgs(os.Stdout, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "demo-security test child: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSecurityDemo(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runDemo(&output, executable); err != nil {
		t.Fatalf("runDemo: %v\noutput:\n%s", err, output.String())
	}

	want := strings.Join([]string{
		"Harness Security Gateway security demo",
		"  synthetic input through production wire -> immutable policy -> service -> SQLite; no network, Docker, or credentials",
		"[PASS] 1/5 closed wire authority: target fields and arbitrary actions were rejected by the strict wire schema",
		"[PASS] 2/5 closed control: select_target is recognized but unsupported; no Run was minted",
		"[PASS] 3/5 exact binding: actor/conversation tuple mismatch was denied; no Run was minted",
		"[PASS] 4/5 crash durability: exact child PID was SIGKILLed after the acceptance receipt; reopen replayed run-demo-0001",
		"[PASS] 5/5 replay integrity: exact replay deduplicated; changed payload under the event ID conflicted",
		"RESULT: PASS (operator target workspace-codex@codex-r1 remained authoritative)",
		"",
	}, "\n")
	if output.String() != want {
		t.Fatalf("output mismatch\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestCrashChildArgumentsFailClosed(t *testing.T) {
	var output bytes.Buffer
	for _, args := range [][]string{
		nil,
		{"database-only"},
		{"database", "not-a-timestamp"},
		{"database", "0"},
		{"database", "1", "extra"},
	} {
		if err := runCrashChildArgs(&output, args); err == nil {
			t.Fatalf("runCrashChildArgs(%q) accepted", args)
		}
	}
	if output.Len() != 0 {
		t.Fatalf("invalid child arguments wrote a false receipt: %q", output.String())
	}
}
