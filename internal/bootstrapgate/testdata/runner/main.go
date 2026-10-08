// A synthetic fixed successor for the isolated mount-gate fixture only.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	_, _ = fmt.Fprintln(os.Stdout, "synthetic-runner-ready")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 128), 256)
	if !scanner.Scan() {
		os.Exit(2)
	}
	nonce := scanner.Text()
	if len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" {
		os.Exit(2)
	}
	data, err := os.ReadFile("/tmp/hgw-codex-home/auth.json")
	if err != nil || string(data) != "synthetic-in-place" {
		os.Exit(2)
	}
	if os.WriteFile("/tmp/hgw-codex-home/auth.json", []byte("synthetic-runner-update"), 0o600) != nil {
		os.Exit(2)
	}
	if os.WriteFile("/tmp/mount-gate-marker", []byte(nonce), 0o600) != nil {
		os.Exit(2)
	}
	_, _ = fmt.Fprintln(os.Stdout, "synthetic-marker-written")
	if !scanner.Scan() || scanner.Text() != "finish" {
		os.Exit(2)
	}
}
