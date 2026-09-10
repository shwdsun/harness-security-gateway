//go:build linux && amd64

// An owned synthetic fixture driver, not a production or message entrypoint.
// Hold survives check failures until the outer fixture confirms exact cleanup.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

type command struct {
	Op        string `json:"op"`
	PID       int    `json:"pid"`
	Ref       string `json:"ref"`
	Bootstrap string `json:"bootstrap"`
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	h, err := credentialsource.Hold(os.Args[1], "slot")
	if err != nil {
		emit(map[string]any{"stage": "hold", "error": err.Error()})
		os.Exit(2)
	}
	defer h.Close()
	source, proof, err := h.CaptureProof()
	if err != nil {
		emit(map[string]any{"stage": "proof", "error": err.Error()})
		os.Exit(2)
	}
	emit(map[string]any{"stage": "source-held"})
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 4096)
	var mount *credentialsource.ContainerMount
	defer func() {
		if mount != nil {
			_ = mount.Close()
		}
	}()
	for scanner.Scan() {
		var cmd command
		if strictjson.Decode(scanner.Bytes(), 4096, 3, &cmd) != nil {
			os.Exit(2)
		}
		switch cmd.Op {
		case "check":
			if mount != nil {
				os.Exit(2)
			}
			mount, err = h.OpenContainerMount(cmd.PID, cmd.Ref, cmd.Bootstrap, source, proof)
			emitCheck(err)
		case "validate":
			if mount == nil {
				os.Exit(2)
			}
			emitCheck(mount.Validate())
		case "finish-after-cleanup":
			err = h.Validate()
			if mount != nil {
				_ = mount.Close()
			}
			closeErr := h.Close()
			emit(map[string]any{"stage": "closed", "source_valid": err == nil, "close_ok": closeErr == nil})
			return
		default:
			os.Exit(2)
		}
	}
	os.Exit(2)
}
func emitCheck(err error) {
	r := map[string]any{"stage": "checked", "accepted": err == nil}
	if e, ok := err.(*credentialsource.MountError); ok {
		r["rejection_stage"] = e.Stage
		r["errno"] = int(e.Errno)
	} else if err != nil {
		r["rejection_stage"] = "source"
	}
	emit(r)
}
func emit(value any) {
	data, err := json.Marshal(value)
	if err != nil {
		os.Exit(2)
	}
	_, _ = fmt.Fprintln(os.Stdout, string(data))
}
