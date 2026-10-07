// Synthetic stdio account server for owner consumer lifecycle tests. No model,
// actual credential, external endpoint, or production invocation selects this.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

func main() {
	runtime.GOMAXPROCS(2)
	root := filepath.Dir(filepath.Dir(os.Getenv("CODEX_HOME")))
	modeBytes, _ := os.ReadFile(filepath.Join(root, "fixture-mode"))
	mode := string(modeBytes)
	if mode == "kill" {
		signal.Ignore(syscall.SIGTERM)
	}
	if mode == "badjson" {
		_, _ = os.Stdout.WriteString("not JSON\n")
		return
	}
	if mode == "stderr" {
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("S"), (1<<20)+1))
		return
	}
	_ = os.WriteFile(filepath.Join(root, "fixture-started"), []byte("started"), 0600)
	scan := bufio.NewScanner(os.Stdin)
	accountReplied := false
	for scan.Scan() {
		var request struct {
			ID     *int   `json:"id"`
			Method string `json:"method"`
			Params struct {
				Refresh bool `json:"refreshToken"`
			} `json:"params"`
		}
		if json.Unmarshal(scan.Bytes(), &request) != nil {
			os.Exit(2)
		}
		if request.ID == nil {
			continue
		}
		var result any = map[string]any{}
		switch request.Method {
		case "initialize":
			if mode == "stale" {
				refresh(mode)
			}
		case "account/read":
			if request.Params.Refresh {
				refresh(mode)
			}
			result = map[string]any{"account": map[string]string{"type": "chatgpt", "email": "synthetic@example.invalid"}, "requiresOpenaiAuth": true}
			if mode == "invalid-account" {
				result = map[string]any{"account": nil}
			}
		default:
			os.Exit(3)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"id": *request.ID, "result": result}); err != nil {
			os.Exit(13)
		}
		if request.Method == "account/read" {
			accountReplied = true
		}
		if request.Method == "initialize" {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"method": "synthetic/notice", "params": map[string]any{}, "emittedAtMs": time.Now().UnixMilli()})
		}
		if mode == "extra-response" && request.Method == "account/read" {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": 99, "result": map[string]any{}})
		}
	}
	if mode == "delayed-eof" {
		if scan.Err() != nil || !accountReplied {
			os.Exit(10)
		}
		marker, err := os.OpenFile(filepath.Join(root, "fixture-eof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			os.Exit(11)
		}
		_, writeErr := marker.WriteString("EOF_AFTER_ACCOUNT\n")
		closeErr := marker.Close()
		if writeErr != nil || closeErr != nil {
			os.Exit(12)
		}
		// Longer than the old five-second cutoff, within normal eight-second grace.
		time.Sleep(6 * time.Second)
	}
	if mode == "hang" || mode == "kill" {
		for {
			time.Sleep(time.Hour)
		}
	}
}

func refresh(mode string) {
	path := filepath.Join(os.Getenv("CODEX_HOME"), "auth.json")
	data, err := os.ReadFile(path)
	if err != nil {
		os.Exit(4)
	}
	var auth map[string]any
	if json.Unmarshal(data, &auth) != nil {
		os.Exit(5)
	}
	tokens := auth["tokens"].(map[string]any)
	body, _ := json.Marshal(map[string]any{"grant_type": "refresh_token", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann", "refresh_token": tokens["refresh_token"]})
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Post(os.Getenv("CODEX_REFRESH_TOKEN_URL_OVERRIDE"), "application/json", bytes.NewReader(body))
	if err != nil {
		os.Exit(6)
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || resp.StatusCode != 200 {
		os.Exit(7)
	}
	if mode == "readonly" {
		return
	}
	var updated map[string]string
	if json.Unmarshal(response, &updated) != nil {
		os.Exit(8)
	}
	for _, name := range []string{"access_token", "refresh_token", "id_token"} {
		tokens[name] = updated[name]
	}
	if mode == "mismatch" {
		tokens["access_token"] = "SYNTHETIC_UNRELATED"
	}
	auth["last_refresh"] = time.Now().UTC().Format(time.RFC3339Nano)
	data, _ = json.Marshal(auth)
	if os.WriteFile(path, data, 0600) != nil {
		os.Exit(9)
	}
}
