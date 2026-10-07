//go:build linux

package codexprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func refreshData(t *testing.T, a *OwnerAuth) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"access_token": a.access, "refresh_token": a.refresh, "id_token": a.identity})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func refreshInput(t *testing.T, a *OwnerAuth) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"grant_type": "refresh_token", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann", "refresh_token": a.refresh})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ownerFixture(t *testing.T, stamp string) *OwnerAuth {
	t.Helper()
	a, err := ParseOwnerAuth(syntheticOwnerAuth("account-one", "subject-one", stamp))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func sendOwnerRefresh(r *ownerRefresh, data []byte) int {
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Post(r.nativeURL(), "application/json", bytes.NewReader(data))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func joinRefresh(t *testing.T, r *ownerRefresh) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if r.close(ctx) != nil {
		t.Fatal("refresh callbacks not joined")
	}
}

func TestOwnerRefreshBindsActualResponseAndAllowsUnchangedTokens(t *testing.T) {
	before := ownerFixture(t, "2026-09-19T00:00:00Z")
	next := ownerFixture(t, "2026-09-19T00:00:01Z") // Identical token strings are valid.
	var calls atomic.Int32
	r, err := newOwnerRefresh(context.Background(), before, func(_ context.Context, req Request) (Response, error) {
		calls.Add(1)
		if req.Operation != Refresh || !bytes.Equal(req.Body, refreshInput(t, before)) || len(req.Header) != 1 {
			t.Error("unsealed refresh projection")
		}
		return Response{Status: 200, MediaType: "application/json", Body: io.NopCloser(bytes.NewReader(refreshData(t, next)))}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer joinRefresh(t, r)
	if sendOwnerRefresh(r, refreshInput(t, before)) != 200 || calls.Load() != 1 {
		t.Fatal("missing real test exchange")
	}
	if _, _, err := r.candidate(next.encoded, true); err == nil {
		t.Fatal("accepted before callback join")
	}
	joinRefresh(t, r)
	if _, refreshed, err := r.candidate(next.encoded, true); err != nil || !refreshed {
		t.Fatal("matched unchanged-token response rejected")
	}
	for _, data := range [][]byte{before.encoded, bytes.Replace(next.encoded, []byte("SYNTHETIC_ACCESS_SECRET"), []byte("UNRELATED_ACCESS"), 1),
		bytes.Replace(next.encoded, []byte("SYNTHETIC_REFRESH_SECRET"), []byte("UNRELATED_REFRESH"), 1)} {
		if _, _, err := r.candidate(data, true); err == nil {
			t.Fatal("unwritten or unrelated candidate accepted")
		}
	}
}

func TestOwnerRefreshCachedReadinessCannotClaimRefresh(t *testing.T) {
	before := ownerFixture(t, "2026-09-19T00:00:00Z")
	r, err := newOwnerRefresh(context.Background(), before, func(context.Context, Request) (Response, error) {
		t.Error("unexpected dispatch")
		return Response{}, ErrUpstream
	})
	if err != nil {
		t.Fatal(err)
	}
	joinRefresh(t, r)
	if _, refreshed, err := r.candidate(before.encoded, false); err != nil || refreshed {
		t.Fatal("cached readiness lost its separate meaning")
	}
	if _, _, err := r.candidate(before.encoded, true); err == nil {
		t.Fatal("cached readiness upgraded to refresh")
	}
	if _, _, err := r.candidate(append(bytes.Clone(before.encoded), '\n'), false); err == nil {
		t.Fatal("unobserved writer accepted")
	}
}

func TestOwnerRefreshNeverReplaysAndFailsClosed(t *testing.T) {
	before := ownerFixture(t, "2026-09-19T00:00:00Z")
	for _, mode := range []string{"parallel", "refused", "uncertain", "partial", "wrong account", "duplicate", "wrong request", "wrong type"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			r, err := newOwnerRefresh(context.Background(), before, func(context.Context, Request) (Response, error) {
				calls.Add(1)
				data := refreshData(t, before)
				status, media := 200, "application/json"
				switch mode {
				case "refused":
					status = 400
				case "uncertain":
					return Response{}, ErrUpstream
				case "partial":
					data = []byte(`{"access_token":"new"}`)
				case "wrong account":
					data = bytes.Replace(data, []byte(`{`), []byte(`{"account_id":"other",`), 1)
				case "duplicate":
					data = bytes.Replace(data, []byte(`{`), []byte(`{"access_token":"other",`), 1)
				case "wrong type":
					media = "text/html"
				}
				return Response{Status: status, MediaType: media, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer joinRefresh(t, r)
			input := refreshInput(t, before)
			if mode == "wrong request" {
				input = bytes.ReplaceAll(input, []byte(before.refresh), []byte("WRONG_REFRESH"))
			}
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(1)
				go func() { defer wg.Done(); sendOwnerRefresh(r, input) }()
			}
			wg.Wait()
			joinRefresh(t, r)
			want := int32(1)
			if mode == "wrong request" {
				want = 0
			}
			if calls.Load() != want {
				t.Fatal("refresh replayed or test did not reach expected boundary")
			}
			if _, _, err := r.candidate(before.encoded, false); err == nil {
				t.Fatal("failed/replayed invocation accepted")
			}
		})
	}
}

func TestOwnerRefreshCloseTimeoutRetainsCallbackObligation(t *testing.T) {
	before := ownerFixture(t, "2026-09-19T00:00:00Z")
	entered, release, requestDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r, err := newOwnerRefresh(context.Background(), before, func(ctx context.Context, _ Request) (Response, error) {
		close(entered)
		<-release // Deliberately hostile test responder ignores cancellation.
		return Response{}, ErrUpstream
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { defer close(requestDone); sendOwnerRefresh(r, refreshInput(t, before)) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if r.close(ctx) != ErrCleanup {
		t.Fatal("cancellation treated as callback join")
	}
	if _, _, err := r.candidate(before.encoded, false); err == nil {
		t.Fatal("accepted live callback")
	}
	close(release)
	joinRefresh(t, r)
	<-requestDone
	if _, _, err := r.candidate(before.encoded, false); err == nil {
		t.Fatal("uncertain refresh was restored to readiness")
	}
}

func TestOwnerRefreshReceiptRequiresCompleteConsistentGroup(t *testing.T) {
	a := ownerFixture(t, "2026-09-19T00:00:00Z")
	good := refreshData(t, a)
	for _, b := range [][]byte{nil, []byte("null"), []byte(`{"access_token":"secret"}`),
		bytes.Replace(good, []byte(`"id_token"`), []byte(`"ID_TOKEN"`), 1),
		[]byte(strings.Repeat("x", maxOwnerAuthBytes+1))} {
		if result, err := ownerRefreshReceipt(a, b); result != nil || err != ErrOwnerAuth {
			t.Fatal("invalid refresh accepted")
		}
	}
}

func TestOwnerRefreshUnrelatedPathCannotPoisonInvocation(t *testing.T) {
	before := ownerFixture(t, "2026-09-19T00:00:00Z")
	next := ownerFixture(t, "2026-09-19T00:00:01Z")
	var calls atomic.Int32
	r, err := newOwnerRefresh(context.Background(), before, func(context.Context, Request) (Response, error) {
		calls.Add(1)
		return Response{Status: 200, MediaType: "application/json", Body: io.NopCloser(bytes.NewReader(refreshData(t, next)))}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer joinRefresh(t, r)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://" + r.address + "/wrong-nonce")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 || r.attempted() || sendOwnerRefresh(r, refreshInput(t, before)) != 200 || calls.Load() != 1 {
		t.Fatal("unrelated request poisoned valid invocation")
	}
	joinRefresh(t, r)
	if _, _, err := r.candidate(next.encoded, true); err != nil {
		t.Fatal("valid refresh rejected after unrelated request")
	}
}
