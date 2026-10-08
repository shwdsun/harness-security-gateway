package discordconnector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type redirectBoundaryTransport func(*http.Request) (*http.Response, error)

func (f redirectBoundaryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestAPIRefusesRedirectsBeforeSendingCredentialsAgain(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, target := range []string{
			"http://discord.com/credential-recipient",
			"https://subdomain.discord.com/credential-recipient",
			"https://unrelated.invalid/credential-recipient",
			"https://discord.com/another-path",
		} {
			t.Run(fmt.Sprintf("%d/%s", status, target), func(t *testing.T) {
				api, err := NewAPI("https://discord.com/api/v10", testToken, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				api.http.(*http.Client).Transport = redirectBoundaryTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if calls > 1 {
						t.Fatal("platform redirect caused a second request")
					}
					if r.URL.Scheme != "https" || r.URL.Host != "discord.com" || r.Header.Get("Authorization") != "Bot "+testToken {
						t.Fatal("initial request lost its configured origin or credential")
					}
					return &http.Response{
						StatusCode: status, Header: http.Header{"Location": {target}},
						Body: io.NopCloser(strings.NewReader("untrusted redirect body")), Request: r,
					}, nil
				})
				_, err = api.SendMessage(context.Background(), "333333333333333333", "", "reply")
				var platformErr *APIError
				if !errors.As(err, &platformErr) || platformErr.Status != status || platformErr.Transport || calls != 1 {
					t.Fatalf("redirect was not classified without following it: calls=%d error=%v", calls, err)
				}
			})
		}
	}
}

func TestSplitReplyPreservesUnicodeAtHardByteBoundaries(t *testing.T) {
	for _, text := range []string{strings.Repeat("界", 700), strings.Repeat("🧪", 1000), strings.Repeat("a界🧪", 501)} {
		chunks, ok := SplitReply(text, 4)
		if !ok || len(chunks) < 2 {
			t.Fatalf("bounded Unicode reply not split: %d chunks, accepted=%v", len(chunks), ok)
		}
		for _, chunk := range chunks {
			if !utf8.ValidString(chunk) || len(chunk) > maxChunkText {
				t.Fatal("chunk corrupted a code point or exceeded the platform bound")
			}
		}
		if strings.Join(chunks, "") != text {
			t.Fatal("splitting changed reply content")
		}
	}
	if _, ok := SplitReply("invalid\xfftext", 4); ok {
		t.Fatal("invalid UTF-8 accepted for platform serialization")
	}
}
