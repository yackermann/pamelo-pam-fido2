package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/werk/fido2-pam-go/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testClient(t *testing.T, handler roundTripFunc) *Client {
	t.Helper()
	u, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatalf("url parse: %v", err)
	}
	return &Client{
		baseURL: u,
		httpClient: &http.Client{
			Transport: handler,
			Timeout:   2 * time.Second,
		},
		bearer: "token",
	}
}

func bearerConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return config.Config{
		Server: config.ServerConfig{URL: "https://auth.example.test", TimeoutMS: 2000},
		Auth: config.AuthConfig{
			Mode: "bearer",
			Bearer: config.BearerAuthConfig{
				TokenFile: tokenPath,
			},
		},
		Policy:   config.PolicyConfig{FailMode: "closed"},
		Offline:  config.OfflineConfig{StateDir: t.TempDir()},
		Feedback: config.FeedbackConfig{Level: "interactive"},
	}
}

func TestNewBearerClient(t *testing.T) {
	cfg := bearerConfig(t)
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if client.bearer != "secret" {
		t.Fatalf("expected bearer token to be loaded")
	}
}

func TestBeginAndCompleteSuccess(t *testing.T) {
	challenge := []byte("challenge")
	hmacSalt := []byte("01234567890123456789012345678901")
	cred := []byte("cred-id")

	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("missing bearer auth header, got %q", got)
		}
		switch r.URL.Path {
		case "/v1/auth/begin":
			body := fmt.Sprintf(`{"request_id":"req-1","rp_id":"example.com","challenge_b64url":"%s","allow_credentials_b64url":["%s"],"user_verification":"required","hmac_salt_b64":"%s"}`,
				base64.RawURLEncoding.EncodeToString(challenge),
				base64.RawURLEncoding.EncodeToString(cred),
				base64.RawStdEncoding.EncodeToString(hmacSalt),
			)
			return jsonResponse(http.StatusOK, body), nil
		case "/v1/auth/complete":
			return jsonResponse(http.StatusOK, `{"decision":"allow","message":"ok"}`), nil
		default:
			return jsonResponse(http.StatusNotFound, "{}"), nil
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	begin, err := client.Begin(ctx, BeginRequest{Username: "alice", PAMService: "sshd", Hostname: "host"})
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	if begin.RequestID != "req-1" || begin.RPID != "example.com" {
		t.Fatalf("unexpected begin response: %+v", begin)
	}
	if len(begin.AllowCredentials) != 1 {
		t.Fatalf("expected one credential")
	}

	_, err = client.Complete(ctx, CompleteRequest{
		RequestID:         begin.RequestID,
		Username:          "alice",
		CredentialID:      cred,
		AuthenticatorData: []byte("auth-data"),
		ClientDataJSON:    []byte(`{"type":"webauthn.get"}`),
		Signature:         []byte("sig"),
		HMACOutput:        []byte("hmac"),
	})
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
}

func TestCompleteDenied(t *testing.T) {
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"decision":"deny","message":"invalid assertion"}`), nil
	})

	_, err := client.Complete(context.Background(), CompleteRequest{RequestID: "x", Username: "alice"})
	if err == nil {
		t.Fatalf("expected deny error")
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got: %v", err)
	}
}

func TestBeginUnavailableOnServerError(t *testing.T) {
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusServiceUnavailable, `{"error":"boom"}`), nil
	})

	_, err := client.Begin(context.Background(), BeginRequest{Username: "alice"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got: %v", err)
	}
}

func TestBeginMalformedResponse(t *testing.T) {
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"request_id":"a","rp_id":"example.com","challenge_b64url":"%%%","allow_credentials_b64url":[],"user_verification":"required","hmac_salt_b64":"AAAA"}`), nil
	})

	_, err := client.Begin(context.Background(), BeginRequest{Username: "alice"})
	if err == nil {
		t.Fatalf("expected malformed response error")
	}
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol, got %v", err)
	}
}

func TestBeginTimeout(t *testing.T) {
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		return nil, timeoutNetError{msg: "dial timeout"}
	})

	_, err := client.Begin(context.Background(), BeginRequest{Username: "alice"})
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestClassifyTransportErrEOF(t *testing.T) {
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		return nil, io.EOF
	})
	_, err := client.Begin(context.Background(), BeginRequest{Username: "alice"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request: &http.Request{
			Method: http.MethodPost,
			URL:    &url.URL{Path: "/"},
			Body:   io.NopCloser(bytes.NewReader(nil)),
		},
	}
}

type timeoutNetError struct {
	msg string
}

func (e timeoutNetError) Error() string   { return e.msg }
func (e timeoutNetError) Timeout() bool   { return true }
func (e timeoutNetError) Temporary() bool { return true }

var _ net.Error = timeoutNetError{}
