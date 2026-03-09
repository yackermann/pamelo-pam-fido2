package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/werk/pamelo-pam-fido2/internal/authn"
	"github.com/werk/pamelo-pam-fido2/internal/config"
	"github.com/werk/pamelo-pam-fido2/internal/server"
	"github.com/werk/pamelo-pam-fido2/internal/state"
)

type fakeServer struct {
	beginResp     server.BeginResponse
	beginErr      error
	completeResp  server.CompleteResponse
	completeErr   error
	beginCalls    int
	completeCalls int
}

func (f *fakeServer) Begin(ctx context.Context, req server.BeginRequest) (server.BeginResponse, error) {
	f.beginCalls++
	if f.beginErr != nil {
		return server.BeginResponse{}, f.beginErr
	}
	return f.beginResp, nil
}

func (f *fakeServer) Complete(ctx context.Context, req server.CompleteRequest) (server.CompleteResponse, error) {
	f.completeCalls++
	if f.completeErr != nil {
		return server.CompleteResponse{}, f.completeErr
	}
	if f.completeResp.Decision == "" {
		return server.CompleteResponse{Decision: "allow"}, nil
	}
	return f.completeResp, nil
}

type fakeAuth struct {
	assertRes      authn.AssertionResult
	assertErr      error
	continuityResp []byte
	continuityErr  error
}

func (f *fakeAuth) Assert(ctx context.Context, req authn.AssertionRequest, progress authn.ProgressReporter) (authn.AssertionResult, error) {
	if f.assertErr != nil {
		return authn.AssertionResult{}, f.assertErr
	}
	return f.assertRes, nil
}

func (f *fakeAuth) ComputeContinuityHMAC(ctx context.Context, req authn.ContinuityRequest, progress authn.ProgressReporter) ([]byte, error) {
	if f.continuityErr != nil {
		return nil, f.continuityErr
	}
	return f.continuityResp, nil
}

type fakeState struct {
	entry state.Entry
	err   error
	saved []state.Entry
}

func (f *fakeState) Load(username string) (state.Entry, error) {
	if f.err != nil {
		return state.Entry{}, f.err
	}
	return f.entry, nil
}

func (f *fakeState) Save(username string, entry state.Entry) error {
	f.saved = append(f.saved, entry)
	return nil
}

type fakeReporter struct {
	infos  []string
	errors []string
	debugs []string
}

func (f *fakeReporter) Info(msg string)  { f.infos = append(f.infos, msg) }
func (f *fakeReporter) Error(msg string) { f.errors = append(f.errors, msg) }
func (f *fakeReporter) Debug(msg string) { f.debugs = append(f.debugs, msg) }

func TestAuthenticateSuccess(t *testing.T) {
	serverClient := &fakeServer{
		beginResp: server.BeginResponse{
			RequestID:        "req",
			RPID:             "example.com",
			Challenge:        []byte("challenge"),
			AllowCredentials: [][]byte{[]byte("cred")},
			UserVerification: "required",
			HMACSalt:         []byte("salt"),
		},
	}
	authenticator := &fakeAuth{assertRes: authn.AssertionResult{
		CredentialID:      []byte("cred"),
		AuthenticatorData: []byte("auth-data"),
		Signature:         []byte("sig"),
		ClientDataJSON:    []byte(`{"type":"webauthn.get"}`),
		HMACOutput:        []byte("hmac"),
	}}
	st := &fakeState{}
	reporter := &fakeReporter{}

	cfg := config.Default()
	cfg.Policy.FailMode = "closed"
	svc := New(serverClient, authenticator, st, cfg, reporter)
	err := svc.Authenticate(context.Background(), Request{Username: "alice", Service: "sshd", Hostname: "host"})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if serverClient.beginCalls != 1 || serverClient.completeCalls != 1 {
		t.Fatalf("unexpected server calls: begin=%d complete=%d", serverClient.beginCalls, serverClient.completeCalls)
	}
	if len(st.saved) != 1 {
		t.Fatalf("expected continuity state save")
	}
}

func TestAuthenticateFailClosedOnUnavailable(t *testing.T) {
	serverClient := &fakeServer{beginErr: fmt.Errorf("wrap: %w", server.ErrUnavailable)}
	authenticator := &fakeAuth{}
	st := &fakeState{}
	reporter := &fakeReporter{}

	cfg := config.Default()
	cfg.Policy.FailMode = "closed"
	svc := New(serverClient, authenticator, st, cfg, reporter)
	err := svc.Authenticate(context.Background(), Request{Username: "alice"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got: %v", err)
	}
}

func TestAuthenticateOpenContinuitySuccess(t *testing.T) {
	storedHMAC := []byte("match")
	serverClient := &fakeServer{beginErr: fmt.Errorf("network: %w", server.ErrUnavailable)}
	authenticator := &fakeAuth{continuityResp: storedHMAC}
	st := &fakeState{entry: state.Entry{
		RPID:         "example.com",
		CredentialID: base64.RawURLEncoding.EncodeToString([]byte("cred")),
		Salt:         base64.RawStdEncoding.EncodeToString([]byte("salt")),
		HMAC:         base64.RawStdEncoding.EncodeToString(storedHMAC),
	}}
	reporter := &fakeReporter{}

	cfg := config.Default()
	cfg.Policy.FailMode = "open_continuity"
	svc := New(serverClient, authenticator, st, cfg, reporter)
	err := svc.Authenticate(context.Background(), Request{Username: "alice"})
	if err != nil {
		t.Fatalf("expected success in continuity mode, got: %v", err)
	}
}

func TestAuthenticateOpenContinuityMismatch(t *testing.T) {
	serverClient := &fakeServer{beginErr: fmt.Errorf("network: %w", server.ErrUnavailable)}
	authenticator := &fakeAuth{continuityResp: []byte("mismatch")}
	st := &fakeState{entry: state.Entry{
		RPID:         "example.com",
		CredentialID: base64.RawURLEncoding.EncodeToString([]byte("cred")),
		Salt:         base64.RawStdEncoding.EncodeToString([]byte("salt")),
		HMAC:         base64.RawStdEncoding.EncodeToString([]byte("expected")),
	}}
	cfg := config.Default()
	cfg.Policy.FailMode = "open_continuity"
	svc := New(serverClient, authenticator, st, cfg, &fakeReporter{})

	err := svc.Authenticate(context.Background(), Request{Username: "alice"})
	if err == nil {
		t.Fatalf("expected mismatch to deny")
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got: %v", err)
	}
}

func TestAuthenticateLocalizedMessages(t *testing.T) {
	serverClient := &fakeServer{
		beginResp: server.BeginResponse{
			RequestID:        "req",
			RPID:             "example.com",
			Challenge:        []byte("challenge"),
			AllowCredentials: [][]byte{[]byte("cred")},
			UserVerification: "required",
			HMACSalt:         []byte("salt"),
		},
	}
	authenticator := &fakeAuth{assertRes: authn.AssertionResult{
		CredentialID:      []byte("cred"),
		AuthenticatorData: []byte("auth-data"),
		Signature:         []byte("sig"),
		ClientDataJSON:    []byte(`{"type":"webauthn.get"}`),
		HMACOutput:        []byte("hmac"),
	}}
	st := &fakeState{}
	reporter := &fakeReporter{}

	cfg := config.Default()
	cfg.Feedback.Language = "es"
	svc := New(serverClient, authenticator, st, cfg, reporter)

	if err := svc.Authenticate(context.Background(), Request{Username: "alice"}); err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if len(reporter.infos) == 0 {
		t.Fatalf("expected info messages")
	}
	if reporter.infos[0] != "Contactando al servidor de autenticacion..." {
		t.Fatalf("unexpected localized message: %q", reporter.infos[0])
	}
}
