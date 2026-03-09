package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadMTLSConfig(t *testing.T) {
	path := writeTempConfig(t, `
server:
  url: https://auth.example.com
  timeout_ms: 6000
auth:
  mode: mtls
  mtls:
    ca_file: /etc/pki/ca.pem
    cert_file: /etc/pki/client.pem
    key_file: /etc/pki/client.key
policy:
  fail_mode: open_continuity
offline:
  state_dir: /var/lib/fido2-pam-go/state
feedback:
  level: interactive
  language: es_MX
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Auth.Mode != "mtls" {
		t.Fatalf("unexpected auth mode: %s", cfg.Auth.Mode)
	}
	if cfg.Policy.FailMode != "open_continuity" {
		t.Fatalf("unexpected fail mode: %s", cfg.Policy.FailMode)
	}
	if cfg.Server.TimeoutMS != 6000 {
		t.Fatalf("unexpected timeout: %d", cfg.Server.TimeoutMS)
	}
	if cfg.Feedback.Language != "es_MX" {
		t.Fatalf("unexpected feedback language: %s", cfg.Feedback.Language)
	}
}

func TestLoadBearerConfig(t *testing.T) {
	path := writeTempConfig(t, `
server:
  url: https://auth.example.com
auth:
  mode: bearer
  bearer:
    token_file: /etc/security/token
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Auth.Mode != "bearer" {
		t.Fatalf("unexpected auth mode: %s", cfg.Auth.Mode)
	}
	if cfg.Auth.Bearer.TokenFile != "/etc/security/token" {
		t.Fatalf("unexpected token file: %s", cfg.Auth.Bearer.TokenFile)
	}
	if cfg.Policy.FailMode != "closed" {
		t.Fatalf("default fail mode not applied")
	}
}

func TestInvalidConfigUnknownKey(t *testing.T) {
	path := writeTempConfig(t, `
server:
  url: https://auth.example.com
  wrong: x
auth:
  mode: bearer
  bearer:
    token_file: /token
`)

	if _, err := Load(path); err == nil {
		t.Fatalf("expected an error for unknown key")
	}
}

func TestInvalidConfigMutuallyExclusiveAuth(t *testing.T) {
	path := writeTempConfig(t, `
server:
  url: https://auth.example.com
auth:
  mode: mtls
  bearer:
    token_file: /token
`)

	if _, err := Load(path); err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestInvalidFeedbackLanguage(t *testing.T) {
	path := writeTempConfig(t, `
server:
  url: https://auth.example.com
auth:
  mode: bearer
  bearer:
    token_file: /token
feedback:
  language: pt_BR
`)

	if _, err := Load(path); err == nil {
		t.Fatalf("expected invalid feedback language error")
	}
}

func TestLoadBearerToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(" token-value \n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	tok, err := LoadBearerToken(path)
	if err != nil {
		t.Fatalf("LoadBearerToken failed: %v", err)
	}
	if tok != "token-value" {
		t.Fatalf("unexpected token value: %q", tok)
	}
}
