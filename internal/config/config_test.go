package config

import (
	"encoding/base64"
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
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(caPath, []byte("CA"), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("CERT"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	path := writeTempConfig(t, `
server:
  url: https://auth.example.com
  timeout_ms: 6000
auth:
  mode: mtls
  mtls:
    ca_file: `+caPath+`
    cert_file: `+certPath+`
    key_file: `+keyPath+`
policy:
  fail_mode: open_continuity
offline:
  state_dir: /var/lib/pamelo-pam-fido2/state
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
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("bearer-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	path := writeTempConfig(t, `
server:
  url: https://auth.example.com
auth:
  mode: bearer
  bearer:
    token_file: `+tokenPath+`
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Auth.Mode != "bearer" {
		t.Fatalf("unexpected auth mode: %s", cfg.Auth.Mode)
	}
	if cfg.Auth.Bearer.TokenFile != tokenPath {
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
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("bearer-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	path := writeTempConfig(t, `
server:
  url: https://auth.example.com
auth:
  mode: bearer
  bearer:
    token_file: `+tokenPath+`
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

func TestResolveTokenInline(t *testing.T) {
	tok, err := (BearerAuthConfig{Token: "inline-license-token"}).ResolveToken()
	if err != nil {
		t.Fatalf("ResolveToken failed: %v", err)
	}
	if tok != "inline-license-token" {
		t.Fatalf("unexpected token value: %q", tok)
	}
}

func TestResolveMTLSInlineB64(t *testing.T) {
	mtls := MTLSConfig{
		CAPEMB64:   base64.StdEncoding.EncodeToString([]byte("CA-PEM")),
		CertPEMB64: base64.StdEncoding.EncodeToString([]byte("CERT-PEM")),
		KeyPEMB64:  base64.StdEncoding.EncodeToString([]byte("KEY-PEM")),
	}
	ca, cert, key, err := mtls.ResolveMaterial()
	if err != nil {
		t.Fatalf("ResolveMaterial failed: %v", err)
	}
	if string(ca) != "CA-PEM" || string(cert) != "CERT-PEM" || string(key) != "KEY-PEM" {
		t.Fatalf("unexpected decoded material")
	}
}
