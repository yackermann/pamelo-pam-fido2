package state

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	err := store.Save("alice", Entry{
		RPID:         "example.com",
		CredentialID: base64.RawURLEncoding.EncodeToString([]byte("cred")),
		Salt:         base64.RawStdEncoding.EncodeToString([]byte("salt")),
		HMAC:         base64.RawStdEncoding.EncodeToString([]byte("hmac")),
	})
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	entry, err := store.Load("alice")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if entry.RPID != "example.com" {
		t.Fatalf("unexpected rpid: %s", entry.RPID)
	}
	if entry.Username != "alice" {
		t.Fatalf("unexpected username: %s", entry.Username)
	}
}

func TestLoadMissingState(t *testing.T) {
	store := New(t.TempDir())
	_, err := store.Load("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestRejectInsecureDirPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	store := New(dir)
	err := store.Save("alice", Entry{RPID: "x", CredentialID: "y", Salt: "z", HMAC: "k"})
	if !errors.Is(err, ErrPermissionInvalid) {
		t.Fatalf("expected ErrPermissionInvalid, got: %v", err)
	}
}

func TestRejectInsecureFilePermissions(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	username := "bob"
	path := filepath.Join(dir, base64.RawURLEncoding.EncodeToString([]byte(username))+".json")
	if err := os.WriteFile(path, []byte(`{"username":"bob","rp_id":"rp","credential_id_b64url":"Y3JlZA","salt_b64":"c2FsdA==","hmac_b64":"aG1hYw=="}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := store.Load(username)
	if !errors.Is(err, ErrPermissionInvalid) {
		t.Fatalf("expected ErrPermissionInvalid, got: %v", err)
	}
}
