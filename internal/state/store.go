package state

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var (
	ErrNotFound          = errors.New("continuity state not found")
	ErrPermissionInvalid = errors.New("continuity state permissions invalid")
)

type Entry struct {
	Username     string    `json:"username"`
	RPID         string    `json:"rp_id"`
	CredentialID string    `json:"credential_id_b64url"`
	Salt         string    `json:"salt_b64"`
	HMAC         string    `json:"hmac_b64"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (e Entry) CredentialIDBytes() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(e.CredentialID)
}

func (e Entry) SaltBytes() ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(e.Salt)
}

func (e Entry) HMACBytes() ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(e.HMAC)
}

type Store struct {
	dir string
}

func New(dir string) *Store {
	return &Store{dir: filepath.Clean(dir)}
}

func (s *Store) Save(username string, entry Entry) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if err := s.ensureSecureDir(); err != nil {
		return err
	}

	entry.Username = username
	entry.UpdatedAt = time.Now().UTC()

	path := s.userPath(username)
	tmpPath := path + ".tmp"

	payload, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func (s *Store) Load(username string) (Entry, error) {
	if err := s.ensureSecureDir(); err != nil {
		return Entry{}, err
	}

	path := s.userPath(username)
	if err := ensureSecureFile(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Entry{}, ErrNotFound
		}
		return Entry{}, err
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Entry{}, ErrNotFound
		}
		return Entry{}, err
	}
	var out Entry
	if err := json.Unmarshal(b, &out); err != nil {
		return Entry{}, fmt.Errorf("invalid state file for %s: %w", username, err)
	}
	if out.RPID == "" || out.CredentialID == "" || out.Salt == "" || out.HMAC == "" {
		return Entry{}, fmt.Errorf("invalid state file for %s: missing required fields", username)
	}
	return out, nil
}

func (s *Store) ensureSecureDir() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Stat(s.dir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is group/world writable", ErrPermissionInvalid, s.dir)
	}

	if os.Geteuid() == 0 {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%w: unable to inspect owner for %s", ErrPermissionInvalid, s.dir)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%w: %s must be owned by root", ErrPermissionInvalid, s.dir)
		}
	}
	return nil
}

func ensureSecureFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s permissions must be 0600 or stricter", ErrPermissionInvalid, path)
	}
	if os.Geteuid() == 0 {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%w: unable to inspect owner for %s", ErrPermissionInvalid, path)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%w: %s must be root-owned", ErrPermissionInvalid, path)
		}
	}
	return nil
}

func (s *Store) userPath(username string) string {
	safe := base64.RawURLEncoding.EncodeToString([]byte(username))
	return filepath.Join(s.dir, safe+".json")
}
