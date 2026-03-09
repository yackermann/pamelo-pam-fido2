package config

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/werk/pamelo-pam-fido2/internal/i18n"
)

const (
	defaultTimeoutMS = 5000
	defaultFailMode  = "closed"
	defaultStateDir  = "/var/lib/pamelo-pam-fido2/state"
	defaultFeedback  = "interactive"
	defaultLanguage  = "auto"
)

var (
	ErrInvalidConfig = errors.New("invalid configuration")
)

type Config struct {
	Server   ServerConfig   `json:"server"`
	Auth     AuthConfig     `json:"auth"`
	License  LicenseConfig  `json:"license"`
	Policy   PolicyConfig   `json:"policy"`
	Offline  OfflineConfig  `json:"offline"`
	Feedback FeedbackConfig `json:"feedback"`
}

type ServerConfig struct {
	URL       string `json:"url"`
	TimeoutMS int    `json:"timeout_ms"`
}

type AuthConfig struct {
	Mode   string           `json:"mode"`
	MTLS   MTLSConfig       `json:"mtls"`
	Bearer BearerAuthConfig `json:"bearer"`
}

type MTLSConfig struct {
	CAFile     string `json:"ca_file"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	CAPEM      string `json:"ca_pem"`
	CertPEM    string `json:"cert_pem"`
	KeyPEM     string `json:"key_pem"`
	CAPEMB64   string `json:"ca_pem_b64"`
	CertPEMB64 string `json:"cert_pem_b64"`
	KeyPEMB64  string `json:"key_pem_b64"`
}

type BearerAuthConfig struct {
	TokenFile string `json:"token_file"`
	Token     string `json:"token"`
}

type LicenseConfig struct {
	Token string `json:"token"`
}

type PolicyConfig struct {
	FailMode string `json:"fail_mode"`
}

type OfflineConfig struct {
	StateDir string `json:"state_dir"`
}

type FeedbackConfig struct {
	Level    string `json:"level"`
	Language string `json:"language"`
}

func Default() Config {
	return Config{
		Server:   ServerConfig{TimeoutMS: defaultTimeoutMS},
		Policy:   PolicyConfig{FailMode: defaultFailMode},
		Offline:  OfflineConfig{StateDir: defaultStateDir},
		Feedback: FeedbackConfig{Level: defaultFeedback, Language: defaultLanguage},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	if err := parseYAMLLike(f, &cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Server.URL == "" {
		return fmt.Errorf("%w: server.url is required", ErrInvalidConfig)
	}
	if _, err := url.ParseRequestURI(c.Server.URL); err != nil {
		return fmt.Errorf("%w: server.url must be a valid URL: %v", ErrInvalidConfig, err)
	}
	if c.Server.TimeoutMS <= 0 {
		return fmt.Errorf("%w: server.timeout_ms must be > 0", ErrInvalidConfig)
	}

	switch c.Auth.Mode {
	case "mtls":
		hasFiles := c.Auth.MTLS.CAFile != "" || c.Auth.MTLS.CertFile != "" || c.Auth.MTLS.KeyFile != ""
		hasInlinePEM := c.Auth.MTLS.CAPEM != "" || c.Auth.MTLS.CertPEM != "" || c.Auth.MTLS.KeyPEM != ""
		hasInlinePEMB64 := c.Auth.MTLS.CAPEMB64 != "" || c.Auth.MTLS.CertPEMB64 != "" || c.Auth.MTLS.KeyPEMB64 != ""

		sources := 0
		if hasFiles {
			if c.Auth.MTLS.CAFile == "" || c.Auth.MTLS.CertFile == "" || c.Auth.MTLS.KeyFile == "" {
				return fmt.Errorf("%w: auth.mtls file mode requires {ca_file,cert_file,key_file}", ErrInvalidConfig)
			}
			sources++
		}
		if hasInlinePEM {
			if c.Auth.MTLS.CAPEM == "" || c.Auth.MTLS.CertPEM == "" || c.Auth.MTLS.KeyPEM == "" {
				return fmt.Errorf("%w: auth.mtls inline PEM mode requires {ca_pem,cert_pem,key_pem}", ErrInvalidConfig)
			}
			sources++
		}
		if hasInlinePEMB64 {
			if c.Auth.MTLS.CAPEMB64 == "" || c.Auth.MTLS.CertPEMB64 == "" || c.Auth.MTLS.KeyPEMB64 == "" {
				return fmt.Errorf("%w: auth.mtls inline base64 PEM mode requires {ca_pem_b64,cert_pem_b64,key_pem_b64}", ErrInvalidConfig)
			}
			sources++
		}
		if sources == 0 {
			return fmt.Errorf("%w: auth.mtls requires one source: file paths or inline PEM or inline PEM base64", ErrInvalidConfig)
		}
		if sources > 1 {
			return fmt.Errorf("%w: auth.mtls must use exactly one source mode", ErrInvalidConfig)
		}
		if _, _, _, err := c.Auth.MTLS.ResolveMaterial(); err != nil {
			return fmt.Errorf("%w: invalid auth.mtls values: %v", ErrInvalidConfig, err)
		}
	case "bearer":
		hasFile := strings.TrimSpace(c.Auth.Bearer.TokenFile) != ""
		hasInline := strings.TrimSpace(c.Auth.Bearer.Token) != ""
		if !hasFile && !hasInline {
			return fmt.Errorf("%w: bearer mode requires auth.bearer.token_file or auth.bearer.token", ErrInvalidConfig)
		}
		if hasFile && hasInline {
			return fmt.Errorf("%w: bearer mode requires exactly one of auth.bearer.token_file or auth.bearer.token", ErrInvalidConfig)
		}
		if _, err := c.Auth.Bearer.ResolveToken(); err != nil {
			return fmt.Errorf("%w: invalid bearer token source: %v", ErrInvalidConfig, err)
		}
	default:
		return fmt.Errorf("%w: auth.mode must be one of [mtls bearer]", ErrInvalidConfig)
	}

	switch c.Policy.FailMode {
	case "":
		// Defaults are applied by Default(), so empty is accepted.
	case defaultFailMode:
		c.Policy.FailMode = defaultFailMode
	case "open_continuity":
	default:
		return fmt.Errorf("%w: policy.fail_mode must be one of [closed open_continuity]", ErrInvalidConfig)
	}

	if c.Offline.StateDir == "" {
		return fmt.Errorf("%w: offline.state_dir cannot be empty", ErrInvalidConfig)
	}
	c.Offline.StateDir = filepath.Clean(c.Offline.StateDir)

	switch c.Feedback.Level {
	case "":
		// Defaults are applied by Default(), so empty is accepted.
	case defaultFeedback:
		c.Feedback.Level = defaultFeedback
	case "minimal":
	default:
		return fmt.Errorf("%w: feedback.level must be one of [minimal interactive]", ErrInvalidConfig)
	}

	if strings.TrimSpace(c.Feedback.Language) == "" {
		c.Feedback.Language = defaultLanguage
	} else if !i18n.IsSupportedLanguage(c.Feedback.Language) {
		return fmt.Errorf("%w: feedback.language must be one of [auto en es fr de ja zh]", ErrInvalidConfig)
	}

	return nil
}

func parseYAMLLikeFile(path string, cfg *Config) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return parseYAMLLike(f, cfg)
}

func parseYAMLLike(r *os.File, cfg *Config) error {
	scanner := bufio.NewScanner(r)
	lineNo := 0
	stack := []string{}

	for scanner.Scan() {
		lineNo++
		line := stripComment(scanner.Text())
		if strings.TrimSpace(line) == "" {
			continue
		}

		indent := leadingSpaces(line)
		if indent%2 != 0 {
			return fmt.Errorf("%w: line %d has odd indentation", ErrInvalidConfig, lineNo)
		}
		level := indent / 2
		trimmed := strings.TrimSpace(line)
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("%w: line %d must use key: value format", ErrInvalidConfig, lineNo)
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			return fmt.Errorf("%w: line %d key cannot be empty", ErrInvalidConfig, lineNo)
		}
		value := strings.TrimSpace(parts[1])

		if level > len(stack) {
			return fmt.Errorf("%w: line %d indentation jumps too far", ErrInvalidConfig, lineNo)
		}
		stack = stack[:level]

		if value == "" {
			stack = append(stack, key)
			continue
		}

		path := append(append([]string{}, stack...), key)
		if err := applySetting(cfg, path, unquote(value)); err != nil {
			return fmt.Errorf("%w: line %d: %v", ErrInvalidConfig, lineNo, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func applySetting(cfg *Config, path []string, value string) error {
	joined := strings.Join(path, ".")
	switch joined {
	case "server.url":
		cfg.Server.URL = value
	case "server.timeout_ms":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("server.timeout_ms must be an integer")
		}
		cfg.Server.TimeoutMS = n
	case "auth.mode":
		cfg.Auth.Mode = value
	case "auth.mtls.ca_file":
		cfg.Auth.MTLS.CAFile = value
	case "auth.mtls.cert_file":
		cfg.Auth.MTLS.CertFile = value
	case "auth.mtls.key_file":
		cfg.Auth.MTLS.KeyFile = value
	case "auth.bearer.token_file":
		cfg.Auth.Bearer.TokenFile = value
	case "auth.bearer.token":
		cfg.Auth.Bearer.Token = value
	case "auth.mtls.ca_pem":
		cfg.Auth.MTLS.CAPEM = value
	case "auth.mtls.cert_pem":
		cfg.Auth.MTLS.CertPEM = value
	case "auth.mtls.key_pem":
		cfg.Auth.MTLS.KeyPEM = value
	case "auth.mtls.ca_pem_b64":
		cfg.Auth.MTLS.CAPEMB64 = value
	case "auth.mtls.cert_pem_b64":
		cfg.Auth.MTLS.CertPEMB64 = value
	case "auth.mtls.key_pem_b64":
		cfg.Auth.MTLS.KeyPEMB64 = value
	case "license.token":
		cfg.License.Token = value
	case "policy.fail_mode":
		cfg.Policy.FailMode = value
	case "offline.state_dir":
		cfg.Offline.StateDir = value
	case "feedback.level":
		cfg.Feedback.Level = value
	case "feedback.language":
		cfg.Feedback.Language = value
	default:
		return fmt.Errorf("unknown key %q", joined)
	}
	return nil
}

func stripComment(s string) string {
	inSingle := false
	inDouble := false
	for i, r := range s {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return s
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

func leadingSpaces(s string) int {
	count := 0
	for _, r := range s {
		if r == ' ' {
			count++
			continue
		}
		break
	}
	return count
}

func LoadBearerToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("%w: bearer token file is empty", ErrInvalidConfig)
	}
	return t, nil
}

func (b BearerAuthConfig) ResolveToken() (string, error) {
	if tok := strings.TrimSpace(b.Token); tok != "" {
		return tok, nil
	}
	if strings.TrimSpace(b.TokenFile) == "" {
		return "", fmt.Errorf("%w: token_file and token are both empty", ErrInvalidConfig)
	}
	return LoadBearerToken(b.TokenFile)
}

func (m MTLSConfig) ResolveMaterial() (caPEM []byte, certPEM []byte, keyPEM []byte, err error) {
	hasFiles := m.CAFile != "" || m.CertFile != "" || m.KeyFile != ""
	hasInline := m.CAPEM != "" || m.CertPEM != "" || m.KeyPEM != ""
	hasInlineB64 := m.CAPEMB64 != "" || m.CertPEMB64 != "" || m.KeyPEMB64 != ""

	switch {
	case hasFiles:
		caPEM, err = os.ReadFile(m.CAFile)
		if err != nil {
			return nil, nil, nil, err
		}
		certPEM, err = os.ReadFile(m.CertFile)
		if err != nil {
			return nil, nil, nil, err
		}
		keyPEM, err = os.ReadFile(m.KeyFile)
		if err != nil {
			return nil, nil, nil, err
		}
		return caPEM, certPEM, keyPEM, nil
	case hasInline:
		return []byte(m.CAPEM), []byte(m.CertPEM), []byte(m.KeyPEM), nil
	case hasInlineB64:
		caPEM, err = base64.StdEncoding.DecodeString(strings.TrimSpace(m.CAPEMB64))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decode ca_pem_b64: %w", err)
		}
		certPEM, err = base64.StdEncoding.DecodeString(strings.TrimSpace(m.CertPEMB64))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decode cert_pem_b64: %w", err)
		}
		keyPEM, err = base64.StdEncoding.DecodeString(strings.TrimSpace(m.KeyPEMB64))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decode key_pem_b64: %w", err)
		}
		return caPEM, certPEM, keyPEM, nil
	default:
		return nil, nil, nil, fmt.Errorf("%w: no mTLS source configured", ErrInvalidConfig)
	}
}
