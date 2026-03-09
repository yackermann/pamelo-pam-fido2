package config

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/werk/fido2-pam-go/internal/i18n"
)

const (
	defaultTimeoutMS = 5000
	defaultFailMode  = "closed"
	defaultStateDir  = "/var/lib/fido2-pam-go/state"
	defaultFeedback  = "interactive"
	defaultLanguage  = "auto"
)

var (
	ErrInvalidConfig = errors.New("invalid configuration")
)

type Config struct {
	Server   ServerConfig   `json:"server"`
	Auth     AuthConfig     `json:"auth"`
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
	CAFile   string `json:"ca_file"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type BearerAuthConfig struct {
	TokenFile string `json:"token_file"`
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
		if c.Auth.MTLS.CAFile == "" || c.Auth.MTLS.CertFile == "" || c.Auth.MTLS.KeyFile == "" {
			return fmt.Errorf("%w: auth.mtls.{ca_file,cert_file,key_file} are required in mtls mode", ErrInvalidConfig)
		}
	case "bearer":
		if c.Auth.Bearer.TokenFile == "" {
			return fmt.Errorf("%w: auth.bearer.token_file is required in bearer mode", ErrInvalidConfig)
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
