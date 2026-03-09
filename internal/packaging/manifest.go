package packaging

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	appconfig "github.com/werk/pamelo-pam-fido2/internal/config"
)

var (
	ErrInvalidManifest = errors.New("invalid OEM vendor manifest")
	vendorIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	pamServicePattern  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	moduleArgsPattern  = regexp.MustCompile(`^[A-Za-z0-9_./=,:\- ]*$`)
)

type Manifest struct {
	OEMFolder     string           `json:"-"`
	VendorPath    string           `json:"-"`
	PAMConfigPath string           `json:"-"`
	Vendor        VendorSection    `json:"vendor"`
	Package       PackageSection   `json:"package"`
	Activation    ActivationConfig `json:"activation"`
	Output        OutputSection    `json:"output"`
}

type VendorSection struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type PackageSection struct {
	Version      string `json:"version"`
	Release      string `json:"release"`
	Architecture string `json:"architecture"`
	Maintainer   string `json:"maintainer"`
	Description  string `json:"description"`
	Depends      string `json:"depends"`
}

type ActivationConfig struct {
	EnableOnInstall bool   `json:"enable_on_install"`
	PAMServices     string `json:"pam_services"`
	ModuleControl   string `json:"module_control"`
	ModuleArgs      string `json:"module_args"`
}

type OutputSection struct {
	Dir string `json:"dir"`
}

func LoadManifestFromOEMFolder(oemFolder string) (Manifest, error) {
	m := Manifest{
		Package: PackageSection{
			Release:      "1",
			Architecture: "amd64",
			Depends:      "libpam0g,libssl3,libcbor0.8,zlib1g,libudev1",
		},
		Activation: ActivationConfig{
			EnableOnInstall: true,
			PAMServices:     "sshd,login,sudo",
			ModuleControl:   "required",
			ModuleArgs:      "config=/etc/security/pam_fido2.yaml",
		},
		Output: OutputSection{Dir: "dist/packages"},
	}

	folder := filepath.Clean(strings.TrimSpace(oemFolder))
	if folder == "" {
		return m, fmt.Errorf("%w: oem folder is required", ErrInvalidManifest)
	}
	if !filepath.IsAbs(folder) {
		abs, err := filepath.Abs(folder)
		if err != nil {
			return m, err
		}
		folder = abs
	}

	vendorPath := filepath.Join(folder, "vendor.yaml")
	pamConfigPath := filepath.Join(folder, "pam_fido2.yaml")

	if _, err := os.Stat(vendorPath); err != nil {
		return m, fmt.Errorf("%w: missing vendor manifest at %s: %v", ErrInvalidManifest, vendorPath, err)
	}
	if _, err := os.Stat(pamConfigPath); err != nil {
		return m, fmt.Errorf("%w: missing PAM config at %s: %v", ErrInvalidManifest, pamConfigPath, err)
	}

	f, err := os.Open(vendorPath)
	if err != nil {
		return m, err
	}
	defer f.Close()

	if err := parseYAMLLike(f, &m); err != nil {
		return m, err
	}

	m.OEMFolder = folder
	m.VendorPath = vendorPath
	m.PAMConfigPath = pamConfigPath
	if err := m.Validate(); err != nil {
		return m, err
	}
	return m, nil
}

func (m *Manifest) Validate() error {
	m.Vendor.ID = strings.ToLower(strings.TrimSpace(m.Vendor.ID))
	m.Vendor.Name = strings.TrimSpace(m.Vendor.Name)
	m.Package.Version = strings.TrimSpace(m.Package.Version)
	m.Package.Release = strings.TrimSpace(m.Package.Release)
	m.Package.Architecture = strings.TrimSpace(m.Package.Architecture)
	m.Package.Maintainer = strings.TrimSpace(m.Package.Maintainer)
	m.Package.Description = strings.TrimSpace(m.Package.Description)
	m.Package.Depends = strings.TrimSpace(m.Package.Depends)
	m.Activation.PAMServices = strings.TrimSpace(m.Activation.PAMServices)
	m.Activation.ModuleControl = strings.TrimSpace(m.Activation.ModuleControl)
	m.Activation.ModuleArgs = strings.TrimSpace(m.Activation.ModuleArgs)
	m.Output.Dir = strings.TrimSpace(m.Output.Dir)

	if m.Vendor.ID == "" || !vendorIDPattern.MatchString(m.Vendor.ID) {
		return fmt.Errorf("%w: vendor.id must match %s", ErrInvalidManifest, vendorIDPattern.String())
	}
	if m.Package.Version == "" {
		return fmt.Errorf("%w: package.version is required", ErrInvalidManifest)
	}
	if m.Package.Release == "" {
		m.Package.Release = "1"
	}
	releaseValue, err := strconv.Atoi(m.Package.Release)
	if err != nil || releaseValue <= 0 {
		return fmt.Errorf("%w: package.release must be a positive integer", ErrInvalidManifest)
	}
	if m.Package.Architecture == "" {
		m.Package.Architecture = "amd64"
	}
	if m.Package.Maintainer == "" {
		return fmt.Errorf("%w: package.maintainer is required", ErrInvalidManifest)
	}
	if m.Package.Description == "" {
		return fmt.Errorf("%w: package.description is required", ErrInvalidManifest)
	}
	if m.Package.Depends == "" {
		m.Package.Depends = "libpam0g,libssl3,libcbor0.8,zlib1g,libudev1"
	}

	if m.Activation.ModuleControl == "" {
		m.Activation.ModuleControl = "required"
	}
	switch m.Activation.ModuleControl {
	case "required", "requisite", "sufficient", "optional":
	default:
		return fmt.Errorf("%w: activation.module_control must be one of [required requisite sufficient optional]", ErrInvalidManifest)
	}
	if m.Activation.ModuleArgs == "" {
		m.Activation.ModuleArgs = "config=/etc/security/pam_fido2.yaml"
	}
	if strings.ContainsAny(m.Activation.ModuleArgs, "\n\r") || !moduleArgsPattern.MatchString(m.Activation.ModuleArgs) {
		return fmt.Errorf("%w: activation.module_args contains unsupported characters", ErrInvalidManifest)
	}
	if m.Activation.PAMServices == "" {
		m.Activation.PAMServices = "sshd,login,sudo"
	}
	if _, err := m.PAMServiceList(); err != nil {
		return err
	}

	if m.Output.Dir == "" {
		m.Output.Dir = "dist/packages"
	}
	if !filepath.IsAbs(m.Output.Dir) {
		m.Output.Dir = filepath.Clean(filepath.Join(m.OEMFolder, m.Output.Dir))
	}

	cfg, err := appconfig.Load(m.PAMConfigPath)
	if err != nil {
		return fmt.Errorf("%w: invalid pam_fido2.yaml: %v", ErrInvalidManifest, err)
	}
	if cfg.Auth.Mode == "bearer" {
		if _, err := cfg.Auth.Bearer.ResolveToken(); err != nil {
			return fmt.Errorf("%w: unable to resolve bearer token from pam_fido2.yaml: %v", ErrInvalidManifest, err)
		}
	}
	return nil
}

func (m Manifest) PAMServiceList() ([]string, error) {
	parts := strings.Split(m.Activation.PAMServices, ",")
	services := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		if !pamServicePattern.MatchString(s) {
			return nil, fmt.Errorf("%w: invalid PAM service %q", ErrInvalidManifest, s)
		}
		services = append(services, s)
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("%w: activation.pam_services must include at least one service", ErrInvalidManifest)
	}
	return services, nil
}

func (m Manifest) ConfigInstallPath() string {
	return "/etc/security/pam_fido2.yaml"
}

func (m Manifest) PackageName() string {
	return "pamelo-pam-fido2-" + m.Vendor.ID
}

func (m Manifest) DebianVersion() string {
	return m.Package.Version + "-" + m.Package.Release
}

func (m Manifest) OutputDebPath() string {
	filename := fmt.Sprintf("%s_%s_%s.deb", m.PackageName(), m.DebianVersion(), m.Package.Architecture)
	return filepath.Join(m.Output.Dir, filename)
}

func parseYAMLLike(f *os.File, m *Manifest) error {
	scanner := bufio.NewScanner(f)
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
			return fmt.Errorf("%w: line %d has odd indentation", ErrInvalidManifest, lineNo)
		}
		level := indent / 2
		trimmed := strings.TrimSpace(line)
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("%w: line %d must use key: value format", ErrInvalidManifest, lineNo)
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			return fmt.Errorf("%w: line %d key cannot be empty", ErrInvalidManifest, lineNo)
		}
		value := strings.TrimSpace(parts[1])

		if level > len(stack) {
			return fmt.Errorf("%w: line %d indentation jumps too far", ErrInvalidManifest, lineNo)
		}
		stack = stack[:level]

		if value == "" {
			stack = append(stack, key)
			continue
		}

		path := append(append([]string{}, stack...), key)
		if err := applySetting(m, path, unquote(value)); err != nil {
			return fmt.Errorf("%w: line %d: %v", ErrInvalidManifest, lineNo, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func applySetting(m *Manifest, path []string, value string) error {
	joined := strings.Join(path, ".")
	switch joined {
	case "vendor.id":
		m.Vendor.ID = value
	case "vendor.name":
		m.Vendor.Name = value
	case "package.version":
		m.Package.Version = value
	case "package.release":
		m.Package.Release = value
	case "package.architecture":
		m.Package.Architecture = value
	case "package.maintainer":
		m.Package.Maintainer = value
	case "package.description":
		m.Package.Description = value
	case "package.depends":
		m.Package.Depends = value
	case "activation.enable_on_install":
		parsed, err := parseBool(value)
		if err != nil {
			return err
		}
		m.Activation.EnableOnInstall = parsed
	case "activation.pam_services":
		m.Activation.PAMServices = value
	case "activation.module_control":
		m.Activation.ModuleControl = value
	case "activation.module_args":
		m.Activation.ModuleArgs = value
	case "output.dir":
		m.Output.Dir = value
	default:
		return fmt.Errorf("unknown key %q", joined)
	}
	return nil
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", v)
	}
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
