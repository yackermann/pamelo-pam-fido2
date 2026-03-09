package packaging

import (
	"os"
	"path/filepath"
	"testing"
)

func writeOEMFolder(t *testing.T, vendorYAML, pamYAML string) string {
	t.Helper()
	oemDir := filepath.Join(t.TempDir(), "oem")
	if err := os.MkdirAll(oemDir, 0o755); err != nil {
		t.Fatalf("mkdir oem dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oemDir, "vendor.yaml"), []byte(vendorYAML), 0o600); err != nil {
		t.Fatalf("write vendor.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oemDir, "pam_fido2.yaml"), []byte(pamYAML), 0o600); err != nil {
		t.Fatalf("write pam_fido2.yaml: %v", err)
	}
	return oemDir
}

func TestLoadManifestFromOEMFolder(t *testing.T) {
	oemDir := writeOEMFolder(t, `
vendor:
  id: acme
  name: Acme Security
package:
  version: 1.2.3
  release: 4
  architecture: amd64
  maintainer: Acme <ops@example.com>
  description: Acme package
  depends: libpam0g,libssl3
activation:
  enable_on_install: true
  pam_services: sshd,login
  module_control: required
  module_args: config=/etc/security/pam_fido2.yaml debug
output:
  dir: out
`, `
server:
  url: https://auth.example.com
auth:
  mode: bearer
  bearer:
    token: inline-license-token
`)

	m, err := LoadManifestFromOEMFolder(oemDir)
	if err != nil {
		t.Fatalf("LoadManifestFromOEMFolder failed: %v", err)
	}
	if m.PackageName() != "pamelo-pam-fido2-acme" {
		t.Fatalf("unexpected package name: %s", m.PackageName())
	}
	if m.DebianVersion() != "1.2.3-4" {
		t.Fatalf("unexpected debian version: %s", m.DebianVersion())
	}
	if filepath.Base(m.OutputDebPath()) != "pamelo-pam-fido2-acme_1.2.3-4_amd64.deb" {
		t.Fatalf("unexpected output path: %s", m.OutputDebPath())
	}
	services, err := m.PAMServiceList()
	if err != nil {
		t.Fatalf("PAMServiceList error: %v", err)
	}
	if len(services) != 2 || services[0] != "sshd" || services[1] != "login" {
		t.Fatalf("unexpected services: %#v", services)
	}
	if m.ConfigInstallPath() != "/etc/security/pam_fido2.yaml" {
		t.Fatalf("unexpected config install path: %s", m.ConfigInstallPath())
	}
}

func TestLoadManifestRejectsBadVendorID(t *testing.T) {
	oemDir := writeOEMFolder(t, `
vendor:
  id: ACME_BAD
package:
  version: 1.0.0
  maintainer: Acme <ops@example.com>
  description: desc
`, `
server:
  url: https://auth.example.com
auth:
  mode: bearer
  bearer:
    token: tok
`)

	if _, err := LoadManifestFromOEMFolder(oemDir); err == nil {
		t.Fatalf("expected error for invalid vendor.id")
	}
}

func TestLoadManifestRejectsInvalidPAMService(t *testing.T) {
	oemDir := writeOEMFolder(t, `
vendor:
  id: acme
package:
  version: 1.0.0
  maintainer: Acme <ops@example.com>
  description: desc
activation:
  pam_services: sshd,../../etc/passwd
`, `
server:
  url: https://auth.example.com
auth:
  mode: bearer
  bearer:
    token: tok
`)

	if _, err := LoadManifestFromOEMFolder(oemDir); err == nil {
		t.Fatalf("expected error for invalid pam service name")
	}
}

func TestLoadManifestRequiresOEMFiles(t *testing.T) {
	oemDir := t.TempDir()
	if _, err := LoadManifestFromOEMFolder(oemDir); err == nil {
		t.Fatalf("expected error for missing OEM files")
	}
}
