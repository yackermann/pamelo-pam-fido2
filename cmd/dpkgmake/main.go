package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/werk/pamelo-pam-fido2/internal/packaging"
)

const (
	moduleSourcePath       = "dist/pamelo_pam_fido2.so"
	configuratorSourcePath = "dist/pamelo-pam-fido2-configurator"
)

func main() {
	oemFolder := flag.String("oem-folder", "", "Path to OEM folder containing vendor.yaml and pam_fido2.yaml")
	skipBuild := flag.Bool("skip-build", false, "Skip running `make build` before packaging")
	flag.Parse()

	if strings.TrimSpace(*oemFolder) == "" {
		exitf("-oem-folder is required")
	}

	repoRoot, err := os.Getwd()
	if err != nil {
		exitf("resolve working directory: %v", err)
	}

	manifest, err := packaging.LoadManifestFromOEMFolder(*oemFolder)
	if err != nil {
		exitf("load OEM manifest: %v", err)
	}

	if runtime.GOOS != "linux" {
		exitf("dpkg packaging is supported on Linux only (current GOOS=%s)", runtime.GOOS)
	}

	if !*skipBuild {
		if err := runCommand(repoRoot, "make", "build"); err != nil {
			exitf("build failed: %v", err)
		}
	}

	if err := requireCommand("dpkg-deb"); err != nil {
		exitf("%v", err)
	}

	modulePath := filepath.Join(repoRoot, moduleSourcePath)
	if _, err := os.Stat(modulePath); err != nil {
		exitf("module binary not found at %s: %v", modulePath, err)
	}
	configuratorPath := filepath.Join(repoRoot, configuratorSourcePath)
	if _, err := os.Stat(configuratorPath); err != nil {
		exitf("configurator binary not found at %s: %v", configuratorPath, err)
	}

	stageRoot := filepath.Join(repoRoot, ".cache", "dpkg", manifest.PackageName())
	if err := os.RemoveAll(stageRoot); err != nil {
		exitf("cleanup stage root: %v", err)
	}
	if err := os.MkdirAll(stageRoot, 0o755); err != nil {
		exitf("create stage root: %v", err)
	}

	if err := stagePayload(stageRoot, modulePath, configuratorPath, manifest); err != nil {
		exitf("stage package payload: %v", err)
	}

	outDeb := manifest.OutputDebPath()
	if !filepath.IsAbs(outDeb) {
		outDeb = filepath.Join(repoRoot, outDeb)
	}
	if err := os.MkdirAll(filepath.Dir(outDeb), 0o755); err != nil {
		exitf("create output dir: %v", err)
	}

	if err := runCommand(repoRoot, "dpkg-deb", "--build", "--root-owner-group", stageRoot, outDeb); err != nil {
		exitf("dpkg-deb build failed: %v", err)
	}

	fmt.Printf("Debian package created: %s\n", outDeb)
}

func stagePayload(stageRoot, modulePath, configuratorPath string, m packaging.Manifest) error {
	debianDir := filepath.Join(stageRoot, "DEBIAN")
	if err := os.MkdirAll(debianDir, 0o755); err != nil {
		return err
	}

	moduleInstallPath := filepath.Join(stageRoot, "lib", "security", "pamelo_pam_fido2.so")
	if err := copyFile(modulePath, moduleInstallPath, 0o755); err != nil {
		return fmt.Errorf("copy module: %w", err)
	}

	configuratorInstallPath := filepath.Join(stageRoot, "usr", "sbin", "pamelo-pam-fido2-configurator")
	if err := copyFile(configuratorPath, configuratorInstallPath, 0o755); err != nil {
		return fmt.Errorf("copy configurator: %w", err)
	}

	targetConfigPath := filepath.Join(stageRoot, strings.TrimPrefix(m.ConfigInstallPath(), "/"))
	if err := copyFile(m.PAMConfigPath, targetConfigPath, 0o600); err != nil {
		return fmt.Errorf("copy pam config: %w", err)
	}

	control := renderControl(m)
	if err := os.WriteFile(filepath.Join(debianDir, "control"), []byte(control), 0o644); err != nil {
		return fmt.Errorf("write control file: %w", err)
	}

	postinst, err := renderPostinst(m)
	if err != nil {
		return fmt.Errorf("render postinst: %w", err)
	}
	if err := os.WriteFile(filepath.Join(debianDir, "postinst"), []byte(postinst), 0o755); err != nil {
		return fmt.Errorf("write postinst: %w", err)
	}
	conffiles := m.ConfigInstallPath() + "\n"
	if err := os.WriteFile(filepath.Join(debianDir, "conffiles"), []byte(conffiles), 0o644); err != nil {
		return fmt.Errorf("write conffiles: %w", err)
	}

	return nil
}

func renderControl(m packaging.Manifest) string {
	depends := strings.TrimSpace(m.Package.Depends)
	if depends == "" {
		depends = "libpam0g"
	}

	description := sanitizeControlLine(m.Package.Description)
	vendor := sanitizeControlLine(m.Vendor.Name)
	if vendor == "" {
		vendor = m.Vendor.ID
	}

	return fmt.Sprintf(`Package: %s
Version: %s
Section: admin
Priority: optional
Architecture: %s
Maintainer: %s
Depends: %s
Description: %s
X-Vendor-Name: %s
`, m.PackageName(), m.DebianVersion(), m.Package.Architecture, sanitizeControlLine(m.Package.Maintainer), depends, description, vendor)
}

func renderPostinst(m packaging.Manifest) (string, error) {
	services, err := m.PAMServiceList()
	if err != nil {
		return "", err
	}
	line := fmt.Sprintf("auth %s pamelo_pam_fido2.so %s", m.Activation.ModuleControl, m.Activation.ModuleArgs)
	line = strings.TrimSpace(line)

	enable := "false"
	if m.Activation.EnableOnInstall {
		enable = "true"
	}

	return fmt.Sprintf(`#!/bin/sh
set -e

install -d -m 0700 -o root -g root /var/lib/pamelo-pam-fido2/state

if [ "%s" = "true" ]; then
  PAM_LINE='%s'
  for svc in %s; do
    pam_file="/etc/pam.d/${svc}"
    [ -f "$pam_file" ] || continue
    if grep -Fq "pamelo_pam_fido2.so" "$pam_file"; then
      continue
    fi
    tmp_file="$(mktemp)"
    printf '%%s\n' "$PAM_LINE" > "$tmp_file"
    cat "$pam_file" >> "$tmp_file"
    cat "$tmp_file" > "$pam_file"
    rm -f "$tmp_file"
  done
fi

echo "pamelo-pam-fido2 installed. Run 'pamelo-pam-fido2-configurator' to bind this device."
exit 0
`, enable, line, strings.Join(services, " ")), nil
}

func sanitizeControlLine(in string) string {
	in = strings.ReplaceAll(in, "\n", " ")
	in = strings.ReplaceAll(in, "\r", " ")
	in = strings.TrimSpace(in)
	if in == "" {
		return "-"
	}
	return in
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func requireCommand(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("required command %q not found in PATH", name)
	}
	return nil
}

func runCommand(cwd, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = cwd
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
