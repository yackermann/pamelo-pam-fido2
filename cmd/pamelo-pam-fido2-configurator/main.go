package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/werk/pamelo-pam-fido2/internal/config"
)

type registerRequest struct {
	LicenseToken    string `json:"license_token"`
	Domain          string `json:"domain"`
	DeviceID        string `json:"device_id"`
	DeviceName      string `json:"device_name"`
	PairingCode     string `json:"pairing_code"`
	DomainJoined    bool   `json:"domain_joined"`
	PublicKeyPEM    string `json:"public_key_pem"`
	BindingPayload  string `json:"binding_payload"`
	ServiceEndpoint string `json:"service_endpoint"`
	RequestedAt     string `json:"requested_at"`
}

const cliBanner = `██████╗  █████╗ ███╗   ███╗███████╗██╗      ██████╗
██╔══██╗██╔══██╗████╗ ████║██╔════╝██║     ██╔═══██╗
██████╔╝███████║██╔████╔██║█████╗  ██║     ██║   ██║
██╔═══╝ ██╔══██║██║╚██╔╝██║██╔══╝  ██║     ██║   ██║
██║     ██║  ██║██║ ╚═╝ ██║███████╗███████╗╚██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝

        FIDO2 SYSTEM AUTH
`

func main() {
	cfgPath := flag.String("config", "/etc/security/pam_fido2.yaml", "Path to PAM FIDO2 YAML config")
	deviceName := flag.String("device-name", "", "Override device name (default: hostname)")
	domain := flag.String("domain", "", "Override domain (default: server hostname)")
	domainJoined := flag.String("domain-joined", "auto", "Domain joined state: auto|true|false")
	privateKeyOut := flag.String("private-key-out", "/var/lib/pamelo-pam-fido2/device_private_key.pem", "Output path for generated device private key")
	mockRequestOut := flag.String("mock-request-out", "/var/lib/pamelo-pam-fido2/activation/mock_register_request.json", "Output path for mock registration request JSON")
	noQR := flag.Bool("no-qr", false, "Disable QR rendering")
	flag.Parse()

	fmt.Print(cliBanner)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		exitf("load config %s: %v", *cfgPath, err)
	}

	licenseToken, err := resolveLicenseToken(cfg)
	if err != nil {
		exitf("resolve license token: %v", err)
	}

	hostname, _ := os.Hostname()
	if strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	resolvedDeviceName := strings.TrimSpace(*deviceName)
	if resolvedDeviceName == "" {
		resolvedDeviceName = hostname
	}

	resolvedDomain := strings.TrimSpace(*domain)
	if resolvedDomain == "" {
		resolvedDomain = inferDomain(cfg.Server.URL)
	}
	if resolvedDomain == "" {
		resolvedDomain = "unknown-domain"
	}

	joined, err := resolveDomainJoined(*domainJoined)
	if err != nil {
		exitf("resolve domain-joined state: %v", err)
	}

	deviceID, err := buildDeviceID(hostname)
	if err != nil {
		exitf("build device id: %v", err)
	}
	pairingCode, err := generatePairingCode()
	if err != nil {
		exitf("generate pairing code: %v", err)
	}
	bindingPayload := buildBindingPayload(resolvedDomain, deviceID, pairingCode)

	publicKeyPEM, privateKeyPEM, err := generateDeviceKeyPairPEM()
	if err != nil {
		exitf("generate device keypair: %v", err)
	}

	if err := writeFileSecure(*privateKeyOut, []byte(privateKeyPEM), 0o600); err != nil {
		exitf("write private key: %v", err)
	}

	endpoint := strings.TrimRight(cfg.Server.URL, "/") + "/v1/device/register"
	request := registerRequest{
		LicenseToken:    licenseToken,
		Domain:          resolvedDomain,
		DeviceID:        deviceID,
		DeviceName:      resolvedDeviceName,
		PairingCode:     pairingCode,
		DomainJoined:    joined,
		PublicKeyPEM:    publicKeyPEM,
		BindingPayload:  bindingPayload,
		ServiceEndpoint: endpoint,
		RequestedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	encoded, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		exitf("marshal mock request: %v", err)
	}
	if err := writeFileSecure(*mockRequestOut, encoded, 0o600); err != nil {
		exitf("write mock request: %v", err)
	}

	fmt.Printf("Device ID: %s\n", deviceID)
	fmt.Printf("Pairing Code: %s\n", pairingCode)
	fmt.Printf("Binding Payload: %s\n", bindingPayload)
	fmt.Printf("Private Key Path: %s\n", *privateKeyOut)
	fmt.Printf("Mock Registration Request Path: %s\n", *mockRequestOut)

	if !*noQR {
		if err := renderQRCode(bindingPayload); err != nil {
			fmt.Printf("QR rendering unavailable (%v). Use the Binding Payload above.\n", err)
		}
	}

	fmt.Printf("\nMock API Request:\n%s\n", string(encoded))
}

func resolveLicenseToken(cfg config.Config) (string, error) {
	if tok := strings.TrimSpace(cfg.License.Token); tok != "" {
		return tok, nil
	}
	if cfg.Auth.Mode == "bearer" {
		return cfg.Auth.Bearer.ResolveToken()
	}
	return "", fmt.Errorf("license token missing: set license.token or bearer token in config")
}

func inferDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	return strings.TrimSpace(host)
}

func resolveDomainJoined(input string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "auto", "":
		return detectDomainJoined(), nil
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("unsupported value %q", input)
	}
}

func detectDomainJoined() bool {
	if fileExists("/etc/krb5.keytab") {
		return true
	}
	if fileExists("/etc/sssd/sssd.conf") {
		return true
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func buildDeviceID(hostname string) (string, error) {
	machineID := strings.TrimSpace(readTextFile("/etc/machine-id"))
	if machineID == "" {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		machineID = hex.EncodeToString(random)
	}
	sum := sha256.Sum256([]byte(machineID + ":" + hostname))
	return hex.EncodeToString(sum[:8]), nil
}

func readTextFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func generatePairingCode() (string, error) {
	alphabet := []byte("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, 0, 19)
	for i, b := range buf {
		out = append(out, alphabet[int(b)%len(alphabet)])
		if (i+1)%4 == 0 && i != len(buf)-1 {
			out = append(out, '-')
		}
	}
	return string(out), nil
}

func buildBindingPayload(domain, deviceID, code string) string {
	return fmt.Sprintf("pamfido2://bind?domain=%s&device_id=%s&code=%s", url.QueryEscape(domain), url.QueryEscape(deviceID), url.QueryEscape(code))
}

func generateDeviceKeyPairPEM() (publicPEM string, privatePEM string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", err
	}

	privatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return publicPEM, privatePEM, nil
}

func renderQRCode(payload string) error {
	if _, err := exec.LookPath("qrencode"); err != nil {
		return err
	}
	cmd := exec.Command("qrencode", "-t", "ANSIUTF8", payload)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func writeFileSecure(path string, contents []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, contents, mode)
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
