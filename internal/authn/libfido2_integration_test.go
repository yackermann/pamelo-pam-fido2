//go:build linux && cgo && libfido2 && integration

package authn

import (
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"
)

type testReporter struct {
	t *testing.T
}

func (r testReporter) Info(msg string) {
	r.t.Logf("INFO: %s", msg)
}

func (r testReporter) Error(msg string) {
	r.t.Logf("ERROR: %s", msg)
}

func (r testReporter) Debug(msg string) {
	r.t.Logf("DEBUG: %s", msg)
}

func TestComputeContinuityHMACHardware(t *testing.T) {
	if os.Getenv("FIDO2_HW_TEST") != "1" {
		t.Skip("set FIDO2_HW_TEST=1 to run hardware integration test")
	}

	rpID := os.Getenv("FIDO2_TEST_RP_ID")
	credB64 := os.Getenv("FIDO2_TEST_CREDENTIAL_ID_B64URL")
	saltB64 := os.Getenv("FIDO2_TEST_SALT_B64")
	if rpID == "" || credB64 == "" || saltB64 == "" {
		t.Fatalf("missing required env vars: FIDO2_TEST_RP_ID, FIDO2_TEST_CREDENTIAL_ID_B64URL, FIDO2_TEST_SALT_B64")
	}

	cred, err := base64.RawURLEncoding.DecodeString(credB64)
	if err != nil {
		t.Fatalf("decode credential id: %v", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}

	a := NewLibfido2Authenticator()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	hmac, err := a.ComputeContinuityHMAC(ctx, ContinuityRequest{
		RPID:         rpID,
		CredentialID: cred,
		Salt:         salt,
	}, testReporter{t: t})
	if err != nil {
		t.Fatalf("ComputeContinuityHMAC failed: %v", err)
	}
	if len(hmac) == 0 {
		t.Fatalf("expected non-empty hmac output")
	}
}
