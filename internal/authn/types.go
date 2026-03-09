package authn

import (
	"context"
	"errors"
)

var (
	ErrDeviceUnavailable = errors.New("fido2 device unavailable")
	ErrAssertionFailed   = errors.New("fido2 assertion failed")
	ErrUnsupported       = errors.New("libfido2 authenticator not available in this build")
)

type AssertionRequest struct {
	RPID             string
	Challenge        []byte
	AllowCredentials [][]byte
	UserVerification string
	HMACSalt         []byte
	ClientDataJSON   []byte
}

type AssertionResult struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
	ClientDataJSON    []byte
	HMACOutput        []byte
}

type ContinuityRequest struct {
	RPID         string
	CredentialID []byte
	Salt         []byte
}

type ProgressReporter interface {
	Info(msg string)
	Error(msg string)
	Debug(msg string)
}

type Authenticator interface {
	Assert(ctx context.Context, req AssertionRequest, progress ProgressReporter) (AssertionResult, error)
	ComputeContinuityHMAC(ctx context.Context, req ContinuityRequest, progress ProgressReporter) ([]byte, error)
}
