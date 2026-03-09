//go:build !linux || !cgo || !libfido2

package authn

import "context"

type Libfido2Authenticator struct{}

func NewLibfido2Authenticator() *Libfido2Authenticator {
	return NewLibfido2AuthenticatorWithLanguage("en")
}

func NewLibfido2AuthenticatorWithLanguage(language string) *Libfido2Authenticator {
	_ = language
	return &Libfido2Authenticator{}
}

func (a *Libfido2Authenticator) Assert(ctx context.Context, req AssertionRequest, progress ProgressReporter) (AssertionResult, error) {
	return AssertionResult{}, ErrUnsupported
}

func (a *Libfido2Authenticator) ComputeContinuityHMAC(ctx context.Context, req ContinuityRequest, progress ProgressReporter) ([]byte, error) {
	return nil, ErrUnsupported
}
