package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/werk/pamelo-pam-fido2/internal/authn"
	"github.com/werk/pamelo-pam-fido2/internal/config"
	"github.com/werk/pamelo-pam-fido2/internal/i18n"
	"github.com/werk/pamelo-pam-fido2/internal/server"
	"github.com/werk/pamelo-pam-fido2/internal/state"
)

var (
	ErrDenied      = errors.New("authentication denied")
	ErrUnavailable = errors.New("authentication unavailable")
	ErrConfig      = errors.New("authentication configuration error")
)

type Request struct {
	Username string
	Service  string
	Hostname string
}

type ServerClient interface {
	Begin(ctx context.Context, req server.BeginRequest) (server.BeginResponse, error)
	Complete(ctx context.Context, req server.CompleteRequest) (server.CompleteResponse, error)
}

type StateStore interface {
	Load(username string) (state.Entry, error)
	Save(username string, entry state.Entry) error
}

type Service struct {
	serverClient  ServerClient
	authenticator authn.Authenticator
	stateStore    StateStore
	failMode      string
	reporter      authn.ProgressReporter
	localizer     *i18n.Localizer
}

func New(serverClient ServerClient, authenticator authn.Authenticator, stateStore StateStore, cfg config.Config, reporter authn.ProgressReporter) *Service {
	language := i18n.ResolveLanguage(cfg.Feedback.Language, "")
	return &Service{
		serverClient:  serverClient,
		authenticator: authenticator,
		stateStore:    stateStore,
		failMode:      cfg.Policy.FailMode,
		reporter:      reporter,
		localizer:     i18n.New(language),
	}
}

func (s *Service) Authenticate(ctx context.Context, req Request) error {
	if req.Username == "" {
		return fmt.Errorf("%w: username is empty", ErrConfig)
	}

	s.reportInfoID(i18n.MsgContactingServer)
	begin, err := s.serverClient.Begin(ctx, server.BeginRequest{
		Username:   req.Username,
		PAMService: req.Service,
		Hostname:   req.Hostname,
	})
	if err != nil {
		return s.handleServerError(ctx, req, err)
	}

	s.reportInfoID(i18n.MsgPreparingAssertion)
	assertion, err := s.authenticator.Assert(ctx, authn.AssertionRequest{
		RPID:             begin.RPID,
		Challenge:        begin.Challenge,
		AllowCredentials: begin.AllowCredentials,
		UserVerification: begin.UserVerification,
		HMACSalt:         begin.HMACSalt,
	}, s.reporter)
	if err != nil {
		s.reportErrorID(i18n.MsgAssertionFailed)
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}

	s.reportInfoID(i18n.MsgVerifyingWithServer)
	_, err = s.serverClient.Complete(ctx, server.CompleteRequest{
		RequestID:         begin.RequestID,
		Username:          req.Username,
		CredentialID:      assertion.CredentialID,
		AuthenticatorData: assertion.AuthenticatorData,
		ClientDataJSON:    assertion.ClientDataJSON,
		Signature:         assertion.Signature,
		HMACOutput:        assertion.HMACOutput,
	})
	if err != nil {
		if errors.Is(err, server.ErrUnavailable) {
			return s.handleServerError(ctx, req, err)
		}
		if errors.Is(err, server.ErrDenied) {
			s.reportErrorID(i18n.MsgDeniedByServer)
			return fmt.Errorf("%w: %v", ErrDenied, err)
		}
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}

	s.reportInfoID(i18n.MsgAuthenticationSucceeded)
	if len(assertion.HMACOutput) == 0 || len(begin.HMACSalt) == 0 || len(assertion.CredentialID) == 0 || begin.RPID == "" {
		s.reportDebugID(i18n.MsgSkipContinuityMissingFields)
		return nil
	}
	entry := state.Entry{
		RPID:         begin.RPID,
		CredentialID: base64.RawURLEncoding.EncodeToString(assertion.CredentialID),
		Salt:         base64.RawStdEncoding.EncodeToString(begin.HMACSalt),
		HMAC:         base64.RawStdEncoding.EncodeToString(assertion.HMACOutput),
	}
	if err := s.stateStore.Save(req.Username, entry); err != nil {
		s.reportDebugf(i18n.MsgPersistContinuityFailed, err)
	}

	return nil
}

func (s *Service) handleServerError(ctx context.Context, req Request, err error) error {
	if errors.Is(err, server.ErrUnavailable) {
		s.reportErrorID(i18n.MsgServerUnavailable)
		if s.failMode == "open_continuity" {
			s.reportInfoID(i18n.MsgTryingOfflineContinuity)
			ok, verifyErr := s.verifyOfflineContinuity(ctx, req.Username)
			if verifyErr != nil {
				s.reportErrorID(i18n.MsgOfflineContinuityFailed)
				return fmt.Errorf("%w: %v", ErrDenied, verifyErr)
			}
			if ok {
				s.reportInfoID(i18n.MsgOfflineContinuitySucceeded)
				return nil
			}
			return fmt.Errorf("%w: offline continuity mismatch", ErrDenied)
		}
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if errors.Is(err, server.ErrDenied) {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

func (s *Service) verifyOfflineContinuity(ctx context.Context, username string) (bool, error) {
	entry, err := s.stateStore.Load(username)
	if err != nil {
		return false, err
	}
	credID, err := entry.CredentialIDBytes()
	if err != nil {
		return false, err
	}
	salt, err := entry.SaltBytes()
	if err != nil {
		return false, err
	}
	expectedHMAC, err := entry.HMACBytes()
	if err != nil {
		return false, err
	}

	observedHMAC, err := s.authenticator.ComputeContinuityHMAC(ctx, authn.ContinuityRequest{
		RPID:         entry.RPID,
		CredentialID: credID,
		Salt:         salt,
	}, s.reporter)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(observedHMAC, expectedHMAC) == 1, nil
}

func (s *Service) reportInfo(msg string) {
	if s.reporter != nil {
		s.reporter.Info(msg)
	}
}

func (s *Service) reportError(msg string) {
	if s.reporter != nil {
		s.reporter.Error(msg)
	}
}

func (s *Service) reportDebug(msg string) {
	if s.reporter != nil {
		s.reporter.Debug(msg)
	}
}

func (s *Service) reportInfoID(id i18n.MessageID, args ...any) {
	s.reportInfo(s.localize(id, args...))
}

func (s *Service) reportErrorID(id i18n.MessageID, args ...any) {
	s.reportError(s.localize(id, args...))
}

func (s *Service) reportDebugID(id i18n.MessageID, args ...any) {
	s.reportDebug(s.localize(id, args...))
}

func (s *Service) reportDebugf(id i18n.MessageID, args ...any) {
	s.reportDebug(s.localize(id, args...))
}

func (s *Service) localize(id i18n.MessageID, args ...any) string {
	if s.localizer == nil {
		return i18n.New("en").S(id, args...)
	}
	return s.localizer.S(id, args...)
}
