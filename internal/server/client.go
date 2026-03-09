package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/werk/fido2-pam-go/internal/config"
)

var (
	ErrUnavailable = errors.New("authentication server unavailable")
	ErrDenied      = errors.New("authentication denied")
	ErrProtocol    = errors.New("authentication protocol error")
)

type BeginRequest struct {
	Username   string `json:"username"`
	PAMService string `json:"pam_service"`
	Hostname   string `json:"hostname"`
}

type BeginResponse struct {
	RequestID        string
	RPID             string
	Challenge        []byte
	AllowCredentials [][]byte
	UserVerification string
	HMACSalt         []byte
}

type CompleteRequest struct {
	RequestID         string
	Username          string
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
	HMACOutput        []byte
}

type CompleteResponse struct {
	Decision string
	Message  string
}

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	bearer     string
}

func New(cfg config.Config) (*Client, error) {
	u, err := url.Parse(cfg.Server.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid server url: %v", config.ErrInvalidConfig, err)
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	bearer := ""
	switch cfg.Auth.Mode {
	case "mtls":
		caPEM, certPEM, keyPEM, err := cfg.Auth.MTLS.ResolveMaterial()
		if err != nil {
			return nil, fmt.Errorf("%w: resolve mTLS material: %v", config.ErrInvalidConfig, err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: loading mTLS certificate/key: %v", config.ErrInvalidConfig, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("%w: CA file has no valid certificates", config.ErrInvalidConfig)
		}
		tlsConfig.RootCAs = pool
		tlsConfig.Certificates = []tls.Certificate{cert}
	case "bearer":
		token, err := cfg.Auth.Bearer.ResolveToken()
		if err != nil {
			return nil, err
		}
		bearer = token
	default:
		return nil, fmt.Errorf("%w: unsupported auth mode %q", config.ErrInvalidConfig, cfg.Auth.Mode)
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsConfig,
		DialContext:         (&net.Dialer{Timeout: time.Duration(cfg.Server.TimeoutMS) * time.Millisecond}).DialContext,
		TLSHandshakeTimeout: time.Duration(cfg.Server.TimeoutMS) * time.Millisecond,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Server.TimeoutMS) * time.Millisecond,
	}

	return &Client{baseURL: u, httpClient: httpClient, bearer: bearer}, nil
}

func (c *Client) Begin(ctx context.Context, req BeginRequest) (BeginResponse, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return BeginResponse{}, fmt.Errorf("%w: marshal begin request: %v", ErrProtocol, err)
	}

	httpReq, err := c.newRequest(ctx, http.MethodPost, "/v1/auth/begin", payload)
	if err != nil {
		return BeginResponse{}, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return BeginResponse{}, classifyTransportErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return BeginResponse{}, classifyStatus(resp.StatusCode)
	}

	var raw struct {
		RequestID              string   `json:"request_id"`
		RPID                   string   `json:"rp_id"`
		ChallengeB64URL        string   `json:"challenge_b64url"`
		AllowCredentialsB64URL []string `json:"allow_credentials_b64url"`
		UserVerification       string   `json:"user_verification"`
		HMACSaltB64            string   `json:"hmac_salt_b64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return BeginResponse{}, fmt.Errorf("%w: decode begin response: %v", ErrProtocol, err)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(raw.ChallengeB64URL)
	if err != nil {
		return BeginResponse{}, fmt.Errorf("%w: invalid challenge_b64url: %v", ErrProtocol, err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(raw.HMACSaltB64)
	if err != nil {
		return BeginResponse{}, fmt.Errorf("%w: invalid hmac_salt_b64: %v", ErrProtocol, err)
	}

	allowCreds := make([][]byte, 0, len(raw.AllowCredentialsB64URL))
	for _, cred := range raw.AllowCredentialsB64URL {
		decoded, err := base64.RawURLEncoding.DecodeString(cred)
		if err != nil {
			return BeginResponse{}, fmt.Errorf("%w: invalid allow credential: %v", ErrProtocol, err)
		}
		allowCreds = append(allowCreds, decoded)
	}

	return BeginResponse{
		RequestID:        raw.RequestID,
		RPID:             raw.RPID,
		Challenge:        challenge,
		AllowCredentials: allowCreds,
		UserVerification: raw.UserVerification,
		HMACSalt:         salt,
	}, nil
}

func (c *Client) Complete(ctx context.Context, req CompleteRequest) (CompleteResponse, error) {
	payload := map[string]any{
		"request_id":         req.RequestID,
		"username":           req.Username,
		"credential_id":      base64.RawURLEncoding.EncodeToString(req.CredentialID),
		"authenticator_data": base64.RawURLEncoding.EncodeToString(req.AuthenticatorData),
		"client_data_json":   string(req.ClientDataJSON),
		"signature":          base64.RawURLEncoding.EncodeToString(req.Signature),
		"hmac_output_b64":    base64.RawStdEncoding.EncodeToString(req.HMACOutput),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return CompleteResponse{}, fmt.Errorf("%w: marshal complete request: %v", ErrProtocol, err)
	}

	httpReq, err := c.newRequest(ctx, http.MethodPost, "/v1/auth/complete", body)
	if err != nil {
		return CompleteResponse{}, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return CompleteResponse{}, classifyTransportErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CompleteResponse{}, classifyStatus(resp.StatusCode)
	}

	var out CompleteResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return CompleteResponse{}, fmt.Errorf("%w: decode complete response: %v", ErrProtocol, err)
	}

	switch out.Decision {
	case "allow", "deny":
	default:
		return CompleteResponse{}, fmt.Errorf("%w: decision must be allow|deny", ErrProtocol)
	}

	if out.Decision == "deny" {
		msg := strings.TrimSpace(out.Message)
		if msg == "" {
			msg = "server denied authentication"
		}
		return out, fmt.Errorf("%w: %s", ErrDenied, msg)
	}

	return out, nil
}

func (c *Client) newRequest(ctx context.Context, method, endpoint string, body []byte) (*http.Request, error) {
	u := *c.baseURL
	u.Path = path.Join(strings.TrimSuffix(u.Path, "/"), endpoint)

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: construct request: %v", ErrProtocol, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	return req, nil
}

func classifyStatus(status int) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("%w: status %d", ErrDenied, status)
	}
	if status == http.StatusBadRequest || status == http.StatusUnprocessableEntity {
		return fmt.Errorf("%w: status %d", ErrDenied, status)
	}
	if status >= 500 {
		return fmt.Errorf("%w: status %d", ErrUnavailable, status)
	}
	return fmt.Errorf("%w: unexpected status %d", ErrProtocol, status)
}

func classifyTransportErr(err error) error {
	if err == nil {
		return nil
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return fmt.Errorf("%w: timeout: %v", ErrUnavailable, err)
		}
		return fmt.Errorf("%w: network error: %v", ErrUnavailable, err)
	}
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: eof: %v", ErrUnavailable, err)
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}
