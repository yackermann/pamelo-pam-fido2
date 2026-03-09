//go:build linux && cgo && libfido2

package authn

/*
Build flags for libfido2 headers and static archive are provided by Makefile:
CGO_CFLAGS -> .cache/libfido2/install/include
CGO_LDFLAGS -> .cache/libfido2/install/lib/libfido2.a plus runtime deps.

#include <fido.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	"unsafe"

	"github.com/werk/pamelo-pam-fido2/internal/i18n"
)

const (
	maxDevices     = 8
	defaultTimeout = 30000
	tickerInterval = 2 * time.Second
)

type Libfido2Authenticator struct {
	localizer *i18n.Localizer
}

func NewLibfido2Authenticator() *Libfido2Authenticator {
	return NewLibfido2AuthenticatorWithLanguage("en")
}

func NewLibfido2AuthenticatorWithLanguage(language string) *Libfido2Authenticator {
	return &Libfido2Authenticator{
		localizer: i18n.New(language),
	}
}

func (a *Libfido2Authenticator) Assert(ctx context.Context, req AssertionRequest, progress ProgressReporter) (AssertionResult, error) {
	if req.RPID == "" {
		return AssertionResult{}, fmt.Errorf("%w: rpid is required", ErrAssertionFailed)
	}
	if len(req.Challenge) == 0 {
		return AssertionResult{}, fmt.Errorf("%w: challenge is required", ErrAssertionFailed)
	}

	clientData := req.ClientDataJSON
	if len(clientData) == 0 {
		generated, err := buildClientDataJSON(req.Challenge)
		if err != nil {
			return AssertionResult{}, fmt.Errorf("%w: build client data json: %v", ErrAssertionFailed, err)
		}
		clientData = generated
	}

	devicePath, err := discoverDevice()
	if err != nil {
		return AssertionResult{}, err
	}
	if progress != nil {
		progress.Debug(a.localizer.S(i18n.MsgUsingFIDO2Device, devicePath))
	}

	C.fido_init(0)

	dev := C.fido_dev_new()
	if dev == nil {
		return AssertionResult{}, fmt.Errorf("%w: unable to allocate fido device", ErrAssertionFailed)
	}
	defer C.fido_dev_free(&dev)

	cPath := C.CString(devicePath)
	defer C.free(unsafe.Pointer(cPath))

	if rc := C.fido_dev_open(dev, cPath); rc != C.FIDO_OK {
		return AssertionResult{}, wrapFIDOError(rc, ErrDeviceUnavailable, "open fido device")
	}
	defer C.fido_dev_close(dev)

	timeoutMS := timeoutFromContext(ctx)
	_ = C.fido_dev_set_timeout(dev, C.int(timeoutMS))

	assert := C.fido_assert_new()
	if assert == nil {
		return AssertionResult{}, fmt.Errorf("%w: unable to allocate assertion", ErrAssertionFailed)
	}
	defer C.fido_assert_free(&assert)

	cRPID := C.CString(req.RPID)
	defer C.free(unsafe.Pointer(cRPID))
	if rc := C.fido_assert_set_rp(assert, cRPID); rc != C.FIDO_OK {
		return AssertionResult{}, wrapFIDOError(rc, ErrAssertionFailed, "set rp id")
	}

	cdh := sha256.Sum256(clientData)
	if rc := C.fido_assert_set_clientdata_hash(assert, (*C.uchar)(unsafe.Pointer(&cdh[0])), C.size_t(len(cdh))); rc != C.FIDO_OK {
		return AssertionResult{}, wrapFIDOError(rc, ErrAssertionFailed, "set client data hash")
	}

	for _, cred := range req.AllowCredentials {
		if len(cred) == 0 {
			continue
		}
		if rc := C.fido_assert_allow_cred(assert, (*C.uchar)(unsafe.Pointer(&cred[0])), C.size_t(len(cred))); rc != C.FIDO_OK {
			return AssertionResult{}, wrapFIDOError(rc, ErrAssertionFailed, "set allowed credential")
		}
	}

	if rc := C.fido_assert_set_uv(assert, uvOption(req.UserVerification)); rc != C.FIDO_OK {
		return AssertionResult{}, wrapFIDOError(rc, ErrAssertionFailed, "set user verification policy")
	}
	if rc := C.fido_assert_set_up(assert, C.FIDO_OPT_TRUE); rc != C.FIDO_OK {
		return AssertionResult{}, wrapFIDOError(rc, ErrAssertionFailed, "set user presence policy")
	}

	if len(req.HMACSalt) > 0 {
		if rc := C.fido_assert_set_extensions(assert, C.FIDO_EXT_HMAC_SECRET); rc != C.FIDO_OK {
			return AssertionResult{}, wrapFIDOError(rc, ErrAssertionFailed, "set hmac-secret extension")
		}
		if rc := C.fido_assert_set_hmac_salt(assert, (*C.uchar)(unsafe.Pointer(&req.HMACSalt[0])), C.size_t(len(req.HMACSalt))); rc != C.FIDO_OK {
			return AssertionResult{}, wrapFIDOError(rc, ErrAssertionFailed, "set hmac salt")
		}
	}

	stopTicker := make(chan struct{})
	if progress != nil {
		go touchTicker(a.localizer, progress, stopTicker)
	}
	rc := C.fido_dev_get_assert(dev, assert, nil)
	if progress != nil {
		close(stopTicker)
	}
	if rc != C.FIDO_OK {
		return AssertionResult{}, wrapFIDOError(rc, ErrAssertionFailed, "perform assertion")
	}

	if C.fido_assert_count(assert) == 0 {
		return AssertionResult{}, fmt.Errorf("%w: no assertion returned from authenticator", ErrAssertionFailed)
	}
	idx := C.size_t(0)

	credID, err := copyOut(C.fido_assert_id_ptr(assert, idx), C.fido_assert_id_len(assert, idx))
	if err != nil {
		return AssertionResult{}, err
	}
	authData, err := copyOut(C.fido_assert_authdata_ptr(assert, idx), C.fido_assert_authdata_len(assert, idx))
	if err != nil {
		return AssertionResult{}, err
	}
	signature, err := copyOut(C.fido_assert_sig_ptr(assert, idx), C.fido_assert_sig_len(assert, idx))
	if err != nil {
		return AssertionResult{}, err
	}
	hmacOutput, err := copyOut(C.fido_assert_hmac_secret_ptr(assert, idx), C.fido_assert_hmac_secret_len(assert, idx))
	if err != nil {
		return AssertionResult{}, err
	}

	return AssertionResult{
		CredentialID:      credID,
		AuthenticatorData: authData,
		Signature:         signature,
		ClientDataJSON:    clientData,
		HMACOutput:        hmacOutput,
	}, nil
}

func (a *Libfido2Authenticator) ComputeContinuityHMAC(ctx context.Context, req ContinuityRequest, progress ProgressReporter) ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("%w: generate continuity challenge: %v", ErrAssertionFailed, err)
	}
	res, err := a.Assert(ctx, AssertionRequest{
		RPID:             req.RPID,
		Challenge:        challenge,
		AllowCredentials: [][]byte{req.CredentialID},
		UserVerification: "preferred",
		HMACSalt:         req.Salt,
	}, progress)
	if err != nil {
		return nil, err
	}
	if len(res.HMACOutput) == 0 {
		return nil, fmt.Errorf("%w: device did not return hmac-secret output", ErrAssertionFailed)
	}
	return res.HMACOutput, nil
}

func discoverDevice() (string, error) {
	info := C.fido_dev_info_new(C.size_t(maxDevices))
	if info == nil {
		return "", fmt.Errorf("%w: unable to allocate fido device list", ErrDeviceUnavailable)
	}
	defer C.fido_dev_info_free(&info, C.size_t(maxDevices))

	var found C.size_t
	if rc := C.fido_dev_info_manifest(info, C.size_t(maxDevices), &found); rc != C.FIDO_OK {
		return "", wrapFIDOError(rc, ErrDeviceUnavailable, "enumerate fido devices")
	}
	if found == 0 {
		return "", fmt.Errorf("%w: no security key found", ErrDeviceUnavailable)
	}
	entry := C.fido_dev_info_ptr(info, 0)
	if entry == nil {
		return "", fmt.Errorf("%w: empty device entry", ErrDeviceUnavailable)
	}
	path := C.fido_dev_info_path(entry)
	if path == nil {
		return "", fmt.Errorf("%w: device path is nil", ErrDeviceUnavailable)
	}
	return C.GoString(path), nil
}

func touchTicker(localizer *i18n.Localizer, progress ProgressReporter, stop <-chan struct{}) {
	frames := []string{"|", "/", "-", "\\"}
	if localizer == nil {
		localizer = i18n.New("en")
	}
	idx := 0
	progress.Info(localizer.S(i18n.MsgTouchSecurityKey, frames[idx]))
	idx++

	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			progress.Info(localizer.S(i18n.MsgTouchSecurityKey, frames[idx%len(frames)]))
			idx++
		}
	}
}

func wrapFIDOError(rc C.int, base error, op string) error {
	return fmt.Errorf("%w: %s: %s (%d)", base, op, C.GoString(C.fido_strerr(rc)), int(rc))
}

func copyOut(ptr *C.uchar, length C.size_t) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	if ptr == nil {
		return nil, fmt.Errorf("%w: missing assertion output", ErrAssertionFailed)
	}
	if length > C.size_t(^uint32(0)) {
		return nil, fmt.Errorf("%w: output too large", ErrAssertionFailed)
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length)), nil
}

func uvOption(input string) C.fido_opt_t {
	switch input {
	case "required":
		return C.FIDO_OPT_TRUE
	case "discouraged":
		return C.FIDO_OPT_FALSE
	default:
		return C.FIDO_OPT_OMIT
	}
}

func timeoutFromContext(ctx context.Context) int {
	if ctx == nil {
		return defaultTimeout
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return defaultTimeout
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 1
	}
	ms := int(remaining / time.Millisecond)
	if ms <= 0 {
		return 1
	}
	return ms
}

func buildClientDataJSON(challenge []byte) ([]byte, error) {
	payload := map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      "pam://localhost",
		"crossOrigin": false,
	}
	return json.Marshal(payload)
}
