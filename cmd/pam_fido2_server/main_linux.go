//go:build linux && cgo && pam

package main

/*
#cgo CFLAGS: -D_GNU_SOURCE
#cgo LDFLAGS: -lpam
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <syslog.h>

static int get_pam_user(pam_handle_t *pamh, const char **user) {
    return pam_get_user(pamh, user, NULL);
}

static int get_pam_service(pam_handle_t *pamh, const char **service) {
    return pam_get_item(pamh, PAM_SERVICE, (const void **)service);
}

static void pam_info_msg(pam_handle_t *pamh, const char *msg) {
    pam_info(pamh, "%s", msg);
}

static void pam_error_msg(pam_handle_t *pamh, const char *msg) {
    pam_error(pamh, "%s", msg);
}

static void pam_debug_msg(pam_handle_t *pamh, const char *msg) {
    pam_syslog(pamh, LOG_DEBUG, "%s", msg);
}

static void pam_err_msg(pam_handle_t *pamh, const char *msg) {
    pam_syslog(pamh, LOG_ERR, "%s", msg);
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/werk/pamelo-pam-fido2/internal/auth"
	"github.com/werk/pamelo-pam-fido2/internal/authn"
	"github.com/werk/pamelo-pam-fido2/internal/config"
	"github.com/werk/pamelo-pam-fido2/internal/feedback"
	"github.com/werk/pamelo-pam-fido2/internal/i18n"
	"github.com/werk/pamelo-pam-fido2/internal/server"
	"github.com/werk/pamelo-pam-fido2/internal/state"
)

const defaultConfigPath = "/etc/security/pam_fido2.yaml"

type moduleOptions struct {
	configPath string
	debug      bool
}

type pamSink struct {
	pamh         *C.pam_handle_t
	debugEnabled bool
}

func (p *pamSink) Info(msg string) {
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))
	C.pam_info_msg(p.pamh, cMsg)
}

func (p *pamSink) Error(msg string) {
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))
	C.pam_error_msg(p.pamh, cMsg)
	C.pam_err_msg(p.pamh, cMsg)
}

func (p *pamSink) Debug(msg string) {
	if !p.debugEnabled {
		return
	}
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))
	C.pam_debug_msg(p.pamh, cMsg)
}

func main() {}

//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	_ = flags
	opts := parseModuleOptions(argc, argv)
	sink := &pamSink{pamh: pamh, debugEnabled: opts.debug}

	cfg, err := config.Load(opts.configPath)
	if err != nil {
		localizer := i18n.New(i18n.ResolveLanguage("", os.Getenv("LANG")))
		sink.Error(localizer.S(i18n.MsgConfigLoadFailed, opts.configPath, err))
		return C.PAM_SERVICE_ERR
	}

	resolvedLanguage := i18n.ResolveLanguage(cfg.Feedback.Language, os.Getenv("LANG"))
	cfg.Feedback.Language = resolvedLanguage
	localizer := i18n.New(resolvedLanguage)
	reporter := feedback.New(cfg.Feedback.Level, sink)

	username, err := getPAMUser(pamh)
	if err != nil {
		reporter.Error(localizer.S(i18n.MsgUnableReadPAMUser))
		reporter.Debug(err.Error())
		return C.PAM_USER_UNKNOWN
	}
	serviceName, err := getPAMService(pamh)
	if err != nil {
		reporter.Error(localizer.S(i18n.MsgUnableReadPAMService))
		reporter.Debug(err.Error())
		return C.PAM_SERVICE_ERR
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	serverClient, err := server.New(cfg)
	if err != nil {
		reporter.Error(localizer.S(i18n.MsgUnableInitServerClient))
		reporter.Debug(err.Error())
		return C.PAM_SERVICE_ERR
	}

	authenticator := authn.NewLibfido2AuthenticatorWithLanguage(resolvedLanguage)
	stateStore := state.New(cfg.Offline.StateDir)
	svc := auth.New(serverClient, authenticator, stateStore, cfg, reporter)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	err = svc.Authenticate(ctx, auth.Request{
		Username: username,
		Service:  serviceName,
		Hostname: hostname,
	})
	if err != nil {
		reporter.Debug(localizer.S(i18n.MsgAuthenticationFailedDebug, err))
		return mapErrorToPAM(err)
	}
	return C.PAM_SUCCESS
}

//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	_ = pamh
	_ = flags
	_ = argc
	_ = argv
	return C.PAM_SUCCESS
}

func mapErrorToPAM(err error) C.int {
	if err == nil {
		return C.PAM_SUCCESS
	}
	if errors.Is(err, auth.ErrConfig) || errors.Is(err, config.ErrInvalidConfig) {
		return C.PAM_SERVICE_ERR
	}
	if errors.Is(err, auth.ErrUnavailable) {
		return C.PAM_AUTHINFO_UNAVAIL
	}
	return C.PAM_AUTH_ERR
}

func parseModuleOptions(argc C.int, argv **C.char) moduleOptions {
	opts := moduleOptions{configPath: defaultConfigPath}
	for _, arg := range parseArgs(argc, argv) {
		switch {
		case strings.HasPrefix(arg, "config="):
			p := strings.TrimSpace(strings.TrimPrefix(arg, "config="))
			if p != "" {
				opts.configPath = p
			}
		case arg == "debug":
			opts.debug = true
		}
	}
	return opts
}

func parseArgs(argc C.int, argv **C.char) []string {
	n := int(argc)
	if n <= 0 || argv == nil {
		return nil
	}
	ptrs := unsafe.Slice(argv, n)
	out := make([]string, 0, len(ptrs))
	for _, ptr := range ptrs {
		if ptr == nil {
			continue
		}
		out = append(out, C.GoString(ptr))
	}
	return out
}

func getPAMUser(pamh *C.pam_handle_t) (string, error) {
	var user *C.char
	rc := C.get_pam_user(pamh, (**C.char)(unsafe.Pointer(&user)))
	if rc != C.PAM_SUCCESS {
		return "", fmt.Errorf("pam_get_user failed with code %d", int(rc))
	}
	if user == nil {
		return "", fmt.Errorf("pam_get_user returned nil")
	}
	return C.GoString(user), nil
}

func getPAMService(pamh *C.pam_handle_t) (string, error) {
	var service *C.char
	rc := C.get_pam_service(pamh, (**C.char)(unsafe.Pointer(&service)))
	if rc != C.PAM_SUCCESS {
		return "", fmt.Errorf("pam_get_item(PAM_SERVICE) failed with code %d", int(rc))
	}
	if service == nil {
		return "", fmt.Errorf("PAM_SERVICE item is nil")
	}
	return C.GoString(service), nil
}
