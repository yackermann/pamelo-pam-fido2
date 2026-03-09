# Masterplan: Ubuntu Go PAM FIDO2 Module with libfido2 + Remote Server

## Summary

- Build a Linux PAM authentication module in Go, compiled as one deployable shared object `pamelo_pam_fido2.so`, using cgo bindings directly to Yubico `libfido2`.
- Primary auth path: server-driven challenge/response over HTTPS JSON. Module reads PAM username, talks to server, performs local FIDO2 assertion (with `hmac-secret`), sends assertion to server, and returns PAM allow/deny.
- Add active user feedback via PAM conversation messages during device detection, touch wait, server round-trips, and final result.
- Add multilingual user feedback with language auto-detection and explicit override.
- Validate behavior on Ubuntu 24.04 LTS and Ubuntu 25.10.

## Implemented Scope

- PAM module exports:
  - `pam_sm_authenticate`
  - `pam_sm_setcred`
- Config path option from PAM args:
  - `config=/etc/security/pam_fido2.yaml`
  - optional `debug`
- Feedback localization:
  - `feedback.language`: `auto`, `en`, `es`, `fr`, `de`, `ja`, `zh`
- HTTPS API contract:
  - `POST /v1/auth/begin`
  - `POST /v1/auth/complete`
- Transport auth:
  - mTLS
  - Bearer token
- Failure policy:
  - `closed` (default)
  - `open_continuity`
- Offline continuity state persistence:
  - root-protected state dir
  - per-user state with rp_id, credential_id, salt, hmac
- Integration docs and build/test workflow.

## Notes

- Enrollment remains external to this module (existing server flow).
- Username is taken directly from PAM (`pam_get_user`) without normalization.
- Hardware-dependent libfido2 integration test is gated behind explicit env vars and build tags.
