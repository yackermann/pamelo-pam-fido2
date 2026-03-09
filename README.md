# fido2-pam-go

Linux PAM authentication module in Go that uses `libfido2` for local key operations and a remote FIDO2 policy server for final allow/deny.

The module is built as a single PAM shared object:
- `pam_fido2_server.so`

`libfido2` is vendored as a git submodule at `third_party/libfido2`, built from source as a static archive, and linked into `pam_fido2_server.so`.

## Features

- Go + cgo PAM module entrypoints (`pam_sm_authenticate`, `pam_sm_setcred`)
- Direct `libfido2` assertion flow with `hmac-secret`
- Remote server flow:
  - `POST /v1/auth/begin`
  - `POST /v1/auth/complete`
- Configurable failure mode:
  - `closed` (default)
  - `open_continuity` (offline continuity verification)
- Active end-user feedback through PAM conversation functions
- Multilingual feedback (`auto`, `en`, `es`, `fr`, `de`, `ja`, `zh`)
- mTLS or Bearer authentication to the remote server

## Ubuntu Prerequisites

Targeted/tested for:
- Ubuntu 24.04 LTS
- Ubuntu 25.10

Install dependencies:

```bash
sudo apt-get update
sudo apt-get install -y \
  golang-go \
  build-essential \
  cmake \
  pkg-config \
  libpam0g-dev \
  libcbor-dev \
  libssl-dev \
  zlib1g-dev \
  libudev-dev \
  pamtester
```

## Build

```bash
make build
```

This automatically:
- initializes/updates `third_party/libfido2` submodule
- builds `libfido2.a` from source into `.cache/libfido2/install/lib/libfido2.a`
- statically links that archive into `dist/pam_fido2_server.so`

Optional explicit submodule/bootstrap steps:

```bash
git submodule update --init --recursive third_party/libfido2
make libfido2
```

## Test

```bash
make test
```

Hardware integration test (optional):

```bash
FIDO2_HW_TEST=1 \
FIDO2_TEST_RP_ID=example.com \
FIDO2_TEST_CREDENTIAL_ID_B64URL=... \
FIDO2_TEST_SALT_B64=... \
go test -tags "libfido2 integration" ./internal/authn -run TestComputeContinuityHMACHardware -v
```

## Configuration

Default config path loaded by the PAM module:
- `/etc/security/pam_fido2_server.yaml`

Example config:
- [`examples/pam_fido2_server.yaml`](examples/pam_fido2_server.yaml)

## Integration Guide

See full setup and PAM stack examples:
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md)

## Server Contract

See request/response schema and field encoding:
- [`docs/SERVER_CONTRACT.md`](docs/SERVER_CONTRACT.md)
