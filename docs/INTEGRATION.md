# Integration Guide

## 1. Build and install module

Build:

```bash
make build
```

`make build` compiles vendored `third_party/libfido2` from source and statically links it into `pamelo_pam_fido2.so`.

For vendor-specific Debian packages, use:

```bash
make dpkg OEM_FOLDER=examples/oem
```

Install:

```bash
sudo install -m 0755 dist/pamelo_pam_fido2.so /lib/security/pamelo_pam_fido2.so
```

## 2. Install module config

```bash
sudo install -d -m 0700 /etc/security/fido2
sudo install -m 0600 examples/oem/pam_fido2.yaml /etc/security/pam_fido2.yaml
```

Edit `/etc/security/pam_fido2.yaml` for your server URL and auth mode (`mtls` or `bearer`).

### mTLS mode

Supported mTLS sources:
- File paths: `auth.mtls.{ca_file,cert_file,key_file}`
- Inline PEM: `auth.mtls.{ca_pem,cert_pem,key_pem}`
- Inline base64 PEM: `auth.mtls.{ca_pem_b64,cert_pem_b64,key_pem_b64}`

Recommended permissions:

```bash
sudo chown root:root /etc/security/fido2/*
sudo chmod 0600 /etc/security/fido2/client.key /etc/security/fido2/client.pem
sudo chmod 0644 /etc/security/fido2/ca.pem
```

### Bearer mode

Set:
- `auth.mode: bearer`
- `auth.bearer.token: <license-key>`

Permissions:

```bash
sudo chown root:root /etc/security/pam_fido2.yaml
sudo chmod 0600 /etc/security/pam_fido2.yaml
```

## 3. Configure continuity state directory

Default:
- `/var/lib/pamelo-pam-fido2/state`

Create with secure ownership:

```bash
sudo install -d -m 0700 -o root -g root /var/lib/pamelo-pam-fido2/state
```

In `open_continuity` mode, this directory stores the latest successful state per user:
- RP ID
- Credential ID
- Last salt
- Corresponding hmac-secret output

## 4. PAM stack examples

### `sshd`

Edit `/etc/pam.d/sshd` and add near the top of `auth` stack:

```pam
auth required pamelo_pam_fido2.so config=/etc/security/pam_fido2.yaml debug
```

### `login`

Edit `/etc/pam.d/login`:

```pam
auth required pamelo_pam_fido2.so config=/etc/security/pam_fido2.yaml
```

### `sudo`

Edit `/etc/pam.d/sudo`:

```pam
auth required pamelo_pam_fido2.so config=/etc/security/pam_fido2.yaml
```

Choose `required` vs `sufficient` according to your local PAM policy.

## 5. Active feedback behavior

`feedback.level` controls runtime user feedback:
- `interactive`: status messages during server calls and touch wait
- `minimal`: suppress informational messages; errors still shown

`feedback.language` controls message language:
- `auto` (default): detect from `LANG`, fallback to English
- explicit: `en`, `es`, `fr`, `de`, `ja`, `zh`

Example messages:
- `Contacting authentication server...`
- `Touch your security key to continue [...]`
- `Verifying assertion with authentication server...`

## 6. Failure policy

`policy.fail_mode` values:
- `closed` (default): deny authentication on server/FIDO2 errors
- `open_continuity`: when server is unreachable, perform local continuity check using stored salt+hmac and live token response

## 7. Validation with pamtester

Test `sshd` policy for a user:

```bash
pamtester sshd <username> authenticate
```

## 8. Troubleshooting

- `PAM_SERVICE_ERR`: configuration or bootstrap issue.
  - Validate config path and keys.
  - Confirm cert/token file permissions.
- `PAM_AUTH_ERR`: assertion failure or deny decision.
  - Verify user has enrolled credential on the server.
  - Confirm RP ID and allowed credentials from `/v1/auth/begin`.
- `PAM_AUTHINFO_UNAVAIL`: backend unavailable path surfaced.
  - Check server TLS connectivity and mTLS token/cert settings.

Debug mode in PAM args (`debug`) logs details to syslog via `pam_syslog`.

## 9. Device activation

After package install, run as admin:

```bash
sudo pamelo-pam-fido2-configurator
```

It will:
- generate and store a device private key
- print device ID + pairing code
- render a QR payload (if `qrencode` is installed)
- output a mock device registration API request JSON
