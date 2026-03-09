# Server Contract

This module expects an HTTPS JSON API with these endpoints.

## `POST /v1/auth/begin`

### Request JSON

```json
{
  "username": "alice",
  "pam_service": "sshd",
  "hostname": "host01"
}
```

### Response JSON

```json
{
  "request_id": "req-123",
  "rp_id": "example.com",
  "challenge_b64url": "<base64url challenge bytes>",
  "allow_credentials_b64url": ["<base64url credential id>", "..."],
  "user_verification": "required",
  "hmac_salt_b64": "<base64 salt bytes>"
}
```

Encoding rules:
- `challenge_b64url`: URL-safe base64 without padding
- `allow_credentials_b64url[]`: URL-safe base64 without padding
- `hmac_salt_b64`: standard base64 with padding

## `POST /v1/auth/complete`

### Request JSON

```json
{
  "request_id": "req-123",
  "username": "alice",
  "credential_id": "<base64url credential id>",
  "authenticator_data": "<base64url authenticatorData>",
  "client_data_json": "{\"type\":\"webauthn.get\",...}",
  "signature": "<base64url signature>",
  "hmac_output_b64": "<base64 hmac-secret output>"
}
```

### Response JSON

```json
{
  "decision": "allow",
  "message": "optional message"
}
```

`decision` must be one of:
- `allow`
- `deny`
