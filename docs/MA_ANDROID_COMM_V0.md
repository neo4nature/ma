# MA Android COMM v0

Status: implementation branch, not merged or exposed to the Internet.

## Identity decision

Natalia is a separate MA user. Her Samsung is a revocable device assigned to
that user. The device owns two independent keys:

- ECDSA P-256 (`ES256`) authenticates requests;
- X25519 encrypts COMM envelopes.

Revoking or replacing the phone therefore does not rename or delete Natalia's
MA identity.

## Pairing

Create the `Natalia` user locally, then start MA with fresh values:

```bash
export MA_DEVICE_PAIR_OWNER=Natalia
export MA_DEVICE_PAIR_CODE='<one-time-random-code>'
```

`POST /comm/device/pair` accepts:

```json
{
  "pair_code": "...",
  "device_id": "uuid",
  "signing_public_key_b64": "DER SubjectPublicKeyInfo",
  "signing_fingerprint": "lowercase sha256 hex",
  "x25519_public_key_b64": "32 raw RFC 7748 bytes"
}
```

The server chooses the owner; the request cannot claim to be Neo, Lira or
another participant. A pairing code hash is consumed atomically and remains
consumed after restart. A byte-identical retry from the same device is
idempotent. The successful response includes current recipients' public X25519
keys, never their private keys.

## Ready envelope endpoint

`POST /comm/envelope` is parallel to the legacy `/comm/send` route. The legacy
route and all existing message rows remain valid.

```json
{
  "device_id": "uuid",
  "message_id": "uuid",
  "timestamp_ms": 0,
  "request_nonce": "at least 32 characters",
  "action": "send_encrypted_message",
  "receiver": "Neo",
  "ciphertext_b64": "...",
  "nonce_b64": "12 bytes",
  "salt_b64": "16 bytes",
  "aad_b64": "...",
  "v": 3,
  "key_id": "sha256:<signing-key-fingerprint>",
  "alg": "ES256",
  "signature": "base64 DER ECDSA signature"
}
```

The sender is never read from the request. It is derived from `device_id` after
signature and revocation checks.

## AAD

For phone-to-MA traffic, decoded AAD is exactly:

```text
<owner>-><receiver>|<message_id>|<timestamp_ms>
```

The first deployment therefore produces, for example:

```text
Natalia->Neo|550e8400-e29b-41d4-a716-446655440000|1789890000000
```

This preserves MA65's existing `sender->receiver|message_id|time` structure but
uses signed integer milliseconds instead of a language-dependent floating
point rendering. Version `3` distinguishes external ready envelopes from
legacy chat rows and the existing version-2 LifeCoin event rows.

## Signed canonical bytes

The ECDSA signature covers UTF-8 bytes of this exact text, including the final
newline:

```text
MA-DEVICE-COMM-V0
device_id:<device_id>
message_id:<message_id>
timestamp_ms:<timestamp_ms>
request_nonce:<request_nonce>
action:send_encrypted_message
receiver:<receiver>
ciphertext_sha256:<lowercase sha256 hex of decoded ciphertext>
nonce_b64:<nonce_b64>
salt_b64:<salt_b64>
aad_b64:<aad_b64>
v:3
key_id:<key_id>
alg:ES256
```

Before storing a row, MA opens it through the existing
`decrypt_for_pair` implementation. This is the cross-platform proof that raw
X25519, HKDF-SHA256 (`MA-COMM-E2E-v0`), AES-256-GCM and AAD agree. The plaintext
then passes the existing Horizon message policy.

## Storage and replies

`comm_devices` stores public keys, fingerprints, owner, creation time and
revocation time. `messages.sender_device_id` and
`messages.receiver_device_id` bind every external ciphertext to the exact key
used for it. Desktop replies to Natalia are encrypted to her active device's
X25519 public key; the phone keeps the private half.

## Exposure boundary

Fresh installations no longer create `Neo` and `Lira` with the known password
`demo`. That compatibility behavior is available only with the explicit local
development flag `MA_BOOTSTRAP_DEMO_USERS=1`.

Do not expose this prototype directly to the Internet. Finish the phone probe,
run the complete regression suite, and put MA behind an authenticated encrypted
transport before any remote test.

