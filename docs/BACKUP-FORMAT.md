# Authio Backup Format v1

Authio owns a documented, version-tolerant backup format so users are never locked in.
There are two shapes, both UTF-8 JSON. Detection rule: top-level `"app": "authio"`.

## 1. Encrypted backup (recommended)

Identical envelope to the on-disk vault:

```json
{
  "app": "authio",
  "kind": "backup",
  "version": 1,
  "kdf": {
    "name": "argon2id",
    "m": 65536,
    "t": 3,
    "p": 4,
    "salt": "<base64, 16 bytes>"
  },
  "cipher": { "name": "aes-256-gcm", "nonce": "<base64, 12 bytes>" },
  "data": "<base64 ciphertext||tag>"
}
```

- **KDF**: Argon2id over the backup passphrase (not necessarily the master password),
  `m` in KiB (65536 = 64 MiB), output 32 bytes.
- **Cipher**: AES-256-GCM, 12-byte random nonce; the 16-byte tag is appended to the
  ciphertext (RustCrypto `aes-gcm` convention). A failed tag means *wrong passphrase
  or tampered file* — there is no oracle.
- **Payload** (decrypted) is the plain backup structure below.

The on-disk vault itself uses `"kind": "vault"`; a vault may instead declare
`"kdf": { "name": "keychain" }` (key stored by the OS credential manager). Keychain
vaults are **not portable** — exporting an encrypted backup is the supported way to
move to another machine.

## 2. Plain backup (explicitly acknowledged by the user)

```json
{
  "app": "authio",
  "kind": "backup",
  "version": 1,
  "encrypted": false,
  "accounts": [
    {
      "issuer": "GitHub",
      "name": "alice@example.com",
      "secret": "JBSWY3DPEHPK3PXP",
      "algorithm": "SHA1",
      "digits": 6,
      "period": 30,
      "type": "totp",
      "counter": 0
    }
  ]
}
```

Field rules:

- `secret` — Base32 (RFC 4648), uppercase, padding optional on import.
- `algorithm` — `SHA1 | SHA256 | SHA512` (case-insensitive, `-` tolerated). Default `SHA1`.
- `digits` — 4–10, default 6. `period` — 5–300 s, default 30 (TOTP only).
- `type` — `totp` (default) | `hotp`; `counter` used by HOTP only (default 0).
- Readers must ignore unknown top-level and per-account fields (forward compatibility)
  and must reject files with `"version"` greater than supported.

## Guarantees

- Importing either shape runs through the same pipeline: format detection → optional
  decryption → per-account validation → duplicate detection → user confirmation.
- Malformed accounts are skipped and counted; tampered encrypted files produce a
  precise error and never a partial silent import.
