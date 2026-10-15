# Authio Security Model

> TL;DR: fully offline, AES-256-GCM everywhere, Argon2id key derivation, secrets decrypted
> only in the Rust core, memory wiped on lock, no telemetry, minimal dependencies.

## Architecture boundary

```
┌─ WebView (TypeScript) ───────────┐      ┌─ Rust core ─────────────────┐
│ lists, search, modals, themes    │ IPC  │ vault, crypto, OTP engine,  │
│ receives: codes + metadata only  │◄────►│ importers, keychain, lock   │
│ sends: user intent (no secrets)  │      │ state (locked = wiped RAM)  │
└──────────────────────────────────┘      └─────────────────────────────┘
```

- Raw account secrets **never cross** the IPC boundary, except inside the
  *reveal-secret* dialog and exports — both gated by re-authentication.
- When the vault is locked, the decrypted state **does not exist** in memory at all:
  the lock screen is not a layer hiding data; the data is gone (DerefDrop → `zeroize`).

## Cryptography

| Purpose | Algorithm | Params |
|---|---|---|
| Vault & backup encryption | AES-256-GCM | random 96-bit nonce per write, 16-byte tag |
| Key derivation (passwords) | Argon2id | 64 MiB, t=3, p=4, 128-bit random salt |
| Aegis import compat | scrypt | params read from the vault (defaults 2^15/8/1) |
| Randomness | OS CSPRNG | `getrandom` only |
| OTP | HMAC-SHA-1/256/512 | RFC 4226/6238, official test vectors in CI |

Master-password verification uses the AEAD tag of the stored vault (re-derive +
decrypt attempt): constant oracles-free, and identical to what an attacker offline
would have to do. Wrong password ⇒ generic error.

The **keychain mode** stores a random 256-bit vault key in the OS credential manager
(Windows Credential Manager via `keyring` with `windows-native`). It protects the
vault file against theft, but not against an attacker seated at an unlocked session —
the master-password mode is the recommendation for high-value secrets.

## Memory & process hardening

- `Zeroizing` containers for the master key, derived keys, and per-account secret bytes.
- Session + pending-import drafts are dropped (zeroized) on: manual lock, auto-lock,
  minimize-lock, and window close.
- **Screen-capture protection**: `set_content_protected(true)` — screenshots and
  screen-share see a black window (Windows).
- No secrets/codes are ever logged; there is no persistent logging at all in v1.

## Platform / WebView hardening

- Strict CSP: `default-src 'self'` (+ `ipc:` for Tauri) — no remote content, ever.
- No HTTP client in the Rust binary; nothing in the app performs network I/O.
- Capability model: only `core:default` and `dialog:default` are granted.
- Settings file contains no secrets (theme/density/geometry only); vault and settings
  writes are atomic (temp → replace, `.bak` of last good copy).

## Threat model — what we do / don't defend against

- ✅ Vault file theft (password mode), casual snooping (keychain mode), shoulder
  surfing (hidden codes + capture protection), tampered backups (AEAD), corrupt
  imports (validation + explicit confirmation), accidental wipe (atomic writes + .bak).
- ⚠️ Not defended: a fully compromised OS (malware reading the unlocked process
  memory or the OS credential store), physical DMA attacks, weak master passwords.
  These are out of scope for a desktop TOTP app.

## Reporting

Open a **private** security advisory on GitHub rather than a public issue.
