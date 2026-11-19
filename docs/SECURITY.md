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

**Key management (since 1.1.0)**
- Every vault has a random id in its header; keychain mode stores its key in an entry named
  after that id (`vault-key-<id>`), so several vaults (installed + portable copies, re-installs)
  never overwrite one another's key. Vaults from 1.0 used one shared entry: they are given an id
  on first unlock (key copied first, then the id written; the shared entry is left in place; any
  failure leaves the vault working as before). If saving the vault fails, the previous keychain
  entry is restored, and no orphaned entry is left behind.
- **The encryption key is always fresh when the unlock method changes** (and the vault is
  re-encrypted) — it is never carried over from the old method. Without this, a stale copy of the
  file (cloud, USB, backup; for "no security" the key sits inside it in clear) would keep opening
  the new vault too. It does **not** protect data already in such copies: if an old copy or old
  password was exposed, treat the existing accounts as exposed and re-issue their secrets.
- **Vault-swap warning:** the last-seen unlock method and vault id are recorded in the OS
  credential store. If the vault file's method or identity differs from that record when Authio
  starts (changed outside the app), the user must confirm before anything is unlocked or added;
  the backend also refuses to unlock until then. Changes made inside the app never trigger it,
  and with no record yet (first run / upgrade) nothing is raised (trust on first use).
- Known limitation: the vault header (kdf, kind, version, id) is not yet bound into the AEAD as
  associated data. Header tampering that matters already fails (the KDF parameters and key feed
  the decryption), and full file replacement is what the warning above detects; binding the header
  needs a file-format version bump and is planned for a later release.

## Memory & process hardening

- `Zeroizing` containers for the master key, derived keys, per-account secret bytes, the decrypted/serialised vault payload buffers, and password strings received over IPC. This is **best effort**: transient copies made by the JSON parser, the WebView/IPC layer or the OS (swap, crash dumps) are outside the app's control.
- KDF parameters read from untrusted files (backups, Aegis) are range-checked, so a crafted header cannot exhaust memory.
- Session + pending-import drafts are dropped (zeroized) on: manual lock, auto-lock,
  minimize-lock, and window close.
- **Lock wipes the UI too**: on every lock, open dialogs/menus (e.g. a revealed secret) are removed from the DOM along with the cached account list.
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
- ✅ A vault file swapped for another one while Authio was closed (warned before unlocking, see above).
- ⚠️ Not defended: a fully compromised OS (malware reading the unlocked process
  memory or the OS credential store), physical DMA attacks, weak master passwords.
  These are out of scope for a desktop TOTP app.

## Reporting

Open a **private** security advisory on GitHub rather than a public issue.
