# Authio — Feature Specification

> A lightweight, fast, secure, and open-source 2FA Authenticator built with **Rust + Tauri + TypeScript**.
> Language: English (i18n-ready). Platform: Windows (NSIS installer `.exe` + portable `.zip`).
> Source: <https://github.com/Arvanta/Authio> — Licensed under MIT.

This document is the single source of truth for Authio's scope. Features are organized into three tiers: **MVP (v1.0)**, **Complementary (v1.x)**, and **Advanced (v2+)**.

**Design principles**

1. **Offline-first, forever** — no accounts, no servers, no telemetry, no network calls of any kind.
2. **Secrets never leave the Rust core** — the WebView UI never receives raw secrets; it only receives generated OTP codes and non-secret metadata.
3. **Small and auditable** — minimal dependencies, hand-written crypto-critical code where practical, RFC test vectors in CI.
4. **Fluent 2 aesthetics** — minimal, calm, and native-feeling on Windows 11.

---

## Tier 1 — MVP (v1.0)

### 1. Code generation

- TOTP per **RFC 6238**, with verification against RFC test vectors in CI.
- Default 30-second period; supports 15/30/60 s and custom periods from `otpauth://` URIs.
- Algorithms: **SHA-1, SHA-256, SHA-512** (per-account, parsed from URI / manual input).
- Digits: **6 or 8** (extensible), grouped rendering for readability (`123 456`).
- **HOTP (RFC 4226)** counter-based codes as an optional per-account type; counter increments only on explicit user request.
- All computation is local; the app never requires internet access.

### 2. Adding accounts

- **QR from image file** (PNG/JPEG) — decoded locally in Rust (`rqrr`), supporting `otpauth://` and `otpauth-migration://` (Google) payloads.
- **Manual secret entry** — Base32 input that tolerates lowercase, spaces, and padding issues; validated before saving.
- **`otpauth://` URI paste** — full parsing of `totp`/`hotp`: issuer, account name, secret, algorithm, digits, period, counter.
- Reads issuer / account name / code parameters from QR automatically.
- **Validation before persistence**: duplicate secret detection, label conflicts, malformed secrets, and unsafe parameters are rejected with clear errors.

### 3. Display & copying

- List of all accounts with simultaneous live codes; automatic per-second refresh.
- **One-click copy** (click code or copy button) with subtle "copied" feedback.
- Countdown to expiry + **circular progress indicator**; linear indicator option in settings.
- **Codes hidden until requested** (default: dots; tap/hover to reveal); global "show codes" toggle.
- HOTP codes revealed on demand (each reveal advances the counter, mirroring the server).

### 4. Account management

- Edit issuer (service) and account (username) labels.
- Delete with confirmation dialog.
- Sort: **manual order (drag & drop)** or alphabetical (issuer → account).
- **Instant search** over issuer and account names.
- **Pin** frequent accounts to the top.
- Issuer + account name always rendered next to the code.

### 5. Security & encryption

- **Whole-vault encryption at rest: AES-256-GCM** (96-bit random nonce per write, 256-bit key).
- Key derivation modes (chosen at first run, shown on lock screen):
  - **Master password mode** — **Argon2id** (m = 64 MiB, t = 3, p = 4) over a 128-bit random salt; password never stored; wrong passwords rejected by AEAD tag verification (no oracle).
  - **OS keychain mode** — random 256-bit key generated at setup and stored in the Windows Credential Manager via the `keyring` crate; vault unlocks without typing a password while the OS session is authenticated.
- **Random salt & nonce per encryption**; header records version + KDF + cipher parameters for forward migration.
- **Atomic persistence**: write-temp-then-rename so a crash never corrupts the vault.
- **Auto-lock**: after N minutes of inactivity (default 5; 0 = off) and on window minimize — key and decrypted accounts are wiped from memory (`zeroize`).
- **Screen-capture protection**: window content protection (`set_content_protected`) on Windows so screenshots/screen-share show a black surface.
- **Re-authentication required** to reveal a stored secret or to perform any export containing secrets.
- **Memory hygiene (`zeroize`)**: master key, derived keys, and per-account secret bytes live in `Zeroizing` containers and are wiped on lock/drop. No plaintext secrets in logs, temp files, crash dumps (best effort), or the frontend.

> Threat-model note: encrypting a database file is not enough by itself. The unlock flow guarantees that until authentication succeeds, decrypted secrets are unreachable — the UI lock is never the only layer. Secrets are decrypted only inside the Rust core; codes are the only OTP-related values crossing the IPC boundary.

### 6. Privacy

- No network access anywhere in the app (no HTTP client, no update pings in v1.0).
- No secrets or OTP codes written to any log; logging is minimal, local, and opt-in.
- No account creation, ads, analytics, or third-party services.
- Strict WebView **CSP**: `default-src 'self'; img-src 'self' data:` — no remote resources.

### 7. Import / Export  *(each importer is an isolated, individually tested module)*

- **Export (Authio native format v1, documented** in `docs/BACKUP-FORMAT.md`):
  - Encrypted backup — vault JSON → AES-256-GCM with a **dedicated backup passphrase** (Argon2id); this is the recommended path.
  - Plain export — only after explicit multi-step confirmation, warn user it is readable by anyone.
- Requires re-authentication before any export containing secrets (`reveal or export` gate).
- **Import**, with a unified preview → duplicate detection → per-account confirm → apply flow:
  | Source | Formats | Notes |
  |---|---|---|
  | **Authio** | encrypted / plain JSON | version-tolerant reader for forward compatibility |
  | **otpauth lines** | list of `otpauth://` URIs (text file / paste) | commonly produced by other CLI tools |
  | **Google Authenticator** | `otpauth-migration://offline?data=…` QR or URI | minimal hand-written protobuf-wire parser (no dependency) |
  | **Aegis** | vault JSON (plain) and **encrypted vault** | scrypt (n/r/p) → AES-256-GCM slots + payload |
  | **Authme** | export JSON (`secrets` array) | tolerant field mapping (`name`/`issuer`), isolated & tested |
- **Duplicate detection** (by secret equality and label match) with keep / skip / import-as-copy choices.
- **Import preview**: full list of accounts to add, duplicates highlighted, nothing applied until the user confirms.
- **Corruption/tamper resistance**: AEAD tag verification rejects modified backups; malformed files fail with specific errors, never with a partial silent import.
- **Restore never clobbers silently**: importing shows existing-vs-incoming conflicts; replacement requires explicit user choice. Existing vault is never overwritten without confirmation.

### 8. UI / UX  — *Fluent 2 design language*

- **Fluent 2-aligned visuals**: Mica/Acrylic window backdrop, Segoe UI Variable type, 8 px rounded controls, layered cards, subtle hover/press states, restrained accent color, reduced-motion respect.
- **Compact account list** (dense rows, minimal chrome): large readable code, one-click copy, small countdown ring, issuer on top, account name below.
- Density toggle **compact / comfortable**; font-size stepper for code readability.
- **Themes**: light, dark, follow system.
- **Window geometry persistence**: size + position restored on next launch (with clamping to visible desktop bounds).
- Minimal empty space, no decorative clutter; empty state explains the three ways to add an account.
- Keyboard-friendly: `Ctrl+F` search, `Enter` reveal/copy, `Ctrl+L` lock, `Ctrl+,` settings.
- **Language: English in v1.0**, with an i18n-ready architecture — every string lives in `locales/en.json`, so future translations are additive.

---

## Tier 2 — Complementary (v1.x)

- **Service icon pack** — bundled, offline SVG set for popular issuers; colored letter-avatar fallback (no remote icon fetching, ever).
- Change master password / re-encrypt vault; switch between password and keychain modes.
- Auto-backup: scheduled encrypted backup to a user-chosen folder.
- Import camera scan (webcam QR) — optional, behind a permission prompt.
- More importers: 2FAS, Raivo, andOTP, Bitwarden/TOTP CSV — each isolated and test-covered.
- Export a selected subset of accounts.
- System tray with minimize-to-tray and lock-on-minimize.
- Portable mode: `--portable` flag keeps vault next to the executable.
- Tauri updater (opt-in, release-signed).
- Windows Hello unlock (where supported by the OS credential APIs).

## Tier 3 — Advanced (v2+)

- Full i18n releases — first: **Persian (Farsi) with complete RTL layout** (CSS logical properties, mirrored icons).
- Multi-vault profiles (e.g., work / personal) with fast switching.
- Local-first encrypted sync via a user-owned folder (WebDAV / LAN / portable drive) — still no first-party servers.
- Specialized issuers: Steam-style 5-character codes, Battle.net 8-digit semantics.
- Hardening extras: optional hardware-key (FIDO2/YubiKey) vault unlock, configurable Argon2id parameters, login-attempt throttling.
- Importer plugin API (WASM) for community formats.
- Optional password-strength meter and breach-check that runs **entirely offline** (local k-anonymity-free wordlist).

---

## Non-goals (permanent)

- No cloud accounts, no first-party servers, no telemetry, no push of secrets anywhere.
- No password-manager features (passwords/forms) — Authio is strictly a TOTP/HOTP vault.
- No blockchain/web3 gimmicks.

## Engineering notes

- **Stack**: Tauri 2 (Rust) backend; Vite + **framework-free TypeScript** frontend; zero runtime JS frameworks to keep binary size and audit surface small.
- **Rust crypto deps**: `aes-gcm`, `argon2`, `scrypt`, `hmac` + `sha1`/`sha2`, `zeroize`, `keyring`, `data-encoding`, `rqrr`, `image`.
- **OTP core hand-written** per RFC 4226/6238 with official test vectors (SHA-1/256/512) as unit tests — runs in CI on every build.
- **Storage**: single encrypted vault file in `%APPDATA%/Authio/vault.json` (Windows), atomic writes, automatic `.bak` of last good vault.
- **Build & release**: GitHub Actions (`tauri-action`, `windows-latest`) → NSIS installer `.exe` + portable `.zip`, published to GitHub Releases on tags; SHA-256 checksums attached.
- **Repo layout**: `/` (Vite app), `src-tauri/` (Rust), `docs/` (SPEC, BACKUP-FORMAT, SECURITY), `.github/workflows/build.yml`.

---

*Status: approved-for-implementation draft → v1.0 scope frozen.*
