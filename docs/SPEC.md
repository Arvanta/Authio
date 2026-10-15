# Authio — Feature Specification

> A lightweight, fast, secure, and open-source 2FA Authenticator built with **Rust + Tauri + TypeScript**.
> Languages: English, German, Spanish, French, Japanese, Korean, Portuguese, Russian, Simplified Chinese (live switchable in Settings; Persian + RTL planned). Platform: Windows (NSIS installer `.exe` + portable `.zip`).
> Source: <https://github.com/Arvanta/Authio> — Licensed under MIT.

This document is the single source of truth for Authio's scope. Features are organized into three tiers: **MVP (v1.0)**, **Complementary (v1.x)**, and **Advanced (v2+)**.

**Design principles**

1. **Offline-first, forever** — no accounts, no servers, no telemetry, no network calls of any kind.
2. **Secrets never leave the Rust core** — the WebView UI never receives raw secrets; it only receives generated OTP codes and non-secret metadata.
3. **Small and auditable** — minimal dependencies, hand-written crypto-critical code where practical, RFC test vectors in CI.
4. **Fluent 2 aesthetics** — minimal, calm, and native-feeling on Windows 11.

---

## Tier 1 — MVP (v1.0) ✅ implemented

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
- Optional **group** assignment when adding an account (with suggestions from existing groups).

### 3. Display & copying

- List of all accounts with simultaneous live codes; automatic per-second refresh.
- **One-click copy** (click code or copy button) with subtle "copied" feedback.
- Countdown to expiry + **circular progress indicator** with the seconds remaining drawn inside the ring (number can be hidden in Settings).
- **Codes hidden until requested** (default: dots; tap to reveal); global "show codes" toggle.
- HOTP codes revealed on demand (each reveal advances the counter, mirroring the server).

### 4. Account management

- Edit issuer (service), account (username) and **group** labels.
- Delete with confirmation dialog.
- Sort: **manual order (drag & drop)** or alphabetical (issuer → account).
- **Instant search** over issuer and account names (search box lives in the top bar).
- **Pin** frequent accounts to the top (via the per-card ⋮ menu).
- **Groups**: free-form group labels per account; a top-bar filter dropdown (All / group / Ungrouped) and a toggle for grouped view with per-group sections.
- **Two view styles**: dense **rows** and compact **tiles**, switchable from the top bar; choice persists.
- Per-card actions (pin, edit, reveal secret, delete) live in a **⋮ dropdown menu** (rows view).
- Issuer + account name always rendered next to the code.

### 5. Security & encryption

- **Whole-vault encryption at rest: AES-256-GCM** (96-bit random nonce per write, 256-bit key).
- Key protection modes, chosen at setup and **changeable later from Settings** (re-verifies the current master password; selecting the master-password mode again = change password with a fresh salt and re-derivation):
  - **Master password** — **Argon2id** (m = 64 MiB, t = 3, p = 4) over a 128-bit random salt; password never stored; wrong passwords rejected by AEAD tag verification (no oracle).
  - **Windows sign-in (OS keychain)** — random 256-bit key stored in the Windows Credential Manager via the `keyring` crate; vault unlocks without typing a password while the OS session is authenticated.
  - **No security** — key embedded in the vault file (obfuscation only, clearly labelled and warned about in the UI).
- **Random salt & nonce per encryption**; header records version + KDF + cipher parameters for forward migration.
- **Atomic persistence**: write-temp-then-rename, plus an automatic `.bak` of the last good vault.
- **Auto-lock**: after N minutes of inactivity (default 5; 0 = off) and on window minimize — key and decrypted accounts are wiped from memory (`zeroize`). Auto-lock is skipped entirely in "no security" mode.
- **Auto-unlock at startup** (once) for keychain / no-security vaults; manual `Ctrl+L` locking still available.
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

- Import and export actions are centralized in **Settings → Data**.
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
  | **2FAS** | plain backup JSON (`services` array) | encrypted (`servicesEncrypted`) backups rejected with a clear message |
  | **andOTP** | plain backup JSON array (`secret`/`issuer`/`label`/`type`) | encrypted andOTP exports unsupported |
  | **Raivo** | `raivo-otp-export.json` | numeric fields arrive as strings — accepted in both forms |
  | **Bitwarden** | vault-export `.csv` (`login_totp` column) | column values may be `otpauth://` URIs or raw Base32 seeds; hand-rolled CSV parser (quoted fields), no extra dependency |
  | **Steam (SDA maFile)** | single JSON object with Base64 `shared_secret` | imports as a Steam-flavored (5-character) account |

- **Duplicate detection** (by secret equality and label match) with keep / skip / import-as-copy choices.
- **Import preview**: full list of accounts to add, duplicates highlighted, nothing applied until the user confirms.
- **Corruption/tamper resistance**: AEAD tag verification rejects modified backups; malformed files fail with specific errors, never with a partial silent import.
- **Restore never clobbers silently**: imports only add accounts; the existing vault is never overwritten without confirmation.

### 8. UI / UX — *Fluent 2 design language*

- **Fluent 2-aligned visuals**: Mica-style backdrop, Segoe UI Variable type, 8 px rounded controls, layered cards, subtle hover/press states, restrained accent color, reduced-motion respect.
- **Compact account list** (dense rows, minimal chrome): large readable code, one-click copy, countdown ring with the seconds number inside, issuer on top, account name below.
- **Two view styles** — rows / tiles (top-bar toggle + Settings).
- Density toggle **compact / comfortable**; font-size stepper for code readability.
- **Themes**: light, dark, follow system.
- **Window geometry persistence**: size + position restored on next launch (inner size is saved so the window never drifts larger; clamped to visible desktop bounds).
- Minimal empty space, no decorative clutter; empty state explains the three ways to add an account.
- Keyboard-friendly: `Ctrl+F` search, `Ctrl+L` lock, `Ctrl+,` settings.
- **Languages in v1.0**: English, German, Spanish, French, Japanese, Korean, Portuguese, Russian and Simplified Chinese — each lives in `locales/<code>.json` mirroring `en.json`'s key structure (fallback: English, then the raw key). Choice persists in the vault settings and applies instantly. Persian + full RTL is the first post-1.0 language (CSS logical properties, mirrored icons).

### v1.0 status

- ✅ **Complete** — including SHA-256 checksums attached to every GitHub Release (NSIS installer + portable zip, `.sha256` files in `sha256sum -c` format).

---

## Tier 2 — Complementary (v1.x)

- ~~SHA-256 checksums~~ ✅
- ~~Portable mode: `--portable`~~ ✅ (vault + settings live in `authio-data/` next to the executable)
- ~~More importers: 2FAS, Raivo, andOTP, Bitwarden/TOTP CSV~~ ✅ (+ Steam maFile)
- ~~System tray with minimize-to-tray~~ ✅ (Settings toggle; tray menu: show / lock / quit; the close button hides to tray)
- ~~Specialized issuers: Steam / Battle.net~~ ✅ (Steam = 5-character custom-alphabet rendering + maFile import, auto-detected from `issuer=Steam` URIs; Battle.net needs nothing special — standard TOTP SHA-1 / 8 digits / 30 s, supported from day one)
- **Import camera scan (webcam QR)** — optional, behind a permission prompt; reuses the existing `rqrr` decode pipeline.
- **Windows Hello unlock** (where supported by the OS credential APIs) — a fourth unlock method alongside password / keychain / none.

### Suggested v1.x order (remaining)

Windows Hello → Camera scan

---

## Tier 3 — Advanced (v2+)

- **i18n releases** — ~~German, Spanish, Simplified Chinese, French, Portuguese, Russian, Japanese, Korean~~ ✅ shipped in v1.0. Next: **Persian (Farsi) with complete RTL layout** (CSS logical properties, mirrored icons); then community languages. All LTR; system fonts only, no font bundling.
- **Local-first encrypted sync** via a user-owned folder (WebDAV / LAN / portable drive) with merge semantics (per-account timestamps + deletion tombstones) — still no first-party servers.
- **Hardening extras**: configurable Argon2id parameters (preset levels) and login-attempt throttling (progressive backoff).
- **Importer plugin API (WASM)** for community formats — sandboxed, with a documented ABI.
- Optional **password-strength meter** that runs entirely offline (local wordlist).

---

## Non-goals (permanent)

- No cloud accounts, no first-party servers, no telemetry, no push of secrets anywhere.
- No password-manager features (passwords/forms) — Authio is strictly a TOTP/HOTP vault.
- No blockchain/web3 gimmicks.

### Explicitly rejected (decided, do not re-propose)

- Linear (bar) progress indicator option — the circular ring with inner countdown number is the single design.
- Enter-key reveal/copy interaction on rows.
- Service icon pack (letter avatars stay the only per-issuer art).
- Scheduled auto-backup.
- Selective (subset) export.
- Tauri auto-updater.
- Multi-vault profiles.
- FIDO2/YubiKey hardware-key unlock.

---

## Engineering notes

- **Stack**: Tauri 2 (Rust) backend; Vite + **framework-free TypeScript** frontend; zero runtime JS frameworks to keep binary size and audit surface small.
- **Rust crypto deps**: `aes-gcm`, `argon2`, `scrypt`, `hmac` + `sha1`/`sha2`, `zeroize`, `keyring`, `data-encoding`, `rqrr`, `image`.
- **OTP core hand-written** per RFC 4226/6238 with official test vectors (SHA-1/256/512) as unit tests — runs in CI on every build.
- **Storage**: single encrypted vault file in `%APPDATA%/Authio/vault.json` (Windows), atomic writes, automatic `.bak` of last good vault.
- **Build & release**: GitHub Actions (`tauri-action`, `windows-latest`) → NSIS installer `.exe` + portable `.zip`, published to GitHub Releases; **exactly one workflow run per release** (triggers: tags `v*` + manual dispatch only). SHA-256 checksums attached (pending).
- **Repo layout**: `/` (Vite app), `src-tauri/` (Rust), `docs/` (SPEC, BACKUP-FORMAT, SECURITY), `.github/workflows/build.yml`.

---

*Status: v1.0 (incl. groups, unlock-mode switching, no-security mode, rows/tiles views) implemented — pending first green CI build. Scope reviewed and trimmed on 2026-10-15.*
