# Authio — Project Handoff

> Single document for anyone (human or AI agent) picking up Authio from zero.
> Read this first; then `docs/SPEC.md` (feature truth), `docs/SECURITY.md` (security model),
> `docs/BACKUP-FORMAT.md` (vault/backup format).

## 1. What this is

**Authio** — a tiny, fast, fully-offline 2FA (TOTP/HOTP) authenticator for Windows.
Rust + Tauri 2 + TypeScript. MIT licensed. Repo: <https://github.com/Arvanta/Authio>.
Releases ship a NSIS installer `.exe` + portable `.zip`, each with a `.sha256` sidecar (`sha256sum -c` format).

Non-negotiable product rules:

- **100% offline** — no accounts, no servers, no telemetry, no auto-update phone-home.
- **Secrets never leave the device.** The WebView never receives raw secrets; only codes + metadata.
- **Locked = wiped RAM.** Until the vault is authorized, decrypted secrets must be unreachable, not just hidden in the UI.
- **No new roadmap promises in public docs.** `docs/SPEC.md` documents shipped scope only.

## 2. Repo layout

```
Authio/
├── src/                    # Frontend (TypeScript, Vite)
│   ├── main.ts             # all UI logic (setup/lock/main, modals, drag&drop, tiles)
│   ├── api.ts              # typed Tauri command wrappers + TS interfaces
│   ├── i18n.ts             # dict flatten + fallback (lang → en → key), LANGS registry
│   ├── locales/*.json      # 9 languages; en.json is the key-structure source of truth
│   └── styles.css          # Fluent-2 token system; light(:root)/dark([data-theme]) vars
├── src-tauri/src/          # Rust core
│   ├── model.rs            # Account/Draft/Settings/Flavor + serde defaults
│   ├── otp.rs              # TOTP/HOTP + Steam 5-char rendering
│   ├── otpauth.rs          # otpauth:// parse/serialize
│   ├── crypto.rs           # AES-256-GCM, Argon2id, scrypt fallback, rand
│   ├── vault.rs            # envelope read/write (version-tolerant), KDF dispatch
│   ├── migration.rs        # old Authio formats → current
│   ├── importers.rs        # authio/aegis/authme/2fas/andotp/raivo/bitwarden/steam-mafile/otpauth
│   ├── qr.rs               # QR decode (rqrr) + content-sniffed image format
│   ├── state.rs            # AppState: session (key+accounts), settings, locks, persistence
│   ├── commands.rs         # every #[tauri::command] + DTOs
│   └── lib.rs              # builder: single-instance FIRST, dialog, tray, watchers, commands
├── src-tauri/tauri.conf.json  # window size 430×700, version, icons
├── src-tauri/Cargo.toml       # Rust deps — keep `tray-icon` feature on `tauri`
├── src-tauri/Cargo.lock       # MUST be committed (CI runs `cargo fetch --locked`)
├── docs/                      # SPEC / SECURITY / BACKUP-FORMAT / screenshot-main.png
├── .github/workflows/build.yml# the only workflow: tags v* + manual dispatch
└── HANDOFF.md                 # this file
```

## 3. Versioning & release flow

- Version lives in **three** files that must move together: `src-tauri/Cargo.toml`,
  `src-tauri/tauri.conf.json`, `package.json`. The About dialog shows it compile-time
  (`option_env!("CARGO_PKG_VERSION")` → `StatusDto.version`).
- Workflow triggers: **push of tag `v*` + manual dispatch only** (exactly one run per release).
- CI jobs: npm ci → vite/tsc → cargo tests → NSIS via tauri-action → portable zip →
  SHA-256 files → softprops release with **all four assets** (`*.exe`, `*.exe.sha256`,
  `authio-windows-portable.zip`, `*.zip.sha256`). Same-named assets are replaced on re-tag.
- Re-tag procedure (Git Bash):
  ```bash
  git tag -d v1.1.0; git push origin :refs/tags/v1.1.0
  git tag v1.1.0 && git push origin v1.1.0
  ```
  Deleting the remote tag keeps the Release object; new assets replace old ones.

## 4. Invariants to keep green (change deliberately, re-run everything)

- **Memory hygiene**: keys/secrets are `Zeroizing`; wiped on lock; never logged.
- **Envelope format**: header = version + KDF + cipher params (see BACKUP-FORMAT.md).
  Readers must stay version-tolerant; writers bump `vault::FORMAT_VERSION` + add a `migration.rs` arm.
- **Settings**: every new field gets `#[serde(default = "...")]` **and** a matching entry in
  `impl Default for Settings` — otherwise old vaults fail to open *and* `get_settings` breaks
  (this class of bug has cost a full CI cycle; see §7 lessons).
- **i18n**: every new UI string goes in **all 9 locales** with identical placeholders; run the
  key-parity QA (flatten each JSON, diff key sets vs `en.json`, compare `{...}` sets).
- **Importers**: one module branch + independent test per format, in `importers.rs`.
- **Single instance** plugin stays **first** in `tauri::Builder`.

## 5. How to build & test (complete recipe)

```bash
# Frontend
npm ci
npx tsc --noEmit        # strict TS gate
npm run build           # vite bundle check

# Rust logic unit tests WITHOUT Tauri (fast, dependency-light):
mkdir rustcheck && cd rustcheck && cargo init --lib
#   Cargo.toml deps: serde, serde_json, zeroize, data-encoding, base64,
#   aes-gcm, argon2, scrypt, hmac, sha1, sha2, getrandom
cp ../src-tauri/src/{model,otp,otpauth,crypto,migration,importers,vault}.rs src/
#   + make src/lib.rs re-export them; run: cargo test

# Rust parse/type smoke for the WHOLE crate incl. Tauri-coupled files
# (tauri unresolved-imports are expected noise — look for anything else):
cd src-tauri && rustc --edition 2021 --crate-type lib src/lib.rs -o /tmp/smoke.rlib

# Full app build (needs Windows/WebView2 for a real run):
npm run build && cd src-tauri && cargo build --release  # or tauri build
```

Expected bars: all rustcheck tests pass (29/29 at handoff), smoke shows **no** non-import errors,
tsc clean, vite clean.

## 6. Screenshots without a Windows box (docs pipeline)

Render the real frontend headlessly: build dist, inject a mock `window.__TAURI_INTERNALS__.invoke`
returning demo data (`vault_status`, `get_settings`, `list_accounts`, `get_codes`), serve the
folder, screenshot with Chromium headless shell (`--force-device-scale-factor=2
--window-size=430,700 --virtual-time-budget=6000 --screenshot=...`). Fonts fall back off-Windows;
layout/colors are exact. This pipeline has already caught real bugs (missing i18n keys,
tiles layout) — use it as a visual QA gate.

## 7. Hard-won lessons (don't re-step the same rakes)

1. `TrayIconBuilder` has **no** `.visible()` on the pinned `tray-icon`; build, then `tray.set_visible()`.
2. `Zeroizing<[u8;32]>.clone()` resolves through `Deref` and yields the inner array → use `Zeroizing::new(*s.key)` for explicit snapshots.
3. Sequential edits inside one struct literal → duplicate-field E0062 / stray braces; re-read the literal after editing.
4. `DraftIn`/DTO fields must actually be **declared** (E0609 was hidden behind a syntax error for a whole cycle).
5. `image::open` guesses format by **extension** → fake `.png`s died with "invalid png signature"; always `ImageReader::open(..)?.with_guessed_format()?`.
6. Re-run unit tests after touching `model.rs`'s `Settings` — new fields break `Default`, `get_settings`, and the TS interface simultaneously.
7. WebView2 honors `color-scheme` — set it per theme or dropdowns stay blinding white in dark mode.
8. `cmd /C start <url>` flashes a console window → use `explorer.exe <url>` for quiet browser opens.
9. Hidden window ≠ minimized: the lock watcher must check `!is_visible()` too, or hide-to-tray skips locking.
10. "Hide all codes": `refresh()` must hide only **newly appeared** ids, or either new accounts show, or revealed ones re-hide.
11. Tiles: fix card height on the **card** (`height:118px`), not `grid-auto-rows` (that also stretches label tracks to 118px).
12. Release asset step must list `nsis/*.exe` itself — one broken release shipped only its `.sha256`.
13. **Never delete the destination before `rename`** — `std::fs::rename` already replaces on Windows. `vault::recover_vault` self-heals from `.tmp`/`.bak` at startup; the `.bak` is only refreshed from an *intact* vault.
14. Anything that reads KDF params from a file must go through `crypto::argon2id_derive`/`scrypt_derive` (they enforce ceilings). Protobuf lengths: use `checked_add`.
15. Dialogs/menus live on `<body>`, not `#app` — `setRoute()` removes them when leaving `main`; keep it that way for any new overlay.
16. Heavy KDF commands are `#[tauri::command(async)]` so Argon2 never freezes the UI thread.
17. Google-migration protobuf: field keys are `0x20/0x28/0x30` (wire 0) for algorithm/digits/type — an older test used wrong keys and only passed because the parser was lax.
18. Key handling lives behind the `KeyStore` trait (`keystore.rs`); `setup_vault_inner` / `unlock_inner` / `change_unlock_mode_inner` are unit-tested with an in-memory store. Never write `keyring::Entry` calls directly; never reuse a key across unlock methods; never delete the legacy `vault-key` entry (other instances may depend on it).
19. GitHub Actions: commit `Cargo.lock`; keep workflow triggers tag-only; use `--force-with-lease`, never `--force`, when rewriting divergence.

## 8. Extending

**Add a language**: copy `src/locales/en.json` → `<code>.json`; translate every value;
add file import + dict entry + `LANGS` item in `src/i18n.ts`; run key-parity QA; done.
Persian + RTL needs CSS logical properties + mirrored directional icons (planned idea, not spec).

**Add an importer**: implement `import_<fmt>(…)-> ImportOutcome` in `importers.rs`,
add a detector branch in `parse_text` via shape sniffing (never extension),
add ≥3 tests (happy path, junk input, duplicate handling) in the scratch crate.

**Add a Tauri command**: declare in `commands.rs`, register in `lib.rs`
(`tauri::generate_handler!`), wrap in `api.ts`, type the DTO on both sides.

## 9. Open items (not public roadmap — internal candidates)

- Windows Hello unlock (fourth method) — OS credential APIs.
- Webcam QR scan — reuses `rqrr`.
- Persian (Farsi) + full RTL.
- Configurable Argon2id params, login-attempt throttling.
- Local-first encrypted sync via user-owned folder (hard; conflicts/tombstones).

## 10. Known quirks of the AI-agent dev environment

If an AI agent works on this repo inside a sandboxes: toolchain installs (Rust, npm packages,
system libs, Playwright browsers) do **not** persist across sessions — reinstall first.
`.git/config` is wiped (re-`git config user.name/email` before committing). Snapshot restores
can drop recent *commits* while keeping the working tree — the **filesystem** is the source of
truth, not `git log`. Always commit and `git archive` the ZIP in the same session.
