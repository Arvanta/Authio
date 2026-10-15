/** Typed wrappers around the Tauri command surface (see src-tauri/src/commands.rs). */
import { invoke } from "@tauri-apps/api/core";

export type UnlockMode = "password" | "keychain" | "none";

export interface AccountDto {
  id: string;
  issuer: string;
  name: string;
  group: string; // "" = ungrouped
  pinned: boolean;
  sort: number;
  kind: "totp" | "hotp" | string;
  algorithm: string;
  digits: number;
  period: number;
  counter: number;
}

export interface CodeDto {
  id: string;
  code: string | null;
  remaining: number;
  progress: number;
}

export interface StatusDto {
  initialized: boolean;
  unlocked: boolean;
  mode: UnlockMode | null;
}

export interface PreviewEntry {
  index: number;
  issuer: string;
  name: string;
  kind: string;
  algorithm: string;
  digits: number;
  period: number;
  duplicate: boolean;
}

export interface PreviewDto {
  format: string;
  needs_password: boolean;
  skipped: number;
  entries: PreviewEntry[];
}

export interface SecretDto {
  secret: string;
  uri: string;
}

export interface Settings {
  theme: "system" | "light" | "dark" | string;
  density: "compact" | "comfortable" | string;
  font_scale: number;
  sort_alpha: boolean;
  hide_codes: boolean;
  auto_lock_minutes: number;
  lock_on_minimize: boolean;
  view_mode: "rows" | "tiles" | string;
  show_timer_number: boolean;
  grouped_view: boolean;
  tray: boolean;
  window?: { x: number; y: number; w: number; h: number } | null;
}

export interface DraftIn {
  issuer: string;
  name: string;
  secret: string;
  group?: string;
  algorithm?: string;
  digits?: number;
  period?: number;
  kind?: "totp" | "hotp";
  counter?: number;
}

export const api = {
  status: () => invoke<StatusDto>("vault_status"),
  setupVault: (mode: UnlockMode, password?: string) =>
    invoke<void>("setup_vault", { mode, password: password ?? null }),
  unlock: (password?: string) => invoke<void>("unlock", { password: password ?? null }),
  lock: () => invoke<void>("lock"),
  changeUnlockMode: (mode: UnlockMode, currentPassword?: string, newPassword?: string) =>
    invoke<void>("change_unlock_mode", {
      mode,
      currentPassword: currentPassword ?? null,
      newPassword: newPassword ?? null,
    }),

  listAccounts: () => invoke<AccountDto[]>("list_accounts"),
  getCodes: () => invoke<CodeDto[]>("get_codes"),
  hotpNext: (id: string) => invoke<CodeDto>("hotp_next", { id }),
  addAccount: (draft: DraftIn) => invoke<AccountDto>("add_account", { draft }),
  addFromUri: (uri: string) => invoke<AccountDto[]>("add_from_uri", { uri }),
  updateAccount: (id: string, issuer: string, name: string, group: string) =>
    invoke<void>("update_account", { id, issuer, name, group }),
  deleteAccount: (id: string) => invoke<void>("delete_account", { id }),
  setPinned: (id: string, pinned: boolean) => invoke<void>("set_pinned", { id, pinned }),
  reorder: (ids: string[]) => invoke<void>("reorder", { ids }),
  revealSecret: (id: string, password?: string) =>
    invoke<SecretDto>("reveal_secret", { id, password: password ?? null }),

  exportBackup: (path: string, encrypted: boolean, password: string | null, masterPassword: string | null) =>
    invoke<string>("export_backup", { path, encrypted, password, masterPassword }),

  importFile: (path: string, password: string | null) => invoke<PreviewDto>("import_file", { path, password }),
  importText: (text: string, password: string | null) => invoke<PreviewDto>("import_text", { text, password }),
  importQr: (path: string) => invoke<PreviewDto>("import_qr", { path }),
  importApply: (indices: number[]) => invoke<AccountDto[]>("import_apply", { indices }),

  getSettings: () => invoke<Settings>("get_settings"),
  setSettings: (settings: Settings) => invoke<void>("set_settings", { settings }),
  userActivity: () => invoke<void>("user_activity"),
};

/** Storage key for UI-only ephemeral preferences (never secrets). */
export const UI_PREFS_KEY = "authio.ui";
