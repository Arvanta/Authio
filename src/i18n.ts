/**
 * i18n: English stays the single source of truth; the other languages mirror
 * its exact key structure in their own files. Missing keys fall back to
 * English, then to the key itself (visible in dev).
 *
 * The JSON may mix nested objects and dotted keys; everything is flattened to
 * dot-joined paths at load, so both `"a": {"b": "x"}` and `"a.b": "x"` resolve
 * for t("a.b") — and a key may be a leaf AND a parent at the same time
 * (e.g. "settings.theme" plus "settings.theme.system").
 *
 * The active language mirrors the vault's persisted settings.lang
 * (src-tauri Settings); before any vault exists the localStorage mirror
 * ("authio-lang") gives the setup/lock screens the right language on boot.
 */
import en from "./locales/en.json";
import de from "./locales/de.json";
import es from "./locales/es.json";
import fr from "./locales/fr.json";
import ja from "./locales/ja.json";
import ko from "./locales/ko.json";
import pt from "./locales/pt.json";
import ru from "./locales/ru.json";
import zhCN from "./locales/zh-CN.json";

type Dict = Record<string, unknown>;

function flatten(node: unknown, prefix: string, out: Record<string, string>) {
  if (typeof node === "string") {
    out[prefix] = node;
    return;
  }
  if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node as Dict)) {
      flatten(v, prefix ? `${prefix}.${k}` : k, out);
    }
  }
}

function flatOf(node: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  flatten(node, "", out);
  return out;
}

/** Languages shown in Settings → Language. `name` is written in the language itself. */
export const LANGS: { code: string; name: string }[] = [
  { code: "en", name: "English" },
  { code: "de", name: "Deutsch" },
  { code: "es", name: "Español" },
  { code: "fr", name: "Français" },
  { code: "ja", name: "日本語" },
  { code: "ko", name: "한국어" },
  { code: "pt", name: "Português" },
  { code: "ru", name: "Русский" },
  { code: "zh-CN", name: "简体中文" },
];

const dicts: Record<string, Record<string, string>> = {
  en: flatOf(en),
  de: flatOf(de),
  es: flatOf(es),
  fr: flatOf(fr),
  ja: flatOf(ja),
  ko: flatOf(ko),
  pt: flatOf(pt),
  ru: flatOf(ru),
  "zh-CN": flatOf(zhCN),
};

let currentCode = "en";
let current = dicts.en;

const LS_KEY = "authio-lang";

export function setLang(code: string) {
  const dict = dicts[code];
  currentCode = dict ? code : "en";
  current = dict ?? dicts.en;
  document.documentElement.lang = currentCode;
  try {
    localStorage.setItem(LS_KEY, currentCode);
  } catch {
    /* storage may be unavailable — harmless */
  }
}

/** Language chosen before any vault/settings exist (localStorage mirror). */
export function getBootLang(): string {
  try {
    return localStorage.getItem(LS_KEY) ?? "en";
  } catch {
    return "en";
  }
}

export function t(key: string, vars?: Record<string, string | number>): string {
  let text = current[key] ?? dicts.en[key] ?? key; // fallback chain: lang → en → key
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      text = text.replaceAll(`{${k}}`, String(v));
    }
  }
  return text;
}

// Paint the very first screen (setup/lock) in the remembered language.
setLang(getBootLang());
