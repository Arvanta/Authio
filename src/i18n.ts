/**
 * Minimal i18n: English is the single source of truth for v1.0.
 * All UI strings live in `locales/en.json`; future languages only add a file
 * and switch the imported module — no code changes.
 */
import en from "./locales/en.json";

type Dict = Record<string, unknown>;
const dict = en as Dict;

export function t(key: string, vars?: Record<string, string | number>): string {
  let node: unknown = dict;
  for (const part of key.split(".")) {
    if (node && typeof node === "object" && part in (node as Dict)) {
      node = (node as Dict)[part];
    } else {
      return key; // missing translation → render the key (visible in dev)
    }
  }
  let text = typeof node === "string" ? node : key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      text = text.replaceAll(`{${k}}`, String(v));
    }
  }
  return text;
}
