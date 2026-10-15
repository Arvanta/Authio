/**
 * Minimal i18n: English is the single source of truth for v1.0.
 * All UI strings live in `locales/en.json`; future languages only add a file
 * and switch the imported module — no code changes.
 *
 * The JSON may mix nested objects and dotted keys; everything is flattened to
 * dot-joined paths at load, so both `"a": {"b": "x"}` and `"a.b": "x"` resolve
 * for t("a.b") — and a key may be a leaf AND a parent at the same time
 * (e.g. "settings.theme" plus "settings.theme.system").
 */
import en from "./locales/en.json";

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

const strings: Record<string, string> = {};
flatten(en, "", strings);

export function t(key: string, vars?: Record<string, string | number>): string {
  let text = strings[key] ?? key; // missing translation → render the key (visible in dev)
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      text = text.replaceAll(`{${k}}`, String(v));
    }
  }
  return text;
}
