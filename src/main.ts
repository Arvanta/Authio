/**
 * Authio UI — framework-free TypeScript.
 * The UI only ever handles codes and metadata; raw secrets never cross IPC
 * except inside the reveal-secret dialog (which re-authenticates) and exports.
 */
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { AccountDto, CodeDto, PreviewDto, Settings, StatusDto, UnlockMode, api } from "./api";
import { t, setLang, getBootLang, LANGS } from "./i18n";
import "./styles.css";

/* ------------------------------------------------------------------ icons */
const ICONS = {
  shield:
    '<path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z"/><circle cx="12" cy="10.5" r="1.8"/><path d="M12 12.3v3.7"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  lock: '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  gear:
    '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9 17 7M7 17l-2.1 2.1"/>',
  upload: '<path d="M12 15V3m0 0L8 7m4-4 4 4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>',
  download:
    '<path d="M12 3v10m0 0L8 9m4 4 4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff:
    '<path d="M3 3l18 18"/><path d="M10.6 5.1A10.8 10.8 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-2.2 3.1M6.6 6.6A16.9 16.9 0 0 0 2 12s3.5 7 10 7a9.8 9.8 0 0 0 2.2-.3"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  star: '<path d="M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z"/>',
  pencil: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
  key: '<path d="M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 0-7.9 7.9 5.5 5.5 0 0 0 7.9-7.9Zm0 0L19 4m-4.5 1.5L17 8"/>',
  trash:
    '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>',
  qr: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM21 14v3M14 21h3M18 18h3v3"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  mag: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  alert:
    '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0ZM12 9v4m0 4h.01"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M4 6h.01M4 12h.01M4 18h.01"/>',
  grid: '<rect x="3" y="3" width="7.5" height="7.5" rx="1.5"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5"/>',
  kebab: '<circle cx="12" cy="5" r="1.5" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="12" cy="19" r="1.5" fill="currentColor" stroke="none"/>',
  layers: '<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>',
  linkExt:
    '<path d="M14 4h6v6"/><path d="M20 4 10 14"/><path d="M20 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h5"/>',
  heart:
    '<path d="M12 20.3C7 16.8 3.5 13.6 3.5 9.9A4.6 4.6 0 0 1 8 5.3c1.7 0 3.2.8 4 2.2a4.9 4.9 0 0 1 4-2.2 4.6 4.6 0 0 1 4.5 4.6c0 3.7-3.5 6.9-8.5 10.4Z"/>',
} as const;
type IconName = keyof typeof ICONS;

/* --------------------------------------------------------------- dom infra */
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function icon(name: IconName, cls?: string): SVGSVGElement {
  const w = document.createElement("div");
  w.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;
  const s = w.firstElementChild as unknown as SVGSVGElement;
  if (cls) s.setAttribute("class", cls);
  return s;
}

function iconBtn(name: IconName, title: string, cls = ""): HTMLButtonElement {
  const b = el("button", `iconbtn ${cls}`.trim());
  b.title = title;
  b.append(icon(name));
  return b;
}

function toast(msg: string, isErr = false) {
  let host = document.querySelector<HTMLElement>(".toasts");
  if (!host) {
    host = el("div", "toasts");
    document.body.append(host);
  }
  const tEl = el("div", `toast${isErr ? " err" : ""}`, msg);
  host.append(tEl);
  setTimeout(() => tEl.remove(), 2600);
}

interface ModalHandle {
  close(): void;
  body: HTMLElement;
  modal: HTMLElement;
}

function openModal(title: string, closable = true): ModalHandle {
  const overlay = el("div", "overlay");
  const modal = el("div", "modal");
  const head = el("div", "mhead");
  head.append(el("h2", "", title));
  const body = el("div", "mbody");
  modal.append(head, body);
  overlay.append(modal);
  const h: ModalHandle = { close: () => overlay.remove(), body, modal };
  if (closable) {
    const x = iconBtn("x", t("common.close"));
    x.onclick = () => h.close();
    head.append(x);
  }
  overlay.addEventListener("pointerdown", (e) => {
    if (e.target === overlay && closable) h.close();
  });
  document.body.append(overlay);
  return h;
}

function footer(...buttons: HTMLButtonElement[]): HTMLElement {
  const f = el("div", "mfoot");
  f.append(...buttons);
  return f;
}

async function confirmBox(
  title: string,
  msg: string,
  confirmText: string,
  danger = false,
): Promise<boolean> {
  return new Promise((resolve) => {
    const h = openModal(title);
    h.body.append(el("p", "hint", msg));
    const no = el("button", "btn", t("common.cancel"));
    const yes = el("button", `btn${danger ? " danger" : " primary"}`, confirmText);
    no.onclick = () => {
      h.close();
      resolve(false);
    };
    yes.onclick = () => {
      h.close();
      resolve(true);
    };
    h.modal.append(footer(no, yes));
    yes.focus();
  });
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = el("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.append(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      return true;
    } catch {
      return false;
    }
  }
}

function field(labelText: string, input: HTMLElement): HTMLElement {
  const wrap = el("div");
  wrap.append(el("label", "lbl", labelText), input);
  return wrap;
}

function fmtError(e: unknown): string {
  const s = typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
  return s.replace(/^error invoking .*?:/i, "").trim() || t("common.error");
}

/* --------------------------------------------------------------- app state */
type Route = "setup" | "lock" | "main";
let route: Route = "lock";
let statusInfo: StatusDto | null = null;
let settings: Settings = {
  theme: "system",
  density: "compact",
  font_scale: 100,
  sort_alpha: false,
  hide_codes: true,
  auto_lock_minutes: 5,
  lock_on_minimize: true,
  lang: "en",
  view_mode: "rows",
  show_timer_number: true,
  grouped_view: false,
  tray: true,
};
let accounts: AccountDto[] = [];
let search = "";
let groupFilter = "ALL"; // "ALL" | "__none__" | group name
let groupSelEl: HTMLSelectElement | null = null;
const hidden = new Set<string>();
const lastHotp = new Map<string, { code: string; until: number }>();
const tickRefs = new Map<
  string,
  { code: HTMLElement; remain: HTMLElement | null; fill: SVGCircleElement | null; dots: boolean }
>();

const app = document.getElementById("app")!;
const mediaDark = matchMedia("(prefers-color-scheme: dark)");

function applyVisualSettings() {
  const sys = mediaDark.matches ? "dark" : "light";
  document.documentElement.dataset.theme = settings.theme === "system" ? sys : settings.theme;
  document.body.dataset.density = settings.density;
  document.documentElement.style.setProperty("--font-scale", String(settings.font_scale / 100));
}
mediaDark.addEventListener("change", () => {
  if (settings.theme === "system") applyVisualSettings();
});

// Keep the backend idle-timer in sync with real user activity (throttled).
let lastPing = 0;
for (const ev of ["pointerdown", "keydown"] as const) {
  window.addEventListener(
    ev,
    () => {
      const n = Date.now();
      if (n - lastPing > 4000 && route === "main") {
        lastPing = n;
        api.userActivity().catch(() => undefined);
      }
    },
    { passive: true },
  );
}

/* ---------------------------------------------------------------- routing */
function setRoute(r: Route) {
  route = r;
  app.innerHTML = "";
}

async function refreshStatus(): Promise<StatusDto> {
  statusInfo = await api.status();
  return statusInfo;
}

/* ------------------------------------------------------------------ setup */
function renderSetup() {
  setRoute("setup");
  const screen = el("div", "center-screen");
  const panel = el("div", "panel");

  const brand = el("div", "brand");
  const logo = el("div", "logo");
  logo.append(icon("shield"));
  brand.append(logo, el("h1", "", t("app.name")));
  panel.append(brand, el("h2", "", ""), el("p", "sub", t("setup.intro")));

  const h2 = panel.querySelector("h2")!;
  h2.textContent = t("setup.title");
  h2.style.cssText = "font-size:16px;margin-bottom:6px";

  let mode: UnlockMode = "password";
  const cards = el("div", "mode-cards");
  const mkCard = (m: typeof mode, title: string, desc: string, ic: IconName) => {
    const c = el("button", "mode-card");
    c.type = "button";
    const tl = el("div", "t");
    tl.append(icon(ic), document.createTextNode(title));
    c.append(tl, el("div", "d", desc));
    c.onclick = () => {
      mode = m;
      cards.querySelectorAll(".mode-card").forEach((n) => n.classList.toggle("sel", n === c));
      pwWrap.style.display = m === "password" ? "" : "none";
    };
    return c;
  };
  const cPw = mkCard("password", t("setup.mode.password"), t("setup.mode.password.desc"), "key");
  const cKc = mkCard("keychain", t("setup.mode.keychain"), t("setup.mode.keychain.desc"), "shield");
  const cNone = mkCard("none", t("setup.mode.none"), t("setup.mode.none.desc"), "alert");
  cards.append(cPw, cKc, cNone);
  cPw.classList.add("sel");

  const pw1 = el("input") as HTMLInputElement;
  pw1.type = "password";
  pw1.placeholder = t("setup.password");
  const pw2 = el("input") as HTMLInputElement;
  pw2.type = "password";
  pw2.placeholder = t("setup.confirm");
  const pwWrap = el("div");
  pwWrap.append(field("", pw1), field("", pw2));
  (pwWrap.querySelectorAll("label") as NodeListOf<HTMLElement>).forEach((l) => l.remove());

  const err = el("div", "errline");
  const go = el("button", "btn primary block", t("setup.create"));
  go.onclick = async () => {
    err.textContent = "";
    if (mode === "password") {
      if (pw1.value.length < 8) {
        err.textContent = t("setup.password");
        return;
      }
      if (pw1.value !== pw2.value) {
        err.textContent = t("setup.mismatch");
        return;
      }
    }
    go.disabled = true;
    go.textContent = t("setup.creating");
    try {
      await api.setupVault(mode, mode === "password" ? pw1.value : undefined);
      pw1.value = pw2.value = "";
      // Refresh status so the UI (settings security section, lock screen)
      // immediately knows the freshly chosen unlock mode.
      await refreshStatus();
      await enterMain();
    } catch (e) {
      err.textContent = fmtError(e);
      go.disabled = false;
      go.textContent = t("setup.create");
    }
  };

  panel.append(cards, pwWrap, err, go);
  screen.append(panel);
  app.append(screen);
}

/* ------------------------------------------------------------------- lock */
function renderLock(auto = false) {
  setRoute("lock");
  tickRefs.clear();
  const screen = el("div", "center-screen");
  const panel = el("div", "panel slim");

  const brand = el("div", "brand");
  const logo = el("div", "logo");
  logo.append(icon("shield"));
  brand.append(logo, el("h1", "", t("app.name")));
  panel.append(brand);
  const h2 = el("h2", "", t("lock.title"));
  h2.style.cssText = "font-size:16px;margin-bottom:4px";
  panel.append(h2);

  const mode = statusInfo?.mode ?? "password";
  panel.append(
    el(
      "p",
      "sub",
      mode === "password"
        ? t("lock.subtitle.password")
        : mode === "keychain"
          ? t("lock.subtitle.keychain")
          : t("lock.subtitle.none"),
    ),
  );
  if (auto) {
    const b = el("div", "banner");
    b.append(icon("lock"), document.createTextNode(t("lock.auto")));
    panel.append(b);
  }

  const err = el("div", "errline");
  const form = el("form");
  form.onsubmit = async (e) => {
    e.preventDefault();
    err.textContent = "";
    const pw = input.value;
    try {
      await api.unlock(mode === "password" ? pw : undefined);
      input.value = "";
      await enterMain();
    } catch (ex) {
      err.textContent = fmtError(ex);
    }
  };

  const input = el("input") as HTMLInputElement;
  input.type = "password";
  input.placeholder = t("lock.password");
  input.autocomplete = "current-password";

  const go = el("button", "btn primary block", t("lock.unlock"));
  go.type = "submit";

  if (mode === "password") form.append(input, go);
  else form.append(go);
  panel.append(form, err);
  screen.append(panel);
  app.append(screen);
  if (mode === "password") input.focus();
}

/* ------------------------------------------------------------------- main */
async function enterMain() {
  accounts = await api.listAccounts();
  hidden.clear();
  if (settings.hide_codes) for (const a of accounts) hidden.add(a.id);
  lastHotp.clear();
  renderMain();
  void pollCodes();
}

/** Accounts after the search query and the group filter are applied. */
function filteredList(): AccountDto[] {
  const q = search.trim().toLowerCase();
  let list = accounts;
  if (q) list = list.filter((a) => `${a.issuer} ${a.name}`.toLowerCase().includes(q));
  if (groupFilter === "__none__") list = list.filter((a) => !a.group);
  else if (groupFilter !== "ALL") list = list.filter((a) => a.group === groupFilter);
  return list;
}

/** Shared comparator: alphabetical in alpha mode, manual order otherwise. */
function baseCmp(): (x: AccountDto, y: AccountDto) => number {
  return settings.sort_alpha
    ? (x, y) => (x.issuer || x.name).localeCompare(y.issuer || y.name) || x.name.localeCompare(y.name)
    : (x, y) => x.sort - y.sort;
}

function avatarColor(key: string): string {
  let h = 0;
  for (const ch of key) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  const hue = h % 360;
  return `hsl(${hue} 55% 46%)`;
}

function grouped(code: string): string {
  return code.replace(/(\d{3})(?=\d)/g, "$1 ");
}

interface MenuItem {
  icon: IconName;
  label: string;
  danger?: boolean;
  onPick: () => void;
}

let openMenuEl: (() => void) | null = null; // disposer of the currently open menu
function closeMenu() {
  openMenuEl?.();
  openMenuEl = null;
}

/** Tiny anchored dropdown menu; closes on outside click or Escape. */
function openMenu(anchor: HTMLElement, items: MenuItem[]) {
  if (openMenuEl) {
    closeMenu();
    return; // clicking the same button toggles it shut
  }
  const menu = el("div", "menu");
  for (const it of items) {
    const b = el("button", "mi" + (it.danger ? " danger" : ""));
    b.type = "button";
    b.append(icon(it.icon), document.createTextNode(it.label));
    b.onclick = (e) => {
      e.stopPropagation();
      closeMenu();
      it.onPick();
    };
    menu.append(b);
  }
  document.body.append(menu);
  const r = anchor.getBoundingClientRect();
  menu.style.top = `${Math.min(window.innerHeight - menu.offsetHeight - 8, r.bottom + 5)}px`;
  menu.style.left = `${Math.max(8, Math.min(window.innerWidth - menu.offsetWidth - 8, r.right - menu.offsetWidth))}px`;
  const onDown = (e: MouseEvent) => {
    if (!menu.contains(e.target as Node)) closeMenu();
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") closeMenu();
  };
  window.addEventListener("mousedown", onDown, true);
  window.addEventListener("keydown", onKey);
  openMenuEl = () => {
    menu.remove();
    window.removeEventListener("mousedown", onDown, true);
    window.removeEventListener("keydown", onKey);
  };
}

async function pinFlow(a: AccountDto) {
  await api.setPinned(a.id, !a.pinned);
  await refresh();
}

async function deleteAccountFlow(a: AccountDto) {
  const ok = await confirmBox(
    t("delete.title"),
    t("delete.msg", { issuer: a.issuer || "—", name: a.name }),
    t("delete.confirm"),
    true,
  );
  if (ok) {
    try {
      await api.deleteAccount(a.id);
      hidden.delete(a.id);
      toast(t("toast.deleted"));
      await refresh();
    } catch (e) {
      toast(fmtError(e), true);
    }
  }
}

function buildTimer(period: number): {
  wrap: HTMLElement;
  fill: SVGCircleElement;
  remain: HTMLElement;
} {
  const wrap = el("div", "timercol");
  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("class", "ring");
  svg.setAttribute("viewBox", "0 0 28 28");
  const mk = (cls: string) => {
    const c = document.createElementNS(svgNS, "circle");
    c.setAttribute("class", cls);
    c.setAttribute("cx", "14");
    c.setAttribute("cy", "14");
    c.setAttribute("r", "11.5");
    c.setAttribute("fill", "none");
    c.setAttribute("stroke-width", cls === "fill" ? "3" : "2.6");
    return c;
  };
  const track = mk("track");
  const fill = mk("fill") as SVGCircleElement;
  fill.setAttribute("stroke-dasharray", "72.26");
  fill.setAttribute("stroke-dashoffset", "0");
  svg.append(track, fill);
  const remain = el("span", "remain", String(period));
  if (!settings.show_timer_number) remain.style.display = "none";
  wrap.append(svg, remain);
  return { wrap, fill, remain };
}

function accountCard(a: AccountDto): HTMLElement {
  const card = el("div", "card");
  card.dataset.id = a.id;

  const avatar = el("div", "avatar", (a.issuer || a.name || "?").charAt(0).toUpperCase());
  avatar.style.background = avatarColor(a.issuer + "/" + a.name);

  const meta = el("div", "meta");
  meta.append(el("div", "issuer", a.issuer || a.name), el("div", "name", a.issuer ? a.name : ""));

  const isHotp = a.kind === "hotp";
  const code = el("span", isHotp ? "code" : "code hidden-code", isHotp ? "•••" : "••• •••");
  code.title = isHotp ? t("code.next") : t("code.reveal");

  const codecol = el("div", "codecol");

  let remain: HTMLElement | null = null;
  let fill: SVGCircleElement | null = null;
  if (!isHotp) {
    const timer = buildTimer(a.period);
    remain = timer.remain;
    fill = timer.fill;
    codecol.append(code, timer.wrap);
  } else {
    codecol.append(code);
  }

  tickRefs.set(a.id, { code, remain, fill, dots: true });

  const actions = el("div", "actions");
  const copyB = iconBtn("copy", t("code.copy"));
  copyB.onclick = async () => {
    const cur = tickRefs.get(a.id);
    const dto = await latestCode(a);
    const value = isHotp ? lastHotp.get(a.id)?.code : dto?.code ?? undefined;
    if (!value) {
      if (isHotp) await doHotp(a);
      else hidden.delete(a.id);
      void pollCodes();
      return;
    }
    const ok = await copyText(value);
    if (ok) {
      copyB.innerHTML = "";
      copyB.append(icon("check"));
      setTimeout(() => {
        copyB.innerHTML = "";
        copyB.append(icon("copy"));
      }, 1100);
      if (cur) cur.code.classList.add("copied");
      setTimeout(() => cur?.code.classList.remove("copied"), 700);
    }
  };

  code.onclick = async () => {
    if (isHotp) {
      await doHotp(a);
      return;
    }
    if (hidden.has(a.id)) {
      hidden.delete(a.id);
    } else {
      const dto = await latestCode(a);
      if (dto?.code) await copyText(dto.code);
    }
    void pollCodes();
  };

  // Kebab menu (⋮): pin + edit + reveal secret + delete live behind it.
  const kebabB = iconBtn("kebab", t("card.menu"));
  kebabB.onclick = (e) => {
    e.stopPropagation();
    openMenu(kebabB, [
      { icon: "star", label: a.pinned ? t("card.unpin") : t("card.pin"), onPick: () => void pinFlow(a) },
      { icon: "pencil", label: t("card.edit"), onPick: () => openEditModal(a) },
      { icon: "key", label: t("card.secret"), onPick: () => openRevealModal(a) },
      { icon: "trash", label: t("card.delete"), danger: true, onPick: () => void deleteAccountFlow(a) },
    ]);
  };

  // Right-edge order: timer ring → code → copy → kebab menu.
  actions.append(kebabB, copyB, codecol);

  // Drag & drop manual reorder (disabled while filtering or alpha-sorting).
  const dnd = !settings.sort_alpha && !search;
  card.draggable = dnd;
  if (dnd) {
    card.addEventListener("dragstart", (e) => {
      card.classList.add("dragging");
      e.dataTransfer?.setData("text/plain", a.id);
      e.dataTransfer?.setDragImage(card, 20, 20);
    });
    card.addEventListener("dragend", () => card.classList.remove("dragging"));
    card.addEventListener("dragover", (e) => {
      e.preventDefault();
      card.classList.add("dragover");
    });
    card.addEventListener("dragleave", () => card.classList.remove("dragover"));
    card.addEventListener("drop", async (e) => {
      e.preventDefault();
      card.classList.remove("dragover");
      const draggedId = e.dataTransfer?.getData("text/plain");
      if (!draggedId || draggedId === a.id) return;
      // Rebuild the full ordered id list: remove the dragged id, then re-insert
      // it right before the id it was dropped on.
      const all = accounts.slice().sort((x, y) => x.sort - y.sort).map((x) => x.id);
      const without = all.filter((id) => id !== draggedId);
      const idx = without.indexOf(a.id);
      if (idx === -1) return;
      without.splice(idx, 0, draggedId);
      try {
        await api.reorder(without);
        await refresh();
      } catch (err) {
        toast(fmtError(err), true);
      }
    });
  }

  card.append(avatar, meta, actions);
  return card;
}

function tileCard(a: AccountDto): HTMLElement {
  const card = el("div", "card tile");
  card.dataset.id = a.id;
  const isHotp = a.kind === "hotp";

  // Header: issuer (+ account) on the left, timer ring on the right.
  const head = el("div", "t-head");
  const iss = el("div", "t-issuer");
  iss.append(document.createTextNode(a.issuer || a.name || "?"));
  if (a.issuer && a.name) iss.append(el("span", "t-name", " / " + a.name));
  head.append(iss);

  let remain: HTMLElement | null = null;
  let fill: SVGCircleElement | null = null;
  if (!isHotp) {
    const timer = buildTimer(a.period);
    remain = timer.remain;
    fill = timer.fill;
    head.append(timer.wrap);
  }

  const code = el("div", "code t-code" + (isHotp ? "" : " hidden-code"), isHotp ? "•••" : "••• •••");
  code.title = isHotp ? t("code.next") : t("code.reveal");
  tickRefs.set(a.id, { code, remain, fill, dots: true });

  const copyB = iconBtn("copy", t("code.copy"));
  copyB.onclick = async () => {
    const dto = await latestCode(a);
    const value = isHotp ? lastHotp.get(a.id)?.code : dto?.code ?? undefined;
    if (!value) {
      if (isHotp) await doHotp(a);
      else hidden.delete(a.id);
      void pollCodes();
      return;
    }
    const ok = await copyText(value);
    if (ok) {
      copyB.innerHTML = "";
      copyB.append(icon("check"));
      setTimeout(() => {
        copyB.innerHTML = "";
        copyB.append(icon("copy"));
      }, 1100);
    }
  };

  code.onclick = async () => {
    if (isHotp) {
      await doHotp(a);
      return;
    }
    if (hidden.has(a.id)) {
      hidden.delete(a.id);
    } else {
      const dto = await latestCode(a);
      if (dto?.code) await copyText(dto.code);
    }
    void pollCodes();
  };

  const pinB = iconBtn("star", a.pinned ? t("card.unpin") : t("card.pin"));
  if (a.pinned) pinB.classList.add("on");
  pinB.onclick = () => void pinFlow(a);

  const editB = iconBtn("pencil", t("card.edit"), "ghost");
  editB.onclick = () => openEditModal(a);
  const secretB = iconBtn("key", t("card.secret"), "ghost");
  secretB.onclick = () => openRevealModal(a);
  const delB = iconBtn("trash", t("card.delete"), "ghost");
  delB.onclick = () => void deleteAccountFlow(a);

  const foot = el("div", "t-foot actions");
  foot.append(editB, secretB, delB, el("div", "spacer"), pinB, copyB);

  card.append(head, code, foot);
  return card;
}

async function doHotp(a: AccountDto) {
  try {
    const dto = await api.hotpNext(a.id);
    if (dto.code) lastHotp.set(a.id, { code: dto.code, until: Date.now() + 30000 });
    void pollCodes();
  } catch (e) {
    toast(fmtError(e), true);
  }
}

const codeCache = new Map<string, CodeDto>();

async function latestCode(a: AccountDto): Promise<CodeDto | undefined> {
  return codeCache.get(a.id);
}

function applyCodes(codes: CodeDto[]) {
  codeCache.clear();
  for (const dto of codes) codeCache.set(dto.id, dto);
  for (const dto of codes) {
    const ref = tickRefs.get(dto.id);
    const acc = accounts.find((x) => x.id === dto.id);
    if (!ref || !acc) continue;
    if (acc.kind === "hotp") {
      const hp = lastHotp.get(dto.id);
      if (hp && hp.until > Date.now()) {
        ref.code.textContent = grouped(hp.code);
        ref.code.classList.remove("hidden-code");
      } else {
        ref.code.textContent = "•••";
        ref.code.title = t("code.next");
        ref.code.classList.add("hidden-code");
      }
      continue;
    }
    if (!dto.code) continue;
    if (hidden.has(dto.id)) {
      ref.code.textContent = "•".repeat(acc.digits).replace(/(.{3})(?=.)/g, "$1 ");
      ref.code.classList.add("hidden-code");
      ref.code.title = t("code.reveal");
    } else {
      ref.code.textContent = grouped(dto.code);
      ref.code.classList.remove("hidden-code");
      ref.code.title = t("code.copy");
    }
    if (ref.fill) {
      ref.fill.style.strokeDashoffset = String(72.26 * (1 - dto.progress));
      ref.fill.style.stroke = dto.remaining <= 5 ? "var(--danger)" : "";
    }
    if (ref.remain) ref.remain.textContent = String(dto.remaining);
  }
}

async function pollCodes() {
  if (route !== "main") return;
  try {
    applyCodes(await api.getCodes());
  } catch (e) {
    if (fmtError(e).includes("locked")) {
      await refreshStatus();
      renderLock(true);
    }
  }
}

async function refresh() {
  const known = new Set(accounts.map((a) => a.id));
  accounts = await api.listAccounts();
  // "Hide codes until revealed" must stay consistent: accounts added after the
  // toggle start hidden; accounts the user already revealed stay revealed.
  if (settings.hide_codes) for (const a of accounts) if (!known.has(a.id)) hidden.add(a.id);
  renderList();
  void pollCodes();
}

let listHost: HTMLElement;

function renderList() {
  tickRefs.clear();
  const tiles = settings.view_mode === "tiles";
  listHost.classList.toggle("tiles", tiles);
  listHost.innerHTML = "";

  // Rebuild the topbar group filter, preserving the current selection.
  if (groupSelEl) {
    const groupNames = [...new Set(accounts.map((a) => a.group).filter((g) => g))].sort((x, y) =>
      x.localeCompare(y),
    );
    groupSelEl.innerHTML = "";
    groupSelEl.append(new Option(t("group.all"), "ALL"));
    for (const g of groupNames) groupSelEl.append(new Option(g, g));
    if (accounts.some((a) => !a.group)) groupSelEl.append(new Option(t("group.ungrouped"), "__none__"));
    groupSelEl.style.display = groupNames.length === 0 ? "none" : "";
    if ([...groupSelEl.options].some((o) => o.value === groupFilter)) {
      groupSelEl.value = groupFilter;
    } else {
      groupFilter = groupSelEl.value = "ALL";
    }
  }

  if (accounts.length === 0) {
    const empty = el("div", "empty");
    const big = el("div", "big");
    big.append(icon("shield"));
    empty.append(big, el("h3", "", t("main.empty.title")), el("p", "", t("main.empty.hint")));
    listHost.append(empty);
    return;
  }
  const list = filteredList();
  const mkCard = tiles ? tileCard : accountCard;
  if (list.length === 0) {
    const empty = el("div", "empty");
    empty.append(el("p", "", t("main.none")));
    listHost.append(empty);
    return;
  }
  const cmp = baseCmp();

  if (settings.grouped_view) {
    // Sections per group (alphabetical), ungrouped last; pinned first within a group.
    const groups = [...new Set(list.map((a) => a.group))].sort((x, y) =>
      x === "" ? 1 : y === "" ? -1 : x.localeCompare(y),
    );
    for (const g of groups) {
      const items = list
        .filter((a) => a.group === g)
        .sort((x, y) => Number(y.pinned) - Number(x.pinned) || cmp(x, y));
      listHost.append(el("div", "section-label", g || t("group.ungrouped")));
      items.forEach((a) => listHost.append(mkCard(a)));
    }
    return;
  }

  const pinned = list.filter((a) => a.pinned).sort(cmp);
  const rest = list.filter((a) => !a.pinned).sort(cmp);
  if (pinned.length) {
    listHost.append(el("div", "section-label", t("main.pinned")));
    pinned.forEach((a) => listHost.append(mkCard(a)));
    if (rest.length) listHost.append(el("div", "section-label", t("main.accounts")));
  }
  rest.forEach((a) => listHost.append(mkCard(a)));
}

function renderMain() {
  setRoute("main");

  // --- top bar: search on the left, actions on the right (no duplicate brand —
  // the window title already says "Authio").
  const top = el("div", "topbar");

  const sinput = el("input") as HTMLInputElement;
  sinput.type = "search";
  sinput.placeholder = t("main.search");
  sinput.value = search;
  sinput.oninput = () => {
    search = sinput.value;
    renderList();
    void pollCodes();
  };
  const sbox = el("div", "searchin");
  sbox.append(sinput, icon("mag", "mag"));

  const eyeAll = iconBtn(settings.hide_codes ? "eyeOff" : "eye", t("main.showall"));
  eyeAll.onclick = () => {
    if (settings.hide_codes) {
      settings.hide_codes = false;
      hidden.clear();
      eyeAll.title = t("main.hideall");
    } else {
      settings.hide_codes = true;
      accounts.forEach((a) => hidden.add(a.id));
      eyeAll.title = t("main.showall");
    }
    eyeAll.innerHTML = "";
    eyeAll.append(icon(settings.hide_codes ? "eyeOff" : "eye"));
    void api.setSettings(settings).catch(() => undefined);
    renderList();
    void pollCodes();
  };

  const addB = iconBtn("plus", t("main.add"));
  addB.style.color = "var(--accent)";
  addB.onclick = () => openAddModal();

  // Group filter dropdown (rebuilt in renderList).
  const gsel = el("select", "gsel") as HTMLSelectElement;
  gsel.title = t("main.filter_group");
  gsel.onchange = () => {
    groupFilter = gsel.value;
    renderList();
    void pollCodes();
  };
  groupSelEl = gsel;

  // Grouped-view toggle (default order vs. grouped sections).
  const groupB = iconBtn("layers", t("main.grouped"));
  if (settings.grouped_view) groupB.classList.add("on");
  groupB.onclick = async () => {
    settings.grouped_view = !settings.grouped_view;
    groupB.classList.toggle("on", settings.grouped_view);
    try {
      await api.setSettings({ ...settings });
    } catch {
      /* keep local state */
    }
    renderList();
    void pollCodes();
  };

  const gearB = iconBtn("gear", t("main.settings"));
  gearB.onclick = () => openSettingsModal();

  const lockB = iconBtn("lock", t("main.lock"));
  lockB.onclick = async () => {
    await api.lock().catch(() => undefined);
    await refreshStatus();
    renderLock();
  };

  // View toggle: shows the icon of the style you will switch to.
  const viewB = iconBtn(settings.view_mode === "tiles" ? "list" : "grid", t("main.view"));
  viewB.onclick = async () => {
    settings.view_mode = settings.view_mode === "tiles" ? "rows" : "tiles";
    viewB.innerHTML = "";
    viewB.append(icon(settings.view_mode === "tiles" ? "list" : "grid"));
    try {
      await api.setSettings({ ...settings });
    } catch {
      /* keep local state */
    }
    renderList();
    void pollCodes();
  };

  top.append(sbox, gsel, groupB, viewB, eyeAll, addB, gearB, lockB);

  listHost = el("div", "list");
  app.append(top, listHost);
  renderList();
}

/* --------------------------------------------------------------- add modal */
function openAddModal() {
  const h = openModal(t("add.title"));
  const tabs = el("div", "tabs");
  const content = el("div");
  h.body.append(tabs, content);

  type TabId = "qr" | "uri" | "manual";
  const mkTabBtn = (id: TabId, label: string) => {
    const b = el("button", "tab", label);
    b.type = "button";
    b.onclick = () => {
      tabs.querySelectorAll(".tab").forEach((n) => n.classList.toggle("sel", n === b));
      show(id);
    };
    return b;
  };
  const bQr = mkTabBtn("qr", t("add.tab.qr"));
  const bUri = mkTabBtn("uri", t("add.tab.uri"));
  const bManual = mkTabBtn("manual", t("add.tab.manual"));
  tabs.append(bQr, bUri, bManual);
  bQr.classList.add("sel");

  const clearFoot = () => h.modal.querySelector(".mfoot")?.remove();

  function show(id: TabId) {
    content.innerHTML = "";
    clearFoot();
    if (id === "qr") {
      content.append(el("p", "hint", t("add.qr.hint")));
      const pick = el("button", "btn primary block", t("add.qr.choose"));
      pick.prepend(icon("qr"));
      pick.onclick = async () => {
        const path = await open({
          multiple: false,
          filters: [{ name: "Images", extensions: ["png", "jpg", "jpeg"] }],
        });
        if (!path || typeof path !== "string") return;
        try {
          const preview = await api.importQr(path);
          h.close();
          openImportPreview(preview);
        } catch (e) {
          toast(fmtError(e), true);
        }
      };
      content.append(pick);
    } else if (id === "uri") {
      const ta = el("textarea");
      ta.placeholder = "otpauth://totp/Issuer:account?secret=…";
      const err = el("div", "errline");
      const go = el("button", "btn primary", t("add.uri.submit"));
      go.onclick = async () => {
        err.textContent = "";
        const uri = ta.value.trim();
        if (!uri) return;
        go.disabled = true;
        try {
          await api.addFromUri(uri);
          toast(t("toast.added"));
          h.close();
          await refresh();
        } catch (e) {
          err.textContent = fmtError(e);
          go.disabled = false;
        }
      };
      content.append(field(t("add.uri.label"), ta), el("p", "hint", t("add.uri.hint")), err);
      const cancel = el("button", "btn", t("common.cancel"));
      cancel.onclick = () => h.close();
      h.modal.append(footer(cancel, go));
    } else {
      manualForm(content, h);
    }
  }

  function manualForm(host: HTMLElement, handle: ModalHandle) {
    const issuer = el("input") as HTMLInputElement;
    issuer.placeholder = t("add.manual.issuer.ph");
    const name = el("input") as HTMLInputElement;
    name.placeholder = t("add.manual.name.ph");
    const secret = el("input") as HTMLInputElement;
    secret.placeholder = t("add.manual.secret.ph");
    secret.style.fontFamily = "var(--mono)";
    const group = el("input") as HTMLInputElement;
    group.placeholder = t("group.placeholder");
    group.setAttribute("list", "authio-groups-add");
    const gdl = el("datalist") as HTMLDataListElement;
    gdl.id = "authio-groups-add";
    for (const g of [...new Set(accounts.map((a) => a.group).filter((g) => g))]) {
      gdl.append(new Option(g, g));
    }
    const kind = el("select") as HTMLSelectElement;
    kind.append(new Option("TOTP (time-based)", "totp"), new Option("HOTP (counter-based)", "hotp"));
    const algo = el("select") as HTMLSelectElement;
    algo.append(new Option("SHA-1", "SHA1"), new Option("SHA-256", "SHA256"), new Option("SHA-512", "SHA512"));
    const digits = el("select") as HTMLSelectElement;
    digits.append(new Option("6", "6"), new Option("8", "8"));
    const period = el("input") as HTMLInputElement;
    period.type = "number";
    period.min = "5";
    period.max = "300";
    period.value = "30";
    const counter = el("input") as HTMLInputElement;
    counter.type = "number";
    counter.min = "0";
    counter.value = "0";

    const fKind = field(t("add.manual.type"), kind);
    const fPeriod = field(t("add.manual.period"), period);
    const fCounter = field(t("add.manual.counter"), counter);
    const rowKind = el("div", "row2");
    rowKind.append(fKind, field(t("add.manual.algorithm"), algo));
    const rowNums = el("div", "row2");
    rowNums.append(fPeriod, fCounter);
    fCounter.style.display = "none";
    kind.onchange = () => {
      const hotp = kind.value === "hotp";
      fCounter.style.display = hotp ? "" : "none";
      fPeriod.style.display = hotp ? "none" : "";
    };

    const err = el("div", "errline");
    const go = el("button", "btn primary", t("add.manual.submit"));
    go.onclick = async () => {
      err.textContent = "";
      go.disabled = true;
      try {
        await api.addAccount({
          issuer: issuer.value,
          name: name.value,
          secret: secret.value,
          group: group.value,
          algorithm: algo.value,
          digits: Number(digits.value),
          period: Number(period.value || 30),
          kind: kind.value === "hotp" ? "hotp" : "totp",
          counter: Number(counter.value || 0),
        });
        toast(t("toast.added"));
        handle.close();
        await refresh();
      } catch (e) {
        err.textContent = fmtError(e);
        go.disabled = false;
      }
    };
    host.append(
      field(t("add.manual.issuer"), issuer),
      field(t("add.manual.name"), name),
      field(t("group.label"), group),
      gdl,
      field(t("add.manual.secret"), secret),
      rowKind,
      rowNums,
      field(t("add.manual.digits"), digits),
      el("p", "hint", t("add.manual.hint")),
      err,
    );
    const cancel = el("button", "btn", t("common.cancel"));
    cancel.onclick = () => handle.close();
    handle.modal.append(footer(cancel, go));
  }

  show("qr");
}

/* ------------------------------------------------------------ import flow */
function openImportModal() {
  const h = openModal(t("import.title"));
  const tabs = el("div", "tabs");
  const content = el("div");
  h.body.append(tabs, content);
  const clearFoot = () => h.modal.querySelector(".mfoot")?.remove();

  type TabId = "file" | "text";
  const mkTabBtn = (id: TabId, label: string) => {
    const b = el("button", "tab", label);
    b.type = "button";
    b.onclick = () => {
      tabs.querySelectorAll(".tab").forEach((n) => n.classList.toggle("sel", n === b));
      show(id);
    };
    return b;
  };
  const bFile = mkTabBtn("file", t("import.tab.file"));
  const bText = mkTabBtn("text", t("import.tab.text"));
  tabs.append(bFile, bText);
  bFile.classList.add("sel");

  function show(id: TabId) {
    content.innerHTML = "";
    clearFoot();
    if (id === "file") {
      content.append(el("p", "hint", t("import.file.hint")));
      const pick = el("button", "btn primary block", t("import.file.choose"));
      pick.onclick = async () => {
        const path = await open({
          multiple: false,
          filters: [{ name: "Backups", extensions: ["json", "txt", "csv", "2fas", "authme", "aegis"] }],
        });
        if (!path || typeof path !== "string") return;
        try {
          const preview = await api.importFile(path, null);
          if (preview.needs_password) {
            passwordStep(content, h, (pw) => api.importFile(path, pw));
          } else {
            h.close();
            openImportPreview(preview);
          }
        } catch (e) {
          toast(fmtError(e), true);
        }
      };
      content.append(pick);
    } else {
      const ta = el("textarea");
      ta.placeholder = "otpauth://totp/…  —  or paste an Aegis/Authio/Authme JSON backup, or an otpauth-migration:// link";
      const err = el("div", "errline");
      const go = el("button", "btn primary", t("import.text.submit"));
      go.onclick = async () => {
        err.textContent = "";
        if (!ta.value.trim()) return;
        go.disabled = true;
        try {
          const preview = await api.importText(ta.value, null);
          if (preview.needs_password) {
            passwordStep(content, h, (pw) => api.importText(ta.value, pw));
            go.disabled = false;
          } else {
            h.close();
            openImportPreview(preview);
          }
        } catch (e) {
          err.textContent = fmtError(e);
          go.disabled = false;
        }
      };
      content.append(field(t("import.text.label"), ta), err);
      const cancel = el("button", "btn", t("common.cancel"));
      cancel.onclick = () => h.close();
      h.modal.append(footer(cancel, go));
    }
  }

  function passwordStep(host: HTMLElement, handle: ModalHandle, retry: (pw: string) => Promise<PreviewDto>) {
    handle.modal.querySelector(".mfoot")?.remove();
    host.innerHTML = "";
    const pw = el("input") as HTMLInputElement;
    pw.type = "password";
    pw.placeholder = "••••••••";
    const err = el("div", "errline");
    const back = el("button", "btn", t("common.back"));
    back.onclick = () => {
      handle.close();
      openImportModal();
    };
    const go = el("button", "btn primary", t("import.password.submit"));
    go.onclick = async () => {
      err.textContent = "";
      go.disabled = true;
      try {
        const preview = await retry(pw.value);
        handle.close();
        openImportPreview(preview);
      } catch (e) {
        err.textContent = fmtError(e);
        go.disabled = false;
      }
    };
    const wrap = el("div");
    const h3 = el("h3", "", t("import.password.title"));
    h3.style.cssText = "font-size:14px;margin:4px 0";
    wrap.append(h3, el("p", "hint", t("import.password.hint")), pw, err);
    host.append(wrap);
    handle.modal.append(footer(back, go));
    pw.focus();
  }
}

function openImportPreview(preview: PreviewDto) {
  const h = openModal(t("import.preview.title"));
  const meta = el("div", "pv-meta");
  meta.append(el("span", "", `${t("import.preview.format")}:`));
  const fmt = el("span", "badge blue", preview.format);
  meta.append(fmt);
  if (preview.skipped > 0) meta.append(el("span", "", t("import.preview.skipped", { n: preview.skipped })));
  h.body.append(meta);

  const selected = new Set<number>();
  preview.entries.forEach((e) => {
    if (!e.duplicate) selected.add(e.index);
  });

  const sel = el("button", "tab", t("import.preview.selectall"));
  sel.style.marginTop = "6px";

  if (preview.entries.length === 0) {
    h.body.append(el("p", "hint", t("import.preview.none")));
    const done = el("button", "btn", t("common.close"));
    done.onclick = () => h.close();
    h.modal.append(footer(done));
    return;
  }

  const list = el("div", "pv-list");
  const rows: HTMLInputElement[] = [];
  for (const e of preview.entries) {
    const row = el("label");
    row.className = `pv-row${e.duplicate ? " duplicate" : ""}`;
    const cb = el("input") as HTMLInputElement;
    cb.type = "checkbox";
    cb.checked = !e.duplicate;
    cb.onchange = () => {
      if (cb.checked) selected.add(e.index);
      else selected.delete(e.index);
      updateGo();
    };
    rows.push(cb);
    const metaCol = el("div");
    const issuerLine = el("div", "issuer", e.issuer || e.name);
    if (e.duplicate) issuerLine.append(el("span", "badge", t("import.preview.dupe")));
    metaCol.append(issuerLine, el("div", "name", `${e.issuer ? e.name : ""} · ${e.kind.toUpperCase()} · ${e.digits} digits`));
    row.append(cb, metaCol);
    list.append(row);
  }
  sel.onclick = () => {
    rows.forEach((cb, i) => {
      cb.checked = true;
      selected.add(preview.entries[i].index);
    });
    updateGo();
  };

  const cancel = el("button", "btn", t("common.cancel"));
  cancel.onclick = () => h.close();
  const go = el("button", "btn primary");
  function updateGo() {
    go.textContent = t("import.preview.submit", { n: selected.size });
    go.disabled = selected.size === 0;
  }
  updateGo();
  go.onclick = async () => {
    go.disabled = true;
    try {
      const added = await api.importApply([...selected]);
      toast(t("toast.imported", { n: added.length }));
      h.close();
      await refresh();
    } catch (e) {
      toast(fmtError(e), true);
      h.close();
    }
  };
  h.body.append(sel, list);
  h.modal.append(footer(cancel, go));
}

/* --------------------------------------------------------------- export flow */
function openExportModal() {
  if (accounts.length === 0) {
    toast(t("export.empty"), true);
    return;
  }
  const h = openModal(t("export.title"));
  let encrypted = true;

  const radio = el("div", "mode-cards");
  const mkRadio = (sel: boolean, ic: IconName, title: string, desc: string) => {
    const c = el("button", `mode-card${sel ? " sel" : ""}`);
    c.type = "button";
    const tl = el("div", "t");
    tl.append(icon(ic), document.createTextNode(title));
    c.append(tl, el("div", "d", desc));
    return c;
  };
  const cEnc = mkRadio(true, "lock", t("export.encrypted"), t("export.encrypted.desc"));
  const cPlain = mkRadio(false, "alert", t("export.plain"), t("export.plain.desc"));
  radio.append(cEnc, cPlain);

  const encFields = el("div");
  const pw1 = el("input") as HTMLInputElement;
  pw1.type = "password";
  pw1.placeholder = t("export.password");
  const pw2 = el("input") as HTMLInputElement;
  pw2.type = "password";
  pw2.placeholder = t("export.password2");
  encFields.append(field("", pw1), field("", pw2));
  (encFields.querySelectorAll("label:empty") as NodeListOf<HTMLElement>).forEach((l) => l.remove());

  const plainFields = el("div");
  const warn = el("div", "banner");
  warn.append(icon("alert"), document.createTextNode(t("export.plain.warn")));
  warn.style.borderColor = "color-mix(in srgb, var(--danger) 40%, transparent)";
  warn.style.background = "color-mix(in srgb, var(--danger) 8%, transparent)";
  const ack = el("label", "pv-row");
  ack.style.cursor = "pointer";
  const ackCb = el("input") as HTMLInputElement;
  ackCb.type = "checkbox";
  ack.append(ackCb, el("div", "issuer", t("export.plain.ack")));
  plainFields.append(warn, ack);
  plainFields.style.display = "none";

  const masterField = el("div");
  let master: HTMLInputElement | null = null;
  if (statusInfo?.mode === "password") {
    master = el("input") as HTMLInputElement;
    master.type = "password";
    master.placeholder = t("export.master");
    masterField.append(field("", master));
    (masterField.querySelector("label:empty") as HTMLElement | null)?.remove();
  }

  cEnc.onclick = () => {
    encrypted = true;
    cEnc.classList.add("sel");
    cPlain.classList.remove("sel");
    encFields.style.display = "";
    plainFields.style.display = "none";
  };
  cPlain.onclick = () => {
    encrypted = false;
    cPlain.classList.add("sel");
    cEnc.classList.remove("sel");
    encFields.style.display = "none";
    plainFields.style.display = "";
  };

  const err = el("div", "errline");
  const cancel = el("button", "btn", t("common.cancel"));
  cancel.onclick = () => h.close();
  const go = el("button", "btn primary", t("export.submit"));
  go.onclick = async () => {
    err.textContent = "";
    if (encrypted) {
      if (pw1.value.length < 8) {
        err.textContent = t("export.password");
        return;
      }
      if (pw1.value !== pw2.value) {
        err.textContent = t("export.mismatch");
        return;
      }
    } else if (!ackCb.checked) {
      err.textContent = t("export.plain.ack");
      return;
    }
    const day = new Date().toISOString().slice(0, 10);
    const path = await save({
      defaultPath: `authio-backup-${day}.json`,
      filters: [{ name: "Authio backup", extensions: ["json"] }],
    });
    if (!path) return;
    go.disabled = true;
    try {
      const msg = await api.exportBackup(
        path,
        encrypted,
        encrypted ? pw1.value : null,
        master ? master.value : null,
      );
      pw1.value = pw2.value = "";
      if (master) master.value = "";
      h.close();
      toast(msg);
    } catch (e) {
      err.textContent = fmtError(e);
      go.disabled = false;
    }
  };
  h.body.append(radio, encFields, plainFields, masterField, err);
  h.modal.append(footer(cancel, go));
}

/*------------------------------------------------------------- settings modal */
async function openSettingsModal() {
  // Always show the security section against fresh backend state.
  await refreshStatus().catch(() => undefined);
  const h = openModal(t("settings.title"));

  const save = async () => {
    applyVisualSettings();
    try {
      await api.setSettings({ ...settings });
    } catch (e) {
      toast(fmtError(e), true);
    }
  };

  const mkRow = (title: string, desc: string | null, control: HTMLElement) => {
    const row = el("div", "set-row");
    const l = el("div", "l");
    l.append(el("div", "t", title));
    if (desc) l.append(el("div", "d", desc));
    row.append(l, control);
    return row;
  };

  // language — stored in the vault settings, applied live via full re-paint
  const langSel = el("select") as HTMLSelectElement;
  LANGS.forEach((l) => langSel.append(new Option(l.name, l.code)));
  langSel.value = settings.lang in Object.fromEntries(LANGS.map((l) => [l.code, true])) ? settings.lang : "en";
  langSel.onchange = () => {
    settings.lang = langSel.value;
    setLang(langSel.value);
    void save().then(() => location.reload()); // re-render every string in the new language
  };

  // theme
  const themeSel = el("select") as HTMLSelectElement;
  themeSel.append(
    new Option(t("settings.theme.system"), "system"),
    new Option(t("settings.theme.light"), "light"),
    new Option(t("settings.theme.dark"), "dark"),
  );
  themeSel.value = settings.theme;
  themeSel.onchange = () => {
    settings.theme = themeSel.value;
    void save();
  };

  // density
  const densSel = el("select") as HTMLSelectElement;
  densSel.append(new Option(t("settings.density.compact"), "compact"), new Option(t("settings.density.comfortable"), "comfortable"));
  densSel.value = settings.density;
  densSel.onchange = () => {
    settings.density = densSel.value;
    void save();
  };

  // code size
  const fontRange = el("input") as HTMLInputElement;
  fontRange.type = "range";
  fontRange.min = "80";
  fontRange.max = "140";
  fontRange.step = "5";
  fontRange.value = String(settings.font_scale);
  fontRange.oninput = () => {
    settings.font_scale = Number(fontRange.value);
    applyVisualSettings();
  };
  fontRange.onchange = () => void save();

  // alphabetical
  const alphaSw = el("input", "switch") as HTMLInputElement;
  alphaSw.type = "checkbox";
  alphaSw.checked = settings.sort_alpha;
  alphaSw.onchange = () => {
    settings.sort_alpha = alphaSw.checked;
    void save();
    renderList();
    void pollCodes();
  };

  // hide codes
  const hideSw = el("input", "switch") as HTMLInputElement;
  hideSw.type = "checkbox";
  hideSw.checked = settings.hide_codes;
  hideSw.onchange = () => {
    settings.hide_codes = hideSw.checked;
    hidden.clear();
    if (settings.hide_codes) accounts.forEach((a) => hidden.add(a.id));
    void save();
    renderList();
    void pollCodes();
  };

  // auto lock minutes
  const lockNum = el("input") as HTMLInputElement;
  lockNum.type = "number";
  lockNum.min = "0";
  lockNum.max = "240";
  lockNum.value = String(settings.auto_lock_minutes);
  const lockWrap = el("div");
  lockWrap.style.cssText = "display:flex;align-items:center;gap:6px";
  lockWrap.append(lockNum, el("span", "", t("settings.autolock.minutes")));
  lockNum.onchange = () => {
    settings.auto_lock_minutes = Math.max(0, Math.min(240, Number(lockNum.value || 0)));
    lockNum.value = String(settings.auto_lock_minutes);
    void save();
  };

  // lock on minimize
  const minSw = el("input", "switch") as HTMLInputElement;
  minSw.type = "checkbox";
  minSw.checked = settings.lock_on_minimize;
  minSw.onchange = () => {
    settings.lock_on_minimize = minSw.checked;
    void save();
  };

  // system tray
  const traySw = el("input", "switch") as HTMLInputElement;
  traySw.type = "checkbox";
  traySw.checked = settings.tray;
  traySw.onchange = () => {
    settings.tray = traySw.checked;
    void save();
  };

  // view style (rows / tiles)
  const viewSel = el("select") as HTMLSelectElement;
  viewSel.append(new Option(t("settings.view.rows"), "rows"), new Option(t("settings.view.tiles"), "tiles"));
  viewSel.value = settings.view_mode === "tiles" ? "tiles" : "rows";
  viewSel.onchange = () => {
    settings.view_mode = viewSel.value;
    void save();
    renderList();
    void pollCodes();
  };

  // countdown number inside the timer ring
  const numSw = el("input", "switch") as HTMLInputElement;
  numSw.type = "checkbox";
  numSw.checked = settings.show_timer_number;
  numSw.onchange = () => {
    settings.show_timer_number = numSw.checked;
    void save();
    renderList();
    void pollCodes();
  };

  // ---- data: import / export live here in settings
  const dataTitle = el("div", "section-label", t("settings.data"));
  dataTitle.style.margin = "10px 0 0";
  const impB = el("button", "btn", t("main.import"));
  impB.prepend(icon("download"));
  impB.onclick = () => {
    h.close();
    openImportModal();
  };
  const expB = el("button", "btn", t("main.export"));
  expB.prepend(icon("upload"));
  expB.onclick = () => {
    h.close();
    openExportModal();
  };
  const dataActions = el("div", "data-actions");
  dataActions.append(impB, expB);

  // ---- security: change unlock method / master password
  const secTitle = el("div", "section-label", t("settings.security"));
  secTitle.style.margin = "10px 0 0";
  const curMode = statusInfo?.mode ?? "password";
  const modeLabel = el("div", "", t("settings.mode." + curMode));
  modeLabel.style.cssText = "font-weight:600;margin-right:8px";
  const chgB = el("button", "btn", t("settings.change"));
  chgB.onclick = () =>
    openChangeUnlockModal((m) => {
      modeLabel.textContent = t("settings.mode." + m);
    });
  const modeWrap = el("div");
  modeWrap.style.cssText = "display:flex;align-items:center";
  modeWrap.append(modeLabel, chgB);

  // ---- about
  const aboutTitle = el("div", "section-label", t("about.title"));
  aboutTitle.style.margin = "10px 0 0";
  const ver = statusInfo?.version ?? "1.0.0";
  const aboutCard = el("div", "about-card");
  const aName = el("div", "a-name");
  aName.append(el("span", "", t("app.name")), el("span", "ver", `v${ver}`));
  const ghB = el("button", "btn", t("about.github"));
  ghB.prepend(icon("linkExt"));
  ghB.onclick = () => void api.openUrl("github").catch((e) => toast(fmtError(e), true));
  const donB = el("button", "btn", t("about.donate"));
  donB.prepend(icon("heart"));
  donB.onclick = () => void api.openUrl("donate").catch((e) => toast(fmtError(e), true));
  const aLinks = el("div", "a-links");
  aLinks.append(ghB, donB);
  aboutCard.append(aName, el("div", "a-sub", t("settings.about", { v: ver })), aLinks);

  h.body.append(
    mkRow(t("settings.language"), t("settings.language.hint"), langSel),
    mkRow(t("settings.theme"), null, themeSel),
    mkRow(t("settings.density"), null, densSel),
    mkRow(t("settings.font"), null, fontRange),
    mkRow(t("settings.view"), null, viewSel),
    mkRow(t("settings.sort_alpha"), null, alphaSw),
    mkRow(t("settings.hide_codes"), null, hideSw),
    mkRow(t("settings.timer_number"), null, numSw),
    mkRow(t("settings.autolock"), t("settings.autolock.off"), lockWrap),
    mkRow(t("settings.lock_minimize"), null, minSw),
    mkRow(t("settings.tray"), null, traySw),
    dataTitle,
    dataActions,
    secTitle,
    mkRow(t("settings.unlock_method"), null, modeWrap),
    aboutTitle,
    aboutCard,
  );

  const done = el("button", "btn primary", t("common.close"));
  done.onclick = () => h.close();
  h.modal.append(footer(done));
}

/* -------------------------------------------------- change unlock method */
function openChangeUnlockModal(onDone?: (m: UnlockMode) => void) {
  const h = openModal(t("chg.title"));
  const curMode: UnlockMode = statusInfo?.mode ?? "password";
  let target: UnlockMode = curMode;

  const upd = () => {
    curWrap.style.display = curMode === "password" ? "" : "none";
    newWrap.style.display = target === "password" ? "" : "none";
    warn.style.display = target === "none" ? "" : "none";
    cards.querySelectorAll(".mode-card").forEach((n) => {
      n.classList.toggle("sel", targetFor.get(n as HTMLElement) === target);
    });
  };

  const targetFor = new Map<HTMLElement, UnlockMode>();
  const cards = el("div", "mode-cards");
  const mkModeCard = (m: UnlockMode, title: string, ic: IconName) => {
    const c = el("button", "mode-card");
    c.type = "button";
    const tl = el("div", "t");
    tl.append(icon(ic), document.createTextNode(title));
    c.append(tl);
    targetFor.set(c, m);
    c.onclick = () => {
      target = m;
      upd();
    };
    return c;
  };
  cards.append(
    mkModeCard("password", t("settings.mode.password"), "key"),
    mkModeCard("keychain", t("settings.mode.keychain"), "shield"),
    mkModeCard("none", t("settings.mode.none"), "alert"),
  );

  const curPw = el("input") as HTMLInputElement;
  curPw.type = "password";
  curPw.placeholder = t("chg.current");
  curPw.autocomplete = "current-password";
  const curWrap = el("div");
  curWrap.append(field("", curPw));
  (curWrap.querySelectorAll("label") as NodeListOf<HTMLElement>).forEach((l) => l.remove());

  const new1 = el("input") as HTMLInputElement;
  new1.type = "password";
  new1.placeholder = t("chg.new_password");
  new1.autocomplete = "new-password";
  const new2 = el("input") as HTMLInputElement;
  new2.type = "password";
  new2.placeholder = t("chg.new_password2");
  new2.autocomplete = "new-password";
  const newWrap = el("div");
  newWrap.append(field("", new1), field("", new2));
  (newWrap.querySelectorAll("label") as NodeListOf<HTMLElement>).forEach((l) => l.remove());

  const warn = el("div", "banner danger");
  warn.append(icon("alert"), document.createTextNode(t("chg.none.warn")));

  const err = el("div", "errline");
  const go = el("button", "btn primary", t("chg.submit"));
  const cancel = el("button", "btn", t("common.cancel"));
  cancel.onclick = () => h.close();

  go.onclick = async () => {
    err.textContent = "";
    if (target === "password") {
      if (new1.value.length < 8) {
        err.textContent = t("chg.new_password");
        return;
      }
      if (new1.value !== new2.value) {
        err.textContent = t("chg.mismatch");
        return;
      }
    }
    if (curMode === "password" && !curPw.value) {
      err.textContent = t("chg.current");
      return;
    }
    go.disabled = true;
    try {
      await api.changeUnlockMode(
        target,
        curMode === "password" ? curPw.value : undefined,
        target === "password" ? new1.value : undefined,
      );
      curPw.value = new1.value = new2.value = "";
      await refreshStatus();
      onDone?.(target);
      toast(t("chg.done"));
      h.close();
    } catch (e) {
      err.textContent = fmtError(e);
      go.disabled = false;
    }
  };

  h.body.append(cards, curWrap, newWrap, warn, err);
  h.modal.append(footer(cancel, go));
  upd();
}

/* --------------------------------------------------------------- edit modal */
function openEditModal(a: AccountDto) {
  const h = openModal(t("card.edit"));
  const issuer = el("input") as HTMLInputElement;
  issuer.value = a.issuer;
  const name = el("input") as HTMLInputElement;
  name.value = a.name;
  const group = el("input") as HTMLInputElement;
  group.value = a.group;
  group.placeholder = t("group.placeholder");
  group.setAttribute("list", "authio-groups-edit");
  const gdl = el("datalist") as HTMLDataListElement;
  gdl.id = "authio-groups-edit";
  for (const g of [...new Set(accounts.map((x) => x.group).filter((g) => g))]) {
    gdl.append(new Option(g, g));
  }
  const err = el("div", "errline");
  const cancel = el("button", "btn", t("common.cancel"));
  cancel.onclick = () => h.close();
  const go = el("button", "btn primary", t("common.save"));
  go.onclick = async () => {
    try {
      await api.updateAccount(a.id, issuer.value, name.value, group.value);
      toast(t("toast.updated"));
      h.close();
      await refresh();
    } catch (e) {
      err.textContent = fmtError(e);
    }
  };
  h.body.append(
    field(t("add.manual.issuer"), issuer),
    field(t("add.manual.name"), name),
    field(t("group.label"), group),
    gdl,
    el("p", "hint", `${a.kind.toUpperCase()} · ${a.algorithm} · ${a.digits} digits${a.kind === "totp" ? ` · ${a.period}s` : ""}`),
    err,
  );
  h.modal.append(footer(cancel, go));
}

/* -------------------------------------------------------------- reveal modal */
function openRevealModal(a: AccountDto) {
  const h = openModal(t("reveal.title"));
  const show = (secret: string, uri: string) => {
    h.body.innerHTML = "";
    const grp = secret.replace(/(.{4})(?=.)/g, "$1 ");
    h.body.append(
      el("label", "lbl", t("reveal.secret")),
      secretBox(grp),
      el("label", "lbl", t("reveal.uri")),
      secretBox(uri),
      el("p", "hint", t("reveal.hint")),
    );
    function secretBox(text: string): HTMLElement {
      const row = el("div");
      row.style.cssText = "display:flex;gap:6px;align-items:flex-start";
      const box = el("div", "mono-box", text);
      box.style.flex = "1";
      const c = iconBtn("copy", t("code.copy"));
      c.onclick = () => void copyText(text.replaceAll(" ", ""));
      row.append(box, c);
      return row;
    }
  };

  if (statusInfo?.mode !== "password") {
    api
      .revealSecret(a.id)
      .then((s) => show(s.secret, s.uri))
      .catch((e) => {
        h.close();
        toast(fmtError(e), true);
      });
    return;
  }
  const pw = el("input") as HTMLInputElement;
  pw.type = "password";
  pw.placeholder = t("reveal.master");
  const err = el("div", "errline");
  const cancel = el("button", "btn", t("common.cancel"));
  cancel.onclick = () => h.close();
  const go = el("button", "btn primary", t("reveal.submit"));
  go.onclick = async () => {
    err.textContent = "";
    try {
      const s = await api.revealSecret(a.id, pw.value);
      pw.value = "";
      h.modal.querySelector(".mfoot")?.remove();
      show(s.secret, s.uri);
    } catch (e) {
      err.textContent = fmtError(e);
    }
  };
  h.body.append(field("", pw), err);
  (h.body.querySelector("label:empty") as HTMLElement | null)?.remove();
  h.modal.append(footer(cancel, go));
  pw.focus();
}

/* --------------------------------------------------------------------- boot */
async function boot() {
  setLang(getBootLang()); // setup/lock screens paint before the vault settings are known
  applyVisualSettings();
  try {
    settings = { ...settings, ...(await api.getSettings()) };
    setLang(settings.lang || getBootLang()); // vault settings win over the boot mirror
  } catch {
    /* defaults */
  }
  applyVisualSettings();

  await listen("authio://locked", async () => {
    await refreshStatus().catch(() => undefined);
    renderLock(true);
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && route === "main") void pollCodes();
  });

  // Global shortcuts: Ctrl+F search · Ctrl+L lock · Ctrl+, settings
  window.addEventListener("keydown", (e) => {
    if (route !== "main" || !e.ctrlKey) return;
    const k = e.key.toLowerCase();
    if (k === "f") {
      e.preventDefault();
      document.querySelector<HTMLInputElement>(".searchin input")?.focus();
    } else if (k === "l") {
      e.preventDefault();
      void api.lock().catch(() => undefined);
      void refreshStatus().then(() => renderLock());
    } else if (k === ",") {
      e.preventDefault();
      openSettingsModal();
    }
  });

  try {
    await refreshStatus();
  } catch (e) {
    toast(fmtError(e), true);
  }

  // 1 Hz code pump.
  setInterval(() => void pollCodes(), 1000);

  if (!statusInfo?.initialized) {
    renderSetup();
  } else if (!statusInfo.unlocked) {
    // For keychain / no-security vaults, unlock once automatically at startup
    // (manual locking via Ctrl+L still shows the lock screen afterwards).
    const m = statusInfo.mode;
    if (m === "keychain" || m === "none") {
      try {
        await api.unlock();
        await refreshStatus();
        await enterMain();
        return;
      } catch {
        /* fall through to the lock screen */
      }
    }
    renderLock();
  } else await enterMain();
}

void boot();
