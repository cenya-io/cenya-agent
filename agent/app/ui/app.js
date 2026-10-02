/* Cenya Agent -- the page. Presentation only.

   Every text, tone, enabled/disabled flag and the reason why comes from Python
   (window.pywebview.api, agent/app/bridge.py -> agent/app/view.py). This file
   lays it out, keeps it fresh by polling, and sends what the person does back.

   Rules kept here:
   - Data reaches the DOM through textContent only. The only HTML strings are
     the icons of icons.js, which are constants.
   - A block is re-rendered only when its data changed, and keyboard focus is
     put back where it was, so a poll every second never steals focus.
   - The NetBox token is read from its field once, sent, and the field is
     cleared; it is never kept in a variable that outlives the call. */
"use strict";

let T = {};
const S = {
  section: "status",
  shell: null,
  perms: { can_act: false, readonly: true, why: "", can_elevate: false },
  dev: false,
  version: "",
  filters: { tasks: [], levels: [] },
  timers: [],
  nbUrl: "",
  nbMode: "send",
  nbInsecure: false,
  mountId: 0,
};

const SECTIONS = [
  { id: "status", icon: "activity", nav: "nav_status", sub: "sub_status" },
  { id: "activity", icon: "scroll-text", nav: "nav_activity", sub: "sub_activity" },
  { id: "netbox", icon: "database", nav: "nav_netbox", sub: "sub_netbox" },
  { id: "tools", icon: "wrench", nav: "nav_tools", sub: "sub_tools" },
  { id: "connection", icon: "plug", nav: "nav_connection", sub: "sub_connection" },
  { id: "settings", icon: "sliders", nav: "nav_settings", sub: "sub_settings" },
  { sep: true },
  { id: "about", icon: "info", nav: "nav_about", sub: "sub_about" },
];

/* --- Bridge ------------------------------------------------------------- */

function call(method, ...args) {
  try {
    return Promise.resolve(window.pywebview.api[method](...args)).then(
      (r) => r || { ok: false, error: "bridge", message: "" },
      (e) => ({ ok: false, error: "bridge", message: String(e && e.message ? e.message : e) })
    );
  } catch (e) {
    return Promise.resolve({ ok: false, error: "bridge", message: String(e) });
  }
}

function fmt(text, params) {
  return String(text || "").replace(/%\((\w+)\)[sd]/g, (m, k) => (params && k in params ? String(params[k]) : m));
}

/* --- DOM helpers -------------------------------------------------------- */

function el(tag, props, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false || kid === "") continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

function ico(name, cls) {
  const t = document.createElement("template");
  t.innerHTML = iconSvg(name, cls);
  return t.content.firstChild;
}

const $ = (id) => document.getElementById(id);

function patch(host, data, render) {
  const sig = JSON.stringify([data, S.perms.can_act, S.perms.why]);
  if (host.dataset.sig === sig) return;
  host.dataset.sig = sig;
  const active = document.activeElement;
  const fkey = active && host.contains(active) ? active.getAttribute("data-fkey") : null;
  const out = render(data);
  host.replaceChildren(...[].concat(out).filter(Boolean));
  if (fkey) {
    const again = host.querySelector('[data-fkey="' + CSS.escape(fkey) + '"]');
    if (again) again.focus();
  }
}

/* --- Components (the window's small design system) ---------------------- */

function btn(label, o = {}) {
  const variant = o.variant || "secondary";
  const cls = ["btn", "btn-" + variant, o.size ? "btn-" + o.size : "", o.iconOnly ? "btn-icon" : ""].join(" ");
  const b = el("button", { type: "button", class: cls, "data-fkey": o.fkey || null, "aria-label": o.iconOnly ? label : null });
  if (o.icon) b.append(ico(o.icon));
  if (!o.iconOnly) b.append(el("span", { text: label }));
  let why = o.why || "";
  if (!why && o.act && !S.perms.can_act) why = S.perms.why;
  if (why || o.disabled) {
    b.setAttribute("aria-disabled", "true");
    if (why) b.dataset.tip = why;
  } else if (o.iconOnly) {
    b.dataset.tip = label;
  }
  if (o.tipLeft) b.dataset.tipSide = "left";
  b.addEventListener("click", async (event) => {
    if (b.getAttribute("aria-disabled") === "true" || b.dataset.busy === "true" || !o.onClick) return;
    const result = o.onClick(event, b);
    if (result && typeof result.then === "function") {
      setBusy(b, true);
      try {
        await result;
      } finally {
        setBusy(b, false);
      }
    }
  });
  return b;
}

function setBusy(b, busy) {
  b.dataset.busy = busy ? "true" : "false";
  b.querySelectorAll(".spin").forEach((s) => s.remove());
  if (busy) b.append(ico("loader", "spin"));
}

function badge(label, tone, withDot) {
  return el("span", { class: "badge", "data-tone": tone || "neutral" }, withDot ? el("span", { class: "dot", "data-tone": tone }) : null, label);
}

function panel(o) {
  const head = o.title
    ? el(
        "div",
        { class: "panel-head" },
        el("div", { class: "panel-title" }, o.titlePrefix || null, el("span", { text: o.title }), o.meta ? el("span", { class: "panel-meta", text: o.meta }) : null),
        o.actions ? el("div", { class: "row" }, o.actions) : null
      )
    : null;
  const body = el("div", { class: "panel-body" + (o.flush ? " flush" : "") }, o.body);
  return el("div", { class: "panel" + (o.cls ? " " + o.cls : "") }, head, body, o.foot ? el("div", { class: "panel-foot" }, o.foot) : null);
}

function skeleton(lines = 3) {
  return el("div", { class: "skeleton", "aria-label": T.loading, role: "status" }, Array.from({ length: lines }, () => el("span")));
}

function emptyState(o) {
  return el(
    "div",
    { class: "empty" + (o.tall ? " tall" : "") },
    o.icon ? el("div", { class: "empty-icon", "data-tone": o.tone || null }, ico(o.icon, "icon-lg")) : null,
    o.title ? el("div", { class: "empty-title", text: o.title }) : null,
    o.text ? el("div", { class: "empty-text", text: o.text }) : null,
    o.actions ? el("div", { class: "empty-actions" }, o.actions) : null
  );
}

function errorState(message, retry) {
  return emptyState({
    icon: "triangle-alert",
    tone: "danger",
    title: T.error_title,
    text: message,
    actions: retry ? [btn(T.retry, { icon: "rotate-cw", onClick: retry })] : null,
  });
}

function resultBox(tone, text, icon) {
  const icons = { success: "circle-check", danger: "circle-x", warning: "triangle-alert", info: "info" };
  return el("div", { class: "result", "data-tone": tone }, ico(icon || icons[tone] || "info"), el("div", { class: "grow result-text", text }));
}

function field(label, control, hint, error) {
  const id = control.id || "f" + Math.random().toString(36).slice(2, 9);
  control.id = id;
  return el(
    "div",
    { class: "field" },
    el("label", { class: "field-label", for: id, text: label }),
    control,
    hint ? el("div", { class: "field-hint", text: hint }) : null,
    error || null
  );
}

function input(o = {}) {
  const i = el("input", {
    class: "field-input" + (o.mono ? " mono" : ""),
    type: o.type || "text",
    placeholder: o.placeholder || null,
    autocomplete: "off",
    spellcheck: "false",
    "data-fkey": o.fkey || null,
  });
  if (o.value) i.value = o.value;
  if (o.disabled) i.disabled = true;
  if (o.onEnter) i.addEventListener("keydown", (e) => e.key === "Enter" && o.onEnter(e));
  return i;
}

function sw(checked, o = {}) {
  const s = el("button", { type: "button", role: "switch", class: "switch", "aria-checked": checked ? "true" : "false", "aria-label": o.label || null, "data-fkey": o.fkey || null });
  const why = o.why || (o.act && !S.perms.can_act ? S.perms.why : "");
  if (why) {
    s.setAttribute("aria-disabled", "true");
    s.dataset.tip = why;
  }
  s.addEventListener("click", async () => {
    if (s.getAttribute("aria-disabled") === "true" || s.dataset.busy === "true") return;
    const next = s.getAttribute("aria-checked") !== "true";
    s.setAttribute("aria-checked", next ? "true" : "false");
    s.dataset.busy = "true";
    const ok = await o.onChange(next);
    s.dataset.busy = "false";
    if (!ok) s.setAttribute("aria-checked", next ? "false" : "true");
  });
  return s;
}

function segmented(options, value, o = {}) {
  const why = o.why || (o.act && !S.perms.can_act ? S.perms.why : "");
  const group = el("div", { class: "segmented", role: "radiogroup", "aria-label": o.label || null, "aria-disabled": why ? "true" : null });
  if (why) group.dataset.tip = why;
  for (const opt of options) {
    const b = el("button", { type: "button", role: "radio", "aria-checked": opt.id === value ? "true" : "false", "data-fkey": (o.fkey || "seg") + ":" + opt.id, text: opt.label });
    b.addEventListener("click", async () => {
      if (why || opt.id === value || group.dataset.busy === "true") return;
      group.dataset.busy = "true";
      await o.onChange(opt.id);
      group.dataset.busy = "false";
    });
    b.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      const items = [...group.querySelectorAll("button")];
      const next = items[(items.indexOf(b) + (e.key === "ArrowRight" ? 1 : items.length - 1)) % items.length];
      next.focus();
    });
    group.append(b);
  }
  return group;
}

function select(options, value, onChange, o = {}) {
  const s = el("select", { class: "field-select", "aria-label": o.label || null, "data-fkey": o.fkey || null });
  for (const opt of options) {
    const option = el("option", { value: opt.id, text: opt.label });
    if (opt.id === value) option.selected = true;
    s.append(option);
  }
  s.addEventListener("change", () => onChange(s.value));
  return s;
}

function toast(message, tone = "success") {
  if (!message) return;
  const icons = { success: "circle-check", danger: "circle-x", warning: "triangle-alert", info: "info" };
  const t = el("div", { class: "toast" }, el("span", { class: "tone-" + tone }, ico(icons[tone] || "info")), el("div", { class: "selectable", text: message }));
  $("toasts").append(t);
  setTimeout(() => t.remove(), tone === "danger" ? 7000 : 4000);
}

function report(r, okMessage) {
  if (r && r.ok) {
    if (okMessage) toast(okMessage, "success");
    return true;
  }
  if (r && r.error === "forbidden") refreshShell();
  if (r && r.message) toast(r.message, "danger");
  return false;
}

function confirmDialog(o) {
  return new Promise((resolve) => {
    const before = document.activeElement;
    const close = (value) => {
      root.remove();
      document.removeEventListener("keydown", onKey, true);
      if (before && before.focus) before.focus();
      resolve(value);
    };
    const cancel = btn(T.cancel, { onClick: () => close(false), fkey: "dlg-cancel" });
    const ok = btn(o.confirm, { variant: o.danger ? "danger-solid" : "primary", onClick: () => close(true) });
    const titleId = "dlg-title";
    const dialog = el(
      "div",
      { class: "dialog", role: "alertdialog", "aria-modal": "true", "aria-labelledby": titleId },
      el("div", { class: "dialog-body" }, el("div", { class: "dialog-title", id: titleId, text: o.title }), el("div", { class: "dialog-text", text: o.text })),
      el("div", { class: "dialog-actions" }, cancel, ok)
    );
    const root = el("div", { class: "scrim", onClick: (e) => e.target === root && close(false) }, dialog);
    const onKey = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        close(false);
      } else if (e.key === "Tab") {
        const items = [cancel, ok];
        const i = items.indexOf(document.activeElement);
        e.preventDefault();
        items[(i + (e.shiftKey ? items.length - 1 : 1)) % items.length].focus();
      }
    };
    document.addEventListener("keydown", onKey, true);
    $("overlay").append(root);
    (o.danger ? cancel : ok).focus();
  });
}

function openMenu(anchor, items) {
  closeMenus();
  const menu = el("div", { class: "menu", role: "menu" });
  for (const item of items) {
    const b = el("button", { type: "button", role: "menuitem" }, item.icon ? ico(item.icon) : null, el("span", { text: item.label }));
    b.addEventListener("click", () => {
      closeMenus();
      item.onClick();
    });
    menu.append(b);
  }
  document.body.append(menu);
  const r = anchor.getBoundingClientRect();
  const width = menu.offsetWidth;
  menu.style.top = r.bottom + 4 + "px";
  menu.style.left = Math.max(8, Math.min(window.innerWidth - width - 8, r.right - width)) + "px";
  const buttons = [...menu.querySelectorAll("button")];
  buttons[0].focus();
  menu.addEventListener("keydown", (e) => {
    const i = buttons.indexOf(document.activeElement);
    if (e.key === "ArrowDown") buttons[(i + 1) % buttons.length].focus();
    else if (e.key === "ArrowUp") buttons[(i + buttons.length - 1) % buttons.length].focus();
    else if (e.key === "Escape" || e.key === "Tab") {
      closeMenus();
      anchor.focus();
    } else return;
    e.preventDefault();
  });
  setTimeout(() => document.addEventListener("mousedown", outside, true), 0);
  function outside(e) {
    if (!menu.contains(e.target)) closeMenus();
  }
  menu._outside = outside;
}

function closeMenus() {
  document.querySelectorAll(".menu").forEach((m) => {
    document.removeEventListener("mousedown", m._outside, true);
    m.remove();
  });
}

/* --- Shell -------------------------------------------------------------- */

function poll(fn, ms) {
  S.timers.push(setInterval(fn, ms));
}

function clearTimers() {
  S.timers.forEach(clearInterval);
  S.timers = [];
}

function renderNav() {
  const nav = $("nav");
  nav.setAttribute("aria-label", "Cenya Agent");
  nav.replaceChildren(
    ...SECTIONS.map((s, index) =>
      s.sep
        ? el("div", { class: "nav-sep", role: "separator" })
        : el(
            "button",
            {
              type: "button",
              class: "nav-item",
              "aria-current": s.id === S.section ? "page" : null,
              "aria-keyshortcuts": "Control+" + (index < 6 ? index + 1 : index),
              onClick: () => go(s.id),
            },
            ico(s.icon),
            el("span", { text: T[s.nav] })
          )
    )
  );
}

function renderBanner() {
  const host = $("banner");
  const shell = S.shell;
  if (!shell || !S.perms.readonly || ["down", "not_installed"].includes(shell.mode)) {
    host.replaceChildren();
    return;
  }
  const button = S.perms.can_elevate
    ? btn(T.readonly_button, {
        size: "sm",
        variant: "warning",
        icon: "shield-check",
        onClick: async () => {
          const r = await call("relaunch_elevated", S.section);
          if (!r.ok && r.message) toast(r.message, "danger");
        },
      })
    : null;
  patch(host, { readonly: true, elevate: S.perms.can_elevate, text: T.readonly_banner }, () =>
    el("div", { class: "banner", role: "note" }, ico("shield-alert"), el("span", { class: "grow", text: T.readonly_banner }), button)
  );
}

function renderFoot() {
  const shell = S.shell || {};
  const tone = shell.tone || "neutral";
  const portalHost = (shell.portal || "").replace(/^https?:\/\//, "").replace(/\/$/, "");
  patch($("sidebar-foot"), { tone, name: shell.agent_name, portalHost, dev: S.dev, mode: shell.mode }, () => [
    S.dev ? el("div", { class: "row" }, badge(T.dev_badge, "info", true)) : null,
    shell.agent_name || portalHost
      ? el(
          "div",
          { class: "machine" },
          el("span", { class: "dot" + (tone === "success" ? " pulse" : ""), "data-tone": tone }),
          el("div", { class: "machine-text" }, el("span", { class: "machine-name", text: shell.agent_name || "—" }), el("span", { class: "machine-portal", text: portalHost }))
        )
      : null,
  ]);
}

async function refreshShell(first) {
  const r = await call("shell");
  if (!r.ok) return;
  const v = r.view;
  const before = S.shell ? S.shell.mode : null;
  const beforeAct = S.perms.can_act;
  S.shell = v;
  S.perms = v.perms;
  S.dev = v.dev;
  renderBanner();
  renderFoot();
  const unenrolled = (mode) => mode === "not_enrolled";
  if (first) {
    if (unenrolled(v.mode)) S.section = "connection";
    return;
  }
  if (before !== v.mode || beforeAct !== v.perms.can_act) {
    if (unenrolled(v.mode) && !unenrolled(before)) S.section = "connection";
    renderNav();
    mountSection();
  }
}

function go(id) {
  closeMenus();
  if (S.section === id) return;
  S.section = id;
  renderNav();
  mountSection();
}

function mountSection() {
  clearTimers();
  closeMenus();
  S.mountId += 1;
  const section = SECTIONS.find((s) => s.id === S.section) || SECTIONS[0];
  $("title").textContent = T[section.nav];
  $("subtitle").textContent = T[section.sub] || "";
  const content = $("content");
  const head = $("head-actions");
  content.replaceChildren();
  head.replaceChildren();
  $("scroller").scrollTop = 0;
  const mode = S.shell ? S.shell.mode : "ready";
  if (section.id !== "about" && mode !== "ready" && mode !== "not_enrolled") {
    renderUnavailable(content, mode);
    return;
  }
  const renderers = { status: renderStatus, activity: renderActivity, netbox: renderNetbox, tools: renderTools, connection: renderConnection, settings: renderSettings, about: renderAbout };
  renderers[section.id](content, head, S.mountId);
}

function alive(id) {
  return id === S.mountId;
}

/* --- Service not running ------------------------------------------------- */

function renderUnavailable(content, mode) {
  const shell = S.shell || {};
  if (mode === "unreachable") {
    content.append(panel({ body: errorState(shell.message, () => refreshShell()) }));
    return;
  }
  if (mode === "not_installed") {
    content.append(panel({ body: emptyState({ icon: "server-off", tone: "danger", title: T.not_installed_title, text: T.not_installed_body, tall: true }) }));
    return;
  }
  const start = btn(T.down_start, {
    variant: "primary",
    icon: "power",
    why: shell.start_why || "",
    onClick: async () => {
      const r = await call("service_action", "start");
      if (report(r)) setTimeout(() => refreshShell(), 1500);
    },
  });
  content.append(
    panel({
      body: emptyState({
        icon: "server-off",
        tone: "warning",
        title: T.down_title,
        text: T.down_body,
        tall: true,
        actions: [start, btn(T.retry, { icon: "rotate-cw", onClick: () => refreshShell() })],
      }),
    })
  );
}

/* --- Estado --------------------------------------------------------------- */

function renderStatus(content, head, id) {
  if (S.shell && S.shell.mode === "not_enrolled") {
    content.append(
      panel({
        body: emptyState({
          icon: "plug",
          tone: "accent",
          title: T.enroll_title,
          text: (S.shell && S.shell.enrollment) || T.enroll_body,
          tall: true,
          actions: [btn(T.enroll_button, { variant: "primary", icon: "arrow-right", onClick: () => go("connection") })],
        }),
      })
    );
    return;
  }
  const overview = el("div", { class: "panel" }, skeleton(2));
  const current = el("div", { class: "panel" }, skeleton(3));
  const counters = el("div", { class: "panel" }, skeleton(3));
  const tasks = el("div", { class: "panel" }, skeleton(5));
  content.append(overview, el("div", { class: "grid-2" }, current, counters), tasks);

  const apply = (v) => {
    patch(overview, { c: v.connection, p: v.pause, cp: v.can_pause, cr: v.can_resume, w: v.pause_why, u: v.update, o: v.pause_options }, () => renderOverview(v, apply));
    patch(current, { a: v.activity, n: v.next_text }, () => renderCurrent(v));
    patch(counters, v.counters, () => renderCounters(v.counters));
    patch(tasks, v.tasks, () => renderTasks(v, apply));
  };
  const refresh = async () => {
    const r = await call("status");
    if (!alive(id)) return;
    if (!r.ok) {
      patch(overview, { error: r.message }, () => errorState(r.message, refresh));
      return;
    }
    apply(r.view);
  };
  refresh();
  poll(refresh, 1500);
}

function renderOverview(v, apply) {
  const c = v.connection;
  const marks = { success: "circle-check", warning: "triangle-alert", danger: "circle-x" };
  const left = el(
    "div",
    { class: "status-line" },
    el("div", { class: "status-mark", "data-tone": c.tone }, ico(marks[c.tone] || "globe", "icon-lg")),
    el(
      "div",
      { class: "grow" },
      el("div", { class: "status-title", text: c.title }),
      c.detail ? el("div", { class: "status-detail selectable", text: c.detail }) : null,
      el("div", { class: "status-since" }, c.since, v.update ? el("span", { class: "tone-info", text: (c.since ? " · " : "") + v.update }) : null)
    )
  );
  let right;
  if (v.pause.paused) {
    right = el(
      "div",
      { class: "row" },
      badge(v.pause.text, "warning", true),
      btn(T.resume, {
        variant: "primary",
        icon: "play",
        act: true,
        why: v.can_resume ? "" : v.pause_why,
        fkey: "resume",
        tipLeft: true,
        onClick: async () => {
          const r = await call("resume");
          if (report(r)) apply(r.view);
        },
      })
    );
  } else {
    right = btn(T.pause, {
      icon: "pause",
      act: true,
      why: v.can_pause ? "" : v.pause_why,
      fkey: "pause",
      tipLeft: true,
      onClick: (event, b) =>
        openMenu(
          b,
          v.pause_options.map((opt) => ({
            label: opt.label,
            icon: opt.id === "indefinite" ? "pause" : "clock",
            onClick: async () => {
              const r = await call("pause", opt.id);
              if (report(r)) apply(r.view);
            },
          }))
        ),
    });
    right.append(ico("chevron-down", "icon-sm"));
  }
  const parts = [el("div", { class: "overview" }, left, right)];
  if (v.pause.paused) parts.push(el("div", { class: "panel-foot" }, v.pause.detail));
  return parts;
}

function renderCurrent(v) {
  const a = v.activity;
  const headActions = a ? badge(a.label, "accent", true) : null;
  let body;
  if (a) {
    const bar = el("div", { class: "progress" + (a.percent === null ? " indeterminate" : ""), role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": a.percent === null ? null : a.percent, "aria-label": a.label }, el("span", { style: "width:" + (a.percent || 0) + "%" }));
    body = el(
      "div",
      { class: "activity" },
      el("div", { class: "activity-top" }, el("span", { class: "activity-name", text: a.step || a.label }), a.percent !== null ? el("span", { class: "activity-pct", text: a.percent + " %" }) : null),
      bar,
      el("div", { class: "activity-meta" }, el("span", { text: a.count }), el("span", { text: a.started }))
    );
  } else {
    body = el(
      "div",
      { class: "row", style: "min-height:4.25rem" },
      el("div", { class: "status-mark" }, ico("clock", "icon-lg")),
      el("div", { class: "grow" }, el("div", { class: "status-title", text: T.idle_title }), v.next_text ? el("div", { class: "status-detail", text: v.next_text }) : null)
    );
  }
  return [
    el("div", { class: "panel-head" }, el("div", { class: "panel-title", text: T.status_current }), headActions),
    el("div", { class: "panel-body" }, body),
  ];
}

function renderCounters(cv) {
  const headRight = cv.result ? badge(cv.result.label, cv.result.tone, true) : null;
  const body = cv.items.length
    ? el(
        "div",
        { class: "kpis" },
        cv.items.map((k) => el("div", { class: "kpi" }, el("div", { class: "kpi-label", text: k.label }), el("div", { class: "kpi-value", "data-tone": k.tone, text: k.value.toLocaleString() })))
      )
    : el("div", { class: "panel-body muted sm", text: T.no_counters });
  return [
    el("div", { class: "panel-head" }, el("div", { class: "panel-title" }, el("span", { text: T.status_counters }), cv.caption ? el("span", { class: "panel-meta", text: cv.caption }) : null), headRight),
    body,
    cv.note ? el("div", { class: "panel-foot", text: cv.note }) : null,
  ];
}

function renderTasks(v, apply) {
  const head = el("div", { class: "panel-head" }, el("div", { class: "panel-title", text: T.status_tasks }));
  if (!v.tasks.length) return [head, el("div", { class: "panel-body muted sm", text: T.no_tasks })];
  const rows = v.tasks.map((t) =>
    el(
      "tr",
      {},
      el("td", { class: "task-name", text: t.label }),
      el("td", { title: t.last_title || null, text: t.last }),
      el("td", {}, badge(t.result.label, t.result.tone, true)),
      el("td", { title: t.next_title || null, text: t.next }),
      el(
        "td",
        { class: "actions" },
        btn(T.run_now, {
          size: "sm",
          icon: "play",
          why: t.can_run ? "" : t.why,
          fkey: "run:" + t.task,
          tipLeft: true,
          onClick: async () => {
            const busy = v.activity && v.activity.task !== t.task;
            const r = await call("run_task", t.task);
            if (report(r)) {
              if (busy) toast(T.run_queued, "info");
              apply(r.view);
            }
          },
        })
      )
    )
  );
  const table = el(
    "table",
    { class: "data-table" },
    el("thead", {}, el("tr", {}, el("th", { text: T.col_task }), el("th", { text: T.col_last }), el("th", { text: T.col_result }), el("th", { text: T.col_next }), el("th", { class: "actions" }, el("span", { class: "sr-only", text: T.run_now })))),
    el("tbody", {}, rows)
  );
  return [head, table];
}

/* --- Actividad ------------------------------------------------------------ */

function renderActivity(content, head, id) {
  const st = { cursor: "", rows: [], task: "", level: "" };
  const log = el("div", { class: "log", role: "log", "aria-live": "off", tabindex: "0" });
  const empty = el("div", {});
  const taskSel = select(S.filters.tasks, "", (v) => ((st.task = v), applyFilter()), { label: T.filter_task });
  const levelSel = select(S.filters.levels, "", (v) => ((st.level = v), applyFilter()), { label: T.filter_level });
  const live = el("span", { class: "live" }, el("span", { class: "dot pulse", "data-tone": "success" }), T.live);
  const copy = btn(T.copy, {
    icon: "copy",
    onClick: async () => {
      const text = st.rows.filter((r) => !r.node.hidden).map((r) => [r.data.title || r.data.clock, r.data.level.toUpperCase(), r.data.task || "-", r.data.text].join("  ")).join("\n");
      const r = await call("copy_text", text);
      report(r, T.copied);
    },
  });
  const folder = btn(T.open_folder, { icon: "folder-open", onClick: async () => report(await call("open_log_folder")) });
  content.append(el("div", { class: "toolbar" }, taskSel, levelSel, el("div", { class: "grow" }), live, copy, folder));
  const box = panel({ flush: true, body: [skeleton(6)] });
  content.append(box);
  const body = box.querySelector(".panel-body");

  function matches(row) {
    const taskOk = !st.task || (st.task === "-" ? !row.task : row.task === st.task);
    return taskOk && (!st.level || row.level === st.level);
  }
  function applyFilter() {
    let visible = 0;
    for (const r of st.rows) {
      r.node.hidden = !matches(r.data);
      if (!r.node.hidden) visible += 1;
    }
    showEmpty(visible);
  }
  function showEmpty(visible) {
    if (!st.rows.length) empty.replaceChildren(emptyState({ icon: "scroll-text", text: T.log_empty }));
    else if (!visible) empty.replaceChildren(emptyState({ icon: "search", text: T.log_filtered_empty }));
    else empty.replaceChildren();
    log.hidden = !visible;
  }
  function rowNode(r) {
    const levelIcon = { warning: ["triangle-alert", "tone-warning"], error: ["circle-x", "tone-danger"], info: ["info", "tone-neutral"] }[r.level];
    return el(
      "div",
      { class: "log-row", "data-level": r.level },
      el("span", { class: "log-time", title: r.title || null, text: r.clock }),
      el("span", { class: "log-level " + levelIcon[1], title: r.level }, ico(levelIcon[0], "icon-sm")),
      el("span", { class: "log-task", text: r.task ? r.task_label : "" }),
      el("span", { class: "log-text", text: r.text })
    );
  }
  let first = true;
  const refresh = async () => {
    const r = await call("log", st.cursor);
    if (!alive(id)) return;
    if (!r.ok) {
      if (first) body.replaceChildren(errorState(r.message, refresh));
      return;
    }
    if (first) {
      body.replaceChildren(log, empty);
      first = false;
    }
    const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    for (const data of r.view.rows) {
      const node = rowNode(data);
      node.hidden = !matches(data);
      st.rows.push({ data, node });
      log.append(node);
    }
    while (st.rows.length > 2000) st.rows.shift().node.remove();
    st.cursor = r.view.cursor;
    showEmpty(st.rows.filter((x) => !x.node.hidden).length);
    if ((atBottom || r.view.rows.length === st.rows.length) && r.view.rows.length) log.scrollTop = log.scrollHeight;
  };
  refresh();
  poll(refresh, 1500);
}

/* --- Importar de NetBox --------------------------------------------------- */

function renderNetbox(content, head, id) {
  const host = el("div", { class: "stack" }, panel({ body: skeleton(4) }));
  content.append(host);
  call("netbox_poll").then((r) => {
    if (!alive(id)) return;
    if (r.ok && (r.state === "running" || r.state === "done" || r.state === "error")) showProgress(host, id, r);
    else showForm(host, id);
  });
}

function showForm(host, id) {
  const url = input({ placeholder: T.nb_url_ph, value: S.nbUrl, mono: true, fkey: "nb-url" });
  url.addEventListener("input", () => (S.nbUrl = url.value));
  const token = input({ type: "password", fkey: "nb-token" });
  const insecure = el("input", { type: "checkbox" });
  insecure.checked = S.nbInsecure;
  insecure.addEventListener("change", () => (S.nbInsecure = insecure.checked));
  const testResult = el("div", { class: "grow" });
  const test = btn(T.nb_test, {
    icon: "plug",
    onClick: async () => {
      testResult.replaceChildren();
      const r = await call("netbox_test", url.value, token.value, insecure.checked);
      testResult.replaceChildren(resultBox(r.ok ? "success" : "danger", r.ok ? r.message : r.message || T.error_title));
    },
  });
  const step1 = panel({
    title: T.nb_step_source,
    titlePrefix: el("span", { class: "step-num", text: "1" }),
    body: el(
      "div",
      { class: "stack" },
      el("div", { class: "form-grid" }, field(T.nb_url, url), field(T.nb_token, token, T.nb_token_help)),
      el("label", { class: "check" }, insecure, el("span", { text: T.nb_insecure })),
      el("div", { class: "form-actions" }, test, testResult)
    ),
  });

  const choice = (mode, icon, title, text) => {
    const c = el(
      "button",
      { type: "button", class: "choice", role: "radio", "aria-checked": S.nbMode === mode ? "true" : "false", "data-fkey": "nb-mode:" + mode },
      el("span", { class: "radio" }),
      el("span", {}, el("span", { class: "choice-title row" }, ico(icon, "icon-sm"), title), el("span", { class: "choice-text", text }))
    );
    c.addEventListener("click", () => {
      S.nbMode = mode;
      choices.querySelectorAll(".choice").forEach((x) => x.setAttribute("aria-checked", x === c ? "true" : "false"));
    });
    return c;
  };
  const choices = el("div", { class: "choices", role: "radiogroup", "aria-label": T.nb_step_destination }, choice("send", "send", T.nb_send, T.nb_send_hint), choice("save", "save", T.nb_save, T.nb_save_hint));
  const error = el("div", {});
  const read = btn(T.nb_read, {
    variant: "primary",
    icon: "database",
    act: true,
    onClick: async () => {
      error.replaceChildren();
      let path = "";
      if (S.nbMode === "save") {
        const chosen = await call("netbox_choose_file");
        if (!chosen.ok || !chosen.path) return;
        path = chosen.path;
      }
      const r = await call("netbox_start", url.value, token.value, insecure.checked, S.nbMode, path);
      if (!r.ok) {
        if (r.error === "forbidden") refreshShell();
        error.replaceChildren(resultBox("danger", r.message));
        return;
      }
      token.value = ""; // usado: fuera del formulario
      showProgress(host, id, { state: "running", mode: S.nbMode, progress: { rows: [], percent: null } });
    },
  });
  const step2 = panel({
    title: T.nb_step_destination,
    titlePrefix: el("span", { class: "step-num", text: "2" }),
    body: el("div", { class: "stack" }, choices, error, el("div", { class: "form-actions" }, read)),
  });
  host.replaceChildren(step1, step2);
}

function showProgress(host, id, first) {
  const box = el("div", { class: "panel" });
  host.replaceChildren(box);
  const render = (r) => {
    patch(box, r, () => {
      const p = r.progress || { rows: [], percent: null };
      if (r.state === "running") {
        return [
          el("div", { class: "panel-head" }, el("div", { class: "panel-title" }, ico("loader", "spin tone-accent"), el("span", { text: T.nb_reading })), p.percent !== null && p.percent !== undefined ? el("span", { class: "activity-pct", text: p.percent + " %" }) : null),
          el(
            "div",
            { class: "panel-body stack" },
            el("div", { class: "progress" + (p.percent === null || p.percent === undefined ? " indeterminate" : ""), role: "progressbar", "aria-label": T.nb_progress }, el("span", { style: "width:" + (p.percent || 0) + "%" })),
            p.rows.length ? collectionList(p.rows) : null,
            el("div", { class: "field-hint row" }, ico("shield-check", "icon-sm"), T.nb_token_cleared)
          ),
        ];
      }
      if (r.state === "error") {
        return [
          el("div", { class: "panel-head" }, el("div", { class: "panel-title", text: T.nav_netbox })),
          el("div", { class: "panel-body stack" }, resultBox("danger", r.message), el("div", { class: "form-actions" }, btn(T.nb_again, { icon: "rotate-cw", onClick: reset }))),
        ];
      }
      const sm = r.summary || { rows: [], total: "" };
      const ending =
        r.mode === "send"
          ? btn(T.nb_open_review, { variant: "primary", icon: "external-link", onClick: async () => report(await call("open_link", "review")) })
          : btn(T.nb_show_file, { variant: "primary", icon: "folder-open", onClick: async () => report(await call("show_file", sm.path)) });
      return [
        el("div", { class: "panel-head" }, el("div", { class: "panel-title" }, ico("circle-check", "tone-success"), el("span", { text: T.nb_done_title }), el("span", { class: "panel-meta", text: sm.total }))),
        el(
          "div",
          { class: "panel-body stack" },
          resultBox("success", sm.message),
          el("ul", { class: "checklist" }, sm.rows.map((row) => el("li", {}, ico("check", "tone-success"), el("span", { class: "mono", text: row.name }), el("span", { class: "count", text: Number(row.count).toLocaleString() })))),
          el("div", { class: "form-actions" }, ending, btn(T.nb_again, { variant: "ghost", icon: "rotate-cw", onClick: reset }))
        ),
      ];
    });
  };
  async function reset() {
    await call("netbox_reset");
    showForm(host, id);
  }
  render(first);
  const timer = setInterval(async () => {
    if (!alive(id)) return clearInterval(timer);
    const r = await call("netbox_poll");
    if (!alive(id)) return clearInterval(timer);
    if (!r.ok) return;
    render(r);
    if (r.state !== "running") clearInterval(timer);
  }, 700);
  S.timers.push(timer);
}

function collectionList(rows) {
  return el(
    "ul",
    { class: "checklist" },
    rows.map((row) =>
      el("li", {}, row.state === "reading" ? ico("loader", "spin tone-accent") : ico("check", "tone-success"), el("span", { class: "mono", text: row.name }), el("span"))
    )
  );
}

/* --- Herramientas --------------------------------------------------------- */

function toolCard(icon, title, text, controls, result) {
  return el(
    "div",
    { class: "panel" },
    el(
      "div",
      { class: "panel-body stack" },
      el("div", { class: "tool-head" }, el("div", { class: "tool-icon" }, ico(icon)), el("div", { class: "grow" }, el("div", { class: "tool-title", text: title }), el("div", { class: "tool-text", text }))),
      controls,
      result
    )
  );
}

function renderTools(content) {
  // Analizar una IP
  const ip = input({ placeholder: T.probe_ph, mono: true, fkey: "probe-ip" });
  const probeResult = el("div", {});
  const runProbe = async () => {
    probeResult.replaceChildren();
    const r = await call("probe", ip.value);
    if (!r.ok) {
      if (r.error === "forbidden") refreshShell();
      probeResult.replaceChildren(resultBox("danger", r.message));
      return;
    }
    probeResult.replaceChildren(el("div", {}, r.view.rows.map((row) => el("div", { class: "proto" }, el("span", { class: "proto-name", text: row.protocol }), el("span", { class: "result-text", text: row.text })))));
  };
  const probeBtn = btn(T.probe_button, { variant: "primary", icon: "search", act: true, onClick: runProbe });
  ip.addEventListener("keydown", (e) => e.key === "Enter" && probeBtn.click());
  const probe = toolCard("search", T.probe_title, T.probe_body, el("div", { class: "inline-form" }, ip, probeBtn), probeResult);

  // Probar la conexión con el portal
  const connResult = el("div", {});
  const conn = toolCard(
    "globe",
    T.conn_test_title,
    T.conn_test_body,
    el(
      "div",
      { class: "form-actions" },
      btn(T.conn_test_button, {
        icon: "plug",
        act: true,
        onClick: async () => {
          connResult.replaceChildren();
          const r = await call("test_connection");
          if (!r.ok) {
            if (r.error === "forbidden") refreshShell();
            connResult.replaceChildren(resultBox("danger", r.message));
            return;
          }
          const marks = { ok: ["circle-check", "tone-success"], fail: ["circle-x", "tone-danger"], skip: ["circle-minus", "tone-neutral"] };
          connResult.replaceChildren(
            el(
              "div",
              { class: "stack" },
              el("ul", { class: "checklist" }, r.view.steps.map((s) => el("li", {}, ico(marks[s.state][0], marks[s.state][1]), el("div", {}, el("div", { class: "strong", text: s.label }), s.detail ? el("div", { class: "detail selectable", text: s.detail }) : null), el("span")))),
              resultBox(r.view.ok ? "success" : "warning", r.view.summary)
            )
          );
        },
      })
    ),
    connResult
  );

  // Autocomprobación
  const selfResult = el("div", {});
  const self = toolCard(
    "clipboard-check",
    T.selftest_title,
    T.selftest_body,
    el(
      "div",
      { class: "form-actions" },
      btn(T.selftest_button, {
        icon: "clipboard-check",
        onClick: async () => {
          selfResult.replaceChildren();
          const r = await call("selftest");
          if (!r.ok) {
            selfResult.replaceChildren(resultBox("danger", r.message || T.error_title));
            return;
          }
          const v = r.view;
          selfResult.replaceChildren(
            el(
              "div",
              { class: "stack" },
              resultBox(v.complete ? "success" : "warning", v.title),
              el("ul", { class: "checklist" }, v.rows.map((row) => el("li", {}, ico(row.ok ? "circle-check" : "circle-x", row.ok ? "tone-success" : "tone-danger"), el("div", {}, el("div", { class: "strong", text: row.label }), el("div", { class: "detail selectable", text: row.detail })), el("span"))))
            )
          );
        },
      })
    ),
    selfResult
  );

  // Paquete de soporte
  const bundleResult = el("div", {});
  const bundle = toolCard(
    "life-buoy",
    T.bundle_title,
    T.bundle_body,
    el(
      "div",
      { class: "form-actions" },
      btn(T.bundle_button, {
        icon: "save",
        act: true,
        onClick: async () => {
          bundleResult.replaceChildren();
          const r = await call("support_bundle");
          if (!r.ok) {
            if (r.error === "cancelled") return;
            if (r.error === "forbidden") refreshShell();
            bundleResult.replaceChildren(resultBox("danger", r.message));
            return;
          }
          bundleResult.replaceChildren(
            el("div", { class: "stack" }, resultBox("success", r.message), el("div", {}, btn(T.nb_show_file, { size: "sm", icon: "folder-open", onClick: async () => report(await call("show_file", r.path)) })))
          );
        },
      })
    ),
    bundleResult
  );
  content.append(el("div", { class: "tools" }, probe, conn, self, bundle));
}

/* --- Conexión ----------------------------------------------------------- */

function renderConnection(content, head, id) {
  const host = el("div", { class: "stack" }, panel({ body: skeleton(3) }));
  content.append(host);
  const load = async () => {
    const r = await call("connection");
    if (!alive(id)) return;
    if (!r.ok) {
      host.replaceChildren(panel({ body: errorState(r.message, load) }));
      return;
    }
    drawConnection(host, r.view);
  };
  load();
}

function drawConnection(host, v) {
  const redraw = (r) => {
    if (report(r) && r.view) drawConnection(host, r.view);
  };
  const network = [caPanel(v, redraw), proxyPanel(v, redraw)];
  if (!v.enrolled) {
    const text = input({ placeholder: T.enroll_placeholder, mono: true, fkey: "enroll" });
    const error = el("div", {});
    const go = btn(T.enroll_button, {
      variant: "primary",
      icon: "plug",
      act: true,
      onClick: async () => {
        error.replaceChildren();
        const r = await call("connect", text.value);
        if (!r.ok) {
          if (r.error === "forbidden") refreshShell();
          error.replaceChildren(resultBox("danger", r.message));
          return;
        }
        await refreshShell();
        drawConnection(host, r.view);
      },
    });
    text.addEventListener("keydown", (e) => e.key === "Enter" && go.click());
    const hero = el(
      "div",
      { class: "panel hero" },
      el(
        "div",
        { class: "panel-body" },
        el("div", { class: "tool-icon" }, ico("plug")),
        el("div", {}, el("div", { class: "hero-title", text: T.enroll_title }), el("div", { class: "muted sm", text: (S.shell && S.shell.enrollment) || T.enroll_body })),
        el("div", { class: "inline-form", style: "max-width:none" }, text, go),
        error
      )
    );
    const more = el("details", { class: "disclosure" }, el("summary", {}, ico("chevron-down", "icon-sm"), el("span", { text: T.proxy_title + " · " + T.ca_title })), el("div", { class: "stack", style: "margin-top:0.75rem" }, network));
    host.replaceChildren(hero, el("div", { class: "hero", style: "margin-top:0" }, more));
    setTimeout(() => text.focus(), 0);
    return;
  }
  const portal = panel({
    title: T.conn_portal,
    actions: v.portal_url ? btn(T.conn_open_portal, { size: "sm", variant: "ghost", icon: "external-link", onClick: async () => report(await call("open_link", "portal")) }) : null,
    body: el("dl", { class: "detail-list" }, el("dt", { text: T.conn_portal }), el("dd", { class: "mono", text: v.portal || "—" }), el("dt", { text: T.conn_name }), el("dd", { class: "strong", text: v.agent_name || "—" })),
  });
  const text = input({ placeholder: T.enroll_placeholder, mono: true, fkey: "change" });
  const changeError = el("div", {});
  const change = btn(T.enroll_button, {
    act: true,
    icon: "plug",
    onClick: async () => {
      changeError.replaceChildren();
      if (!text.value.trim()) {
        changeError.replaceChildren(resultBox("danger", T.enroll_missing));
        return;
      }
      const ok = await confirmDialog({ title: T.conn_change_confirm_title, text: fmt(T.conn_change_confirm_body, { portal: v.portal }), confirm: T.conn_change_confirm });
      if (!ok) return;
      const r = await call("connect", text.value);
      if (!r.ok) {
        if (r.error === "forbidden") refreshShell();
        changeError.replaceChildren(resultBox("danger", r.message));
        return;
      }
      text.value = "";
      toast(T.saved);
      refreshShell();
      drawConnection(host, r.view);
    },
  });
  const changePanel = panel({ title: T.conn_change_title, body: el("div", { class: "stack" }, el("div", { class: "muted sm", text: T.conn_change_body }), el("div", { class: "inline-form", style: "max-width:36rem" }, text, change), changeError) });
  const danger = panel({
    title: T.disconnect_title,
    body: el(
      "div",
      { class: "row", style: "justify-content:space-between;gap:1rem" },
      el("div", { class: "muted sm", style: "max-width:36rem", text: T.disconnect_body }),
      btn(T.disconnect_button, {
        variant: "danger",
        icon: "unplug",
        act: true,
        tipLeft: true,
        onClick: async () => {
          const ok = await confirmDialog({ title: T.disconnect_confirm_title, text: fmt(T.disconnect_confirm_body, { portal: v.portal }), confirm: T.disconnect_confirm, danger: true });
          if (!ok) return;
          const r = await call("disconnect");
          if (report(r)) {
            await refreshShell();
          }
        },
      })
    ),
  });
  host.replaceChildren(portal, changePanel, ...network, danger);
}

function caPanel(v, redraw) {
  return panel({
    title: T.ca_title,
    body: el(
      "div",
      { class: "stack" },
      el("div", { class: "muted sm", text: T.ca_body }),
      el(
        "div",
        { class: "row wrap" },
        v.ca_bundle ? el("span", { class: "badge mono", "data-tone": "accent", text: v.ca_bundle }) : el("span", { class: "subtle sm", text: T.ca_none }),
        el("div", { class: "grow" }),
        btn(T.ca_choose, { size: "sm", icon: "shield-check", act: true, onClick: async () => { const r = await call("choose_ca"); if (r.error !== "cancelled") redraw(r); } }),
        v.ca_bundle ? btn(T.ca_clear, { size: "sm", variant: "ghost", icon: "x", act: true, onClick: async () => redraw(await call("clear_ca")) }) : null
      )
    ),
  });
}

function proxyPanel(v, redraw) {
  const url = input({ placeholder: T.proxy_url_ph, value: v.proxy.url, mono: true, fkey: "proxy-url", disabled: !S.perms.can_act });
  const save = btn(T.save, { act: true, onClick: async () => redraw(await call("set_proxy", "manual", url.value)) });
  const manualRow = el("div", { class: "inline-form", style: "max-width:30rem" }, url, save);
  manualRow.hidden = v.proxy.mode !== "manual";
  const options = [
    { id: "system", label: T.proxy_system },
    { id: "manual", label: T.proxy_manual },
    { id: "none", label: T.proxy_none },
  ];
  const seg = segmented(options, v.proxy.mode, {
    act: true,
    label: T.proxy_title,
    fkey: "proxy",
    onChange: async (mode) => {
      if (mode === "manual") {
        seg.querySelectorAll("button").forEach((b) => b.setAttribute("aria-checked", b.textContent === T.proxy_manual ? "true" : "false"));
        manualRow.hidden = false;
        url.focus();
        return;
      }
      redraw(await call("set_proxy", mode, ""));
    },
  });
  return panel({ title: T.proxy_title, body: el("div", { class: "stack" }, seg, manualRow, el("div", { class: "field-hint", text: T.proxy_hint })) });
}

/* --- Ajustes ------------------------------------------------------------- */

function renderSettings(content, head, id) {
  const host = el("div", { class: "stack" }, panel({ body: skeleton(5) }));
  content.append(host);
  const load = async () => {
    const r = await call("settings");
    if (!alive(id)) return;
    if (!r.ok) {
      host.replaceChildren(panel({ body: errorState(r.message, load) }));
      return;
    }
    drawSettings(host, r.view);
  };
  load();
}

function drawSettings(host, v) {
  const redraw = (r) => {
    if (report(r) && r.view) drawSettings(host, r.view);
    return !!(r && r.ok);
  };
  const ex = v.exclusions;
  const add = input({ placeholder: T.excl_ph, mono: true, fkey: "excl", disabled: !v.can_act });
  const addError = el("div", {});
  const addIt = async (value) => {
    addError.replaceChildren();
    const r = await call("add_exclusion", value);
    if (!r.ok) {
      if (r.error === "forbidden") refreshShell();
      addError.replaceChildren(el("div", { class: "field-error" }, ico("circle-x", "icon-sm"), el("span", { text: r.message })));
      return;
    }
    drawSettings(host, r.view);
    const again = host.querySelector('[data-fkey="excl"]');
    if (again) again.focus();
  };
  const addBtn = btn(T.excl_add, { icon: "plus", act: true, onClick: () => addIt(add.value) });
  add.addEventListener("keydown", (e) => e.key === "Enter" && addBtn.click());
  const chips = ex.items.length
    ? el(
        "div",
        { class: "chips" },
        ex.items.map((item) => {
          const x = el("button", { type: "button", class: "chip-x", "aria-label": T.excl_remove + " " + item.value, "data-tip": v.can_act ? T.excl_remove : v.why, "aria-disabled": v.can_act ? null : "true" }, ico("x", "icon-sm"));
          x.addEventListener("click", async () => v.can_act && redraw(await call("remove_exclusion", item.value)));
          return el("span", { class: "chip" }, el("span", { class: "mono", text: item.value }), el("span", { class: "kind", text: item.kind_label }), x);
        })
      )
    : el("div", { class: "subtle sm", text: T.excl_empty });
  const suggestions = ex.suggestions.length
    ? el(
        "div",
        { class: "stack", style: "gap:0.375rem" },
        el("div", { class: "field-hint", text: T.excl_suggest }),
        el(
          "div",
          { class: "chips" },
          ex.suggestions.map((s) => {
            const b = el("button", { type: "button", class: "chip chip-add", "aria-disabled": v.can_act ? null : "true", "data-tip": v.can_act ? s.interface || null : v.why }, ico("plus", "icon-sm"), el("span", { class: "mono", text: s.value }));
            b.addEventListener("click", () => v.can_act && addIt(s.value));
            return b;
          })
        )
      )
    : null;
  const exclusions = panel({
    title: T.excl_title,
    body: el("div", { class: "stack" }, el("div", { class: "muted sm", text: T.excl_body }), chips, el("div", { class: "inline-form" }, add, addBtn), addError, suggestions),
  });

  const setting = (title, text, ...controls) => el("div", { class: "setting" }, el("div", {}, el("div", { class: "setting-title", text: title }), text ? el("div", { class: "setting-text", text }) : null), el("div", { class: "setting-control" }, controls));

  const g = v.gentleness;
  const gentle = setting(T.gentle_title, T.gentle_body, segmented(g.options, g.value, { act: true, fkey: "gentle", label: T.gentle_title, onChange: async (value) => redraw(await call("set_setting", "gentleness_cap", value)) }), g.effective ? el("div", { class: "field-hint", text: g.effective }) : null);

  const u = v.updates;
  const updates = setting(
    T.upd_title,
    null,
    segmented([{ id: "auto", label: T.upd_auto }, { id: "notify", label: T.upd_notify }], u.auto ? "auto" : "notify", { act: true, fkey: "upd", label: T.upd_title, onChange: async (value) => redraw(await call("set_setting", "auto_update", value === "auto")) }),
    el(
      "div",
      { class: "row wrap" },
      el("span", { class: "sm muted" }, T.upd_installed + " ", el("span", { class: "mono", style: "color:var(--fg)", text: u.installed })),
      el("span", { class: "subtle", text: "·" }),
      el("span", { class: "sm muted" }, T.upd_latest + " ", el("span", { class: "mono", style: "color:var(--fg)", text: u.latest })),
      u.checked ? el("span", { class: "subtle", text: "·" }) : null,
      u.checked ? el("span", { class: "sm muted", text: u.checked }) : null
    ),
    u.message ? el("div", { class: "field-hint upd-message tone-" + u.tone, role: "status", text: u.message }) : null,
    u.progress ? el("div", { class: "field-hint upd-message tone-" + u.tone, role: "status", text: u.progress }) : null,
    btn(T.upd_check, { size: "sm", icon: "rotate-cw", act: true, onClick: async () => redraw(await call("check_update")) })
  );

  const s = v.service;
  const svcButtons = el(
    "div",
    { class: "row wrap" },
    badge(s.label, s.tone, true),
    btn(T.svc_start, { size: "sm", icon: "play", why: s.why, disabled: !s.can_start, onClick: async () => serviceDo("start") }),
    btn(T.svc_stop, { size: "sm", icon: "pause", why: s.why, disabled: !s.can_stop, onClick: async () => serviceDo("stop") }),
    btn(T.svc_restart, { size: "sm", icon: "rotate-cw", why: s.why, disabled: !s.can_restart, onClick: async () => serviceDo("restart") })
  );
  async function serviceDo(action) {
    const r = await call("service_action", action);
    if (report(r)) {
      setTimeout(async () => {
        const again = await call("settings");
        if (again.ok) drawSettings(host, again.view);
        refreshShell();
      }, 1200);
    }
  }
  const auto = el("label", { class: "check", style: "align-items:center" }, sw(s.autostart, { why: s.can_autostart ? "" : s.why, label: T.svc_autostart, fkey: "autostart", onChange: async (on) => redraw(await call("set_autostart", on)) }), el("span", { class: "sm", text: T.svc_autostart }));
  const service = setting(T.svc_title, null, svcButtons, auto);

  const tray = setting(T.tray_title, T.tray_hint, sw(v.tray.enabled, { why: v.tray.can_change ? "" : v.tray.why, label: T.tray_title, fkey: "tray", onChange: async (on) => redraw(await call("set_tray_startup", on)) }));
  const notif = setting(T.notif_title, T.notif_hint, sw(v.notifications, { act: true, label: T.notif_title, fkey: "notif", onChange: async (on) => redraw(await call("set_setting", "notifications", on)) }));
  const lang = setting(
    T.lang_title,
    null,
    select(v.language.options, v.language.value, async (code) => {
      const r = await call("set_language", code);
      if (!report(r)) return;
      T = r.strings;
      S.filters = r.filters;
      renderNav();
      renderBanner();
      mountSection();
    }, { label: T.lang_title, fkey: "lang" })
  );
  host.replaceChildren(exclusions, el("div", { class: "panel" }, gentle, updates, service, tray, notif, lang));
}

/* --- Acerca de ----------------------------------------------------------- */

function renderAbout(content, head, id) {
  const host = el("div", { class: "stack" }, panel({ body: skeleton(4) }));
  content.append(host);
  call("about").then((r) => {
    if (!alive(id)) return;
    const v = r.ok ? r.view : { version: S.version, hostname: "", system: "", repo: "" };
    const logo = el("div", { class: "about-logo" });
    logo.innerHTML = brandTileSvg();
    host.replaceChildren(
      panel({
        body: el(
          "div",
          { class: "stack", style: "gap:1.25rem" },
          el("div", { class: "about-head" }, logo, el("div", {}, el("div", { class: "about-name", text: "Cenya Agent" }), el("div", { class: "muted sm mono", text: v.version }))),
          el("p", { class: "muted sm", style: "max-width:40rem", text: T.about_body }),
          el(
            "dl",
            { class: "detail-list" },
            el("dt", { text: T.about_version }),
            el("dd", { class: "mono", text: v.version }),
            el("dt", { text: T.about_license }),
            el("dd", { text: T.about_license_value }),
            v.hostname ? [el("dt", { text: T.about_machine }), el("dd", { text: v.hostname })] : null,
            v.system ? [el("dt", { text: T.about_system }), el("dd", { text: v.system })] : null
          ),
          el(
            "div",
            { class: "row wrap" },
            btn(T.about_repo, { icon: "code", onClick: async () => report(await call("open_link", "repo")) }),
            btn(T.about_data, { icon: "file-text", onClick: async () => report(await call("open_link", "data_doc")) })
          )
        ),
        foot: T.about_icons,
      })
    );
  });
}

/* --- Start ---------------------------------------------------------------- */

let started = false;

async function start() {
  if (started || !window.pywebview || !window.pywebview.api || !window.pywebview.api.init) return;
  started = true;
  $("brand-mark").innerHTML = brandSvg();
  const r = await call("init");
  if (!r.ok) return;
  T = r.strings;
  S.version = r.version;
  S.dev = r.dev;
  S.filters = r.filters;
  $("brand-version").textContent = r.version;
  if (r.section && SECTIONS.some((s) => s.id === r.section)) S.section = r.section;
  await refreshShell(true);
  renderNav();
  mountSection();
  setInterval(() => refreshShell(), 3000);
  document.addEventListener("keydown", (e) => {
    if (!e.ctrlKey || e.altKey || e.shiftKey) return;
    const sections = SECTIONS.filter((s) => !s.sep);
    const n = Number(e.key);
    if (n >= 1 && n <= sections.length) {
      e.preventDefault();
      go(sections[n - 1].id);
    }
  });
}

window.addEventListener("pywebviewready", start);
document.addEventListener("DOMContentLoaded", () => setTimeout(start, 0));
