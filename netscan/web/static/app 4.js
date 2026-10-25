// netScan dashboard. Vanilla ES modules, no build step.
import { buildHelp } from "/help.js";
import { createExtra } from "/extra.js";
import { createUpdates } from "/updates.js";
import { createSpoof } from "/spoof.js";
import { createIdentify } from "/identify.js";
import { createNetworks } from "/networks.js";
// Every piece of data from the network (hostnames, vendors) is inserted with textContent via h(),
// never innerHTML, so a device cannot inject markup into this page.

const TOKEN_KEY = "netscan.token";
const state = {
  token: localStorage.getItem(TOKEN_KEY) || "",
  status: null, devices: [], blocks: [], jobs: [], schedules: [], events: [], config: null, rules: [], alerts: null, update: null, bootId: "", selected: new Set(),
  skew: 0, tab: "devices", online: true, lastJobStates: {}, filter: "all", search: "", sort: { key: "ip", dir: 1 },
};

// ---------- helpers ----------
// Element.append turns null/undefined/false into the text "null"/"undefined"/"false", so conditional children
// (`cond ? node : null`) passed straight to append() would print that word on the page. Drop them instead.
const nativeAppend = Element.prototype.append;
Element.prototype.append = function append(...nodes) {
  return nativeAppend.apply(this, nodes.filter((n) => n !== null && n !== undefined && n !== false));
};

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "value" || k === "checked" || k === "disabled" || k === "selected") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  const add = (kid) => {
    if (kid === null || kid === undefined || kid === false) return;
    if (Array.isArray(kid)) kid.forEach(add);
    else el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  };
  kids.forEach(add);
  return el;
}
const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
const nowSec = () => Date.now() / 1000 + state.skew;

function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, nowSec() - ts);
  if (s < 10) return "just now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function fmtTime(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function fmtDur(sec) {
  sec = Math.round(sec);
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.round(sec / 60)} min`;
  if (sec < 86400) { const v = sec / 3600; return `${Number.isInteger(v) ? v : v.toFixed(1)} h`; }
  return `${Math.round(sec / 86400)} d`;
}
function until(ts) {
  if (!ts) return "-";
  const s = ts - nowSec();
  if (s <= 1) return "due now";
  return `in ${fmtDur(s)}`;
}
function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${v} B` : `${v.toFixed(1)} ${units[i]}`;
}
const label = (d) => d.name || d.hostname || d.vendor || "Unknown device";
const isProtected = (d) => !!state.status?.network && (d.ip === state.status.network.gateway || d.ip === state.status.network.ip);

// ---------- api ----------
async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { Authorization: `Bearer ${state.token}`, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error page */ }
  if (res.status === 401) { state.token = ""; localStorage.removeItem(TOKEN_KEY); renderLogin("That access token was not accepted."); throw new Error("unauthorised"); }
  if (!res.ok) throw new Error(data?.error || `${res.status} ${res.statusText}`);
  return data;
}
const act = async (fn, okMsg) => {
  try { const r = await fn(); if (okMsg) toast(okMsg); await refresh(); return r; } catch (e) { if (e.message !== "unauthorised") toast(e.message, true); return null; }
};

// ---------- toast + modal ----------
function toast(msg, isError = false) {
  const t = h("div", { class: `toast${isError ? " error" : ""}`, role: isError ? "alert" : "status" }, msg);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), isError ? 8000 : 4500);
}
function closeModal() { clear(document.getElementById("overlay")); }
function modal({ title, body, actions = [], wide = false }) {
  const overlay = clear(document.getElementById("overlay"));
  const foot = h("footer", {}, actions.map((a) => h("button", { class: `btn ${a.kind || ""}`, type: "button", onclick: a.onClick, disabled: a.disabled }, a.label)));
  const box = h("div", { class: `modal${wide ? " wide" : ""}`, role: "dialog", "aria-modal": "true", "aria-label": title },
    h("header", {}, h("h2", {}, title), h("button", { class: "btn small ghost", "aria-label": "Close", onclick: closeModal }, "Close")),
    body, actions.length ? foot : null);
  const scrim = h("div", { class: "scrim", onmousedown: (e) => { if (e.target === scrim) closeModal(); } }, box);
  overlay.append(scrim);
  const first = box.querySelector("input, select, button.primary");
  if (first) first.focus();
  return box;
}
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target?.tagName || "");
  if (e.key === "?" && !typing && shell) { e.preventDefault(); openHelp(); }
});
function openHelp() {
  modal({ title: "How to use netScan", body: buildHelp(h), actions: [{ label: "Close", onClick: closeModal }], wide: true });
}

function field(labelText, control, hint) {
  return h("div", { class: "field" }, h("label", {}, labelText), control, hint ? h("span", { class: "hint" }, hint) : null);
}
// number + unit selector; value kept in seconds
function unitField(labelText, seconds, units, hint, min = 0) {
  let unit = units.slice().reverse().find((u) => seconds >= u[1] && seconds % u[1] === 0) || units[0];
  if (seconds === 0) unit = units[0];
  const num = h("input", { class: "input", type: "number", min, step: "any", value: String(seconds / unit[1]) });
  const sel = h("select", { class: "input" }, units.map((u) => h("option", { value: u[1], selected: u === unit }, u[0])));
  return { el: field(labelText, h("div", { class: "row" }, num, sel), hint), get: () => Math.round(Number(num.value) * Number(sel.value)) };
}
const UNITS_SHORT = [["seconds", 1], ["minutes", 60], ["hours", 3600], ["days", 86400]];

// ---------- login ----------
function renderLogin(message) {
  stopPolling();
  const app = clear(document.getElementById("app"));
  const input = h("input", { class: "input", type: "password", placeholder: "Access token", autocomplete: "off", "aria-label": "Access token" });
  const go = () => { state.token = input.value.trim(); if (!state.token) return; localStorage.setItem(TOKEN_KEY, state.token); start(); };
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  app.append(h("div", { class: "card login" },
    h("h2", {}, "netScan"),
    h("p", { class: "muted" }, "Enter the dashboard access token. It was printed when the dashboard started and lives in ", h("code", {}, "web_token"), " in the netScan data directory (on the Pi: ", h("code", {}, "/var/lib/netscan/web_token"), ")."),
    message ? h("div", { class: "callout bad" }, message) : null,
    input, h("button", { class: "btn primary", onclick: go }, "Open dashboard")));
  input.focus();
}

// ---------- shell ----------
const TABS = [
  ["devices", "Devices"], ["presence", "Presence"], ["security", "Security"], ["traffic", "Traffic"], ["schedule", "Schedule"], ["activity", "Activity"], ["blocks", "Access"], ["system", "System"],
];
let shell = null;
const views = {};

function buildShell() {
  const app = clear(document.getElementById("app"));
  const chips = h("div", { class: "chips" });
  const tabs = h("nav", { class: "tabs", role: "tablist" });
  const main = h("main", { id: "main" });
  const updateBox = h("div", { id: "update-banner" });
  app.append(h("header", { class: "topbar" }, h("span", { class: "brand" }, "netScan"), chips, h("span", { class: "grow" }),
    h("button", { class: "btn small", "aria-haspopup": "dialog", title: "How to use netScan (press ? anywhere)", onclick: openHelp }, "Help"),
    h("button", { class: "btn small ghost", onclick: () => { state.token = ""; localStorage.removeItem(TOKEN_KEY); renderLogin(); } }, "Sign out")), tabs, updateBox, main);
  shell = { chips, tabs, main, updateBox, tabButtons: {} };
  for (const [id, name] of TABS) {
    const count = h("span", { class: "count hidden" });
    const b = h("button", { class: "tab", role: "tab", "aria-selected": "false", onclick: () => selectTab(id) }, name, count);
    shell.tabButtons[id] = { b, count };
    tabs.append(b);
  }
}
function selectTab(id) {
  state.tab = id;
  location.hash = id;
  for (const [tid, { b }] of Object.entries(shell.tabButtons)) b.setAttribute("aria-selected", String(tid === id));
  clear(shell.main);
  views[id].mount(shell.main);
  views[id].update();
}
function updateShell() {
  const s = state.status;
  clear(shell.updateBox).append(updates.banner());
  const chips = clear(shell.chips);
  if (!state.online) chips.append(h("span", { class: "chip bad" }, "Cannot reach netScan"));
  if (s) {
    chips.append(h("span", { class: `chip ${s.ready ? "good" : "bad"}` }, s.ready ? "Ready" : "Not ready"));
    if (s.network) chips.append(h("span", { class: "chip" }, `${s.network.network} on ${s.network.interface}`), h("span", { class: "chip" }, `gateway ${s.network.gateway || "?"}`));
    chips.append(h("span", { class: "chip" }, s.daemon ? "daemon mode" : "local mode"));
    if (!s.privileged) chips.append(h("span", { class: "chip warn", title: "Raw sockets need root (sudo) or CAP_NET_RAW. Scans fall back to a slower method; capture, ARP watch and blocking are unavailable." }, "limited: not root"));
    if (s.active_jobs.length) chips.append(h("span", { class: "chip warn" }, h("span", { class: "spinner" }), `${s.active_jobs.length} job${s.active_jobs.length > 1 ? "s" : ""}`));
    shell.tabButtons.devices.count.textContent = String(s.counts.devices);
    shell.tabButtons.devices.count.classList.toggle("hidden", !s.counts.devices);
    shell.tabButtons.blocks.count.textContent = String(s.counts.blocked);
    shell.tabButtons.blocks.count.classList.toggle("hidden", !s.counts.blocked);
  }
}

// ---------- shared widgets ----------
function setupCard() {
  const s = state.status;
  if (!s || s.ready) return null;
  const body = [h("h3", {}, s.configured ? "netScan cannot start scanning" : "Set up netScan for this network"), h("p", {}, s.error || "No configuration found.")];
  if (!s.configured) {
    const follow = h("input", { type: "checkbox", id: "f-follow" });
    body.push(h("p", { class: "muted" }, "This detects your subnet, pins your router's MAC (so the config refuses to run on any other network) and writes the allow-list. netScan will only scan or block inside it."));
    body.push(h("div", { class: "field inline" }, follow, h("label", { for: "f-follow" }, "I move between networks (laptop): work on whichever private network I am connected to, and do not pin the router")));
    body.push(h("button", { class: "btn primary", onclick: () => act(() => api("POST", "/api/init", { follow_network: follow.checked }), "Config written") }, "Detect my network and create config"));
  } else {
    body.push(h("button", { class: "btn", onclick: () => act(() => api("POST", "/api/refresh"), "Network re-detected") }, "Try again"));
  }
  return h("div", { class: "callout bad" }, body);
}

function scanModal() {
  const timeout = h("input", { class: "input", type: "number", min: 1, max: 30, step: "any", value: "3" });
  const names = h("input", { type: "checkbox", checked: true, id: "f-names" });
  const offline = unitField("Mark missing devices offline after", 0, UNITS_SHORT.slice(0, 3), "0 means any device that does not answer this sweep is marked offline straight away.");
  const cap = h("input", { class: "input", type: "number", min: 0, max: 3600, value: "0" });
  modal({
    title: "Scan options",
    body: h("div", {},
      field("Wait for replies (seconds)", timeout, "How long to wait for ARP answers. Longer finds sleepy devices."),
      h("div", { class: "field inline" }, names, h("label", { for: "f-names" }, "Look up hostnames (reverse DNS)")),
      offline.el,
      field("Then capture traffic metadata for (seconds)", cap, "0 skips capture. Needs root, and only sees traffic that passes this machine.")),
    actions: [
      { label: "Cancel", onClick: closeModal },
      { label: "Scan", kind: "primary", onClick: async () => {
        closeModal();
        await act(() => api("POST", "/api/scan", { timeout: Number(timeout.value), hostnames: names.checked, offline_after: offline.get(), capture_seconds: Number(cap.value) || 0 }), "Scan queued");
      } }],
  });
}

function blockModal(dev) {
  const reason = h("input", { class: "input", placeholder: "Reason (optional), e.g. bedtime", maxlength: 200 });
  const s = state.status;
  modal({
    title: `Block ${dev.ip}?`,
    body: h("div", {},
      h("p", {}, `${label(dev)} (${dev.mac}) will lose network access.`),
      s.block_method === "arp" ? h("div", { class: "callout" }, "ARP cutoff holds only while the enforcer runs. ",
        s.services.enforce.running ? "It is running." : "It is not running; start it under System after blocking.") : null,
      field("Reason", reason)),
    actions: [
      { label: "Cancel", onClick: closeModal },
      { label: "Block device", kind: "danger solid", onClick: async () => {
        closeModal();
        const r = await act(() => api("POST", "/api/block", { target: dev.mac, reason: reason.value }), `Blocked ${dev.ip}`);
        if (r?.note) toast(r.note);
      } }],
  });
}
const unblock = (dev) => act(() => api("POST", "/api/unblock", { target: dev.mac }), `Unblocked ${dev.ip}`);

function statusCell(d) {
  if (d.blocked) return h("span", { class: "nowrap" }, h("span", { class: "dot blocked" }), "Blocked");
  return h("span", { class: "nowrap" }, h("span", { class: `dot${d.online ? " on" : ""}` }), d.online ? "Online" : "Offline");
}
function deviceActions(d, withDetails = true) {
  return h("div", { class: "actions" },
    withDetails ? h("button", { class: "btn small", onclick: (e) => { e.stopPropagation(); openDevice(d.mac); } }, "Details") : null,
    d.blocked
      ? (extra.isRuleBlock(d)
        ? h("button", { class: "btn small", disabled: true, title: "Held by a timetable or timer. Pause or delete it under Access to release." }, "Held by rule")
        : h("button", { class: "btn small", onclick: (e) => { e.stopPropagation(); if (!withDetails) closeModal(); unblock(d); } }, "Unblock"))
      : [
        h("button", { class: "btn small danger", disabled: isProtected(d), title: isProtected(d) ? "The gateway and this machine are never blocked" : "", onclick: (e) => { e.stopPropagation(); blockModal(d); } }, "Block"),
        withDetails ? null : h("button", { class: "btn small danger", disabled: isProtected(d), onclick: (e) => { e.stopPropagation(); closeModal(); extra.quickBlockModal([d]); } }, "Block for..."),
      ]);
}

async function openDevice(mac) {
  {
    let data;
    try { data = await api("GET", `/api/devices/${encodeURIComponent(mac)}`); } catch (e) { toast(e.message, true); return; }
    const d = data.device;
    const ex = extra.deviceExtras(data);
    const body = h("div", {},
      ex.top,
      h("dl", { class: "kv" },
        h("dt", {}, "Status"), h("dd", {}, statusCell(d)),
        d.owner ? [h("dt", {}, "Owner"), h("dd", {}, d.owner)] : null,
        h("dt", {}, "IP"), h("dd", { class: "mono" }, d.ip),
        h("dt", {}, "MAC"), h("dd", { class: "mono" }, d.mac),
        h("dt", {}, "Vendor"), h("dd", {}, d.vendor || "-"),
        h("dt", {}, "Hostname"), h("dd", {}, d.hostname || "-"),
        h("dt", {}, "First seen"), h("dd", {}, fmtTime(d.first_seen)),
        h("dt", {}, "Last seen"), h("dd", {}, `${fmtTime(d.last_seen)} (${ago(d.last_seen)})`),
        d.block ? [h("dt", {}, "Blocked"), h("dd", {}, `${fmtTime(d.block.blocked_at)} via ${d.block.method}${d.block.reason ? ` - ${d.block.reason}` : ""}`)] : null),
      identify.identityBlock(data),
      identify.behaviourBlock(data),
      h("h3", { class: "muted" }, "Traffic metadata (no payloads)"),
      data.traffic.length ? trafficTable(data.traffic) : h("p", { class: "muted" }, "No traffic recorded for this device. ", state.status.capture_limits),
      h("h3", { class: "muted" }, "Recent events"),
      data.events.length ? h("ul", { class: "list" }, data.events.map((e) => h("li", {}, h("span", { class: "when" }, ago(e.ts)), h("span", { class: "body" }, h("span", { class: `badge ${e.kind}` }, e.kind), " ", e.message)))) : h("p", { class: "muted" }, "No events."),
      ex.bottom);
    const box = modal({ title: label(d), body, actions: [{ label: "Close", onClick: closeModal }], wide: true });
    box.querySelector("footer").prepend(deviceActions(d, false));
  }
}
function trafficTable(rows) {
  return h("div", { class: "tablewrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Dir", "Proto", "Service", "Peer", "Port", "Bytes", "Packets", "Last seen"].map((c) => h("th", {}, c)))),
    h("tbody", {}, rows.map((r) => h("tr", {},
      h("td", {}, r.direction), h("td", {}, r.proto), h("td", {}, r.service || "-"),
      h("td", {}, r.peer_host ? [r.peer_host, h("div", { class: "muted small mono" }, r.peer_ip)] : h("span", { class: "mono" }, r.peer_ip)),
      h("td", {}, r.peer_port || "-"), h("td", { class: "nowrap" }, fmtBytes(r.bytes)), h("td", {}, r.packets), h("td", { class: "nowrap" }, ago(r.last_seen)))))));
}

const updates = createUpdates({ h, clear, api, act, toast, state, ago, fmtTime, rerender: () => { if (shell) { updateShell(); views[state.tab].update(); } } });
const spoof = createSpoof({ h, clear, api, act, toast, state, fmtDur, fmtTime, label, rerender: () => { if (shell) views[state.tab].update(); } });
const identify = createIdentify({ h, clear, api, act, toast, closeModal, state, ago, fmtTime, fmtDur, fmtBytes, refresh: () => refresh(), rerender: () => { if (shell) views[state.tab].update(); } });
const networks = createNetworks({ h, clear, api, act, toast, state, refresh: () => refresh() });
const extra = createExtra({ h, clear, api, act, toast, modal, closeModal, field, state, ago, fmtTime, fmtDur, until, refresh: () => refresh(), openDevice: (m) => openDevice(m), label, isProtected });

// ---------- views ----------
views.devices = (() => {
  let setup, banner, bulk, summary, tbody, scanBtn, headRow, selAll, view, seg, shownRows = [];
  const FILTERS = [["all", "All"], ["online", "Online"], ["offline", "Offline"], ["blocked", "Blocked"], ["review", "Unreviewed"]];
  const sorters = {
    ip: (a, b) => a.ip.split(".").reduce((x, y) => x * 256 + Number(y), 0) - b.ip.split(".").reduce((x, y) => x * 256 + Number(y), 0),
    name: (a, b) => label(a).localeCompare(label(b)),
    seen: (a, b) => a.last_seen - b.last_seen,
    traffic: (a, b) => a.bytes - b.bytes,
  };
  return {
    mount(root) {
      view = this; setup = h("div"); banner = h("div"); bulk = h("div"); summary = h("span", { class: "muted" });
      scanBtn = h("button", { class: "btn primary", onclick: () => act(() => api("POST", "/api/scan", { hostnames: true, timeout: 3, offline_after: 0 }), "Scan queued") }, "Scan now");
      const search = h("input", { class: "input", type: "search", placeholder: "Search name, owner, ip, mac, vendor", "aria-label": "Search devices", value: state.search, oninput: (e) => { state.search = e.target.value; this.update(); } });
      seg = h("div", { class: "seg" }, FILTERS.map(([id, name]) => h("button", { "data-filter": id, "aria-pressed": String(state.filter === id), onclick: () => { state.filter = id; this.update(); } }, name)));
      selAll = h("input", { type: "checkbox", "aria-label": "Select all shown devices", onchange: (e) => { for (const d of shownRows) { if (e.target.checked) state.selected.add(d.mac); else state.selected.delete(d.mac); } view.update(); } });
      headRow = h("tr", {}, [[selAll, null], ["Status", null], ["Device", "name"], ["IP", "ip"], ["MAC", null], ["Last seen", "seen"], ["Traffic", "traffic"], ["", null]].map(([n, key]) =>
        h("th", { class: key ? "sortable" : "", onclick: key ? () => { state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : 1 }; this.update(); } : null }, n)));
      tbody = h("tbody");
      root.append(setup, banner, h("div", { class: "toolbar" }, scanBtn, h("button", { class: "btn", onclick: scanModal }, "Scan options"), search, seg, h("span", { class: "grow" }), summary),
        bulk, h("div", { class: "card tablewrap" }, h("table", {}, h("thead", {}, headRow), tbody)));
    },
    update() {
      const s = state.status; if (!s) return;
      clear(setup); const sc = setupCard(); if (sc) setup.append(sc);
      const scanning = s.active_jobs.some((j) => j.kind === "sweep");
      clear(scanBtn).append(scanning ? [h("span", { class: "spinner" }), " Scanning"] : "Scan now");
      scanBtn.disabled = scanning || !s.ready;
      const q = state.search.trim().toLowerCase();
      let rows = state.devices.filter((d) => {
        if (state.filter === "online" && (!d.online || d.blocked)) return false;
        if (state.filter === "offline" && (d.online || d.blocked)) return false;
        if (state.filter === "blocked" && !d.blocked) return false;
        if (state.filter === "review" && d.trust !== "unknown") return false;
        return !q || [d.ip, d.mac, d.vendor, d.hostname, d.name, d.owner, d.category].some((v) => (v || "").toLowerCase().includes(q));
      });
      rows = rows.slice().sort((a, b) => sorters[state.sort.key](a, b) * state.sort.dir);
      shownRows = rows;
      summary.textContent = `${s.counts.online} online, ${s.counts.offline} offline, ${s.counts.blocked} blocked`;
      const known = new Set(state.devices.map((d) => d.mac));
      for (const m of [...state.selected]) if (!known.has(m)) state.selected.delete(m);
      [...seg.children].forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.filter === state.filter)));
      clear(banner); const rb = extra.reviewBanner(() => { state.filter = "review"; view.update(); }); if (rb && state.filter !== "review") banner.append(rb);
      clear(bulk); if (state.selected.size) bulk.append(extra.bulkBar(state.selected, () => { state.selected.clear(); view.update(); }));
      selAll.checked = rows.length > 0 && rows.every((d) => state.selected.has(d.mac));
      clear(tbody);
      if (!rows.length) {
        tbody.append(h("tr", {}, h("td", { colspan: 8 }, h("div", { class: "empty" }, state.devices.length
          ? h("h3", {}, "No devices match")
          : [h("h3", {}, "No devices yet"), h("p", {}, "Run a scan to discover what is on your network."), h("button", { class: "btn primary", disabled: !s.ready, onclick: () => act(() => api("POST", "/api/scan", { hostnames: true, timeout: 3, offline_after: 0 }), "Scan queued") }, "Scan now")]))));
        return;
      }
      for (const d of rows) {
        const pick = h("input", { type: "checkbox", checked: state.selected.has(d.mac), "aria-label": `Select ${label(d)}`, disabled: isProtected(d),
          onchange: (e) => { if (e.target.checked) state.selected.add(d.mac); else state.selected.delete(d.mac); view.update(); } });
        pick.addEventListener("click", (e) => e.stopPropagation());
        const sub = [d.owner, d.name && d.hostname && d.name !== d.hostname ? d.hostname : (d.name ? null : d.vendor), d.category || (d.guess_category ? `${d.guess_category}?` : "")].filter(Boolean).join(" · ");
        tbody.append(h("tr", { class: "clickable", onclick: () => openDevice(d.mac) },
          h("td", { class: "selcell", onclick: (e) => e.stopPropagation() }, pick),
          h("td", {}, statusCell(d)),
          h("td", {}, h("div", {}, label(d), isProtected(d) ? [" ", h("span", { class: "badge" }, d.ip === s.network?.gateway ? "gateway" : "this machine")] : null, " ", extra.trustBadges(d), d.blocked && extra.isRuleBlock(d) ? [" ", h("span", { class: "badge blocked", title: d.block.reason }, "timetable")] : null), sub ? h("div", { class: "muted small" }, sub) : null),
          h("td", { class: "mono nowrap" }, d.ip), h("td", { class: "mono nowrap hide-sm" }, d.mac),
          h("td", { class: "nowrap", title: fmtTime(d.last_seen) }, ago(d.last_seen)),
          h("td", { class: "nowrap hide-sm" }, d.packets ? `${fmtBytes(d.bytes)}` : "-"),
          h("td", {}, deviceActions(d))));
      }
    },
  };
})();

views.presence = extra.presenceView;
views.security = extra.securityView;

views.traffic = (() => {
  let info, form, list;
  return {
    mount(root) {
      info = h("div"); list = h("div", { class: "card" });
      const dur = h("input", { class: "input", type: "number", min: 1, max: 3600, value: "30", "aria-label": "Capture seconds" });
      form = h("div", { class: "card" }, h("h2", {}, "Capture traffic metadata"),
        h("p", { class: "muted" }, "Records addresses, ports and sizes per device. Payloads are never stored."),
        h("div", { class: "row" }, dur, h("span", { class: "muted" }, "seconds"),
          h("button", { class: "btn primary", onclick: () => act(() => api("POST", "/api/traffic", { duration: Number(dur.value) }), "Capture queued") }, "Capture now")));
      root.append(info, form, list);
    },
    update() {
      const s = state.status; if (!s) return;
      clear(info).append(h("div", { class: "callout warn" }, s.capture_limits),
        !s.privileged ? h("div", { class: "callout bad" }, "Capture needs root (sudo) or CAP_NET_RAW. Restart netScan with those privileges.") : null,
        s.services.capture.running ? h("div", { class: "callout" }, "Continuous capture is running; counters below update live.") : null);
      clear(list).append(h("h2", {}, "Per-device totals"));
      const rows = state.devices.filter((d) => d.packets).sort((a, b) => b.bytes - a.bytes);
      if (!rows.length) { list.append(h("div", { class: "empty" }, "No traffic recorded yet.")); return; }
      const max = rows[0].bytes || 1;
      list.append(h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Device", "IP", "Share", "Bytes", "Packets", ""].map((c) => h("th", {}, c)))),
        h("tbody", {}, rows.map((d) => { const fill = h("span"); fill.style.width = `${Math.max(2, (d.bytes / max) * 100)}%`;
          return h("tr", { class: "clickable", onclick: () => openDevice(d.mac) }, h("td", {}, label(d)), h("td", { class: "mono" }, d.ip), h("td", {}, h("div", { class: "bar" }, fill)), h("td", { class: "nowrap" }, fmtBytes(d.bytes)), h("td", {}, d.packets), h("td", {}, deviceActions(d))); })))));
    },
  };
})();

function describeRule(s) {
  if (s.kind === "interval") return `Every ${fmtDur(s.every_seconds)}`;
  if (s.kind === "daily") return `Daily at ${s.at_time} (${state.status?.tz || "device"} time)`;
  return `Once at ${fmtTime(s.run_at)}`;
}
function paramChips(p) {
  const chips = [`wait ${p.timeout}s`, p.hostnames ? "hostnames on" : "no hostnames", p.offline_after ? `offline after ${fmtDur(p.offline_after)}` : "offline immediately"];
  if (p.capture_seconds) chips.push(`capture ${p.capture_seconds}s`);
  return h("div", { class: "params" }, chips.map((c) => h("span", { class: "chip" }, c)));
}

function scheduleModal(existing) {
  const s = state.status;
  const p = existing?.params || { timeout: 3, hostnames: true, offline_after: state.config?.daemon.offline_after ?? 900, capture_seconds: 0 };
  const name = h("input", { class: "input", maxlength: 60, value: existing?.name || "Timed sweep" });
  const kind = h("select", { class: "input" }, [["interval", "Repeat every..."], ["daily", "Every day at..."], ["once", "Once at..."]].map(([v, n]) => h("option", { value: v, selected: (existing?.kind || "interval") === v }, n)));
  const every = unitField("Repeat every", existing?.every_seconds || 3600, UNITS_SHORT.slice(1), "Minimum 30 seconds.", 0);
  const daily = h("input", { class: "input", type: "time", value: existing?.at_time || "03:00" });
  const dailyField = field(`Time of day (${s?.tz || "device"} clock)`, daily, "Uses the clock of the machine running netScan, not your browser.");
  const toLocalInput = (ts) => { const d = new Date(ts * 1000); const pad = (n) => String(n).padStart(2, "0"); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; };
  const once = h("input", { class: "input", type: "datetime-local", value: toLocalInput(existing?.run_at || nowSec() + 3600) });
  const onceField = field("Date and time", once, "Your browser's local time.");
  const timeout = h("input", { class: "input", type: "number", min: 1, max: 30, step: "any", value: String(p.timeout) });
  const names = h("input", { type: "checkbox", checked: p.hostnames, id: "s-names" });
  const offline = unitField("Mark missing devices offline after", p.offline_after, UNITS_SHORT.slice(0, 3), "0 marks any device missing from this sweep offline immediately. Use a few sweep intervals to avoid flapping.");
  const cap = h("input", { class: "input", type: "number", min: 0, max: 3600, value: String(p.capture_seconds) });
  const enabled = h("input", { type: "checkbox", checked: existing ? existing.enabled : true, id: "s-en" });
  const runNow = h("input", { type: "checkbox", id: "s-now" });
  const sync = () => { every.el.classList.toggle("hidden", kind.value !== "interval"); dailyField.classList.toggle("hidden", kind.value !== "daily"); onceField.classList.toggle("hidden", kind.value !== "once"); };
  kind.addEventListener("change", sync);
  const preset = (n, k, secs, at) => h("button", { class: "btn small", type: "button", onclick: () => { kind.value = k; sync(); if (secs) { every.el.querySelector("input").value = secs >= 3600 ? secs / 3600 : secs / 60; every.el.querySelector("select").value = secs >= 3600 ? 3600 : 60; } if (at) daily.value = at; } }, n);
  const body = h("div", {},
    h("div", { class: "presets" }, preset("Every 5 min", "interval", 300), preset("Hourly", "interval", 3600), preset("Every 6 h", "interval", 21600), preset("Nightly 03:00", "daily", 0, "03:00")),
    field("Name", name), field("When", kind), every.el, dailyField, onceField,
    h("h3", { class: "muted" }, "Sweep parameters"),
    field("Wait for replies (seconds)", timeout),
    h("div", { class: "field inline" }, names, h("label", { for: "s-names" }, "Look up hostnames (reverse DNS)")),
    offline.el,
    field("Then capture traffic metadata for (seconds)", cap, "0 skips capture. Needs root and only sees traffic that passes this machine."),
    h("div", { class: "field inline" }, enabled, h("label", { for: "s-en" }, "Enabled")),
    existing ? null : h("div", { class: "field inline" }, runNow, h("label", { for: "s-now" }, "Also run once right now")));
  sync();
  modal({
    title: existing ? "Edit timed sweep" : "New timed sweep", body,
    actions: [{ label: "Cancel", onClick: closeModal }, { label: existing ? "Save" : "Create", kind: "primary", onClick: async () => {
      const payload = {
        name: name.value, kind: kind.value, enabled: enabled.checked,
        params: { timeout: Number(timeout.value), hostnames: names.checked, offline_after: offline.get(), capture_seconds: Number(cap.value) || 0 },
      };
      if (kind.value === "interval") payload.every_seconds = every.get();
      if (kind.value === "daily") payload.at_time = daily.value;
      if (kind.value === "once") payload.run_at = new Date(once.value).getTime() / 1000;
      if (!existing && runNow.checked) payload.run_now = true;
      try {
        await api(existing ? "PUT" : "POST", existing ? `/api/schedules/${existing.id}` : "/api/schedules", payload);
        closeModal(); toast(existing ? "Schedule saved" : "Schedule created"); await refresh();
      } catch (e) { if (e.message !== "unauthorised") toast(e.message, true); }
    } }],
  });
}

views.schedule = (() => {
  let list;
  return {
    mount(root) {
      list = h("div");
      root.append(h("div", { class: "toolbar" }, h("button", { class: "btn primary", onclick: () => scheduleModal(null) }, "New timed sweep"),
        h("span", { class: "muted" }, "Timed sweeps run on this machine, even when no browser is open.")), list);
    },
    update() {
      clear(list);
      const s = state.status;
      if (s && !s.privileged) list.append(h("div", { class: "callout warn" }, "Not running as root: timed sweeps use the slower fallback scan, and timed capture is unavailable."));
      if (!state.schedules.length) {
        list.append(h("div", { class: "card empty" }, h("h3", {}, "No timed sweeps yet"), h("p", {}, "Create one to sweep automatically, for example every 5 minutes or nightly at 03:00."),
          h("button", { class: "btn primary", onclick: () => scheduleModal(null) }, "New timed sweep")));
        return;
      }
      const grid = h("div", { class: "grid2" });
      for (const sc of state.schedules) {
        const running = state.jobs.some((j) => j.source === `schedule:${sc.id}` && (j.state === "queued" || j.state === "running"));
        grid.append(h("div", { class: "card sched" },
          h("div", { class: "head" }, h("span", { class: "title grow" }, sc.name), h("span", { class: `badge ${sc.enabled ? "on" : ""}` }, sc.enabled ? "enabled" : "paused")),
          h("div", {}, describeRule(sc)), paramChips(sc.params),
          h("dl", { class: "kv" },
            h("dt", {}, "Next run"), h("dd", {}, sc.enabled && sc.next_run ? `${until(sc.next_run)} (${fmtTime(sc.next_run)})` : "-"),
            h("dt", {}, "Last run"), h("dd", {}, sc.last_run ? [ago(sc.last_run), " ", sc.last_status ? h("span", { class: `badge ${sc.last_status}` }, sc.last_status) : null, sc.last_message ? h("div", { class: "muted small" }, sc.last_message) : null] : "never")),
          h("div", { class: "actions" },
            h("button", { class: "btn small", disabled: running || !s?.ready, onclick: () => act(() => api("POST", `/api/schedules/${sc.id}/run`), "Sweep queued") }, running ? "Running..." : "Run now"),
            h("button", { class: "btn small", onclick: () => act(() => api("PUT", `/api/schedules/${sc.id}`, { enabled: !sc.enabled }), sc.enabled ? "Paused" : "Resumed") }, sc.enabled ? "Pause" : "Resume"),
            h("button", { class: "btn small", onclick: () => scheduleModal(sc) }, "Edit"),
            h("button", { class: "btn small danger", onclick: () => { if (confirm(`Delete "${sc.name}"?`)) act(() => api("DELETE", `/api/schedules/${sc.id}`), "Deleted"); } }, "Delete"))));
      }
      list.append(grid);
    },
  };
})();

function describeSource(src) {
  if (src === "manual") return "manual";
  if (src === "startup") return "start-up";
  if (src === "auto") return "automatic";
  if (src.startsWith("schedule:")) { const sc = state.schedules.find((x) => `schedule:${x.id}` === src); return sc ? sc.name : "schedule"; }
  return src;
}
const JOB_NAMES = { sweep: "Scan", traffic: "Capture", update_oui: "Vendor update", update: "Update", spoof: "MAC change", unspoof: "MAC restore", dhcp: "DHCP check", ports: "Port check", identify: "Identify" };
function jobSummary(j) {
  const sm = j.summary || {};
  if (j.error) return j.error;
  if (j.kind === "sweep" && sm.seen !== undefined) {
    const bits = [`${sm.seen} devices`]; if (sm.new) bits.push(`${sm.new} new`); if (sm.online) bits.push(`${sm.online} back online`); if (sm.offline) bits.push(`${sm.offline} went offline`); if (sm.ip_changed) bits.push(`${sm.ip_changed} IP changed`);
    if (sm.baseline) bits.push("baseline recorded"); if (sm.mode === "nudge") bits.push("fallback scan"); if (sm.capture) bits.push(`captured ${sm.capture.packets} packets`);
    return bits.join(", ");
  }
  if (j.kind === "traffic" && sm.packets !== undefined) return `${sm.packets} packets, ${fmtBytes(sm.bytes)} across ${sm.devices} devices`;
  if (j.kind === "dhcp" && sm.offers !== undefined) return `${sm.offers} DHCP server${sm.offers === 1 ? "" : "s"} answered${sm.problems ? `, ${sm.problems} problem${sm.problems === 1 ? "" : "s"} found` : ", looks normal"}`;
  if (j.kind === "ports" && sm.devices !== undefined) return `${sm.devices} devices checked, ${sm.open} open ports${sm.findings ? `, ${sm.findings} new finding(s)` : ""}`;
  if (j.kind === "identify" && sm.devices !== undefined) return `${sm.devices} device${sm.devices === 1 ? "" : "s"} asked, ${sm.named} with a name`;
  if (j.kind === "update" && sm.to) return `${sm.from} to ${sm.to}${sm.restarting ? ", restarting" : ", restart netScan to use it"}`;
  if (j.kind === "spoof" && sm.mac) return `${sm.interface} now uses ${sm.mac}`;
  if (j.kind === "unspoof" && sm.mac) return `${sm.interface} is back to ${sm.mac}`;
  if (j.kind === "update_oui" && sm.prefixes) return `${sm.prefixes} vendor prefixes`;
  return "";
}
views.activity = (() => {
  let jobs, events;
  return {
    mount(root) { jobs = h("div", { class: "card" }); events = h("div", { class: "card" }); root.append(h("div", { class: "grid2" }, jobs, events)); },
    update() {
      clear(jobs).append(h("h2", {}, "Jobs"));
      if (!state.jobs.length) jobs.append(h("p", { class: "muted" }, "Nothing has run yet."));
      jobs.append(h("ul", { class: "list" }, state.jobs.map((j) => h("li", {},
        h("span", { class: "when", title: fmtTime(j.created) }, ago(j.created)),
        h("span", { class: "body" }, h("span", { class: `badge ${j.state}` }, j.state), " ", h("strong", {}, j.kind === "update_oui" ? "update vendors" : j.kind), h("span", { class: "muted" }, ` (${describeSource(j.source)})`),
          j.finished && j.started ? h("span", { class: "muted" }, ` ${fmtDur(j.finished - j.started)}`) : null,
          jobSummary(j) ? h("div", { class: "muted small" }, jobSummary(j)) : null),
        (j.state === "queued" || j.state === "running") ? h("button", { class: "btn small", onclick: () => act(() => api("POST", `/api/jobs/${j.id}/cancel`), "Cancel requested") }, "Cancel") : null))));
      clear(events).append(h("h2", {}, "Events"));
      if (!state.events.length) events.append(h("p", { class: "muted" }, "No events yet."));
      events.append(h("ul", { class: "list" }, state.events.map((e) => h("li", {},
        h("span", { class: "when", title: fmtTime(e.ts) }, ago(e.ts)),
        h("span", { class: "body" }, h("span", { class: `badge ${e.kind}` }, e.kind.replace("_", " ")), " ", e.message, e.ip ? h("div", { class: "muted small mono" }, `${e.ip} ${e.mac}`) : null)))));
    },
  };
})();

views.blocks = (() => {
  let info, form, table, pick, manual, rules;
  return {
    mount(root) {
      info = h("div"); table = h("div", { class: "card" }); rules = extra.rulesCard();
      pick = h("select", { class: "input", "aria-label": "Device to block" });
      manual = h("input", { class: "input", placeholder: "or type an ip / mac", "aria-label": "IP or MAC to block" });
      form = h("div", { class: "card" }, h("h2", {}, "Block a device now"),
        h("div", { class: "row" }, pick, manual, h("button", { class: "btn danger", onclick: () => {
          const target = manual.value.trim() || pick.value; if (!target) return;
          const dev = state.devices.find((d) => d.mac === target || d.ip === target) || { ip: target, mac: target, hostname: "", vendor: "" };
          blockModal(dev); } }, "Block...")));
      root.append(info, form, rules.el, h("div", {}, table));
    },
    update() {
      const s = state.status; if (!s) return;
      rules.update();
      clear(info);
      if (s.block_method === "arp") {
        info.append(h("div", { class: `callout${state.blocks.length && !s.services.enforce.running ? " warn" : ""}` },
          "ARP cutoff only holds while the enforcer runs. ", s.services.enforce.running ? "The enforcer is running." : "The enforcer is stopped.",
          " ", s.services.enforce.running ? null : h("button", { class: "btn small", disabled: !s.privileged, onclick: () => act(() => api("POST", "/api/services/enforce/start"), "Enforcer started") }, "Start enforcer")));
      } else info.append(h("div", { class: "callout" }, `Blocks use ${s.block_method} rules, which only work if this machine is your router.`));
      const keep = pick.value;
      clear(pick).append(h("option", { value: "" }, "Choose a device..."));
      state.devices.filter((d) => !d.blocked && !isProtected(d)).forEach((d) => pick.append(h("option", { value: d.mac, selected: d.mac === keep }, `${d.ip}  ${label(d)}`)));
      clear(table).append(h("h2", {}, "Blocked devices"));
      if (!state.blocks.length) { table.append(h("div", { class: "empty" }, "No blocked devices.")); return; }
      table.append(h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["IP", "MAC", "Method", "Since", "Reason", ""].map((c) => h("th", {}, c)))),
        h("tbody", {}, state.blocks.map((b) => { const d = state.devices.find((x) => x.mac === b.mac) || { ip: b.ip, mac: b.mac };
          return h("tr", {}, h("td", { class: "mono" }, b.ip), h("td", { class: "mono" }, b.mac), h("td", {}, b.method), h("td", {}, ago(b.blocked_at)), h("td", {}, b.reason || "-"),
            h("td", {}, h("div", { class: "actions" }, (b.reason || "").startsWith("rule: ")
              ? h("button", { class: "btn small", disabled: true, title: "Held by a timetable or timer. Pause or delete it above to release." }, "Held by rule")
              : h("button", { class: "btn small", onclick: () => unblock(d) }, "Unblock")))); })))));
    },
  };
})();

views.system = (() => {
  let setup, services, tools, cfg, about, alertsBox, updatesBox, spoofBox, identBox, netBox;
  return {
    mount(root) {
      setup = h("div"); services = h("div", { class: "card" }); tools = h("div", { class: "card" }); cfg = h("div", { class: "card" }); about = h("div", { class: "card" }); alertsBox = h("div"); updatesBox = h("div"); spoofBox = h("div"); identBox = h("div"); netBox = h("div");
      root.append(setup, netBox, h("div", { class: "grid2" }, services, tools), h("div", { class: "grid2" }, alertsBox, cfg), h("div", { class: "grid2" }, updatesBox, about), h("div", { class: "grid2" }, spoofBox, identBox));
      extra.loadAlerts().then(() => this.update());
      identify.loadSettings().then(() => { if (state.tab === "system") this.update(); });
      updates.load(true).then(() => { if (state.tab === "system") { updateShell(); this.update(); } });
      api("GET", "/api/config").then((c) => { state.config = c; this.update(); }).catch(() => {});
    },
    update() {
      const s = state.status; if (!s) return;
      clear(setup); const sc = setupCard(); if (sc) setup.append(sc);
      clear(services).append(h("h2", {}, "Background services"));
      for (const [name, sv] of Object.entries(s.services)) {
        services.append(h("div", { class: "service" },
          h("div", {}, h("strong", {}, sv.label), " ", h("span", { class: `badge ${sv.running ? "on" : ""}` }, sv.running ? "running" : "stopped"),
            h("div", { class: "muted small" }, sv.available ? sv.description : sv.unavailable_reason), sv.error ? h("div", { class: "small" }, h("span", { class: "badge error" }, "error"), ` ${sv.error}`) : null,
            sv.running && sv.since ? h("div", { class: "muted small" }, `since ${ago(sv.since)}`) : null),
          sv.running
            ? h("button", { class: "btn", onclick: () => act(() => api("POST", `/api/services/${name}/stop`), `${sv.label} stopped`) }, "Stop")
            : h("button", { class: "btn primary", disabled: !sv.available || !s.privileged || !s.ready, title: !s.privileged ? "Needs root or CAP_NET_RAW" : "", onclick: () => act(() => api("POST", `/api/services/${name}/start`), `${sv.label} started`) }, "Start")));
      }
      clear(tools).append(h("h2", {}, "Maintenance"),
        h("div", { class: "service" }, h("div", {}, h("strong", {}, "Vendor database"), h("div", { class: "muted small" }, "Download the latest IEEE registry so new vendors are recognised (needs internet).")),
          h("button", { class: "btn", onclick: () => act(() => api("POST", "/api/update-oui"), "Vendor update queued") }, "Update")),
        h("div", { class: "service" }, h("div", {}, h("strong", {}, "Re-detect network"), h("div", { class: "muted small" }, "Use after moving to another network or changing the router. Stop services first.")),
          h("button", { class: "btn", onclick: () => act(() => api("POST", "/api/refresh"), "Network re-detected") }, "Re-detect")));
      clear(alertsBox).append(extra.alertsCard());
      clear(updatesBox).append(updates.card());
      if (!spoofBox.contains(document.activeElement)) clear(spoofBox).append(spoof.card());
      { const nc = networks.card(); if (nc.parentNode !== netBox) netBox.append(nc); }
      if (!identBox.contains(document.activeElement)) clear(identBox).append(identify.card());
      const c = state.config;
      clear(cfg).append(h("h2", {}, "Configuration (edit in config.toml)"));
      if (c) cfg.append(h("dl", { class: "kv" },
        h("dt", {}, "Config file"), h("dd", { class: "mono" }, c.path),
        h("dt", {}, "Allow-list"), h("dd", {}, [...c.allowed_subnets, ...(c.follow_network ? ["whichever private network you are connected to"] : [])].join(", ") || "none"),
        h("dt", {}, "Gateway pin"), h("dd", { class: "mono" }, c.gateway_mac || "not pinned"),
        h("dt", {}, "Block method"), h("dd", {}, c.block_method),
        h("dt", {}, "Also protected"), h("dd", {}, c.extra_protected.join(", ") || "gateway and this machine only"),
        h("dt", {}, "Daemon"), h("dd", {}, `sweep ${fmtDur(c.daemon.sweep_interval)}, offline after ${fmtDur(c.daemon.offline_after)}, ARP watch ${c.daemon.arp_watch ? "on" : "off"}, capture ${c.daemon.capture_traffic ? "on" : "off"}`)));
      clear(about).append(h("h2", {}, "About"), h("dl", { class: "kv" },
        h("dt", {}, "Version"), h("dd", {}, s.version), h("dt", {}, "Mode"), h("dd", {}, s.daemon ? "daemon (sweeps, watch and enforcement run in the background)" : "local"),
        h("dt", {}, "Machine clock"), h("dd", {}, `${fmtTime(s.now)} ${s.tz}`)),
        h("p", { class: "muted small" }, s.notice));
    },
  };
})();

// ---------- data loop ----------
let timer = null;
function stopPolling() { if (timer) clearTimeout(timer); timer = null; }

async function refresh() {
  try {
    const [status, devices, blocks, jobs, schedules, events, rules] = await Promise.all([
      api("GET", "/api/status"), api("GET", "/api/devices"), api("GET", "/api/blocks"), api("GET", "/api/jobs?limit=25"), api("GET", "/api/schedules"), api("GET", "/api/events?limit=40"), api("GET", "/api/rules"),
    ]);
    if (state.bootId && status.boot_id && status.boot_id !== state.bootId) { location.reload(); return; }
    state.bootId = status.boot_id || "";
    if (state.update?.applying || status.active_jobs.some((j) => j.kind === "update")) await updates.load();
    Object.assign(state, { status, devices, blocks, jobs, schedules, events, rules, online: true, skew: status.now - Date.now() / 1000 });
    for (const j of jobs) {
      const prev = state.lastJobStates[j.id];
      if (prev && (prev === "queued" || prev === "running") && j.state !== prev && j.source === "manual") {
        toast(j.state === "done" ? `${JOB_NAMES[j.kind] || "Job"} finished: ${jobSummary(j)}` : `${j.kind} ${j.state}${j.error ? `: ${j.error}` : ""}`, j.state === "error");
      }
      state.lastJobStates[j.id] = j.state;
    }
  } catch (e) {
    if (e.message === "unauthorised") return;
    state.online = false;
  }
  if (!shell) return;
  updateShell();
  views[state.tab].update();
}
function schedulePoll() {
  stopPolling();
  if (!state.token) return;
  const busy = state.status?.active_jobs?.length;
  timer = setTimeout(async () => { await refresh(); schedulePoll(); }, busy ? 1200 : 4000);
}

async function start() {
  const hash = new URLSearchParams(location.hash.slice(1));
  let wanted = location.hash.slice(1);
  if (hash.get("token")) {
    state.token = hash.get("token"); localStorage.setItem(TOKEN_KEY, state.token);
    wanted = hash.get("tab") || "";
    history.replaceState(null, "", location.pathname + (wanted ? `#${wanted}` : ""));
  }
  if (!state.token) return renderLogin();
  buildShell();
  const want = TABS.find(([id]) => id === wanted);
  state.tab = want ? want[0] : "devices";
  try { await api("GET", "/api/status"); } catch (e) { if (e.message === "unauthorised") return; }
  try { state.config = await api("GET", "/api/config"); } catch { /* shown later */ }
  selectTab(state.tab);
  updates.load().then(() => { if (shell) updateShell(); });
  setInterval(() => { if (state.token) updates.load().then(() => { if (shell) updateShell(); }); }, 10 * 60 * 1000);
  await refresh();
  schedulePoll();
}
window.addEventListener("hashchange", () => { const id = location.hash.slice(1); if (shell && views[id] && id !== state.tab) selectTab(id); });
start();
