// Dashboard features beyond the core device list: labels and trust, block timers and timetables,
// presence, security checks and alert settings. Same rules as app.js: DOM is built with h() and
// textContent only, so data from the network can never inject markup.

export const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const CATEGORIES = ["", "phone", "computer", "tv", "media", "console", "speaker", "camera", "iot", "printer", "network", "server", "other"];
const KIND_TEXT = {
  new_device: "A new device joins the network",
  device_online: "A device comes back online",
  device_offline: "A device goes offline",
  ip_changed: "A device changes IP address",
  blocked: "A device is blocked",
  unblocked: "A device is unblocked",
  ip_conflict: "Two devices claim the same IP address",
  arp_spoof: "Something pretends to be your router",
  rogue_dhcp: "An unexpected DHCP server answers",
  port_opened: "A risky or newly opened port is found",
};
const SECURITY_KINDS = ["ip_conflict", "arp_spoof", "rogue_dhcp", "port_opened"];
const PRESETS_MIN = [["15 min", 15], ["30 min", 30], ["1 hour", 60], ["2 hours", 120], ["4 hours", 240], ["8 hours", 480]];

export const daysText = (days) => {
  const key = days.join(",");
  if (days.length === 7) return "Every day";
  if (key === "0,1,2,3,4") return "Mon to Fri";
  if (key === "5,6") return "Weekends";
  return days.map((d) => DAYS[d]).join(", ");
};

export function createExtra(ctx) {
  const { h, clear, api, act, toast, modal, closeModal, field, state, ago, fmtTime, fmtDur, until, refresh, openDevice, label, isProtected } = ctx;
  const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const nameOf = (mac) => { const d = state.devices.find((x) => x.mac === mac); return d ? label(d) : mac; };
  const isRuleBlock = (d) => !!d.blocked && (d.block?.reason || "").startsWith("rule: ");
  const runJob = async (path, body, okMsg) => act(() => api("POST", path, body), okMsg);

  // ---------- block for N minutes ----------
  function quickBlockModal(devs) {
    const targets = devs.filter((d) => !isProtected(d) && !d.blocked);
    if (!targets.length) { toast("Nothing to block: those devices are protected or already blocked.", true); return; }
    const num = h("input", { class: "input", type: "number", min: 1, step: 1, value: "30", "aria-label": "Duration" });
    const unit = h("select", { class: "input", "aria-label": "Unit" }, [["minutes", 1], ["hours", 60]].map(([n, v]) => h("option", { value: v }, n)));
    const preset = ([text, mins]) => h("button", { class: "btn small", type: "button", onclick: () => {
      if (mins % 60 === 0) { num.value = String(mins / 60); unit.value = "60"; } else { num.value = String(mins); unit.value = "1"; }
    } }, text);
    const who = targets.length === 1 ? label(targets[0]) : plural(targets.length, "device");
    modal({
      title: `Block ${who} for...`,
      body: h("div", {},
        h("div", { class: "presets" }, PRESETS_MIN.map(preset)),
        field("Block for", h("div", { class: "row" }, num, unit), "The block lifts by itself when the time is up (as long as netScan keeps running). Pause or delete it any time under Access."),
        targets.length > 1 ? h("p", { class: "muted small" }, targets.map(label).join(", ")) : null,
        state.status?.block_method === "arp" ? h("div", { class: "callout" }, "ARP cutoff needs the enforcer. netScan starts it for you when it can (needs root).") : null),
      actions: [{ label: "Cancel", onClick: closeModal }, { label: "Block", kind: "danger solid", onClick: async () => {
        const minutes = Math.round(Number(num.value) * Number(unit.value));
        closeModal();
        const r = await act(() => api("POST", "/api/rules/quick", { macs: targets.map((d) => d.mac), minutes }), null);
        if (r) toast(`Blocked ${plural(targets.length, "device")} until ${clock(r.until)}`);
      } }],
    });
  }

  // ---------- weekly timetable ----------
  function ruleModal(existing, presetMacs = []) {
    const chosen = new Set(existing ? existing.macs : presetMacs);
    const name = h("input", { class: "input", maxlength: 60, value: existing?.name || "", placeholder: "e.g. Kids' devices off at night" });
    const days = new Set(existing ? existing.days : [0, 1, 2, 3, 4, 5, 6]);
    const start = h("input", { class: "input", type: "time", value: existing?.start || "22:00" });
    const end = h("input", { class: "input", type: "time", value: existing?.end || "07:00" });
    const dayBtns = DAYS.map((n, i) => h("button", { type: "button", "aria-pressed": String(days.has(i)), onclick: (e) => {
      if (days.has(i)) days.delete(i); else days.add(i);
      e.currentTarget.setAttribute("aria-pressed", String(days.has(i)));
    } }, n));
    const setDays = (list) => { days.clear(); list.forEach((d) => days.add(d)); dayBtns.forEach((b, i) => b.setAttribute("aria-pressed", String(days.has(i)))); };
    const filter = h("input", { class: "input", type: "search", placeholder: "Filter devices", "aria-label": "Filter devices" });
    const list = h("div", { class: "picklist", role: "group", "aria-label": "Devices in this rule" });
    const candidates = state.devices.filter((d) => !isProtected(d) || chosen.has(d.mac));
    const drawList = () => {
      clear(list);
      const q = filter.value.trim().toLowerCase();
      for (const d of candidates) {
        if (q && ![d.name, d.ip, d.owner, d.vendor].some((v) => (v || "").toLowerCase().includes(q))) continue;
        const id = `rm-${d.mac}`;
        list.append(h("div", { class: "pick" },
          h("input", { type: "checkbox", id, checked: chosen.has(d.mac), onchange: (e) => { if (e.target.checked) chosen.add(d.mac); else chosen.delete(d.mac); } }),
          h("label", { for: id }, label(d), d.owner ? h("span", { class: "muted" }, ` (${d.owner})`) : null, h("span", { class: "muted mono small" }, `  ${d.ip}`))));
      }
      if (!list.firstChild) list.append(h("p", { class: "muted small" }, "No devices match."));
    };
    filter.addEventListener("input", drawList);
    drawList();
    const tz = state.status?.tz || "device";
    modal({
      title: existing ? "Edit timetable" : "New timetable",
      wide: true,
      body: h("div", {},
        field("Name", name),
        field("Devices", h("div", {}, filter, list), "These devices lose network access during the window and get it back afterwards."),
        field("Days", h("div", {}, h("div", { class: "seg wrap" }, dayBtns),
          h("div", { class: "presets", style: null }, [["Every day", [0, 1, 2, 3, 4, 5, 6]], ["School nights (Sun to Thu)", [6, 0, 1, 2, 3]], ["Weekends", [5, 6]]].map(([t, l]) =>
            h("button", { class: "btn small", type: "button", onclick: () => setDays(l) }, t)))),
          "A window that runs past midnight belongs to the day it starts on."),
        h("div", { class: "row" }, field("Block from", start), field("until", end)),
        h("p", { class: "muted small" }, `If "until" is earlier than "from" the block runs overnight (22:00 to 07:00 covers the night). Times use the clock of the machine running netScan (${tz}). Timetables are applied by the netScan dashboard process, so it must be running (the Pi service always is).`)),
      actions: [{ label: "Cancel", onClick: closeModal }, { label: existing ? "Save" : "Create timetable", kind: "primary", onClick: async () => {
        const payload = { name: name.value, kind: "window", macs: [...chosen], days: [...days].sort(), start: start.value, end: end.value };
        try {
          await api(existing ? "PUT" : "POST", existing ? `/api/rules/${existing.id}` : "/api/rules", payload);
          closeModal(); toast(existing ? "Timetable saved" : "Timetable created"); await refresh();
        } catch (e) { if (e.message !== "unauthorised") toast(e.message, true); }
      } }],
    });
  }

  function rulesCard() {
    const card = h("div", { class: "card" });
    const render = () => {
      clear(card).append(
        h("div", { class: "head-row" }, h("h2", {}, "Timetables and timers"), h("span", { class: "grow" }),
          h("button", { class: "btn small primary", onclick: () => ruleModal(null) }, "New timetable")),
        h("p", { class: "muted small" }, "Block devices on a weekly schedule, or for a set time. They are applied by the running netScan dashboard, and a manual block you placed yourself is never touched."));
      if (!state.rules.length) { card.append(h("div", { class: "empty" }, "No timetables or timers yet. Use \"Block for...\" on a device for a quick timer.")); return; }
      for (const r of state.rules) {
        const status = r.active ? h("span", { class: "badge blocked" }, "blocking now")
          : !r.enabled ? h("span", { class: "badge" }, "paused")
          : h("span", { class: "badge" }, r.next_transition ? `starts ${until(r.next_transition)}` : "waiting");
        const names = r.devices.map((d) => d.name);
        card.append(h("div", { class: "rule" },
          h("div", { class: "grow" },
            h("div", {}, h("strong", {}, r.name), " ", status),
            h("div", { class: "muted small" }, r.kind === "timer" ? `Timer until ${clock(r.until)} (${until(r.until)})` : `${daysText(r.days)}, ${r.start} to ${r.end}`),
            h("div", { class: "muted small" }, names.slice(0, 4).join(", ") + (names.length > 4 ? ` +${names.length - 4} more` : "")),
            r.warning ? h("div", { class: "small warn-text" }, r.warning) : null),
          h("div", { class: "actions" },
            r.kind === "window" ? h("button", { class: "btn small", onclick: () => act(() => api("PUT", `/api/rules/${r.id}`, { enabled: !r.enabled }), r.enabled ? "Paused" : "Resumed") }, r.enabled ? "Pause" : "Resume") : null,
            r.kind === "window" ? h("button", { class: "btn small", onclick: () => ruleModal(r) }, "Edit") : null,
            h("button", { class: "btn small danger", onclick: () => { if (confirm(`${r.kind === "timer" ? "Cancel" : "Delete"} "${r.name}"? Any devices it blocks are released.`)) act(() => api("DELETE", `/api/rules/${r.id}`), "Removed"); } }, r.kind === "timer" ? "Cancel" : "Delete"))));
      }
    };
    return { el: card, update: render };
  }

  // ---------- labels, owner, trust ----------
  function metaSection(d) {
    const lab = h("input", { class: "input", maxlength: 40, value: d.label || "", placeholder: d.hostname || d.vendor || "e.g. Dad's laptop" });
    const owner = h("input", { class: "input", maxlength: 40, value: d.owner || "", placeholder: "e.g. Mum" });
    const cat = h("select", { class: "input" }, CATEGORIES.map((c) => h("option", { value: c, selected: c === d.category }, c || "not set")));
    const trust = h("select", { class: "input" }, [["unknown", "Not reviewed"], ["known", "Known"], ["guest", "Guest"]].map(([v, n]) => h("option", { value: v, selected: v === d.trust }, n)));
    const alertMode = h("select", { class: "input" }, [["default", "Use my alert settings"], ["always", "Always alert about this device"], ["mute", "Never alert about this device"]].map(([v, n]) => h("option", { value: v, selected: v === d.alert }, n)));
    const track = h("input", { type: "checkbox", id: "m-track", checked: d.track });
    const notes = h("textarea", { class: "input", rows: 2, maxlength: 500, placeholder: "Anything worth remembering" }, d.notes || "");
    notes.value = d.notes || "";
    const save = h("button", { class: "btn primary", onclick: async () => {
      const payload = { label: lab.value, owner: owner.value, category: cat.value, trust: trust.value, alert: alertMode.value, track: track.checked, notes: notes.value };
      try { await api("PUT", `/api/devices/${encodeURIComponent(d.mac)}/meta`, payload); closeModal(); toast("Details saved"); await refresh(); } catch (e) { if (e.message !== "unauthorised") toast(e.message, true); }
    } }, "Save details");
    return h("div", {},
      h("h3", { class: "muted" }, "Name and owner"),
      h("div", { class: "formgrid" }, field("Name", lab), field("Owner", owner), field("Type", cat), field("Review status", trust, "Mark devices you recognise as Known."), field("Alerts", alertMode)),
      h("div", { class: "field inline" }, track, h("label", { for: "m-track" }, "Track presence (show on the Presence tab as home / away)")),
      field("Notes", notes), save);
  }

  const riskBadge = (p) => h("span", { class: `badge risk-${p.risk}`, title: p.why || p.service }, `${p.port} ${p.service}`);

  function portsSection(d, ports) {
    return h("div", {},
      h("h3", { class: "muted" }, "Open ports"),
      ports
        ? h("div", {}, ports.open.length ? h("div", { class: "params" }, ports.open.map(riskBadge)) : h("p", { class: "muted" }, "No common ports were open."),
          h("p", { class: "muted small" }, `Checked ${ago(ports.ts)}. Red marks services that are often misused or unprotected.`))
        : h("p", { class: "muted" }, "Not checked yet."),
      h("button", { class: "btn small", disabled: !state.status?.ready, onclick: async () => { closeModal(); await runJob("/api/security/ports", { macs: [d.mac] }, "Port check queued"); } }, ports ? "Check again" : "Check ports"));
  }

  function presenceStrip(segments, since, untilTs) {
    const total = untilTs - since;
    const el = h("div", { class: "strip", role: "img" });
    const piece = (cls, secs, title) => { const s = h("span", { class: cls, title: title || "" }); s.style.width = `${(secs / total) * 100}%`; return s; };
    let cursor = since, onSecs = 0;
    for (const s of segments) {
      if (s.start > cursor) el.append(piece("gap", s.start - cursor, "Not known yet"));
      el.append(piece(s.online ? "on" : "off", s.end - s.start, `${s.online ? "Online" : "Away"}: ${fmtTime(s.start)} to ${fmtTime(s.end)}`));
      if (s.online) onSecs += s.end - s.start;
      cursor = s.end;
    }
    if (cursor < untilTs) el.append(piece("gap", untilTs - cursor));
    el.setAttribute("aria-label", `Online ${fmtDur(onSecs)} of ${fmtDur(total)}`);
    return el;
  }

  function presenceSection(p) {
    return h("div", {},
      h("h3", { class: "muted" }, "Last 7 days"),
      p.segments.length ? [presenceStrip(p.segments, p.since, p.until), h("div", { class: "strip-axis" }, h("span", {}, "7 days ago"), h("span", {}, "now"))] : h("p", { class: "muted" }, "No history yet."),
      h("p", { class: "muted small" }, "Green is online, dark is away. Approximate: follows sweeps."));
  }

  function deviceExtras(data) {
    const d = data.device;
    return {
      top: [
        data.held_by_rule ? h("div", { class: "callout warn" }, `Blocked by the rule "${data.held_by_rule.name}". Pause or delete that rule on the Access tab to release it.`) : null,
        d.trust === "unknown" ? h("div", { class: "callout" }, "You have not reviewed this device yet. ",
          h("button", { class: "btn small", onclick: async () => { closeModal(); await act(() => api("POST", "/api/devices/review", { macs: [d.mac], trust: "known" }), "Marked as known"); } }, "Mark as known")) : null,
      ],
      bottom: [presenceSection(data.presence), portsSection(d, data.ports), metaSection(d)],
    };
  }

  // ---------- devices tab helpers ----------
  async function review(macs, trust, okMsg) { return act(() => api("POST", "/api/devices/review", { macs, trust }), okMsg); }

  function reviewBanner(onShow) {
    const n = state.status?.counts.unreviewed || 0;
    if (!n) return null;
    return h("div", { class: "callout" },
      h("strong", {}, plural(n, "device")), ` ${n === 1 ? "has" : "have"} not been reviewed. Mark the ones you recognise as known, so anything new stands out.`, " ",
      h("button", { class: "btn small", onclick: onShow }, "Show them"), " ",
      h("button", { class: "btn small", onclick: () => { if (confirm(`Mark all ${n} unreviewed devices as known? Only do this if you recognise every one of them.`)) act(() => api("POST", "/api/devices/review", { all_unreviewed: true, trust: "known" }), "All marked as known"); } }, "Mark all as known"));
  }

  function bulkBar(selected, clearSel) {
    const devs = () => state.devices.filter((d) => selected.has(d.mac));
    const bar = h("div", { class: "bulk", role: "toolbar", "aria-label": "Actions for selected devices" },
      h("strong", {}, `${selected.size} selected`),
      h("button", { class: "btn small danger", onclick: () => quickBlockModal(devs()) }, "Block for..."),
      h("button", { class: "btn small", onclick: () => ruleModal(null, devs().filter((d) => !isProtected(d)).map((d) => d.mac)) }, "Add to timetable..."),
      h("button", { class: "btn small", onclick: async () => { await review([...selected], "known", "Marked as known"); clearSel(); } }, "Mark known"),
      h("button", { class: "btn small", onclick: async () => { await review([...selected], "guest", "Marked as guests"); clearSel(); } }, "Mark guest"),
      h("button", { class: "btn small ghost", onclick: clearSel }, "Clear"));
    return bar;
  }

  const trustBadges = (d) => [
    d.trust === "guest" ? h("span", { class: "badge", title: "Marked as a guest device" }, "guest") : null,
    d.trust === "unknown" && nowAgo(d.first_seen) < 86400 ? h("span", { class: "badge warn", title: "First seen in the last 24 hours and not reviewed" }, "new") : null,
  ];
  const nowAgo = (ts) => Date.now() / 1000 + state.skew - ts;

  // ---------- presence tab ----------
  const presenceView = (() => {
    let toolbar, summary, rows, hours = 24, seq = 0;
    const trackModal = () => {
      const picks = new Map(state.devices.map((d) => [d.mac, d.track]));
      const list = h("div", { class: "picklist" }, state.devices.map((d) => {
        const id = `tr-${d.mac}`;
        return h("div", { class: "pick" }, h("input", { type: "checkbox", id, checked: d.track, onchange: (e) => picks.set(d.mac, e.target.checked) }),
          h("label", { for: id }, label(d), d.owner ? h("span", { class: "muted" }, ` (${d.owner})`) : null, h("span", { class: "muted mono small" }, `  ${d.ip}`)));
      }));
      modal({
        title: "Choose devices to track", body: h("div", {}, h("p", { class: "muted" }, "Tick the devices that tell you who is home, usually phones. Give them an owner in their details to group them."), list),
        actions: [{ label: "Cancel", onClick: closeModal }, { label: "Save", kind: "primary", onClick: async () => {
          const changes = state.devices.filter((d) => picks.get(d.mac) !== d.track);
          closeModal();
          try { for (const d of changes) await api("PUT", `/api/devices/${encodeURIComponent(d.mac)}/meta`, { track: picks.get(d.mac) }); toast("Tracking updated"); } catch (e) { toast(e.message, true); }
          await refresh();
        } }],
      });
    };
    return {
      mount(root) {
        summary = h("div"); rows = h("div", { class: "card" });
        const seg = h("div", { class: "seg" }, [[6, "6 h"], [24, "24 h"], [168, "7 d"], [720, "30 d"]].map(([v, n]) => h("button", { "aria-pressed": String(hours === v), onclick: (e) => {
          hours = v; [...seg.children].forEach((b) => b.setAttribute("aria-pressed", String(b === e.currentTarget))); this.update();
        } }, n)));
        toolbar = h("div", { class: "toolbar" }, h("button", { class: "btn primary", onclick: trackModal }, "Choose tracked devices"), seg);
        root.append(toolbar, summary, rows);
      },
      async update() {
        const mine = ++seq;
        let p;
        try { p = await api("GET", `/api/presence?hours=${hours}`); } catch { return; }
        if (mine !== seq || state.tab !== "presence") return;
        clear(summary);
        if (!p.devices.length) {
          clear(rows).append(h("div", { class: "empty" }, h("h3", {}, "Nobody is being tracked yet"),
            h("p", {}, "Pick the phones and laptops of the people you want to see as home or away."), h("button", { class: "btn primary", onclick: trackModal }, "Choose tracked devices")));
          return;
        }
        const owners = new Map();
        for (const d of p.devices) { const key = d.owner || d.name; const cur = owners.get(key) || { home: false, names: [] }; cur.home = cur.home || d.online; cur.names.push(d.name); owners.set(key, cur); }
        summary.append(h("div", { class: "card home" }, h("h2", {}, `${p.home} of ${p.tracked} tracked devices home`),
          h("div", { class: "params" }, [...owners].map(([who, o]) => h("span", { class: `chip ${o.home ? "good" : ""}`, title: o.names.join(", ") }, h("span", { class: `dot${o.home ? " on" : ""}` }), `${who}: ${o.home ? "home" : "away"}`)))));
        clear(rows).append(h("h2", {}, `Timeline, last ${fmtDur(p.hours * 3600)}`));
        for (const d of p.devices) {
          const pct = Math.round((d.online_seconds / Math.max(1, Math.min(p.until - p.since, p.until - d.first_seen))) * 100);
          rows.append(h("div", { class: "prow" },
            h("div", { class: "pname" }, h("div", {}, h("span", { class: `dot${d.online ? " on" : ""}` }), h("a", { href: "#", onclick: (e) => { e.preventDefault(); openDevice(d.mac); } }, d.name)),
              h("div", { class: "muted small" }, [d.owner, d.category, `${pct}% online`].filter(Boolean).join(" · "))),
            presenceStrip(d.segments, p.since, p.until)));
        }
        rows.append(h("div", { class: "strip-axis" }, h("span", {}, fmtTime(p.since)), h("span", {}, "now")), h("p", { class: "muted small" }, p.approximate));
      },
    };
  })();

  // ---------- security tab ----------
  const securityView = (() => {
    let box, seq = 0;
    const busy = (kind) => (state.status?.active_jobs || []).some((j) => j.kind === kind);
    const btn = (text, kind, onClick, disabledWhy) => h("button", { class: "btn", disabled: busy(kind) || !state.status?.ready || !!disabledWhy, title: disabledWhy || "", onclick: onClick }, busy(kind) ? [h("span", { class: "spinner" }), ` ${text}`] : text);
    const findingList = (sec) => {
      if (!sec.findings.length) return h("p", { class: "muted" }, "Nothing suspicious has been found so far.");
      return h("ul", { class: "list" }, sec.findings.map((f) => h("li", {},
        h("span", { class: "when", title: fmtTime(f.ts) }, ago(f.ts)),
        h("span", { class: "body" }, h("span", { class: "badge blocked" }, f.kind.replace("_", " ")), " ", f.message, f.name ? h("div", { class: "muted small" }, `${f.name} ${f.ip || ""}`) : null))));
    };
    const dhcpCard = (sec, s) => {
      const r = sec.last_dhcp;
      const body = [h("p", { class: "muted" }, "Your router should be the only thing handing out addresses. A second DHCP server (often a plugged-in extra router) can silently redirect your traffic. This sends one discovery broadcast and asks for no lease.")];
      body.push(btn("Check for rogue DHCP servers", "dhcp", () => runJob("/api/security/dhcp-probe", {}, "DHCP check started"), s.privileged ? "" : "Needs root (sudo)"));
      if (r) {
        body.push(h("p", { class: "muted small" }, `Last check ${ago(r.ts)}: ${plural(r.offers.length, "server")} answered.`));
        if (r.problems.length) body.push(h("div", { class: "callout bad" }, r.problems.map((p) => h("div", {}, p))));
        else body.push(h("div", { class: "callout" }, "Looks normal."));
        if (r.offers.length) body.push(h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Server", "MAC", "Offers IP", "Router", "DNS", "Lease"].map((c) => h("th", {}, c)))),
          h("tbody", {}, r.offers.map((o) => h("tr", {}, h("td", { class: "mono" }, o.server_ip), h("td", { class: "mono" }, o.server_mac || "-"), h("td", { class: "mono" }, o.offered_ip || "-"), h("td", { class: "mono" }, o.router || "-"), h("td", { class: "mono" }, o.dns.join(", ") || "-"), h("td", {}, o.lease ? fmtDur(o.lease) : "-")))))));
      }
      return h("div", { class: "card" }, h("h2", {}, "Rogue DHCP server check"), body);
    };
    const portsCard = (sec, s) => {
      const body = [h("p", { class: "muted" }, `Tries to connect to ${sec.ports_checked.length} common ports on each device on your own network (no passwords, nothing is sent beyond the connection). Red results are services that are often unprotected, such as Telnet, remote desktop or databases.`),
        h("div", { class: "row" }, btn("Check all online devices", "ports", () => { if (state.status.counts.online > sec.max_targets) { toast(`Too many online devices for one check (max ${sec.max_targets}). Check them from each device's details.`, true); return; } runJob("/api/security/ports", {}, "Port check started"); }),
          h("span", { class: "muted small" }, "Or open a device and press Check ports."))];
      if (!sec.port_scans.length) body.push(h("div", { class: "empty" }, "No port checks yet."));
      else body.push(h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Device", "IP", "Open ports", "Checked"].map((c) => h("th", {}, c)))),
        h("tbody", {}, sec.port_scans.map((p) => h("tr", { class: "clickable", onclick: () => openDevice(p.mac) }, h("td", {}, p.name), h("td", { class: "mono" }, p.ip),
          h("td", {}, p.open.length ? h("div", { class: "params" }, p.open.map(riskBadge)) : h("span", { class: "muted" }, "none")), h("td", { class: "nowrap" }, ago(p.ts))))))));
      return h("div", { class: "card" }, h("h2", {}, "Open ports"), body);
    };
    const watchCard = (sec, s) => h("div", { class: "card" }, h("h2", {}, "Always-on checks"),
      h("dl", { class: "kv" },
        h("dt", {}, "IP conflicts"), h("dd", {}, "Checked on every sweep: two devices answering for one address."),
        h("dt", {}, "Router impersonation"), h("dd", {}, sec.gateway_mac
          ? [sec.arp_watch ? h("span", { class: "badge on" }, "watching") : h("span", { class: "badge warn" }, "ARP watch is off"), ` Flags anyone other than ${sec.gateway_mac} claiming ${sec.gateway}. `,
            sec.arp_watch ? null : h("button", { class: "btn small", disabled: !s.privileged, onclick: () => runJob("/api/services/watch/start", undefined, "ARP watch started") }, "Start ARP watch")]
          : "Needs the router's MAC to be known (run a scan with network access)."),
        h("dt", {}, "New devices"), h("dd", {}, sec.unreviewed ? [`${plural(sec.unreviewed, "device")} not reviewed yet. `, h("a", { href: "#devices", onclick: () => { state.filter = "review"; } }, "Review them")] : "Every device has been reviewed.")));
    return {
      mount(root) { box = h("div"); root.append(box); },
      async update() {
        const mine = ++seq;
        let sec;
        try { sec = await api("GET", "/api/security"); } catch { return; }
        if (mine !== seq || state.tab !== "security") return;
        const s = state.status;
        clear(box).append(
          s && !s.privileged ? h("div", { class: "callout warn" }, "Not running as root: the DHCP check and ARP watch are unavailable. Port checks still work.") : null,
          h("div", { class: "grid2" }, watchCard(sec, s), h("div", { class: "card" }, h("h2", {}, "Findings"), findingList(sec))),
          h("div", { class: "grid2" }, dhcpCard(sec, s), portsCard(sec, s)));
      },
    };
  })();

  // ---------- alert settings ----------
  async function loadAlerts() { try { state.alerts = await api("GET", "/api/alerts"); } catch { /* shown as unavailable */ } }

  function alertsModal() {
    const a = state.alerts;
    const hook = h("input", { class: "input", type: "url", placeholder: a.webhook.configured ? "Leave blank to keep the current address" : "https://example.com/hook", autocomplete: "off" });
    const ntfy = h("input", { class: "input", type: "url", placeholder: a.ntfy.configured ? "Leave blank to keep the current topic" : "https://ntfy.sh/your-private-topic", autocomplete: "off" });
    const token = h("input", { class: "input", type: "password", placeholder: a.ntfy.token ? "Leave blank to keep the current token" : "Only for protected ntfy topics", autocomplete: "off" });
    const rm = (id, on) => (on ? h("div", { class: "field inline" }, h("input", { type: "checkbox", id }), h("label", { for: id }, "Remove it")) : null);
    const rmHook = rm("rm-hook", a.webhook.configured), rmNtfy = rm("rm-ntfy", a.ntfy.configured), rmTok = rm("rm-tok", a.ntfy.token);
    const kinds = new Set(a.notify_on);
    const boxes = a.kinds.map((k) => h("div", { class: "pick" }, h("input", { type: "checkbox", id: `k-${k}`, checked: kinds.has(k), onchange: (e) => { if (e.target.checked) kinds.add(k); else kinds.delete(k); } }),
      h("label", { for: `k-${k}` }, KIND_TEXT[k] || k, SECURITY_KINDS.includes(k) ? h("span", { class: "badge warn" }, "security") : null)));
    const checked = (el) => !!el && el.querySelector("input").checked;
    modal({
      title: "Alert settings", wide: true,
      body: h("div", {},
        h("p", { class: "muted" }, "Where netScan sends a message when something happens. Addresses are write-only: once saved they are never shown again. Settings made here win over config.toml."),
        h("div", { class: "formgrid" }, field("Webhook URL", hook, a.webhook.configured ? `Currently set (${a.webhook.host})` : "A JSON POST is sent for each event."), rmHook,
          field("ntfy topic URL", ntfy, a.ntfy.configured ? `Currently set (${a.ntfy.host})` : "For push notifications to your phone via ntfy.sh or your own server."), rmNtfy,
          field("ntfy access token", token), rmTok),
        h("h3", { class: "muted" }, "Notify me when"), h("div", { class: "picklist tall" }, boxes),
        h("p", { class: "muted small" }, "Individual devices can be muted, or always alerted, from their details.")),
      actions: [
        { label: "Reset to config file", onClick: async () => { if (!confirm("Discard the settings made in the dashboard and use config.toml again?")) return; closeModal(); await act(() => api("PUT", "/api/alerts", { reset: true }), "Alert settings reset"); await loadAlerts(); } },
        { label: "Cancel", onClick: closeModal },
        { label: "Save", kind: "primary", onClick: async () => {
          const payload = { notify_on: [...kinds] };
          const put = (key, input, remove) => { if (checked(remove)) payload[key] = ""; else if (input.value.trim()) payload[key] = input.value.trim(); };
          put("webhook_url", hook, rmHook); put("ntfy_url", ntfy, rmNtfy); put("ntfy_token", token, rmTok);
          try { state.alerts = await api("PUT", "/api/alerts", payload); closeModal(); toast("Alert settings saved"); await refresh(); } catch (e) { if (e.message !== "unauthorised") toast(e.message, true); }
        } }],
    });
  }

  async function sendTest() {
    try {
      const res = await api("POST", "/api/alerts/test");
      for (const [name, r] of Object.entries(res)) if (r.configured) toast(r.ok ? `${name}: test message sent` : `${name} failed: ${r.error}`, !r.ok);
    } catch (e) { if (e.message !== "unauthorised") toast(e.message, true); }
  }

  function alertsCard() {
    const a = state.alerts;
    const card = h("div", { class: "card" }, h("h2", {}, "Alerts"));
    if (!a) { card.append(h("p", { class: "muted" }, "Loading...")); return card; }
    card.append(h("dl", { class: "kv" },
      h("dt", {}, "Webhook"), h("dd", {}, a.webhook.configured ? a.webhook.host : "not set"),
      h("dt", {}, "ntfy"), h("dd", {}, a.ntfy.configured ? `${a.ntfy.host}${a.ntfy.token ? " (with token)" : ""}` : "not set"),
      h("dt", {}, "Notify on"), h("dd", { class: "params" }, a.notify_on.length ? a.notify_on.map((k) => h("span", { class: `badge${SECURITY_KINDS.includes(k) ? " warn" : ""}` }, k.replace("_", " "))) : "nothing (log only)")),
      h("div", { class: "row" }, h("button", { class: "btn primary", onclick: alertsModal }, "Edit alerts"),
        h("button", { class: "btn", disabled: !a.webhook.configured && !a.ntfy.configured, onclick: sendTest }, "Send test message")),
      h("p", { class: "muted small" }, "Everything is also written to the log and shown under Activity."));
    return card;
  }

  return {
    quickBlockModal, ruleModal, rulesCard, deviceExtras, reviewBanner, bulkBar, trustBadges, isRuleBlock,
    presenceView, securityView, loadAlerts, alertsCard, nameOf,
  };
}
