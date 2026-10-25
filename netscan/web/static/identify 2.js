// Device identification UI: what a device says about itself, habits worked out from its history, and the System card.
// Same rules as app.js: DOM is built with h() and textContent only. Everything here came from devices on the network,
// so it is treated as untrusted text and never as markup.

const SOURCE_NAMES = { mdns: "Bonjour (mDNS)", ssdp: "UPnP", netbios: "NetBIOS", dhcp: "DHCP request", ttl: "Ping reply", banners: "Web and SSH banners" };

export function createIdentify(ctx) {
  const { h, clear, api, act, toast, closeModal, state, ago, fmtTime, fmtDur, fmtBytes, refresh } = ctx;

  async function loadSettings() {
    try { state.identify = await api("GET", "/api/identify/settings"); } catch (e) { if (e.message !== "unauthorised") state.identify = state.identify || null; }
    return state.identify;
  }

  const rows = (pairs) => h("dl", { class: "kv" }, pairs.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k, v]) => [h("dt", {}, k), h("dd", {}, Array.isArray(v) ? v.join(", ") : String(v))]));

  function describeSource(src, data) {
    if (src === "mdns") return rows([["Name shown", data.friendly], ["Host name", data.hostname], ["Services", data.services], ["Model", data.txt?.md || data.txt?.model || data.txt?.am]]);
    if (src === "ssdp") return rows([["Name shown", data.friendly], ["Maker", data.manufacturer], ["Model", [data.model, data.model_number].filter(Boolean).join(" ")], ["Kind", data.device_type], ["Software", data.server]]);
    if (src === "netbios") return rows([["Computer name", data.name], ["Workgroup", data.workgroup]]);
    if (src === "dhcp") return rows([["Asked for the name", data.hostname], ["Vendor class", data.vendor_class], ["Looks like", data.os], ["Option order", data.params]]);
    if (src === "ttl") return rows([["Reply TTL", data.ttl], ["Started at", data.initial]]);
    if (src === "banners") {
      return h("div", {}, Object.entries(data).map(([port, p]) => h("div", { class: "muted small" }, h("span", { class: "mono" }, `${port}/${p.proto || "tcp"}`), " ",
        [p.banner, p.server, p.title && `"${p.title}"`, p.realm && `login realm "${p.realm}"`].filter(Boolean).join(" · ") || p.status || "")));
    }
    return null;
  }

  function identityBlock(data) {
    const d = data.device, id = data.identity;
    const have = Object.keys(id.sources);
    const kids = [h("h3", { class: "muted" }, "What it says about itself")];
    if (!have.length) {
      kids.push(h("p", { class: "muted" }, id.checked ? `Asked ${ago(id.checked)}, but it did not answer on Bonjour, UPnP or NetBIOS, and has not sent a DHCP request since netScan started listening.` : "Nobody has asked this device yet."));
    } else {
      kids.push(rows([
        ["Calls itself", id.name && `${id.name} (${id.name_source})`],
        ["Looks like", [id.category, id.os, id.model].filter(Boolean).join(" · ")],
      ]));
      if (id.reasons.length) kids.push(h("ul", { class: "list reasons" }, id.reasons.map((r) => h("li", {}, h("span", { class: "body muted small" }, r)))));
      for (const src of Object.keys(SOURCE_NAMES)) {
        if (!id.sources[src]) continue;
        kids.push(h("details", { class: "src" }, h("summary", {}, SOURCE_NAMES[src], h("span", { class: "muted small" }, `  ${ago(id.sources[src].ts)}`)), describeSource(src, id.sources[src].data)));
      }
    }
    const actions = [h("button", { class: "btn small", disabled: !id.can_identify || !state.status?.ready || !d.online, title: !d.online ? "The device is offline" : "", onclick: async () => { closeModal(); await act(() => api("POST", "/api/identify", { macs: [d.mac] }), "Asking the device what it is"); } }, have.length || id.checked ? "Ask again" : "Identify")];
    if (id.category && !d.category) {
      actions.push(h("button", { class: "btn small", onclick: async () => { try { await api("PUT", `/api/devices/${encodeURIComponent(d.mac)}/meta`, { category: id.category }); closeModal(); toast(`Type set to ${id.category}`); await refresh(); } catch (e) { if (e.message !== "unauthorised") toast(e.message, true); } } }, `Use "${id.category}" as its type`));
    }
    kids.push(h("div", { class: "row" }, actions));
    kids.push(h("p", { class: "muted small" }, "These are guesses from what the device announces, not proof. Names are shown only when you have not given the device a name yourself."));
    return h("div", {}, kids);
  }

  function hoursChart(profile) {
    const el = h("div", { class: "hours", role: "img", "aria-label": "Share of each hour of the day this device is usually online" });
    profile.forEach((p, hour) => {
      const bar = h("span", { class: p === null ? "none" : "", title: `${String(hour).padStart(2, "0")}:00 ${p === null ? "no history" : `online ${Math.round(p * 100)}% of the time`}` });
      bar.style.height = `${p === null ? 4 : Math.max(6, Math.round(p * 100))}%`;
      el.append(bar);
    });
    return el;
  }

  function behaviourBlock(data) {
    const b = data.behaviour, d = data.device;
    const kids = [h("h3", { class: "muted" }, "Habits")];
    kids.push(rows([
      ["Offline for", !d.online && b.offline_for_text ? `${b.offline_for_text} (last seen ${fmtTime(d.last_seen)})` : ""],
      ["Online", b.history_days ? `${b.online_percent}% of the last ${b.history_days >= 14 ? 14 : b.history_days} days` : ""],
      ["Drops off the network", b.history_days ? `${b.drops} time${b.drops === 1 ? "" : "s"} (${b.drops_per_day} a day)${b.drops_often ? " - often; weak Wi-Fi or a device that sleeps" : ""}` : ""],
      ["Longest gap", b.longest_offline ? fmtDur(b.longest_offline) : ""],
      ["Usual hours", b.usual_hours || (b.enough_history ? "no clear pattern" : "needs about a day of history")],
      ["MAC address", b.private_mac ? "private (randomised)" : ""],
    ]));
    if (b.enough_history) kids.push(hoursChart(b.hourly), h("div", { class: "strip-axis" }, h("span", {}, "00:00"), h("span", {}, "12:00"), h("span", {}, "23:00")));
    if (b.mac_note) kids.push(h("p", { class: "muted small" }, b.mac_note));
    if (b.destinations.length) {
      kids.push(h("h3", { class: "muted" }, "Where its traffic goes"),
        h("div", { class: "tablewrap" }, h("table", {}, h("tbody", {}, b.destinations.map((t) => h("tr", {},
          h("td", {}, t.host === t.ip ? h("span", { class: "mono" }, t.ip) : [t.host, h("div", { class: "muted small mono" }, t.ip)]),
          h("td", { class: "mono" }, (t.ports || []).join(", ")), h("td", { class: "nowrap" }, fmtBytes(t.bytes)), h("td", { class: "nowrap" }, ago(t.last_seen))))))));
    } else {
      kids.push(h("p", { class: "muted small" }, "No traffic recorded, so there is nothing to say about where it connects. Start Traffic capture on the System tab."));
    }
    return h("div", {}, kids);
  }

  function card() {
    const s = state.identify;
    const el = h("div", { class: "card" }, h("h2", {}, "Device identification"));
    if (!s) { el.append(h("p", { class: "muted" }, "Loading...")); return el; }
    if (!s.available) { el.append(h("p", { class: "muted" }, "Not available in this session.")); return el; }
    const auto = h("input", { type: "checkbox", id: "i-auto", checked: s.auto, onchange: async (e) => { await act(() => api("PUT", "/api/identify/settings", { auto: e.target.checked }), e.target.checked ? "Automatic identification on" : "Automatic identification off"); await loadSettings(); ctx.rerender(); } });
    el.append(
      h("p", { class: "muted" }, "Asks devices what they are: Bonjour names and services, UPnP descriptions, NetBIOS names, ping TTL, and web or SSH banners on ports a port check found open. The Watch service also listens for the names devices send when they ask for an address (DHCP)."),
      h("div", { class: "field inline" }, auto, h("label", { for: "i-auto" }, "Quietly identify new and unchecked devices after each scan (at most every 6 hours per device)")),
      h("div", { class: "row" }, h("button", { class: "btn primary", disabled: !state.status?.ready, onclick: () => act(() => api("POST", "/api/identify", {}), "Identifying online devices") }, "Identify all online devices")),
      h("p", { class: "muted small" }, "Only addresses in your allow-list are contacted. Bonjour and UPnP questions go to the local network; nothing leaves it."));
    return el;
  }

  return { loadSettings, identityBlock, behaviourBlock, card };
}
