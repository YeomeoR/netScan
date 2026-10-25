// "Networks" card on the System tab: which networks netScan may work on, and scanning for and joining Wi-Fi.
// The server does the guarding (and the joining); this collects the choice. The password only ever goes to the
// join request and is cleared straight after. Network names come from the air, so DOM is built with h() and textContent only.

const BARS = (q) => (q === null || q === undefined ? "" : q >= 70 ? "strong" : q >= 40 ? "good" : "weak");

export function createNetworks(ctx) {
  const { h, clear, api, act, toast, state, refresh } = ctx;
  const root = h("div", { class: "card" });
  const draft = { scanning: false, joining: false, result: null, ssid: "", password: "", error: "", outcome: null };

  async function scan() {
    draft.scanning = true; draft.error = ""; render();
    try { draft.result = await api("POST", "/api/wifi/scan"); } catch (e) { if (e.message !== "unauthorised") draft.error = e.message; }
    draft.scanning = false; render();
  }

  async function join() {
    const ssid = draft.ssid.trim();
    if (!ssid) { toast("Pick a network or type its name.", true); return; }
    const ok = confirm(`Join "${ssid}"?\n\nThis machine leaves its current Wi-Fi network, so this page may pause for a few seconds. Only join a network you have been given the password for.`);
    if (!ok) return;
    draft.joining = true; draft.error = ""; draft.outcome = null; render();
    try {
      draft.outcome = await api("POST", "/api/wifi/connect", { ssid, password: draft.password });
      draft.password = "";
      toast(draft.outcome.ready ? `Joined ${ssid}` : `Joined ${ssid}, but netScan cannot use it yet`, !draft.outcome.ready);
      draft.result = null;
    } catch (e) { if (e.message !== "unauthorised") draft.error = e.message; }
    draft.joining = false;
    await refresh(); render();
  }

  function scopeBlock(s) {
    const net = s.network;
    const box = h("input", { type: "checkbox", id: "n-follow", checked: !!s.follow_network, disabled: !s.configured || s.active_services_running,
      onchange: async (e) => { await act(() => api("PUT", "/api/network/follow", { follow_network: e.target.checked }), e.target.checked ? "Following whichever network you join" : "Back to the saved allow-list only"); render(); } });
    return h("div", {},
      h("dl", { class: "kv" },
        h("dt", {}, "Connected to"), h("dd", {}, net ? `${net.network} on ${net.interface}${net.gateway ? ` (router ${net.gateway})` : ""}` : "no network detected"),
        h("dt", {}, "Allowed"), h("dd", {}, [...(state.config?.allowed_subnets || []), ...(s.follow_network ? ["whichever private network you are on"] : [])].join(", ") || "-")),
      h("div", { class: "field inline" }, box, h("label", { for: "n-follow" }, "Work on whichever network I am connected to (for a laptop that visits other networks)")),
      !s.configured ? h("p", { class: "muted small" }, "Set netScan up first, then this can be switched.") : null,
      s.services && Object.values(s.services).some((v) => v.running) ? h("p", { class: "muted small" }, "Stop the background services below before changing this.") : null);
  }

  function networkRow(n) {
    const pick = () => { draft.ssid = n.ssid; draft.outcome = null; render(); };
    return h("button", { class: `netrow${draft.ssid === n.ssid ? " selected" : ""}`, type: "button", onclick: pick },
      h("span", { class: "body" }, n.ssid, n.current ? [" ", h("span", { class: "badge on" }, "connected")] : null),
      h("span", { class: "muted small" }, [n.security, BARS(n.quality), n.channel ? `ch ${n.channel}` : ""].filter(Boolean).join(" · ")));
  }

  function wifiBlock(s) {
    const w = s.wifi;
    if (!w) return h("p", { class: "muted" }, "Loading...");
    if (!w.supported) return h("p", { class: "muted" }, w.reason);
    const r = draft.result;
    const name = h("input", { class: "input", placeholder: "network name", value: draft.ssid, "aria-label": "Wi-Fi network name", autocomplete: "off", spellcheck: "false", oninput: (e) => { draft.ssid = e.target.value; } });
    const pass = h("input", { class: "input", type: "password", placeholder: "password (leave empty for an open or saved network)", value: draft.password, "aria-label": "Wi-Fi password", autocomplete: "off", oninput: (e) => { draft.password = e.target.value; } });
    return h("div", {},
      h("div", { class: "row" }, h("button", { class: "btn", disabled: draft.scanning || draft.joining, onclick: scan }, draft.scanning ? "Scanning..." : r ? "Scan again" : "Scan for Wi-Fi networks")),
      r && r.networks.length ? h("div", { class: "netlist" }, r.networks.map(networkRow)) : null,
      r && !r.networks.length ? h("p", { class: "muted" }, r.redacted
        ? "This Mac is hiding nearby network names. Allow Location Services for Terminal (System Settings, Privacy and Security), or pick a saved network or type the name below."
        : "No networks found. Move closer to the router, or type the name below.") : null,
      r && r.saved.length ? [h("p", { class: "muted small" }, "Saved on this machine"), h("div", { class: "netlist" }, r.saved.map((ssid) => networkRow({ ssid, security: "Saved", current: ssid === r.current })))] : null,
      h("div", { class: "formgrid" }, name, pass),
      h("div", { class: "row" }, h("button", { class: "btn primary", disabled: draft.joining || draft.scanning, onclick: join }, draft.joining ? "Joining..." : "Join this network")),
      draft.error ? h("div", { class: "callout bad" }, draft.error) : null,
      draft.outcome && !draft.outcome.ready ? h("div", { class: "callout bad" }, h("p", {}, `Joined ${draft.outcome.connected}, but netScan cannot scan it yet: ${draft.outcome.problem}`),
        h("p", { class: "small" }, "Switch on \"Work on whichever network I am connected to\" above, then press Re-detect network under Maintenance.")) : null,
      draft.outcome && draft.outcome.ready ? h("p", { class: "muted" }, `Connected to ${draft.outcome.connected}. Run a scan from the Devices tab.`) : null,
      h("p", { class: "muted small" }, "The password is sent to this machine's own Wi-Fi settings and is not kept by netScan. Only join networks you have permission to use."));
  }

  function render() {
    const s = state.status;
    clear(root).append(h("h2", {}, "Networks"));
    if (!s) { root.append(h("p", { class: "muted" }, "Loading...")); return; }
    root.append(scopeBlock({ ...s, active_services_running: Object.values(s.services || {}).some((v) => v.running) }), h("h3", { class: "muted" }, "Wi-Fi"), wifiBlock(s));
  }

  // the card keeps its own element so a typed password or a picked network survives the dashboard's periodic refresh
  function card() {
    if (!root.childNodes.length || !root.contains(document.activeElement)) render();
    return root;
  }

  return { card };
}
