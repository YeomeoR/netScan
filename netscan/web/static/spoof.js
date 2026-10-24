// "Temporary MAC address" card on the System tab. The server does the work and the guarding;
// this only collects the address and the duration. DOM is built with h() and textContent only.

const MINUTES = [[15, "15 minutes"], [30, "30 minutes"], [60, "1 hour"], [120, "2 hours"], [240, "4 hours"], [480, "8 hours"]];

export function createSpoof(ctx) {
  const { h, api, act, state, fmtDur, fmtTime, label, toast, clear } = ctx;
  const draft = { mac: "", minutes: "30", confirm: false };

  async function start() {
    const mac = draft.mac.trim();
    if (!mac) { toast("Enter the MAC address to use, or pick a device.", true); return; }
    const minutes = Number(draft.minutes);
    const ok = confirm(
      `Make this machine use ${mac} for ${fmtDur(minutes * 60)}?\n\n` +
      "Its network connection drops for a few seconds and its IP address may change, so this page can stop responding until the original address is back. " +
      "The real address returns by itself when the time is up.");
    if (!ok) return;
    await act(() => api("POST", "/api/spoof", { mac, minutes, confirm: draft.confirm }), "Changing the MAC address...");
  }

  function card() {
    const s = state.status?.spoof;
    const el = h("div", { class: "card" }, h("h2", {}, "Temporary MAC address"));
    if (!s) { el.append(h("p", { class: "muted" }, "Loading...")); return el; }
    if (!s.supported) { el.append(h("p", { class: "muted" }, s.reason)); return el; }
    if (s.active) {
      el.append(
        h("dl", { class: "kv" },
          h("dt", {}, "Interface"), h("dd", { class: "mono" }, s.interface),
          h("dt", {}, "Using now"), h("dd", { class: "mono" }, s.spoofed),
          h("dt", {}, "Real address"), h("dd", { class: "mono" }, s.original),
          h("dt", {}, "Goes back"), h("dd", {}, `${fmtTime(s.expires)} (in ${fmtDur(s.seconds_left)})`)),
        h("div", { class: "row" },
          h("button", { class: "btn primary", disabled: s.busy, onclick: () => act(() => api("POST", "/api/spoof/restore"), "Putting the real address back...") }, s.busy ? "Working..." : "Put the real address back now")),
        h("p", { class: "muted small" }, "It also goes back by itself at that time, and after a reboot."));
      return el;
    }
    const net = state.status.network || {};
    const devices = (state.devices || [])
      .filter((d) => d.mac !== (net.mac || "").toLowerCase() && d.ip !== net.gateway)
      .sort((a, b) => label(a).localeCompare(label(b)));
    const find = (value) => devices.find((d) => d.mac === value.trim().toLowerCase());
    const warn = h("div");
    const pick = h("select", { class: "input", "aria-label": "Pick another device on the network" },
      h("option", { value: "" }, "Pick a device on the network..."),
      devices.map((d) => h("option", { value: d.mac }, `${label(d)} (${d.mac})${d.online ? " - online" : ""}`)));
    const mac = h("input", { class: "input mono", placeholder: "or type aa:bb:cc:dd:ee:ff", value: draft.mac, "aria-label": "MAC address to use", autocomplete: "off", spellcheck: "false" });
    function sync() {
      const d = find(draft.mac);
      pick.value = d ? d.mac : "";
      clear(warn);
      if (d && d.online) {
        warn.append(h("div", { class: "field inline" },
          h("input", { type: "checkbox", id: "sp-confirm", checked: draft.confirm, onchange: (e) => { draft.confirm = e.target.checked; } }),
          h("label", { for: "sp-confirm" }, `${label(d)} is online. Two devices sharing one address knock each other off, so switch it off first, or tick this to go ahead.`)));
      }
    }
    pick.onchange = () => { if (pick.value) { draft.mac = pick.value; draft.confirm = false; mac.value = pick.value; sync(); } };
    mac.oninput = () => { draft.mac = mac.value; draft.confirm = false; sync(); };
    sync();
    const mins = h("select", { class: "input", "aria-label": "How long", onchange: (e) => { draft.minutes = e.target.value; } },
      MINUTES.map(([v, t]) => h("option", { value: String(v), selected: String(v) === draft.minutes }, t)));
    el.append(
      h("p", { class: "muted" }, "Make this machine's own network card use another device's address for a while, to see how your network treats that device. The real address is saved first and comes back automatically."),
      h("div", { class: "formgrid" }, pick, mac, mins),
      warn,
      h("div", { class: "row" }, h("button", { class: "btn primary", disabled: s.busy, onclick: start }, s.busy ? "Working..." : "Use this address")),
      h("p", { class: "muted small" }, "Pick a device from the list to fill the address in, or type any address yourself. Only this machine's own interface is changed, never another device. The router's address is refused. Expect a short network drop and a possible new IP address."));
    return el;
  }

  return { card };
}
