// Self-update UI: a banner when GitHub has newer commits, and the Updates card on the System tab.
// Same rules as app.js: DOM is built with h() and textContent only.

export function createUpdates(ctx) {
  const { h, api, act, state, ago } = ctx;

  async function load(force = false) {
    try { state.update = await api("GET", `/api/update${force ? "?force=1" : ""}`); } catch (e) { if (e.message !== "unauthorised") state.update = state.update || null; }
    return state.update;
  }

  async function apply() {
    if (!confirm("Update netScan now? The dashboard restarts for a few seconds, running scans are interrupted, and this page reloads by itself.")) return;
    await act(() => api("POST", "/api/update/apply"), "Update started. The dashboard will restart and reload.");
    await load();
  }

  const commitList = (u, max) => u.new_commits.length
    ? h("ul", { class: "list" }, u.new_commits.slice(0, max).map((c) => h("li", {}, h("span", { class: "when mono" }, c.sha), h("span", { class: "body" }, c.subject))))
    : null;

  function banner() {
    const u = state.update;
    const box = h("div");
    if (!u || !u.supported || (!u.behind && !u.applying)) return box;
    if (u.applying) return h("div", { class: "callout" }, h("span", { class: "spinner" }), " Updating netScan. This page reloads itself when the new version is running.");
    box.append(h("div", { class: "callout" },
      h("strong", {}, `A newer version is on GitHub (${u.behind} new commit${u.behind === 1 ? "" : "s"}).`), " ",
      u.can_apply ? h("button", { class: "btn small primary", onclick: apply }, "Update now") : h("span", { class: "muted" }, u.blocker),
      u.new_commits.length ? h("div", { class: "muted small" }, u.new_commits.slice(0, 3).map((c) => c.subject).join(" / ")) : null));
    return box;
  }

  function card() {
    const u = state.update;
    const el = h("div", { class: "card" }, h("h2", {}, "Updates"));
    if (!u) { el.append(h("p", { class: "muted" }, "Checking...")); return el; }
    if (!u.supported) {
      el.append(h("p", { class: "muted" }, u.reason || "Updates are not available here."));
      return el;
    }
    const auto = h("input", { type: "checkbox", id: "u-auto", checked: u.auto, onchange: (e) => act(() => api("PUT", "/api/update", { auto: e.target.checked }), e.target.checked ? "Automatic updates on" : "Automatic updates off") });
    el.append(
      h("dl", { class: "kv" },
        h("dt", {}, "Installed"), h("dd", {}, h("span", { class: "mono" }, u.commit), ` on ${u.branch}: ${u.subject}`),
        h("dt", {}, "GitHub"), h("dd", {}, u.error ? h("span", { class: "warn-text" }, u.error)
          : u.behind ? `${u.behind} newer commit${u.behind === 1 ? "" : "s"}` : "up to date"),
        h("dt", {}, "Checked"), h("dd", {}, u.checked_at ? ago(u.checked_at) : "never")),
      commitList(u, 5),
      u.dirty ? h("p", { class: "small warn-text" }, "This checkout has uncommitted changes, so updating is paused.") : null,
      u.ahead ? h("p", { class: "small warn-text" }, "This checkout has commits that are not on GitHub, so it cannot fast-forward.") : null,
      h("div", { class: "row" },
        h("button", { class: "btn", onclick: async () => { await load(true); ctx.rerender(); } }, "Check now"),
        h("button", { class: "btn primary", disabled: !u.can_apply, title: u.can_apply ? "" : u.blocker, onclick: apply }, u.applying ? "Updating..." : "Update now")),
      h("div", { class: "field inline" }, auto, h("label", { for: "u-auto" }, "Update automatically when I open or refresh the dashboard")),
      h("p", { class: "muted small" }, "Follows the branch that is checked out. It is checked when you open or refresh the page and every 10 minutes while it is open. Automatic updates install whatever is pushed to that branch and restart the dashboard, so only switch them on for a repository only you can push to."));
    return el;
  }

  return { load, banner, card };
}
