// How-to content for the Help dialog. Static text only; built with the same h() helper as the app.

const SECTIONS = [
  {
    id: "start",
    title: "Quick start",
    open: true,
    body: (h) => [
      h("ol", {},
        h("li", {}, "Open the ", h("strong", {}, "Devices"), " tab and press ", h("strong", {}, "Scan now"), ". Every device on your network that answers shows up with its IP, MAC address, vendor and name."),
        h("li", {}, "Click a device (or ", h("strong", {}, "Details"), ") to see when it first and last appeared, its traffic metadata and its history."),
        h("li", {}, "Open ", h("strong", {}, "Schedule"), " to make sweeps run by themselves, e.g. hourly or every night at 03:00."),
        h("li", {}, "Watch the ", h("strong", {}, "Activity"), " tab for what ran and what changed (new device, went offline, blocked...)."),
        h("li", {}, "Give devices a name and owner, and mark the ones you recognise as ", h("strong", {}, "Known"), ". Anything new then stands out."),
        h("li", {}, "Use ", h("strong", {}, "System"), " to start background services, set up alerts and see your configuration.")),
      h("p", { class: "muted" }, "The yellow \"limited: not root\" chip means the dashboard was started without sudo. You can look around, but raw network features (fast ARP scan, ARP watch, blocking, capture) are unavailable.")],
  },
  {
    id: "scan",
    title: "Scanning and the device list",
    body: (h) => [
      h("p", {}, "A scan sends ARP requests to every address in your allowed subnet and records who answers. Open ", h("strong", {}, "Scan options"), " to set:"),
      h("dl", { class: "kv" },
        h("dt", {}, "Wait for replies"), h("dd", {}, "Seconds to listen for answers. Raise it to catch sleepy phones and IoT gadgets."),
        h("dt", {}, "Look up hostnames"), h("dd", {}, "Reverse-DNS names such as pihole.lan. Turn off for a faster scan."),
        h("dt", {}, "Mark offline after"), h("dd", {}, "How long a device may go unseen before it is shown Offline. 0 means immediately. Phones that sleep need a longer value (15 minutes is a good start)."),
        h("dt", {}, "Then capture"), h("dd", {}, "Optionally record traffic metadata straight after the scan.")),
      h("p", {}, "Filter the table by Online / Offline / Blocked / Unreviewed, search by name, owner, IP, MAC or vendor, and click a column heading to sort."),
      h("p", { class: "muted" }, "Devices that use a private (randomised) Wi-Fi address show \"(randomised MAC)\" instead of a vendor; that is normal on modern phones and the address can change per network.")],
  },
  {
    id: "schedule",
    title: "Timed sweeps",
    body: (h) => [
      h("p", {}, "Press ", h("strong", {}, "New timed sweep"), " on the Schedule tab. A sweep runs on the machine hosting netScan, so a Pi keeps sweeping with every browser closed."),
      h("ul", {},
        h("li", {}, h("strong", {}, "Every N"), ": 30 seconds up to 7 days. Presets: every 5 min, hourly, every 6 h."),
        h("li", {}, h("strong", {}, "Daily"), ": at HH:MM on that machine's clock (the dashboard shows its timezone)."),
        h("li", {}, h("strong", {}, "Once"), ": a single run at a date and time in your browser's local time.")),
      h("p", {}, "Each schedule has its own parameters (reply wait, hostnames, mark-offline-after, optional capture afterwards). Use ", h("strong", {}, "Run now"), " to test one, ", h("strong", {}, "Pause"), " to stop it without deleting it."),
      h("p", { class: "muted" }, "If the previous run of a schedule is still going when the next one is due, the new run is skipped and flagged rather than piling up. Interrupted jobs (power cut, restart) are marked \"interrupted\" in Activity.")],
  },
  {
    id: "block",
    title: "Blocking and unblocking a device",
    body: (h) => [
      h("p", {}, "Press ", h("strong", {}, "Block"), " on a device and confirm. You can add a reason. Blocks are tied to the device's MAC address and survive restarts."),
      h("ul", {},
        h("li", {}, h("strong", {}, "ARP method (default)"), ": the enforcer sends forged ARP replies that cut the device off. It only works ", h("em", {}, "while the enforcer is running"), ": start it under System. The Pi service starts it automatically."),
        h("li", {}, h("strong", {}, "iptables / nftables (Pi)"), ": a firewall rule. Only affects traffic that passes through the Pi, so it only helps if the Pi is your router.")),
      h("p", {}, h("strong", {}, "To reverse it:"), " press ", h("strong", {}, "Unblock"), " in Devices, Access or the device's detail window. The correct ARP entries are restored and the device normally recovers within seconds (up to a minute or two on some devices; toggling its Wi-Fi speeds it up). Stopping the enforcer also restores everyone, but the blocks stay listed and apply again when it restarts."),
      h("p", { class: "muted" }, "Your router and the machine running netScan can never be blocked; their buttons are greyed out and the server refuses the request too. A device that switches to a new randomised MAC will not be blocked under its new address.")],
  },
  {
    id: "labels",
    title: "Names, owners and the review flow",
    body: (h) => [
      h("p", {}, "Open a device and fill in ", h("strong", {}, "Name"), " (e.g. \"Dad's laptop\"), ", h("strong", {}, "Owner"), " and ", h("strong", {}, "Type"), ". The name replaces the hostname everywhere. These are stored in netScan's database and never sent anywhere."),
      h("p", {}, "Every newly discovered device starts as ", h("strong", {}, "Not reviewed"), ". A banner on the Devices tab counts them. Mark the ones you recognise ", h("strong", {}, "Known"), " (or ", h("strong", {}, "Guest"), " for visitors' devices). Tick several rows to act on them together."),
      h("p", { class: "muted" }, "The first scan after install marks nothing as reviewed on purpose: you decide what is yours. \"Mark all as known\" is a shortcut for when you really do recognise everything.")],
  },
  {
    id: "rules",
    title: "Block timers and weekly timetables",
    body: (h) => [
      h("ul", {},
        h("li", {}, h("strong", {}, "Block for..."), ": on a device (or several ticked ones) for 15 minutes to a few hours. It lifts itself when the time is up."),
        h("li", {}, h("strong", {}, "Timetable"), " (Access tab): block chosen devices on chosen days between two times, e.g. Mon to Fri 21:00 to 07:00. Overnight windows belong to the day they start on. Times use the clock of the machine running netScan.")),
      h("p", {}, "Rules show up under Access with their next change. Pausing, editing or deleting a rule releases the devices it was holding. A device you blocked by hand is never touched by a rule, and a rule-held device cannot be unblocked by hand until you pause the rule."),
      h("p", { class: "muted" }, "Rules are applied by the running dashboard (", h("code", {}, "netscan web"), " or the Pi service). The plain ", h("code", {}, "netscan daemon"), " does not evaluate them. With the ARP method the enforcer must be running; netScan starts it for you when it has root. If the dashboard is stopped, a window block is not applied and a timer is released when it comes back.")],
  },
  {
    id: "presence",
    title: "Presence: who is home",
    body: (h) => [
      h("p", {}, "On the Presence tab choose the devices to track, usually phones, and set an owner on each so they group by person. You get a home / away summary and a timeline for each device."),
      h("p", { class: "muted" }, "It is approximate: a phone that sleeps its Wi-Fi looks away, and times follow your sweeps and the \"offline after\" setting. Randomised Wi-Fi addresses can change. Use it as a guide, not an alibi.")],
  },
  {
    id: "checks",
    title: "Security checks",
    body: (h) => [
      h("dl", { class: "kv" },
        h("dt", {}, "IP conflict"), h("dd", {}, "Two MAC addresses answering for the same IP during a scan. Usually a misconfigured device; can be a sign of impersonation. Some routers answer for everything (proxy ARP) and can cause false alarms."),
        h("dt", {}, "ARP spoof"), h("dd", {}, "Something other than your router claims the router's IP. Needs the ARP watch service running (System tab, needs root)."),
        h("dt", {}, "Rogue DHCP"), h("dd", {}, "Sends one DHCP discovery (asks for no address) and lists every server that answers. More than one, or one that is not your router, gets flagged. Needs root."),
        h("dt", {}, "Open ports"), h("dd", {}, "A TCP connect check of about 30 common ports on chosen devices. Telnet, exposed databases and similar are marked risky. Only devices inside your allowed subnet are checked.")),
      h("p", {}, "Findings appear on the Security tab and in Activity, and can be sent as alerts.")],
  },
  {
    id: "alerts",
    title: "Alerts (ntfy and webhook)",
    body: (h) => [
      h("p", {}, "On the System tab press ", h("strong", {}, "Edit alerts"), " to set a webhook URL and/or an ntfy topic, choose which events to be told about, and use ", h("strong", {}, "Send test message"), " to check it works. Settings saved here override the ones in config.toml; ", h("strong", {}, "Reset to config file"), " removes the overrides."),
      h("p", {}, "Per device you can choose to always be alerted, or never (log only), in the device's details. Saved secrets are never shown back to you, only the host."),
      h("p", { class: "muted" }, "Everything is written to the log and Activity whether or not it is sent.")],
  },
  {
    id: "traffic",
    title: "Traffic metadata",
    body: (h) => [
      h("p", {}, "The Traffic tab shows who talked to whom: peers, ports, services, bytes and packet counts. It records ", h("strong", {}, "metadata only"), ", never packet contents."),
      h("p", {}, "Start a capture with ", h("strong", {}, "Capture now"), " (needs root). On a normal switched home network this machine only sees its own traffic plus broadcast/multicast, not other devices' internet traffic, unless netScan runs on the router or a mirrored port. The Devices detail window says so when it has nothing to show.")],
  },
  {
    id: "system",
    title: "System tab: services, maintenance, config",
    body: (h) => [
      h("dl", { class: "kv" },
        h("dt", {}, "ARP watch"), h("dd", {}, "Listens for ARP between sweeps and alerts the moment an unknown device appears."),
        h("dt", {}, "Enforcer"), h("dd", {}, "Keeps ARP-method blocks alive. Needed after you block something."),
        h("dt", {}, "Traffic capture"), h("dd", {}, "Continuous metadata capture (same limits as above)."),
        h("dt", {}, "Vendor database"), h("dd", {}, "Update downloads the latest IEEE vendor list. The built-in list works without it."),
        h("dt", {}, "Re-detect network"), h("dd", {}, "Use after moving networks or replacing the router. Stop services first."),
        h("dt", {}, "Configuration"), h("dd", {}, "Read-only here. Edit config.toml on the machine for block method, subnet and daemon intervals. Alerts are edited in the Alerts card."),
        h("dt", {}, "Alerts"), h("dd", {}, "Webhook and ntfy settings, which events are sent, and a test button.")),
      h("p", {}, "On first run with no config, a card offers to detect your network and create it, pinning your router's MAC so the tool refuses to run on a different network by accident.")],
  },
  {
    id: "spoof",
    title: "Temporarily changing this machine's MAC address",
    body: (h) => [
      h("p", {}, "Under ", h("strong", {}, "System > Temporary MAC address"), " you can make the machine running netScan (the Mac or the Pi) use another address on its network card for 15 minutes to 8 hours, then put the real one back. Pick a known device or type an address."),
      h("ul", {},
        h("li", {}, "Only this machine's own interface changes. Other devices are never touched, and a device's record in netScan cannot be edited."),
        h("li", {}, "The real address is saved first. It returns on its own when the time is up, from the button, with ", h("code", {}, "netscan spoof restore"), ", and after a reboot."),
        h("li", {}, "Expect the connection to drop for a few seconds and the IP address to change. If you are viewing the Pi's dashboard from your phone, the page may stop responding until the real address is back."),
        h("li", {}, "If the device you copy is online, both fight over the address, so switch it off first. The router's address and blocked devices are refused."),
        h("li", {}, "Linux needs root or CAP_NET_ADMIN (the Pi service has it). macOS needs sudo, and on Wi-Fi it often only works while Wi-Fi is on but not joined; some newer Macs refuse it. Not available in demo mode.")),
      h("p", {}, "In a terminal: ", h("code", {}, "sudo netscan spoof set aa:bb:cc:dd:ee:ff --minutes 30"), " holds it for that long (Ctrl-C restores early); ", h("code", {}, "netscan spoof status"), " and ", h("code", {}, "netscan spoof restore"), " do what they say.")],
  },
  {
    id: "updates",
    title: "Updating netScan from GitHub",
    body: (h) => [
      h("p", {}, "When you push new commits, the dashboard notices on the next page load or refresh and shows a banner: ", h("strong", {}, "Update now"), " pulls them, reinstalls, restarts the dashboard and reloads the page. The same controls are in ", h("strong", {}, "System > Updates"), ", where you can also tick ", h("strong", {}, "Update automatically"), " (off by default)."),
      h("p", {}, "In a terminal: ", h("code", {}, "netscan update"), " (or ", h("code", {}, "--check"), " to only look), then restart the dashboard. ", h("code", {}, "netscan update --auto on"), " (or off) flips automatic updates. With them on, the dashboard checks GitHub every 5 minutes even with no browser open; the Pi install turns this on."),
      h("p", { class: "muted" }, "It follows the branch that is checked out, and refuses if the checkout has uncommitted changes. If a new version fails to install it rolls back. Running scans are interrupted by the restart. Automatic updates run whatever is pushed to that branch, so only use them on a repository only you can push to.")],
  },
  {
    id: "where",
    title: "Running it: Mac and Raspberry Pi",
    body: (h) => [
      h("p", {}, h("strong", {}, "Mac:")),
      h("pre", {}, "cd ~/Documents/DEV/netScan && source .venv/bin/activate\nsudo -E .venv/bin/netscan web --open     # real network, opens the browser\nnetscan web --demo                      # fake network to practise on"),
      h("p", {}, h("strong", {}, "Raspberry Pi:"), " run ", h("code", {}, "deploy/install-pi.sh"), " once. It installs a service that starts at boot and prints ", h("code", {}, "http://<pi-ip>:8787/#token=..."), ". Open that from any device on your network and bookmark it."),
      h("p", {}, "Same screens either way. The terminal program is unchanged and still works on both: ", h("code", {}, "netscan scan"), ", ", h("code", {}, "list"), ", ", h("code", {}, "block"), "...")],
  },
  {
    id: "cli",
    title: "Dashboard action = terminal command",
    body: (h) => [
      h("div", { class: "tablewrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "In the dashboard"), h("th", {}, "In the terminal"))),
        h("tbody", {}, [
          ["Scan now / Scan options", "netscan scan [--timeout 5] [--no-hostnames]"],
          ["Devices table", "netscan list"],
          ["Device detail", "netscan show <ip-or-mac>"],
          ["Capture now", "sudo -E netscan traffic --duration 60"],
          ["Block / Unblock", "netscan block <ip> / netscan unblock <ip>"],
          ["Blocks tab", "netscan blocks"],
          ["Enforcer service", "sudo -E netscan enforce"],
          ["ARP watch service", "sudo -E netscan watch"],
          ["Activity > Events", "netscan events"],
          ["Vendor database > Update", "netscan update-oui"],
          ["System > Updates", "netscan update [--check]"],
          ["System > Temporary MAC address", "netscan spoof set|status|restore"],
          ["Pi background service", "netscan daemon"],
          ["Names, owner, review, timers, presence, security checks, alert settings", "dashboard only (stored in the same database)"],
          ["Create config", "netscan init"],
        ].map(([a, b]) => h("tr", {}, h("td", {}, a), h("td", { class: "mono" }, b))))))],
  },
  {
    id: "security",
    title: "Security and safety",
    body: (h) => [
      h("ul", {},
        h("li", {}, "Only use netScan on networks you own or are authorised to manage."),
        h("li", {}, "Every request needs the access token. It is plain HTTP, so treat the token like a Wi-Fi password and keep the dashboard on your home network. Never port-forward it; use a VPN or an SSH tunnel for remote access."),
        h("li", {}, "The token lives in ", h("code", {}, "web_token"), " in the data folder (",
          h("code", {}, "~/.netscan"), " on a Mac, ", h("code", {}, "/var/lib/netscan"), " on the Pi). Delete the file and restart to rotate it."),
        h("li", {}, "A scope guard keeps scans and blocks inside your configured subnet, and your router is pinned by MAC."))],
  },
  {
    id: "trouble",
    title: "Troubleshooting",
    body: (h) => [
      h("dl", { class: "kv" },
        h("dt", {}, "Scan finds few devices"), h("dd", {}, "Run with sudo (fast ARP scan), raise \"Wait for replies\", or scan twice; sleeping phones answer late."),
        h("dt", {}, "Everything shows Offline"), h("dd", {}, "Raise \"Mark offline after\" (e.g. 15 min) so briefly sleeping devices are not flagged."),
        h("dt", {}, "Blocked device is back online"), h("dd", {}, "The enforcer is not running, the machine sleeping, or the device switched to a new MAC. Start the enforcer on System."),
        h("dt", {}, "\"unauthorised\" / back at login"), h("dd", {}, "Wrong or rotated token. Use the URL printed at startup, or read web_token."),
        h("dt", {}, "Vendor update fails"), h("dd", {}, "Needs internet and the latest netScan; the message lists which address failed. Built-in vendors keep working."),
        h("dt", {}, "ModuleNotFoundError: netscan (terminal)"), h("dd", {}, "Reinstall into the venv with ", h("code", {}, "pip install ."), " (and re-run it after every update)."),
        h("dt", {}, "Files in ~/.netscan owned by root"), h("dd", {}, h("code", {}, "sudo chown -R $USER ~/.netscan"), " after mixing sudo and non-sudo runs."),
        h("dt", {}, "Wrong network detected"), h("dd", {}, "System > Re-detect (stop services first). If the router changed, run ", h("code", {}, "netscan init --force"), "."))],
  },
];

export function buildHelp(h) {
  const search = h("input", { class: "input", type: "search", placeholder: "Filter topics...", "aria-label": "Filter help topics" });
  const list = h("div", { class: "help" });
  const items = SECTIONS.map((s) => {
    const el = h("details", { class: "help-sec", open: s.open ? true : null }, h("summary", {}, s.title), h("div", { class: "help-body" }, s.body(h)));
    el.dataset.text = `${s.title} ${el.textContent}`.toLowerCase();
    return el;
  });
  items.forEach((el) => list.append(el));
  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    for (const el of items) {
      const hit = !q || el.dataset.text.includes(q);
      el.classList.toggle("hidden", !hit);
      if (q && hit) el.open = true;
    }
  });
  return h("div", {}, search, list);
}
