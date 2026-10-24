# netScan

A fing-lite scanner and controller for **your own home network**, terminal-first (tables via [rich](https://github.com/Textualize/rich)).

> **Only use netScan on networks you own or are explicitly authorised to administer.**
> It shows this notice on first run and will not run until you acknowledge it. It refuses to scan, probe or block anything outside the subnet allow-list in your config, and never blocks the gateway or the machine it runs on. There is deliberately nothing in here for third-party networks.

## What it does

| Feature | How |
| --- | --- |
| Discover devices | ARP sweep of your subnet: IP, MAC, vendor (bundled IEEE OUI table), hostname (reverse DNS), first/last seen, online/offline |
| Traffic metadata | Per device: bytes/packets, protocol (TCP/UDP/ICMP/ARP/...), service label, destination/peer IPs, ports, hostnames (from observed DNS answers, reverse DNS fallback). **Metadata only; payloads are never stored** (the packet record type has no payload field) |
| Block / unblock | ARP cutoff (any LAN host, root) or `iptables`/`nftables` (Linux gateway). Block state persists in sqlite and survives restarts |
| Two modes, one core | (1) Mac local CLI, (2) Pi daemon: periodic sweep + ARP watch for new devices + alerts (terminal/log, webhook, ntfy) + systemd unit |

## Honest limits of traffic capture

A normal host on a switched LAN **only sees its own traffic plus broadcast/multicast**. Running `netscan traffic` on your Mac will therefore show your Mac (and things like mDNS/SSDP chatter from others), not what your TV is doing. To see other devices' traffic you need one of:

- the capture machine **in the path**: the Pi acts as the gateway/router (or sits on a bridge), or ARP-mediated forwarding (the Pi tells devices it is the gateway and forwards for them; **netScan does not do ARP interception for monitoring**, only ARP cutoff for blocking);
- **port mirroring/SPAN** on a managed switch or router pointing at the capture machine;
- running the capture on the router itself.

Other things to know:

- Wi-Fi client isolation, guest networks and VLANs hide devices from an ARP sweep.
- Devices with randomised ("private") MACs show vendor `(randomised MAC)` and appear as new devices if the MAC rotates per network. iOS/Android private Wi-Fi addresses are the usual cause.
- Hostnames come from reverse DNS only. Many home routers do not serve reverse names, so expect `-` for several devices.
- Encrypted traffic (HTTPS/QUIC/DoH) is classified by port; netScan does not look inside TLS.
- Without root, scanning falls back to a UDP "nudge" plus reading the OS ARP table. This finds most devices but is slower and less complete. Capture, ARP watch and blocking need root (or `CAP_NET_RAW`/`CAP_NET_ADMIN` on Linux).

### Blocking: what to expect

- **ARP cutoff** (`block.method = "arp"`, default): the target is told the gateway is at a dead MAC and the gateway is told the target is at a dead MAC, every 2 seconds. It only holds **while an enforcer is running** (`sudo netscan enforce` on the Mac, or the Pi daemon). `unblock` and a clean enforcer shutdown send the real MACs back; otherwise devices recover when their ARP caches expire. Devices with static ARP entries, some routers with ARP protection / DAI, and Wi-Fi isolation can defeat it. It is a home-network convenience, not a security boundary. If the device changes IP (DHCP), the block follows its MAC.
- **iptables / nftables**: only effective if this machine **forwards** the target's traffic (it is your router/gateway). Rules are re-applied from the database when the daemon starts, since they do not survive a reboot.
- The gateway, this host and anything in `safety.extra_protected` are refused by the block manager and again by the ARP enforcer before each packet. The transport layer additionally enforces the subnet allow-list on every sweep and send.

## Install

Needs Python 3.10+. Scapy handles raw packets; on macOS libpcap is built in, on Raspberry Pi OS/Debian install `libpcap` too.

### Mac (local CLI)

```bash
cd ~/Documents/DEV/netScan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

netscan init            # detects your subnet, writes ~/.netscan/config.toml (the allow-list)
netscan scan            # first run shows the own-network notice; unprivileged fallback sweep
sudo .venv/bin/netscan scan              # full ARP sweep (root needed for raw sockets)
```

`sudo` does not see your venv's PATH, so call `.venv/bin/netscan` explicitly. When run with `sudo`, data goes to root's home (`/var/root/.netscan`); to share one database with your normal user, set `NETSCAN_HOME`:

```bash
export NETSCAN_HOME=~/Documents/DEV/netScan/.netscan   # already in .gitignore
sudo -E .venv/bin/netscan scan
```

Everyday commands:

```bash
netscan list                   # devices from the database (no network access)
netscan show 192.168.1.20      # device detail + traffic metadata (ip or mac)
sudo -E .venv/bin/netscan traffic --duration 60   # capture metadata, then per-device totals
netscan block 192.168.1.20 --reason "bedtime"     # persists the block
sudo -E .venv/bin/netscan enforce                 # keeps the ARP cutoff alive; Ctrl-C restores
netscan blocks                 # list persisted blocks
netscan unblock 192.168.1.20
netscan events                 # new device / online / offline / ip change / block history
sudo -E .venv/bin/netscan watch   # foreground ARP watch with alerts
netscan update-oui             # optional: refresh the vendor table from the IEEE registry
```

### Raspberry Pi (daemon)

```bash
sudo apt install -y python3-venv python3-pip libpcap0.8 git
sudo useradd --system --home /var/lib/netscan --shell /usr/sbin/nologin netscan
sudo git clone https://github.com/YeomeoR/netScan.git /opt/netScan
cd /opt/netScan && sudo python3 -m venv .venv && sudo .venv/bin/pip install -e .

# one-off: create the config + data dir as the service user, check the detected subnet
sudo mkdir -p /var/lib/netscan && sudo chown netscan: /var/lib/netscan
sudo -u netscan env NETSCAN_HOME=/var/lib/netscan /opt/netScan/.venv/bin/netscan init
sudoedit /var/lib/netscan/config.toml     # alerts, intervals, block method

sudo cp deploy/netscan.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netscan
journalctl -u netscan -f
```

The unit runs as the unprivileged `netscan` user with only `CAP_NET_RAW` and `CAP_NET_ADMIN`, and passes `--accept-terms` (a daemon cannot answer a prompt; by enabling the unit you confirm the network is yours). Use the CLI against the same data with `sudo -u netscan env NETSCAN_HOME=/var/lib/netscan /opt/netScan/.venv/bin/netscan list`.

The daemon:

- sweeps every `daemon.sweep_interval` seconds (default 300), marks devices offline after `daemon.offline_after` seconds unseen;
- listens for ARP between sweeps and alerts the moment an unknown MAC appears;
- the first sweep seeds the inventory silently (`silent_baseline`), then every new MAC alerts;
- enforces persisted ARP blocks (or re-applies iptables/nftables blocks at start);
- optionally records traffic metadata (`daemon.capture_traffic`; subject to the capture limits above).

### Alerts

Configure in `config.toml`:

```toml
[alerts]
ntfy_url = "https://ntfy.sh/your-private-topic"   # optional bearer: ntfy_token = "..."
webhook_url = "https://example.invalid/hook"      # POSTs JSON {kind, message, ip, mac, vendor, hostname, text}
notify_on = ["new_device", "ip_conflict", "arp_spoof", "rogue_dhcp", "port_opened"]   # the default
```

Terminal/journal logging is always on. Webhook/ntfy failures are logged and never stop the daemon. Only `http(s)` URLs are accepted. The dashboard's **System > Alerts** card edits the same settings (stored in the database, they win over `config.toml`), sends a test message, and a device can be set to "always alert" or "never alert" in its details. Secrets are never sent back to the browser, only the host.

## Web dashboard (Mac and Pi, same GUI)

`netscan web` serves a browser dashboard with the same functions as the terminal program: scan (timeout, hostnames), devices with vendor/hostname/first-last seen/online state, per-device detail and traffic metadata, block/unblock, traffic capture, OUI update, the event log, background services (ARP watch, ARP-cutoff enforcer), a read-only config view with a first-run `init`, an alert settings editor, and **timed sweeps**. The terminal commands are unchanged and remain a separate way to use the tool.

The frontend is plain JavaScript (no build step, no npm); the server is Python stdlib, so nothing extra is installed.

### On the Mac

```bash
netscan web --open                   # http://127.0.0.1:8787, only this Mac can connect
sudo -E .venv/bin/netscan web        # root only needed for ARP sweep, watch, enforce and capture
netscan web --demo                   # fake network and throwaway data, to look around safely
```

**Double-click launcher.** `deploy/mac-launch.sh` updates from GitHub (switching to `main` when the checkout is clean), then starts the dashboard with sudo. Make the Desktop shortcut a one-line stub that runs it, so launcher changes update too:

```bash
printf '#!/bin/bash\nexec bash ~/Documents/DEV/netScan/deploy/mac-launch.sh\n' > ~/Desktop/netScan.command
chmod +x ~/Desktop/netScan.command
```

The URL printed includes `#token=...`; the token is stored at `~/.netscan/web_token` (mode 0600). Without root the dashboard still opens, but scans that need raw sockets report a clear error.

### On the Pi

```bash
curl -fsSL https://raw.githubusercontent.com/YeomeoR/netScan/main/deploy/install-pi.sh | sudo bash
# or, from a clone:  sudo bash deploy/install-pi.sh
```

This installs the `netscan-web` systemd unit (daemon and dashboard in one process, unprivileged user, `CAP_NET_RAW`/`CAP_NET_ADMIN` only), prints `http://<pi-ip>:8787/#token=...`, and replaces the plain `netscan` daemon unit (they conflict, because both would run the same background work). Open that URL from your Mac or phone. On the Pi it starts a baseline sweep, re-applies persisted blocks, and seeds a "Periodic sweep" schedule from `daemon.sweep_interval`. To use the Mac's browser against the Pi's data you simply browse to the Pi; there is one source of truth.

### Labels, review, presence, timetables and security checks

- **Names, owner, type, notes and review status** per device (`PUT /api/devices/<id>/meta`). Every discovered device starts as *not reviewed*; the Devices tab shows a banner, an "Unreviewed" filter and bulk actions (mark known/guest, block for a while, add to a timetable).
- **Block timers and weekly timetables** (Access tab, `/api/rules`). "Block for 30 min" lifts itself; a timetable blocks chosen devices on chosen days between two local times (overnight windows belong to the day they start; end `24:00` is allowed). Rules block through the normal block manager with the reason `rule: <name>`, never touch a block you placed by hand, and release only what they hold when paused, edited or deleted. A device held by a rule cannot be unblocked by hand (409). The gateway and this machine are refused (403). **Rules are evaluated by the web process** (`netscan web` or the Pi service, every 5 s), not by the plain `netscan daemon`. With the ARP method the enforcer is started automatically when privileged.
- **Presence** (`/api/presence`): tick the devices that mean "someone is home" and give them an owner. It is rebuilt from the event log, so it is approximate (phones sleep their Wi-Fi; times follow your sweeps and `offline_after`).
- **Security checks** (`/api/security`): *IP conflict* (two MACs for one IP in a sweep, de-duplicated for 6 h), *ARP spoof* (a non-gateway MAC claiming the gateway IP, needs the ARP watch service), *rogue DHCP* (one `DISCOVER` that requests no lease; every responding server is listed, needs root), and a *port check* (TCP connect to 31 common ports on up to 64 in-scope devices; risky services and newly opened ports raise `port_opened`). Routers that answer ARP for every address (proxy ARP) can cause noisy conflict findings.

None of this is exposed in the terminal commands yet; it lives in the same SQLite database, so the CLI and the dashboard share data.

### Timed sweeps

The **Schedule** tab creates sweeps that run on the machine hosting the dashboard (the Pi stays on, so it keeps sweeping with your browser closed). Kinds: every N seconds (30 s to 7 days), daily at HH:MM (the Pi's local time), or once. Each schedule stores its own parameters: timeout (1-30 s), resolve hostnames, mark-offline-after, optional traffic capture afterwards (up to an hour) and its flush interval. If the previous run of a schedule is still going, the next one is skipped and flagged rather than piling up. Jobs and schedules persist in the SQLite database; a restart marks interrupted jobs as such.

### Updating from GitHub

The dashboard can pull your latest commits itself. **System > Updates** shows what is installed and whether GitHub has newer commits on the branch that is checked out; a banner appears on every tab when it does. It checks when you open or refresh the page (cached for a minute) and every 10 minutes while the page stays open. **Update now** (or `netscan update` in a terminal, `netscan update --check` to only look) does a fast-forward `git pull`, reinstalls into the same virtualenv, checks the new code imports, then restarts the dashboard in place; the page notices the restart and reloads itself. If the install or the import check fails, the checkout is rolled back to the previous commit.

- It refuses when the checkout has uncommitted changes or commits GitHub does not have, and it never follows another branch.
- It finds the checkout from how netScan was installed (`pip install .` or `pip install -e .` from a clone). A copy installed from a tarball with no `.git` cannot update itself. `NETSCAN_SOURCE=/path/to/clone` overrides the lookup.
- **Automatic updates** (a checkbox on the card, off by default) apply a new version as soon as the page checks and nothing else is running. Anyone who can push to that branch can then run code on this machine, so only enable it for a repository only you can push to.
- With automatic updates on, the dashboard also checks GitHub in the background every 5 minutes, so a push to the branch reaches the machine with no browser open. `netscan update --auto on|off` flips the same switch from a terminal. `install-pi.sh` turns it on for the Pi (set `NETSCAN_AUTO_UPDATE=0` when running it to skip).
- On the Pi, `install-pi.sh` makes the service user own `/opt/netScan`, and the unit lists it under `ReadWritePaths`, so the service can update itself. A private repository needs credentials the service user can use (a read-only deploy key or token). Re-run `install-pi.sh` once to get this on an existing install.
- Updates run as the owner of the checkout, so a root-run dashboard on the Mac does not leave root-owned files in your repo. Demo mode never updates.
- Running scans and timers are interrupted by the restart; timetables re-apply when it is back.

### Dashboard security

- Every `/api` call needs the bearer token (constant-time compare). Tokens come from `web_token` in the data dir, `--token`, or `$NETSCAN_WEB_TOKEN`.
- The server is plain HTTP. On a LAN treat the token like a Wi-Fi password; do not port-forward it or expose it to the internet. For remote access use a VPN (WireGuard/Tailscale) or an SSH tunnel: `ssh -L 8787:127.0.0.1:8787 pi@<pi-ip>`, and bind the Pi to `--host 127.0.0.1`.
- Default bind is `127.0.0.1`. Binding wider prints a warning. Loopback binds check the `Host` header (DNS-rebinding), there is no CORS, a strict CSP is set, and device names are rendered as text only.
- The dashboard cannot widen the allow-list or touch the protected gateway/host: it uses the same scope and block guards as the CLI. Config is read-only there except first-run `init` and the alert settings (which can only hold http(s) URLs and never widen scope).

## Configuration

`~/.netscan/config.toml` (or `$NETSCAN_HOME`, or `--home`/`--config`). See [`config.example.toml`](config.example.toml). Key safety rules enforced at load time: the allow-list must be **private IPv4** and no larger than a `/16`; the host's detected network must sit inside it or every command refuses. `netscan init` also pins your router's MAC as `network.gateway_mac` when it can resolve it, because a CIDR alone cannot tell your `192.168.1.0/24` from a cafe's; if the gateway MAC differs, every command refuses. Keep that line (and re-run `init --force` if you replace the router).

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e . --no-deps
pytest
```

CI (`.github/workflows/ci.yml`) runs the suite on Python 3.10 and 3.12. All network I/O sits behind `netscan.net.Transport`; tests use a fake transport and scapy packets built in memory, so they need no root and touch no network. The suite covers parsing, allow-list refusal, protected-host refusal, block persistence/enforcement/restore, new-device detection, alerts, traffic metadata extraction and the CLI end to end.

Layout: `netscan/safety.py` (scope guard + notice), `net.py` (wire I/O), `monitor.py` (inventory/events), `blocker.py`, `traffic.py`, `daemon.py`, `cli.py`, `store.py` (sqlite), and `web/` (`controller.py` jobs/services/schedules, `schedule.py`, `server.py` JSON API, `demo.py`, `static/` the JS frontend).

## Licence / responsibility

You are responsible for how you use this tool. Scanning or interfering with devices on networks you do not own may be unlawful.
