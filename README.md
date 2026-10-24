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
notify_on = ["new_device", "device_offline", "ip_changed"]
```

Terminal/journal logging is always on. Webhook/ntfy failures are logged and never stop the daemon. Only `http(s)` URLs are accepted.

## Configuration

`~/.netscan/config.toml` (or `$NETSCAN_HOME`, or `--home`/`--config`). See [`config.example.toml`](config.example.toml). Key safety rules enforced at load time: the allow-list must be **private IPv4** and no larger than a `/16`; the host's detected network must sit inside it or every command refuses. `netscan init` also pins your router's MAC as `network.gateway_mac` when it can resolve it, because a CIDR alone cannot tell your `192.168.1.0/24` from a cafe's; if the gateway MAC differs, every command refuses. Keep that line (and re-run `init --force` if you replace the router).

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e . --no-deps
pytest
```

CI (`.github/workflows/ci.yml`) runs the suite on Python 3.10 and 3.12. All network I/O sits behind `netscan.net.Transport`; tests use a fake transport and scapy packets built in memory, so they need no root and touch no network. The suite covers parsing, allow-list refusal, protected-host refusal, block persistence/enforcement/restore, new-device detection, alerts, traffic metadata extraction and the CLI end to end.

Layout: `netscan/safety.py` (scope guard + notice), `net.py` (wire I/O), `monitor.py` (inventory/events), `blocker.py`, `traffic.py`, `daemon.py`, `cli.py`, `store.py` (sqlite).

## Licence / responsibility

You are responsible for how you use this tool. Scanning or interfering with devices on networks you do not own may be unlawful.
