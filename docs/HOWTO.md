# netScan how-to guide

Everything you need to run and look after netScan on your Mac and your Raspberry Pi. The guide starts with a cheat sheet of commands, then goes through each task step by step.

> Only use netScan on networks you own or are authorised to manage.

Contents

1. [Useful commands](#1-useful-commands)
2. [Where things live](#2-where-things-live)
3. [Install and start on the Mac](#3-install-and-start-on-the-mac)
4. [Install on the Raspberry Pi](#4-install-on-the-raspberry-pi)
5. [Open the dashboard from your iPhone or another computer](#5-open-the-dashboard-from-your-iphone-or-another-computer)
6. [The access token](#6-the-access-token)
7. [Updating netScan](#7-updating-netscan)
8. [Pushing changes to GitHub with `netscan-sync`](#8-pushing-changes-to-github-with-netscan-sync)
9. [Scanning and devices](#9-scanning-and-devices)
10. [Blocking devices](#10-blocking-devices)
11. [Timers, timetables and schedules](#11-timers-timetables-and-schedules)
12. [Traffic capture](#12-traffic-capture)
13. [Alerts](#13-alerts)
14. [Presence and security checks](#14-presence-and-security-checks)
15. [Temporarily changing this machine's MAC address](#15-temporarily-changing-this-machines-mac-address)
16. [Configuration](#16-configuration)
17. [Backups, data and resetting](#17-backups-data-and-resetting)
18. [Troubleshooting](#18-troubleshooting)
19. [Development](#19-development)

---

## 1. Useful commands

Where a command begins with `ssh`, run it on your Mac. Where it starts with `sudo systemctl` or `journalctl`, run it on the Pi (log in with `ssh` first).

### netScan on the Mac

Run these from the repo with the virtualenv active:

```bash
cd ~/Documents/DEV/netScan
source .venv/bin/activate
```

| Task | Command |
| --- | --- |
| Start the dashboard (this Mac only) | `sudo -E .venv/bin/netscan web --open` |
| Start the dashboard without root | `netscan web --open` |
| Try it on a fake network | `netscan web --demo` |
| First-time setup (writes your subnet allow-list) | `netscan init` |
| Scan the network (full ARP sweep) | `sudo -E .venv/bin/netscan scan` |
| Scan without root (slower, less complete) | `netscan scan` |
| Scan with a longer wait | `sudo -E .venv/bin/netscan scan --timeout 6` |
| Scan without reverse DNS lookups | `netscan scan --no-hostnames` |
| List known devices (no network access) | `netscan list` |
| Detail for one device | `netscan show 192.168.1.20` (or a MAC) |
| Capture traffic metadata for 60 s | `sudo -E .venv/bin/netscan traffic --duration 60` |
| Block a device | `netscan block 192.168.1.20 --reason "bedtime"` |
| Keep blocks enforced | `sudo -E .venv/bin/netscan enforce` |
| List blocks | `netscan blocks` |
| Unblock a device | `netscan unblock 192.168.1.20` |
| Recent events | `netscan events` |
| Watch for new devices in the foreground | `sudo -E .venv/bin/netscan watch` |
| Refresh the vendor (OUI) table | `netscan update-oui` |
| Is there a newer version? | `netscan update --check` |
| Update now | `netscan update` |
| Automatic updates on / off | `netscan update --auto on` / `netscan update --auto off` |
| Temporary MAC: status | `netscan spoof status` |
| Temporary MAC: set for 30 min | `sudo -E .venv/bin/netscan spoof set aa:bb:cc:dd:ee:ff --minutes 30` |
| Temporary MAC: put the real one back | `sudo -E .venv/bin/netscan spoof restore` |
| Show the version | `netscan --version` |
| Re-read the own-network notice | `netscan notice` |
| Push the agent's latest build to GitHub | `netscan-sync` |
| Run the tests | `pytest` |

Global options go before the subcommand: `--home DIR`, `--config FILE`, `--accept-terms`, `-v`. Example: `netscan --home ~/Documents/DEV/netScan/.netscan list`.

`sudo` does not see your virtualenv, so use `.venv/bin/netscan` after it. `-E` keeps your `NETSCAN_HOME` so root uses the same database as your normal user.

### The Pi service

| Task | Command |
| --- | --- |
| Log in from the Mac | `ssh yeomeo@R-Bot.local` (or `ssh yeomeo@<pi-ip>`) |
| Is the service running? | `systemctl status netscan-web --no-pager` |
| Follow the logs | `journalctl -u netscan-web -f` |
| Last 100 log lines | `journalctl -u netscan-web -n 100 --no-pager` |
| Restart | `sudo systemctl restart netscan-web` |
| Stop / start | `sudo systemctl stop netscan-web` / `sudo systemctl start netscan-web` |
| Start at boot / not at boot | `sudo systemctl enable netscan-web` / `sudo systemctl disable netscan-web` |
| Show the dashboard URL and token | `echo "http://$(hostname -I \| awk '{print $1}'):8787/#token=$(sudo cat /var/lib/netscan/web_token)"` |
| Show the URL as a QR code | `qrencode -t ansiutf8 "http://$(hostname -I \| awk '{print $1}'):8787/#token=$(sudo cat /var/lib/netscan/web_token)"` |
| Install the QR tool (once) | `sudo apt install -y qrencode` |
| Rotate the token | `sudo rm /var/lib/netscan/web_token && sudo systemctl restart netscan-web` |
| Use the CLI against the Pi's data | `sudo -u netscan env NETSCAN_HOME=/var/lib/netscan /opt/netScan/.venv/bin/netscan list` |
| Check for / apply an update | `sudo -u netscan env NETSCAN_HOME=/var/lib/netscan /opt/netScan/.venv/bin/netscan update --check` |
| Re-run the installer (repairs / upgrades the setup) | `curl -fsSL https://raw.githubusercontent.com/YeomeoR/netScan/main/deploy/install-pi.sh \| sudo bash` |
| Which version is installed? | `git -C /opt/netScan log --oneline -1` |
| Pi's IP address | `hostname -I` |
| Free disk space | `df -h /` |

`hostname -I`, `/var/lib/netscan/web_token` and `apt` exist only on the Pi. On a Mac they give errors such as `hostname: illegal option -- I`.

---

## 2. Where things live

| What | Mac | Raspberry Pi |
| --- | --- | --- |
| Code | `~/Documents/DEV/netScan` | `/opt/netScan` |
| Virtualenv | `~/Documents/DEV/netScan/.venv` | `/opt/netScan/.venv` |
| Data folder (`NETSCAN_HOME`) | `~/.netscan` (root's runs: `/var/root/.netscan`) | `/var/lib/netscan` |
| Database (devices, events, sweeps, blocks, settings) | `~/.netscan/netscan.db` | `/var/lib/netscan/netscan.db` |
| Config | `~/.netscan/config.toml` | `/var/lib/netscan/config.toml` |
| Access token | `~/.netscan/web_token` | `/var/lib/netscan/web_token` |
| Service unit | none (run by hand or the Desktop launcher) | `/etc/systemd/system/netscan-web.service` |
| Logs | the terminal window | `journalctl -u netscan-web` |
| Desktop launcher | `~/Desktop/netScan.command` | none |

The Mac and the Pi each have their own database, token and device list. They do not sync with each other.

---

## 3. Install and start on the Mac

You need Python 3.10 or newer and git.

### First install

```bash
cd ~/Documents/DEV/netScan
python3 -m venv .venv
source .venv/bin/activate
pip install .            # or "pip install -e ." while developing
netscan init             # detects your subnet and your router, writes ~/.netscan/config.toml
```

`netscan init` shows the own-network notice on first run. It will not run until you accept it.

### Run the dashboard

```bash
sudo -E .venv/bin/netscan web --open
```

It opens `http://127.0.0.1:8787/#token=...` in your browser. Root is only needed for the ARP sweep, ARP watch, the enforcer and capture. Without sudo the dashboard still opens, but those features report a clear error.

Try it safely first with a fake network and throwaway data:

```bash
netscan web --demo
```

### The Desktop double-click launcher

`deploy/mac-launch.sh` updates netScan from GitHub (`main`) and then starts the dashboard. Create the Desktop icon once:

```bash
printf '#!/bin/bash\nexec bash ~/Documents/DEV/netScan/deploy/mac-launch.sh\n' > ~/Desktop/netScan.command
chmod +x ~/Desktop/netScan.command
```

Double-click `netScan.command`, type your Mac password when asked, and the dashboard opens. Because the icon only runs the script in the repo, launcher improvements arrive with each update.

If the script says "No such file or directory", the repo checkout is missing or on an older commit. Make sure `~/Documents/DEV/netScan/deploy/mac-launch.sh` exists and that the repo is on `main` (`git -C ~/Documents/DEV/netScan checkout main && git pull`).

### Share one database between normal and sudo runs

When you use `sudo`, data goes to root's home. To keep a single database:

```bash
export NETSCAN_HOME=~/Documents/DEV/netScan/.netscan      # already in .gitignore
sudo -E .venv/bin/netscan scan
```

Put the `export` line in `~/.zshrc` to make it permanent.

---

## 4. Install on the Raspberry Pi

### What you need

- Raspberry Pi OS (or Debian / Ubuntu) on the same network, with internet access.
- The GitHub repository `YeomeoR/netScan` readable from the Pi. The simplest way is to make it public. For a private repository, give the service user a read-only deploy key or token (see below).
- The latest code pushed to `main` (see [section 8](#8-pushing-changes-to-github-with-netscan-sync)).

### One-command install

Log in to the Pi (`ssh yeomeo@R-Bot.local`), then run:

```bash
curl -fsSL https://raw.githubusercontent.com/YeomeoR/netScan/main/deploy/install-pi.sh | sudo bash
```

The `[sudo] password for ...` prompt is the Pi login password of the user you are logged in as. It is not a GitHub password.

The script:

1. installs `python3`, `python3-venv`, `python3-pip`, `libpcap0.8` and `git`;
2. creates the `netscan` system user and `/var/lib/netscan`;
3. clones the repo into `/opt/netScan` (or updates it);
4. builds the virtualenv and installs netScan;
5. writes the config (detects your subnet, pins your router's MAC);
6. turns on automatic updates (set `NETSCAN_AUTO_UPDATE=0` to skip);
7. installs and starts the `netscan-web` systemd service;
8. prints the dashboard URL with the token.

It takes a few minutes. Plenty of scrolling output while it builds is normal.

Optional settings for the installer: `NETSCAN_REPO`, `NETSCAN_BRANCH`, `NETSCAN_DEST`, `NETSCAN_PORT` and `NETSCAN_AUTO_UPDATE`. Example:

```bash
curl -fsSL https://raw.githubusercontent.com/YeomeoR/netScan/main/deploy/install-pi.sh | sudo NETSCAN_PORT=9000 bash
```

### Check that it works

```bash
systemctl status netscan-web --no-pager        # should say "active (running)"
journalctl -u netscan-web -n 50 --no-pager
```

Once it is running, the Pi sweeps your network every 5 minutes by default, listens for new devices, enforces blocks and checks GitHub for updates. It keeps doing this with your browser closed and starts again after a reboot.

### If the installer fails with `curl: (22) ... 404`

GitHub cannot serve the file. Either the repository is private, or `deploy/install-pi.sh` has not been pushed to `main` yet. Fix it by making the repository public (GitHub > Settings > Danger zone), or push the latest code, then run the command again.

### If `systemctl status` says `Unit netscan-web.service could not be found`

The install did not finish, usually because of the 404 above. Fix the cause and run the installer again. It is safe to repeat.

### Private repositories

The Pi needs a credential it can use without a prompt. Create a fine-grained token or deploy key with read-only access to this one repository, then give the `netscan` user a way to use it, for example a clone URL containing the token (`NETSCAN_REPO=https://<token>@github.com/YeomeoR/netScan.git`). Keep the token out of chat and out of the repo. Anyone with the token can read the code.

### Uninstall

```bash
sudo systemctl disable --now netscan-web
sudo rm /etc/systemd/system/netscan-web.service && sudo systemctl daemon-reload
sudo rm -rf /opt/netScan            # code
sudo rm -rf /var/lib/netscan        # data: devices, events, token (optional)
sudo userdel netscan
```

---

## 5. Open the dashboard from your iPhone or another computer

The Pi serves the dashboard on port 8787 for every device on your Wi-Fi.

### With a QR code (easiest for the iPhone)

1. Log in to the Pi from your Mac: `ssh yeomeo@R-Bot.local`.
2. Install the QR tool once: `sudo apt install -y qrencode`.
3. Show the code:

   ```bash
   qrencode -t ansiutf8 "http://$(hostname -I | awk '{print $1}'):8787/#token=$(sudo cat /var/lib/netscan/web_token)"
   ```

4. Point the iPhone camera at the code in the terminal window and tap the banner. Make the terminal window larger if it will not scan.

### By typing the URL

On the Pi:

```bash
echo "http://$(hostname -I | awk '{print $1}'):8787/#token=$(sudo cat /var/lib/netscan/web_token)"
```

Open the printed address in Safari. To find the token by itself, run `sudo cat /var/lib/netscan/web_token`; you can paste it into the dashboard's login screen.

### Tips

- Add it to the iPhone home screen: Safari Share button > Add to Home Screen.
- The dashboard works over `http`, so the address starts with `http://`, not `https://`.
- A Pi that gets a different IP after a reboot changes the URL. Give the Pi a fixed address (DHCP reservation) in your router, or use `R-Bot.local`.
- The iPhone must be on the same Wi-Fi as the Pi. Wi-Fi client isolation or a guest network will block it.
- Use a VPN (WireGuard or Tailscale) for access away from home. Do not port-forward the dashboard.

### Reaching the Pi's dashboard from the Mac

Just browse to `http://R-Bot.local:8787/` or the Pi's IP and sign in with the token. For a more private route, bind the dashboard to the Pi only and use an SSH tunnel:

```bash
ssh -L 8787:127.0.0.1:8787 yeomeo@R-Bot.local
# then open http://127.0.0.1:8787/ on the Mac (needs the token)
```

(That needs the Pi service started with `--host 127.0.0.1` instead of `0.0.0.0`; edit `/etc/systemd/system/netscan-web.service`, run `sudo systemctl daemon-reload` and restart the service.)

---

## 6. The access token

The dashboard asks for a token on every request. It works like a password.

- The token is created once, the first time the dashboard starts, and is saved in `web_token` in the data folder (`~/.netscan/web_token` on the Mac, `/var/lib/netscan/web_token` on the Pi). It stays the same across restarts, reboots and updates, and your iPhone remembers it after the first visit.
- It changes only if you delete or replace the file, start the dashboard with `--token` or `NETSCAN_WEB_TOKEN`, or reinstall with a wiped data folder.
- The Mac and the Pi have separate tokens.
- To rotate it:
  - Pi: `sudo rm /var/lib/netscan/web_token && sudo systemctl restart netscan-web`
  - Mac: delete `~/.netscan/web_token` and start the dashboard again.
  Then use the new URL or QR code on your devices.
- The dashboard uses plain HTTP, so anyone on your Wi-Fi who has the token can control the scanner. Do not share screenshots of the URL or QR code, and do not expose the port to the internet.

---

## 7. Updating netScan

### How updates reach each machine

```
you (or the agent) -> GitHub main -> Pi checks every 5 min -> Pi updates and restarts
                                  -> Mac launcher updates on each double-click
```

### Pi: automatic

The installer turns on automatic updates. When you push to `main`:

1. the Pi checks GitHub every 5 minutes (even with no browser open);
2. it fast-forwards `/opt/netScan`, reinstalls into the virtualenv, and checks that the new code imports;
3. it restarts the service. The open dashboard page notices and reloads itself.

If the install or the import check fails, the Pi goes back to the previous commit.

Other ways to update the Pi:

- In the dashboard, open System > Updates and press Update now.
- In a terminal on the Pi: `sudo -u netscan env NETSCAN_HOME=/var/lib/netscan /opt/netScan/.venv/bin/netscan update`.
- Re-run the installer one-liner.

Turn automatic updates on or off:

```bash
sudo -u netscan env NETSCAN_HOME=/var/lib/netscan /opt/netScan/.venv/bin/netscan update --auto off
```

Or use the checkbox on System > Updates. Anyone who can push to `main` can run code on a machine with automatic updates on, so only use it with a repository that only you can push to.

### Mac

- The Desktop launcher runs `git fetch`, switches to `main` if your checkout is clean, runs `netscan update`, then starts the dashboard.
- In a terminal: `netscan update` (or `netscan update --check` to just look).
- If you use `pip install .` rather than `pip install -e .`, an update reinstalls automatically. In the dashboard: System > Updates > Update now.

### When an update refuses to run

It stops when the checkout has uncommitted changes or commits GitHub does not have, when you are not on a branch it can track, or when the install was made from a tarball with no `.git` folder. Commit or discard your changes, or set `NETSCAN_SOURCE=/path/to/clone` to point at the real clone.

---

## 8. Pushing changes to GitHub with `netscan-sync`

Changes the agent makes arrive as a tarball. `netscan-sync` unpacks the newest one into your repo, commits it, and pushes. Once it is on GitHub, the Pi and the Mac launcher update themselves.

### One-time setup

1. Put the script at `~/Documents/DEV/netscan-sync` and make it executable: `chmod +x ~/Documents/DEV/netscan-sync`. The script must contain only the script, not the alias line.
2. Add the alias to your shell profile, not to the script:

   ```bash
   echo 'alias netscan-sync="$HOME/Documents/DEV/netscan-sync"' >> ~/.zshrc
   source ~/.zshrc
   ```

### Every time

```bash
netscan-sync
```

It unpacks `netScan-source-with-dashboard.tar.gz` over `~/Documents/DEV/netScan` (the same command every time), shows the changed files, commits with the message "netScan: latest from the agent", and pushes the current branch. If nothing changed, it says so and stops.

Override the locations if needed with `NETSCAN_REPO_DIR=...` and `NETSCAN_TARBALL=...`.

### Doing it by hand

```bash
cd ~/Documents/DEV/netScan
tar -xzf "$HOME/Library/Application Support/Cursor/AgentStores/cursor_agent_stores/bc-aa8567fc-6eb7-4874-99b4-bafb24340444/files/docs/netscan/netScan-source-with-dashboard.tar.gz" --strip-components=1
git add -A && git commit -m "netScan: latest" && git push origin main
```

`--strip-components=1` removes the `netScan/` folder that wraps the files in the tarball.

If the push is rejected, GitHub has commits you do not: `git pull --rebase origin main`, then push again.

---

## 9. Scanning and devices

### Scan

- Dashboard: Devices tab > Scan now (Scan options sets the wait time and whether to look up hostnames).
- Terminal: `sudo -E .venv/bin/netscan scan`.

A scan is an ARP sweep of your allowed subnet. It records each device's IP, MAC, vendor, hostname, first seen, last seen and online state. Run with root for the full sweep. Without root, netScan falls back to a slower method that finds most devices.

### Tips for better results

- Sleeping phones answer late. Raise "Wait for replies" (or `--timeout 6`), or scan twice.
- If everything shows Offline, raise "Mark offline after" (for example 15 minutes). The Pi default is 900 s.
- Randomised ("private") MAC addresses on iPhones and Android show vendor `(randomised MAC)` and appear as a new device if the address changes per network.
- Hostnames come from reverse DNS. Many routers do not provide them, so `-` is common.
- Wi-Fi guest networks, client isolation and VLANs hide devices from the sweep.

### Name and organise devices

Open a device in the Devices tab to set a name, owner, type and notes, and a review status (Known, Guest, or Not reviewed). New devices start as Not reviewed. The banner at the top and the Unreviewed filter help you go through them, and bulk actions mark many as known or guests, block them for a while, or add them to a timetable. These labels live only in the dashboard (and the database).

### Look at one device from the terminal

```bash
netscan show 192.168.1.20
netscan show aa:bb:cc:dd:ee:ff
```

### Events

Dashboard: Activity tab. Terminal: `netscan events`. It records new devices, online/offline changes, IP changes, blocks and unblocks.

### Refresh the vendor names

System > Vendor database > Update, or `netscan update-oui`. It needs internet access. The built-in table keeps working if the download fails.

---

## 10. Blocking devices

### From the dashboard

Devices tab > open the device > Block, or Access tab for the list of blocks and timers. Give a reason so you remember why.

### From the terminal

```bash
netscan block 192.168.1.20 --reason "bedtime"
netscan blocks
netscan unblock 192.168.1.20
```

A block is stored in the database and survives restarts. It only has an effect while an enforcer is running:

- Pi: the service does it for you.
- Mac: start the enforcer service on the System tab, or run `sudo -E .venv/bin/netscan enforce` (Ctrl-C restores the real addresses).

### How blocking works

- ARP cutoff (the default, `block.method = "arp"`): netScan tells the device that the router is at a dead address, and tells the router the same about the device, every 2 seconds. It works from any machine on the LAN with root. `unblock` and a clean shutdown send the true addresses back; otherwise devices recover when their ARP caches expire.
- `iptables` / `nftables`: Linux only. It works only if this machine forwards the target's traffic (it is your router). Rules are re-applied when the service starts.

### What it cannot do

- Devices with static ARP entries, routers with ARP protection, and Wi-Fi isolation can defeat an ARP cutoff. It is a home convenience, not a security boundary.
- The router, the machine running netScan, and anything in `safety.extra_protected` can never be blocked.
- A device that changes its MAC (randomised address) looks like a new device and is no longer blocked.
- A device held by a timetable or timer cannot be unblocked by hand; pause or delete the rule instead.

---

## 11. Timers, timetables and schedules

### Block for a while

Press **Block for...** on a device (or on several ticked devices) and pick 15 min, 30 min, 1 hour, 2, 4 or 8 hours, or enter your own time. The block lifts itself, as long as netScan keeps running.

### Weekly timetables

Access tab > New timetable. Choose devices, days, and a start and end time in the machine's local time (the Pi uses its own clock). An overnight window belongs to the day it starts on, and `24:00` is allowed as an end time. A timetable only releases blocks that it placed; blocks you added by hand stay.

Rules are evaluated every 5 seconds by the dashboard process, so the dashboard (or the Pi service) must be running. A Mac that is asleep does not enforce anything.

### Timed sweeps

Schedule tab > New schedule. Kinds: every N seconds (30 s to 7 days), daily at a time, or once. Each schedule has its own wait time, hostname lookup, mark-offline-after and optional traffic capture. The Pi keeps running them with your browser closed. A run that overlaps the previous one is skipped and flagged. Schedules persist across restarts.

The Pi also seeds a "Periodic sweep" schedule from `daemon.sweep_interval` (default 300 s).

---

## 12. Traffic capture

Dashboard: Traffic tab > Capture now. Terminal: `sudo -E .venv/bin/netscan traffic --duration 60`.

It records metadata only: bytes, packets, protocol, service label, peers, ports and hostnames seen in DNS. Payloads are never stored.

Important limit: on a normal switched network, a machine only sees its own traffic plus broadcast and multicast. To see another device's traffic you need the capture machine in the path (the Pi acting as the router or bridge), a mirrored port on a managed switch, or capture on the router itself. netScan does not do ARP interception for monitoring.

Encrypted traffic (HTTPS, QUIC, DNS over HTTPS) is classified by port; netScan does not look inside it.

To record traffic continuously on the Pi, set `capture_traffic = true` under `[daemon]` in `/var/lib/netscan/config.toml`, then restart the service.

---

## 13. Alerts

Alerts always go to the terminal or the journal. You can also send them to your phone or another service.

### In the dashboard

System > Alerts. Fill in a ntfy URL or a webhook URL, choose which events notify you, and press Send test. Settings saved here win over `config.toml`; "Reset to config file" removes them. Secrets are never sent back to the browser, only the host name.

A device can be set to "always alert" or "never alert" from its details.

### In the config file

```toml
[alerts]
ntfy_url = "https://ntfy.sh/your-private-topic"   # optional: ntfy_token = "..."
webhook_url = "https://example.invalid/hook"      # receives JSON {kind, message, ip, mac, vendor, hostname, text}
notify_on = ["new_device", "ip_conflict", "arp_spoof", "rogue_dhcp", "port_opened"]
```

Other event names: `device_online`, `device_offline`, `ip_changed`, `blocked`, `unblocked`. Only `http` and `https` addresses are accepted. A failing webhook or ntfy server is logged and never stops the service.

### What a notification contains

The headline is the device itself: the name you gave it in the dashboard, otherwise the vendor and the last two bytes of its MAC (`Samsung 77:25: new device`), otherwise `Private MAC 25:77` for a randomised address, otherwise the IP. The hostname is in the body, not the headline. The body also lists IP, MAC, vendor, owner, type, review status, how long netScan has known the device, and which machine sent the message (useful when the Mac and the Pi share one topic). "Back online" says how long the device was unseen.

**Getting messages you did not tick?** Three usual causes:

1. The device is set to "Always alert about this device". That overrides the tick boxes for every event kind. The message then ends with `Sent because: this device is set to 'Always alert'`. Check on the Pi: `sqlite3 /var/lib/netscan/netscan.db "select mac,alert from device_meta where alert != 'default'"`.
2. A second netScan (for example on the Mac) uses the same ntfy topic. Each machine has its own alert settings. The `Sent by` line names the sender.
3. The settings were not saved. See what the Pi actually uses: `sqlite3 /var/lib/netscan/netscan.db "select json_extract(value,'$.notify_on') from settings where key='alerts'"`.

### Phone notifications with ntfy

1. Install the ntfy app on the iPhone.
2. Subscribe to a long, hard-to-guess topic name.
3. Put `https://ntfy.sh/<that-topic>` in System > Alerts and send a test.

---

## 14. Presence and security checks

### Presence

Presence tab. Tick the devices that mean "someone is home" and give them an owner. The page shows who is probably in, rebuilt from the event log, so treat it as approximate: phones sleep their Wi-Fi, and times follow your sweeps and the offline-after setting.

### Security tab

- IP conflict: two MACs claiming one IP in a sweep (reported at most once every 6 hours per conflict). A router that answers ARP for every address can cause false findings.
- ARP spoof: a non-router MAC claiming the router's IP. Needs the ARP watch service running.
- Rogue DHCP: sends one DHCP discover that requests no lease and lists every server that answers. Needs root.
- Port check: TCP connects to 31 common ports on up to 64 in-scope devices. Risky services and newly opened ports raise `port_opened`.

---

## 15. Temporarily changing this machine's MAC address

Use this to see how your network treats a particular address. It changes only the machine running netScan (the Pi or the Mac). It never touches another device.

### In the dashboard

System > Temporary MAC address:

1. Pick a device from the list to fill the address in, or choose from the dropdown in the address box, or type an address.
2. Choose how long (15 minutes to 8 hours).
3. If that device is currently online, tick the confirmation box. Two machines with one address knock each other off the network.
4. Press **Use this address**. Expect a few seconds without network, and possibly a new IP address. If you are using the Pi's dashboard from the Pi's own address, the page may not answer until the real address is back.
5. Press **Put the real address back now** whenever you are done.

### In a terminal

```bash
netscan spoof status
sudo -E .venv/bin/netscan spoof set aa:bb:cc:dd:ee:ff --minutes 30
sudo -E .venv/bin/netscan spoof restore
```

`--yes` skips the confirmation. While `spoof set` runs it waits and restores when the time is up; Ctrl-C restores early.

### Safety

- Your real address is saved first. It is restored when the timer ends, when you press the button or run `restore`, and after a reboot.
- Refused: the router's address, multicast addresses, devices that are currently blocked, and (unless you confirm) a device that is online.
- A device's address in the database cannot be edited. Names, blocks and rules hang off it.
- Linux uses `ip link set` and needs root or `CAP_NET_ADMIN` (the Pi service has it). macOS uses `ifconfig <interface> ether <mac>` and needs `sudo`; on Wi-Fi it often works only while Wi-Fi is on but not joined to a network, and some newer Macs refuse. So far it has only been tested against a simulated interface.
- If something goes wrong and the network stays down, run `netscan spoof restore`, or reboot the machine (the real address is applied on reboot on the Pi; on a Mac a reboot also restores the hardware address).

---

## 16. Configuration

File: `~/.netscan/config.toml` on the Mac and `/var/lib/netscan/config.toml` on the Pi. Edit it with `nano ~/.netscan/config.toml`, or on the Pi `sudoedit /var/lib/netscan/config.toml`, then restart the service (`sudo systemctl restart netscan-web`). The dashboard shows the config read-only under System.

```toml
[network]
allowed_subnets = ["192.168.1.0/24"]   # netScan refuses to scan or block anything outside these
# interface = "en0"
# gateway = "192.168.1.1"
# gateway_mac = "aa:bb:cc:dd:ee:ff"    # pins your router so the same subnet at a cafe is refused
# follow_network = true                # laptop use: also allow whichever private network you are connected to

[safety]
extra_protected = []                   # more IPs or MACs that must never be blocked

[block]
method = "arp"                         # or "iptables" / "nftables" (Linux router only)

[daemon]
sweep_interval = 300                   # seconds between automatic sweeps
offline_after = 900                    # seconds unseen before a device is marked offline
arp_watch = true                       # alert the moment a new MAC appears
capture_traffic = false
silent_baseline = true                 # the first sweep seeds devices without alerting for each
```

Rules enforced when the config loads: the allow-list must be private IPv4 and no larger than a /16, and the network the machine is on must sit inside it.

If you replace your router or move house, run `netscan init --force` (stop the services first) so the router is pinned again.

**Using the Mac on other networks (family and friends, with their say-so).** Run `netscan init --force --follow` (or tick "I move between networks" on the dashboard's first-run card). That writes `follow_network = true` and does not pin a router. From then on netScan allows whichever private network the Mac is connected to, as well as anything in `allowed_subnets`. The same limits apply: private IPv4 only, no larger than a /16, and a public network is refused. Press "Re-detect network" on the System tab after joining a new network (services stopped). Keep the Pi's config as it is; it stays on the home network. All networks share one database, so use a separate `NETSCAN_HOME` per place if you want the lists kept apart. Leave Block and MAC changing alone on other people's networks.

Environment variables: `NETSCAN_HOME` (data folder), `NETSCAN_WEB_TOKEN` (token override), `NETSCAN_SOURCE` (path to the git clone used for updates), `NETSCAN_BRANCH` (branch the launcher and installer follow; default `main`).

---

## 17. Backups, data and resetting

Everything is in the data folder, mainly `netscan.db` (SQLite), `config.toml` and `web_token`.

### Back up the Pi

```bash
sudo systemctl stop netscan-web
sudo cp /var/lib/netscan/netscan.db ~/netscan-backup.db
sudo systemctl start netscan-web
```

Copy it to your Mac with `scp yeomeo@R-Bot.local:~/netscan-backup.db .`.

### Look inside the database

```bash
sqlite3 /var/lib/netscan/netscan.db ".tables"
```

(`sudo apt install -y sqlite3` if the command is missing.)

### Start fresh

Stop the service, then move the database away; netScan creates a new one:

```bash
sudo systemctl stop netscan-web
sudo mv /var/lib/netscan/netscan.db /var/lib/netscan/netscan.db.old
sudo systemctl start netscan-web
```

You lose device names, events, rules and schedules. Keep `config.toml` and `web_token` so your allow-list and your devices' saved token still work.

### If files in `~/.netscan` are owned by root

This happens after mixing sudo and non-sudo runs:

```bash
sudo chown -R "$USER" ~/.netscan
```

---

## 18. Troubleshooting

| Symptom | What to do |
| --- | --- |
| Blank page at `127.0.0.1:8787` | Check the terminal for errors. Make sure nothing else uses port 8787 (`lsof -i :8787`) or pick another with `--port 8788`. Hard refresh the browser. Update, because older builds could miss static files. |
| "Port not loading" after double-clicking the launcher | The window may be waiting for your Mac password. Type it (nothing shows as you type) and press Enter. |
| Back at the login screen or "unauthorised" | The token is wrong or was rotated. Use the URL printed at startup or the QR code, or paste the token from `web_token`. |
| `nullnullnull` or the word `null` appears on a card | Fixed in the latest build. Update to the newest version. |
| `hostname: illegal option -- I` | You ran a Pi command on the Mac. `ssh` into the Pi first. |
| `cat: /var/lib/netscan/web_token: No such file or directory` on the Mac | Same cause. On the Mac the token is `~/.netscan/web_token`. |
| `command not found: qrencode` | Install it on the Pi: `sudo apt install -y qrencode` (on a Mac: `brew install qrencode`). |
| `command not found: netscan-sync` | The alias is missing. Add it to `~/.zshrc` and run `source ~/.zshrc`. |
| `curl: (22) ... 404` while installing on the Pi | The repo is private or the file is not on `main` yet. See [section 4](#4-install-on-the-raspberry-pi). |
| `Unit netscan-web.service could not be found` | The install did not complete. Re-run the installer. |
| Service keeps restarting | `journalctl -u netscan-web -n 100 --no-pager` and read the last error. A config problem exits with code 2 and will not loop. |
| Scan finds few devices | Use sudo, raise the wait time, scan twice. |
| Everything shows Offline | Raise "Mark offline after". |
| A blocked device is back online | The enforcer is not running, the machine is asleep, or the device changed its MAC. Start the enforcer. |
| `ModuleNotFoundError: netscan` | Reinstall into the venv with `pip install .` and run it again after updates. |
| "Wrong network detected" or "refusing to run" | The machine is on a network outside the allow-list or with a different router. Check `config.toml`. If it is genuinely your new network, run `netscan init --force`. |
| An update will not apply | See "When an update refuses to run" in [section 7](#7-updating-netscan). |
| The Pi dashboard is unreachable after a MAC change | Wait for the timer, or restore from a terminal on the Pi: `sudo -u netscan env NETSCAN_HOME=/var/lib/netscan /opt/netScan/.venv/bin/netscan spoof restore`. |
| The iPhone cannot connect | Same Wi-Fi as the Pi? Guest network or client isolation on? Try the Pi's IP instead of `R-Bot.local`. |

---

## 19. Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e . --no-deps
pytest
```

- Tests use a fake transport and in-memory packets, so they need no root and touch no network.
- CI (`.github/workflows/ci.yml`) runs the suite on Python 3.10 and 3.12.
- After a change, reinstall (`pip install .`) if you did not use `-e`, so the Desktop launcher and `netscan` pick it up.
- The frontend is plain JavaScript in `netscan/web/static/` with no build step.

Layout:

| Path | Purpose |
| --- | --- |
| `netscan/cli.py` | The terminal commands |
| `netscan/safety.py` | Allow-list and notice |
| `netscan/net.py` | Network I/O behind a swappable transport |
| `netscan/monitor.py`, `traffic.py`, `blocker.py`, `daemon.py` | Inventory, capture, blocking, background work |
| `netscan/spoof.py` | Temporary MAC address changes |
| `netscan/store.py` | SQLite storage |
| `netscan/web/` | Dashboard: `server.py` (JSON API), `controller.py` (jobs, services, schedules), `static/` (frontend) |
| `deploy/` | `install-pi.sh`, the systemd units, `mac-launch.sh` |

For the full reference on what each feature does and its limits, see the [README](../README.md).
