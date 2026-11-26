# tuisnitch

An application firewall for Linux, in the spirit of LittleSnitch, with two
front ends:

* **TUI** (`-ui tui`, the default): runs in your terminal.
* **Web** (`-ui web`): runs headless, e.g. as a systemd service, and serves a
  browser UI on `http://127.0.0.1:8484` that alerts you about new connections.

Pick one per run. In web mode the TUI isn't started; in TUI mode there is no
web server. Both drive the same engine, rules file and modes.

## How it works

```
app ──SYN/UDP──► nftables (table inet tuisnitch, OUTPUT hook)
                    │  ct state new, tcp/udp
                    ▼
                 NFQUEUE 4242 ──► tuisnitch: who sent it? (/proc/net/* → inode → /proc/*/fd)
                                   │  where to? (IP → hostname from observed DNS answers)
                                   ▼
                       mode / rules / ask user ──► ACCEPT or DROP verdict

DNS replies (udp sport 53, INPUT hook) ──► NFQUEUE 4243 ──► learn IP→name, always ACCEPT

remote ──SYN/UDP──► INPUT, before ufw/iptables ──► NFQUEUE 4244 (mark packet) ──► "seen", ACCEPT
                    host firewall (ufw) ── drops it? ──► never reported after → "blocked"
                    INPUT, after ufw, marked only ──► NFQUEUE 4245 ──► "passed", ACCEPT
```

## Incoming (watch only)

The **Incoming** tab (TUI and web) shows who is trying to connect *to* this
machine: one row per remote address, with the ports it tried, whether your
host firewall (ufw, iptables, firewalld…) **blocked** or **passed** each
attempt, and which program is listening on that port (none means the port is
closed). tuisnitch never drops inbound traffic itself. Both inbound queues
always accept, and the firewall in front decides.

* Only unicast TCP SYNs and first UDP packets to this host are counted.
  Broadcast/multicast LAN chatter (mDNS, SSDP) and loopback are skipped
  (`-loopback` includes loopback).
* At most 50 attempts/s (burst 100) go to userspace, so a flood or scan stays
  cheap. Attempts beyond that are not shown and are otherwise unaffected.
* "Passed" means the firewall let it through, not that a connection was made.
  A passed attempt to a port with no listener gets a TCP reset from the kernel.
* An attempt counts as blocked if it isn't seen after the firewall within 2s.
* `-no-inbound` turns this off (no inbound queues or chains at all).

Only the **first packet of each new flow** goes to userspace. Established
traffic stays in the kernel, so throughput is unaffected.

## Modes

| key | mode  | behaviour |
|-----|-------|-----------|
| `1` | ALERT | Matching rules apply; anything else pops a prompt and the packet is held until you answer (auto-deny after `-timeout`) |
| `2` | ALLOW | Everything new is allowed and logged (★ marks first-seen destinations) |
| `3` | BLOCK | Every new outbound connection is dropped (existing ones keep working) |

Prompt keys (TUI and web): `a` allow once, `A` allow always, `d` deny once, `D` deny always,
`s` cycles the rule scope (host+port → host any port → whole program).

Other keys: `tab` Connections/Incoming/Rules, `n` only-new filter, `↑↓` scroll/select,
`t` toggle rule allow/deny, `x` delete rule, `q` quit.

## Build & run

**Full install guide: [docs/INSTALL.md](docs/INSTALL.md)** (requirements,
`cargo run`, systemd service, upgrade, uninstall, troubleshooting).

```sh
cargo build --release                  # binary: target/release/tuisnitch
cargo test

cargo run -- -demo                     # TUI with fake traffic, no root needed
cargo run -- -demo -ui web             # web UI with fake traffic; prints a URL with the token

cargo run-root -- -ui web              # real thing, web mode: open http://127.0.0.1:8484
cargo run-root                         # real thing, TUI mode
cargo run-root -- -ui web -mode allow  # learn quietly first, watch the log
```

`cargo run-root` (an alias in `.cargo/config.toml`) builds as you and runs the
binary under `sudo`. That's the same as `sudo ./target/debug/tuisnitch …`.

## Web mode

The first visit asks for an **access token**. It is created on first start in
`/etc/tuisnitch/web-token` (root-only, mode 0600) and stays the same across
restarts:

```sh
sudo cat /etc/tuisnitch/web-token
```

Paste it into the page, or open `http://127.0.0.1:8484/?token=<token>` once.
The browser then keeps it in a cookie, so later visits go straight in. The
token is there because anything that can reach the UI can allow connections.
Without it, any local process (including the malware you're trying to catch)
or any web page you visit could approve its own traffic.

**Alerts.** Click **Enable notifications** on the page (or **Alerts → Test**).
Each new prompt then raises a desktop notification that stays until clicked,
plays a short sound, and shows the count in the tab title (`(2) tuisnitch`),
even when the tab is in the background. Keep the tab open (a pinned tab works
well). Under **Alerts** you can also get notified about first-seen
destinations in any mode, or turn the sound off. The page answers prompts with
buttons or the same keys as the TUI (`a` `A` `d` `D` `s`, `1` `2` `3` for
modes) and updates live over Server-Sent Events.

Web flags: `-listen 127.0.0.1:8484` (address and port), `-token-file PATH`
(`-token-file ""` makes a new token each run and prints it in the URL).

## Running as a service

`packaging/tuisnitch.service` runs web mode under systemd:

```sh
cargo build --release
sudo install -m 755 target/release/tuisnitch /usr/local/bin/tuisnitch
sudo install -m 644 packaging/tuisnitch.service /etc/systemd/system/tuisnitch.service
sudo systemctl daemon-reload
sudo systemctl enable --now tuisnitch
sudo cat /etc/tuisnitch/web-token      # then open http://127.0.0.1:8484
```

Read [docs/INSTALL.md](docs/INSTALL.md) before leaving it in alert mode: with
nobody answering, unknown connections are held for `-timeout` and then denied.
That guide also covers changing flags, upgrading and uninstalling.

## Flags

Flags use Go-style syntax (`-timeout 60s`, `-mode=allow`, `--no-dns`), so commands
written for the Go version still work.

Flags: `-ui tui|web`, `-listen ADDR`, `-token-file PATH`,
`-rules /etc/tuisnitch/rules.json`, `-timeout 60s`, `-queue 4242`,
`-loopback` (also judge connections to lo), `-fail-closed`, `-no-dns`,
`-no-inbound`, `-demo`. Queue numbers: outbound `-queue N`, DNS `N+1`, inbound `N+2` and `N+3`.

Rules are JSON (same format as the Go version) and can be edited by hand. `host` accepts `*` or a `*.example.com` wildcard.

## Safety

* The nft table uses `queue … bypass`: if tuisnitch crashes or is killed,
  new connections are **allowed**. Pass `-fail-closed` to drop them instead,
  which stays in force until you run `sudo nft delete table inet tuisnitch`.
* On exit the table is removed and held packets are released.
* The web UI listens on 127.0.0.1 by default and is plain HTTP. Binding to a
  non-loopback address prints a warning: put it behind TLS (or an SSH tunnel:
  `ssh -L 8484:127.0.0.1:8484 host`) rather than exposing it.
* With `-loopback`, your browser's own connection to the web UI is filtered
  too, and the prompt for it can only be answered from that same UI. Add a
  rule for your browser to `127.0.0.1` first, or don't combine `-loopback`
  with web mode.
* If you're on SSH, existing sessions survive BLOCK mode, but new ones from
  the box won't. Inbound SSH isn't affected; only outbound is filtered.
* Inbound watching marks the packets it queued with bit `0x04000000` of the
  packet mark (other bits are kept). If something else on the machine uses
  that bit for incoming packets, pass `-no-inbound`.

## Code layout

| file | job |
|------|-----|
| `queue.rs` | one netlink socket bound to all queues (outbound, DNS, inbound seen/passed); one thread owns held packets and applies verdicts sent back by the engine over a channel |
| `engine.rs` | modes, prompts, timeouts, rule application; inbound attempts grouped by remote |
| `packet.rs` / `dns.rs` | IPv4/IPv6 + TCP/UDP parsing; hand-written DNS answer parser |
| `procinfo.rs` | socket → inode → pid via `/proc` (also: who listens on a port) |
| `rules.rs` | rule matching and JSON persistence |
| `firewall.rs` | the nftables table |
| `ui.rs` | ratatui UI (`-ui tui`) |
| `web.rs` / `web/index.html` | axum server + browser UI (`-ui web`): token auth, SSE state stream, JSON actions |
| `packaging/tuisnitch.service` | systemd unit for web mode |

## Limitations

* Only locally-originated traffic (OUTPUT hook) is filtered. Docker/VM traffic
  goes through FORWARD and is neither filtered nor shown as incoming.
* Incoming is watch-only, and its blocked/passed verdict reflects firewalls
  in the INPUT hook at priorities up to `filter + 10` (that includes ufw, iptables and
  firewalld). Anything dropped earlier (e.g. in `raw`) isn't seen at all.
* Hostnames come from plain DNS seen on the wire. DoH/DoT done inside the app
  (e.g. Firefox DoH) shows bare IPs.
* Very short-lived processes may exit before /proc lookup → shown as `unknown(uid N)`.
* ICMP and other non-TCP/UDP protocols are not filtered.
