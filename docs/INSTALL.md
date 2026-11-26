# Installing tuisnitch

This guide covers building from source, running it from the repo with
`cargo run` (TUI or web mode), and installing it as a systemd service that
serves the web UI on `http://127.0.0.1:8484`.

## 1. Requirements

| what | why | check |
|------|-----|-------|
| Linux with nftables + NFQUEUE support | packets are diverted with an nft `queue` rule | `sudo modprobe -a nf_tables nfnetlink_queue nft_queue && echo ok` |
| `nft` command | tuisnitch installs its table with `nft -f -` | `command -v nft` |
| Rust 1.85 or newer | the crate uses edition 2024 | `rustc --version` |
| a C linker (`cc`) | Rust links through it | `command -v cc` |
| systemd | only for running as a service | `systemctl --version` |

Debian / Ubuntu:

```sh
sudo apt install nftables build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # if you don't have Rust
```

Fedora: `sudo dnf install nftables gcc`. Arch: `sudo pacman -S nftables base-devel`.

tuisnitch adds its own table (`inet tuisnitch`) next to whatever firewall you
already have (ufw, firewalld, your own nft rules); it doesn't replace them.

## 2. Build

```sh
git clone <repo-url> tuisnitch-rs
cd tuisnitch-rs
cargo test
cargo build --release          # -> target/release/tuisnitch (single file, web page built in)
```

## 3. Try it without root (demo)

Demo mode feeds the engine fake connections. It touches no firewall rules and
needs no root, so it's the safe way to look at either UI:

```sh
cargo run -- -demo                 # TUI
cargo run -- -demo -ui web         # web UI
```

In web demo mode the token is new each run and printed as a ready-to-open URL:

```
tuisnitch: web UI on http://127.0.0.1:8484/?token=3f9c…
```

Open that link. Stop with `Ctrl+C`.

## 4. Run it for real with `cargo run`

Real mode needs root (NFQUEUE, nftables, reading every process's `/proc`).
Don't use `sudo cargo run`: root usually has no Rust toolchain, and if it does
it leaves root-owned files in `target/`. Build as yourself and run only the
binary as root. The repo has a cargo alias for that (`.cargo/config.toml`):

```sh
cargo run-root -- -ui web                  # web mode, alert mode (asks about everything new)
cargo run-root -- -ui web -mode allow      # web mode, allow + log everything (good first run)
cargo run-root --release -- -ui web        # optimised build
cargo run-root                             # TUI mode
```

`cargo run-root` is `cargo run` with `sudo` as the runner. It's the same as:

```sh
cargo build && sudo ./target/debug/tuisnitch -ui web
```

Then, in web mode:

1. It prints `tuisnitch: web UI on http://127.0.0.1:8484/  (access token is in /etc/tuisnitch/web-token)`.
2. Get the token: `sudo cat /etc/tuisnitch/web-token`. It's created on the
   first run and stays the same afterwards, so the service you install later
   uses the same one.
3. Open http://127.0.0.1:8484, paste the token, then click
   **Enable notifications**. The browser remembers the token in a cookie.
4. Stop with `Ctrl+C`. tuisnitch removes its nft table and releases any held
   connections on the way out.

If you'd rather get a clickable link and not touch `/etc`, use a throwaway token:

```sh
cargo run-root -- -ui web -token-file ""
```

Other useful flags: `-listen 127.0.0.1:9000` (different port),
`-rules ./rules.json` (separate rules file while experimenting),
`-timeout 2m` (longer before an unanswered prompt is denied). Run with `-h`
for the full list.

Only one instance can run at a time. If the service from step 5 is running,
stop it first: `sudo systemctl stop tuisnitch`.

## 5. Install as a service (web mode)

```sh
cargo build --release
sudo install -m 755 target/release/tuisnitch /usr/local/bin/tuisnitch
sudo install -m 644 packaging/tuisnitch.service /etc/systemd/system/tuisnitch.service
sudo systemctl daemon-reload
sudo systemctl enable --now tuisnitch
```

Check it:

```sh
systemctl status tuisnitch                 # should be "active (running)"
journalctl -u tuisnitch -b                 # shows "web UI on http://127.0.0.1:8484/ ..."
sudo nft list table inet tuisnitch         # the queue rules are in place
sudo cat /etc/tuisnitch/web-token          # token for the UI
```

Open http://127.0.0.1:8484, paste the token, click **Enable notifications**,
and keep the tab open (a pinned tab works well). New connections now pop up
as desktop notifications with a sound, and the waiting count shows in the
tab title.

**Before you leave it in alert mode:** a connection with no matching rule is
held for 60 seconds and then denied if nobody answers. That includes the time
before you've logged in and opened the page. A gentle start:

1. Run in allow mode for a day (see step 6), with the page open.
2. Use **Alerts → Notify on first-seen destinations** and the ★ "only new"
   filter to see what talks to the network, and add rules for what's expected.
3. Switch to alert mode from the page (or `-mode alert` in the unit).

Files the service uses:

| path | what |
|------|------|
| `/usr/local/bin/tuisnitch` | the binary |
| `/etc/systemd/system/tuisnitch.service` | the unit |
| `/etc/tuisnitch/rules.json` | your rules (created when you add the first one) |
| `/etc/tuisnitch/web-token` | web UI access token (root-only, mode 0600) |

## 6. Change settings

Don't edit the installed unit; add an override, which survives reinstalls:

```sh
sudo systemctl edit tuisnitch
```

and put in:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/tuisnitch -ui web -listen 127.0.0.1:8484 -mode allow -timeout 60s
```

(The empty `ExecStart=` clears the original line.) Then
`sudo systemctl restart tuisnitch`.

To get a new token (logs out every browser):
`sudo rm /etc/tuisnitch/web-token && sudo systemctl restart tuisnitch`.

## 7. Upgrade

```sh
git pull
cargo build --release
sudo install -m 755 target/release/tuisnitch /usr/local/bin/tuisnitch
sudo install -m 644 packaging/tuisnitch.service /etc/systemd/system/tuisnitch.service
sudo systemctl daemon-reload
sudo systemctl restart tuisnitch
```

Rules and the token are kept.

## 8. Uninstall

```sh
sudo systemctl disable --now tuisnitch
sudo rm /etc/systemd/system/tuisnitch.service /usr/local/bin/tuisnitch
sudo rm -r /etc/systemd/system/tuisnitch.service.d   # only if you used systemctl edit
sudo systemctl daemon-reload
sudo rm -r /etc/tuisnitch                            # only if you don't want your rules
```

## 9. Troubleshooting

| symptom | fix |
|---------|-----|
| `must run as root` | use `cargo run-root` / `sudo`, or `-demo` |
| `binding nfqueue 4242 (is another tuisnitch running?)` | another instance (often the service) is running: `sudo systemctl stop tuisnitch` |
| `listening on 127.0.0.1:8484 (is another instance running?)` | port in use: stop the other instance or pass `-listen 127.0.0.1:<port>` |
| `running nft: No such file or directory` | install the `nftables` package |
| page says "Access token needed" again | the cookie was cleared or the token changed: `sudo cat /etc/tuisnitch/web-token` |
| no desktop notifications | allow notifications for `127.0.0.1` in the browser's site settings, check the OS do-not-disturb setting, then **Alerts → Test** |
| no sound | the browser only plays sound after you click or press a key on the page once |
| network acting strangely after a crash or `kill -9` | `sudo nft delete table inet tuisnitch`, then start it again |
| everything new gets denied at boot | expected in alert mode with nobody answering: add rules, or use `-mode allow` |
