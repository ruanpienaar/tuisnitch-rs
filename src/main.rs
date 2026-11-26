//! tuisnitch: a terminal application firewall for Linux.

mod dns;
mod engine;
mod firewall;
mod packet;
mod procinfo;
mod queue;
mod rules;
mod ui;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use dns::DnsCache;
use engine::{Engine, Mode};
use firewall::FwConfig;
use packet::{Flow, Proto};
use procinfo::ProcInfo;
use rules::RuleStore;

const USAGE: &str = "\
usage: tuisnitch [flags]

  -mode alert|allow|block  start mode (default alert)
  -rules PATH              rules file, \"\" for none (default /etc/tuisnitch/rules.json)
  -queue N                 NFQUEUE number for outbound connections; DNS uses N+1 and
                           inbound watching N+2, N+3 (default 4242)
  -timeout DUR             auto-deny a prompt after this long, e.g. 30s, 2m (default 60s)
  -loopback                also intercept connections to loopback (lo)
  -fail-closed             drop new connections if tuisnitch dies (default: let them through)
  -no-dns                  do not learn hostnames from DNS responses
  -no-inbound              do not show incoming connection attempts
  -demo                    run the UI with fake connections; no root, no firewall changes
  -ui tui|web              front end (default tui). web serves a browser UI instead of the TUI
  -listen ADDR             web UI address (default 127.0.0.1:8484)
  -token-file PATH         web UI access token, created if missing; \"\" for a new one each run
                           (default /etc/tuisnitch/web-token; with -demo, a new one each run)
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ui {
    Tui,
    Web,
}

#[derive(Debug, PartialEq)]
struct Opts {
    ui: Ui,
    listen: SocketAddr,
    /// None: a fresh token each run. Default depends on -demo, so it's resolved after parsing.
    token_file: Option<Option<PathBuf>>,
    mode: Mode,
    rules: Option<PathBuf>,
    queue: u16,
    timeout: Duration,
    loopback: bool,
    fail_closed: bool,
    no_dns: bool,
    no_inbound: bool,
    demo: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            ui: Ui::Tui,
            listen: SocketAddr::from(([127, 0, 0, 1], 8484)),
            token_file: None,
            mode: Mode::Alert,
            rules: Some("/etc/tuisnitch/rules.json".into()),
            queue: 4242,
            timeout: Duration::from_secs(60),
            loopback: false,
            fail_closed: false,
            no_dns: false,
            no_inbound: false,
            demo: false,
        }
    }
}

/// Go-`flag` style: `-name value`, `-name=value`, `--name`; bools take no value.
/// Err("") means help was requested.
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let Some(flag) = a
            .strip_prefix("--")
            .or_else(|| a.strip_prefix('-'))
            .filter(|f| !f.is_empty())
        else {
            return Err(format!("unexpected argument {a:?}"));
        };
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (flag, None),
        };
        match name {
            "h" | "help" => return Err(String::new()),
            "loopback" | "fail-closed" | "no-dns" | "no-inbound" | "demo" => {
                let v = match inline.as_deref() {
                    None | Some("true" | "1") => true,
                    Some("false" | "0") => false,
                    Some(x) => return Err(format!("invalid boolean {x:?} for -{name}")),
                };
                match name {
                    "loopback" => o.loopback = v,
                    "fail-closed" => o.fail_closed = v,
                    "no-dns" => o.no_dns = v,
                    "no-inbound" => o.no_inbound = v,
                    _ => o.demo = v,
                }
            }
            "mode" | "rules" | "queue" | "timeout" | "ui" | "listen" | "token-file" => {
                let v = match inline {
                    Some(v) => v,
                    None => it
                        .next()
                        .ok_or_else(|| format!("flag needs an argument: -{name}"))?,
                };
                match name {
                    "mode" => o.mode = Mode::parse(&v)?,
                    "rules" => o.rules = (!v.is_empty()).then(|| v.into()),
                    "ui" => {
                        o.ui = match v.as_str() {
                            "tui" => Ui::Tui,
                            "web" => Ui::Web,
                            _ => return Err(format!("unknown ui {v:?} (tui|web)")),
                        }
                    }
                    "listen" => {
                        o.listen = v
                            .parse()
                            .map_err(|_| format!("invalid -listen {v:?} (e.g. 127.0.0.1:8484)"))?
                    }
                    "token-file" => o.token_file = Some((!v.is_empty()).then(|| v.into())),
                    "queue" => {
                        o.queue = v
                            .parse()
                            .map_err(|_| format!("invalid queue number {v:?}"))?
                    }
                    _ => o.timeout = parse_duration(&v)?,
                }
            }
            _ => return Err(format!("flag provided but not defined: -{name}")),
        }
    }
    if !o.no_inbound && o.queue > u16::MAX - 3 {
        return Err(
            "-queue must be below 65533 (inbound watching uses queue+2 and +3), or pass -no-inbound"
                .into(),
        );
    }
    if !o.no_dns && o.queue == u16::MAX {
        return Err("-queue must be below 65535 (DNS uses queue+1), or pass -no-dns".into());
    }
    Ok(o)
}

impl Opts {
    fn token_path(&self) -> Option<PathBuf> {
        match &self.token_file {
            Some(p) => p.clone(),
            None if self.demo => None,
            None => Some("/etc/tuisnitch/web-token".into()),
        }
    }
}

/// The chosen front end, prepared before any firewall changes so that
/// mistakes (busy port, unreadable token) fail without side effects.
enum Front {
    Tui,
    Web {
        listener: std::net::TcpListener,
        token: String,
    },
}

impl Front {
    fn prepare(opts: &Opts) -> Result<Front> {
        Ok(match opts.ui {
            Ui::Tui => Front::Tui,
            Ui::Web => {
                let path = opts.token_path();
                let token = web::load_token(path.as_deref()).context("web token")?;
                let listener = web::bind(opts.listen)?;
                let ip = opts.listen.ip();
                let host = if ip.is_unspecified() || ip.is_loopback() {
                    format!("127.0.0.1:{}", opts.listen.port())
                } else {
                    opts.listen.to_string()
                };
                match &path {
                    Some(p) => eprintln!(
                        "tuisnitch: web UI on http://{host}/  (access token is in {})",
                        p.display()
                    ),
                    None => eprintln!("tuisnitch: web UI on http://{host}/?token={token}"),
                }
                if !ip.is_loopback() {
                    eprintln!(
                        "tuisnitch: warning: {} is reachable from other machines and the UI is plain HTTP",
                        opts.listen
                    );
                }
                Front::Web { listener, token }
            }
        })
    }

    /// Runs until the user quits or a signal arrives.
    fn run(self, eng: Arc<Engine>, demo: bool, quit: Arc<AtomicBool>) -> Result<()> {
        match self {
            Front::Tui => {
                let mut term = ratatui::init(); // also restores the terminal on panic
                let res = ui::run(&mut term, eng, demo, &quit);
                ratatui::restore();
                Ok(res?)
            }
            Front::Web { listener, token } => web::serve(listener, eng, token, demo, quit),
        }
    }
}

/// Parses Go-style durations ("90s", "1m30s", "500ms", "1.5h"); a bare number is seconds.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let err = || format!("invalid duration {s:?} (e.g. 60s, 2m, 1m30s)");
    if s.is_empty() {
        return Err(err());
    }
    let secs = if let Ok(n) = s.parse::<f64>() {
        n
    } else {
        let (mut total, mut rest) = (0.0, s);
        while !rest.is_empty() {
            let i = rest
                .find(|c: char| !(c.is_ascii_digit() || c == '.'))
                .ok_or_else(err)?;
            let n: f64 = rest[..i].parse().map_err(|_| err())?;
            rest = &rest[i..];
            let j = rest
                .find(|c: char| c.is_ascii_digit() || c == '.')
                .unwrap_or(rest.len());
            total += n * match &rest[..j] {
                "ms" => 0.001,
                "s" => 1.0,
                "m" => 60.0,
                "h" => 3600.0,
                _ => return Err(err()),
            };
            rest = &rest[j..];
        }
        total
    };
    Duration::try_from_secs_f64(secs).map_err(|_| err())
}

fn main() {
    let opts = match parse_args(std::env::args().skip(1)) {
        Ok(o) => o,
        Err(e) if e.is_empty() => {
            print!("{USAGE}");
            return;
        }
        Err(e) => {
            eprintln!("tuisnitch: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    let res = if opts.demo {
        run_demo(&opts)
    } else {
        run(&opts)
    };
    // Everything with cleanup in Drop has been dropped by now.
    if let Err(e) = res {
        eprintln!("tuisnitch: {e:#}");
        std::process::exit(1);
    }
}

fn quit_on_signals() -> Result<Arc<AtomicBool>> {
    let quit = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGINT,
    ] {
        signal_hook::flag::register(sig, quit.clone())?;
    }
    Ok(quit)
}

/// Undoes everything on the way out, including on error or panic: releases
/// held packets, removes the nft table, then stops the queue thread.
struct Cleanup {
    eng: Arc<Engine>,
    stop: Arc<AtomicBool>,
    queue_thread: Option<JoinHandle<()>>,
    fw_installed: bool,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.eng.shutdown();
        if self.fw_installed
            && let Err(e) = firewall::remove()
        {
            eprintln!(
                "tuisnitch: failed to remove nft table ({e:#}); run: sudo nft delete table inet {}",
                firewall::TABLE
            );
        }
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.queue_thread.take() {
            let _ = t.join();
        }
    }
}

fn run(opts: &Opts) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        let me = std::env::args()
            .next()
            .unwrap_or_else(|| "tuisnitch".into());
        bail!("must run as root (NFQUEUE + nftables). Try: sudo {me}");
    }
    let rules = RuleStore::load(opts.rules.clone()).context("loading rules")?;
    let front = Front::prepare(opts)?;
    let dns = Arc::new(DnsCache::new());
    let extra = queue::Extra {
        dns: (!opts.no_dns).then_some(opts.queue + 1),
        inbound: (!opts.no_inbound).then_some((opts.queue + 2, opts.queue + 3)),
    };
    let q = queue::open(opts.queue, extra)?;

    let (tx, rx) = mpsc::channel();
    let verdict = Box::new(move |id, accept| {
        let _ = tx.send((id, accept));
    });
    let eng = Arc::new(Engine::new(
        opts.mode,
        rules,
        dns.clone(),
        verdict,
        opts.timeout,
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let queue_thread = queue::spawn(q, extra, eng.clone(), dns, rx, stop.clone())?;
    let mut cleanup = Cleanup {
        eng: eng.clone(),
        stop,
        queue_thread: Some(queue_thread),
        fw_installed: false,
    };

    // Queues are listening; now divert traffic to them.
    let fw = FwConfig {
        out_queue: opts.queue,
        dns_queue: extra.dns,
        loopback: opts.loopback,
        fail_closed: opts.fail_closed,
        inbound: extra.inbound,
    };
    firewall::install(&fw)?;
    cleanup.fw_installed = true;

    let quit = quit_on_signals()?;
    let res = front.run(eng, false, quit);
    drop(cleanup);
    res
}

// ---- demo mode -------------------------------------------------------------

fn run_demo(opts: &Opts) -> Result<()> {
    let front = Front::prepare(opts)?;
    let dns = Arc::new(DnsCache::new());
    let eng = Arc::new(Engine::new(
        opts.mode,
        RuleStore::in_memory(),
        dns.clone(),
        Box::new(|_, _| {}),
        opts.timeout,
    ));

    let fakes: &[(&str, &str, &str, u16, Proto)] = &[
        (
            "/usr/bin/curl",
            "example.com",
            "93.184.215.14",
            443,
            Proto::Tcp,
        ),
        (
            "/usr/lib/firefox/firefox",
            "www.mozilla.org",
            "2600:9000:2156::7",
            443,
            Proto::Tcp,
        ),
        (
            "/usr/lib/firefox/firefox",
            "detectportal.firefox.com",
            "34.107.221.82",
            80,
            Proto::Tcp,
        ),
        (
            "/usr/lib/systemd/systemd-resolved",
            "",
            "1.1.1.1",
            53,
            Proto::Udp,
        ),
        ("/usr/bin/ssh", "github.com", "140.82.121.3", 22, Proto::Tcp),
        (
            "/usr/sbin/chronyd",
            "ntp.ubuntu.com",
            "185.125.190.56",
            123,
            Proto::Udp,
        ),
        (
            "/snap/spotify/x1/spotify",
            "apresolve.spotify.com",
            "35.186.224.24",
            443,
            Proto::Tcp,
        ),
    ];
    // (remote, local port, listener, let through by the host firewall)
    let inbound_fakes: &[(&str, u16, Option<&str>, bool)] = &[
        ("192.168.1.23", 22, Some("/usr/sbin/sshd"), true),
        ("192.168.1.40", 8484, None, false),
        ("45.33.32.156", 0, None, false), // port scan
        ("198.51.100.20", 3389, None, false),
        ("2001:db8::5", 443, Some("/usr/sbin/nginx"), true),
    ];
    if !opts.no_inbound {
        dns.add(
            "192.168.1.23".parse()?,
            "laptop.lan".into(),
            Duration::from_secs(3600),
        );
    }
    for &(_, host, ip, ..) in fakes {
        if !host.is_empty() {
            dns.add(ip.parse()?, host.into(), Duration::from_secs(3600));
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let generator = {
        let (eng, stop) = (eng.clone(), stop.clone());
        let no_inbound = opts.no_inbound;
        thread::spawn(move || {
            let mut rng = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(1, |d| d.as_nanos() as u64)
                | 1;
            let mut next = |n: u64| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng % n
            };
            let mut id = 0;
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(400 + next(1600)));
                if !no_inbound && next(3) == 0 {
                    let (src, port, listener, pass) =
                        inbound_fakes[next(inbound_fakes.len() as u64) as usize];
                    let flow = Flow {
                        proto: Proto::Tcp,
                        src: src.parse().unwrap(),
                        dst: if src.contains(':') {
                            "2001:db8::2".parse().unwrap()
                        } else {
                            "192.168.1.10".parse().unwrap()
                        },
                        sport: 30000 + next(30000) as u16,
                        dport: if port == 0 {
                            1 + next(1024) as u16
                        } else {
                            port
                        },
                    };
                    eng.inbound_seen(
                        flow,
                        listener.map(|l| ProcInfo::new(Some(800), Some(0), l, l)),
                    );
                    if pass {
                        eng.inbound_passed(flow);
                    }
                    continue;
                }
                let (exe, _, ip, port, proto) = fakes[next(fakes.len() as u64) as usize];
                id += 1;
                let flow = Flow {
                    proto,
                    src: "192.168.1.10".parse().unwrap(),
                    dst: ip.parse().unwrap(),
                    sport: 30000 + next(30000) as u16,
                    dport: port,
                };
                eng.handle_outbound(
                    id,
                    flow,
                    ProcInfo::new(Some(1000 + next(9000) as u32), Some(1000), exe, exe),
                );
            }
        })
    };

    let quit = quit_on_signals()?;
    let res = front.run(eng, true, quit);
    stop.store(true, Ordering::Relaxed);
    let _ = generator.join();
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Result<Opts, String> {
        parse_args(s.split_whitespace().map(String::from))
    }

    #[test]
    fn flags_go_style() {
        assert_eq!(args("").unwrap(), Opts::default());
        let o = args(
            "-mode allow --timeout=1m30s -rules /tmp/r.json -fail-closed -no-dns=false -queue 7",
        )
        .unwrap();
        assert_eq!(o.mode, Mode::Allow);
        assert_eq!(o.timeout, Duration::from_secs(90));
        assert_eq!(o.rules, Some("/tmp/r.json".into()));
        assert!(o.fail_closed && !o.no_dns);
        assert_eq!(o.queue, 7);
        assert_eq!(args("-rules=").unwrap().rules, None);
        assert_eq!(args("-h").unwrap_err(), "");
        assert!(args("-mode").is_err());
        assert!(args("-bogus").is_err());
        assert!(args("-queue 65535").is_err());
        assert!(args("-queue 65535 -no-dns -no-inbound").is_ok());
        assert!(args("-queue 65533").is_err());
        assert!(args("-queue 65532").is_ok());
        assert!(args("-queue 65533 -no-inbound").is_ok());
    }

    #[test]
    fn web_flags() {
        let o = args("-ui web -listen 127.0.0.1:9000").unwrap();
        assert_eq!(o.ui, Ui::Web);
        assert_eq!(o.listen.port(), 9000);
        assert_eq!(o.token_path(), Some("/etc/tuisnitch/web-token".into()));
        assert_eq!(args("-demo").unwrap().token_path(), None);
        assert_eq!(args("-token-file=").unwrap().token_path(), None);
        assert_eq!(
            args("-demo -token-file /tmp/t").unwrap().token_path(),
            Some("/tmp/t".into())
        );
        assert!(args("-ui gui").is_err());
        assert!(args("-listen nope").is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("60s"), Ok(Duration::from_secs(60)));
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("1h2m3s"), Ok(Duration::from_secs(3723)));
        assert_eq!(parse_duration("1.5m"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("45"), Ok(Duration::from_secs(45)));
        for bad in ["", "s", "10x", "inf", "NaN", "-5s", "1e999"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
