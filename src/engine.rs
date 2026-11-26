//! Decides what happens to each new outbound connection.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};

use crate::dns::DnsCache;
use crate::packet::{Flow, Proto};
use crate::procinfo::ProcInfo;
use crate::rules::{Rule, RuleStore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Alert,
    Allow,
    Block,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Alert, Mode::Allow, Mode::Block];

    pub fn label(self) -> &'static str {
        match self {
            Mode::Alert => "ALERT",
            Mode::Allow => "ALLOW",
            Mode::Block => "BLOCK",
        }
    }

    pub fn parse(s: &str) -> Result<Mode, String> {
        match s {
            "alert" => Ok(Mode::Alert),
            "allow" => Ok(Mode::Allow),
            "block" => Ok(Mode::Block),
            _ => Err(format!("unknown mode {s:?} (alert|allow|block)")),
        }
    }
}

/// What an "always" answer covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Scope {
    #[default]
    HostPort,
    Host,
    App,
}

impl Scope {
    pub fn next(self) -> Scope {
        match self {
            Scope::HostPort => Scope::Host,
            Scope::Host => Scope::App,
            Scope::App => Scope::HostPort,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Scope::HostPort => "this host + port",
            Scope::Host => "this host, any port",
            Scope::App => "any host (whole program)",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pending,
    Allowed,
    Denied,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pending => "pending",
            Verdict::Allowed => "allowed",
            Verdict::Denied => "denied",
        }
    }
}

/// One new outbound connection attempt.
#[derive(Clone, Debug)]
pub struct Conn {
    pub id: u64,
    pub time: DateTime<Local>,
    pub proto: Proto,
    pub dst: IpAddr,
    pub dport: u16,
    /// Hostname from the DNS cache.
    pub host: Option<String>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub exe: String,
    pub name: String,
    pub cmd: String,
    /// First time this program contacted this destination (this session).
    pub is_new: bool,
    pub verdict: Verdict,
    pub reason: String,
}

impl Conn {
    pub fn dest(&self) -> String {
        self.host.clone().unwrap_or_else(|| self.dst.to_string())
    }

    fn key(&self) -> String {
        format!("{}|{}|{}|{}", self.exe, self.proto, self.dest(), self.dport)
    }
}

/// A connection awaiting a user decision. Packets for the same
/// program/destination that arrive meanwhile are held on the same prompt.
#[derive(Clone, Debug)]
pub struct Prompt {
    pub id: u64,
    pub conn: Conn,
    pub deadline: Instant,
    /// Extra attempts held behind this prompt.
    pub extra: usize,
    /// (queue packet id, conn id)
    packets: Vec<(u32, u64)>,
}

/// One local port a remote source tried, aggregated.
#[derive(Clone, Debug)]
pub struct InPort {
    pub proto: Proto,
    pub port: u16,
    /// Program listening on it at the last attempt; None means nothing was.
    pub listener: Option<String>,
    pub attempts: u64,
    pub passed: u64,
    pub blocked: u64,
}

/// Everything one remote address tried inbound, aggregated.
#[derive(Clone, Debug)]
pub struct InSource {
    pub src: IpAddr,
    /// Hostname, if it appeared in a DNS answer we saw.
    pub host: Option<String>,
    /// Our address it connected to (last attempt).
    pub local: IpAddr,
    pub first: DateTime<Local>,
    pub last: DateTime<Local>,
    pub attempts: u64,
    pub passed: u64,
    pub blocked: u64,
    /// Most recently tried first, at most MAX_IN_PORTS.
    pub ports: Vec<InPort>,
    /// Distinct ports beyond what `ports` keeps.
    pub more_ports: usize,
}

/// Identifies one inbound attempt between "seen" and "passed".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct InKey {
    proto: Proto,
    src: IpAddr,
    sport: u16,
    dport: u16,
}

/// Delivers a verdict for a queued packet to the kernel. Called with the
/// engine lock held, so it must not call back into the engine.
pub type VerdictFn = Box<dyn Fn(u32, bool) + Send + Sync>;

/// A consistent copy of the state for rendering.
pub struct Snapshot {
    pub mode: Mode,
    /// Newest first.
    pub log: Vec<Conn>,
    pub pending: Vec<Prompt>,
    pub rules: Vec<Rule>,
    pub allowed: u64,
    pub denied: u64,
    /// Inbound sources, most recently active first.
    pub inbound: Vec<InSource>,
    pub in_attempts: u64,
    pub in_blocked: u64,
    pub err: Option<String>,
}

struct State {
    mode: Mode,
    rules: RuleStore,
    next_id: u64,
    log: VecDeque<Conn>,
    pending: Vec<Prompt>,
    seen: HashSet<String>,
    allowed: u64,
    denied: u64,
    inbound: HashMap<IpAddr, InSource>,
    /// Attempts seen before the host firewall, not yet seen after it.
    in_pending: HashMap<InKey, Instant>,
    in_attempts: u64,
    in_blocked: u64,
    err: Option<String>,
    /// Set by shutdown: no new prompts, nothing held.
    closed: bool,
}

const MAX_LOG: usize = 2000;
const MAX_IN_SOURCES: usize = 1000;
const MAX_IN_PORTS: usize = 50;
/// An inbound attempt not seen after the firewall within this long was dropped by it.
const IN_PASS_WAIT: Duration = Duration::from_secs(2);

pub struct Engine {
    st: Mutex<State>,
    dns: Arc<DnsCache>,
    verdict: VerdictFn,
    timeout: Duration,
    generation: AtomicU64,
}

impl Engine {
    pub fn new(
        mode: Mode,
        rules: RuleStore,
        dns: Arc<DnsCache>,
        verdict: VerdictFn,
        timeout: Duration,
    ) -> Self {
        Engine {
            st: Mutex::new(State {
                mode,
                rules,
                next_id: 0,
                log: VecDeque::new(),
                pending: Vec::new(),
                seen: HashSet::new(),
                allowed: 0,
                denied: 0,
                inbound: HashMap::new(),
                in_pending: HashMap::new(),
                in_attempts: 0,
                in_blocked: 0,
                err: None,
                closed: false,
            }),
            dns,
            verdict,
            timeout,
            generation: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic elsewhere must not stop us releasing packets.
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Increments whenever state visible to the UI changes.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn set_err(&self, e: impl std::fmt::Display) {
        self.lock().err = Some(e.to_string());
        self.changed();
    }

    /// Decides what to do with the first packet of a new flow.
    pub fn handle_outbound(&self, packet: u32, flow: Flow, proc: ProcInfo) {
        let host = self.dns.lookup(&flow.dst);
        let mut st = self.lock();
        st.next_id += 1;
        let mut c = Conn {
            id: st.next_id,
            time: Local::now(),
            proto: flow.proto,
            dst: flow.dst,
            dport: flow.dport,
            host,
            pid: proc.pid,
            uid: proc.uid,
            exe: proc.exe,
            name: proc.name,
            cmd: proc.cmd,
            is_new: false,
            verdict: Verdict::Pending,
            reason: String::new(),
        };
        let key = c.key();
        c.is_new = st.seen.insert(key.clone());

        let decision = match st.mode {
            Mode::Allow => Some((true, "allow mode")),
            Mode::Block => Some((false, "block mode")),
            Mode::Alert => match st.rules.find(&c) {
                Some(r) => Some((r.allow, "rule")),
                None if st.closed => Some((true, "shutdown")),
                None => None,
            },
        };
        match decision {
            Some((allow, reason)) => {
                self.verdict_packet(&mut st, packet, allow);
                set_verdict(&mut c, allow, reason);
            }
            None => {
                c.reason = "awaiting decision".into();
                let id = c.id;
                if let Some(pr) = st.pending.iter_mut().find(|p| p.conn.key() == key) {
                    pr.packets.push((packet, id));
                    pr.extra += 1;
                } else {
                    let deadline = Instant::now() + self.timeout;
                    st.pending.push(Prompt {
                        id,
                        conn: c.clone(),
                        deadline,
                        extra: 0,
                        packets: vec![(packet, id)],
                    });
                }
            }
        }
        st.log.push_back(c);
        while st.log.len() > MAX_LOG {
            st.log.pop_front();
        }
        drop(st);
        self.changed();
    }

    /// Records a new inbound attempt, seen before the host firewall judged it.
    /// `listener` is the program listening on the port, if any.
    pub fn inbound_seen(&self, flow: Flow, listener: Option<ProcInfo>) {
        let host = self.dns.lookup(&flow.src);
        let now = Local::now();
        let key = InKey {
            proto: flow.proto,
            src: flow.src,
            sport: flow.sport,
            dport: flow.dport,
        };
        let mut st = self.lock();
        // Same flow again before it got through: the earlier one was dropped
        // and this is a retransmission.
        if st.in_pending.insert(key, Instant::now()).is_some() {
            in_settle(&mut st, key, false);
        }
        st.in_attempts += 1;
        if !st.inbound.contains_key(&flow.src) && st.inbound.len() >= MAX_IN_SOURCES {
            let oldest = st.inbound.values().min_by_key(|s| s.last).map(|s| s.src);
            if let Some(o) = oldest {
                st.inbound.remove(&o);
            }
        }
        let s = st.inbound.entry(flow.src).or_insert_with(|| InSource {
            src: flow.src,
            host: None,
            local: flow.dst,
            first: now,
            last: now,
            attempts: 0,
            passed: 0,
            blocked: 0,
            ports: Vec::new(),
            more_ports: 0,
        });
        if host.is_some() {
            s.host = host;
        }
        s.local = flow.dst;
        s.last = now;
        s.attempts += 1;
        let listener = listener.map(|p| p.name);
        let mut p = match s
            .ports
            .iter()
            .position(|p| p.proto == flow.proto && p.port == flow.dport)
        {
            Some(i) => s.ports.remove(i),
            None => {
                if s.ports.len() >= MAX_IN_PORTS {
                    s.ports.pop();
                    s.more_ports += 1;
                }
                InPort {
                    proto: flow.proto,
                    port: flow.dport,
                    listener: None,
                    attempts: 0,
                    passed: 0,
                    blocked: 0,
                }
            }
        };
        p.listener = listener;
        p.attempts += 1;
        s.ports.insert(0, p);
        drop(st);
        self.changed();
    }

    /// The same attempt, seen after the host firewall: it was let through.
    pub fn inbound_passed(&self, flow: Flow) {
        let key = InKey {
            proto: flow.proto,
            src: flow.src,
            sport: flow.sport,
            dport: flow.dport,
        };
        let mut st = self.lock();
        if st.in_pending.remove(&key).is_some() {
            in_settle(&mut st, key, true);
            drop(st);
            self.changed();
        }
    }

    fn verdict_packet(&self, st: &mut State, packet: u32, allow: bool) {
        (self.verdict)(packet, allow);
        if allow {
            st.allowed += 1;
        } else {
            st.denied += 1;
        }
    }

    fn finish(&self, st: &mut State, pr: &Prompt, allow: bool, reason: &str) {
        for &(packet, cid) in &pr.packets {
            self.verdict_packet(st, packet, allow);
            // Log ids are increasing, so the entry (if not yet trimmed) is found by bisection.
            if let Ok(i) = st.log.binary_search_by_key(&cid, |c| c.id) {
                set_verdict(&mut st.log[i], allow, reason);
            }
        }
    }

    /// Answers a prompt. If `forever`, a rule with the given scope is saved and
    /// other pending prompts it now covers are resolved too.
    pub fn resolve(
        &self,
        prompt_id: u64,
        allow: bool,
        forever: bool,
        scope: Scope,
        reason: Option<&str>,
    ) {
        let mut st = self.lock();
        let Some(idx) = st.pending.iter().position(|p| p.id == prompt_id) else {
            return;
        };
        let pr = st.pending.remove(idx);
        let reason = reason.unwrap_or(if forever {
            "user (rule)"
        } else {
            "user (once)"
        });
        self.finish(&mut st, &pr, allow, reason);

        if forever {
            let c = &pr.conn;
            let mut r = Rule {
                exe: c.exe.clone(),
                host: c.dest(),
                port: c.dport,
                proto: c.proto.to_string(),
                allow,
                created: Local::now(),
            };
            match scope {
                Scope::HostPort => {}
                Scope::Host => (r.port, r.proto) = (0, String::new()),
                Scope::App => (r.host, r.port, r.proto) = ("*".into(), 0, String::new()),
            }
            if let Err(e) = st.rules.add(r) {
                st.err = Some(format!("saving rules: {e:#}"));
            }
            for other in std::mem::take(&mut st.pending) {
                match st.rules.find(&other.conn).map(|r| r.allow) {
                    Some(a) => self.finish(&mut st, &other, a, "rule"),
                    None => st.pending.push(other),
                }
            }
        }
        drop(st);
        self.changed();
    }

    /// Denies prompts whose deadline has passed, and counts inbound attempts
    /// the host firewall never let through as blocked.
    pub fn expire(&self, now: Instant) {
        let mut st = self.lock();
        let dropped: Vec<InKey> = st
            .in_pending
            .iter()
            .filter(|(_, t)| now.saturating_duration_since(**t) >= IN_PASS_WAIT)
            .map(|(k, _)| *k)
            .collect();
        for k in &dropped {
            st.in_pending.remove(k);
            in_settle(&mut st, *k, false);
        }
        drop(st);
        if !dropped.is_empty() {
            self.changed();
        }
        let due: Vec<u64> = self
            .lock()
            .pending
            .iter()
            .filter(|p| p.deadline <= now)
            .map(|p| p.id)
            .collect();
        for id in due {
            self.resolve(id, false, false, Scope::HostPort, Some("timeout"));
        }
    }

    /// Switches mode; pending prompts are settled by the new mode.
    pub fn set_mode(&self, m: Mode) {
        let mut st = self.lock();
        st.mode = m;
        if m != Mode::Alert {
            let reason = format!("{} mode", m.label().to_lowercase());
            for pr in std::mem::take(&mut st.pending) {
                self.finish(&mut st, &pr, m == Mode::Allow, &reason);
            }
        }
        drop(st);
        self.changed();
    }

    /// Releases held packets (accepting them unless in block mode). After
    /// this, nothing new is held.
    pub fn shutdown(&self) {
        let mut st = self.lock();
        st.closed = true;
        let allow = st.mode != Mode::Block;
        for pr in std::mem::take(&mut st.pending) {
            self.finish(&mut st, &pr, allow, "shutdown");
        }
        drop(st);
        self.changed();
    }

    pub fn snapshot(&self) -> Snapshot {
        let st = self.lock();
        Snapshot {
            mode: st.mode,
            log: st.log.iter().rev().cloned().collect(),
            pending: st
                .pending
                .iter()
                .map(|p| Prompt {
                    packets: Vec::new(),
                    ..p.clone()
                })
                .collect(),
            rules: st.rules.list().to_vec(),
            allowed: st.allowed,
            denied: st.denied,
            inbound: {
                let mut v: Vec<InSource> = st.inbound.values().cloned().collect();
                v.sort_unstable_by(|a, b| b.last.cmp(&a.last));
                v
            },
            in_attempts: st.in_attempts,
            in_blocked: st.in_blocked,
            err: st.err.clone(),
        }
    }

    pub fn delete_rule(&self, i: usize) {
        let mut st = self.lock();
        if let Err(e) = st.rules.delete(i) {
            st.err = Some(format!("saving rules: {e:#}"));
        }
        drop(st);
        self.changed();
    }

    pub fn toggle_rule(&self, i: usize) {
        let mut st = self.lock();
        if let Err(e) = st.rules.toggle(i) {
            st.err = Some(format!("saving rules: {e:#}"));
        }
        drop(st);
        self.changed();
    }
}

/// Counts a finished inbound attempt as passed or blocked.
fn in_settle(st: &mut State, k: InKey, passed: bool) {
    if !passed {
        st.in_blocked += 1;
    }
    let Some(s) = st.inbound.get_mut(&k.src) else {
        return; // source evicted meanwhile
    };
    let p = s
        .ports
        .iter_mut()
        .find(|p| p.proto == k.proto && p.port == k.dport);
    if passed {
        s.passed += 1;
        if let Some(p) = p {
            p.passed += 1;
        }
    } else {
        s.blocked += 1;
        if let Some(p) = p {
            p.blocked += 1;
        }
    }
}

fn set_verdict(c: &mut Conn, allow: bool, reason: &str) {
    c.verdict = if allow {
        Verdict::Allowed
    } else {
        Verdict::Denied
    };
    c.reason = reason.to_string();
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::thread::sleep;

    pub fn conn(exe: &str, host: Option<&str>, port: u16) -> Conn {
        Conn {
            id: 0,
            time: Local::now(),
            proto: Proto::Tcp,
            dst: "1.2.3.4".parse().unwrap(),
            dport: port,
            host: host.map(Into::into),
            pid: None,
            uid: None,
            exe: exe.into(),
            name: String::new(),
            cmd: String::new(),
            is_new: false,
            verdict: Verdict::Pending,
            reason: String::new(),
        }
    }

    type Verdicts = Arc<Mutex<HashMap<u32, bool>>>;

    fn engine(mode: Mode, timeout: Duration) -> (Engine, Verdicts) {
        let v: Verdicts = Default::default();
        let v2 = v.clone();
        let f: VerdictFn = Box::new(move |id, a| {
            v2.lock().unwrap().insert(id, a);
        });
        (
            Engine::new(
                mode,
                RuleStore::in_memory(),
                Arc::new(DnsCache::new()),
                f,
                timeout,
            ),
            v,
        )
    }

    fn get(v: &Verdicts, id: u32) -> Option<bool> {
        v.lock().unwrap().get(&id).copied()
    }

    fn curl() -> ProcInfo {
        ProcInfo::new(Some(42), Some(1000), "/usr/bin/curl", "curl")
    }

    fn flow(port: u16) -> Flow {
        Flow {
            proto: Proto::Tcp,
            src: "10.0.0.2".parse().unwrap(),
            dst: "1.2.3.4".parse().unwrap(),
            sport: 40000,
            dport: port,
        }
    }

    #[test]
    fn modes() {
        let (e, v) = engine(Mode::Allow, Duration::from_secs(60));
        e.handle_outbound(1, flow(443), curl());
        assert_eq!(get(&v, 1), Some(true), "allow mode should accept");
        e.set_mode(Mode::Block);
        e.handle_outbound(2, flow(443), curl());
        assert_eq!(get(&v, 2), Some(false), "block mode should drop");
        e.set_mode(Mode::Alert);
        e.handle_outbound(3, flow(443), curl());
        assert_eq!(get(&v, 3), None, "alert mode should hold the packet");
        e.handle_outbound(4, flow(443), curl()); // retry joins the same prompt
        let s = e.snapshot();
        assert_eq!(s.pending.len(), 1);
        assert_eq!(s.pending[0].extra, 1);
        e.set_mode(Mode::Allow); // switching mode settles pending
        assert_eq!(get(&v, 3), Some(true));
        assert_eq!(get(&v, 4), Some(true));
        let s = e.snapshot();
        assert!(
            s.log
                .iter()
                .all(|c| c.verdict == Verdict::Allowed || c.id == 2)
        );
    }

    #[test]
    fn alert_always_creates_rule() {
        let (e, v) = engine(Mode::Alert, Duration::from_secs(60));
        e.handle_outbound(1, flow(443), curl());
        e.handle_outbound(2, flow(80), curl()); // separate prompt (different port)
        let s = e.snapshot();
        assert_eq!(s.pending.len(), 2);
        e.resolve(s.pending[0].id, false, true, Scope::Host, None); // deny curl -> host, any port
        assert_eq!(get(&v, 1), Some(false));
        assert_eq!(
            get(&v, 2),
            Some(false),
            "2 should be denied by the new host rule"
        );
        e.handle_outbound(3, flow(8080), curl());
        assert_eq!(
            get(&v, 3),
            Some(false),
            "3 should be denied by rule without a prompt"
        );
        assert!(e.snapshot().pending.is_empty());
    }

    #[test]
    fn prompt_timeout_denies() {
        let (e, v) = engine(Mode::Alert, Duration::from_millis(50));
        e.handle_outbound(1, flow(443), curl());
        e.expire(Instant::now());
        assert_eq!(get(&v, 1), None, "not due yet");
        sleep(Duration::from_millis(80));
        e.expire(Instant::now());
        assert_eq!(get(&v, 1), Some(false), "timeout should deny");
        assert_eq!(e.snapshot().log[0].reason, "timeout");
    }

    #[test]
    fn shutdown_releases_and_stops_holding() {
        let (e, v) = engine(Mode::Alert, Duration::from_secs(60));
        e.handle_outbound(1, flow(443), curl());
        e.shutdown();
        assert_eq!(get(&v, 1), Some(true));
        e.handle_outbound(2, flow(443), curl());
        assert_eq!(get(&v, 2), Some(true), "nothing is held after shutdown");
    }

    fn inflow(src: &str, sport: u16, dport: u16) -> Flow {
        Flow {
            proto: Proto::Tcp,
            src: src.parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            sport,
            dport,
        }
    }

    #[test]
    fn inbound_passed_and_blocked() {
        let (e, _) = engine(Mode::Alert, Duration::from_secs(60));
        let sshd = ProcInfo::new(Some(1), Some(0), "/usr/sbin/sshd", "sshd");
        e.inbound_seen(inflow("192.0.2.7", 5000, 22), Some(sshd));
        e.inbound_passed(inflow("192.0.2.7", 5000, 22));
        e.inbound_seen(inflow("192.0.2.7", 5001, 445), None);
        e.inbound_seen(inflow("192.0.2.7", 5001, 445), None); // retransmit: first was dropped
        e.inbound_seen(inflow("198.51.100.1", 6000, 80), None);
        e.inbound_passed(inflow("203.0.113.9", 1, 1)); // never seen: ignored

        let s = e.snapshot();
        assert_eq!((s.in_attempts, s.in_blocked), (4, 1));
        assert_eq!(s.inbound.len(), 2);
        let a = s
            .inbound
            .iter()
            .find(|x| x.src.to_string() == "192.0.2.7")
            .unwrap();
        assert_eq!((a.attempts, a.passed, a.blocked), (3, 1, 1));
        assert_eq!(a.ports[0].port, 445, "most recent port first");
        assert_eq!(a.ports[1].listener.as_deref(), Some("sshd"));

        sleep(IN_PASS_WAIT + Duration::from_millis(50));
        e.expire(Instant::now());
        let s = e.snapshot();
        assert_eq!(s.in_blocked, 3, "unconfirmed attempts count as blocked");
        assert_eq!(
            s.inbound[0].src.to_string(),
            "198.51.100.1",
            "most recent source first"
        );
    }

    #[test]
    fn inbound_caps_ports() {
        let (e, _) = engine(Mode::Alert, Duration::from_secs(60));
        for p in 0..(MAX_IN_PORTS as u16 + 10) {
            e.inbound_seen(inflow("192.0.2.7", 1000 + p, p), None);
        }
        let s = &e.snapshot().inbound[0];
        assert_eq!((s.ports.len(), s.more_ports), (MAX_IN_PORTS, 10));
    }
}
