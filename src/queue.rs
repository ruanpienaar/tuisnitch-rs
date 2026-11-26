//! The NFQUEUE side: one netlink socket bound to the outbound queue (and the
//! DNS queue), serviced by one thread that owns every held packet.
//!
//! The engine decides; its verdicts arrive here over a channel, so prompts
//! answered from the UI or by timeout never touch the socket directly.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use nfq::{Message, Queue};

use crate::dns::DnsCache;
use crate::engine::Engine;
use crate::packet;
use crate::procinfo::ProcLookup;

/// How long recv blocks before checking for verdicts and the stop flag.
const POLL: Duration = Duration::from_millis(20);

/// Queue numbers besides the outbound one.
#[derive(Clone, Copy)]
pub struct Extra {
    pub dns: Option<u16>,
    /// Inbound attempts: (before the host firewall, after it).
    pub inbound: Option<(u16, u16)>,
}

pub fn open(out_q: u16, extra: Extra) -> Result<Queue> {
    let mut q = Queue::open().context("opening netfilter netlink socket")?;
    let inbound = extra.inbound.into_iter().flat_map(|(a, b)| [a, b]);
    for n in std::iter::once(out_q).chain(extra.dns).chain(inbound) {
        q.bind(n)
            .with_context(|| format!("binding nfqueue {n} (is another tuisnitch running?)"))?;
        q.set_queue_max_len(n, 4096)?;
    }
    q.set_recv_uid_gid(out_q, true)?;
    set_recv_timeout(&q, POLL)?;
    Ok(q)
}

fn set_recv_timeout(q: &Queue, d: Duration) -> Result<()> {
    let tv = libc::timeval {
        tv_sec: d.as_secs() as _,
        tv_usec: d.subsec_micros() as _,
    };
    // SAFETY: valid fd owned by `q`, and a correctly sized timeval.
    let rc = unsafe {
        libc::setsockopt(
            q.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("setting SO_RCVTIMEO");
    }
    Ok(())
}

pub fn spawn(
    mut q: Queue,
    extra: Extra,
    eng: Arc<Engine>,
    dns: Arc<DnsCache>,
    verdicts: Receiver<(u32, bool)>,
    stop: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    let body = move || {
        let mut held: HashMap<u32, Message> = HashMap::new();
        let mut procs = ProcLookup::default();
        loop {
            apply_verdicts(&mut q, &mut held, &verdicts, &eng);
            if stop.load(Ordering::Acquire) {
                break;
            }
            let msg = match q.recv() {
                Ok(m) => m,
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => {
                    eng.set_err(format!("nfqueue: {e}"));
                    thread::sleep(POLL); // don't spin on a persistent error
                    continue;
                }
            };

            let qn = msg.get_queue_num();
            if let Some((seen_q, passed_q)) = extra.inbound
                && (qn == seen_q || qn == passed_q)
            {
                // Watch only: always accept, and do so before the /proc lookup.
                let flow = packet::parse(msg.get_payload()).ok().map(|p| p.flow);
                send(&mut q, msg, true, &eng);
                match flow {
                    Some(f) if qn == seen_q => {
                        let listener = procs.listener(f.proto, f.dport);
                        eng.inbound_seen(f, listener);
                    }
                    Some(f) => eng.inbound_passed(f),
                    None => {}
                }
                continue;
            }

            if Some(qn) == extra.dns {
                if let Ok(p) = packet::parse(msg.get_payload())
                    && p.flow.sport == 53
                {
                    dns.ingest(p.payload);
                }
                send(&mut q, msg, true, &eng);
                continue;
            }

            let Ok(flow) = packet::parse(msg.get_payload()).map(|p| p.flow) else {
                send(&mut q, msg, true, &eng); // not something we judge
                continue;
            };
            let proc = procs.lookup(flow.proto, flow.sport, msg.get_uid());
            let id = msg.get_packet_id();
            held.insert(id, msg);
            eng.handle_outbound(id, flow, proc);
        }
        // After engine shutdown everything has a verdict; release stragglers anyway.
        apply_verdicts(&mut q, &mut held, &verdicts, &eng);
        for (_, msg) in held.drain() {
            send(&mut q, msg, true, &eng);
        }
    };
    Ok(thread::Builder::new().name("nfqueue".into()).spawn(body)?)
}

fn apply_verdicts(
    q: &mut Queue,
    held: &mut HashMap<u32, Message>,
    rx: &Receiver<(u32, bool)>,
    eng: &Engine,
) {
    while let Ok((id, accept)) = rx.try_recv() {
        if let Some(msg) = held.remove(&id) {
            send(q, msg, accept, eng);
        }
    }
}

fn send(q: &mut Queue, mut msg: Message, accept: bool, eng: &Engine) {
    msg.set_verdict(if accept {
        nfq::Verdict::Accept
    } else {
        nfq::Verdict::Drop
    });
    if let Err(e) = q.verdict(msg) {
        eng.set_err(format!("verdict: {e}"));
    }
}
