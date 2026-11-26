//! Passive hostname learning: maps IPs to the name that was queried to get
//! them, from DNS responses seen on the wire.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

struct Entry {
    name: String,
    expires: Instant,
}

#[derive(Default)]
pub struct DnsCache {
    m: RwLock<HashMap<IpAddr, Entry>>,
}

const MAX_ENTRIES: usize = 50_000;

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let m = self.m.read().unwrap_or_else(|e| e.into_inner());
        m.get(ip).map(|e| e.name.clone())
    }

    pub fn add(&self, ip: IpAddr, name: String, ttl: Duration) {
        // Keep names for a while after TTL expiry: apps reuse connections and
        // addresses long after the record nominally expired.
        let ttl = ttl.max(Duration::from_secs(3600));
        let now = Instant::now();
        let mut m = self.m.write().unwrap_or_else(|e| e.into_inner());
        m.insert(
            ip,
            Entry {
                name,
                expires: now + ttl,
            },
        );
        if m.len() > MAX_ENTRIES {
            m.retain(|_, e| e.expires > now);
        }
    }

    /// Records the A/AAAA answers of a DNS response under its question name.
    /// Returns the number of addresses learned.
    pub fn ingest(&self, msg: &[u8]) -> usize {
        let Some((name, addrs)) = parse_response(msg) else {
            return 0;
        };
        for &(ip, ttl) in &addrs {
            self.add(ip, name.clone(), Duration::from_secs(ttl.into()));
        }
        addrs.len()
    }
}

/// Parses a DNS response into (first question name, [(address, ttl)]).
/// Names are lowercased (resolvers may randomise case) and restricted to
/// hostname characters so they are safe to show in a terminal.
pub fn parse_response(msg: &[u8]) -> Option<(String, Vec<(IpAddr, u32)>)> {
    let be16 =
        |i: usize| -> Option<u16> { Some(u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?])) };
    let flags = be16(2)?;
    if flags & 0x8000 == 0 {
        return None; // a query, not a response
    }
    let qd = be16(4)?;
    let an = be16(6)?;
    if qd == 0 {
        return None;
    }
    let (qname, mut pos) = read_name(msg, 12)?;
    pos += 4; // qtype, qclass
    for _ in 1..qd {
        pos = read_name(msg, pos)?.1 + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        pos = read_name(msg, pos)?.1;
        let ty = be16(pos)?;
        let class = be16(pos + 2)?;
        let ttl = u32::from_be_bytes(msg.get(pos + 4..pos + 8)?.try_into().ok()?);
        let rdlen = be16(pos + 8)? as usize;
        pos += 10;
        let rd = msg.get(pos..pos + rdlen)?;
        pos += rdlen;
        if class != 1 {
            continue;
        }
        match ty {
            1 => out.push((IpAddr::from(<[u8; 4]>::try_from(rd).ok()?), ttl)),
            28 => out.push((IpAddr::from(<[u8; 16]>::try_from(rd).ok()?), ttl)),
            _ => {}
        }
    }
    if qname.is_empty() {
        return None;
    }
    Some((qname, out))
}

/// Reads a (possibly compressed) name at `pos`; returns it and the offset
/// just past it in the original message.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        match len & 0xc0 {
            0x00 if len == 0 => {
                pos += 1;
                break;
            }
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + len)?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|&b| clean_byte(b)));
                if name.len() > 255 {
                    return None;
                }
                pos += 1 + len;
            }
            0xc0 => {
                let lo = *msg.get(pos + 1)? as usize;
                end.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > 32 {
                    return None; // pointer loop
                }
                pos = (len & 0x3f) << 8 | lo;
            }
            _ => return None,
        }
    }
    Some((name, end.unwrap_or(pos)))
}

fn clean_byte(b: u8) -> char {
    match b {
        b'A'..=b'Z' => b.to_ascii_lowercase() as char,
        b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'*' => b as char,
        _ => '?',
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a response for `name` with A records, answers using a
    /// compression pointer back to the question.
    pub fn response(name: &str, ips: &[[u8; 4]], ttl: u32) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, ips.len() as u8, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        for ip in ips {
            m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&[0, 4]);
            m.extend_from_slice(ip);
        }
        m
    }

    #[test]
    fn ingest_learns_a_records() {
        let c = DnsCache::new();
        assert_eq!(
            c.ingest(&response("example.com", &[[93, 184, 215, 14]], 60)),
            1
        );
        assert_eq!(
            c.lookup(&"93.184.215.14".parse().unwrap()).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn names_are_lowercased_and_sanitised() {
        let c = DnsCache::new();
        c.ingest(&response("ExAmPle.COM", &[[1, 1, 1, 1]], 60));
        assert_eq!(
            c.lookup(&"1.1.1.1".parse().unwrap()).as_deref(),
            Some("example.com")
        );
        c.ingest(&response("evil\x1b[2J.com", &[[2, 2, 2, 2]], 60));
        assert_eq!(
            c.lookup(&"2.2.2.2".parse().unwrap()).as_deref(),
            Some("evil??2j.com")
        );
    }

    #[test]
    fn rejects_queries_truncation_and_loops() {
        let mut q = response("example.com", &[[1, 2, 3, 4]], 60);
        q[2] &= 0x7f; // clear QR
        assert!(parse_response(&q).is_none());
        let full = response("example.com", &[[1, 2, 3, 4]], 60);
        assert!(parse_response(&full[..full.len() - 1]).is_none());
        let looped = [0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12];
        assert!(parse_response(&looped).is_none());
    }
}
