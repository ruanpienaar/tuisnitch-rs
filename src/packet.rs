//! Minimal IPv4/IPv6 + TCP/UDP header parsing for queued packets.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// The parts of a connection's first packet the engine judges on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub proto: Proto,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
}

#[derive(Debug)]
pub struct Packet<'a> {
    pub flow: Flow,
    /// L4 payload (used for DNS parsing).
    pub payload: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Short,
    Fragment,
    NotIp,
    Unsupported,
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

pub fn parse(b: &[u8]) -> Result<Packet<'_>, ParseError> {
    use ParseError::*;
    let first = *b.first().ok_or(Short)?;
    let (src, dst, proto, l4): (IpAddr, IpAddr, u8, &[u8]) = match first >> 4 {
        4 => {
            if b.len() < 20 {
                return Err(Short);
            }
            let ihl = (first & 0x0f) as usize * 4;
            if ihl < 20 || b.len() < ihl {
                return Err(Short);
            }
            if be16(b, 6) & 0x1fff != 0 {
                return Err(Fragment);
            }
            let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
            let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
            (src.into(), dst.into(), b[9], &b[ihl..])
        }
        6 => {
            if b.len() < 40 {
                return Err(Short);
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap());
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).unwrap());
            let mut proto = b[6];
            let mut off = 40;
            // Skip extension headers. `off` strictly grows, so this terminates.
            loop {
                match proto {
                    0 | 43 | 60 => {
                        // hop-by-hop, routing, destination options
                        if b.len() < off + 2 {
                            return Err(Short);
                        }
                        proto = b[off];
                        off += (b[off + 1] as usize + 1) * 8;
                    }
                    44 => {
                        if b.len() < off + 8 {
                            return Err(Short);
                        }
                        if be16(b, off + 2) & 0xfff8 != 0 {
                            return Err(Fragment);
                        }
                        proto = b[off];
                        off += 8;
                    }
                    _ => break,
                }
            }
            if b.len() < off {
                return Err(Short);
            }
            (src.into(), dst.into(), proto, &b[off..])
        }
        _ => return Err(NotIp),
    };

    let (p, payload): (Proto, &[u8]) = match proto {
        6 => {
            if l4.len() < 20 {
                return Err(Short);
            }
            let doff = (l4[12] >> 4) as usize * 4;
            let payload = if doff >= 20 && doff <= l4.len() {
                &l4[doff..]
            } else {
                &[]
            };
            (Proto::Tcp, payload)
        }
        17 => {
            if l4.len() < 8 {
                return Err(Short);
            }
            (Proto::Udp, &l4[8..])
        }
        _ => return Err(Unsupported),
    };
    Ok(Packet {
        flow: Flow {
            proto: p,
            src,
            dst,
            sport: be16(l4, 0),
            dport: be16(l4, 2),
        },
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut b = vec![0u8; 40];
        b[0] = 0x45;
        b[9] = 6;
        b[12..16].copy_from_slice(&[10, 0, 0, 2]);
        b[16..20].copy_from_slice(&dst);
        b[20..22].copy_from_slice(&sport.to_be_bytes());
        b[22..24].copy_from_slice(&dport.to_be_bytes());
        b[32] = 5 << 4;
        b
    }

    #[test]
    fn ipv4_tcp_parses() {
        let raw = ipv4_tcp([93, 184, 215, 14], 40000, 443);
        let p = parse(&raw).unwrap();
        assert_eq!(p.flow.proto, Proto::Tcp);
        assert_eq!((p.flow.sport, p.flow.dport), (40000, 443));
        assert_eq!(p.flow.dst.to_string(), "93.184.215.14");
        assert_eq!(p.flow.src.to_string(), "10.0.0.2");
    }

    #[test]
    fn ipv6_udp_with_ext_header() {
        let mut b = vec![0u8; 40 + 8 + 8 + 4];
        b[0] = 0x60;
        b[6] = 0; // hop-by-hop
        let dst: Ipv6Addr = "2606:4700::1111".parse().unwrap();
        b[24..40].copy_from_slice(&dst.octets());
        b[40] = 17; // next: udp
        b[41] = 0; // len (0+1)*8
        b[48..50].copy_from_slice(&54321u16.to_be_bytes());
        b[50..52].copy_from_slice(&53u16.to_be_bytes());
        let p = parse(&b).unwrap();
        assert_eq!(p.flow.proto, Proto::Udp);
        assert_eq!((p.flow.sport, p.flow.dport), (54321, 53));
        assert_eq!(p.flow.dst.to_string(), "2606:4700::1111");
        assert_eq!(p.payload.len(), 4);
    }

    #[test]
    fn rejects_garbage() {
        let cases: [&[u8]; 4] = [&[], &[0x45], &[0x99, 1, 2], &[0u8; 20]];
        for b in cases {
            assert!(parse(b).is_err(), "expected error for {b:?}");
        }
    }

    #[test]
    fn rejects_non_first_fragment() {
        let mut raw = ipv4_tcp([1, 2, 3, 4], 1, 2);
        raw[7] = 1; // fragment offset 8 bytes
        assert_eq!(parse(&raw).unwrap_err(), ParseError::Fragment);
    }
}
