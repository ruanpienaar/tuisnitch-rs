//! The nftables table that diverts new outbound flows to NFQUEUE.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

pub const TABLE: &str = "tuisnitch";

/// Packet-mark bit set on inbound attempts we queued before the host firewall,
/// so the after-firewall chain only re-queues those. Other bits are preserved.
pub const SEEN_MARK: u32 = 0x0400_0000;

/// Inbound attempts at most this often go to userspace; a flood or scan
/// beyond it is not shown but is otherwise unaffected.
const INBOUND_RATE: &str = "limit rate 50/second burst 100 packets";

pub struct FwConfig {
    pub out_queue: u16,
    /// Queue DNS responses here for hostname learning.
    pub dns_queue: Option<u16>,
    /// Also intercept connections to loopback.
    pub loopback: bool,
    /// Drop new connections if tuisnitch is not running.
    pub fail_closed: bool,
    /// Watch new inbound connections: (before-firewall queue, after-firewall queue).
    pub inbound: Option<(u16, u16)>,
}

impl FwConfig {
    pub fn ruleset(&self) -> String {
        let bypass = if self.fail_closed { "" } else { " bypass" };
        let mut s = format!("table inet {TABLE} {{\n  chain output {{\n");
        s += "    type filter hook output priority filter - 1; policy accept;\n";
        if !self.loopback {
            s += "    oifname \"lo\" accept\n";
        }
        s += &format!(
            "    meta l4proto {{ tcp, udp }} ct state new queue num {}{bypass}\n  }}\n",
            self.out_queue
        );
        if self.dns_queue.is_some() || self.inbound.is_some() {
            // Before the host firewall (ufw/iptables run at priority filter).
            s +=
                "  chain input {\n    type filter hook input priority filter - 1; policy accept;\n";
            if let Some(q) = self.dns_queue {
                // Always bypass here: DNS learning must never break resolution.
                s += &format!("    udp sport 53 queue num {q} bypass\n");
            }
            if let Some((seen, _)) = self.inbound {
                if !self.loopback {
                    s += "    iifname \"lo\" return\n";
                }
                // Only unicast to us (no broadcast/multicast chatter), and only
                // real connection openers: TCP SYN, or the first UDP packet.
                s += "    meta pkttype != host return\n";
                s += "    tcp flags & (syn | ack) != syn return\n";
                s += &format!(
                    "    ct state new meta l4proto {{ tcp, udp }} {INBOUND_RATE} \
                     meta mark set meta mark | {SEEN_MARK:#x} queue num {seen} bypass\n"
                );
            }
            s += "  }\n";
        }
        if let Some((_, passed)) = self.inbound {
            // After the host firewall: what gets here was let through.
            s += "  chain input_after {\n    type filter hook input priority filter + 10; policy accept;\n";
            s += &format!("    meta mark & {SEEN_MARK:#x} != 0 queue num {passed} bypass\n  }}\n");
        }
        s + "}\n"
    }
}

fn nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running nft")?;
    child.stdin.take().unwrap().write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&[out.stdout, out.stderr].concat())
            .trim()
            .to_string();
        bail!("nft: {}: {msg}", out.status);
    }
    Ok(())
}

/// "add" then "delete" makes the delete succeed whether or not the table existed.
fn reset() -> String {
    format!("add table inet {TABLE}\ndelete table inet {TABLE}\n")
}

/// Atomically replaces any previous tuisnitch table.
pub fn install(c: &FwConfig) -> Result<()> {
    nft(&(reset() + &c.ruleset()))
}

pub fn remove() -> Result<()> {
    nft(&reset())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset() {
        let rs = FwConfig {
            out_queue: 4242,
            dns_queue: Some(4243),
            loopback: false,
            fail_closed: false,
            inbound: Some((4244, 4245)),
        }
        .ruleset();
        for want in [
            "oifname \"lo\" accept",
            "ct state new queue num 4242 bypass",
            "udp sport 53 queue num 4243 bypass",
            "iifname \"lo\" return",
            "queue num 4244 bypass",
            "priority filter + 10",
            "meta mark & 0x4000000 != 0 queue num 4245 bypass",
        ] {
            assert!(rs.contains(want), "ruleset missing {want:?}:\n{rs}");
        }
        let rs = FwConfig {
            out_queue: 1,
            dns_queue: None,
            loopback: true,
            fail_closed: true,
            inbound: None,
        }
        .ruleset();
        assert!(
            rs.contains("queue num 1\n") && !rs.contains("lo") && !rs.contains("input"),
            "{rs}"
        );
    }
}
