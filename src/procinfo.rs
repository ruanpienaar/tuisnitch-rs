//! Finds the process that owns a local socket, via /proc.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::packet::Proto;

#[derive(Clone, Debug, Default)]
pub struct ProcInfo {
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub exe: String,
    pub name: String,
    pub cmd: String,
}

impl ProcInfo {
    pub fn new(pid: Option<u32>, uid: Option<u32>, exe: &str, cmd: &str) -> Self {
        ProcInfo {
            pid,
            uid,
            exe: exe.into(),
            name: basename(exe),
            cmd: cmd.into(),
        }
    }
}

fn basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map_or_else(|| p.to_string(), |n| n.to_string_lossy().into_owned())
}

/// Socket → process lookup with a small inode→pid cache.
#[derive(Default)]
pub struct ProcLookup {
    cache: HashMap<u64, u32>,
}

impl ProcLookup {
    /// `uid_hint` comes from NFQUEUE and is used when /proc has no answer.
    pub fn lookup(&mut self, proto: Proto, lport: u16, uid_hint: Option<u32>) -> ProcInfo {
        let (inode, uid) = find_socket_inode(proto, lport, false);
        self.describe(inode, uid.or(uid_hint))
    }

    /// The process listening on local `port` (TCP LISTEN, or an unconnected
    /// UDP socket), or None if nothing is.
    pub fn listener(&mut self, proto: Proto, port: u16) -> Option<ProcInfo> {
        let (inode, uid) = find_socket_inode(proto, port, true);
        inode.map(|i| self.describe(Some(i), uid))
    }

    fn describe(&mut self, inode: Option<u64>, uid: Option<u32>) -> ProcInfo {
        let mut info = ProcInfo {
            uid,
            ..Default::default()
        };
        if let Some(pid) = inode.and_then(|i| self.find_pid(i)) {
            info.pid = Some(pid);
            if let Ok(p) = fs::read_link(format!("/proc/{pid}/exe")) {
                let s = p.to_string_lossy();
                info.exe = s.strip_suffix(" (deleted)").unwrap_or(&s).to_string();
            }
            if let Ok(b) = fs::read(format!("/proc/{pid}/cmdline")) {
                info.cmd = String::from_utf8_lossy(&b)
                    .replace('\0', " ")
                    .trim()
                    .to_string();
            }
        }
        info.exe = match (info.exe.is_empty(), info.pid, info.uid) {
            (false, ..) => info.exe,
            (true, Some(pid), _) => format!("pid:{pid}"),
            // Kernel-originated, or the process exited before we looked.
            (true, None, Some(0)) => "unknown(root)".into(),
            (true, None, Some(uid)) => format!("unknown(uid {uid})"),
            (true, None, None) => "unknown".into(),
        };
        info.name = if info.exe.starts_with('/') {
            basename(&info.exe)
        } else {
            info.exe.clone()
        };
        info
    }

    fn find_pid(&mut self, inode: u64) -> Option<u32> {
        let target = format!("socket:[{inode}]");
        if let Some(&pid) = self.cache.get(&inode) {
            if pid_has_socket(pid, &target) {
                return Some(pid);
            }
            self.cache.remove(&inode);
        }
        let mut pids: Vec<u32> = fs::read_dir("/proc")
            .ok()?
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        // Newest PIDs first: the connecting process is often recently started.
        pids.sort_unstable_by(|a, b| b.cmp(a));
        let pid = pids.into_iter().find(|&pid| pid_has_socket(pid, &target))?;
        if self.cache.len() > 4096 {
            self.cache.clear();
        }
        self.cache.insert(inode, pid);
        Some(pid)
    }
}

/// Scans /proc/net/{proto,proto6} for a socket bound to `lport`. With
/// `listening`, only TCP sockets in LISTEN state and UDP sockets with no
/// remote end count.
fn find_socket_inode(proto: Proto, lport: u16, listening: bool) -> (Option<u64>, Option<u32>) {
    let mut uid = None;
    for f in [format!("/proc/net/{proto}"), format!("/proc/net/{proto}6")] {
        let Ok(s) = fs::read_to_string(&f) else {
            continue;
        };
        for line in s.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let Some((_, port)) = fields[1].rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(port, 16).ok() != Some(lport) {
                continue;
            }
            if listening {
                let ok = match proto {
                    Proto::Tcp => fields[3] == "0A",
                    Proto::Udp => fields[2].ends_with(":0000"),
                };
                if !ok {
                    continue;
                }
            }
            let ino: u64 = fields[9].parse().unwrap_or(0);
            let u = fields[7].parse().ok();
            if ino != 0 {
                return (Some(ino), u);
            }
            uid = u;
        }
    }
    (None, uid)
}

fn pid_has_socket(pid: u32, target: &str) -> bool {
    let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    fds.filter_map(Result::ok)
        .any(|fd| fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn finds_own_socket() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let info = ProcLookup::default().lookup(Proto::Tcp, port, None);
        assert_eq!(info.pid, Some(std::process::id()));
        assert_eq!(info.uid, Some(unsafe { libc::getuid() }));
        assert_eq!(info.exe, std::env::current_exe().unwrap().to_string_lossy());
    }

    #[test]
    fn finds_listener_only_when_listening() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let info = ProcLookup::default().listener(Proto::Tcp, port).unwrap();
        assert_eq!(info.pid, Some(std::process::id()));
        // The client side of a connection is not a listener.
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let cport = c.local_addr().unwrap().port();
        assert!(ProcLookup::default().listener(Proto::Tcp, cport).is_none());
    }

    #[test]
    fn unknown_socket_falls_back_to_uid() {
        let info = ProcLookup::default().lookup(Proto::Udp, 1, Some(1000));
        assert_eq!((info.pid, info.exe.as_str()), (None, "unknown(uid 1000)"));
    }
}
