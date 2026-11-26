//! Persistent allow/deny rules, stored as JSON (same format as the Go version).

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::engine::Conn;

/// * `exe`:   full executable path, or `*` for any program
/// * `host`:  hostname, IP, `*.example.com` suffix wildcard, or `*` for any
/// * `port`:  destination port, 0 = any
/// * `proto`: `tcp`, `udp` or empty for any
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Rule {
    pub exe: String,
    pub host: String,
    pub port: u16,
    pub proto: String,
    pub allow: bool,
    pub created: DateTime<Local>,
}

impl Rule {
    pub fn matches(&self, c: &Conn) -> bool {
        (self.exe == "*" || self.exe == c.exe)
            && (self.proto.is_empty() || self.proto == c.proto.as_str())
            && (self.port == 0 || self.port == c.dport)
            && host_matches(&self.host, c.host.as_deref(), &c.dst.to_string())
    }

    fn specificity(&self) -> u8 {
        u8::from(self.exe != "*") * 4 + u8::from(self.host != "*") * 2 + u8::from(self.port != 0)
    }

    fn same_target(&self, o: &Rule) -> bool {
        self.exe == o.exe && self.host == o.host && self.port == o.port && self.proto == o.proto
    }
}

fn host_matches(pattern: &str, host: Option<&str>, ip: &str) -> bool {
    if pattern == "*" || pattern == ip {
        return true;
    }
    let Some(host) = host else { return false };
    if let Some(suffix) = pattern.strip_prefix('*') {
        // "*.example.com" matches subdomains, not example.com itself.
        return suffix.starts_with('.')
            && host.len() > suffix.len()
            && host
                .get(host.len() - suffix.len()..)
                .is_some_and(|t| t.eq_ignore_ascii_case(suffix));
    }
    !pattern.is_empty() && pattern.eq_ignore_ascii_case(host)
}

pub struct RuleStore {
    path: Option<PathBuf>,
    rules: Vec<Rule>,
}

impl RuleStore {
    pub fn in_memory() -> Self {
        RuleStore {
            path: None,
            rules: Vec::new(),
        }
    }

    /// Loads rules from `path`; a missing file is an empty rule set.
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let mut rs = RuleStore {
            path,
            rules: Vec::new(),
        };
        if let Some(p) = &rs.path {
            match fs::read(p) {
                Ok(b) => {
                    let rules: Option<Vec<Rule>> = serde_json::from_slice(&b)
                        .with_context(|| format!("parsing {}", p.display()))?;
                    rs.rules = rules.unwrap_or_default();
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
            }
        }
        Ok(rs)
    }

    fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(&self.rules)?)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// The most specific matching rule; deny wins ties.
    pub fn find(&self, c: &Conn) -> Option<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.matches(c))
            .fold(None, |best: Option<&Rule>, r| match best {
                Some(b) if r.specificity() < b.specificity() => best,
                Some(b) if r.specificity() == b.specificity() && (r.allow || !b.allow) => best,
                _ => Some(r),
            })
    }

    /// Inserts a rule, replacing any rule with the same target.
    pub fn add(&mut self, r: Rule) -> Result<()> {
        match self.rules.iter_mut().find(|x| x.same_target(&r)) {
            Some(x) => *x = r,
            None => self.rules.push(r),
        }
        self.save()
    }

    pub fn list(&self) -> &[Rule] {
        &self.rules
    }

    pub fn delete(&mut self, i: usize) -> Result<()> {
        if i >= self.rules.len() {
            return Ok(());
        }
        self.rules.remove(i);
        self.save()
    }

    pub fn toggle(&mut self, i: usize) -> Result<()> {
        let Some(r) = self.rules.get_mut(i) else {
            return Ok(());
        };
        r.allow = !r.allow;
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tests::conn;

    fn rule(exe: &str, host: &str, port: u16, allow: bool) -> Rule {
        Rule {
            exe: exe.into(),
            host: host.into(),
            port,
            allow,
            ..Default::default()
        }
    }

    #[test]
    fn specificity_and_wildcards() {
        let mut rs = RuleStore::in_memory();
        rs.add(rule("/usr/bin/curl", "*", 0, true)).unwrap();
        rs.add(rule("/usr/bin/curl", "*.evil.com", 0, false))
            .unwrap();
        let mut c = conn("/usr/bin/curl", Some("a.evil.com"), 443);
        assert!(!rs.find(&c).unwrap().allow);
        c.host = Some("good.com".into());
        assert!(rs.find(&c).unwrap().allow);
        c.host = Some("evil.com".into()); // wildcard is subdomains only
        assert!(rs.find(&c).unwrap().allow);
        c.exe = "/usr/bin/wget".into();
        assert!(rs.find(&c).is_none());
    }

    #[test]
    fn deny_wins_ties_and_ip_matches() {
        let mut rs = RuleStore::in_memory();
        rs.add(rule("*", "1.2.3.4", 0, false)).unwrap();
        rs.add(rule("*", "*", 443, true)).unwrap();
        rs.add(rule("*", "*", 443, true)).unwrap(); // same target: replaced, not duplicated
        assert_eq!(rs.list().len(), 2);
        let mut c = conn("/x", None, 443);
        // host rule (2) beats port rule (1)
        assert!(!rs.find(&c).unwrap().allow);
        c.dst = "5.6.7.8".parse().unwrap();
        assert!(rs.find(&c).unwrap().allow);
        // equal specificity: deny wins regardless of order
        rs.add(Rule {
            proto: "tcp".into(),
            ..rule("*", "*", 443, false)
        })
        .unwrap();
        assert!(!rs.find(&c).unwrap().allow);
    }

    #[test]
    fn persists_and_reads_go_format() {
        let dir = std::env::temp_dir().join(format!("tuisnitch-test-{}", std::process::id()));
        let path = dir.join("sub").join("rules.json");
        let mut rs = RuleStore::load(Some(path.clone())).unwrap();
        rs.add(rule("/x", "h", 1, true)).unwrap();
        assert_eq!(RuleStore::load(Some(path.clone())).unwrap().list().len(), 1);

        // A file written by the Go version.
        fs::write(
            &path,
            r#"[{"exe":"/usr/bin/curl","host":"example.com","port":443,"proto":"tcp",
            "allow":true,"created":"2026-11-24T19:55:01.123456789+01:00"}]"#,
        )
        .unwrap();
        let rs = RuleStore::load(Some(path.clone())).unwrap();
        assert_eq!(rs.list()[0].host, "example.com");
        fs::write(&path, "null").unwrap();
        assert!(RuleStore::load(Some(path)).unwrap().list().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
