//! The terminal UI (ratatui + crossterm).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::engine::{Engine, InSource, Mode, Prompt, Scope, Snapshot, Verdict};

fn fg(n: u8) -> Style {
    Style::new().fg(Color::Indexed(n))
}
fn dim() -> Style {
    fg(244)
}
fn new_style() -> Style {
    fg(51).add_modifier(Modifier::BOLD)
}
fn pend() -> Style {
    fg(214)
}
fn mode_color(m: Mode) -> u8 {
    match m {
        Mode::Alert => 214,
        Mode::Allow => 42,
        Mode::Block => 196,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Conns,
    Incoming,
    Rules,
}

impl Tab {
    fn next(self) -> Tab {
        match self {
            Tab::Conns => Tab::Incoming,
            Tab::Incoming => Tab::Rules,
            Tab::Rules => Tab::Conns,
        }
    }
}

struct App {
    eng: Arc<Engine>,
    snap: Snapshot,
    seen_gen: u64,
    refreshed: Instant,
    tab: Tab,
    scope: Scope,
    log_off: usize,
    in_off: usize,
    rule_cur: usize,
    only_new: bool,
    demo: bool,
    /// Rows available for the table body at the last draw.
    body_h: usize,
}

/// Runs until the user quits or `quit` is set (by a signal).
pub fn run(
    term: &mut DefaultTerminal,
    eng: Arc<Engine>,
    demo: bool,
    quit: &AtomicBool,
) -> io::Result<()> {
    let snap = eng.snapshot();
    let mut app = App {
        seen_gen: eng.generation(),
        eng,
        snap,
        refreshed: Instant::now(),
        tab: Tab::Conns,
        scope: Scope::default(),
        log_off: 0,
        in_off: 0,
        rule_cur: 0,
        only_new: false,
        demo,
        body_h: 1,
    };
    loop {
        app.eng.expire(Instant::now());
        if app.eng.generation() != app.seen_gen || app.refreshed.elapsed() >= Duration::from_secs(1)
        {
            app.refresh();
        }
        term.draw(|f| app.draw(f))?;
        if quit.load(Ordering::Relaxed) {
            return Ok(());
        }
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
            && !app.key(k)
        {
            return Ok(());
        }
    }
}

impl App {
    fn refresh(&mut self) {
        self.seen_gen = self.eng.generation();
        self.snap = self.eng.snapshot();
        self.refreshed = Instant::now();
        self.rule_cur = self.rule_cur.min(self.snap.rules.len().saturating_sub(1));
    }

    /// Handles a key; returns false to quit.
    fn key(&mut self, k: KeyEvent) -> bool {
        let name = match k.code {
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                "ctrl+c".to_string()
            }
            KeyCode::Char(c) => c.to_string(),
            KeyCode::Up => "up".into(),
            KeyCode::Down => "down".into(),
            KeyCode::PageUp => "pgup".into(),
            KeyCode::PageDown => "pgdown".into(),
            KeyCode::Home => "home".into(),
            KeyCode::Delete => "delete".into(),
            KeyCode::Tab => "tab".into(),
            _ => return true,
        };

        // Prompt keys take priority while a decision is pending.
        if let Some(id) = self.snap.pending.first().map(|p| p.id) {
            let answer = match name.as_str() {
                "a" => Some((true, false)),
                "A" => Some((true, true)),
                "d" => Some((false, false)),
                "D" => Some((false, true)),
                "s" => {
                    self.scope = self.scope.next();
                    None
                }
                _ => None,
            };
            if let Some((allow, forever)) = answer {
                self.eng.resolve(id, allow, forever, self.scope, None);
                self.scope = Scope::default();
                self.refresh();
                return true;
            }
        }

        let rules = self.tab == Tab::Rules;
        let inc = self.tab == Tab::Incoming;
        match name.as_str() {
            "q" | "ctrl+c" => return false,
            "1" => self.eng.set_mode(Mode::Alert),
            "2" => self.eng.set_mode(Mode::Allow),
            "3" => self.eng.set_mode(Mode::Block),
            "tab" => self.tab = self.tab.next(),
            "n" => {
                self.only_new = !self.only_new;
                self.log_off = 0;
            }
            "up" | "k" if rules => self.rule_cur = self.rule_cur.saturating_sub(1),
            "up" | "k" if inc => self.in_off = self.in_off.saturating_sub(1),
            "up" | "k" => self.log_off = self.log_off.saturating_sub(1),
            "down" | "j" if rules => self.rule_cur += 1,
            "down" | "j" if inc => self.in_off += 1,
            "down" | "j" => self.log_off += 1,
            "pgup" if inc => self.in_off = self.in_off.saturating_sub(self.body_h),
            "pgup" => self.log_off = self.log_off.saturating_sub(self.body_h),
            "pgdown" if inc => self.in_off += self.body_h,
            "pgdown" => self.log_off += self.body_h,
            "home" | "g" => (self.log_off, self.in_off, self.rule_cur) = (0, 0, 0),
            "x" | "delete" if rules => self.eng.delete_rule(self.rule_cur),
            "t" if rules => self.eng.toggle_rule(self.rule_cur),
            _ => {}
        }
        self.refresh();
        self.log_off = self
            .log_off
            .min(self.visible_conns().saturating_sub(self.body_h));
        self.in_off = self
            .in_off
            .min(self.snap.inbound.len().saturating_sub(self.body_h));
        true
    }

    fn visible_conns(&self) -> usize {
        if self.only_new {
            self.snap.log.iter().filter(|c| c.is_new).count()
        } else {
            self.snap.log.len()
        }
    }

    fn draw(&mut self, f: &mut Frame) {
        let w = f.area().width as usize;
        let prompt = self.snap.pending.first().map(|p| self.prompt_view(p, w));
        let prompt_h = prompt.as_ref().map_or(0, |(_, h)| *h);
        let [title, tabs, prompt_area, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(prompt_h),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(f.area());
        self.body_h = (body.height as usize).saturating_sub(1).max(1);

        f.render_widget(self.title_line(), title);
        f.render_widget(self.tabs_line(), tabs);
        if let Some((p, _)) = prompt {
            f.render_widget(p, prompt_area);
        }
        let lines = match self.tab {
            Tab::Conns => self.conns_view(w),
            Tab::Incoming => self.incoming_view(w),
            Tab::Rules => self.rules_view(w),
        };
        f.render_widget(Paragraph::new(lines), body);

        let help = match (&self.snap.err, self.tab) {
            (Some(e), _) => Line::styled(format!("error: {}", clean(e)), fg(196)),
            (None, Tab::Conns) => Line::styled(
                "1/2/3 mode · tab incoming · n only-new · ↑↓ scroll · q quit",
                dim(),
            ),
            (None, Tab::Incoming) => Line::styled(
                "1/2/3 mode · tab rules · ↑↓ scroll · watch only: the host firewall decides · q quit",
                dim(),
            ),
            (None, Tab::Rules) => Line::styled(
                "1/2/3 mode · tab conns · ↑↓ select · t toggle allow/deny · x delete · q quit",
                dim(),
            ),
        };
        f.render_widget(help, footer);
    }

    fn title_line(&self) -> Line<'static> {
        let mut spans = vec![Span::styled(
            " tuisnitch ",
            fg(15).bg(Color::Indexed(57)).add_modifier(Modifier::BOLD),
        )];
        if self.demo {
            spans.push(Span::styled(" DEMO ", dim()));
        }
        spans.push(Span::raw("  "));
        for (i, m) in Mode::ALL.into_iter().enumerate() {
            let label = format!(" {} {} ", i + 1, m.label());
            spans.push(if m == self.snap.mode {
                Span::styled(
                    label,
                    fg(0)
                        .bg(Color::Indexed(mode_color(m)))
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(label, fg(241))
            });
        }
        let s = &self.snap;
        spans.push(Span::styled(
            format!(
                " allowed {}  denied {}  pending {}  rules {}  inbound {} ({} blocked)",
                s.allowed,
                s.denied,
                s.pending.len(),
                s.rules.len(),
                s.in_attempts,
                s.in_blocked
            ),
            dim(),
        ));
        Line::from(spans)
    }

    fn tabs_line(&self) -> Line<'static> {
        let on = Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
        let st = |t: Tab| if self.tab == t { on } else { dim() };
        let mut spans = vec![
            Span::raw(" "),
            Span::styled("Connections", st(Tab::Conns)),
            Span::raw("  "),
            Span::styled(
                format!("Incoming ({})", self.snap.inbound.len()),
                st(Tab::Incoming),
            ),
            Span::raw("  "),
            Span::styled("Rules", st(Tab::Rules)),
        ];
        if self.only_new && self.tab == Tab::Conns {
            spans.push(Span::styled("  [only new]", new_style()));
        }
        Line::from(spans)
    }

    fn prompt_view(&self, pr: &Prompt, w: usize) -> (Paragraph<'static>, u16) {
        let c = &pr.conn;
        let left = pr
            .deadline
            .saturating_duration_since(Instant::now())
            .as_secs();
        let host = match &c.host {
            Some(h) => format!("{} ({})", clean(h), c.dst),
            None => c.dst.to_string(),
        };
        let opt = |v: Option<u32>| v.map_or_else(|| "?".to_string(), |v| v.to_string());
        let key = |k: &'static str| Span::styled(k, pend().add_modifier(Modifier::BOLD));

        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    "⚠ New outbound connection",
                    pend().add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("   auto-deny in {left}s"), dim()),
                Span::styled(more(self.snap.pending.len() - 1, pr.extra), dim()),
            ]),
            Line::raw(format!(
                "Program  {}  (pid {}, uid {})",
                clean(&c.exe),
                opt(c.pid),
                opt(c.uid)
            )),
        ];
        if !c.cmd.is_empty() && c.cmd != c.exe {
            lines.push(Line::from(vec![
                Span::raw("Command  "),
                Span::styled(truncate(&c.cmd, w.saturating_sub(14)), dim()),
            ]));
        }
        lines.extend([
            Line::from(vec![
                Span::raw("Connect  "),
                Span::styled(host, new_style()),
                Span::raw(format!("  {}/{}", c.proto, c.dport)),
            ]),
            Line::from(vec![
                Span::raw(format!("Rule     {}  ", self.scope.label())),
                Span::styled("(s: change)", dim()),
            ]),
            Line::from(vec![
                key("a"),
                Span::raw(" allow once   "),
                key("A"),
                Span::raw(" allow always   "),
                key("d"),
                Span::raw(" deny once   "),
                key("D"),
                Span::raw(" deny always"),
            ]),
        ]);
        let h = lines.len() as u16 + 2;
        let block = Block::bordered()
            .border_type(BorderType::Thick)
            .border_style(pend())
            .padding(Padding::horizontal(1));
        (Paragraph::new(lines).block(block), h)
    }

    fn conns_view(&self, w: usize) -> Vec<Line<'static>> {
        let dest_w = w.saturating_sub(59).max(10);
        let mut out = vec![Line::styled(
            format!(
                "{:<8} {:<8} {:<2}{:<18} {:>7} {:<5} {:<dest_w$} {:>5}",
                "TIME", "VERDICT", "", "PROGRAM", "PID", "PROTO", "DESTINATION", "PORT"
            ),
            dim().add_modifier(Modifier::BOLD),
        )];
        let rows: Vec<_> = self
            .snap
            .log
            .iter()
            .filter(|c| !self.only_new || c.is_new)
            .collect();
        let h = self.body_h;
        let off = self.log_off.min(rows.len().saturating_sub(h));
        for c in rows.iter().skip(off).take(h) {
            let vstyle = match c.verdict {
                Verdict::Allowed => fg(42),
                Verdict::Denied => fg(196),
                Verdict::Pending => pend(),
            };
            let pid = c.pid.map(|p| p.to_string()).unwrap_or_default();
            let mut spans = vec![
                Span::raw(format!("{} ", c.time.format("%H:%M:%S"))),
                Span::styled(format!("{:<8}", c.verdict.label()), vstyle),
                Span::raw(" "),
                if c.is_new {
                    Span::styled("★ ", new_style())
                } else {
                    Span::raw("  ")
                },
                Span::raw(format!(
                    "{:<18} {:>7} {:<5} ",
                    truncate(&c.name, 18),
                    pid,
                    c.proto
                )),
            ];
            let ip = c.dst.to_string();
            match &c.host {
                Some(host) if host.chars().count() + 1 + ip.len() <= dest_w => {
                    let pad = dest_w - host.chars().count() - 1 - ip.len();
                    spans.push(Span::raw(format!("{} ", clean(host))));
                    spans.push(Span::styled(ip, dim()));
                    spans.push(Span::raw(" ".repeat(pad)));
                }
                _ => spans.push(Span::raw(format!(
                    "{:<dest_w$}",
                    truncate(&c.dest(), dest_w)
                ))),
            }
            spans.push(Span::raw(format!(" {:>5}", c.dport)));
            out.push(Line::from(spans));
        }
        out
    }

    fn incoming_view(&self, w: usize) -> Vec<Line<'static>> {
        const REMOTE_W: usize = 30;
        let mut out = vec![Line::styled(
            format!(
                "{:<8} {:<REMOTE_W$} {:>6} {:>7} {:>6}  PORTS (listener ×tries)",
                "LAST", "REMOTE", "TRIES", "BLOCKED", "PASSED"
            ),
            dim().add_modifier(Modifier::BOLD),
        )];
        let srcs = &self.snap.inbound;
        if srcs.is_empty() {
            out.push(Line::styled(
                "  nothing has tried to connect to this machine yet",
                dim(),
            ));
            return out;
        }
        let h = self.body_h;
        let off = self.in_off.min(srcs.len().saturating_sub(h));
        let ports_w = w.saturating_sub(8 + 1 + REMOTE_W + 1 + 6 + 1 + 7 + 1 + 6 + 2);
        for s in srcs.iter().skip(off).take(h) {
            let style = match (s.passed, s.blocked) {
                (0, 0) => pend(),
                (_, 0) => fg(42),
                (0, _) => fg(196),
                _ => pend(),
            };
            let remote = match &s.host {
                Some(hn) => format!("{} {}", clean(hn), s.src),
                None => s.src.to_string(),
            };
            out.push(Line::from(vec![
                Span::raw(format!("{} ", s.last.format("%H:%M:%S"))),
                Span::styled(format!("{:<REMOTE_W$}", truncate(&remote, REMOTE_W)), style),
                Span::raw(format!(" {:>6} ", s.attempts)),
                Span::styled(
                    format!("{:>7}", s.blocked),
                    if s.blocked > 0 { fg(196) } else { dim() },
                ),
                Span::styled(
                    format!(" {:>6}", s.passed),
                    if s.passed > 0 { fg(42) } else { dim() },
                ),
                Span::styled(format!("  {}", truncate(&ports_summary(s), ports_w)), dim()),
            ]));
        }
        out
    }

    fn rules_view(&self, _w: usize) -> Vec<Line<'static>> {
        let mut out = vec![Line::styled(
            format!(
                "{:<6} {:<40} {:<30} {:>5} {:<5} {}",
                "ACTION", "PROGRAM", "HOST", "PORT", "PROTO", "CREATED"
            ),
            dim().add_modifier(Modifier::BOLD),
        )];
        let rules = &self.snap.rules;
        if rules.is_empty() {
            out.push(Line::styled(
                "  no rules yet: answer a prompt with A or D to create one",
                dim(),
            ));
            return out;
        }
        let h = self.body_h;
        let start = (self.rule_cur + 1).saturating_sub(h);
        for (i, r) in rules.iter().enumerate().skip(start).take(h) {
            let act = if r.allow {
                Span::styled("allow ", fg(42))
            } else {
                Span::styled("deny  ", fg(196))
            };
            let port = if r.port == 0 {
                "any".to_string()
            } else {
                r.port.to_string()
            };
            let proto = if r.proto.is_empty() {
                "any"
            } else {
                r.proto.as_str()
            };
            let mut line = Line::from(vec![
                act,
                Span::raw(format!(
                    " {:<40} {:<30} {:>5} {:<5} {}",
                    truncate(&r.exe, 40),
                    truncate(&r.host, 30),
                    port,
                    clean(proto),
                    r.created.format("%Y-%m-%d %H:%M")
                )),
            ]);
            if i == self.rule_cur {
                line = line.patch_style(Style::new().add_modifier(Modifier::REVERSED));
            }
            out.push(line);
        }
        out
    }
}

/// "tcp/22 sshd ×3, tcp/445 ×1 +12 more"
fn ports_summary(s: &InSource) -> String {
    let mut parts: Vec<String> = s
        .ports
        .iter()
        .map(|p| {
            let who = p
                .listener
                .as_deref()
                .map(|l| format!(" {l}"))
                .unwrap_or_default();
            format!("{}/{}{who} ×{}", p.proto, p.port, p.attempts)
        })
        .collect();
    if s.more_ports > 0 {
        parts.push(format!("+{} more", s.more_ports));
    }
    parts.join(", ")
}

fn more(prompts: usize, extra: usize) -> String {
    let mut s = String::new();
    if extra > 0 {
        s += &format!("  +{extra} retries held");
    }
    if prompts > 0 {
        s += &format!("  · {prompts} more waiting");
    }
    s
}

/// Replaces control characters so process names, command lines and hand-edited
/// rules can't inject terminal escape sequences.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn truncate(s: &str, n: usize) -> String {
    let s = clean(s);
    if s.chars().count() <= n {
        return s;
    }
    if n <= 1 {
        return s.chars().take(n).collect();
    }
    s.chars().take(n - 1).chain(['…']).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_and_clean() {
        assert_eq!(truncate("firefox", 18), "firefox");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("a\x1b[31mb", 20), "a?[31mb");
    }
}
