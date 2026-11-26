//! The web UI (axum): an alternative front end to the engine, used instead of
//! the TUI when started with `-ui web`.
//!
//! The browser gets the whole state over Server-Sent Events whenever it
//! changes, and sends decisions back as small JSON POSTs. Every API call needs
//! the access token (as a cookie set by `/api/login`), so other local users,
//! processes and web pages cannot approve connections on your behalf.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::extract::{Path as UrlPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use futures_util::Stream;
use serde::{Deserialize, Serialize};

use crate::engine::{Conn, Engine, InSource, Mode, Scope, Snapshot};
use crate::rules::Rule;

const INDEX: &str = include_str!("web/index.html");
const COOKIE: &str = "tuisnitch_token";
/// Most recent connections sent to the browser.
const WEB_LOG: usize = 500;
/// Most recently active inbound sources sent to the browser.
const WEB_INBOUND: usize = 300;
/// How often state changes are checked for (and the most often they are pushed).
const TICK: Duration = Duration::from_millis(150);

struct Ctx {
    eng: Arc<Engine>,
    token: String,
    demo: bool,
    quit: Arc<AtomicBool>,
}

type Shared = Arc<Ctx>;

/// Binds the listening socket. Done before the firewall is installed so a
/// busy port fails cleanly.
pub fn bind(addr: SocketAddr) -> Result<std::net::TcpListener> {
    let l = std::net::TcpListener::bind(addr)
        .with_context(|| format!("listening on {addr} (is another instance running?)"))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// Reads the access token from `path`, creating it (mode 0600) if missing.
/// With no path, a fresh token is made for this run only.
pub fn load_token(path: Option<&Path>) -> Result<String> {
    let Some(path) = path else {
        return random_token();
    };
    match fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => return Ok(s.trim().to_string()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    let t = random_token()?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(format!("{t}\n").as_bytes()))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(t)
}

fn random_token() -> Result<String> {
    let mut b = [0u8; 24];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .context("reading /dev/urandom")?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Serves the UI until `quit` is set. Also runs prompt timeouts, which the
/// TUI does in its own loop.
pub fn serve(
    listener: std::net::TcpListener,
    eng: Arc<Engine>,
    token: String,
    demo: bool,
    quit: Arc<AtomicBool>,
) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let ctx = Arc::new(Ctx {
            eng: eng.clone(),
            token,
            demo,
            quit: quit.clone(),
        });

        let ticker = {
            let (eng, quit) = (eng, quit.clone());
            tokio::spawn(async move {
                while !quit.load(Ordering::Relaxed) {
                    eng.expire(Instant::now());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        };

        axum::serve(listener, router(ctx))
            .with_graceful_shutdown(async move {
                while !quit.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await?;
        ticker.abort();
        Ok(())
    })
}

fn router(ctx: Shared) -> Router {
    let api = Router::new()
        .route("/events", get(events))
        .route("/state", get(state))
        .route("/mode", post(set_mode))
        .route("/prompts/{id}", post(answer))
        .route("/rules/{i}/toggle", post(toggle_rule))
        .route("/rules/{i}", delete(delete_rule))
        .route_layer(middleware::from_fn_with_state(ctx.clone(), auth));
    Router::new()
        .route("/", get(index))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .nest("/api", api)
        .layer(middleware::from_fn(security_headers))
        .with_state(ctx)
}

// ---- auth ------------------------------------------------------------------

/// Compares in time independent of where the first difference is.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn cookie_token(h: &HeaderMap) -> Option<&str> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(COOKIE)?.strip_prefix('='))
}

async fn auth(State(ctx): State<Shared>, req: Request, next: Next) -> Response {
    let ok = cookie_token(req.headers()).is_some_and(|t| same(t, &ctx.token))
        || req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| same(t.trim(), &ctx.token));
    if ok {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "token required").into_response()
    }
}

#[derive(Deserialize)]
struct Login {
    token: String,
}

async fn login(State(ctx): State<Shared>, Json(l): Json<Login>) -> Response {
    if !same(l.token.trim(), &ctx.token) {
        // Slow down guessing a little; the token is 192 bits anyway.
        tokio::time::sleep(Duration::from_millis(500)).await;
        return (StatusCode::UNAUTHORIZED, "wrong token").into_response();
    }
    let c = format!(
        "{COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000",
        ctx.token
    );
    ([(header::SET_COOKIE, c)], StatusCode::NO_CONTENT).into_response()
}

async fn logout() -> Response {
    let c = format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    ([(header::SET_COOKIE, c)], StatusCode::NO_CONTENT).into_response()
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(
        h,
        "content-security-policy",
        "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; \
         connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'",
    );
    set(h, "x-content-type-options", "nosniff");
    set(h, "referrer-policy", "no-referrer");
    set(h, "cache-control", "no-store");
    r
}

// ---- state -----------------------------------------------------------------

#[derive(Serialize)]
struct WebConn {
    id: u64,
    time: String,
    proto: &'static str,
    dst: String,
    dport: u16,
    host: Option<String>,
    pid: Option<u32>,
    uid: Option<u32>,
    exe: String,
    name: String,
    cmd: String,
    is_new: bool,
    verdict: &'static str,
    reason: String,
}

impl From<&Conn> for WebConn {
    fn from(c: &Conn) -> Self {
        WebConn {
            id: c.id,
            time: c.time.to_rfc3339(),
            proto: c.proto.as_str(),
            dst: c.dst.to_string(),
            dport: c.dport,
            host: c.host.clone(),
            pid: c.pid,
            uid: c.uid,
            exe: c.exe.clone(),
            name: c.name.clone(),
            cmd: c.cmd.clone(),
            is_new: c.is_new,
            verdict: c.verdict.label(),
            reason: c.reason.clone(),
        }
    }
}

#[derive(Serialize)]
struct WebPort {
    proto: &'static str,
    port: u16,
    listener: Option<String>,
    attempts: u64,
    passed: u64,
    blocked: u64,
}

#[derive(Serialize)]
struct WebSource {
    src: String,
    host: Option<String>,
    local: String,
    first: String,
    last: String,
    attempts: u64,
    passed: u64,
    blocked: u64,
    ports: Vec<WebPort>,
    more_ports: usize,
}

impl From<&InSource> for WebSource {
    fn from(s: &InSource) -> Self {
        WebSource {
            src: s.src.to_string(),
            host: s.host.clone(),
            local: s.local.to_string(),
            first: s.first.to_rfc3339(),
            last: s.last.to_rfc3339(),
            attempts: s.attempts,
            passed: s.passed,
            blocked: s.blocked,
            ports: s
                .ports
                .iter()
                .map(|p| WebPort {
                    proto: p.proto.as_str(),
                    port: p.port,
                    listener: p.listener.clone(),
                    attempts: p.attempts,
                    passed: p.passed,
                    blocked: p.blocked,
                })
                .collect(),
            more_ports: s.more_ports,
        }
    }
}

#[derive(Serialize)]
struct WebPrompt {
    id: u64,
    conn: WebConn,
    /// Milliseconds until auto-deny.
    ms_left: u64,
    extra: usize,
}

#[derive(Serialize)]
struct WebState {
    mode: &'static str,
    demo: bool,
    allowed: u64,
    denied: u64,
    err: Option<String>,
    pending: Vec<WebPrompt>,
    /// Newest first, at most WEB_LOG entries.
    log: Vec<WebConn>,
    rules: Vec<Rule>,
    /// Most recently active first, at most WEB_INBOUND entries.
    inbound: Vec<WebSource>,
    in_attempts: u64,
    in_blocked: u64,
}

fn web_state(s: &Snapshot, demo: bool) -> WebState {
    let now = Instant::now();
    WebState {
        mode: mode_name(s.mode),
        demo,
        allowed: s.allowed,
        denied: s.denied,
        err: s.err.clone(),
        pending: s
            .pending
            .iter()
            .map(|p| WebPrompt {
                id: p.id,
                conn: (&p.conn).into(),
                ms_left: p.deadline.saturating_duration_since(now).as_millis() as u64,
                extra: p.extra,
            })
            .collect(),
        log: s.log.iter().take(WEB_LOG).map(Into::into).collect(),
        rules: s.rules.clone(),
        inbound: s.inbound.iter().take(WEB_INBOUND).map(Into::into).collect(),
        in_attempts: s.in_attempts,
        in_blocked: s.in_blocked,
    }
}

fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Alert => "alert",
        Mode::Allow => "allow",
        Mode::Block => "block",
    }
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn state(State(ctx): State<Shared>) -> Json<WebState> {
    Json(web_state(&ctx.eng.snapshot(), ctx.demo))
}

/// Pushes the full state immediately, then again whenever it changes. The
/// stream ends on shutdown so graceful shutdown isn't held up.
async fn events(State(ctx): State<Shared>) -> Sse<impl Stream<Item = Result<Event, axum::Error>>> {
    let stream = futures_util::stream::unfold((ctx, None::<u64>), |(ctx, seen)| async move {
        loop {
            if ctx.quit.load(Ordering::Relaxed) {
                return None;
            }
            let g = ctx.eng.generation();
            if seen != Some(g) {
                let st = web_state(&ctx.eng.snapshot(), ctx.demo);
                let ev = Event::default().event("state").json_data(st);
                return Some((ev, (ctx, Some(g))));
            }
            tokio::time::sleep(TICK).await;
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

// ---- actions ---------------------------------------------------------------

#[derive(Deserialize)]
struct SetMode {
    mode: String,
}

async fn set_mode(State(ctx): State<Shared>, Json(b): Json<SetMode>) -> Response {
    match Mode::parse(&b.mode) {
        Ok(m) => {
            ctx.eng.set_mode(m);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

#[derive(Deserialize)]
struct Answer {
    allow: bool,
    #[serde(default)]
    forever: bool,
    /// "hostport" (default), "host" or "app".
    #[serde(default)]
    scope: String,
}

async fn answer(
    State(ctx): State<Shared>,
    UrlPath(id): UrlPath<u64>,
    Json(a): Json<Answer>,
) -> Response {
    let scope = match a.scope.as_str() {
        "" | "hostport" => Scope::HostPort,
        "host" => Scope::Host,
        "app" => Scope::App,
        s => return (StatusCode::BAD_REQUEST, format!("unknown scope {s:?}")).into_response(),
    };
    if !ctx.eng.snapshot().pending.iter().any(|p| p.id == id) {
        return (StatusCode::NOT_FOUND, "no such prompt (already answered?)").into_response();
    }
    ctx.eng.resolve(id, a.allow, a.forever, scope, None);
    StatusCode::NO_CONTENT.into_response()
}

async fn toggle_rule(State(ctx): State<Shared>, UrlPath(i): UrlPath<usize>) -> StatusCode {
    ctx.eng.toggle_rule(i);
    StatusCode::NO_CONTENT
}

async fn delete_rule(State(ctx): State<Shared>, UrlPath(i): UrlPath<usize>) -> StatusCode {
    ctx.eng.delete_rule(i);
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parsing_and_compare() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; tuisnitch_token=abc; b=2"),
        );
        assert_eq!(cookie_token(&h), Some("abc"));
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
    }

    #[test]
    fn token_file_is_created_once() {
        let dir = std::env::temp_dir().join(format!("tuisnitch-tok-{}", std::process::id()));
        let p = dir.join("web-token");
        let t1 = load_token(Some(&p)).unwrap();
        assert_eq!(t1.len(), 48);
        assert_eq!(load_token(Some(&p)).unwrap(), t1);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
