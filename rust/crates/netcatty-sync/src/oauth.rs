//! OAuth loopback redirect receiver for Google Drive and OneDrive
//! (`oauthBridge.cjs`).
//!
//! Flow, driven by the renderer:
//! 1. [`OAuthCallbackServer::prepare`] binds `127.0.0.1:45678` (or an
//!    OS-assigned port when that one is taken) and returns the redirect URI;
//! 2. the renderer opens the provider's authorization URL in the browser;
//! 3. [`OAuthCallbackServer::await_callback`] resolves with the `code` once
//!    the browser hits `/oauth/callback`, checking `state` against CSRF.
//!
//! Only one flow is active at a time; preparing a new one cancels the old.

use netcatty_core::{CoreError, CoreResult};
use parking_lot::Mutex;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

pub const PREFERRED_PORT: u16 = 45678;
pub const CALLBACK_PATH: &str = "/oauth/callback";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_REQUEST_HEAD: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedCallback {
    pub session_id: String,
    pub port: u16,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallbackResult {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

type Waiter = oneshot::Sender<CoreResult<CallbackResult>>;

struct Active {
    id: String,
    waiter: Option<Waiter>,
    expected_state: Option<String>,
    error: Option<CoreError>,
    server_open: bool,
    shutdown: CancellationToken,
}

#[derive(Default)]
struct Inner {
    active: Option<Active>,
    next_id: u64,
}

impl Inner {
    fn is_active(&self, id: &str) -> bool {
        self.active.as_ref().is_some_and(|a| a.id == id)
    }

    /// Dispose the active flow, rejecting its waiter (if armed) with `err`.
    fn reject(&mut self, err: CoreError) {
        if let Some(active) = self.active.take() {
            active.shutdown.cancel();
            if let Some(waiter) = active.waiter {
                let _ = waiter.send(Err(err));
            }
        }
    }

    fn resolve(&mut self, result: CallbackResult) {
        if let Some(active) = self.active.take() {
            active.shutdown.cancel();
            if let Some(waiter) = active.waiter {
                let _ = waiter.send(Ok(result));
            }
        }
    }

    /// Reject an armed waiter, or remember the error for the next
    /// [`OAuthCallbackServer::await_callback`] and close the listener.
    fn finish_with_error(&mut self, err: CoreError) {
        let armed = self.active.as_ref().is_some_and(|a| a.waiter.is_some());
        if armed {
            self.reject(err);
        } else if let Some(active) = self.active.as_mut() {
            active.shutdown.cancel();
            active.server_open = false;
            active.expected_state = None;
            active.error = Some(err);
        }
    }
}

/// Loopback OAuth redirect receiver. Cheap to clone.
#[derive(Clone)]
pub struct OAuthCallbackServer {
    inner: Arc<Mutex<Inner>>,
    preferred_port: u16,
    timeout: Duration,
}

impl Default for OAuthCallbackServer {
    fn default() -> Self {
        Self::new(PREFERRED_PORT, DEFAULT_TIMEOUT)
    }
}

fn cancelled() -> CoreError {
    CoreError::cancelled("OAuth flow cancelled")
}

impl OAuthCallbackServer {
    pub fn new(preferred_port: u16, timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            preferred_port,
            timeout,
        }
    }

    async fn bind(&self) -> CoreResult<TcpListener> {
        let mut last_err = None;
        for port in [self.preferred_port, 0] {
            match TcpListener::bind(("127.0.0.1", port)).await {
                Ok(listener) => return Ok(listener),
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    last_err = Some(err);
                }
                Err(err) => {
                    return Err(CoreError::io(format!(
                        "Failed to bind OAuth loopback server: {err}"
                    )))
                }
            }
        }
        Err(CoreError::io(format!(
            "Failed to bind OAuth loopback server: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }

    /// Bind the listener and start a new flow, cancelling any previous one.
    pub async fn prepare(&self) -> CoreResult<PreparedCallback> {
        let (id, shutdown) = {
            let mut inner = self.inner.lock();
            inner.reject(cancelled());
            inner.next_id += 1;
            let id = format!("oauth-{}", inner.next_id);
            let shutdown = CancellationToken::new();
            inner.active = Some(Active {
                id: id.clone(),
                waiter: None,
                expected_state: None,
                error: None,
                server_open: false,
                shutdown: shutdown.clone(),
            });
            (id, shutdown)
        };

        let listener = match self.bind().await {
            Ok(listener) => listener,
            Err(err) => {
                let mut inner = self.inner.lock();
                if inner.is_active(&id) {
                    inner.active = None;
                }
                shutdown.cancel();
                return Err(err);
            }
        };
        let port = listener
            .local_addr()
            .map_err(|err| CoreError::io(err.to_string()))?
            .port();

        {
            let mut inner = self.inner.lock();
            match inner.active.as_mut() {
                Some(active) if active.id == id && active.error.is_none() => {
                    active.server_open = true
                }
                _ => {
                    shutdown.cancel();
                    let err = inner
                        .active
                        .as_ref()
                        .filter(|a| a.id == id)
                        .and_then(|a| a.error.clone())
                        .unwrap_or_else(cancelled);
                    if inner.is_active(&id) {
                        inner.active = None;
                    }
                    return Err(err);
                }
            }
        }

        tokio::spawn(accept_loop(
            self.inner.clone(),
            id.clone(),
            listener,
            shutdown.clone(),
        ));
        let inner = self.inner.clone();
        let timeout = self.timeout;
        let timeout_id = id.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancelled() => {}
                _ = tokio::time::sleep(timeout) => {
                    let mut inner = inner.lock();
                    if inner.is_active(&timeout_id) {
                        inner.reject(CoreError::timeout(
                            "OAuth timeout - user did not complete authorization in time",
                        ));
                    }
                }
            }
        });

        let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
        tracing::info!(%redirect_uri, "OAuth callback server listening");
        Ok(PreparedCallback {
            session_id: id,
            port,
            redirect_uri,
        })
    }

    /// Wait for the authorization code of the prepared flow.
    pub async fn await_callback(
        &self,
        expected_state: Option<String>,
        session_id: Option<String>,
    ) -> CoreResult<CallbackResult> {
        let rx = {
            let mut inner = self.inner.lock();
            let Some(active) = inner.active.as_mut() else {
                return Err(CoreError::invalid("OAuth callback server not prepared"));
            };
            if session_id
                .as_deref()
                .is_some_and(|sid| !sid.is_empty() && sid != active.id)
            {
                return Err(cancelled());
            }
            if active.waiter.is_some() {
                return Err(CoreError::invalid(
                    "An OAuth callback is already in progress",
                ));
            }
            if let Some(err) = active.error.take() {
                inner.active = None;
                return Err(err);
            }
            if !active.server_open {
                return Err(CoreError::invalid("OAuth callback server not prepared"));
            }
            let (tx, rx) = oneshot::channel();
            active.waiter = Some(tx);
            active.expected_state = expected_state.filter(|s| !s.is_empty());
            rx
        };
        rx.await.unwrap_or_else(|_| Err(cancelled()))
    }

    /// Cancel the active flow (only `session_id`'s, when given).
    pub fn cancel(&self, session_id: Option<&str>) {
        let mut inner = self.inner.lock();
        let Some(active) = inner.active.as_ref() else {
            return;
        };
        if session_id.is_some_and(|sid| !sid.is_empty() && sid != active.id) {
            return;
        }
        inner.finish_with_error(cancelled());
    }

    /// True while a prepared flow is listening.
    pub fn is_active(&self) -> bool {
        self.inner
            .lock()
            .active
            .as_ref()
            .is_some_and(|a| a.server_open)
    }
}

async fn accept_loop(
    inner: Arc<Mutex<Inner>>,
    id: String,
    listener: TcpListener,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let inner = inner.clone();
                    let id = id.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(inner, &id, stream).await {
                            tracing::debug!(%err, "OAuth callback connection failed");
                        }
                    });
                }
                Err(err) => {
                    tracing::warn!(%err, "OAuth callback accept failed");
                    let mut guard = inner.lock();
                    if guard.is_active(&id) {
                        guard.reject(CoreError::io(format!("OAuth server error: {err}")));
                    }
                    break;
                }
            }
        }
    }
}

async fn read_request_target(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > MAX_REQUEST_HEAD {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
    let _method = parts.next();
    Ok(parts.next().map(str::to_owned))
}

/// What the callback page says and what happens to the flow.
#[derive(Debug, PartialEq)]
enum Outcome {
    NotFound,
    Page { page: Page, effect: Effect },
}

#[derive(Debug, PartialEq)]
enum Effect {
    None,
    Resolve(CallbackResult),
    Fail(String),
}

#[derive(Debug, PartialEq)]
struct Page {
    title: &'static str,
    message: &'static str,
    detail: Option<String>,
    status: PageStatus,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum PageStatus {
    Success,
    Warning,
    Error,
}

fn page(title: &'static str, message: &'static str, status: PageStatus) -> Page {
    Page {
        title,
        message,
        detail: None,
        status,
    }
}

/// Decide the response to a request for `target` given whether a waiter is
/// armed and the state it expects.
fn decide(target: &str, armed: bool, expected_state: Option<&str>) -> Outcome {
    let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
        return Outcome::NotFound;
    };
    if url.path() != CALLBACK_PATH {
        return Outcome::NotFound;
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    // Callbacks before the renderer armed the flow are stale noise and must
    // not consume it.
    if !armed {
        return Outcome::Page {
            page: page(
                "Authorization Not Ready",
                "This sign-in request is not active yet. Return to Netcatty and try again.",
                PageStatus::Warning,
            ),
            effect: Effect::None,
        };
    }
    if let Some(error) = param("error") {
        let detail = param("error_description")
            .filter(|d| !d.is_empty())
            .unwrap_or(error);
        let detail = if detail.is_empty() {
            "Unknown error".to_owned()
        } else {
            detail
        };
        return Outcome::Page {
            page: Page {
                detail: Some(detail.clone()),
                ..page(
                    "Authorization Failed",
                    "We could not complete the sign-in flow.",
                    PageStatus::Error,
                )
            },
            effect: Effect::Fail(detail),
        };
    }
    let Some(code) = param("code").filter(|c| !c.is_empty()) else {
        return Outcome::Page {
            page: page(
                "Missing Authorization Code",
                "The authorization response did not include a code.",
                PageStatus::Error,
            ),
            effect: Effect::Fail("Missing authorization code".into()),
        };
    };
    let state = param("state");
    if let Some(expected) = expected_state {
        if state.as_deref() != Some(expected) {
            return Outcome::Page {
                page: page(
                    "Security Check Failed",
                    "State parameter mismatch. This may indicate a CSRF attack.",
                    PageStatus::Error,
                ),
                effect: Effect::Fail("State mismatch - possible CSRF attack".into()),
            };
        }
    }
    Outcome::Page {
        page: page(
            "Authorization Complete",
            "You are signed in and ready to sync. You can close this tab now.",
            PageStatus::Success,
        ),
        effect: Effect::Resolve(CallbackResult { code, state }),
    }
}

async fn handle_connection(
    inner: Arc<Mutex<Inner>>,
    id: &str,
    mut stream: TcpStream,
) -> std::io::Result<()> {
    let Some(target) = read_request_target(&mut stream).await? else {
        return Ok(());
    };
    let (armed, expected) = {
        let guard = inner.lock();
        match guard.active.as_ref().filter(|a| a.id == id) {
            Some(active) => (active.waiter.is_some(), active.expected_state.clone()),
            None => (false, None),
        }
    };
    let (status_line, body) = match decide(&target, armed, expected.as_deref()) {
        Outcome::NotFound => ("404 Not Found", "<h1>404 Not Found</h1>".to_owned()),
        Outcome::Page { page, effect } => {
            let body = render_page(&page);
            let mut guard = inner.lock();
            if guard.is_active(id) {
                match effect {
                    Effect::None => {}
                    Effect::Resolve(result) => guard.resolve(result),
                    Effect::Fail(message) => guard.finish_with_error(CoreError::auth(message)),
                }
            }
            ("200 OK", body)
        }
    };
    let response = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_page(page: &Page) -> String {
    let accent = match page.status {
        PageStatus::Success => "#2f7bff",
        PageStatus::Warning => "#f59e0b",
        PageStatus::Error => "#dc2626",
    };
    let detail = page
        .detail
        .as_deref()
        .map(|d| format!("<pre class=\"detail\">{}</pre>", escape_html(d)))
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Netcatty</title>
<style>
  :root {{ color-scheme: light dark; --accent: {accent}; }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: Canvas; color: CanvasText; }}
  .card {{ max-width: 460px; margin: 16px; padding: 28px 32px; border-radius: 14px;
    border: 1px solid color-mix(in srgb, CanvasText 12%, transparent); }}
  .brand {{ font-weight: 600; opacity: .7; margin-bottom: 12px; }}
  h1 {{ font-size: 20px; margin: 0 0 8px; color: var(--accent); }}
  p {{ margin: 0 0 12px; }}
  .detail {{ white-space: pre-wrap; word-break: break-word; padding: 10px 12px; border-radius: 8px;
    background: color-mix(in srgb, CanvasText 6%, transparent); font-size: 13px; }}
  .footer {{ font-size: 13px; opacity: .7; }}
</style>
</head>
<body>
  <div class="card">
    <div class="brand">Netcatty</div>
    <h1>{title}</h1>
    <p>{message}</p>
    {detail}
    <div class="footer">You can close this window and return to Netcatty.</div>
  </div>
</body>
</html>"#,
        title = escape_html(page.title),
        message = escape_html(page.message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_follows_the_electron_rules() {
        assert_eq!(decide("/favicon.ico", true, None), Outcome::NotFound);
        assert!(matches!(
            decide("/oauth/callback?code=x", false, None),
            Outcome::Page {
                effect: Effect::None,
                ..
            }
        ));
        assert!(matches!(
            decide("/oauth/callback?error=access_denied&error_description=No", true, None),
            Outcome::Page { effect: Effect::Fail(ref m), .. } if m == "No"
        ));
        assert!(matches!(
            decide("/oauth/callback?state=s", true, None),
            Outcome::Page { effect: Effect::Fail(ref m), .. } if m == "Missing authorization code"
        ));
        assert!(matches!(
            decide("/oauth/callback?code=c&state=bad", true, Some("good")),
            Outcome::Page { effect: Effect::Fail(ref m), .. } if m.starts_with("State mismatch")
        ));
        assert_eq!(
            decide("/oauth/callback?code=c%2Fd&state=good", true, Some("good")),
            Outcome::Page {
                page: page(
                    "Authorization Complete",
                    "You are signed in and ready to sync. You can close this tab now.",
                    PageStatus::Success
                ),
                effect: Effect::Resolve(CallbackResult {
                    code: "c/d".into(),
                    state: Some("good".into())
                }),
            }
        );
    }

    #[test]
    fn page_escapes_detail() {
        let html = render_page(&Page {
            detail: Some("<script>x</script>".into()),
            ..page("T", "M", PageStatus::Error)
        });
        assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
        assert!(!html.contains("<script>"));
    }
}
